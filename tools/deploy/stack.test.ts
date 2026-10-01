import { readFileSync } from 'node:fs';
import net, { type AddressInfo } from 'node:net';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { indexProblems, mainScript, scriptNonce } from './checks';
import { Api, envFileText, secret, stopStacksOnSignal } from './stack';

const NONCE = 'k3Jq9x0PZ1s2mM4yT7uV8w==';
const CSP =
  "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; " +
  "frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; " +
  `script-src 'self' 'nonce-${NONCE}'; script-src-attr 'none'; style-src 'self' 'nonce-${NONCE}'`;
const PAGE = `<html><body><q-root ngcspnonce="${NONCE}"></q-root><script src="main-VPIJLN4P.js" type="module" nonce="${NONCE}"></script></body></html>`;

function headers(overrides: Record<string, string | null> = {}): Headers {
  const h = new Headers({
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': CSP,
    'x-frame-options': 'DENY',
    'cache-control': 'no-store',
  });
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) h.delete(k);
    else h.set(k, v);
  }
  return h;
}

describe('UI index checks of the smoke test', () => {
  it('accepts the index the server sends (api.md §4, plan 1F ruling Y2)', () => {
    expect(scriptNonce(CSP)).toBe(NONCE);
    expect(indexProblems(headers(), PAGE)).toEqual([]);
    expect(mainScript(PAGE)).toBe('main-VPIJLN4P.js');
  });

  it('names every way the index can be wrong', () => {
    expect(indexProblems(headers({ 'content-security-policy': null }), PAGE)).toContain(
      'the CSP has no script nonce',
    );
    expect(indexProblems(headers(), PAGE.replaceAll(NONCE, 'other'))).toContain(
      'the page does not carry the CSP nonce',
    );
    expect(
      indexProblems(
        headers({ 'content-security-policy': `${CSP}; script-src 'unsafe-inline'` }),
        PAGE,
      ),
    ).toContain('the CSP allows unsafe-inline or eval');
    expect(indexProblems(headers({ 'cache-control': 'public, max-age=60' }), PAGE)).toContain(
      'the index is cacheable',
    );
    expect(indexProblems(headers({ 'x-frame-options': null }), PAGE)).toContain(
      'X-Frame-Options is not DENY',
    );
    expect(indexProblems(headers(), PAGE.replace(NONCE, '__QUALOR_CSP_NONCE__'))).toContain(
      'the nonce placeholder was not replaced',
    );
    expect(indexProblems(headers(), '<html></html>')).toContain('the page is not the Qualor UI');
  });
});

describe('throwaway stack secrets', () => {
  it('generates hex secrets, safe inside a postgres:// URL', () => {
    const s = secret();
    expect(s).toMatch(/^[0-9a-f]{64}$/);
    expect(secret()).not.toBe(s);
  });

  it('writes an env file and refuses names or values that would break it', () => {
    expect(envFileText({ A_B: 'x', C: '' })).toBe('A_B=x\nC=\n');
    expect(() => envFileText({ 'a-b': 'x' })).toThrow('invalid variable name');
    expect(() => envFileText({ A: 'x\nB=y' })).toThrow('single line');
  });
});

describe('a stack script that hangs or is interrupted', () => {
  it('gives up on a server that accepts the connection but never answers', async () => {
    const sockets: net.Socket[] = [];
    const server = net.createServer((socket) => sockets.push(socket));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const started = Date.now();
      await expect(new Api(`http://127.0.0.1:${port}`, 200).json('GET', '/x')).rejects.toThrow(
        /timeout|aborted/i,
      );
      await expect(
        new Api(`http://127.0.0.1:${port}`, 200).login('admin', 'secret'),
      ).rejects.toThrow(/timeout|aborted/i);
      expect(Date.now() - started).toBeLessThan(5_000);
    } finally {
      for (const socket of sockets) socket.destroy();
      server.close();
    }
  });

  it('retries a GET once when the connection drops, and names the cause when it gives up', async () => {
    // The first connection is reset as its request arrives, like a keep-alive socket the stack
    // closed while a blocking scan held the event loop; later ones answer.
    let connections = 0;
    const server = net.createServer((socket) => {
      connections += 1;
      socket.once('data', () => {
        if (connections === 1) socket.resetAndDestroy();
        else socket.end('HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 7\r\n\r\n{"a":1}');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    try {
      const api = new Api(`http://127.0.0.1:${port}`, 2_000);
      expect(await api.json('GET', '/x')).toEqual({ a: 1 });
      expect(connections).toBe(2);
      connections = 0;
      // Not a GET: it may have reached the server, so it is not sent twice.
      await expect(api.json('POST', '/x', {})).rejects.toThrow(/fetch failed \(.+\)/);
      expect(connections).toBe(1);
    } finally {
      server.close();
    }
  });

  it('tears the started stacks down on SIGINT and SIGTERM, from before the first one starts', () => {
    const before = [process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')];
    const dispose = stopStacksOnSignal();
    expect([process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')]).toEqual([
      before[0]! + 1,
      before[1]! + 1,
    ]);
    dispose();
    expect([process.listenerCount('SIGINT'), process.listenerCount('SIGTERM')]).toEqual(before);
  });
});

describe('deploy/docker-compose.yml (plan 1G)', () => {
  const compose = parse(readFileSync('deploy/docker-compose.yml', 'utf8')) as {
    services: Record<
      string,
      {
        image: string;
        pull_policy?: string;
        security_opt?: string[];
        ports?: string[];
        environment: Record<string, string>;
        read_only?: boolean;
        networks: string[];
      }
    >;
    networks: Record<string, { internal?: boolean }>;
  };

  it('never starts without the three secrets and never publishes PostgreSQL', () => {
    const { postgres, server } = compose.services;
    expect(postgres?.environment['POSTGRES_PASSWORD']).toMatch(/^\$\{POSTGRES_PASSWORD:\?/);
    expect(server?.environment['QUALOR_SECRET_KEY']).toMatch(/^\$\{QUALOR_SECRET_KEY:\?/);
    expect(server?.environment['QUALOR_BOOTSTRAP_ADMIN_PASSWORD']).toMatch(
      /^\$\{QUALOR_BOOTSTRAP_ADMIN_PASSWORD:\?/,
    );
    expect(postgres?.ports).toBeUndefined();
    expect(postgres?.networks).toEqual(['internal']);
    expect(compose.networks['internal']?.internal).toBe(true);
    expect(server?.ports).toEqual(['${QUALOR_BIND_ADDRESS:-127.0.0.1}:${QUALOR_PORT:-8080}:8080']);
    expect(server?.read_only).toBe(true);
  });

  it('keeps PostgreSQL from gaining privileges too', () => {
    expect(compose.services['postgres']?.security_opt).toEqual(['no-new-privileges:true']);
  });

  it('builds the unpublished dev image instead of asking Docker Hub for it', () => {
    // With `pull_policy: missing`, a fresh `up` first tries Docker Hub's `qualor/server:dev`, which
    // is never published, prints "pull access denied", then builds (checked with compose 5.1).
    const server = compose.services['server'];
    expect(server?.pull_policy).toBe('never');
    expect(server?.image).toBe('${QUALOR_SERVER_IMAGE:-qualor/server:dev}');
    // A released image is pulled by hand and started with --no-build, which fails on a missing
    // image rather than building this checkout under the release's name.
    for (const file of ['deploy/docker-compose.yml', 'deploy/.env.example', 'deploy/README.md']) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).toContain('qualor/server:<version>');
      expect(text, file).toContain('--no-build');
    }
  });

  it('runs the scanner image of the dogfood scripts only from a local build', () => {
    const source = readFileSync('tools/deploy/workspace.ts', 'utf8');
    expect(source).toContain("const LOCAL_SCANNER = ['--pull=never', SCANNER_IMAGE];");
    // Every `docker run` of the scanner goes through LOCAL_SCANNER, never the bare name.
    expect(source.match(/\bSCANNER_IMAGE\b/g)).toHaveLength(2); // the import and LOCAL_SCANNER
    expect(source.match(/\.\.\.LOCAL_SCANNER,/g)?.length).toBe(4);
  });

  it('leaves no default secret in the env template', () => {
    const lines = readFileSync('deploy/.env.example', 'utf8').split('\n');
    for (const name of [
      'POSTGRES_PASSWORD',
      'QUALOR_SECRET_KEY',
      'QUALOR_BOOTSTRAP_ADMIN_PASSWORD',
    ]) {
      expect(lines, name).toContain(`${name}=`);
    }
  });
});
