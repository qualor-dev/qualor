import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildServer } from '../scripts/bundle';
import { createTestDatabase, type TestDatabase } from '../test/db';
import { E2E_SIGNER, signCurrent } from '../test/license-e2e-key';
import { auditEvents } from './db/schema';

const MAIN = fileURLToPath(new URL('../dist/main.js', import.meta.url));
const ADMIN_PASSWORD = 'smoke-test admin passphrase';

/** Resolves with the first stdout line matching `pattern` (the process logs JSON lines). */
function waitForLine(child: ChildProcess, pattern: RegExp): Promise<RegExpMatchArray> {
  return new Promise((resolve, reject) => {
    let buffered = '';
    const onData = (chunk: Buffer): void => {
      buffered += chunk.toString('utf8');
      const match = pattern.exec(buffered);
      if (match) {
        child.stdout?.off('data', onData);
        child.off('exit', onExit);
        resolve(match);
      }
    };
    const onExit = (code: number | null): void =>
      reject(new Error(`server exited (${code}) before logging ${pattern}; stdout: ${buffered}`));
    child.stdout?.on('data', onData);
    child.once('exit', onExit);
  });
}

function exited(child: ChildProcess): Promise<number | null> {
  if (child.exitCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve) => child.once('exit', (code) => resolve(code)));
}

/**
 * Boot smoke test of the production bundle (ruling S14): the real `main.ts` path — config from
 * the environment, migrations on an empty database, bootstrap, listen, readiness — and a graceful
 * shutdown that exits 0.
 */
describe('server bundle boot (main.ts)', () => {
  let database: TestDatabase;
  let child: ChildProcess;
  let stderr = '';

  beforeAll(async () => {
    await buildServer(); // what `pnpm --filter @qualor/server build` runs: server/dist/main.js
    database = await createTestDatabase({ migrated: false });
  }, 120_000);

  afterAll(async () => {
    if (child.exitCode === null) child.kill('SIGKILL');
    await database.close();
  });

  it('migrates, bootstraps, serves /readyz and the login, then shuts down cleanly with exit 0', async () => {
    child = spawn(process.execPath, [MAIN], {
      env: {
        PATH: process.env.PATH,
        SYSTEMROOT: process.env.SYSTEMROOT, // Windows needs it for sockets
        DATABASE_URL: database.url,
        QUALOR_TELEMETRY: 'false',
        QUALOR_SECRET_KEY: 'smoke-test-secret-key-that-is-at-least-32-characters',
        QUALOR_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD,
        HOST: '127.0.0.1',
        PORT: '0',
      },
      // 'ipc': on Windows a child cannot receive SIGTERM (Node emulates kill() by terminating the
      // process outright), so the test asks for the same graceful shutdown over IPC there.
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    const [, baseUrl] = await waitForLine(child, /Server listening at (http:\/\/127\.0\.0\.1:\d+)/);

    const ready = await fetch(`${baseUrl}/readyz`);
    expect(ready.status).toBe(200);
    const login = await fetch(`${baseUrl}/api/v0/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: ADMIN_PASSWORD }),
    });
    expect(login.status).toBe(204);
    expect(login.headers.get('set-cookie')).toContain('qualor_session=');

    const stoppedAt = Date.now();
    if (process.platform === 'win32') child.send('shutdown');
    else child.kill('SIGTERM');
    expect(await exited(child)).toBe(0);
    expect(Date.now() - stoppedAt).toBeLessThan(5_000);
    expect(stderr).toBe('');
  }, 60_000);
});

/** The environment of a bundle boot on its own database (enterprise.md §6, §12). */
function bootEnv(databaseUrl: string, extra: Record<string, string>): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    SYSTEMROOT: process.env.SYSTEMROOT,
    DATABASE_URL: databaseUrl,
    QUALOR_TELEMETRY: 'false',
    QUALOR_SECRET_KEY: 'smoke-test-secret-key-that-is-at-least-32-characters',
    QUALOR_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD,
    HOST: '127.0.0.1',
    PORT: '0',
    ...extra,
  };
}

describe('the bundle without a valid licence (enterprise.md §12)', () => {
  const MARKER_PLUGIN = fileURLToPath(
    new URL('../test/fixtures/plugins/marker-plugin.mjs', import.meta.url),
  );
  const REJECTED = 'QLK1.test-a.bm90LWEta2V5.AAAA';

  it.each([
    ['without a licence', {}, /"licence":"none"/],
    ['with a rejected licence', { QUALOR_LICENSE: REJECTED }, /"reason":"malformed"/],
  ])(
    '%s: runs as community and never imports a plugin',
    async (_what, extra, licenceLine) => {
      const database = await createTestDatabase({ migrated: false });
      const marker = path.join(tmpdir(), `qualor-marker-${randomBytes(4).toString('hex')}`);
      let stdout = '';
      const child = spawn(process.execPath, [MAIN], {
        env: bootEnv(database.url, {
          QUALOR_PLUGIN_PATHS: MARKER_PLUGIN,
          QUALOR_TEST_PLUGIN_MARKER: marker,
          ...extra,
        }),
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      });
      try {
        await new Promise<void>((resolve, reject) => {
          child.stdout!.on('data', (chunk: Buffer) => {
            stdout += chunk.toString('utf8');
            if (/Server listening/.test(stdout)) resolve();
          });
          child.once('exit', (code) => reject(new Error(`exited ${code}: ${stdout}`)));
        });
        expect(stdout).toMatch(licenceLine);
        expect(stdout).toMatch(/"edition":"community"/);
        expect(stdout).toMatch(/"plugins":\[\]/);
        expect(existsSync(marker)).toBe(false);
        expect(stdout).not.toContain('bm90LWEta2V5');
        child.send('shutdown');
        expect(await exited(child)).toBe(0);
      } finally {
        if (child.exitCode === null) child.kill('SIGKILL');
        rmSync(marker, { force: true });
        await database.close();
      }
    },
    120_000,
  );

  it.each([
    ['a missing licence file', false, /^qualor-server: QUALOR_LICENSE_FILE: cannot read .*\n$/],
    [
      'an oversized licence file',
      true,
      /^qualor-server: QUALOR_LICENSE_FILE: .* is larger than 16 KiB\n$/,
    ],
  ])(
    'fails the boot on %s, naming the variable and nothing of its content',
    async (_what, write, message) => {
      const database = await createTestDatabase({ migrated: false });
      const file = path.join(tmpdir(), `qualor-licence-${randomBytes(4).toString('hex')}`);
      const content = `QLK1.test-a.${'c2VjcmV0LWxpY2VuY2U'.repeat(1000)}.AAAA`;
      if (write) writeFileSync(file, content);
      let output = '';
      const child = spawn(process.execPath, [MAIN], {
        env: bootEnv(database.url, { QUALOR_LICENSE_FILE: file }),
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      child.stdout!.on('data', (chunk: Buffer) => {
        output += chunk.toString('utf8');
      });
      let stderr = '';
      child.stderr!.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      // A server that boots anyway must not outlive the test.
      const deadline = setTimeout(() => child.kill('SIGKILL'), 60_000);
      try {
        expect(await exited(child)).toBe(1);
        expect(stderr).toMatch(message);
        expect(stderr + output).not.toContain('c2VjcmV0LWxpY2VuY2U');
        expect(output).not.toMatch(/Server listening/);
      } finally {
        clearTimeout(deadline);
        if (child.exitCode === null) child.kill('SIGKILL');
        rmSync(file, { force: true });
        await database.close();
      }
    },
    120_000,
  );
});

/**
 * enterprise.md §14.2: test keys exist only in test bundles. The production bundle defines the
 * test-key name as `undefined`, so neither a test signer nor a global set before its code runs
 * (a preloaded script) makes it accept a `test-` key. A test bundle accepts its own test key, and
 * only then does the loader import a plugin.
 */
describe('test licence keys and the bundles (enterprise.md §14.2)', () => {
  const MARKER_PLUGIN = fileURLToPath(
    new URL('../test/fixtures/plugins/marker-plugin.mjs', import.meta.url),
  );
  // One level below server/, like dist/main.js, so the bundle finds ../drizzle; never in the image.
  const TEST_MAIN = fileURLToPath(new URL('../.tmp/test-main.js', import.meta.url));
  /** Sets the global before the bundle's code runs, as a hostile preload would. */
  const PRELOAD = `data:text/javascript,${encodeURIComponent(
    `globalThis.__QUALOR_TEST_LICENSE_KEYS__ = ${JSON.stringify(
      JSON.stringify({ [E2E_SIGNER.kid]: E2E_SIGNER.x }),
    )};`,
  )}`;

  beforeAll(async () => {
    await buildServer(); // the production bundle, as the image builds it
    await buildServer({ outfile: TEST_MAIN, testLicenseKeys: { [E2E_SIGNER.kid]: E2E_SIGNER.x } });
  }, 120_000);

  /** Boots `main` until it listens; returns its stdout and whether the plugin was imported. */
  async function boot(
    main: string,
    execArgv: string[],
  ): Promise<{ stdout: string; imported: boolean }> {
    const database = await createTestDatabase({ migrated: false });
    const marker = path.join(tmpdir(), `qualor-marker-${randomBytes(4).toString('hex')}`);
    let stdout = '';
    let stderr = '';
    const child = spawn(process.execPath, [...execArgv, main], {
      env: bootEnv(database.url, {
        QUALOR_LICENSE: signCurrent(E2E_SIGNER),
        QUALOR_PLUGIN_PATHS: MARKER_PLUGIN,
        QUALOR_TEST_PLUGIN_MARKER: marker,
      }),
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    try {
      child.stderr!.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      await new Promise<void>((resolve, reject) => {
        child.stdout!.on('data', (chunk: Buffer) => {
          stdout += chunk.toString('utf8');
          if (/Server listening/.test(stdout)) resolve();
        });
        child.once('exit', (code) => reject(new Error(`exited ${code}: ${stdout}${stderr}`)));
      });
      const imported = existsSync(marker);
      child.send('shutdown');
      expect(await exited(child)).toBe(0);
      return { stdout, imported };
    } finally {
      if (child.exitCode === null) child.kill('SIGKILL');
      rmSync(marker, { force: true });
      await database.close();
    }
  }

  it.each([
    ['with a test key on the production bundle', []],
    [
      'with a test key on the production bundle and the global set before it loads',
      ['--import', PRELOAD],
    ],
  ])(
    '%s: rejects the key as unknown and imports no plugin',
    async (_what, execArgv) => {
      const { stdout, imported } = await boot(MAIN, execArgv);
      expect(stdout).toMatch(/"licence":"invalid"/);
      expect(stdout).toMatch(/"reason":"unknown-key"/);
      expect(stdout).toMatch(/"edition":"community"/);
      expect(imported).toBe(false);
    },
    120_000,
  );

  it('QUALOR_FORCE_PASSWORD_SIGN_IN=true: one warn line and auth.password_sign_in_forced (sso-scim.md §10.4)', async () => {
    const AUDIT_PLUGIN = fileURLToPath(
      new URL('../test/fixtures/plugins/audit-log-plugin.mjs', import.meta.url),
    );
    const database = await createTestDatabase({ migrated: false });
    let stdout = '';
    const child = spawn(process.execPath, [TEST_MAIN], {
      env: bootEnv(database.url, {
        QUALOR_LICENSE: signCurrent(E2E_SIGNER, ['audit-log']),
        QUALOR_PLUGIN_PATHS: AUDIT_PLUGIN,
        QUALOR_FORCE_PASSWORD_SIGN_IN: 'true',
      }),
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    try {
      await new Promise<void>((resolve, reject) => {
        child.stdout!.on('data', (chunk: Buffer) => {
          stdout += chunk.toString('utf8');
          if (/Server listening/.test(stdout)) resolve();
        });
        child.once('exit', (code) => reject(new Error(`exited ${code}: ${stdout}`)));
      });
      const warns = stdout
        .split(/\r?\n/)
        .filter((l) => l.includes('password sign-in forced by QUALOR_FORCE_PASSWORD_SIGN_IN'))
        .map((l) => JSON.parse(l) as { level: number; component: string });
      expect(warns).toHaveLength(1);
      expect(warns[0]).toMatchObject({ level: 40, component: 'sign-in' });
      const events = await database.db
        .select()
        .from(auditEvents)
        .where(eq(auditEvents.action, 'auth.password_sign_in_forced'));
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        actorType: 'system',
        targetType: null,
        details: { storedPolicy: 'everyone' },
      });
      child.send('shutdown');
      expect(await exited(child)).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill('SIGKILL');
      await database.close();
    }
  }, 120_000);

  it('a test bundle accepts its test key, and only then imports the plugin', async () => {
    const { stdout, imported } = await boot(TEST_MAIN, []);
    expect(stdout).toMatch(/"licence":"active"/);
    expect(stdout).toMatch(/"edition":"enterprise"/);
    expect(imported).toBe(true);
  }, 120_000);
});
