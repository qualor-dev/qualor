import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ENTERPRISE_PROBE, indexProblems, mainScript } from './checks';
import {
  Api,
  compose,
  envFileText,
  run,
  secret,
  SERVER_IMAGE,
  startStack,
  stopStack,
  stopStacksOnSignal,
} from './stack';

/** A GET that gives up after 30 s, so a hung server fails the check instead of the run. */
const get = (url: string): Promise<Response> => fetch(url, { signal: AbortSignal.timeout(30_000) });

/**
 * `pnpm deploy:smoke [--build]` (plan 1G): the brief's acceptance test, "docker compose up gives a
 * working server in minutes", automated. It checks that compose refuses to start without the
 * secrets, brings a fresh stack up (building the server image first with --build), waits for
 * health, signs in as the bootstrap admin, loads the UI index with its CSP nonce and a hashed
 * asset, checks the container's hardening and that PostgreSQL is not published, then tears it all
 * down. Exit 0 when every check passed.
 */
const failures: string[] = [];
const check = (ok: boolean, what: string): void => {
  process.stdout.write(`${ok ? 'ok  ' : 'FAIL'} ${what}\n`);
  if (!ok) failures.push(what);
};

function refusesWithoutSecrets(): void {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-smoke-empty-'));
  try {
    const envFile = path.join(dir, 'empty.env');
    writeFileSync(
      envFile,
      envFileText({
        POSTGRES_PASSWORD: '',
        QUALOR_SECRET_KEY: '',
        QUALOR_BOOTSTRAP_ADMIN_PASSWORD: '',
      }),
    );
    const r = compose({ name: 'qualor-smoke-refusal', envFile }, ['config', '--quiet']);
    check(r.code !== 0, 'docker compose refuses to start without the secrets');
    check(
      /POSTGRES_PASSWORD|QUALOR_SECRET_KEY|QUALOR_BOOTSTRAP_ADMIN_PASSWORD/.test(r.stderr),
      `and names the missing one (${r.stderr.trim().split('\n').at(-1)})`,
    );
    // Each secret on its own: the other two set, this one empty.
    const names = ['POSTGRES_PASSWORD', 'QUALOR_SECRET_KEY', 'QUALOR_BOOTSTRAP_ADMIN_PASSWORD'];
    for (const missing of names) {
      writeFileSync(
        envFile,
        envFileText(Object.fromEntries(names.map((n) => [n, n === missing ? '' : secret()]))),
      );
      const one = compose({ name: 'qualor-smoke-refusal', envFile }, ['config', '--quiet']);
      check(
        one.code !== 0 && one.stderr.includes(`required variable ${missing} is missing a value`),
        `docker compose refuses to start with only ${missing} empty`,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

interface Container {
  Config: { User: string };
  HostConfig: { ReadonlyRootfs: boolean; PortBindings: Record<string, unknown> | null };
  NetworkSettings: { Networks: Record<string, unknown> | null };
  State: { Health?: { Status: string } };
}

function inspect(id: string): Container | undefined {
  return (JSON.parse(run('docker', ['inspect', id]).stdout) as Container[])[0];
}

async function main(): Promise<void> {
  refusesWithoutSecrets();
  const build = process.argv.includes('--build');
  // An interrupted run (Ctrl+C, a CI timeout) tears down too, also during `compose up`.
  const undoSignals = stopStacksOnSignal();
  const stack = await startStack(`qualor-smoke-${process.pid}`, { build });
  try {
    process.stdout.write(
      `compose up${build ? ' --build' : ''} until healthy: ${(stack.upMs / 1000).toFixed(1)} s\n`,
    );
    check((await get(`${stack.url}/healthz`)).status === 200, 'GET /healthz is 200');
    check(
      (await get(`${stack.url}/readyz`)).status === 200,
      'GET /readyz is 200 (migrations applied)',
    );

    const api = new Api(stack.url);
    await api.login(stack.admin.username, stack.admin.password);
    const me = await api.json<{ user: { username: string; isInstanceAdmin: boolean } }>(
      'GET',
      '/api/v0/auth/me',
    );
    check(me.user.username === 'admin' && me.user.isInstanceAdmin, 'the bootstrap admin signs in');

    // enterprise.md §14.1, §17 AC 7: one image; without a key it is the community edition, and
    // the enterprise plugin it carries is never loaded.
    const info = await api.json<{ edition: string; features: string[] }>(
      'GET',
      '/api/v0/system/info',
    );
    check(
      info.edition === 'community' && info.features.length === 0,
      'without a key the server is the community edition',
    );
    const licence = await api.json<{ state: string; plugins: unknown[] }>('GET', '/api/v0/license');
    check(
      licence.state === 'none' && licence.plugins.length === 0,
      'without a key no plugin is loaded',
    );
    const serverId = compose(stack, ['ps', '-q', 'server']).stdout.trim();
    const probe = run('docker', [
      'exec',
      serverId,
      '/usr/local/bin/node',
      '-e',
      "const fs=require('fs');" +
        "process.exit(process.env.QUALOR_PLUGIN_PATHS==='/app/enterprise/plugin.js'" +
        "&&fs.statSync('/app/enterprise/plugin.js').isFile()" +
        "&&fs.readFileSync('/app/enterprise/LICENSE','utf8').startsWith('Qualor Enterprise Licence')?0:1)",
    ]);
    check(
      probe.code === 0,
      'the image carries /app/enterprise/plugin.js, its LICENSE, and QUALOR_PLUGIN_PATHS',
    );
    // Final review A I-2: the plugin the image carries is one the loader would accept
    // (R-PLUGINPATH: root-owned, not group- or world-writable, the directory too) and one that
    // loads, as the server's user, as qualor-enterprise. Imported in its own process, not the server.
    const plugin = run('docker', [
      'exec',
      serverId,
      '/usr/local/bin/node',
      '--input-type=module',
      '-e',
      ENTERPRISE_PROBE,
      '/app/enterprise/plugin.js',
      '0',
    ]);
    check(
      plugin.code === 0,
      'the enterprise plugin is root-owned, read-only and loads as qualor-enterprise' +
        (plugin.code === 0 ? '' : `: ${plugin.stdout.trim()} ${plugin.stderr.trim()}`),
    );
    // enterprise.md §10.1.1: the loader's own check (checkPluginFile), as the image ships it.
    const fileCheck = run('docker', [
      'exec',
      serverId,
      '/usr/local/bin/node',
      '/app/dist/check-plugin-file.js',
      '/app/enterprise/plugin.js',
    ]);
    let accepted = false;
    try {
      accepted =
        fileCheck.code === 0 &&
        (JSON.parse(fileCheck.stdout) as { ok?: unknown; realPath?: unknown }).ok === true;
    } catch {
      accepted = false;
    }
    check(
      accepted,
      "the loader's plugin file check accepts /app/enterprise/plugin.js" +
        (accepted ? '' : `: ${fileCheck.stdout.trim()} ${fileCheck.stderr.trim()}`),
    );

    const index = await get(`${stack.url}/projects`);
    const body = await index.text();
    const problems = indexProblems(index.headers, body);
    check(
      index.status === 200 && problems.length === 0,
      `the UI index is served with its CSP nonce${problems.length > 0 ? `: ${problems.join('; ')}` : ''}`,
    );
    const script = mainScript(body);
    const asset = script ? await get(`${stack.url}/${script}`) : null;
    check(
      asset?.status === 200 && (asset.headers.get('cache-control') ?? '').includes('immutable'),
      `the hashed script ${script} is served as immutable`,
    );
    check(
      (await get(`${stack.url}/api/v0/nope`)).status === 404,
      'an unknown /api path is a 404, not the UI',
    );

    const postgres = inspect(compose(stack, ['ps', '-q', 'postgres']).stdout.trim());
    check(
      Object.keys(postgres?.HostConfig.PortBindings ?? {}).length === 0,
      'PostgreSQL has no published port',
    );
    const networks = Object.keys(postgres?.NetworkSettings.Networks ?? {});
    check(
      networks.length === 1 && networks[0] === `${stack.name}_internal`,
      `PostgreSQL is only on the internal network (${networks.join(', ')})`,
    );
    const server = inspect(compose(stack, ['ps', '-q', 'server']).stdout.trim());
    check(
      server?.Config.User === '65532:65532',
      `the server runs as a non-root user (${server?.Config.User})`,
    );
    check(server?.HostConfig.ReadonlyRootfs === true, 'the server has a read-only root filesystem');
    check(server?.State.Health?.Status === 'healthy', 'the container health check reports healthy');
    const size = run('docker', [
      'image',
      'ls',
      SERVER_IMAGE,
      '--format',
      '{{.Size}}',
    ]).stdout.trim();
    process.stdout.write(`${SERVER_IMAGE}: ${size} on disk\n`);
  } finally {
    stopStack(stack);
    undoSignals();
  }
  if (failures.length > 0) {
    process.stderr.write(`${failures.length} check(s) failed\n`);
    process.exitCode = 1;
  }
}

await main();
