import {
  existsSync,
  mkdirSync,
  readdirSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { EXIT } from '../errors';
import { silentLogger } from '../log';
import { main } from '../main';
import { captureIO } from '../../test/io';
import { commitAll, initRepo } from '../../test/git';
import { useTempDirs } from '../../test/tmp';
import { runDotnetBegin } from './begin';
import { hookPath, installHook } from './hook';
import { addLease, leaseDir } from './leases';

const tmp = useTempDirs();

function setup() {
  const root = tmp();
  initRepo(root);
  writeFileSync(
    path.join(root, 'qualor.yml'),
    'version: 1\nanalyzers:\n  gitleaks: { enabled: false }\n',
  );
  commitAll(root, 'init');
  const env = {
    QUALOR_MSBUILD_USER_DIR: tmp(),
    QUALOR_CACHE_DIR: tmp(),
    QUALOR_DOTNET_ANALYZERS: tmp(),
    DOTNET_CLI_TELEMETRY_OPTOUT: '1',
    // abort never uploads: a server and a token in the environment are never used.
    QUALOR_URL: 'http://127.0.0.1:9',
    QUALOR_TOKEN: 'qlr_never_used',
    PATH: process.env['PATH'] ?? '',
  };
  return { root, env };
}

const leases = (env: { QUALOR_MSBUILD_USER_DIR: string }) => leaseDir(env.QUALOR_MSBUILD_USER_DIR);

async function abort(root: string, env: Record<string, string>, args: string[] = []) {
  const captured = captureIO({ cwd: root, env });
  const code = await main(['dotnet', 'abort', ...args], captured.io);
  return { code, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe('qualor dotnet abort (config.md §6.1)', () => {
  it('releases the lease, removes the hook and the session, and scans nothing', async () => {
    const { root, env } = setup();
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    // A failed build may have left logs behind.
    writeFileSync(path.join(root, '.qualor', 'dotnet', 'sarif', 'Lib-1-net8.0.sarif'), '{}');

    const { code, stdout } = await abort(root, env, ['--config', 'qualor.yml']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toBe('');
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
    expect(existsSync(leases(env)) ? readdirSync(leases(env)) : []).toEqual([]);
  });

  it("keeps the hook while another checkout's session holds a live lease", async () => {
    const a = setup();
    const b = setup();
    const shared = { ...b.env, QUALOR_MSBUILD_USER_DIR: a.env.QUALOR_MSBUILD_USER_DIR };
    runDotnetBegin({}, captureIO({ cwd: a.root, env: a.env }).io, silentLogger);
    runDotnetBegin({}, captureIO({ cwd: b.root, env: shared }).io, silentLogger);

    expect((await abort(a.root, a.env)).code).toBe(EXIT.OK);
    expect(existsSync(hookPath(a.env.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    expect(existsSync(path.join(a.root, '.qualor', 'dotnet'))).toBe(false);
    expect(existsSync(path.join(b.root, '.qualor', 'dotnet', 'session.json'))).toBe(true);
    expect(readdirSync(leases(a.env))).toHaveLength(1);

    expect((await abort(b.root, shared)).code).toBe(EXIT.OK);
    expect(existsSync(hookPath(a.env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('without a session still prunes a stale lease and removes the hook it guarded', async () => {
    const { root, env } = setup();
    installHook(env.QUALOR_MSBUILD_USER_DIR);
    const staleId = 'a'.repeat(32);
    const old = new Date(Date.now() - 25 * 3600_000);
    addLease(leases(env), staleId, '/some/other/checkout', old);
    utimesSync(path.join(leases(env), staleId), old, old);

    expect((await abort(root, env)).code).toBe(EXIT.OK);
    expect(existsSync(path.join(leases(env), staleId))).toBe(false);
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('without a session keeps the hook while a live foreign lease remains', async () => {
    const { root, env } = setup();
    installHook(env.QUALOR_MSBUILD_USER_DIR);
    const liveId = 'b'.repeat(32);
    addLease(leases(env), liveId, '/some/other/checkout', new Date());

    expect((await abort(root, env)).code).toBe(EXIT.OK);
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    expect(existsSync(path.join(leases(env), liveId))).toBe(true);
  });

  it('exits 2 and leaves a .qualor/dotnet that is a link alone', async () => {
    const { root, env } = setup();
    const outside = tmp();
    writeFileSync(path.join(outside, 'keep.txt'), 'x');
    mkdirSync(path.join(root, '.qualor'));
    symlinkSync(outside, path.join(root, '.qualor', 'dotnet'), 'junction');

    const { code, stderr } = await abort(root, env);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toMatch(/\.qualor\/dotnet must be a directory/);
    expect(existsSync(path.join(outside, 'keep.txt'))).toBe(true);
  });
});
