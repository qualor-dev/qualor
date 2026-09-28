import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { EXIT } from '../errors';
import { createLogger, silentLogger } from '../log';
import { captureIO } from '../../test/io';
import { useTempDirs } from '../../test/tmp';
import { runDotnetBegin } from './begin';
import { hookPath } from './hook';
import { leaseDir } from './leases';
import { readSession } from './session';

const tmp = useTempDirs();

function repo(files: Record<string, string> = {}) {
  const root = tmp();
  mkdirSync(path.join(root, '.git'));
  for (const [p, text] of Object.entries(files)) writeFileSync(path.join(root, p), text);
  return root;
}

function env(extra: Record<string, string> = {}) {
  const analyzers = tmp();
  writeFileSync(path.join(analyzers, 'Roslynator.CSharp.Analyzers.dll'), '');
  writeFileSync(path.join(analyzers, 'readme.txt'), '');
  return {
    QUALOR_MSBUILD_USER_DIR: tmp(),
    // Leases no longer live here (final review R9); set so that no test can reach the real one.
    QUALOR_CACHE_DIR: tmp(),
    QUALOR_DOTNET_ANALYZERS: analyzers,
    DOTNET_CLI_TELEMETRY_OPTOUT: '1',
    ...extra,
  };
}

describe('qualor dotnet begin (config.md §6.1)', () => {
  it('creates the session, records a lease beside the hook and installs the hook', () => {
    const root = repo();
    const e = env();
    const { io } = captureIO({ cwd: root, env: e });
    expect(runDotnetBegin({}, io, silentLogger)).toBe(EXIT.OK);
    const session = readSession(root)!;
    expect(session.analyzers).toEqual([
      path.join(e.QUALOR_DOTNET_ANALYZERS, 'Roslynator.CSharp.Analyzers.dll'),
    ]);
    expect(existsSync(hookPath(e.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    expect(existsSync(path.join(leaseDir(e.QUALOR_MSBUILD_USER_DIR), session.id))).toBe(true);
  });

  it('bundles nothing with bundledAnalyzers: false, and warns when there is nothing to bundle', () => {
    const root = repo({
      'qualor.yml': 'version: 1\nanalyzers:\n  roslyn: { bundledAnalyzers: false }\n',
    });
    const { io } = captureIO({ cwd: root, env: env() });
    runDotnetBegin({}, io, silentLogger);
    expect(readSession(root)!.analyzers).toEqual([]);
    const lines: string[] = [];
    const other = repo();
    const e = env({ QUALOR_DOTNET_ANALYZERS: tmp() });
    runDotnetBegin(
      {},
      captureIO({ cwd: other, env: e }).io,
      createLogger('warn', (t) => lines.push(t)),
    );
    expect(lines.join('')).toMatch(/SDK's own rules only/);
  });

  it('installs nothing when roslyn is disabled', () => {
    const root = repo({ 'qualor.yml': 'version: 1\nanalyzers:\n  roslyn: { enabled: false }\n' });
    const e = env();
    expect(runDotnetBegin({}, captureIO({ cwd: root, env: e }).io, silentLogger)).toBe(EXIT.OK);
    expect(readSession(root)).toBeNull();
    expect(existsSync(hookPath(e.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('exits 2 outside the root of a work tree, or with a relative or in-repo analyzer directory', () => {
    const notRepo = tmp();
    expect(() =>
      runDotnetBegin({}, captureIO({ cwd: notRepo, env: env() }).io, silentLogger),
    ).toThrow(expect.objectContaining({ exitCode: EXIT.USAGE }));
    const root = repo();
    for (const dir of ['rel/dir', path.join(root, 'analyzers')]) {
      expect(() =>
        runDotnetBegin(
          {},
          captureIO({ cwd: root, env: env({ QUALOR_DOTNET_ANALYZERS: dir }) }).io,
          silentLogger,
        ),
      ).toThrow(expect.objectContaining({ exitCode: EXIT.USAGE }));
    }
  });

  it('exits 2 when QUALOR_MSBUILD_USER_DIR is inside the repository (fix round 1, R5.1)', () => {
    const root = repo();
    expect(() =>
      runDotnetBegin(
        {},
        captureIO({
          cwd: root,
          env: env({ QUALOR_MSBUILD_USER_DIR: path.join(root, 'msbuild') }),
        }).io,
        silentLogger,
      ),
    ).toThrow(expect.objectContaining({ exitCode: EXIT.USAGE }));
    expect(readSession(root)).toBeNull();
  });

  it('warns, leaves the hook-failed marker and exits 0 under auto when the MSBuild user directory cannot be written, exits 3 under true (Review Focus 5, final review R10)', () => {
    const blocked = tmp();
    writeFileSync(path.join(blocked, 'Current'), 'a file where a directory must go');
    const root = repo();
    expect(
      runDotnetBegin(
        {},
        captureIO({ cwd: root, env: env({ QUALOR_MSBUILD_USER_DIR: blocked }) }).io,
        silentLogger,
      ),
    ).toBe(EXIT.OK);
    expect(readSession(root)).toBeNull();
    expect(readFileSync(path.join(root, '.qualor', 'dotnet', 'hook-failed'), 'utf8')).toMatch(
      /^cannot record the dotnet session lease in /,
    );
    expect(readdirSync(path.join(root, '.qualor', 'dotnet'))).toEqual(['hook-failed']);
    const strict = repo({ 'qualor.yml': 'version: 1\nanalyzers:\n  roslyn: { enabled: true }\n' });
    expect(() =>
      runDotnetBegin(
        {},
        captureIO({ cwd: strict, env: env({ QUALOR_MSBUILD_USER_DIR: blocked }) }).io,
        silentLogger,
      ),
    ).toThrow(expect.objectContaining({ exitCode: EXIT.ANALYZER_FAILED }));
  });

  it('installs no hook when the lease cannot be recorded, and exits 3 under enabled: true (fix round 1, R5.4; final review R9)', () => {
    const block = (userDir: string) => {
      mkdirSync(path.dirname(leaseDir(userDir)), { recursive: true });
      writeFileSync(leaseDir(userDir), 'a file where the lease directory must go');
    };
    const root = repo();
    const e = env();
    block(e.QUALOR_MSBUILD_USER_DIR);
    expect(runDotnetBegin({}, captureIO({ cwd: root, env: e }).io, silentLogger)).toBe(EXIT.OK);
    expect(readSession(root)).toBeNull();
    expect(existsSync(hookPath(e.QUALOR_MSBUILD_USER_DIR))).toBe(false);
    expect(existsSync(path.join(root, '.qualor', 'dotnet', 'hook-failed'))).toBe(true);

    const strict = repo({ 'qualor.yml': 'version: 1\nanalyzers:\n  roslyn: { enabled: true }\n' });
    const strictEnv = env();
    block(strictEnv.QUALOR_MSBUILD_USER_DIR);
    expect(() =>
      runDotnetBegin({}, captureIO({ cwd: strict, env: strictEnv }).io, silentLogger),
    ).toThrow(expect.objectContaining({ exitCode: EXIT.ANALYZER_FAILED }));
    expect(readSession(strict)).toBeNull();
    expect(existsSync(hookPath(strictEnv.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('records the lease before the hook, and releases it again when the hook cannot be installed (final review R9, R10)', () => {
    const root = repo();
    const e = env();
    const importBefore = path.dirname(hookPath(e.QUALOR_MSBUILD_USER_DIR));
    mkdirSync(path.dirname(importBefore), { recursive: true });
    writeFileSync(importBefore, 'a file where ImportBefore/ must go');
    expect(runDotnetBegin({}, captureIO({ cwd: root, env: e }).io, silentLogger)).toBe(EXIT.OK);
    expect(readSession(root)).toBeNull();
    // The lease directory was created (the lease came first), and holds nothing any more.
    expect(readdirSync(leaseDir(e.QUALOR_MSBUILD_USER_DIR))).toEqual([]);
    expect(readFileSync(path.join(root, '.qualor', 'dotnet', 'hook-failed'), 'utf8')).toMatch(
      /^cannot install the MSBuild hook in /,
    );
  });

  it('warns when the checkout path contains a comma (final review R12, M2)', () => {
    const parent = tmp();
    const root = path.join(parent, 'a,b');
    mkdirSync(path.join(root, '.git'), { recursive: true });
    const lines: string[] = [];
    expect(
      runDotnetBegin(
        {},
        captureIO({ cwd: root, env: env() }).io,
        createLogger('warn', (t) => lines.push(t)),
      ),
    ).toBe(EXIT.OK);
    expect(lines.join('')).toMatch(/comma/);
    expect(readSession(root)).not.toBeNull();
  });

  it('warns when dotnet telemetry is not turned off', () => {
    const lines: string[] = [];
    const e = env();
    delete (e as Record<string, string | undefined>).DOTNET_CLI_TELEMETRY_OPTOUT;
    runDotnetBegin(
      {},
      captureIO({ cwd: repo(), env: e }).io,
      createLogger('warn', (t) => lines.push(t)),
    );
    expect(lines.join('')).toMatch(/DOTNET_CLI_TELEMETRY_OPTOUT/);
  });
});
