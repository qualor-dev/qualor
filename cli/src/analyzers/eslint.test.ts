import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import {
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  recorded,
  scanFixtureWith,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createLogger } from '../log';
import {
  eslintAnalyzer,
  eslintJsonToSarif,
  eslintVersion,
  findEslintConfig,
  findLocalEslint,
} from './eslint';

const tmp = useTempDirs();
const REPO_NODE_MODULES = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../node_modules',
);
const exe = process.platform === 'win32' ? '.exe' : '';
const delimiter = process.platform === 'win32' ? ';' : ':';

/** Writes an executable file (a stand-in binary: these tests never start it). */
function executable(root: string, rel: string): string {
  writeTree(root, { [rel]: '#!/bin/sh\n' });
  const abs = path.join(root, ...rel.split('/'));
  chmodSync(abs, 0o755);
  return abs;
}

/** File symlinks need Developer Mode or elevation on Windows; probe once, like external.test.ts. */
function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    writeFileSync(path.join(dir, 'target.txt'), 'x');
    symlinkSync(path.join(dir, 'target.txt'), path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const CAN_SYMLINK_FILES = canCreateFileSymlinks();

describe('eslintJsonToSarif', () => {
  it('turns the recorded ts-basic output into exactly the fixture findings', () => {
    const sarif = eslintJsonToSarif(recorded('eslint-ts-basic.json'), '/fixture-root', '10.11.0');
    const out = normalizeRecorded(sarif, eslintAnalyzer, 'ts-basic');
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('ts-basic', 'eslint'));
    expect(out.engines[0]?.version).toBe('10.11.0');
    expect(out.engines[0]?.rules.find((r) => r.id === 'eqeqeq')).toEqual({
      id: 'eqeqeq',
      shortDescription: 'Require the use of `===` and `!==`',
      helpUri: 'https://eslint.org/docs/latest/rules/eqeqeq',
      quality: 'maintainability',
      kind: 'issue',
      languages: ['typescript', 'javascript'],
    });
    const eqeqeq = out.findings.find((f) => f.ruleId === 'eqeqeq');
    expect(eqeqeq?.location).toEqual({
      path: 'src/math.ts',
      startLine: 12,
      startColumn: 16,
      endLine: 12,
      endColumn: 17,
    });
  });

  it('drops messages without a rule id and percent-encodes relative paths', () => {
    const sarif = eslintJsonToSarif(
      {
        results: [
          {
            filePath: path.join('/r', 'dir with space', '100%.ts'),
            messages: [
              { ruleId: null, fatal: true, severity: 2, message: 'Parsing error', line: 1 },
              { ruleId: 'no-var', severity: 1, message: 'Unexpected var.', line: 3, column: 1 },
            ],
          },
        ],
        metadata: { rulesMeta: {} },
      },
      path.resolve('/r'),
      null,
    ) as { runs: { tool: { driver: Record<string, unknown> }; results: unknown[] }[] };
    const run = sarif.runs[0]!;
    expect(run.tool.driver).toEqual({
      name: 'ESLint',
      informationUri: 'https://eslint.org',
      rules: [{ id: 'no-var' }],
    });
    expect(run.results).toEqual([
      {
        ruleId: 'no-var',
        level: 'warning',
        message: { text: 'Unexpected var.' },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'dir%20with%20space/100%25.ts' },
              region: { startLine: 3, startColumn: 1 },
            },
          },
        ],
      },
    ]);
  });

  it('rejects output that is not ESLint JSON', () => {
    expect(() => eslintJsonToSarif({ results: 'nope' }, '/r', null)).toThrow();
  });
});

describe('ESLint discovery', () => {
  it('finds flat, legacy and package.json configurations, or none', () => {
    const flat = tmp();
    writeTree(flat, { 'eslint.config.mjs': 'export default [];\n' });
    expect(findEslintConfig(flat)).toBe('eslint.config.mjs');
    const legacy = tmp();
    writeTree(legacy, { '.eslintrc.json': '{}\n' });
    expect(findEslintConfig(legacy)).toBe('.eslintrc.json');
    const pkg = tmp();
    writeTree(pkg, { 'package.json': '{"eslintConfig": {}}\n' });
    expect(findEslintConfig(pkg)).toBe('package.json');
    const none = tmp();
    writeTree(none, { 'package.json': '{"name": "x"}\n' });
    expect(findEslintConfig(none)).toBeNull();
  });

  it('finds the project ESLint through its package.json bin, never outside the package', () => {
    const root = tmp();
    writeTree(root, {
      'node_modules/eslint/package.json':
        '{"version": "9.9.0", "bin": {"eslint": "./bin/eslint.js"}}',
      'node_modules/eslint/bin/eslint.js': '',
    });
    expect(findLocalEslint(root)).toEqual({
      script: path.join(root, 'node_modules', 'eslint', 'bin', 'eslint.js'),
      version: '9.9.0',
    });
    const escape = tmp();
    writeTree(escape, {
      'node_modules/eslint/package.json': '{"version": "9.9.0", "bin": "../../evil.js"}',
      'evil.js': '',
    });
    expect(findLocalEslint(escape)).toBeNull();
    expect(findLocalEslint(tmp())).toBeNull();
  });
});

describe('eslintAnalyzer.prepare', () => {
  it('skips a repository without an ESLint configuration', async () => {
    const root = tmp();
    expect(await eslintAnalyzer.prepare(fakeContext(root))).toEqual({
      skip: 'the repository has no ESLint configuration (none is bundled)',
    });
  });

  it('skips a configured configFile that does not exist', async () => {
    const root = tmp();
    const ctx = fakeContext(root, { config: { analyzers: { eslint: { configFile: 'x.js' } } } });
    expect(await eslintAnalyzer.prepare(ctx)).toEqual({ skip: 'configFile x.js does not exist' });
  });

  it('runs the project ESLint with node, the JSON formatter, the args and the config', async () => {
    const root = tmp();
    writeTree(root, {
      'lint/custom.mjs': 'export default [];\n',
      'node_modules/eslint/package.json':
        '{"version": "9.9.0", "bin": {"eslint": "bin/eslint.js"}}',
      'node_modules/eslint/bin/eslint.js': '',
    });
    const ctx = fakeContext(root, {
      config: {
        analyzers: { eslint: { configFile: 'lint/custom.mjs', args: ['--max-warnings', '5'] } },
      },
      binaries: { node: '/usr/bin/node' },
    });
    const prep = await eslintAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const out = path.join(ctx.workDir, 'eslint.json');
    expect(prep.run).toMatchObject({
      command: '/usr/bin/node',
      args: [
        path.join(root, 'node_modules', 'eslint', 'bin', 'eslint.js'),
        '--format',
        'json-with-metadata',
        '--output-file',
        out,
        '--no-color',
        '--config',
        path.join(root, 'lint', 'custom.mjs'),
        '--max-warnings',
        '5',
        '.',
      ],
      cwd: root,
      sarifPath: out,
      okExitCodes: [0, 1],
      version: '9.9.0',
    });
  });

  it('falls back to an ESLint on PATH and reads its version', async () => {
    const root = tmp();
    writeTree(root, { 'eslint.config.js': 'export default [];\n' });
    const ctx = fakeContext(root, {
      binaries: { eslint: '/opt/qualor/bin/eslint' },
      exec: () => ({
        exitCode: 0,
        timedOut: false,
        durationMs: 1,
        stdout: 'v9.30.1\n',
        stderr: '',
      }),
    });
    const prep = await eslintAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.command).toBe('/opt/qualor/bin/eslint');
    expect(prep.run.version).toBe('9.30.1');
  });

  it('skips when neither a project nor a PATH ESLint exists, or node is missing', async () => {
    const root = tmp();
    writeTree(root, { 'eslint.config.js': 'export default [];\n' });
    expect(await eslintAnalyzer.prepare(fakeContext(root))).toEqual({
      unavailable: 'ESLint is not installed (node_modules/eslint or PATH)',
    });
    writeTree(root, {
      'node_modules/eslint/package.json': '{"version": "9.9.0", "bin": "bin/eslint.js"}',
      'node_modules/eslint/bin/eslint.js': '',
    });
    expect(await eslintAnalyzer.prepare(fakeContext(root))).toEqual({
      unavailable: 'the project ESLint needs node on PATH',
    });
  });
});

describe('ESLint hardening (fix round 1)', () => {
  it('never runs a repository-supplied eslint shim or node when the project ESLint is rejected', async () => {
    const root = tmp();
    writeTree(root, {
      'eslint.config.js': 'export default [];\n',
      // A crafted package whose bin escapes node_modules/eslint: findLocalEslint rejects it...
      'node_modules/eslint/package.json': '{"version": "9.9.0", "bin": "../../evil.js"}',
      'evil.js': '',
    });
    // ...and the repository also plants an executable .bin shim, a node and an eslint at its root.
    executable(root, `node_modules/.bin/eslint${exe}`);
    executable(root, `eslint${exe}`);
    executable(root, `node${exe}`);
    const exec = vi.fn(() => ({
      exitCode: 0,
      timedOut: false,
      durationMs: 1,
      stdout: 'v9.0.0',
      stderr: '',
    }));
    // Even a PATH that names the repository's own directories (absolute or relative) finds nothing.
    const env = {
      PATH: [path.join(root, 'node_modules', '.bin'), root, '.', 'node_modules/.bin'].join(
        delimiter,
      ),
    };
    expect(await eslintAnalyzer.prepare(fakeContext(root, { env, exec }))).toEqual({
      unavailable:
        'ESLint is not installed (node_modules/eslint or PATH; an eslint binary inside the repository is not used)',
    });
    expect(exec).not.toHaveBeenCalled();

    // A genuine ESLint outside the repository is used, and only it is probed.
    const system = tmp();
    const eslint = executable(system, `eslint${exe}`);
    const prep = await eslintAnalyzer.prepare(
      fakeContext(root, { env: { PATH: `${env.PATH}${delimiter}${system}` }, exec }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.command).toBe(eslint);
    expect(exec).toHaveBeenCalledTimes(1);
    expect(exec).toHaveBeenCalledWith(eslint, ['--version'], expect.anything());
  });

  it('runs the project ESLint only with a node from outside the repository', async () => {
    const root = tmp();
    writeTree(root, {
      'eslint.config.js': 'export default [];\n',
      'node_modules/eslint/package.json': '{"version": "9.9.0", "bin": "bin/eslint.js"}',
      'node_modules/eslint/bin/eslint.js': '',
    });
    executable(root, `node_modules/.bin/node${exe}`);
    executable(root, `node${exe}`);
    const env = { PATH: [root, path.join(root, 'node_modules', '.bin')].join(delimiter) };
    expect(await eslintAnalyzer.prepare(fakeContext(root, { env }))).toEqual({
      unavailable:
        'the project ESLint needs node on PATH (a node inside the repository is not used)',
    });
    const system = tmp();
    const node = executable(system, `node${exe}`);
    const prep = await eslintAnalyzer.prepare(
      fakeContext(root, { env: { PATH: `${env.PATH}${delimiter}${system}` } }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.command).toBe(node);
  });

  it('keeps configFile inside the repository, also through a linked directory', async () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'eslint.config.js': 'export default [];\n' });
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    const ctx = (configFile: string) =>
      fakeContext(root, {
        config: { analyzers: { eslint: { configFile } } },
        binaries: { eslint: '/opt/qualor/bin/eslint' },
      });
    const rel = path.relative(root, path.join(outside, 'eslint.config.js'));
    expect(await eslintAnalyzer.prepare(ctx(rel))).toEqual({
      skip: `configFile ${rel} is outside the repository`,
    });
    const abs = path.join(outside, 'eslint.config.js');
    expect(await eslintAnalyzer.prepare(ctx(abs))).toEqual({
      skip: `configFile ${abs} is outside the repository`,
    });
    expect(await eslintAnalyzer.prepare(ctx('linked/eslint.config.js'))).toEqual({
      skip: 'configFile linked/eslint.config.js is outside the repository',
    });
    // A user-supplied name is bounded in the reason (fix round 2).
    const long = `${'x'.repeat(300)}.js`;
    expect(await eslintAnalyzer.prepare(ctx(long))).toEqual({
      skip: `configFile ${'x'.repeat(199)}… does not exist`,
    });
  });

  it.skipIf(!CAN_SYMLINK_FILES)(
    'follows a configuration symlink that stays inside the repository, and only that',
    () => {
      const inside = tmp();
      writeTree(inside, { 'config/eslint.config.js': 'export default [];\n' });
      symlinkSync(
        path.join(inside, 'config', 'eslint.config.js'),
        path.join(inside, 'eslint.config.js'),
        'file',
      );
      expect(findEslintConfig(inside)).toBe('eslint.config.js');
      const outside = tmp();
      writeTree(outside, { 'eslint.config.js': 'export default [];\n' });
      const escaping = tmp();
      symlinkSync(
        path.join(outside, 'eslint.config.js'),
        path.join(escaping, 'eslint.config.js'),
        'file',
      );
      expect(findEslintConfig(escaping)).toBeNull();
    },
  );

  it('skips a legacy eslintrc configuration this ESLint does not read, with a clear reason', async () => {
    const legacy = (
      version: string,
      files: Record<string, string>,
      env: Record<string, string> = {},
    ) => {
      const root = tmp();
      writeTree(root, {
        ...files,
        'node_modules/eslint/package.json': `{"version": "${version}", "bin": "bin/eslint.js"}`,
        'node_modules/eslint/bin/eslint.js': '',
      });
      return eslintAnalyzer.prepare(
        fakeContext(root, { binaries: { node: '/usr/bin/node' }, env }),
      );
    };
    expect(await legacy('9.9.0', { '.eslintrc.json': '{}\n' })).toEqual({
      skip: '.eslintrc.json is a legacy eslintrc configuration, which ESLint 9 does not read (migrate to eslint.config.js)',
    });
    expect(await legacy('10.0.0', { 'package.json': '{"eslintConfig": {}}\n' })).toEqual({
      skip: 'package.json is a legacy eslintrc configuration, which ESLint 10 does not read (migrate to eslint.config.js)',
    });
    expect(await legacy('8.57.0', { '.eslintrc.json': '{}\n' })).toHaveProperty('run');
    // ESLint 9 still reads eslintrc with ESLINT_USE_FLAT_CONFIG=false (fix round 2); 10 never does.
    const off = { ESLINT_USE_FLAT_CONFIG: 'false' };
    expect(await legacy('9.9.0', { '.eslintrc.json': '{}\n' }, off)).toHaveProperty('run');
    expect(await legacy('10.0.0', { '.eslintrc.json': '{}\n' }, off)).toEqual({
      skip: '.eslintrc.json is a legacy eslintrc configuration, which ESLint 10 does not read (migrate to eslint.config.js)',
    });
    // A flat config wins over a leftover eslintrc, as in ESLint itself.
    expect(
      await legacy('9.9.0', {
        '.eslintrc.json': '{}\n',
        'eslint.config.js': 'export default [];\n',
      }),
    ).toHaveProperty('run');
  });

  it('accepts only a bounded x.y.z version from package.json or --version', () => {
    expect(eslintVersion('v9.30.1\n')).toBe('9.30.1');
    expect(eslintVersion('10.0.0-rc.1')).toBe('10.0.0-rc.1');
    expect(eslintVersion(`9.0.0${'x'.repeat(200)}`)).toBeNull();
    expect(eslintVersion('9.0.0 \u001b[31m')).toBeNull();
    expect(eslintVersion('garbage')).toBeNull();
    const root = tmp();
    writeTree(root, {
      'node_modules/eslint/package.json': `{"version": "${'9'.repeat(300)}", "bin": "bin/eslint.js"}`,
      'node_modules/eslint/bin/eslint.js': '',
    });
    expect(findLocalEslint(root)?.version).toBeNull();
  });

  it('logs how many messages without a rule id it dropped, at debug level', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    eslintJsonToSarif(
      {
        results: [
          {
            filePath: path.resolve('/r/a.ts'),
            messages: [
              { ruleId: null, fatal: true, severity: 2, message: 'Parsing error', line: 1 },
              { ruleId: null, fatal: true, severity: 2, message: 'Parsing error', line: 2 },
            ],
          },
        ],
      },
      path.resolve('/r'),
      null,
      log,
    );
    expect(lines.join('')).toContain('eslint: dropped 2 message(s) without a rule id');
    expect(lines.join('')).not.toContain('Parsing error');
  });
});

describe('ESLint on the ts-basic fixture (real ESLint from the repo devDependencies)', () => {
  it('reports exactly the fixture findings', { timeout: 120_000 }, async () => {
    const { capture, keys } = await scanFixtureWith(eslintAnalyzer, 'ts-basic', tmp(), (root) =>
      symlinkSync(REPO_NODE_MODULES, path.join(root, 'node_modules'), 'junction'),
    );
    expect(capture.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(keys).toEqual(expectedKeys('ts-basic', 'eslint'));
  });
});
