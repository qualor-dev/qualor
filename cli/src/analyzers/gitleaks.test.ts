import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { parseConfig, reportSchema } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  describeWithTools,
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  sarifSample,
  scanFixtureWith,
} from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { commitAll, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { captureIO } from '../../test/io';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseCommandLine } from '../args';
import { createLogger, silentLogger } from '../log';
import { runScan } from '../scan/run';
import { discoverFiles } from '../discovery/discover';
import { Warnings } from '../warnings';
import { checkGitleaksConfig, gitleaksAnalyzer, parseGitleaksVersion } from './gitleaks';
import { gitleaksExtends, MAX_GITLEAKS_CONFIG_BYTES } from './gitleaks-config';
import { deadProxyEnv } from './offline';
import { runAnalyzers } from './runner';
import { semgrepAnalyzer } from './semgrep';

const tmp = useTempDirs();
/** The fake secret in fixtures/mixed-secrets/src/config.ts. */
const SECRET = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';

describe('gitleaksAnalyzer.prepare', () => {
  it('scans the working tree with SARIF output and exit code 0 on leaks, and asks for the version', async () => {
    const root = tmp();
    writeTree(root, { '.gitleaks.custom.toml': 'title = "x"\n' });
    const calls: string[][] = [];
    const ctx = fakeContext(root, {
      config: { analyzers: { gitleaks: { configFile: '.gitleaks.custom.toml' } } },
      binaries: { gitleaks: '/opt/qualor/bin/gitleaks' },
      exec: (command, args) => {
        calls.push([command, ...args]);
        return { exitCode: 0, timedOut: false, durationMs: 1, stdout: '8.30.1\n', stderr: '' };
      },
    });
    const prep = await gitleaksAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const out = path.join(ctx.workDir, 'gitleaks.sarif');
    expect(prep.run).toEqual({
      command: '/opt/qualor/bin/gitleaks',
      args: [
        'dir',
        '.',
        '--report-format',
        'sarif',
        '--report-path',
        out,
        '--config',
        path.join(root, '.gitleaks.custom.toml'),
        '--no-banner',
        '--no-color',
        '--log-level',
        'error',
        '--exit-code',
        '0',
      ],
      cwd: root,
      // Defence in depth, as for Semgrep: every HTTP(S) request goes to a dead proxy.
      env: deadProxyEnv(),
      sarifPath: out,
      okExitCodes: [0],
      version: '8.30.1',
    });
    expect(calls).toEqual([['/opt/qualor/bin/gitleaks', 'version']]);
  });

  it('skips a missing configFile or a missing gitleaks', async () => {
    const root = tmp();
    expect(
      await gitleaksAnalyzer.prepare(
        fakeContext(root, { config: { analyzers: { gitleaks: { configFile: 'gl.toml' } } } }),
      ),
    ).toEqual({ skip: 'configFile gl.toml does not exist' });
    expect(await gitleaksAnalyzer.prepare(fakeContext(root))).toEqual({
      unavailable: 'Gitleaks is not installed (gitleaks on PATH or in the scanner image)',
    });
  });

  it('parses the version output', () => {
    expect(parseGitleaksVersion('8.30.1\n')).toBe('8.30.1');
    expect(parseGitleaksVersion('v8.19.0')).toBe('8.19.0');
    expect(parseGitleaksVersion('dev')).toBeNull();
  });

  it('never runs a configuration checkConfig refuses (for callers other than qualor scan)', async () => {
    const root = tmp();
    writeTree(root, { '.gitleaks.toml': '[extend]\npath = "/etc/gitleaks.toml"\n' });
    expect(
      await gitleaksAnalyzer.prepare(
        fakeContext(root, { binaries: { gitleaks: '/opt/qualor/bin/gitleaks' } }),
      ),
    ).toEqual({
      skip: 'Gitleaks config .gitleaks.toml: extend.path "/etc/gitleaks.toml" is an absolute path (only repository files)',
    });
    expect(gitleaksAnalyzer.checkConfig).toBe(checkGitleaksConfig);
  });

  it('passes the checked .gitleaks.toml explicitly, so Gitleaks never searches for .gitleaks.<ext> (fix round 1)', async () => {
    const root = tmp();
    writeTree(root, {
      '.gitleaks.toml': 'title = "t"\n',
      // Viper would find this one first (json before toml) and parse it as TOML, unchecked.
      '.gitleaks.json': '[extend]\npath = "/etc/gitleaks.toml"\n',
    });
    const binaries = { gitleaks: '/opt/qualor/bin/gitleaks' };
    const args = async (env: Record<string, string> = {}) => {
      const prep = await gitleaksAnalyzer.prepare(fakeContext(root, { binaries, env }));
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      return prep.run.args;
    };
    const withRepoConfig = await args();
    expect(
      withRepoConfig.slice(
        withRepoConfig.indexOf('--config'),
        withRepoConfig.indexOf('--config') + 2,
      ),
    ).toEqual(['--config', path.join(root, '.gitleaks.toml')]);
    // The CI's own config keeps its precedence: no --config.
    expect(await args({ GITLEAKS_CONFIG: '/etc/ci/gitleaks.toml' })).not.toContain('--config');
    const bare = tmp();
    const prep = await gitleaksAnalyzer.prepare(fakeContext(bare, { binaries }));
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args).not.toContain('--config');
  });
});

describe('gitleaksExtends: the [extend] keys of a Gitleaks TOML config', () => {
  const ok = (text: string) => gitleaksExtends(Buffer.from(text));

  it('finds extend.path in every spelling viper accepts (keys are case-insensitive)', () => {
    for (const text of [
      '[extend]\npath = "a.toml"\n',
      '[ Extend ]\n  Path = "a.toml" # comment\n',
      "[EXTEND]\nPATH = 'a.toml'\n",
      'extend.path = "a.toml"\n',
      '"extend".path = "a.toml"\n',
      "'extend'.'path' = \"a.toml\"\n",
      '"\\u0065xtend".path = "a\\u002etoml"\n',
      '"extend.path" = "a.toml"\n',
      'extend = { path = "a.toml", useDefault = false }\n',
      'title = "t"\n[extend]\nuseDefault = false\npath = """a.toml"""\ndisabledRules = [ "x",\n  "y", # c\n]\n',
    ]) {
      expect(ok(text), text).toEqual({ paths: ['a.toml'] });
    }
  });

  it('is not fooled by strings or comments that look like [extend]', () => {
    const text =
      '# [extend]\n# path = "/etc/x"\ntitle = """\n[extend]\npath = "/etc/x"\n"""\n' +
      "[[rules]]\nid = 'r'\nregex = '''(?i)[extend]\"path\\\"'''\nkeywords = ['a', \"b\"]\n" +
      "[rules.allowlist]\npaths = ['''x''']\n[allowlist]\ndescription = \"extend.path = \\\"/x\\\"\"\n";
    expect(ok(text)).toEqual({ paths: [] });
    expect(ok('[extend]\nuseDefault = true\n')).toEqual({ paths: [] });
  });

  it('refuses what it cannot check with certainty', () => {
    const bad = (text: string | Buffer, error: string) =>
      expect(
        gitleaksExtends(typeof text === 'string' ? Buffer.from(text) : text),
        String(text),
      ).toEqual({
        error,
      });
    bad('[extend]\nurl = "https://x/y.toml"\n', 'has extend.url, which Qualor does not check');
    bad('[extend.sub]\npath = "a"\n', 'has extend.sub.path, which Qualor does not check');
    bad('[[extend]]\npath = "a"\n', 'has an [[extend]] array, which Qualor does not check');
    bad('extend = "a.toml"\n', 'has an extend that is not a table');
    bad('[extend]\npath = 1\n', 'has an extend.path that is not a string');
    bad('[extend]\npath = ["a"]\n', 'has an extend.path that is not a string');
    bad('[extend\npath = "a"\n', 'cannot be parsed as TOML');
    bad('[extend]\npath = "a\n', 'cannot be parsed as TOML');
    bad('[extend]\npath = "\\q"\n', 'cannot be parsed as TOML');
    bad('[extend] x\n', 'cannot be parsed as TOML');
    bad('a = 1 b = 2\n', 'cannot be parsed as TOML');
    bad(Buffer.from([0x61, 0x20, 0x3d, 0x20, 0x22, 0xff, 0x22, 0x0a]), 'is not UTF-8');
    // A lone CR or a control character: TOML (and Gitleaks) reject them; a reader that treated
    // `# c\r[extend]` as one comment line would miss the table.
    bad('# c\r[extend]\rpath = "/tmp/o.toml"\n', 'cannot be parsed as TOML');
    bad('# c\u000b\n[extend]\npath = "a"\n', 'cannot be parsed as TOML');
    bad('title = "a\u0000b"\n', 'cannot be parsed as TOML');
  });
});

describe('checkGitleaksConfig (containment, ruling V4)', () => {
  const check = (
    root: string,
    gitleaks: Record<string, unknown> = {},
    env: Record<string, string | undefined> = {},
  ) => checkGitleaksConfig(root, parseConfig({ version: 1, analyzers: { gitleaks } }), env);

  it('accepts no config, a contained configFile and a contained chain of extends', () => {
    const root = tmp();
    expect(check(root)).toBeNull();
    writeTree(root, {
      '.gitleaks.toml': '[extend]\npath = "config/base.toml"\n',
      'config/base.toml': '[extend]\nuseDefault = true\n',
      'config/custom.toml': '[extend]\npath = ".gitleaks.toml"\n',
      '.gitleaksignore': 'src/a.ts:generic-api-key:2\n',
    });
    expect(check(root)).toBeNull();
    expect(check(root, { configFile: 'config/custom.toml' })).toBeNull();
  });

  it('refuses a configFile that is a URL or outside the repository', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'g.toml': 'title = "x"\n' });
    const rel = path.relative(root, path.join(outside, 'g.toml')).split(path.sep).join('/');
    expect(check(root, { configFile: 'https://x/g.toml' })).toBe(
      'configFile https://x/g.toml is a URL (only repository files)',
    );
    for (const f of [path.join(outside, 'g.toml'), rel]) {
      expect(check(root, { configFile: f })).toBe(`configFile ${f} is outside the repository`);
    }
  });

  it('refuses an extend path that is absolute, a URL, outside the repository or missing, also deeper in the chain', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'o.toml': 'title = "o"\n' });
    const rel = path.relative(root, path.join(outside, 'o.toml')).split(path.sep).join('/');
    const at = (file: string, target: string, why: string) =>
      `Gitleaks config ${file}: extend.path "${target}" ${why}`;
    const cases: [string, string][] = [
      [path.join(outside, 'o.toml'), 'is an absolute path (only repository files)'],
      ['/etc/gitleaks.toml', 'is an absolute path (only repository files)'],
      ['C:\\gitleaks.toml', 'is an absolute path (only repository files)'],
      ['https://x/g.toml', 'is a URL (only repository files)'],
      [rel, 'is outside the repository'],
      ['config/missing.toml', 'does not exist'],
    ];
    for (const [target, why] of cases) {
      writeTree(root, { '.gitleaks.toml': `[extend]\npath = '${target}'\n` });
      expect(check(root), target).toBe(at('.gitleaks.toml', target, why));
    }
    writeTree(root, {
      '.gitleaks.toml': '[extend]\npath = "a.toml"\n',
      'a.toml': `[extend]\npath = '${rel}'\n`,
    });
    expect(check(root)).toBe(at('a.toml', rel, 'is outside the repository'));
    // A cycle ends; Gitleaks itself stops at its extend depth.
    writeTree(root, { 'a.toml': '[extend]\npath = ".gitleaks.toml"\n' });
    expect(check(root)).toBeNull();
  });

  it('refuses an unreadable, oversized or unparsable repository config', () => {
    const root = tmp();
    writeTree(root, { '.gitleaks.toml': `# ${'x'.repeat(MAX_GITLEAKS_CONFIG_BYTES)}\n` });
    expect(check(root)).toBe(
      `Gitleaks config .gitleaks.toml is larger than ${MAX_GITLEAKS_CONFIG_BYTES / 1024 / 1024} MiB`,
    );
    writeTree(root, { '.gitleaks.toml': '[extend\n' });
    expect(check(root)).toBe('Gitleaks config .gitleaks.toml cannot be parsed as TOML');
    const dir = tmp();
    mkdirSync(path.join(dir, '.gitleaks.toml'));
    mkdirSync(path.join(dir, '.gitleaksignore'));
    expect(check(dir)).toBe('.gitleaks.toml is not a regular file');
    writeTree(dir, { 'g.toml': 'title = "x"\n' });
    expect(check(dir, { configFile: 'g.toml' })).toBe('.gitleaksignore is not a regular file');
  });

  it('leaves a config the CI names in GITLEAKS_CONFIG or GITLEAKS_CONFIG_TOML to the CI (it wins over .gitleaks.toml)', () => {
    const root = tmp();
    writeTree(root, { '.gitleaks.toml': '[extend]\npath = "/etc/x.toml"\n' });
    expect(check(root, {}, { GITLEAKS_CONFIG: '/etc/ci/gitleaks.toml' })).toBeNull();
    expect(check(root, {}, { GITLEAKS_CONFIG_TOML: 'title = "ci"\n' })).toBeNull();
    expect(check(root, {}, { GITLEAKS_CONFIG: '' })).not.toBeNull();
  });

  it('ignores every other .gitleaks.* file: the checked .gitleaks.toml is passed as --config, so Gitleaks never reads them', () => {
    const root = tmp();
    writeTree(root, {
      '.gitleaks.toml': 'title = "t"\n',
      '.gitleaks.json': '[extend]\npath = "/etc/x.toml"\n',
      '.gitleaks.yaml': '[extend]\nurl = "https://x"\n',
    });
    expect(check(root)).toBeNull();
    const alone = tmp();
    writeTree(alone, { '.gitleaks.json': '[extend]\npath = "/etc/x.toml"\n' });
    expect(check(alone)).toBeNull();
  });

  it.runIf(process.platform !== 'win32')(
    'refuses a config or ignore file that links out of the repository',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'g.toml': 'title = "x"\n', ign: 'x:y:1\n' });
      writeTree(root, { 'config/in.toml': 'title = "in"\n' });
      symlinkSync(path.join(outside, 'g.toml'), path.join(root, '.gitleaks.toml'));
      expect(check(root)).toBe('.gitleaks.toml is outside the repository');
      expect(check(root, { configFile: '.gitleaks.toml' })).toBe(
        'configFile .gitleaks.toml is outside the repository',
      );
      symlinkSync(outside, path.join(root, 'linked'));
      expect(check(root, { configFile: 'linked/g.toml' })).toBe(
        'configFile linked/g.toml is outside the repository',
      );
      writeTree(root, { 'x.toml': '[extend]\npath = "linked/g.toml"\n' });
      expect(check(root, { configFile: 'x.toml' })).toBe(
        'Gitleaks config x.toml: extend.path "linked/g.toml" is outside the repository',
      );
      symlinkSync(path.join(outside, 'ign'), path.join(root, '.gitleaksignore'));
      expect(check(root, { configFile: 'config/in.toml' })).toBe(
        '.gitleaksignore is outside the repository',
      );
    },
  );

  it.runIf(process.platform !== 'win32')('refuses a FIFO, which would hang Gitleaks', () => {
    const root = tmp();
    if (spawnSync('mkfifo', [path.join(root, '.gitleaksignore')]).status !== 0) return;
    expect(check(root)).toBe('.gitleaksignore is not a regular file');
  });
});

describe('Gitleaks SARIF (recorded Gitleaks 8.30.1 output on mixed-secrets)', () => {
  it('normalises to exactly the fixture finding and never carries the secret', () => {
    const out = normalizeRecorded(sarifSample('gitleaks'), gitleaksAnalyzer, 'mixed-secrets');
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('mixed-secrets', 'gitleaks'));
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out.findings[0]?.snippet?.lines).toContain('const a«redacted»;');
  });
});

describeWithTools(['gitleaks'])('Gitleaks on the mixed-secrets fixture (real Gitleaks)', () => {
  it('reports exactly the fixture finding, redacted', { timeout: 300_000 }, async () => {
    const { capture, out, keys } = await scanFixtureWith(gitleaksAnalyzer, 'mixed-secrets', tmp());
    expect(capture.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(keys).toEqual(expectedKeys('mixed-secrets', 'gitleaks'));
    expect(JSON.stringify(out)).not.toContain(SECRET);
  });

  // Fix round 1 of tasks 5-6: with a .gitleaks.toml present, Gitleaks' viper searched
  // .gitleaks.<ext> (json first) and parsed the first match as TOML, unchecked.
  const RULE = (id: string) =>
    `title = "${id}"\n[[rules]]\nid = "${id}"\nregex = '''Zx9Qe4Lr8'''\n`;

  it(
    'G1: never loads a sibling .gitleaks.json that extends a file outside the repository',
    { timeout: 300_000 },
    async () => {
      const outside = tmp();
      writeTree(outside, { 'o.toml': RULE('outside-rule') });
      const { keys } = await scanFixtureWith(gitleaksAnalyzer, 'mixed-secrets', tmp(), (root) =>
        writeTree(root, {
          '.gitleaks.toml': RULE('from-toml'),
          '.gitleaks.json': `[extend]\npath = '${path.join(outside, 'o.toml')}'\n`,
        }),
      );
      expect(keys).toEqual(['gitleaks:from-toml src/config.ts:2 [blocker]']);
    },
  );

  it.runIf(process.platform !== 'win32')(
    'G2: never opens a sibling .gitleaks.json that links out, or a .gitleaks.yml FIFO',
    { timeout: 300_000 },
    async () => {
      const outside = tmp();
      writeTree(outside, { 'o.toml': RULE('outside-rule') });
      const { capture, keys } = await scanFixtureWith(
        gitleaksAnalyzer,
        'mixed-secrets',
        tmp(),
        (root) => {
          writeTree(root, {
            '.gitleaks.toml': RULE('from-toml'),
            'qualor.yml': 'version: 1\nanalyzers:\n  gitleaks:\n    timeoutSeconds: 60\n',
          });
          symlinkSync(path.join(outside, 'o.toml'), path.join(root, '.gitleaks.json'));
          if (spawnSync('mkfifo', [path.join(root, '.gitleaks.yml')]).status !== 0) {
            throw new Error('mkfifo failed');
          }
        },
      );
      expect(capture.status).toBe('ok');
      expect(keys).toEqual(['gitleaks:from-toml src/config.ts:2 [blocker]']);
    },
  );

  it(
    'ignores a .gitleaks.json without a .gitleaks.toml (Gitleaks then uses its default rules)',
    { timeout: 300_000 },
    async () => {
      const outside = tmp();
      writeTree(outside, { 'o.toml': RULE('outside-rule') });
      const { keys } = await scanFixtureWith(gitleaksAnalyzer, 'mixed-secrets', tmp(), (root) =>
        writeTree(root, {
          '.gitleaks.json': `[extend]\npath = '${path.join(outside, 'o.toml')}'\n`,
        }),
      );
      expect(keys).toEqual(expectedKeys('mixed-secrets', 'gitleaks'));
    },
  );

  it(
    'honours a contained .gitleaksignore (the repository suppresses its own finding)',
    { timeout: 300_000 },
    async () => {
      const { keys } = await scanFixtureWith(gitleaksAnalyzer, 'mixed-secrets', tmp(), (root) =>
        writeTree(root, { '.gitleaksignore': 'src/config.ts:generic-api-key:2\n' }),
      );
      expect(keys).toEqual([]);
    },
  );
});

describeWithTools(['gitleaks', ['opengrep', 'semgrep']])(
  'report-format §10.4 with the real tools: the secret is nowhere in the gzipped report',
  () => {
    it('byte-searches the report of a mixed-secrets scan', { timeout: 300_000 }, async () => {
      const repo = path.join(tmp(), 'repo');
      cpSync(path.join(FIXTURES_DIR, 'mixed-secrets'), repo, { recursive: true });
      initRepo(repo);
      commitAll(repo, 'fixture');
      const command = parseCommandLine([
        'scan',
        '--dry-run',
        '--output',
        'r.json.gz',
        '--project-key',
        'fixtures/mixed-secrets',
      ]);
      if (command.name !== 'scan') throw new Error('not a scan');
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(command.flags, c.io, silentLogger, {
        analyzers: [gitleaksAnalyzer, semgrepAnalyzer],
      });
      expect(code, c.stderr()).toBe(0);
      const bytes = readFileSync(path.join(repo, 'r.json.gz'));
      const json = gunzipSync(bytes).toString('utf8');
      expect(json).not.toContain(SECRET);
      const report = reportSchema.parse(JSON.parse(json));
      expect(report.engines.map((e) => [e.id, e.status])).toEqual([
        ['gitleaks', 'ok'],
        ['semgrep', 'ok'],
      ]);
      // Both engines flag config.ts:2; both snippets show the redaction marker instead.
      const onConfig = report.findings.filter((f) => f.location?.path === 'src/config.ts');
      expect(onConfig.map((f) => f.ruleId).sort()).toEqual([
        'generic-api-key',
        'hardcoded-api-key',
      ]);
      for (const f of onConfig) expect(f.snippet?.lines.join('\n')).toContain('«redacted»');
    });

    it(
      "keeps the secret out of every log line, the tools' stdout and stderr included",
      { timeout: 300_000 },
      async () => {
        const root = tmp();
        cpSync(path.join(FIXTURES_DIR, 'mixed-secrets'), root, { recursive: true });
        const config = parseConfig({ version: 1 });
        const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
        const lines: string[] = [];
        const captures = await runAnalyzers([gitleaksAnalyzer, semgrepAnalyzer], {
          root,
          config: parseConfig({
            version: 1,
            analyzers: { semgrep: { configs: ['semgrep/rules.yml'] } },
          }),
          files,
          log: createLogger('debug', (t) => lines.push(t)),
        });
        expect(captures.map((c) => [c.engineId, c.status])).toEqual([
          ['gitleaks', 'ok'],
          ['semgrep', 'ok'],
        ]);
        expect(lines.length).toBeGreaterThan(0);
        expect(lines.join('')).not.toContain(SECRET);
        // A failing run: the reason is fixed, never the tool's output.
        writeTree(root, { 'bad.toml': '[extend]\nuseDefault = true\npath = "x.toml"\n' });
        writeTree(root, { 'x.toml': 'title = "x"\n' });
        const [failed] = await runAnalyzers([gitleaksAnalyzer], {
          root,
          config: parseConfig({ version: 1, analyzers: { gitleaks: { configFile: 'bad.toml' } } }),
          files,
          log: createLogger('debug', (t) => lines.push(t)),
        });
        expect(failed).toMatchObject({ status: 'failed', reason: 'exited with code 1' });
        expect(lines.join('')).not.toContain(SECRET);
      },
    );
  },
);
