import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';
import { parseConfig, reportSchema } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  describeWithTools,
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  recorded,
  sarifSample,
  scanFixtureWith,
  startListener,
  toolInstalled,
} from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { commitAll, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { captureIO } from '../../test/io';
import { parseCommandLine } from '../args';
import { runScan } from '../scan/run';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { resolveBinary } from './binary';
import { deadProxyEnv } from './offline';
import { runProcess } from './process';
import { runAnalyzers } from './runner';
import {
  checkSemgrepConfig,
  createSemgrepAnalyzer,
  isOpengrepVariable,
  MAX_RULE_FILE_BYTES,
  MAX_SEMGREP_CONFIGS,
  offlineFlags,
  resolveConfigs,
  semgrepAnalyzer,
} from './semgrep';

const tmp = useTempDirs();

const RULE = (id: string, extra = '') =>
  `rules:\n  - id: ${id}\n    pattern: eval(...)\n    message: m\n    languages: [javascript]\n    severity: ERROR\n${extra}`;
const JOIN_RULE = (ref: string) =>
  'rules:\n  - id: joined\n    mode: join\n    message: m\n    severity: ERROR\n    join:\n' +
  `      refs:\n        - rule: ${ref}\n          as: a\n      on:\n        - 'a.$X == a.$X'\n`;

describe('Semgrep/OpenGrep inputs', () => {
  it('keeps both tools offline and the rule ids stable', () => {
    expect(offlineFlags('semgrep')).toEqual([
      '--metrics=off',
      '--disable-version-check',
      '--no-rewrite-rule-ids',
      '--quiet',
    ]);
    expect(offlineFlags('opengrep')).toEqual([
      '--disable-version-check',
      '--no-rewrite-rule-ids',
      '--quiet',
    ]);
  });

  it('resolves qualor-default to the image rule pack and local configs to absolute paths', () => {
    const root = tmp();
    const pack = tmp();
    writeTree(root, { 'rules/a.yml': 'rules: []\n' });
    writeTree(pack, { 'java/a.yaml': 'rules: []\n' });
    expect(resolveConfigs(root, ['qualor-default', 'rules/a.yml'], pack)).toEqual([
      pack,
      path.join(root, 'rules', 'a.yml'),
    ]);
    expect(resolveConfigs(root, ['rules/missing.yml'], pack)).toEqual({
      skip: 'config rules/missing.yml does not exist',
    });
    expect(resolveConfigs(root, ['qualor-default'], path.join(pack, 'absent'))).toEqual({
      skip: 'qualor-default rules come with the qualor/scanner image; set analyzers.semgrep.configs to local rule files',
    });
  });

  it('treats a qualor-default directory without rule files as no rules (the image ships none)', () => {
    const root = tmp();
    const empty = tmp();
    writeTree(empty, { 'README.md': 'no rules yet\n' });
    writeTree(root, { 'rules/a.yml': 'rules: []\n' });
    const skip = {
      skip: 'the qualor/scanner image ships no Semgrep rules yet; set analyzers.semgrep.configs to local rule files',
    };
    expect(resolveConfigs(root, ['qualor-default'], empty)).toEqual(skip);
    // The repository's own rules still run; only the empty default is dropped.
    expect(resolveConfigs(root, ['qualor-default', 'rules/a.yml'], empty)).toEqual([
      path.join(root, 'rules', 'a.yml'),
    ]);
  });

  it('refuses URLs, paths outside the repository and too many configs (offline, ruling V4)', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'r.yml': RULE('x') });
    const rel = path.relative(root, path.join(outside, 'r.yml')).split(path.sep).join('/');
    expect(resolveConfigs(root, ['git+https://example.com/r.git'], outside)).toEqual({
      error: 'config git+https://example.com/r.git is a URL (the tool would download it)',
    });
    expect(resolveConfigs(root, ['file:///etc/r.yml'], outside)).toEqual({
      error: 'config file:///etc/r.yml is a URL (the tool would download it)',
    });
    for (const c of [path.join(outside, 'r.yml'), rel]) {
      expect(resolveConfigs(root, [c], outside)).toEqual({
        error: `config ${c} is outside the repository`,
      });
    }
    expect(
      resolveConfigs(
        root,
        Array.from({ length: MAX_SEMGREP_CONFIGS + 1 }, () => 'r.yml'),
        outside,
      ),
    ).toEqual({ error: `more than ${MAX_SEMGREP_CONFIGS} configs` });
    expect(resolveConfigs(root, ['r\u001b[2J.yml'], outside)).toEqual({
      skip: 'config r?[2J.yml does not exist',
    });
  });

  it.runIf(process.platform !== 'win32')(
    'refuses a config that links out of the repository',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'r.yml': RULE('x') });
      symlinkSync(path.join(outside, 'r.yml'), path.join(root, 'r.yml'));
      symlinkSync(outside, path.join(root, 'rules'));
      expect(resolveConfigs(root, ['r.yml'], outside)).toEqual({
        error: 'config r.yml is outside the repository',
      });
      expect(resolveConfigs(root, ['rules/r.yml'], outside)).toEqual({
        error: 'config rules/r.yml is outside the repository',
      });
    },
  );
});

describe('checkSemgrepConfig (offline: no rule may load rules from elsewhere)', () => {
  const check = (root: string, configs: string[]) =>
    checkSemgrepConfig(root, parseConfig({ version: 1, analyzers: { semgrep: { configs } } }));

  it('accepts plain local rule files and directories, and never looks at qualor-default', () => {
    const root = tmp();
    writeTree(root, {
      'r.yml': RULE('a'),
      'rules/b.yaml': RULE('b'),
      'rules/sub/c.json': JSON.stringify({ rules: [] }),
      'rules/readme.md': 'not a rule file',
    });
    expect(check(root, ['r.yml', 'rules', 'qualor-default', 'missing.yml'])).toBeNull();
  });

  it('refuses a join rule, which fetches the rules it references (verified with both tools)', () => {
    const root = tmp();
    writeTree(root, {
      'join.yml': JOIN_RULE('http://127.0.0.1:9/r.yml'),
      'rules/ok.yml': RULE('ok'),
      'rules/deep/j.yaml': JOIN_RULE('p/javascript'),
      'merged.yml':
        'base: &b\n  mode: join\nrules:\n  - <<: *b\n    id: m\n    message: m\n    severity: ERROR\n',
      'keyed.yml': 'rules:\n  - id: k\n    "join": {}\n',
    });
    const msg = (file: string, id: string) =>
      `rule file ${file}: rule ${id} is a join rule, which can load rules from a URL or the registry (not supported)`;
    expect(check(root, ['join.yml'])).toBe(msg('join.yml', 'joined'));
    expect(check(root, ['rules'])).toBe(msg('rules/deep/j.yaml', 'joined'));
    expect(check(root, ['merged.yml'])).toBe(msg('merged.yml', 'm'));
    expect(check(root, ['keyed.yml'])).toBe(msg('keyed.yml', 'k'));
  });

  it('refuses what it cannot check with certainty', () => {
    const root = tmp();
    writeTree(root, {
      'bad.yml': 'rules: [\n',
      'dup.yml': 'rules: []\nrules: []\n',
      'bin.yml': new Uint8Array([0x72, 0x3a, 0x20, 0xff, 0xfe, 0x0a]),
      'r.jsonnet': "local x = import 'p/python';\nx\n",
      'lib/x.libsonnet': '{}',
      'big.yml': `# ${'x'.repeat(MAX_RULE_FILE_BYTES)}\n`,
      'bomb.yml': `a: &a [x, x, x, x, x, x, x, x, x, x]\n${Array.from(
        { length: 8 },
        (_, i) =>
          `${String.fromCharCode(98 + i)}: &${String.fromCharCode(98 + i)} [${Array(10)
            .fill(`*${String.fromCharCode(97 + i)}`)
            .join(', ')}]`,
      ).join('\n')}\nrules: []\n`,
    });
    expect(check(root, ['bad.yml'])).toBe('rule file bad.yml cannot be parsed as YAML');
    expect(check(root, ['dup.yml'])).toBe('rule file dup.yml cannot be parsed as YAML');
    expect(check(root, ['bin.yml'])).toBe('rule file bin.yml is not UTF-8');
    expect(check(root, ['r.jsonnet'])).toBe(
      'rule file r.jsonnet is Jsonnet (not supported: its import could name a registry pack or a URL)',
    );
    expect(check(root, ['lib'])).toBe(
      'rule file lib/x.libsonnet is Jsonnet (not supported: its import could name a registry pack or a URL)',
    );
    expect(check(root, ['big.yml'])).toBe(
      `rule file big.yml is larger than ${MAX_RULE_FILE_BYTES / 1024 / 1024} MiB`,
    );
    expect(check(root, ['bomb.yml'])).toBe('rule file bomb.yml cannot be parsed as YAML');
    // A URL never gets this far: the qualor.yml schema refuses it (exit 2).
    expect(() => check(root, ['git+https://x/r.git'])).toThrow(/analyzers\.semgrep\.configs/);
  });

  it.runIf(process.platform !== 'win32')(
    'judges a link by its target (a .yml link to Jsonnet) and never opens a FIFO',
    () => {
      const root = tmp();
      writeTree(root, { 'real.jsonnet': '{}', 'rules/ok.yml': RULE('ok') });
      symlinkSync(path.join(root, 'real.jsonnet'), path.join(root, 'r.yml'));
      symlinkSync(path.join(root, 'real.jsonnet'), path.join(root, 'rules', 'x.yml'));
      const jsonnet = (f: string) =>
        `rule file ${f} is Jsonnet (not supported: its import could name a registry pack or a URL)`;
      expect(check(root, ['r.yml'])).toBe(jsonnet('r.yml'));
      expect(check(root, ['rules'])).toBe(jsonnet('rules/x.yml'));
      const fifo = tmp();
      writeTree(fifo, { 'rules/ok.yml': RULE('ok') });
      if (
        spawnSync('mkfifo', [path.join(fifo, 'f.yml'), path.join(fifo, 'rules', 'g.yaml')])
          .status !== 0
      )
        return;
      expect(check(fifo, ['f.yml'])).toBe('rule file f.yml is not a regular file');
      expect(check(fifo, ['rules'])).toBe('rule file rules/g.yaml is not a regular file');
    },
  );

  it.runIf(process.platform !== 'win32')(
    'refuses a rule directory with a link out of the repository',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'r.yml': RULE('x') });
      writeTree(root, { 'rules/ok.yml': RULE('ok') });
      symlinkSync(outside, path.join(root, 'rules', 'more'));
      expect(check(root, ['rules'])).toBe('rule file rules/more links outside the repository');
    },
  );
});

describe('semgrepAnalyzer.prepare', () => {
  const setup = () => {
    const root = tmp();
    writeTree(root, { 'rules.yml': 'rules: []\n' });
    return root;
  };
  const config = { analyzers: { semgrep: { configs: ['rules.yml'] } } };

  it('prefers OpenGrep under binary: auto', async () => {
    const root = setup();
    const ctx = fakeContext(root, {
      config,
      binaries: { opengrep: '/opt/qualor/bin/opengrep', semgrep: '/usr/bin/semgrep' },
    });
    const prep = await semgrepAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const out = path.join(ctx.workDir, 'semgrep.sarif');
    expect(prep.run).toEqual({
      command: '/opt/qualor/bin/opengrep',
      args: [
        'scan',
        '--config',
        path.join(root, 'rules.yml'),
        '--sarif',
        '--output',
        out,
        '--disable-version-check',
        '--no-rewrite-rule-ids',
        '--quiet',
        '.',
      ],
      cwd: root,
      // Defence in depth: every HTTP(S) request of the tool goes to a dead proxy.
      env: deadProxyEnv(),
      dropEnv: isOpengrepVariable,
      sarifPath: out,
      okExitCodes: [0],
      version: null,
    });
  });

  it('never passes SEMGREP_* or OPENGREP_* variables to the tool (plan 6B-1)', async () => {
    const root = setup();
    const installed: Record<string, string>[] = [{ opengrep: '/o' }, { semgrep: '/s' }];
    for (const binaries of installed) {
      const prep = await semgrepAnalyzer.prepare(fakeContext(root, { config, binaries }));
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      expect(prep.run.dropEnv).toBe(isOpengrepVariable);
    }
  });

  it('runs Semgrep with --metrics=off when it is the one installed or the one asked for', async () => {
    const root = setup();
    const onlySemgrep = await semgrepAnalyzer.prepare(
      fakeContext(root, { config, binaries: { semgrep: '/usr/bin/semgrep' } }),
    );
    const asked = await semgrepAnalyzer.prepare(
      fakeContext(root, {
        config: { analyzers: { semgrep: { configs: ['rules.yml'], binary: 'semgrep' } } },
        binaries: { opengrep: '/o', semgrep: '/usr/bin/semgrep' },
      }),
    );
    for (const prep of [onlySemgrep, asked]) {
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      expect(prep.run.command).toBe('/usr/bin/semgrep');
      expect(prep.run.args).toContain('--metrics=off');
    }
  });

  it('skips when the tool is missing', async () => {
    const root = setup();
    expect(await semgrepAnalyzer.prepare(fakeContext(root, { config }))).toEqual({
      unavailable: 'OpenGrep or Semgrep is not installed',
    });
    expect(
      await semgrepAnalyzer.prepare(
        fakeContext(root, {
          config: { analyzers: { semgrep: { configs: ['rules.yml'], binary: 'opengrep' } } },
          binaries: { semgrep: '/usr/bin/semgrep' },
        }),
      ),
    ).toEqual({ unavailable: 'opengrep is not installed' });
  });

  it('never runs a configuration checkConfig refuses (for callers other than qualor scan)', async () => {
    const root = setup();
    writeTree(root, { 'join.yml': JOIN_RULE('p/x') });
    const binaries = { opengrep: '/opt/qualor/bin/opengrep' };
    expect(
      await semgrepAnalyzer.prepare(
        fakeContext(root, {
          config: { analyzers: { semgrep: { configs: ['join.yml'] } } },
          binaries,
        }),
      ),
    ).toEqual({
      skip: 'rule file join.yml: rule joined is a join rule, which can load rules from a URL or the registry (not supported)',
    });
    expect(
      await semgrepAnalyzer.prepare(
        fakeContext(root, {
          config: { analyzers: { semgrep: { configs: ['../x.yml'] } } },
          binaries,
        }),
      ),
    ).toEqual({ skip: 'config ../x.yml is outside the repository' });
    expect(semgrepAnalyzer.checkConfig).toBe(checkSemgrepConfig);
  });
});

describe('recorded Semgrep 1.178.0 and OpenGrep 1.30.0 output on mixed-secrets', () => {
  it.each([
    ['Semgrep', sarifSample('semgrep'), '1.178.0'],
    ['OpenGrep', recorded('opengrep-mixed-secrets.sarif'), '1.30.0'],
  ])('%s normalises to exactly the fixture findings', (_name, sarif, version) => {
    const out = normalizeRecorded(sarif, semgrepAnalyzer, 'mixed-secrets');
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('mixed-secrets', 'semgrep'));
    expect(out.engines[0]?.version).toBe(version);
    const secretFinding = out.findings.find((f) => f.ruleId === 'hardcoded-api-key');
    expect(JSON.stringify(secretFinding)).not.toContain('Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1');
    expect(out.engines[0]?.rules.find((r) => r.id === 'hardcoded-api-key')?.cwe).toEqual([798]);
  });
});

describeWithTools([['opengrep', 'semgrep']])(
  'Semgrep/OpenGrep on the mixed-secrets fixture (real tool, offline)',
  () => {
    it(
      'reports exactly the fixture findings with the fixture rules',
      { timeout: 300_000 },
      async () => {
        const { keys } = await scanFixtureWith(semgrepAnalyzer, 'mixed-secrets', tmp());
        expect(keys).toEqual(expectedKeys('mixed-secrets', 'semgrep'));
      },
    );

    it('runs the qualor-default pack from the rules directory', { timeout: 300_000 }, async () => {
      const pack = tmp();
      cpSync(
        path.join(FIXTURES_DIR, 'mixed-secrets', 'semgrep', 'rules.yml'),
        path.join(pack, 'a.yml'),
      );
      const { keys } = await scanFixtureWith(
        createSemgrepAnalyzer(pack),
        'mixed-secrets',
        tmp(),
        (root) => writeTree(root, { 'qualor.yml': 'version: 1\n' }),
      );
      // The same ids wherever the rule files live (ruling A3).
      expect(keys).toEqual(expectedKeys('mixed-secrets', 'semgrep'));
    });

    it(
      'a join rule fetches its refs without the dead proxy, and reaches nothing with it',
      { timeout: 300_000 },
      async () => {
        const flavour = toolInstalled('opengrep') ? 'opengrep' : 'semgrep';
        const bin = resolveBinary(flavour, { root: process.cwd(), env: process.env });
        if (bin === null) throw new Error(`${flavour} is not installed`);
        const listener = await startListener();
        try {
          const root = tmp();
          writeTree(root, {
            'join.yml': JOIN_RULE(`${listener.url}/join-ref.yml`),
            'a.js': 'eval(x);\n',
          });
          const run = (env: Record<string, string>) =>
            runProcess(
              {
                command: bin,
                args: [
                  'scan',
                  '--config',
                  path.join(root, 'join.yml'),
                  '--sarif',
                  ...offlineFlags(flavour),
                  '.',
                ],
                cwd: root,
                env: { ...(process.env as Record<string, string>), ...env },
                timeoutMs: 240_000,
              },
              silentLogger,
            );
          await run({ NO_PROXY: '*', no_proxy: '*' });
          // The control run proves the vector: the tool itself requested the ref.
          expect(listener.hits.length).toBeGreaterThan(0);
          listener.hits.length = 0;
          await run(deadProxyEnv());
          expect(listener.hits).toEqual([]);
        } finally {
          await listener.close();
        }
      },
    );

    it(
      'keeps a secret out of the report when a secret rule interpolates it into its message (Gitleaks off)',
      { timeout: 300_000 },
      async () => {
        const SECRET = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';
        const repo = path.join(tmp(), 'repo');
        cpSync(path.join(FIXTURES_DIR, 'mixed-secrets'), repo, { recursive: true });
        writeTree(repo, {
          'leak.yml':
            'rules:\n  - id: key-in-message\n    languages: [typescript]\n    severity: ERROR\n' +
            '    message: "key $K in $N"\n    pattern: const $N = "$K";\n' +
            "    metadata:\n      cwe: ['CWE-798: Use of Hard-coded Credentials']\n",
          'qualor.yml':
            'version: 1\nanalyzers:\n  gitleaks:\n    enabled: false\n  semgrep:\n    enabled: true\n    configs: [leak.yml]\n',
        });
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
          analyzers: [semgrepAnalyzer],
        });
        expect(code, c.stderr()).toBe(0);
        const json = gunzipSync(readFileSync(path.join(repo, 'r.json.gz'))).toString('utf8');
        expect(json).not.toContain(SECRET);
        const report = reportSchema.parse(JSON.parse(json));
        const f = report.findings.find((x) => x.ruleId === 'key-in-message');
        // The rule's static text, never the interpolated one.
        expect(f?.message).toBe('key $K in $N');
        expect(f?.snippet?.lines.join('\n')).toContain('«redacted»');
      },
    );

    // Semgrep is a Python program: each variable alone would make it run the repository's
    // Python (an in-repo PYTHONHOME would at least stop Python from starting).
    it.each(['PYTHONPATH', 'PYTHONUSERBASE', 'PYTHONHOME'])(
      'never runs Python from the repository through %s',
      { timeout: 300_000 },
      async (name) => {
        const root = tmp();
        const marker = path.join(root, 'PWNED');
        const payload = `open(${JSON.stringify(marker)}, 'w').write('x')\n`;
        writeTree(root, {
          'rules.yml': RULE('r'),
          'a.js': 'eval(x);\n',
          'sitecustomize.py': payload,
          'requests/__init__.py': payload,
          'ruamel/__init__.py': payload,
          'yaml/__init__.py': payload,
        });
        writeFileSync(path.join(root, 'usercustomize.py'), payload);
        // The user site-packages below PYTHONUSERBASE: a .pth line starting with `import` runs.
        for (let minor = 8; minor <= 16; minor += 1) {
          writeTree(root, {
            [`lib/python3.${minor}/site-packages/evil.pth`]: `import os; ${payload}`,
          });
        }
        const value = {
          PYTHONPATH: `${path.delimiter}.${path.delimiter}${root}`,
          PYTHONUSERBASE: root,
          PYTHONHOME: root,
        }[name];
        const [capture] = await runAnalyzers([semgrepAnalyzer], {
          root,
          config: parseConfig({
            version: 1,
            analyzers: { semgrep: { enabled: true, configs: ['rules.yml'] } },
          }),
          files: [],
          log: silentLogger,
          env: { ...process.env, [name]: value },
        });
        expect(existsSync(marker)).toBe(false);
        expect(capture?.status).toBe('ok');
      },
    );
  },
);
