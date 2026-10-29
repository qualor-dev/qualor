import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  BUILTIN_EXCLUDES,
  engineMapping,
  findingConfidence,
  parseConfig,
  type QualorManifest,
  type SarifLog,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { expectedKeys, fakeContext, findingKeys, normalizeRecorded } from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { engineSarif, writeEnginePack } from '../../test/taint';
import { useTempDirs, writeTree } from '../../test/tmp';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { fileLines, normalizeCaptures } from './normalize';
import { deadProxyEnv } from './offline';
import {
  createQualorAnalyzer,
  loadQualorPack,
  QUALOR_LANGUAGES,
  QUALOR_RULES_NOT_INSTALLED,
  qualorAnalyzer,
  withQualorRules,
} from './qualor';
import {
  isOpengrepVariable,
  OPENGREP_GROUP,
  OPENGREP_WARM_ARGS,
  opengrepCacheDir,
} from './semgrep';
import type { AnalyzerContext, TaintRun } from './types';

const tmp = useTempDirs();
const OPENGREP = '/opt/qualor/bin/opengrep';
const RULE = 'rules/python/sql/sql-injection.yml';
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

/**
 * A synthetic pack. Never a real rule: the qualor-rules pack is not MIT and is never copied into
 * this repository; the loader checks bytes, not YAML.
 */
function writePack(
  dir: string,
  files: Record<string, string> = { [RULE]: 'rules: []\n' },
  edit: (m: Record<string, unknown>) => unknown = (m) => m,
): string {
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, p)), { recursive: true });
    writeFileSync(path.join(dir, p), text);
  }
  const rules = Object.entries(files).map(([p, text]) => {
    const [, lang, , base] = p.split('/');
    return {
      id: `${lang}/${base!.replace(/\.yml$/, '')}`,
      path: p,
      sha256: sha256(text),
      languages: ['python'],
      kind: 'issue',
      severity: 'high',
      cwe: ['CWE-89'],
      title: 'A synthetic rule',
    };
  });
  const manifest = { version: '2026.10.0', opengrep: '1.30.0', rules };
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(edit(manifest), null, 2));
  return dir;
}

const scopeFile = (root: string, rel: string, language: ScopeFile['language']): ScopeFile => ({
  path: rel,
  absPath: path.join(root, ...rel.split('/')),
  language,
  grammar: null,
  kind: 'main',
  size: 1,
});

function context(
  root: string,
  o: { files?: ScopeFile[]; env?: Record<string, string>; binaries?: Record<string, string> } = {},
): AnalyzerContext {
  return {
    ...fakeContext(root, { binaries: o.binaries ?? { opengrep: OPENGREP } }),
    files: o.files ?? [scopeFile(root, 'app.py', 'python')],
    env: o.env ?? {},
  };
}

describe('loadQualorPack (config.md §6, plan 6B-1)', () => {
  it('accepts a pack whose rules/ holds exactly the files its manifest lists, unchanged', () => {
    const dir = writePack(tmp());
    const pack = loadQualorPack(dir);
    if ('problem' in pack) throw new Error(pack.problem);
    expect(pack.manifest.rules.map((r) => r.id)).toEqual(['python/sql-injection']);
  });

  it('keeps the pack, and its OpenGrep rules, when its dotnetEngine is malformed (ruling R-E14)', () => {
    const dir = writePack(tmp(), undefined, (m) => ({
      ...m,
      dotnetEngine: {
        version: '2026.10.4',
        entry: '../evil.dll',
        models: 'dotnet/models',
        files: [],
      },
    }));
    const pack = loadQualorPack(dir);
    if ('problem' in pack) throw new Error(pack.problem);
    expect(pack.manifest.rules.map((r) => r.id)).toEqual(['python/sql-injection']);
    expect(pack.manifest.dotnetEngine).toEqual({ invalid: 'entry' });
  });

  it('refuses a missing, malformed, partial or changed pack, with a fixed reason', () => {
    const cases: [string, (dir: string) => void, RegExp][] = [
      ['no manifest', (d) => rmSync(path.join(d, 'manifest.json')), /has no manifest\.json/],
      [
        'not JSON',
        (d) => writeFileSync(path.join(d, 'manifest.json'), '{'),
        /manifest\.json is not valid/,
      ],
      [
        'bad version',
        (d) => writePack(d, undefined, (m) => ({ ...m, version: '2026.01.0' })),
        /manifest\.json is not valid/,
      ],
      [
        'a changed rule',
        (d) => writeFileSync(path.join(d, RULE), 'rules: [x]\n'),
        /does not match its manifest checksum/,
      ],
      [
        'an unlisted rule',
        (d) => writeFileSync(path.join(d, 'rules/python/sql/extra.yaml'), 'rules: []\n'),
        /which its manifest does not list/,
      ],
      // Any unlisted file, whatever its name: OpenGrep would read a .jsonnet config too.
      [
        'an unlisted file of another type',
        (d) => writeFileSync(path.join(d, 'rules/python/x.jsonnet'), '{}\n'),
        /holds rules\/python\/x\.jsonnet, which its manifest does not list/,
      ],
      [
        'a listed rule that is a directory',
        (d) => {
          rmSync(path.join(d, RULE));
          mkdirSync(path.join(d, RULE));
        },
        /file rules\/python\/sql\/sql-injection\.yml is not a regular rule file/,
      ],
      [
        'a listed rule missing',
        (d) => rmSync(path.join(d, RULE)),
        /is missing rules\/python\/sql\/sql-injection\.yml/,
      ],
      [
        'no rules/',
        (d) => rmSync(path.join(d, 'rules'), { recursive: true }),
        /has no rules\/ directory/,
      ],
      [
        'a huge manifest',
        (d) => writeFileSync(path.join(d, 'manifest.json'), ' '.repeat(1024 * 1024 + 1)),
        /larger than 1 MiB/,
      ],
    ];
    for (const [name, damage, reason] of cases) {
      const dir = writePack(tmp());
      damage(dir);
      const pack = loadQualorPack(dir);
      expect('problem' in pack ? pack.problem : 'loaded', name).toMatch(reason);
    }
  });

  it.runIf(process.platform !== 'win32')('refuses a symbolic link anywhere below rules/', () => {
    const dir = writePack(tmp());
    symlinkSync(path.join(dir, RULE), path.join(dir, 'rules/python/sql/link.yml'));
    const pack = loadQualorPack(dir);
    expect('problem' in pack ? pack.problem : 'loaded').toMatch(/symbolic link/);
  });
});

describe('qualorAnalyzer.prepare (config.md §6, plan 6B-1)', () => {
  it('runs for the languages of the pack, and gives its rules those languages', () => {
    expect(qualorAnalyzer.id).toBe('qualor');
    expect(qualorAnalyzer.languages).toEqual([
      'javascript',
      'typescript',
      'python',
      'java',
      'go',
      'csharp',
    ]);
    expect(qualorAnalyzer.ruleLanguages).toBe(QUALOR_LANGUAGES);
  });

  it("skips where the image's pack is not installed", async () => {
    const root = tmp();
    const analyzer = createQualorAnalyzer({ defaultDir: path.join(tmp(), 'none') });
    expect(await analyzer.prepare(context(root))).toEqual({ skip: QUALOR_RULES_NOT_INSTALLED });
    // True whether or not a released image includes the rules: it names the way out.
    expect(QUALOR_RULES_NOT_INSTALLED).toBe(
      "Qualor's security rules are not installed (set QUALOR_RULES_DIR to a rules release, or use a qualor/scanner image that includes them)",
    );
  });

  it('is unavailable for a QUALOR_RULES_DIR that is relative, inside the repository or missing', async () => {
    const root = tmp();
    const inside = writePack(path.join(root, 'rules-pack'));
    const analyzer = createQualorAnalyzer({ defaultDir: writePack(tmp()) });
    for (const dir of ['packs/qualor', inside]) {
      expect(
        await analyzer.prepare(context(root, { env: { QUALOR_RULES_DIR: dir } })),
        dir,
      ).toEqual({
        unavailable: 'QUALOR_RULES_DIR must be an absolute path outside the repository',
      });
    }
    expect(
      await analyzer.prepare(
        context(root, { env: { QUALOR_RULES_DIR: path.join(tmp(), 'gone') } }),
      ),
    ).toEqual({ unavailable: 'QUALOR_RULES_DIR does not exist' });
  });

  it('is unavailable, with the reason, when the pack fails its check', async () => {
    const pack = writePack(tmp());
    writeFileSync(path.join(pack, RULE), 'rules: [changed]\n');
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(context(tmp()));
    expect(prep).toEqual({
      unavailable:
        'the rules pack file rules/python/sql/sql-injection.yml does not match its manifest checksum',
    });
  });

  it('skips without a file of its languages, and never runs Semgrep in place of OpenGrep', async () => {
    const root = tmp();
    const analyzer = createQualorAnalyzer({ defaultDir: writePack(tmp()) });
    const files = [scopeFile(root, 'README.md', 'other'), scopeFile(root, 'a.kt', 'kotlin')];
    expect(await analyzer.prepare(context(root, { files }))).toEqual({
      skip: 'no JavaScript, TypeScript, Python, Java, Go or C# files in scope',
    });
    expect(
      await analyzer.prepare(context(root, { binaries: { semgrep: '/usr/bin/semgrep' } })),
    ).toEqual({
      unavailable: 'OpenGrep is not installed',
    });
  });

  it('runs only the pack, on the in-scope files named after --, without SEMGREP_/OPENGREP_ variables', async () => {
    const root = tmp();
    const pack = writePack(tmp());
    const ctx = context(root, {
      files: [
        scopeFile(root, '-x.py', 'python'),
        scopeFile(root, 'src/a.py', 'python'),
        scopeFile(root, 'web/b.ts', 'typescript'),
        scopeFile(root, 'web/c.js', 'javascript'),
        scopeFile(root, 'App.java', 'java'),
        scopeFile(root, 'cmd/main.go', 'go'),
        scopeFile(root, 'src/Api/OrdersController.cs', 'csharp'),
        scopeFile(root, 'README.md', 'other'),
        scopeFile(root, 'a.kt', 'kotlin'),
      ],
    });
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const out = path.join(ctx.workDir, 'qualor.sarif');
    expect(prep.run).toEqual({
      command: OPENGREP,
      args: [
        'scan',
        '--config',
        path.join(pack, 'rules'),
        '--sarif',
        '--output',
        out,
        '--disable-version-check',
        '--no-rewrite-rule-ids',
        '--quiet',
        '--',
        '-x.py',
        'src/a.py',
        'web/b.ts',
        'web/c.js',
        'App.java',
        'cmd/main.go',
        'src/Api/OrdersController.cs',
      ],
      cwd: root,
      env: deadProxyEnv(),
      dropEnv: isOpengrepVariable,
      sarifPath: out,
      // Never at the same time as the semgrep engine's OpenGrep (its self-unpacking cache).
      exclusive: OPENGREP_GROUP,
      okExitCodes: [0],
      version: null,
      transform: expect.any(Function),
    });
    expect(OPENGREP_GROUP).toBe('opengrep');
    expect(prep.run.exclusive).toBe(OPENGREP_GROUP);
    // The pack from QUALOR_RULES_DIR replaces the default one.
    const other = writePack(tmp());
    const fromEnv = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      context(root, { env: { QUALOR_RULES_DIR: other } }),
    );
    if (!('run' in fromEnv)) throw new Error(JSON.stringify(fromEnv));
    expect(fromEnv.run.args.slice(1, 3)).toEqual(['--config', path.join(other, 'rules')]);
  });

  it('analyses main files only', async () => {
    const root = tmp();
    const pack = writePack(tmp());
    const test = (rel: string, language: ScopeFile['language']): ScopeFile => ({
      ...scopeFile(root, rel, language),
      kind: 'test',
    });
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      context(root, {
        files: [
          scopeFile(root, 'src/app.ts', 'typescript'),
          test('src/app.test.ts', 'typescript'),
          test('tests/test_app.py', 'python'),
        ],
      }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args.slice(prep.run.args.indexOf('--') + 1)).toEqual(['src/app.ts']);
  });

  it('analyses every file when tests.include matches nothing', async () => {
    const root = tmp();
    const prep = await createQualorAnalyzer({ defaultDir: writePack(tmp()) }).prepare(
      context(root, {
        files: [
          scopeFile(root, 'src/app.ts', 'typescript'),
          scopeFile(root, 'src/a.test.ts', 'typescript'),
        ],
      }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args.slice(prep.run.args.indexOf('--') + 1)).toEqual([
      'src/app.ts',
      'src/a.test.ts',
    ]);
  });

  it('skips when every file of its languages is a test file', async () => {
    const root = tmp();
    const prep = await createQualorAnalyzer({ defaultDir: writePack(tmp()) }).prepare(
      context(root, {
        files: [{ ...scopeFile(root, 'src/a.test.ts', 'typescript'), kind: 'test' }],
      }),
    );
    expect(prep).toEqual({ skip: 'skipped (no main files in scope)' });
  });

  it('drops OpenGrep results on test files when it selects the files itself', async () => {
    const root = tmp();
    const prep = await createQualorAnalyzer({
      defaultDir: writePack(tmp()),
      maxTargetArgBytes: 1,
    }).prepare(
      context(root, {
        files: [
          scopeFile(root, 'src/app.ts', 'typescript'),
          { ...scopeFile(root, 'src/app.test.ts', 'typescript'), kind: 'test' },
        ],
      }),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    const at = (uri: string) => ({
      ruleId: 'python.sql-injection',
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    });
    const out = prep.run.transform(
      {
        version: '2.1.0',
        runs: [
          { tool: { driver: { rules: [] } }, results: [at('src/app.ts'), at('src/app.test.ts')] },
        ],
      },
      '',
    ) as { runs: { results: unknown[] }[] };
    const resultPath = (r: unknown) =>
      (r as typeof at extends (u: string) => infer R ? R : never).locations[0]!.physicalLocation
        .artifactLocation.uri;
    expect(out.runs[0]!.results.map((r) => resultPath(r))).toEqual(['src/app.ts']);
  });

  it("unpacks OpenGrep's cache first, under the lock every qualor scan sharing the cache takes", async () => {
    const root = tmp();
    const home = tmp();
    const env = { HOME: home, LOCALAPPDATA: home };
    const lock = path.join(opengrepCacheDir(env) ?? '', '.qualor-unpack.lock');
    const calls: { command: string; args: readonly string[]; locked: boolean }[] = [];
    const ctx: AnalyzerContext = {
      ...context(root, { env }),
      exec: (command, args) => {
        calls.push({ command, args, locked: existsSync(lock) });
        return Promise.resolve({
          exitCode: 0,
          timedOut: false,
          durationMs: 1,
          stdout: '',
          stderr: '',
        });
      },
    };
    const prep = await createQualorAnalyzer({ defaultDir: writePack(tmp()) }).prepare(ctx);
    expect('run' in prep).toBe(true);
    expect(calls).toEqual([{ command: OPENGREP, args: OPENGREP_WARM_ARGS, locked: true }]);
    expect(existsSync(lock)).toBe(false);
  });

  it('runs taint rules across functions of a file when the pack says it is tested that way', async () => {
    const root = tmp();
    const args = async (edit?: (m: Record<string, unknown>) => unknown) => {
      const pack = writePack(tmp(), undefined, edit);
      const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(context(root));
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      return { pack, args: prep.run.args };
    };
    const on = await args((m) => ({ ...m, taintIntrafile: true }));
    expect(on.args.slice(0, 4)).toEqual([
      'scan',
      '--config',
      path.join(on.pack, 'rules'),
      '--taint-intrafile',
    ]);
    for (const edit of [
      undefined,
      (m: Record<string, unknown>) => ({ ...m, taintIntrafile: false }),
    ]) {
      expect((await args(edit)).args).not.toContain('--taint-intrafile');
    }
  });

  it('counts the pointer of each argument (8 bytes) as well as its length and terminator', async () => {
    const root = tmp();
    const analyze = async (maxTargetArgBytes: number) => {
      const prep = await createQualorAnalyzer({
        defaultDir: writePack(tmp()),
        maxTargetArgBytes,
      }).prepare(context(root, { files: [scopeFile(root, 'a.py', 'python')] }));
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      return prep.run.args;
    };
    // 'a.py' is 4 bytes + 1 terminator + 8 pointer = 13.
    expect(await analyze(13)).toContain('--');
    expect(await analyze(12)).not.toContain('--');
  });

  it("falls back to OpenGrep's own selection when the files do not fit one command line", async () => {
    const root = tmp();
    const prep = await createQualorAnalyzer({
      defaultDir: writePack(tmp()),
      maxTargetArgBytes: 10,
    }).prepare(context(root, { files: [scopeFile(root, 'src/a-long-enough-name.py', 'python')] }));
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    // OpenGrep skips files over 1,000,000 bytes below `.` unless told otherwise.
    expect(prep.run.args.slice(-4)).toEqual([
      '--max-target-bytes',
      String(MAX_ANALYZED_BYTES),
      '--x-ignore-semgrepignore-files',
      '.',
    ]);
    expect(prep.run.args).not.toContain('--');
  });

  it("gives OpenGrep the built-in excludes and the project's own when it selects the files itself", async () => {
    const root = tmp();
    const config = parseConfig({ version: 1, sources: { exclude: ['gen/**', '**/*.snap'] } });
    const files = [scopeFile(root, 'src/a-long-enough-name.py', 'python')];
    const run = async (maxTargetArgBytes: number) => {
      const prep = await createQualorAnalyzer({
        defaultDir: writePack(tmp()),
        maxTargetArgBytes,
      }).prepare({ ...context(root, { files }), config });
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      return prep.run.args;
    };
    const excludes = (args: readonly string[]) =>
      args.flatMap((a, i) => (args[i - 1] === '--exclude' ? [a] : []));
    // Past the command line: the whole list, the built-in ones first, as written.
    const dot = await run(10);
    // OpenGrep matches every pattern at any depth, so only the `**/` ones (equal there) are passed:
    // `gen/**` would also drop `a/gen/**`, which Qualor scans.
    expect(excludes(dot)).toEqual([...BUILTIN_EXCLUDES, '**/*.snap']);
    expect(excludes(dot)).not.toContain('gen/**');
    expect(dot.indexOf('--exclude')).toBeLessThan(dot.indexOf('.'));
    expect(excludes(dot)).toEqual(expect.arrayContaining(['**/*.min.mjs', '**/*.min.cjs']));
    // A short list names its files: no excludes needed, the arguments unchanged.
    const listed = await run(1_000_000);
    expect(listed).toContain('--');
    expect(listed).not.toContain('--exclude');
  });

  it('warns when the files do not fit one command line, and only then', async () => {
    const root = tmp();
    const warnings: string[] = [];
    const ctx = (): AnalyzerContext => ({
      ...context(root, {
        files: [scopeFile(root, 'src/a.py', 'python'), scopeFile(root, 'web/b.ts', 'typescript')],
      }),
      log: { ...silentLogger, warn: (m: string) => warnings.push(m) },
    });
    await createQualorAnalyzer({ defaultDir: writePack(tmp()) }).prepare(ctx());
    expect(warnings).toEqual([]);
    await createQualorAnalyzer({ defaultDir: writePack(tmp()), maxTargetArgBytes: 10 }).prepare(
      ctx(),
    );
    expect(warnings).toEqual([
      "qualor: 2 files do not fit one command line; OpenGrep selects the files itself and findings outside the scan's scope are dropped",
    ]);
  });

  it('warns when OpenGrep is not the version the pack is tested with, and only then', async () => {
    const root = tmp();
    const warnings: string[] = [];
    const prep = await createQualorAnalyzer({ defaultDir: writePack(tmp()) }).prepare({
      ...context(root),
      log: { ...silentLogger, warn: (m: string) => warnings.push(m) },
    });
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    const sarif = (semanticVersion: string) => ({
      runs: [
        { tool: { driver: { name: 'Opengrep OSS', semanticVersion, rules: [] } }, results: [] },
      ],
    });
    prep.run.transform(sarif('1.30.0'), '');
    expect(warnings).toEqual([]);
    const out = prep.run.transform(sarif('1.31.0'), '') as ReturnType<typeof sarif>;
    expect(warnings).toEqual([
      'qualor: the rules pack 2026.10.0 is tested with OpenGrep 1.30.0, not 1.31.0',
    ]);
    // A warning only: the results are still used, with the pack named in the version.
    expect(out.runs[0]?.tool.driver).toMatchObject({ version: '1.31.0 + qualor-rules 2026.10.0' });
  });
});

describe('isOpengrepVariable (config.md §6, plan 6B-1)', () => {
  it('drops every SEMGREP_* and OPENGREP_* variable, in any case, and nothing else', () => {
    for (const name of [
      'SEMGREP_BASELINE_REF',
      'SEMGREP_BASELINE_COMMIT',
      'SEMGREP_LOG_FILE',
      'SEMGREP_TIMEOUT',
      'SEMGREP_RULES',
      'OPENGREP_BINARY',
      'semgrep_rules',
    ]) {
      expect(isOpengrepVariable(name), name).toBe(true);
    }
    for (const name of ['PATH', 'HOME', 'HTTPS_PROXY', 'QUALOR_RULES_DIR', 'MY_SEMGREP_X']) {
      expect(isOpengrepVariable(name), name).toBe(false);
    }
  });
});

describe('withQualorRules (config.md §6, plan 6B-1)', () => {
  const manifest = {
    version: '2026.10.0',
    opengrep: '1.30.0',
    rules: [
      {
        id: 'python/sql-injection',
        path: RULE,
        sha256: 'a'.repeat(64),
        languages: ['python'],
        kind: 'issue',
        severity: 'high',
        cwe: ['CWE-89'],
        title: 'A synthetic rule',
      },
    ],
  } as unknown as QualorManifest;
  const result = (extra: Record<string, unknown> = {}) => ({
    ruleId: 'python.sql-injection',
    message: { text: 'm' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: 'app.py', uriBaseId: '%SRCROOT%' },
          region: { startLine: 3 },
        },
      },
    ],
    properties: {},
    ...extra,
  });
  // OpenGrep 1.30.0's SARIF shape, with synthetic texts.
  const log = () => ({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Opengrep OSS',
            semanticVersion: '1.30.0',
            rules: [
              {
                id: 'python.sql-injection',
                name: 'python.sql-injection',
                shortDescription: { text: 'Opengrep Finding: python.sql-injection' },
                defaultConfiguration: { level: 'error' },
                properties: { precision: 'very-high', tags: ['CWE-89', 'security'] },
                // A rule's own reference is replaced by its page in qualor-rules.
                helpUri: 'https://owasp.org/Top10/A03_2021-Injection/',
              },
              {
                id: 'python.not-in-manifest',
                name: 'python.not-in-manifest',
                properties: { tags: [] },
              },
              { id: 'someone.else', name: 'someone.else' },
            ],
          },
        },
        results: [
          result(),
          result({ suppressions: [{ kind: 'inSource' }] }),
          result({ suppressions: [{ kind: 'external', status: 'accepted' }] }),
        ],
      },
    ],
  });
  type Log = ReturnType<typeof log>;

  it('maps ids, copies title, kind and severity from the manifest, and names the pack in the version', () => {
    const out = log() as Log & {
      runs: { tool: { driver: { version: string } } }[];
    };
    withQualorRules(out, manifest);
    const driver = out.runs[0]!.tool.driver;
    expect(driver.version).toBe('1.30.0 + qualor-rules 2026.10.0');
    expect(driver.rules[0]).toEqual({
      id: 'python/sql-injection',
      name: 'python/sql-injection',
      helpUri:
        'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/python/sql-injection.md',
      shortDescription: { text: 'A synthetic rule' },
      defaultConfiguration: { level: 'error' },
      properties: {
        precision: 'very-high',
        tags: ['CWE-89', 'security'],
        qualorKind: 'issue',
        qualorSeverity: 'high',
      },
    });
    // A rule the manifest does not know keeps no metadata (issue/medium by the mapping).
    expect(driver.rules[1]).toEqual({
      id: 'python/not-in-manifest',
      name: 'python/not-in-manifest',
      helpUri:
        'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/python/not-in-manifest.md',
      properties: { tags: [] },
    });
    expect(driver.rules[2]).toEqual({ id: 'someone.else', name: 'someone.else' });
    expect(out.runs[0]!.results.map((r) => r.ruleId)).toEqual(
      Array(3).fill('python/sql-injection'),
    );
  });

  it('removes in-source suppressions (nosem comments in the checkout), and keeps any other', () => {
    const out = log();
    withQualorRules(out, manifest);
    const [plain, inSource, external] = out.runs[0]!.results as Record<string, unknown>[];
    expect(plain).not.toHaveProperty('suppressions');
    expect(inSource).not.toHaveProperty('suppressions');
    expect(external?.['suppressions']).toEqual([{ kind: 'external', status: 'accepted' }]);
  });

  it('leaves anything that is not a SARIF log as it is', () => {
    for (const odd of [
      null,
      'text',
      42,
      { runs: 'x' },
      { runs: [null, { tool: null }, { tool: { driver: 'x' } }] },
    ]) {
      const before = structuredClone(odd);
      withQualorRules(odd, manifest);
      expect(odd).toEqual(before);
    }
  });
});

describe('qualor SARIF through normalisation (synthetic, in the shape OpenGrep 1.30.0 writes)', () => {
  const expected = JSON.parse(
    readFileSync(path.join(FIXTURES_DIR, 'qualor-security', 'expected.json'), 'utf8'),
  ) as { findings: { ruleKey: string; path: string; startLine: number }[] };
  const ids = [...new Set(expected.findings.map((f) => f.ruleKey.slice('qualor:'.length)))];
  const manifest = {
    version: '2026.10.0',
    opengrep: '1.30.0',
    rules: ids.map((id) => ({
      id,
      path: `rules/${id.split('/')[0]}/sql/${id.split('/')[1]}.yml`,
      sha256: 'a'.repeat(64),
      languages: ['x'],
      kind: 'issue',
      severity: 'high',
      cwe: ['CWE-89'],
      title: 'A synthetic rule',
    })),
  } as unknown as QualorManifest;
  const sarif = () => ({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Opengrep OSS',
            semanticVersion: '1.30.0',
            rules: ids.map((id) => ({
              id: id.replace('/', '.'),
              name: id.replace('/', '.'),
              shortDescription: { text: `Opengrep Finding: ${id.replace('/', '.')}` },
              defaultConfiguration: { level: 'error' },
              properties: { precision: 'very-high', tags: ['CWE-89', 'security'] },
            })),
          },
        },
        results: expected.findings.map((f) => ({
          ruleId: f.ruleKey.slice('qualor:'.length).replace('/', '.'),
          message: { text: 'A synthetic message.' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.path, uriBaseId: '%SRCROOT%' },
                region: { startLine: f.startLine },
              },
            },
          ],
          properties: {},
        })),
      },
    ],
  });

  it('gives the fixture keys, with kind and severity from the manifest and the CWE from the tags', () => {
    const log = sarif();
    withQualorRules(log, manifest);
    const out = normalizeRecorded(log, qualorAnalyzer, 'qualor-security');
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('qualor-security', 'qualor'));
    expect(out.engines[0]?.version).toBe('1.30.0 + qualor-rules 2026.10.0');
    // The loop below proves nothing over an empty list.
    expect(out.engines[0]?.rules).toHaveLength(ids.length);
    expect(ids.length).toBeGreaterThan(0);
    for (const r of out.engines[0]?.rules ?? []) {
      expect(r, r.id).toMatchObject({
        helpUri: `https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/${r.id}.md`,
        quality: 'security',
        kind: 'issue',
        defaultSeverity: 'high',
        cwe: [89],
      });
    }
  });

  it('without the transform, nothing would be right: the guard against a missing transform', () => {
    const out = normalizeRecorded(sarif(), qualorAnalyzer, 'qualor-security');
    expect(findingKeys(out.findings)).not.toEqual(expectedKeys('qualor-security', 'qualor'));
  });
});

describe("qualor with Qualor's Roslyn taint engine under qualor dotnet end (6B-C# R, R-4)", () => {
  const merged = {
    sarif: { version: '2.1.0', runs: [] },
    version: '5.9.0',
    results: 0,
    duplicates: 0,
  };
  const C_SHARP = [
    'class A {',
    '  void Get(string q) {',
    '    var sql = "SELECT " + q;',
    '    Run(sql);',
    '  }',
    '}',
    '',
  ].join('\n');

  /** A checkout with one Python and two C# files, and a pack with two C# rules. */
  function setup(o: { python?: boolean } = {}) {
    const root = tmp();
    writeTree(root, { 'src/A.cs': C_SHARP, 'src/B.cs': C_SHARP, 'app.py': 'print(1)\n' });
    const files = [
      ...(o.python === false ? [] : [scopeFile(root, 'app.py', 'python')]),
      scopeFile(root, 'src/A.cs', 'csharp'),
      scopeFile(root, 'src/B.cs', 'csharp'),
    ];
    const pack = writeEnginePack(tmp(), {
      ids: ['csharp/sql-injection', 'csharp/tls-verification-disabled'],
      severity: 'blocker',
    });
    return { root, files, pack };
  }

  const ok = (root: string, sources: readonly string[] = ['src/A.cs', 'src/B.cs']): TaintRun => ({
    kind: 'ok',
    sources,
    sarif: engineSarif(root, [
      {
        rule: 'csharp.sql-injection',
        uri: 'src/A.cs',
        line: 4,
        steps: [
          ['src/A.cs', 2, 'request data: q'],
          ['src/A.cs', 3, 'string concatenation'],
          ['src/A.cs', 4, 'sink: Run'],
        ],
        others: [['src/B.cs', 2]],
      },
    ]) as SarifLog,
  });

  function withTaint(
    root: string,
    files: ScopeFile[],
    taint: TaintRun | null,
    o: { binaries?: Record<string, string> } = {},
  ): AnalyzerContext {
    return {
      ...context(root, { files, ...(o.binaries !== undefined && { binaries: o.binaries }) }),
      dotnet: { kind: 'collected', merged, taint },
    };
  }

  function normalizeIn(root: string, sarif: unknown) {
    return normalizeCaptures(
      [
        {
          engineId: 'qualor',
          kind: 'builtin',
          status: 'ok',
          reason: null,
          durationMs: 1,
          version: null,
          required: false,
          sarif,
          mapping: engineMapping('qualor')!,
          ruleLanguages: QUALOR_LANGUAGES,
        },
      ],
      {
        repoRoot: root,
        readLines: fileLines(root),
        knownPaths: new Set(['app.py', 'src/A.cs', 'src/B.cs']),
        log: silentLogger,
      },
    );
  }

  /** OpenGrep's SARIF for the pack, with a C# result the engine replaces. */
  const opengrepSarif = () => ({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Opengrep OSS',
            semanticVersion: '1.30.0',
            rules: [{ id: 'csharp.sql-injection', properties: { tags: ['CWE-89', 'security'] } }],
          },
        },
        results: [
          {
            ruleId: 'csharp.sql-injection',
            message: { text: 'OpenGrep says so' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/B.cs', uriBaseId: '%SRCROOT%' },
                  region: { startLine: 4 },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  const at = (p: string, line: number, message: string) => ({
    path: p,
    startLine: line,
    startColumn: 1,
    endLine: line,
    endColumn: 1,
    message,
  });

  it('keeps the engine findings on test files out', async () => {
    const { root, files, pack } = setup();
    const taint = ok(root);
    if (taint.kind !== 'ok') throw new Error('taint');
    const run = (taint.sarif as unknown as { runs: { results: Record<string, unknown>[] }[] })
      .runs[0]!;
    run.results.push(structuredClone(run.results[0]!));
    const loc = run.results[1]!['locations'] as {
      physicalLocation: { artifactLocation: { uri: string } };
    }[];
    loc[0]!.physicalLocation.artifactLocation.uri = 'src/B.cs';
    const marked = files.map((f) => (f.path === 'src/B.cs' ? { ...f, kind: 'test' as const } : f));
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, marked, taint),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    const out = normalizeIn(root, prep.run.transform(opengrepSarif(), ''));
    expect(out.findings.map((f) => f.location?.path)).toEqual(['src/A.cs']);
  });

  it('does not pass .cs files to OpenGrep, and adds the engine findings with the manifest kind and severity and the flow as related locations', async () => {
    const { root, files, pack } = setup();
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, ok(root)),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    expect(prep.run.args.slice(prep.run.args.indexOf('--') + 1)).toEqual(['app.py']);
    expect(prep.run.warnings).toBeUndefined();
    expect(prep.run.okExitCodes).toEqual([0]);

    const out = normalizeIn(root, prep.run.transform(opengrepSarif(), ''));
    expect(out.warnings).toEqual([]);
    // OpenGrep's own C# result (were it to select the .cs files itself) is dropped.
    expect(findingKeys(out.findings)).toEqual(['qualor:csharp/sql-injection src/A.cs:4 [blocker]']);
    // The flow from source to sink (the sink itself is the primary location), then the other sources.
    expect(out.findings[0]?.secondaryLocations).toEqual([
      at('src/A.cs', 2, 'request data: q'),
      at('src/A.cs', 3, 'string concatenation'),
      at('src/B.cs', 2, 'other request data reaching the same sink'),
    ]);
    expect(out.engines[0]?.rules.find((r) => r.id === 'csharp/sql-injection')).toMatchObject({
      kind: 'issue',
      defaultSeverity: 'blocker',
      quality: 'security',
      cwe: [89],
    });
    // The OpenGrep run stays first: the engine's version is OpenGrep's with the pack.
    expect(out.engines[0]?.version).toBe('1.30.0 + qualor-rules 2026.10.4');
  });

  it('leaves on OpenGrep the .cs files no recorded compilation holds, with their OpenGrep findings (fix round 1, I2)', async () => {
    const { root, files, pack } = setup();
    // src/B.cs belongs to no project the build compiled: the engine never saw it.
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, ok(root, ['src/A.cs', 'src/obj/Debug/App.AssemblyInfo.cs'])),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    expect(prep.run.args.slice(prep.run.args.indexOf('--') + 1)).toEqual(['app.py', 'src/B.cs']);
    const sarif = opengrepSarif();
    const onA = structuredClone(sarif.runs[0]!.results[0]!);
    onA.locations[0]!.physicalLocation.artifactLocation.uri = 'src/A.cs';
    sarif.runs[0]!.results.push(onA);
    const out = normalizeIn(root, prep.run.transform(sarif, ''));
    // OpenGrep's finding on src/B.cs stays; its finding on src/A.cs gives way to the engine's.
    expect(findingKeys(out.findings)).toEqual([
      'qualor:csharp/sql-injection src/A.cs:4 [blocker]',
      'qualor:csharp/sql-injection src/B.cs:4 [blocker]',
    ]);
    expect(out.findings.find((f) => f.location?.path === 'src/A.cs')?.message).not.toBe(
      'OpenGrep says so',
    );

    // C# only, with a file the engine did not see: OpenGrep runs on that file alone.
    const only = setup({ python: false });
    const csharp = await createQualorAnalyzer({ defaultDir: only.pack }).prepare(
      withTaint(only.root, only.files, ok(only.root, ['src/A.cs']), {
        binaries: { opengrep: OPENGREP },
      }),
    );
    if (!('run' in csharp)) throw new Error(JSON.stringify(csharp));
    expect(csharp.run.args.slice(csharp.run.args.indexOf('--') + 1)).toEqual(['src/B.cs']);
  });

  it("carries the engine's confidence into the finding, with the rule's severity whatever the level (R-9)", async () => {
    const { root, files, pack } = setup();
    const taint: TaintRun = {
      kind: 'ok',
      sources: ['src/A.cs', 'src/B.cs'],
      sarif: engineSarif(root, [
        { rule: 'csharp.sql-injection', uri: 'src/A.cs', line: 4, confidence: 'medium' },
        { rule: 'csharp.sql-injection', uri: 'src/B.cs', line: 4, confidence: 'high' },
      ]) as SarifLog,
    };
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, taint),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    const out = normalizeIn(root, prep.run.transform(opengrepSarif(), ''));

    // A medium result's SARIF level is "warning": the severity stays the manifest's.
    expect(findingKeys(out.findings)).toEqual([
      'qualor:csharp/sql-injection src/A.cs:4 [blocker]',
      'qualor:csharp/sql-injection src/B.cs:4 [blocker]',
    ]);
    expect(out.findings.map((f) => findingConfidence(f))).toEqual(['medium', 'high']);

    // The OpenGrep path keeps no confidence.
    const plain = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, null),
    );
    if (!('run' in plain) || plain.run.transform === undefined) throw new Error('no run');
    const opengrep = normalizeIn(root, plain.run.transform(opengrepSarif(), ''));
    expect(opengrep.findings).toHaveLength(1);
    expect(findingConfidence(opengrep.findings[0]!)).toBeUndefined();
  });

  it("reads a confidence from the taint engine's SARIF only, never from an OpenGrep result's properties (fix round 1, M4)", async () => {
    const { root, files, pack } = setup();
    const taint: TaintRun = {
      kind: 'ok',
      sources: ['src/A.cs'],
      sarif: engineSarif(root, [
        { rule: 'csharp.sql-injection', uri: 'src/A.cs', line: 4, confidence: 'medium' },
      ]) as SarifLog,
    };
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, taint),
    );
    if (!('run' in prep) || prep.run.transform === undefined) throw new Error(JSON.stringify(prep));
    // An OpenGrep that copied its rules' metadata (`confidence: medium`) into its results.
    const sarif = opengrepSarif();
    (sarif.runs[0]!.results[0] as Record<string, unknown>)['properties'] = {
      confidence: 'medium',
      other: 1,
    };
    const out = normalizeIn(root, prep.run.transform(sarif, ''));

    const byPath = (p: string) => out.findings.find((f) => f.location?.path === p)!;
    expect(findingConfidence(byPath('src/A.cs'))).toBe('medium');
    expect(findingConfidence(byPath('src/B.cs'))).toBeUndefined();
    expect(byPath('src/B.cs').properties).toEqual({ other: 1 });
  });

  it('needs no OpenGrep when only C# files are in scope: the engine findings are the run', async () => {
    const { root, files, pack } = setup({ python: false });
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, ok(root), { binaries: {} }),
    );
    if (!('collected' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.collected.version).toBe('qualor-taint 2026.10.4 + qualor-rules 2026.10.4');
    const out = normalizeIn(root, prep.collected.sarif);
    expect(findingKeys(out.findings)).toEqual(['qualor:csharp/sql-injection src/A.cs:4 [blocker]']);
    expect(out.findings[0]?.secondaryLocations).toHaveLength(3);
    expect(out.engines[0]?.rules.find((r) => r.id === 'csharp/sql-injection')).toMatchObject({
      kind: 'issue',
      defaultSeverity: 'blocker',
      cwe: [89],
      helpUri:
        'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/csharp/sql-injection.md',
    });
  });

  it('on a fallback runs OpenGrep on the .cs files as without the engine, and the report says why (Review Focus 3 and 4)', async () => {
    const { root, files, pack } = setup();
    const analyzer = createQualorAnalyzer({ defaultDir: pack });
    const plain = await analyzer.prepare(context(root, { files }));
    if (!('run' in plain)) throw new Error(JSON.stringify(plain));
    const reasons = [
      'no-engine',
      'engine-mismatch',
      'no-inputs',
      'budget',
      'crash',
      'dotnet-missing',
      'load',
    ] as const;
    for (const reason of reasons) {
      const prep = await analyzer.prepare(
        withTaint(root, files, { kind: 'fallback', reason, detail: 'stderr text, never reported' }),
      );
      if (!('run' in prep)) throw new Error(JSON.stringify(prep));
      const { warnings, ...run } = prep.run;
      // Exactly the run without the engine: the same files and exit codes.
      expect({ ...run, transform: null }, reason).toEqual({ ...plain.run, transform: null });
      expect(run.args, reason).toContain('src/A.cs');
      expect(warnings, reason).toEqual([
        {
          code: 'TAINT_ENGINE_FALLBACK',
          message: expect.stringMatching(
            new RegExp(
              `^Qualor's Roslyn taint engine did not run \\(${reason}: [^)]+\\); the OpenGrep C# rules analysed the C# files$`,
            ),
          ) as unknown,
          count: 1,
        },
      ]);
      expect(JSON.stringify(warnings)).not.toContain('stderr text');
    }
  });

  it('hands the engine findings on whatever OpenGrep does: absent, timed out or failed (Task 24)', async () => {
    const { root, files, pack } = setup();
    const analyzer = createQualorAnalyzer({ defaultDir: pack });
    const expected = ['qualor:csharp/sql-injection src/A.cs:4 [blocker]'];
    const capture = (sarif: unknown): unknown => sarif;

    // OpenGrep is not installed: unavailable, with the engine's SARIF.
    const absent = await analyzer.prepare(withTaint(root, files, ok(root), { binaries: {} }));
    if (!('unavailable' in absent) || absent.salvage === undefined) {
      throw new Error(JSON.stringify(absent));
    }
    expect(absent.unavailable).toBe('OpenGrep is not installed');
    expect(absent.salvage.version).toBe('qualor-taint 2026.10.4 + qualor-rules 2026.10.4');
    expect(findingKeys(normalizeIn(root, capture(absent.salvage.sarif)).findings)).toEqual(
      expected,
    );

    // The OpenGrep run carries the same SARIF for a timeout, a failure or a bad conversion.
    const prep = await analyzer.prepare(withTaint(root, files, ok(root)));
    if (!('run' in prep) || prep.run.salvage === undefined) throw new Error(JSON.stringify(prep));
    expect(findingKeys(normalizeIn(root, capture(prep.run.salvage.sarif)).findings)).toEqual(
      expected,
    );

    // Without an engine run there is nothing to keep.
    const plain = await analyzer.prepare(withTaint(root, files, null));
    if (!('run' in plain)) throw new Error(JSON.stringify(plain));
    expect(plain.run.salvage).toBeUndefined();
    const none = await analyzer.prepare(withTaint(root, files, null, { binaries: {} }));
    expect(none).toEqual({ unavailable: 'OpenGrep is not installed' });
  });

  it('reports the engine findings of a timed-out or failed OpenGrep run, with its status and reason (fix round 1, I2)', async () => {
    const { root, files, pack } = setup();
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, ok(root)),
    );
    if (!('run' in prep) || prep.run.salvage === undefined) throw new Error(JSON.stringify(prep));
    const salvage = prep.run.salvage;
    for (const [status, reason] of [
      ['timeout', "timed out after 900 s; the Roslyn taint engine's findings are included"],
      ['failed', "exited with code 2; the Roslyn taint engine's findings are included"],
    ] as const) {
      const out = normalizeCaptures(
        [
          {
            engineId: 'qualor',
            kind: 'builtin',
            status,
            reason,
            durationMs: 1,
            version: salvage.version,
            required: false,
            sarif: salvage.sarif,
            salvaged: true,
            mapping: engineMapping('qualor')!,
            ruleLanguages: QUALOR_LANGUAGES,
          },
        ],
        {
          repoRoot: root,
          readLines: fileLines(root),
          knownPaths: new Set(['app.py', 'src/A.cs', 'src/B.cs']),
          log: silentLogger,
        },
      );
      expect(findingKeys(out.findings), status).toEqual([
        'qualor:csharp/sql-injection src/A.cs:4 [blocker]',
      ]);
      expect(out.engines[0], status).toMatchObject({ status, reason });
    }
    // A salvage that cannot be read leaves the status and reason as they were.
    const bad = normalizeCaptures(
      [
        {
          engineId: 'qualor',
          kind: 'builtin',
          status: 'timeout',
          reason: 'timed out after 900 s',
          durationMs: 1,
          version: null,
          required: false,
          sarif: { runs: 'nonsense' },
          salvaged: true,
          mapping: engineMapping('qualor')!,
        },
      ],
      { repoRoot: root, readLines: fileLines(root), knownPaths: new Set(), log: silentLogger },
    );
    expect(bad.findings).toEqual([]);

    // A non-ok capture with SARIF but without the salvage flag reports nothing.
    const unflagged = normalizeCaptures(
      [
        {
          engineId: 'qualor',
          kind: 'builtin',
          status: 'timeout',
          reason: 'timed out after 900 s',
          durationMs: 1,
          version: null,
          required: false,
          sarif: salvage.sarif,
          mapping: engineMapping('qualor')!,
        },
      ],
      { repoRoot: root, readLines: fileLines(root), knownPaths: new Set(), log: silentLogger },
    );
    expect(unflagged.findings).toEqual([]);
    expect(unflagged.engines[0]).toMatchObject({ status: 'timeout' });
    expect(bad.engines[0]).toMatchObject({ status: 'timeout', reason: 'timed out after 900 s' });
  });

  it('keeps the fallback warning when OpenGrep is missing, and does not claim C# rules a pack lacks (final review M3)', async () => {
    const { root, files, pack } = setup();
    const fallback = { kind: 'fallback', reason: 'crash', detail: 'x' } as const;
    const missing = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, fallback, { binaries: {} }),
    );
    if (!('unavailable' in missing)) throw new Error(JSON.stringify(missing));
    expect(missing.unavailable).toBe('OpenGrep is not installed');
    expect(missing.warnings?.map((w) => w.code)).toEqual(['TAINT_ENGINE_FALLBACK']);
    expect(missing.warnings?.[0]?.message).toBe(
      "Qualor's Roslyn taint engine did not run (crash: the engine failed); OpenGrep is not installed, so Qualor's C# security rules did not run",
    );

    // A pack with no C# rules: nothing analysed the C# files, and the warning says so.
    const plainPack = writePack(tmp());
    const prep = await createQualorAnalyzer({ defaultDir: plainPack }).prepare(
      withTaint(root, files, fallback),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const message = prep.run.warnings?.[0]?.message ?? '';
    expect(message).toContain('did not run (crash:');
    expect(message).toBe(
      "Qualor's Roslyn taint engine did not run (crash: the engine failed); the rules pack has no OpenGrep C# rules, so Qualor's C# security rules did not run",
    );
    expect(message).not.toContain('OpenGrep C# rules analysed');
  });

  it('names the load fallback and reports the projects with load or compile errors (R-E42)', async () => {
    const { root, files, pack } = setup();
    const analyzer = createQualorAnalyzer({ defaultDir: pack });
    const load = await analyzer.prepare(
      withTaint(root, files, { kind: 'fallback', reason: 'load', detail: 'x' }),
    );
    if (!('run' in load)) throw new Error(JSON.stringify(load));
    expect(load.run.warnings?.[0]?.message).toBe(
      "Qualor's Roslyn taint engine did not run (load: the sources of a project could not be loaded); the OpenGrep C# rules analysed the C# files",
    );

    const problems = { projects: 2, unresolvedReferences: 3 };
    const text =
      "Qualor's Roslyn taint engine analysed 2 project(s) with load or compile errors (3 unresolved reference(s)); their findings may be incomplete";
    const withProblems = { ...ok(root), problems } as TaintRun;
    const run = await analyzer.prepare(withTaint(root, files, withProblems));
    if (!('run' in run)) throw new Error(JSON.stringify(run));
    expect(run.run.warnings).toEqual([
      { code: 'TAINT_ENGINE_PROJECT_ERRORS', message: text, count: 2 },
    ]);
    // Without OpenGrep, and with only C# files (the engine's findings are the run).
    const missing = await analyzer.prepare(withTaint(root, files, withProblems, { binaries: {} }));
    if (!('unavailable' in missing)) throw new Error(JSON.stringify(missing));
    expect(missing.warnings?.map((w) => w.code)).toEqual(['TAINT_ENGINE_PROJECT_ERRORS']);
    const only = setup({ python: false });
    const collected = await createQualorAnalyzer({ defaultDir: only.pack }).prepare(
      withTaint(only.root, only.files, { ...ok(only.root), problems } as TaintRun),
    );
    if (!('collected' in collected)) throw new Error(JSON.stringify(collected));
    expect(collected.collected.warnings?.map((w) => w.code)).toEqual([
      'TAINT_ENGINE_PROJECT_ERRORS',
    ]);
    // A clean run has none.
    const clean = await analyzer.prepare(withTaint(root, files, ok(root)));
    if (!('run' in clean)) throw new Error(JSON.stringify(clean));
    expect(clean.run.warnings).toBeUndefined();
  });

  it('runs as in a plain scan when the engine was not attempted', async () => {
    const { root, files, pack } = setup();
    const prep = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      withTaint(root, files, null),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args).toContain('src/A.cs');
    expect(prep.run.warnings).toBeUndefined();
  });
});
