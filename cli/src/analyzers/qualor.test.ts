import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { QualorManifest } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { expectedKeys, fakeContext, findingKeys, normalizeRecorded } from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs } from '../../test/tmp';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { deadProxyEnv } from './offline';
import {
  createQualorAnalyzer,
  loadQualorPack,
  QUALOR_LANGUAGES,
  QUALOR_RULES_NOT_INSTALLED,
  qualorAnalyzer,
  withQualorRules,
} from './qualor';
import { isOpengrepVariable } from './semgrep';
import type { AnalyzerContext } from './types';

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
    expect(qualorAnalyzer.languages).toEqual(['javascript', 'typescript', 'python', 'java', 'go']);
    expect(qualorAnalyzer.ruleLanguages).toBe(QUALOR_LANGUAGES);
  });

  it("skips where the image's pack is not installed", async () => {
    const root = tmp();
    const analyzer = createQualorAnalyzer({ defaultDir: path.join(tmp(), 'none') });
    expect(await analyzer.prepare(context(root))).toEqual({ skip: QUALOR_RULES_NOT_INSTALLED });
    // True whether or not a released image includes the rules (R8): it names the way out.
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
      skip: 'no JavaScript, TypeScript, Python, Java or Go files in scope',
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
      ],
      cwd: root,
      env: deadProxyEnv(),
      dropEnv: isOpengrepVariable,
      sarifPath: out,
      okExitCodes: [0],
      version: null,
      transform: expect.any(Function),
    });
    // The pack from QUALOR_RULES_DIR replaces the default one.
    const other = writePack(tmp());
    const fromEnv = await createQualorAnalyzer({ defaultDir: pack }).prepare(
      context(root, { env: { QUALOR_RULES_DIR: other } }),
    );
    if (!('run' in fromEnv)) throw new Error(JSON.stringify(fromEnv));
    expect(fromEnv.run.args.slice(1, 3)).toEqual(['--config', path.join(other, 'rules')]);
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
    const out = withQualorRules(log(), manifest) as Log & {
      runs: { tool: { driver: { version: string } } }[];
    };
    const driver = out.runs[0]!.tool.driver;
    expect(driver.version).toBe('1.30.0 + qualor-rules 2026.10.0');
    expect(driver.rules[0]).toEqual({
      id: 'python/sql-injection',
      name: 'python/sql-injection',
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
      properties: { tags: [] },
    });
    expect(driver.rules[2]?.id).toBe('someone.else');
    expect(out.runs[0]!.results.map((r) => r.ruleId)).toEqual(
      Array(3).fill('python/sql-injection'),
    );
  });

  it('removes in-source suppressions (nosem comments in the checkout), and keeps any other', () => {
    const out = withQualorRules(log(), manifest) as Log;
    const [plain, inSource, external] = out.runs[0]!.results as Record<string, unknown>[];
    expect(plain).not.toHaveProperty('suppressions');
    expect(inSource).not.toHaveProperty('suppressions');
    expect(external?.['suppressions']).toEqual([{ kind: 'external', status: 'accepted' }]);
  });

  it('returns anything that is not a SARIF log as it is', () => {
    for (const odd of [
      null,
      'text',
      42,
      { runs: 'x' },
      { runs: [null, { tool: null }, { tool: { driver: 'x' } }] },
    ]) {
      const before = structuredClone(odd);
      expect(withQualorRules(odd, manifest)).toBe(odd);
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
    const out = normalizeRecorded(
      withQualorRules(sarif(), manifest),
      qualorAnalyzer,
      'qualor-security',
    );
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('qualor-security', 'qualor'));
    expect(out.engines[0]?.version).toBe('1.30.0 + qualor-rules 2026.10.0');
    // The loop below proves nothing over an empty list.
    expect(out.engines[0]?.rules).toHaveLength(ids.length);
    expect(ids.length).toBeGreaterThan(0);
    for (const r of out.engines[0]?.rules ?? []) {
      expect(r, r.id).toMatchObject({
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
