import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { engineMapping, filelessHash, parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  ANALYZER_OUTPUT_DIR,
  describeWithTools,
  expectedKeys,
  fakeContext,
  findingKeys,
  recorded,
  scanFixtureWith,
  startListener,
} from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { resolveBinary } from './binary';
import { fileLines, normalizeCaptures } from './normalize';
import { deadProxyEnv } from './offline';
import { runProcess } from './process';
import { runAnalyzers } from './runner';
import {
  checkTrivyConfig,
  createTrivyAnalyzer,
  isTrivyVariable,
  readDatabaseDate,
  skipDirs,
  trivyAnalyzer,
} from './trivy';
import { findPackageLine, lockfileLines, trivyJsonToSarif, trivyMessage } from './trivy-output';
import type { SarifCapture } from './types';

const tmp = useTempDirs();
/** Recorded with Trivy 0.74.0 and the database of 2026-09-25 over the tree next to it. */
const RECORDED = 'trivy-deps-vulnerable.json';
const TREE = path.join(ANALYZER_OUTPUT_DIR, 'trivy-deps-vulnerable');
const UPDATED_AT = '2026-09-25T06:36:11.019457553Z';

/** A Trivy cache directory with a database (its metadata only: nothing opens trivy.db here). */
function database(metadata: unknown = { Version: 2, UpdatedAt: UPDATED_AT }): string {
  const dir = tmp();
  writeTree(dir, {
    'db/trivy.db': 'not a real database',
    'db/metadata.json': typeof metadata === 'string' ? metadata : JSON.stringify(metadata),
  });
  return dir;
}

const cfg = parseConfig({ version: 1 });

describe('trivyAnalyzer.prepare (config.md §6)', () => {
  const at = (iso: string) => () => new Date(iso);

  it('runs trivy fs offline, with an empty config and its own ignore file, on the database', async () => {
    const root = tmp();
    const dir = database();
    const ctx = fakeContext(root, { binaries: { trivy: '/opt/qualor/bin/trivy' } });
    mkdirSync(ctx.workDir, { recursive: true });
    const prep = await createTrivyAnalyzer(dir, at('2026-09-26T00:00:00Z')).prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const work = (name: string) => path.join(ctx.workDir, name);
    const { transform, dropEnv, ...run } = prep.run;
    expect(run).toEqual({
      command: '/opt/qualor/bin/trivy',
      args: [
        'fs',
        '--config',
        work('trivy.yaml'),
        '--cache-dir',
        dir,
        '--cache-backend',
        'memory',
        '--skip-db-update',
        '--skip-java-db-update',
        '--skip-vex-repo-update',
        '--skip-check-update',
        '--offline-scan',
        '--skip-version-check',
        '--disable-telemetry',
        '--module-dir',
        work('modules'),
        '--scanners',
        'vuln',
        '--pkg-types',
        'library',
        '--list-all-pkgs',
        '--ignorefile',
        work('trivyignore'),
        '--skip-dirs',
        '**/node_modules',
        '--skip-dirs',
        '**/.git',
        '--skip-dirs',
        '**/dist',
        '--skip-dirs',
        '**/build',
        '--skip-dirs',
        '**/target',
        '--skip-dirs',
        '**/vendor',
        '--skip-dirs',
        '**/obj',
        '--skip-dirs',
        '**/bin/Debug',
        '--skip-dirs',
        '**/bin/Release',
        '--skip-dirs',
        '**/.venv',
        '--skip-dirs',
        '**/venv',
        '--skip-dirs',
        '**/.tox',
        '--skip-dirs',
        '**/.nox',
        '--skip-dirs',
        '**/__pycache__',
        '--skip-dirs',
        '**/__pypackages__',
        '--skip-dirs',
        '**/.eggs',
        '--skip-dirs',
        '**/site-packages',
        '--skip-dirs',
        '**/Pods',
        '--skip-dirs',
        '**/Carthage',
        '--skip-dirs',
        '**/.build',
        '--timeout',
        '600s',
        '--format',
        'json',
        '--output',
        work('trivy.json'),
        '--quiet',
        '.',
      ],
      cwd: root,
      env: deadProxyEnv(),
      sarifPath: work('trivy.json'),
      okExitCodes: [0],
      version: null,
      database: { name: 'trivy-db', updatedAt: UPDATED_AT },
    });
    expect(typeof transform).toBe('function');
    expect(dropEnv).toBe(isTrivyVariable);
    expect(skipDirs()).toHaveLength(20);
  });

  it('passes a root .trivyignore, and warns about a database older than 14 days', async () => {
    const root = tmp();
    writeTree(root, { '.trivyignore': 'CVE-2021-44906\n' });
    const dir = database();
    const ctx = fakeContext(root, {
      binaries: { trivy: '/usr/bin/trivy' },
      config: { analyzers: { trivy: { timeoutSeconds: 60 } } },
    });
    mkdirSync(ctx.workDir, { recursive: true });
    const fresh = await createTrivyAnalyzer(dir, at('2026-10-09T06:36:11Z')).prepare(ctx);
    if (!('run' in fresh)) throw new Error(JSON.stringify(fresh));
    expect(fresh.run.args).toContain(path.join(root, '.trivyignore'));
    expect(fresh.run.args).toContain('60s');
    expect(fresh.run.warnings).toBeUndefined();
    const ctx2 = fakeContext(root, { binaries: { trivy: '/usr/bin/trivy' }, workDir: tmp() });
    const old = await createTrivyAnalyzer(dir, at('2026-10-10T06:36:12Z')).prepare(ctx2);
    if (!('run' in old)) throw new Error(JSON.stringify(old));
    expect(old.run.warnings).toEqual([
      {
        code: 'VULNERABILITY_DB_STALE',
        message:
          'the Trivy vulnerability database is 15 days old (built 2026-09-25); update the scanner image or set QUALOR_TRIVY_CACHE_DIR',
        count: 1,
      },
    ]);
  });

  it('skips without a database, and is unavailable without trivy or with unreadable metadata', async () => {
    const root = tmp();
    const ctx = () => fakeContext(root, { binaries: { trivy: '/usr/bin/trivy' }, workDir: tmp() });
    const empty = tmp();
    expect(await createTrivyAnalyzer(empty).prepare(ctx())).toEqual({
      skip: `no Trivy vulnerability database in ${empty} (it comes with the qualor/scanner image; or set QUALOR_TRIVY_CACHE_DIR)`,
    });
    for (const bad of [
      '{',
      { Version: 1, UpdatedAt: UPDATED_AT },
      { Version: 2 },
      { Version: 2, UpdatedAt: 'soon' },
    ]) {
      const dir = database(bad);
      expect(await createTrivyAnalyzer(dir).prepare(ctx()), JSON.stringify(bad)).toEqual({
        unavailable: `the Trivy vulnerability database in ${dir} cannot be read (db/metadata.json)`,
      });
    }
    expect(
      await createTrivyAnalyzer(database()).prepare(fakeContext(root, { workDir: tmp() })),
    ).toEqual({
      unavailable: 'Trivy is not installed (trivy on PATH or in the scanner image)',
    });
  });

  it('takes the database the CI names in QUALOR_TRIVY_CACHE_DIR', async () => {
    const root = tmp();
    const named = database();
    const ctx = fakeContext(root, {
      binaries: { trivy: '/usr/bin/trivy' },
      env: { QUALOR_TRIVY_CACHE_DIR: named },
    });
    mkdirSync(ctx.workDir, { recursive: true });
    const prep = await createTrivyAnalyzer(tmp()).prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args[prep.run.args.indexOf('--cache-dir') + 1]).toBe(named);
  });

  it('drops every TRIVY_ variable, in any case, and nothing else', () => {
    for (const name of ['TRIVY_SERVER', 'TRIVY_DB_REPOSITORY', 'trivy_config', 'Trivy_Cache_Dir']) {
      expect(isTrivyVariable(name), name).toBe(true);
    }
    for (const name of ['PATH', 'HTTP_PROXY', 'QUALOR_TRIVY_CACHE_DIR', 'MY_TRIVY_X']) {
      expect(isTrivyVariable(name), name).toBe(false);
    }
  });
});

describe('checkTrivyConfig: configuration errors (exit 2)', () => {
  it('refuses a relative QUALOR_TRIVY_CACHE_DIR or one inside the checkout', () => {
    const root = tmp();
    expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: 'cache/trivy' })).toBe(
      'QUALOR_TRIVY_CACHE_DIR must be an absolute path',
    );
    expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: path.join(root, 'db') })).toBe(
      'QUALOR_TRIVY_CACHE_DIR is inside the repository (the database must come from the CI, not the checkout)',
    );
    expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: tmp() })).toBeNull();
    expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: '' })).toBeNull();
  });

  it('refuses a .trivyignore that is not a regular file of at most 1 MiB', () => {
    const root = tmp();
    mkdirSync(path.join(root, '.trivyignore'));
    expect(checkTrivyConfig(root, cfg)).toBe('.trivyignore is not a regular file');
    const big = tmp();
    writeFileSync(path.join(big, '.trivyignore'), 'x'.repeat(1024 * 1024 + 1));
    expect(checkTrivyConfig(big, cfg)).toBe('.trivyignore is larger than 1 MiB');
    const ok = tmp();
    writeTree(ok, { '.trivyignore': 'CVE-2021-44906\n' });
    expect(checkTrivyConfig(ok, cfg)).toBeNull();
  });

  it.runIf(process.platform !== 'win32')(
    'refuses a .trivyignore that links out of the repository',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { ignore: 'CVE-1\n' });
      symlinkSync(path.join(outside, 'ignore'), path.join(root, '.trivyignore'));
      expect(checkTrivyConfig(root, cfg)).toBe('.trivyignore is outside the repository');
    },
  );

  it.runIf(process.platform !== 'win32')(
    'refuses a QUALOR_TRIVY_CACHE_DIR whose database files resolve into the checkout',
    () => {
      const refused = (file: string) =>
        `QUALOR_TRIVY_CACHE_DIR/db/${file} resolves into the repository (the database must come from the CI, not the checkout)`;
      for (const file of ['trivy.db', 'metadata.json']) {
        const root = tmp();
        writeTree(root, { [`planted/${file}`]: 'x' });
        const dir = database();
        rmSync(path.join(dir, 'db', file));
        symlinkSync(path.join(root, 'planted', file), path.join(dir, 'db', file));
        expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: dir })).toBe(refused(file));
      }
      const root = tmp();
      writeTree(root, { 'planted/trivy.db': 'x', 'planted/metadata.json': '{}' });
      const dir = tmp();
      symlinkSync(path.join(root, 'planted'), path.join(dir, 'db'));
      expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: dir })).toBe(
        refused('trivy.db'),
      );
      expect(checkTrivyConfig(root, cfg, { QUALOR_TRIVY_CACHE_DIR: database() })).toBeNull();
    },
  );

  it('reads the build time of the database only from version 2 metadata', () => {
    expect(readDatabaseDate(database())).toBe(UPDATED_AT);
    // report-format.md §9: at most 64 characters.
    const long = `2026-09-25T06:36:11.${'0'.repeat(50)}Z`;
    expect(readDatabaseDate(database({ Version: 2, UpdatedAt: long }))).toBeNull();
    expect(readDatabaseDate(tmp())).toBeNull();
  });
});

describe('Trivy JSON to SARIF (report-format.md §7.1)', () => {
  const copy = () => {
    const root = tmp();
    cpSync(TREE, root, { recursive: true });
    return root;
  };

  it('places each vulnerability at its lock entry’s version line: in Trivy’s range, else the name@version search', () => {
    const root = copy();
    const sarif = trivyJsonToSarif(recorded(RECORDED), root) as {
      runs: { tool: { driver: { version?: string; rules: unknown[] } }; results: unknown[] }[];
    };
    const run = sarif.runs[0]!;
    expect(run.tool.driver.version).toBe('0.74.0');
    expect(run.results).toEqual([
      expect.objectContaining({
        ruleId: 'CVE-2015-7501',
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'java/gradle.lockfile' },
              region: { startLine: 4, endLine: 4 },
            },
          },
        ],
        properties: {
          trivySeverity: 'CRITICAL',
          dependency: {
            name: 'commons-collections:commons-collections',
            version: '3.2.1',
            fixedVersion: '3.2.2',
            purl: 'pkg:maven/commons-collections/commons-collections@3.2.1',
            type: 'gradle',
          },
          vendorIds: ['GHSA-fjq5-5j5f-mvxh'],
        },
      }),
      expect.objectContaining({ ruleId: 'CVE-2015-6420' }),
      expect.objectContaining({
        ruleId: 'CVE-2021-44906',
        message: {
          text: 'minimist 1.2.5: CVE-2021-44906 minimist: prototype pollution (fixed in 1.2.6, 0.2.4)',
        },
        // pnpm-lock.yaml: Trivy gives no position; the first `minimist@1.2.5:` line is 17.
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'tools/pnpm-lock.yaml' },
              region: { startLine: 17 },
            },
          },
        ],
      }),
      expect.objectContaining({
        ruleId: 'CVE-2021-44906',
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'web/package-lock.json' },
              // Trivy’s entry is lines 14–19; its `"version": "1.2.5"` line is 15 (ruling T3).
              region: { startLine: 15, endLine: 15 },
            },
          },
        ],
      }),
    ]);
    // One rule per vulnerability id, whatever the number of lockfiles.
    expect(run.tool.driver.rules).toEqual([
      expect.objectContaining({ id: 'CVE-2015-7501' }),
      expect.objectContaining({ id: 'CVE-2015-6420' }),
      {
        id: 'CVE-2021-44906',
        name: 'CVE-2021-44906',
        shortDescription: { text: 'minimist: prototype pollution' },
        helpUri: 'https://avd.aquasec.com/nvd/cve-2021-44906',
        properties: { tags: ['dependency', 'pnpm'], cwe: ['CWE-1321'], trivySeverity: 'CRITICAL' },
      },
    ]);
  });

  it('becomes security findings whose hashes are the package, through the shared normaliser', () => {
    const root = copy();
    const capture: SarifCapture = {
      engineId: 'trivy',
      kind: 'builtin',
      status: 'ok',
      reason: null,
      durationMs: 1,
      version: null,
      required: false,
      sarif: trivyJsonToSarif(recorded(RECORDED), root),
      mapping: engineMapping('trivy')!,
    };
    const out = normalizeCaptures([capture], {
      repoRoot: root,
      readLines: fileLines(root),
      knownPaths: new Set([
        'java/gradle.lockfile',
        'tools/pnpm-lock.yaml',
        'web/package-lock.json',
      ]),
      log: silentLogger,
    });
    expect(findingKeys(out.findings)).toEqual([
      'trivy:CVE-2015-6420 java/gradle.lockfile:4 [high]',
      'trivy:CVE-2015-7501 java/gradle.lockfile:4 [blocker]',
      'trivy:CVE-2021-44906 tools/pnpm-lock.yaml:17 [blocker]',
      'trivy:CVE-2021-44906 web/package-lock.json:15 [blocker]',
    ]);
    const web = out.findings.find((f) => f.location?.path === 'web/package-lock.json')!;
    const hash = filelessHash('trivy:CVE-2021-44906', 'minimist@1.2.5', 'web/package-lock.json');
    expect([web.lineHash, web.contextHash]).toEqual([hash, hash]);
    expect(web.snippet?.startLine).toBe(12);
    expect(out.engines[0]!.rules.find((r) => r.id === 'CVE-2021-44906')).toMatchObject({
      quality: 'security',
      kind: 'issue',
      defaultSeverity: 'blocker',
      cwe: [1321],
      tags: ['dependency', 'pnpm'],
    });
    expect(out.warnings).toEqual([]);
  });

  it('keeps a finding at the file when the package cannot be found, and refuses what is not Trivy JSON', () => {
    const root = tmp();
    writeTree(root, { 'pnpm-lock.yaml': "lockfileVersion: '9.0'\n" });
    const vuln = {
      VulnerabilityID: 'GHSA-xxxx-yyyy-zzzz',
      PkgName: 'left-pad',
      InstalledVersion: '1.0.0',
      Severity: 'SUPER',
    };
    const sarif = trivyJsonToSarif(
      {
        SchemaVersion: 2,
        Results: [{ Target: 'pnpm-lock.yaml', Type: 'pnpm', Vulnerabilities: [vuln] }],
      },
      root,
    ) as { runs: { results: { locations: unknown[]; message: unknown; properties: unknown }[] }[] };
    const result = sarif.runs[0]!.results[0]!;
    expect(result.locations).toEqual([
      { physicalLocation: { artifactLocation: { uri: 'pnpm-lock.yaml' } } },
    ]);
    expect(result.message).toEqual({
      text: 'left-pad 1.0.0: GHSA-xxxx-yyyy-zzzz (no fixed version)',
    });
    expect(result.properties).toMatchObject({ trivySeverity: 'UNKNOWN' });
    expect(() => trivyJsonToSarif({ SchemaVersion: 1 }, root)).toThrow();
    expect(() => trivyJsonToSarif({ runs: [] }, root)).toThrow();
  });

  it('finds name@version as a whole word only', () => {
    const lines = [
      'packages:',
      '  not-minimist@1.2.5:',
      '  minimist@1.2.50:',
      "  '@scope/minimist@1.2.5':",
      '  minimist@1.2.5(peer@2.0.0):',
    ];
    expect(findPackageLine(lines, 'minimist', '1.2.5')).toBe(5);
    expect(findPackageLine(lines, '@scope/minimist', '1.2.5')).toBe(4);
    expect(findPackageLine(['/minimist@1.2.5:'], 'minimist', '1.2.5')).toBe(1);
    // pnpm lockfile v5: `/name/version:`, with peers `/name/version_peer@1.0.0:` (v5) or `(…)`.
    const v5 = [
      'packages:',
      '  /not-minimist/1.2.5:',
      '  /minimist/1.2.50:',
      '  minimist/1.2.5:',
      '  /@scope/minimist/1.2.5:',
      "  '/minimist/1.2.5_peer@2.0.0':",
      '  /minimist/1.2.5:',
    ];
    expect(findPackageLine(v5, 'minimist', '1.2.5')).toBe(6);
    expect(findPackageLine(v5.slice(0, 5).concat(v5[6]!), 'minimist', '1.2.5')).toBe(6);
    expect(findPackageLine(v5, '@scope/minimist', '1.2.5')).toBe(5);
    expect(findPackageLine(['  /minimist/1.2.5(peer@2.0.0):'], 'minimist', '1.2.5')).toBe(1);
    expect(findPackageLine(['  /minimist/1.2.5'], 'minimist', '1.2.5')).toBeNull();
    expect(findPackageLine(lines, 'minimist', '9.9.9')).toBeNull();
    expect(
      trivyMessage({ VulnerabilityID: 'CVE-1', PkgName: 'a', InstalledVersion: '1', Title: ' ' }),
    ).toBe('a 1: CVE-1 (no fixed version)');
  });

  it('moves a finding Trivy places to the line of its resolved version (ruling T3)', () => {
    const root = tmp();
    writeTree(root, {
      'package-lock.json': [
        '{',
        '  "packages": {',
        '    "node_modules/a": {',
        '      "version": "1.0.0",',
        '      "dependencies": { "b": "1.0.0" }',
        '    }',
        '  }',
        '}',
        '',
      ].join('\n'),
      'yarn.lock': ['a@^1.0.0:', '  version "1.0.0"', '  resolved "x"', ''].join('\n'),
      'berry/yarn.lock': [
        '"a@npm:^1.0.0":',
        '  version: 1.0.0',
        '  resolution: "a@npm:1.0.0"',
        '',
      ].join('\n'),
      'pom.xml': [
        '<project>',
        '  <properties>',
        '    <a.version>1.0.0</a.version>',
        '  </properties>',
        '  <dependency>',
        '    <groupId>g</groupId>',
        '    <artifactId>a</artifactId>',
        '    <version>${a.version}</version>',
        '  </dependency>',
        '  <dependency>',
        '    <groupId>g</groupId>',
        '    <artifactId>b</artifactId>',
        '    <version>2.0.0</version>',
        '  </dependency>',
        '  <dependency>',
        '    <groupId>g</groupId>',
        '    <artifactId>c</artifactId>',
        '    <version>${missing}</version>',
        '  </dependency>',
        '</project>',
        '',
      ].join('\n'),
      'Gemfile.lock': ['GEM', '  specs:', '    a (1.0.0)', ''].join('\n'),
    });
    const target = (
      Target: string,
      Type: string,
      name: string,
      version: string,
      at: [number, number],
    ) => ({
      Target,
      Type,
      Packages: [
        {
          ID: `${name}@${version}`,
          Name: name,
          Version: version,
          Locations: [{ StartLine: at[0], EndLine: at[1] }],
        },
      ],
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-1',
          PkgID: `${name}@${version}`,
          PkgName: name,
          InstalledVersion: version,
        },
      ],
    });
    const lineOf = (t: ReturnType<typeof target>) => {
      const sarif = trivyJsonToSarif({ SchemaVersion: 2, Results: [t] }, root) as {
        runs: { results: { locations: { physicalLocation: { region?: unknown } }[] }[] }[];
      };
      return sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region;
    };
    const one = (line: number) => ({ startLine: line, endLine: line });
    // npm: the `"version"` line of the entry, not the dependency range below it.
    expect(lineOf(target('package-lock.json', 'npm', 'a', '1.0.0', [3, 6]))).toEqual(one(4));
    // yarn v1 and berry.
    expect(lineOf(target('yarn.lock', 'yarn', 'a', '1.0.0', [1, 3]))).toEqual(one(2));
    expect(lineOf(target('berry/yarn.lock', 'yarn', 'a', '1.0.0', [1, 3]))).toEqual(one(2));
    // pom.xml: the property a `${…}` version names, a literal `<version>`, else the `<version>` line.
    expect(lineOf(target('pom.xml', 'pom', 'g:a', '1.0.0', [5, 9]))).toEqual(one(3));
    expect(lineOf(target('pom.xml', 'pom', 'g:b', '2.0.0', [10, 14]))).toEqual(one(13));
    expect(lineOf(target('pom.xml', 'pom', 'g:c', '3.0.0', [15, 19]))).toEqual(one(18));
    // Nothing in range holds the version, another ecosystem, or no readable file: the range start.
    expect(lineOf(target('package-lock.json', 'npm', 'a', '9.9.9', [3, 6]))).toEqual(one(3));
    expect(lineOf(target('Gemfile.lock', 'bundler', 'a', '1.0.0', [3, 3]))).toEqual(one(3));
    expect(lineOf(target('gone/package-lock.json', 'npm', 'a', '1.0.0', [3, 6]))).toEqual(one(3));
  });

  it('never reads a lockfile through a link, a dot segment or a directory', () => {
    const root = tmp();
    writeTree(root, { 'a/pnpm-lock.yaml': 'x\n' });
    expect(lockfileLines(root, 'a/pnpm-lock.yaml')).toEqual(['x']);
    for (const bad of [
      '',
      'a/../a/pnpm-lock.yaml',
      './a/pnpm-lock.yaml',
      'a',
      'a//pnpm-lock.yaml',
      'missing',
    ]) {
      expect(lockfileLines(root, bad), bad).toBeNull();
    }
  });

  it.runIf(process.platform !== 'win32')('does not follow a linked lockfile or directory', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'pnpm-lock.yaml': 'secret@1.0.0:\n' });
    symlinkSync(path.join(outside, 'pnpm-lock.yaml'), path.join(root, 'pnpm-lock.yaml'));
    symlinkSync(outside, path.join(root, 'dir'));
    expect(lockfileLines(root, 'pnpm-lock.yaml')).toBeNull();
    expect(lockfileLines(root, 'dir/pnpm-lock.yaml')).toBeNull();
  });
});

describe('the deps-vulnerable fixture (plan 2B)', () => {
  it('holds exactly the lockfiles the recorded Trivy output was taken over', () => {
    for (const file of [
      'web/package.json',
      'web/package-lock.json',
      'tools/package.json',
      'tools/pnpm-lock.yaml',
      'java/gradle.lockfile',
    ]) {
      expect(readFileSync(path.join(FIXTURES_DIR, 'deps-vulnerable', file), 'utf8'), file).toBe(
        readFileSync(path.join(TREE, file), 'utf8'),
      );
    }
  });
});

/** The database of the scanner image, which install.sh puts there (config.md §6). */
const IMAGE_DATABASE = '/opt/qualor/share/trivy/db/trivy.db';

describeWithTools(['trivy'])('Trivy on the deps-vulnerable fixture (real Trivy, offline)', () => {
  it('needs the scanner image’s database here', () => {
    expect(existsSync(IMAGE_DATABASE)).toBe(true);
  });

  it(
    'reports exactly the fixture findings, with the database date',
    { timeout: 300_000 },
    async () => {
      const { capture, out, keys } = await scanFixtureWith(trivyAnalyzer, 'deps-vulnerable', tmp());
      expect(capture.version).toBeNull();
      expect(out.engines[0]?.version).toBe('0.74.0');
      expect(out.engines[0]?.database).toEqual({
        name: 'trivy-db',
        updatedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      });
      expect(keys).toEqual(expectedKeys('deps-vulnerable', 'trivy'));
    },
  );

  it(
    'never reads trivy.yaml or TRIVY_ variables, and contacts nothing',
    { timeout: 300_000 },
    async () => {
      const listener = await startListener();
      try {
        const root = tmp();
        cpSync(path.join(FIXTURES_DIR, 'deps-vulnerable'), root, { recursive: true });
        // Each of these would make Trivy call the listener, or hide every finding, if it read it.
        writeTree(root, {
          'trivy.yaml': `server:\n  addr: ${listener.url}\ndb:\n  repository: 127.0.0.1:1/db\nseverity:\n  - LOW\n`,
        });
        const trivy = resolveBinary('trivy', { root, env: process.env })!;
        // The control run proves the vector: Trivy in client mode asks the listener.
        await runProcess(
          {
            command: trivy,
            args: ['fs', '--server', listener.url, '--scanners', 'vuln', '--quiet', '.'],
            cwd: root,
            env: { ...(process.env as Record<string, string>), NO_PROXY: '*', no_proxy: '*' },
            timeoutMs: 120_000,
          },
          silentLogger,
        );
        expect(listener.hits.length).toBeGreaterThan(0);
        listener.hits.length = 0;
        const config = parseConfig({ version: 1 });
        const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
        const [capture] = await runAnalyzers([trivyAnalyzer], {
          root,
          config,
          files,
          log: silentLogger,
          env: {
            ...process.env,
            TRIVY_SERVER: listener.url,
            TRIVY_DB_REPOSITORY: `${listener.url.replace('http://', '')}/db`,
            TRIVY_SEVERITY: 'LOW',
            TRIVY_SKIP_DB_UPDATE: 'false',
          },
        });
        expect(capture?.status, capture?.reason ?? '').toBe('ok');
        const out = normalizeCaptures([capture!], {
          repoRoot: root,
          readLines: fileLines(root),
          knownPaths: new Set(files.map((f) => f.path)),
          log: silentLogger,
        });
        expect(findingKeys(out.findings)).toEqual(expectedKeys('deps-vulnerable', 'trivy'));
        expect(listener.hits).toEqual([]);
      } finally {
        await listener.close();
      }
    },
  );

  it(
    'places each lockfile type’s finding at the line of its resolved version (ruling T3)',
    { timeout: 300_000 },
    async () => {
      const { out } = await scanFixtureWith(trivyAnalyzer, 'deps-vulnerable', tmp(), (root) =>
        writeTree(root, {
          'yarn/package.json':
            '{ "name": "deps-yarn", "version": "1.0.0", "dependencies": { "minimist": "1.2.5" } }\n',
          'yarn/yarn.lock': [
            '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.',
            '# yarn lockfile v1',
            '',
            '',
            'minimist@1.2.5:',
            '  version "1.2.5"',
            '  resolved "https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz#67d66014b66a6a8aaa0c083c5fd58df4e4e97602"',
            '  integrity sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==',
            '',
          ].join('\n'),
          // pnpm lockfile v5: Trivy gives no position; `/minimist/1.2.5:` is line 11.
          'pnpm5/package.json':
            '{ "name": "deps-pnpm5", "version": "1.0.0", "dependencies": { "minimist": "1.2.5" } }\n',
          'pnpm5/pnpm-lock.yaml': [
            'lockfileVersion: 5.4',
            '',
            'specifiers:',
            '  minimist: 1.2.5',
            '',
            'dependencies:',
            '  minimist: 1.2.5',
            '',
            'packages:',
            '',
            '  /minimist/1.2.5:',
            '    resolution: {integrity: sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==}',
            '    dev: false',
            '',
          ].join('\n'),
          'maven/pom.xml': [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<project xmlns="http://maven.apache.org/POM/4.0.0">',
            '  <modelVersion>4.0.0</modelVersion>',
            '  <groupId>com.example</groupId>',
            '  <artifactId>deps-maven</artifactId>',
            '  <version>1.0.0</version>',
            '  <properties>',
            '    <commons.version>3.2.1</commons.version>',
            '  </properties>',
            '  <dependencies>',
            '    <dependency>',
            '      <groupId>commons-collections</groupId>',
            '      <artifactId>commons-collections</artifactId>',
            '      <version>${commons.version}</version>',
            '    </dependency>',
            '    <dependency>',
            '      <groupId>org.apache.logging.log4j</groupId>',
            '      <artifactId>log4j-core</artifactId>',
            '      <version>2.14.1</version>',
            '    </dependency>',
            '  </dependencies>',
            '</project>',
            '',
          ].join('\n'),
        }),
      );
      const lines = (ruleId: string, file: string) =>
        out.findings
          .filter((f) => f.ruleId === ruleId && f.location?.path === file)
          .map((f) => f.location?.startLine);
      // package-lock.json: Trivy's entry is lines 14–19, `"version": "1.2.5"` is line 15.
      expect(lines('CVE-2021-44906', 'web/package-lock.json')).toEqual([15]);
      // pnpm-lock.yaml: no range from Trivy; `minimist@1.2.5:` holds the version itself.
      expect(lines('CVE-2021-44906', 'tools/pnpm-lock.yaml')).toEqual([17]);
      // pnpm-lock.yaml v5: `/minimist/1.2.5:`, not line 1.
      expect(lines('CVE-2021-44906', 'pnpm5/pnpm-lock.yaml')).toEqual([11]);
      // gradle.lockfile: one line per package.
      expect(lines('CVE-2015-7501', 'java/gradle.lockfile')).toEqual([4]);
      // yarn.lock: the entry is lines 5–8, `version "1.2.5"` is line 6.
      expect(lines('CVE-2021-44906', 'yarn/yarn.lock')).toEqual([6]);
      // pom.xml: a `${commons.version}` version is located at the property (line 8), a literal
      // one at its `<version>` line (19), not at `<dependency>` (11 and 16).
      expect(lines('CVE-2015-7501', 'maven/pom.xml')).toEqual([8]);
      expect(lines('CVE-2021-44228', 'maven/pom.xml')).toEqual([19]);
    },
  );

  it('honours a root .trivyignore', { timeout: 300_000 }, async () => {
    const { keys } = await scanFixtureWith(trivyAnalyzer, 'deps-vulnerable', tmp(), (root) =>
      writeTree(root, { '.trivyignore': '# accepted: not reachable\nCVE-2015-6420\n' }),
    );
    expect(keys).toEqual(
      expectedKeys('deps-vulnerable', 'trivy').filter((k) => !k.includes('CVE-2015-6420')),
    );
  });

  it.runIf(process.platform !== 'win32')(
    'does not follow a lockfile or a directory that links out of the repository',
    { timeout: 300_000 },
    async () => {
      const outside = tmp();
      cpSync(path.join(FIXTURES_DIR, 'deps-vulnerable', 'web'), outside, { recursive: true });
      const { keys } = await scanFixtureWith(trivyAnalyzer, 'deps-vulnerable', tmp(), (root) => {
        symlinkSync(path.join(outside, 'package-lock.json'), path.join(root, 'linked-lock.json'));
        mkdirSync(path.join(root, 'more'));
        symlinkSync(outside, path.join(root, 'more', 'web'));
      });
      expect(keys).toEqual(expectedKeys('deps-vulnerable', 'trivy'));
    },
  );
});
