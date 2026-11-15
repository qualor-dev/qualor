import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dependencyEntrySchema, type DependencyEntry } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { deadProxyEnv } from './offline';
import { execEnv } from './runner';
import { isTrivyVariable } from './trivy';
import {
  capInventory,
  goModLine,
  licenseCommand,
  licenseSkipDirs,
  mergeDuplicates,
  trivyJsonToInventory,
} from './trivy-licenses';

const tmp = useTempDirs();
const here = path.dirname(fileURLToPath(import.meta.url));
/** Trivy 0.74.0 output of the 6M probe (Task 1), trimmed to a few packages per target. */
const recorded = (name: string): unknown =>
  JSON.parse(
    readFileSync(path.join(here, '__fixtures__', 'trivy-licenses', `${name}.json`), 'utf8'),
  ) as unknown;

/** A Trivy JSON report of one `lang-pkgs` result per target. */
const trivyJson = (
  results: { Target: string; Type?: string; Class?: string; Packages?: unknown[] }[],
): unknown => ({
  SchemaVersion: 2,
  Trivy: { Version: '0.74.0' },
  Results: results.map((r) => ({ Class: 'lang-pkgs', ...r })),
});

const entry = (e: Partial<DependencyEntry> & { name: string }): DependencyEntry => ({
  ecosystem: 'npm',
  path: 'package-lock.json',
  version: '1.0.0',
  licenses: [],
  ...e,
});

describe('the licence pass command (spec §1)', () => {
  it('is the vulnerability pass without vuln, the built-in skips and the ignore file', () => {
    const root = tmp();
    const ctx = fakeContext(root, {
      binaries: { trivy: '/opt/qualor/bin/trivy' },
      workDir: tmp(),
      config: { sources: { exclude: ['legacy/**', '**/generated/**', '**/*.min.js'] } },
    });
    const cache = path.join(ctx.workDir, 'cache');
    const { dropEnv, env, ...run } = licenseCommand(ctx, cache);
    const work = (name: string) => path.join(ctx.workDir, name);
    expect(run).toEqual({
      command: '/opt/qualor/bin/trivy',
      args: [
        'fs',
        '--config',
        work('trivy-licenses.yaml'),
        '--cache-dir',
        cache,
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
        work('licenses-modules'),
        '--scanners',
        'license',
        '--pkg-types',
        'library',
        '--list-all-pkgs',
        '--skip-dirs',
        'legacy',
        '--skip-dirs',
        '**/generated',
        '--timeout',
        '300s',
        '--format',
        'json',
        '--output',
        work('licenses.json'),
        '--quiet',
        '.',
      ],
      cwd: root,
      sarifPath: work('licenses.json'),
      okExitCodes: [0],
      version: null,
    });
    // No vulnerability scan, no node_modules skip (pnpm's licences live there), no .trivyignore.
    expect(run.args).not.toContain('vuln');
    expect(run.args).not.toContain('**/node_modules');
    expect(run.args).not.toContain('--ignorefile');
    expect(dropEnv).toBe(isTrivyVariable);
    expect(env).toEqual(deadProxyEnv());
    expect(readFileSync(work('trivy-licenses.yaml'), 'utf8')).toBe('');
  });

  it('skips the scan’s cache directory inside the checkout, after the user’s excludes', () => {
    const ctx = {
      ...fakeContext(tmp(), {
        binaries: { trivy: 'trivy' },
        workDir: tmp(),
        config: { sources: { exclude: ['legacy/**'] } },
      }),
      // The scan's database step names it (D13-5): Trivy never reads the archive there.
      trivyCacheSkipDir: 'ci/trivy',
    };
    const { args } = licenseCommand(ctx, tmp());
    const last = args.lastIndexOf('--skip-dirs');
    expect(args.slice(last - 2, last + 3)).toEqual([
      '--skip-dirs',
      'legacy',
      '--skip-dirs',
      'ci/trivy',
      '--timeout',
    ]);
  });

  it('takes its own timeout', () => {
    const ctx = fakeContext(tmp(), {
      binaries: { trivy: 'trivy' },
      workDir: tmp(),
      config: { analyzers: { trivy: { licenseTimeoutSeconds: 42 } } },
    });
    const { args } = licenseCommand(ctx, tmp());
    expect(args[args.indexOf('--timeout') + 1]).toBe('42s');
  });

  it('turns only directory excludes into --skip-dirs', () => {
    expect(licenseSkipDirs(['a/**', '**/b/**', '*.min.js', '**/c/*.ts', 'd/'])).toEqual([
      'a',
      '**/b',
    ]);
  });

  it('drops every TRIVY_ variable and passes the package caches through', () => {
    const root = tmp();
    const ctx = fakeContext(root, {
      binaries: { trivy: 'trivy' },
      workDir: tmp(),
      env: {
        PATH: process.env['PATH'],
        GOPATH: '/go',
        GOMODCACHE: '/go/pkg/mod',
        NUGET_PACKAGES: '/nuget',
        HOME: '/home/ci',
        TRIVY_DB_REPOSITORY: 'evil.example/db',
        trivy_insecure: 'true',
      },
    });
    const run = licenseCommand(ctx, tmp());
    expect(run.env).toEqual({
      ...deadProxyEnv(),
      GOPATH: '/go',
      GOMODCACHE: '/go/pkg/mod',
      NUGET_PACKAGES: '/nuget',
      HOME: '/home/ci',
    });
    const child = execEnv(
      ctx.env,
      {
        ...(run.env !== undefined && { env: run.env }),
        ...(run.dropEnv !== undefined && { dropEnv: run.dropEnv }),
      },
      root,
    );
    expect(Object.keys(child).filter((k) => /^trivy_/i.test(k))).toEqual([]);
    expect(child['GOPATH']).toBe('/go');
    expect(child['GOMODCACHE']).toBe('/go/pkg/mod');
    expect(child['HTTPS_PROXY']).toBe(deadProxyEnv()['HTTPS_PROXY']);
  });

  it('sets GOPATH to ~/go when it is unset and the module cache is there', () => {
    const home = tmp();
    const ctx = (env: Record<string, string>) =>
      fakeContext(tmp(), { binaries: { trivy: 'trivy' }, workDir: tmp(), env });
    // Without a module cache Trivy would find nothing there: GOPATH stays unset.
    expect(licenseCommand(ctx({ HOME: home }), tmp()).env?.['GOPATH']).toBeUndefined();
    mkdirSync(path.join(home, 'go', 'pkg', 'mod'), { recursive: true });
    expect(licenseCommand(ctx({ HOME: home }), tmp()).env?.['GOPATH']).toBe(path.join(home, 'go'));
    expect(licenseCommand(ctx({ USERPROFILE: home }), tmp()).env?.['GOPATH']).toBe(
      path.join(home, 'go'),
    );
    // A GOPATH the CI set wins.
    expect(licenseCommand(ctx({ HOME: home, GOPATH: '/ci/go' }), tmp()).env?.['GOPATH']).toBe(
      '/ci/go',
    );
  });
});

describe('Trivy licence JSON to the dependency inventory (spec §1)', () => {
  const root = () => tmp();

  it('reads npm lockfile packages: Relationship gives direct, Class license is ignored', () => {
    const { entries, warnings } = trivyJsonToInventory(recorded('npm-lockfile-only'), root());
    expect(warnings).toEqual([]);
    expect(entries).toEqual([
      {
        ecosystem: 'npm',
        path: 'package-lock.json',
        line: 235,
        name: 'express',
        version: '4.22.3',
        licenses: ['MIT'],
        direct: true,
      },
      {
        ecosystem: 'npm',
        path: 'package-lock.json',
        line: 626,
        name: 'readline-sync',
        version: '1.4.10',
        licenses: ['MIT'],
        direct: true,
      },
      {
        ecosystem: 'npm',
        path: 'package-lock.json',
        line: 16,
        name: 'accepts',
        version: '1.3.8',
        licenses: ['MIT'],
        direct: false,
      },
    ]);
    for (const e of entries) expect(dependencyEntrySchema.parse(e)).toEqual(e);
  });

  it('gives pnpm packages no licence without node_modules, and theirs with it', () => {
    const bare = trivyJsonToInventory(recorded('pnpm-lockfile-only'), root()).entries;
    expect(bare.map((e) => [e.ecosystem, e.name, e.licenses, e.direct, e.line])).toEqual([
      ['pnpm', 'express', [], true, undefined],
      ['pnpm', 'readline-sync', [], true, undefined],
      ['pnpm', 'accepts', [], false, undefined],
    ]);
    const installed = trivyJsonToInventory(recorded('pnpm-installed'), root()).entries;
    expect(installed.map((e) => [e.name, e.licenses])).toEqual([
      ['express', ['MIT']],
      ['readline-sync', ['MIT']],
      ['accepts', ['MIT']],
    ]);
  });

  it('drops the root module of Go and yarn, and keeps the v of Go versions', () => {
    const go = trivyJsonToInventory(recorded('go-modcache'), root()).entries;
    expect(go.map((e) => [e.ecosystem, e.path, e.name, e.version, e.licenses, e.direct])).toEqual([
      ['gomod', 'go.mod', 'github.com/gin-gonic/gin', 'v1.9.1', ['MIT'], true],
      ['gomod', 'go.mod', 'github.com/sirupsen/logrus', 'v1.9.3', ['MIT'], true],
    ]);
    const noGopath = trivyJsonToInventory(recorded('go-no-gopath'), root()).entries;
    expect(noGopath.map((e) => e.licenses)).toEqual([[], []]);
    const yarn = trivyJsonToInventory(recorded('yarn1-lockfile-only'), root()).entries;
    expect(yarn.map((e) => e.name)).toEqual(['express', 'readline-sync']);
  });

  it('leaves direct out when Trivy does not say', () => {
    const pip = trivyJsonToInventory(recorded('pip-requirements'), root()).entries;
    expect(pip.map((e) => [e.name, e.line, 'direct' in e])).toEqual([
      ['paramiko', 2, false],
      ['requests', 1, false],
    ]);
    const indirectOnly = trivyJsonToInventory(
      trivyJson([
        {
          Target: 'a.lock',
          Type: 'npm',
          Packages: [
            { Name: 'x', Version: '1', Indirect: true },
            { Name: 'y', Version: '1' },
          ],
        },
      ]),
      root(),
    ).entries;
    expect(indirectOnly.map((e) => [e.name, e.direct])).toEqual([
      ['x', false],
      ['y', undefined],
    ]);
  });

  it('normalises, sorts and dedupes each licence list', () => {
    const { entries, warnings } = trivyJsonToInventory(
      trivyJson([
        {
          Target: 'package-lock.json',
          Type: 'npm',
          Packages: [
            { Name: 'a', Version: '1', Licenses: ['MIT', 'GPLv2+', 'mit', ' MIT ', ''] },
            { Name: 'd' },
          ],
        },
      ]),
      root(),
    );
    expect(entries.map((e) => [e.name, e.version, e.licenses])).toEqual([
      ['a', '1', ['GPL-2.0-or-later', 'MIT']],
      ['d', '', []],
    ]);
    expect(warnings).toEqual([]);
  });

  it('drops a licence string over 256 characters rather than cut it, and counts it', () => {
    // Cut short, this expression would lose its permissive alternative and read as GPL only.
    const long = `${Array.from({ length: 40 }, () => 'GPL-3.0-only').join(' OR ')} OR MIT`;
    expect(long.length).toBeGreaterThan(256);
    const { entries, warnings } = trivyJsonToInventory(
      trivyJson([
        {
          Target: 'package-lock.json',
          Type: 'npm',
          Packages: [
            { Name: 'only-long', Version: '1', Licenses: [long] },
            { Name: 'with-other', Version: '1', Licenses: ['x'.repeat(300), 'Apache-2.0'] },
          ],
        },
      ]),
      root(),
    );
    // Nothing left is unknown ([]), never a truncated expression.
    expect(entries.map((e) => [e.name, e.licenses])).toEqual([
      ['only-long', []],
      ['with-other', ['Apache-2.0']],
    ]);
    expect(warnings).toEqual([
      {
        code: 'DEPENDENCY_LICENSES_SKIPPED',
        message: expect.stringContaining('2 licence strings') as string,
        count: 2,
      },
    ]);
    expect(warnings[0]?.message).toMatch(/longer than 256 characters/);
  });

  it('keeps 16 licences of a package and counts the ones left out', () => {
    const many = Array.from({ length: 20 }, (_, i) => `Custom-${String(i).padStart(2, '0')}`);
    const { entries, warnings } = trivyJsonToInventory(
      trivyJson([
        {
          Target: 'package-lock.json',
          Type: 'npm',
          Packages: [{ Name: 'b', Version: '1', Licenses: many }],
        },
      ]),
      root(),
    );
    expect(entries.map((e) => e.licenses)).toEqual([many.slice(0, 16)]);
    expect(warnings).toEqual([
      {
        code: 'DEPENDENCY_LICENSES_SKIPPED',
        message: expect.stringContaining('4 licence strings') as string,
        count: 4,
      },
    ]);
  });

  it('places a package at its version line, else a name@version search, else its go.mod line', () => {
    const dir = root();
    writeTree(dir, {
      'web/package-lock.json': readFileSync(
        path.join(here, '../../../fixtures/deps-licenses/web/package-lock.json'),
        'utf8',
      ),
      'app/pnpm-lock.yaml': readFileSync(
        path.join(here, '../../../fixtures/deps-licenses/app/pnpm-lock.yaml'),
        'utf8',
      ),
      'svc/go.mod':
        'module x\n\ngo 1.22\n\nrequire github.com/a/b v1.0.0\n\nrequire (\n\tgithub.com/c/d v2.1.0 // indirect\n)\n',
    });
    const { entries } = trivyJsonToInventory(
      trivyJson([
        {
          Target: 'web/package-lock.json',
          Type: 'npm',
          // Trivy's range of the entry; the version line inside it is the place (ruling T3).
          Packages: [
            { Name: 'apache-lib', Version: '3.1.0', Locations: [{ StartLine: 16, EndLine: 22 }] },
          ],
        },
        {
          Target: 'app/pnpm-lock.yaml',
          Type: 'pnpm',
          Packages: [{ Name: 'tiny-util', Version: '0.4.2' }],
        },
        {
          Target: 'svc/go.mod',
          Type: 'gomod',
          Packages: [
            { Name: 'github.com/a/b', Version: 'v1.0.0' },
            { Name: 'github.com/c/d', Version: 'v2.1.0' },
            { Name: 'github.com/e/f', Version: 'v0.1.0' },
          ],
        },
      ]),
      dir,
    );
    expect(entries.map((e) => [e.path, e.name, e.line])).toEqual([
      ['web/package-lock.json', 'apache-lib', 17],
      ['app/pnpm-lock.yaml', 'tiny-util', 17],
      ['svc/go.mod', 'github.com/a/b', 5],
      ['svc/go.mod', 'github.com/c/d', 8],
      ['svc/go.mod', 'github.com/e/f', undefined],
    ]);
  });

  it('finds a go.mod requirement as a whole word only', () => {
    const lines = [
      'module example.com/m',
      'require example.com/a v1.0.0',
      'replace example.com/b v1.0.0 => ../b',
      'require (',
      '\texample.com/b v1.0.0',
      '\texample.com/c v1.0.0-pre // indirect',
      ')',
    ];
    expect(goModLine(lines, 'example.com/a', 'v1.0.0')).toBe(2);
    expect(goModLine(lines, 'example.com/b', 'v1.0.0')).toBe(5);
    expect(goModLine(lines, 'example.com/c', 'v1.0.0-pre')).toBe(6);
    expect(goModLine(lines, 'example.com/c', 'v1.0.0')).toBeNull();
    expect(goModLine(lines, 'example.com', 'v1.0.0')).toBeNull();
  });

  it('drops lockfiles under sources.exclude, and results that are not packages of a lockfile', () => {
    const json = trivyJson([
      { Target: 'web/package-lock.json', Type: 'npm', Packages: [{ Name: 'a', Version: '1' }] },
      { Target: 'legacy/package-lock.json', Type: 'npm', Packages: [{ Name: 'b', Version: '1' }] },
      {
        Target: 'web/package-lock.json',
        Class: 'license',
        Packages: [{ Name: 'c', Version: '1' }],
      },
      { Target: 'x/Dockerfile', Class: 'config', Type: 'dockerfile', Packages: [] },
    ]);
    const { entries, warnings } = trivyJsonToInventory(json, root(), {
      exclude: (p) => p.startsWith('legacy/'),
    });
    expect(entries.map((e) => `${e.path} ${e.name}`)).toEqual(['web/package-lock.json a']);
    expect(warnings).toEqual([]);
  });

  it('drops and counts the lockfiles outside the scan’s files, as the vulnerability pass does (Task 11 C1)', () => {
    const cached = '.go/pkg/mod/github.com/bytedance/sonic@v1.9.1/go.mod';
    const json = trivyJson([
      { Target: 'go.mod', Type: 'gomod', Packages: [{ Name: 'example.com/a', Version: 'v1.0.0' }] },
      {
        Target: cached,
        Type: 'gomod',
        Packages: [
          { Name: 'example.com/b', Version: 'v1.0.0' },
          { Name: 'example.com/c', Version: 'v1.0.0' },
          { Name: 'github.com/bytedance/sonic', Version: 'v1.9.1', Relationship: 'root' },
        ],
      },
      {
        Target: './.go/pkg/mod/github.com/x/y@v2.0.0/go.mod',
        Type: 'gomod',
        Packages: [{ Name: 'example.com/d', Version: 'v1.0.0' }],
      },
      {
        Target: 'pkg/testdata/package-lock.json',
        Type: 'npm',
        Packages: [{ Name: 'e', Version: '1' }],
      },
      { Target: 'legacy/package-lock.json', Type: 'npm', Packages: [{ Name: 'f', Version: '1' }] },
    ]);
    const { entries, warnings } = trivyJsonToInventory(json, root(), {
      knownPaths: new Set(['go.mod', 'go.sum', 'pkg/main.go']),
      exclude: (p) => p.startsWith('legacy/'),
    });
    expect(entries.map((e) => `${e.path} ${e.name}`)).toEqual(['go.mod example.com/a']);
    expect(warnings).toEqual([
      {
        code: 'DEPENDENCIES_OUT_OF_SCOPE',
        message: expect.stringContaining('4 dependencies from 3 lockfiles') as string,
        count: 4,
      },
    ]);
  });

  it('skips and counts what the report cannot carry, rather than failing', () => {
    const { entries, warnings } = trivyJsonToInventory(
      trivyJson([
        {
          Target: './web\\package-lock.json',
          Type: 'npm',
          Packages: [
            { Name: 'ok', Version: '1' },
            { Name: 'n'.repeat(513), Version: '1' },
            { Name: 'v', Version: '1'.repeat(257) },
            { Version: '1' },
          ],
        },
        { Target: 'Weird.lock', Type: 'Not An Ecosystem', Packages: [{ Name: 'w', Version: '1' }] },
        {
          Target: `${'d/'.repeat(520)}x.lock`,
          Type: 'npm',
          Packages: [{ Name: 'p', Version: '1' }],
        },
        {
          Target: '../outside/package-lock.json',
          Type: 'npm',
          Packages: [{ Name: 'o', Version: '1' }],
        },
      ]),
      root(),
    );
    expect(entries.map((e) => `${e.path} ${e.name}`)).toEqual(['web/package-lock.json ok']);
    expect(warnings).toEqual([
      {
        code: 'DEPENDENCIES_SKIPPED',
        message: expect.stringContaining('6 dependencies'),
        count: 6,
      },
    ]);
  });

  it('refuses output that is not Trivy JSON', () => {
    expect(() => trivyJsonToInventory({ runs: [] }, root())).toThrow();
    expect(() => trivyJsonToInventory('{}', root())).toThrow();
  });
});

describe('merging and capping the inventory (spec §2)', () => {
  it('merges entries of one lockfile, ecosystem, name and version into the union of their licences', () => {
    const merged = mergeDuplicates([
      entry({ name: 'a', licenses: ['MIT'], line: 9, direct: false }),
      entry({ name: 'b', licenses: [] }),
      entry({ name: 'a', licenses: ['Apache-2.0', 'MIT'], line: 4 }),
      entry({ name: 'a', ecosystem: 'yarn', licenses: ['ISC'] }),
      entry({ name: 'a', licenses: [], direct: true }),
    ]);
    expect(merged).toEqual([
      entry({ name: 'a', licenses: ['Apache-2.0', 'MIT'], line: 4, direct: true }),
      entry({ name: 'b', licenses: [] }),
      entry({ name: 'a', ecosystem: 'yarn', licenses: ['ISC'] }),
    ]);
  });

  it('keeps at most 16 licences when merging, and counts the ones left out', () => {
    const a = Array.from({ length: 10 }, (_, i) => `A-${i}`);
    const b = Array.from({ length: 10 }, (_, i) => `B-${i}`);
    const stats = { licensesDropped: 0 };
    const [m] = mergeDuplicates(
      [entry({ name: 'x', licenses: a }), entry({ name: 'x', licenses: b })],
      stats,
    );
    expect(m?.licenses).toEqual([...a, ...b].sort().slice(0, 16));
    // Licences are AND-combined: the 4 left out could hold the forbidden one, so they are counted.
    expect(stats.licensesDropped).toBe(4);
  });

  it('puts direct dependencies first, then orders by path, name and version', () => {
    const { entries, truncated } = capInventory([
      entry({ path: 'b.lock', name: 'z' }),
      entry({ path: 'a.lock', name: 'y', direct: false }),
      entry({ path: 'b.lock', name: 'a', direct: true }),
      entry({ path: 'a.lock', name: 'y', version: '0.9.0' }),
      entry({ path: 'c.lock', name: 'a', direct: true }),
    ]);
    expect(truncated).toBe(false);
    expect(entries.map((e) => `${e.path} ${e.name}@${e.version}`)).toEqual([
      'b.lock a@1.0.0',
      'c.lock a@1.0.0',
      'a.lock y@0.9.0',
      'a.lock y@1.0.0',
      'b.lock z@1.0.0',
    ]);
  });

  it('keeps 50 000 of 60 000 entries, the direct ones first', () => {
    const all = Array.from({ length: 60_000 }, (_, i) =>
      entry({ name: `p${String(i).padStart(5, '0')}`, direct: i % 6 === 0 }),
    );
    const { entries, truncated } = capInventory(all);
    expect(truncated).toBe(true);
    expect(entries).toHaveLength(50_000);
    expect(entries.slice(0, 10_000).every((e) => e.direct === true)).toBe(true);
    expect(entries.slice(10_000).some((e) => e.direct === true)).toBe(false);
    expect(capInventory(all, 3).entries.map((e) => e.name)).toEqual(['p00000', 'p00006', 'p00012']);
  });
});
