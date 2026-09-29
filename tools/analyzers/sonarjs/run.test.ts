import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Qualor's sonarjs pass (config.md §6). The real-tool tests run where the pass is installed
 * (`npm ci --omit=dev --ignore-scripts` in tools/analyzers/sonarjs, as in the qualor/scanner
 * image) and categories.json has been built next to run.mjs (`node categories.mjs <rules dir>`);
 * they are skipped elsewhere.
 */
const DIR = path.resolve('tools/analyzers/sonarjs');
const RUN = path.join(DIR, 'run.mjs');
const installed = existsSync(path.join(DIR, 'node_modules/eslint-plugin-sonarjs/package.json'));
const have = installed && existsSync(path.join(DIR, 'categories.json'));

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(os.tmpdir(), 'sonarjs-'));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    writeFileSync(path.join(root, f), text);
  }
  return root;
}
function run(root: string, extra: string[] = []) {
  const out = path.join(root, '..', path.basename(root) + '.sarif');
  const stdout = execFileSync(process.execPath, [RUN, '--root', root, '--out', out, ...extra], {
    encoding: 'utf8',
  });
  return {
    log: JSON.parse(readFileSync(out, 'utf8')),
    info: JSON.parse(stdout.trim().split('\n').at(-1)!),
  };
}

// S1871 (no-duplicated-branches), no type information needed.
const BRANCHES = [
  'export function f(a, b) {',
  '  if (a) {',
  '    b.push(1);',
  '    b.push(2);',
  '  } else if (b) {',
  '    b.push(1);',
  '    b.push(2);',
  '  }',
  '}',
  '',
].join('\n');
// S2871 (no-alphabetical-sort), type-aware.
const SORT = 'export const sorted = [3, 1, 2].sort();\n';
const TSCONFIG = '{ "compilerOptions": { "strict": true }, "include": ["*.ts"] }';
const ruleIds = (log: { runs: { results: { ruleId: string }[] }[] }) =>
  log.runs[0]!.results.map((r) => r.ruleId);

describe.skipIf(!have)('sonarjs run.mjs', { timeout: 120_000 }, () => {
  it('reports a finding under its RSPEC key, with the plugin rule name and a category', () => {
    const root = repo({ 'a.js': BRANCHES });
    const { log, info } = run(root);
    expect(info).toEqual({ typeChecking: 'off', files: 1, parseErrors: 0, disabledRules: [] });
    expect(log.version).toBe('2.1.0');
    expect(log.runs[0].tool.driver).toMatchObject({
      name: 'eslint-plugin-sonarjs',
      version: '2.0.4',
    });
    const results = log.runs[0].results;
    expect(results).toContainEqual(
      expect.objectContaining({
        ruleId: 'S1871',
        locations: [
          expect.objectContaining({
            physicalLocation: expect.objectContaining({ artifactLocation: { uri: 'a.js' } }),
          }),
        ],
      }),
    );
    const rule = log.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'S1871');
    expect(rule.name).toBe('no-duplicated-branches');
    expect(rule.helpUri).toBe('https://rules.sonarsource.com/javascript/RSPEC-1871');
    expect(rule.properties.category).toMatch(/^(Blocker|Critical|Major|Minor|Info) Code Smell$/);
  });

  it("runs the plugin's recommended config: S1192 is off there", () => {
    const s = "'dup-string-value';";
    const { log } = run(repo({ 'a.js': `${s}\n${s}\n${s}\n${s}\n` }));
    expect(log.runs[0].results.map((r: { ruleId: string }) => r.ruleId)).not.toContain('S1192');
  });

  it('runs the decorated ESLint core rules that need ESLint 8 option defaults', () => {
    const { log } = run(repo({ 'a.js': 'function g() {}\nlet q;\nq && g();\n' }));
    const ids = log.runs[0].results.map((r: { ruleId: string }) => r.ruleId).sort();
    expect(ids).toEqual(['S1186', 'S905']);
  });

  it('never loads the project ESLint config (untrusted checkout)', () => {
    const root = repo({
      'eslint.config.js': 'throw new Error("project config executed")',
      'a.js': 'var x = 1;\n',
    });
    expect(() => run(root)).not.toThrow();
  });

  it('never lints node_modules or the given excludes', () => {
    const clean = 'export const a = 1;\n';
    // Ruling 3: the one linted file triggers no rule on its own, and the excluded ones do, so an
    // empty result means they were excluded, not that the rules were silent.
    expect(run(repo({ 'src/a.js': clean })).log.runs[0].results).toEqual([]);
    expect(run(repo({ 'src/b.js': BRANCHES })).log.runs[0].results).not.toEqual([]);
    const root = repo({
      'node_modules/p/i.js': BRANCHES,
      'dist/b.js': BRANCHES,
      'src/a.js': clean,
    });
    const { log, info } = run(root, ['--exclude', 'dist/**']);
    expect(log.runs[0].results).toEqual([]);
    expect(info.files).toBe(1);
  });

  it('runs type-aware rules with a valid tsconfig', () => {
    const root = repo({ 'tsconfig.json': TSCONFIG, 'a.ts': SORT });
    const { log, info } = run(root);
    expect(info).toEqual({ typeChecking: 'on', files: 1, parseErrors: 0, disabledRules: [] });
    expect(ruleIds(log)).toContain('S2871');
  });

  it('falls back to rules without type information when the tsconfig is broken', () => {
    const root = repo({
      'tsconfig.json': '{ "compilerOptions": { "strict": ',
      'a.ts': SORT + BRANCHES,
    });
    const { log, info } = run(root, ['--type-checking', 'on']);
    expect(info.typeChecking).toBe('fallback');
    // Review focus 2: the rules without type information still report.
    expect(ruleIds(log)).toContain('S1871');
    expect(ruleIds(log)).not.toContain('S2871');
  });

  it('lints a file outside the tsconfig without type information, and the rest with it', () => {
    const root = repo({ 'tsconfig.json': TSCONFIG, 'a.ts': SORT, 'tools/b.js': BRANCHES });
    const { log, info } = run(root);
    expect(info).toEqual({ typeChecking: 'fallback', files: 2, parseErrors: 0, disabledRules: [] });
    expect(ruleIds(log)).toEqual(expect.arrayContaining(['S2871', 'S1871']));
  });

  it('never asks for type information with --type-checking off', () => {
    const root = repo({ 'tsconfig.json': TSCONFIG, 'a.ts': SORT });
    const { log, info } = run(root, ['--type-checking', 'off']);
    expect(info.typeChecking).toBe('off');
    expect(ruleIds(log)).not.toContain('S2871');
  });

  it('runs without a tsconfig and reports typeChecking off', () => {
    const root = repo({ 'a.ts': 'const s: string = "x";\n' });
    expect(run(root).info.typeChecking).toBe('off');
  });

  it('drops a negated exclude, which would re-include node_modules', () => {
    const root = repo({ 'node_modules/p/i.js': BRANCHES, 'src/a.js': 'export const a = 1;\n' });
    const out = path.join(root, '..', path.basename(root) + '.sarif');
    const r = spawnSync(
      process.execPath,
      [RUN, '--root', root, '--out', out, '--exclude', '!**/node_modules/**'],
      { encoding: 'utf8' },
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('ignoring the negated --exclude "!**/node_modules/**"');
    expect(JSON.parse(readFileSync(out, 'utf8')).runs[0].results).toEqual([]);
    expect(JSON.parse(r.stdout.trim()).files).toBe(1);
  });

  it('never lints a symbolic link or junction, to a file or directory, inside or outside the root', () => {
    const outside = repo({ 'x.js': BRANCHES, 'dir/y.js': BRANCHES });
    const root = repo({
      'src/a.js': 'export const a = 1;\n',
      'vendor/b.js': BRANCHES,
      'data/z.txt': BRANCHES,
    });
    // Directory junctions need no privilege on Windows; file links may (developer mode), so the
    // file links are left out there when they cannot be made.
    symlinkSync(path.join(outside, 'dir'), path.join(root, 'src/linked'), 'junction');
    symlinkSync(path.join(root, 'vendor'), path.join(root, 'src/inner'), 'junction');
    for (const [target, link] of [
      [path.join(outside, 'x.js'), 'src/l.js'],
      [path.join(root, 'data/z.txt'), 'src/m.js'],
    ] as const) {
      try {
        symlinkSync(target, path.join(root, link), 'file');
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
      }
    }
    // Every target reports when it is linted as a regular file.
    expect(ruleIds(run(outside).log)).toEqual(['S1871', 'S1871']);
    expect(ruleIds(run(root).log)).toEqual(['S1871']);
    const { log, info } = run(root, ['--exclude', 'vendor/**']);
    expect(log.runs[0].results).toEqual([]);
    expect(info.files).toBe(1);
  });

  it('counts the files that did not parse in parseErrors', () => {
    const root = repo({ 'bad.js': 'function (\n', 'a.js': BRANCHES });
    const { log, info } = run(root);
    expect(info).toEqual({ typeChecking: 'off', files: 2, parseErrors: 1, disabledRules: [] });
    expect(ruleIds(log)).toEqual(['S1871']);
  });

  it('exits 2 on an internal error', () => {
    expect(() =>
      execFileSync(process.execPath, [RUN, '--out', path.join(os.tmpdir(), 'x.sarif')], {
        stdio: 'pipe',
      }),
    ).toThrow(expect.objectContaining({ status: 2 }));
  });
});

describe('sonarjs categories.mjs', () => {
  it('turns RSPEC metadata into SonarQube category words', async () => {
    // @ts-expect-error: a plain ES module of the image, without type declarations
    const { categoryOf } = await import('./categories.mjs');
    expect(categoryOf({ type: 'CODE_SMELL', defaultSeverity: 'Critical' })).toBe(
      'Critical Code Smell',
    );
    expect(categoryOf({ type: 'SECURITY_HOTSPOT', defaultSeverity: 'Minor' })).toBe(
      'Minor Security Hotspot',
    );
    expect(categoryOf({ type: 'VULNERABILITY', defaultSeverity: 'Blocker' })).toBe(
      'Blocker Vulnerability',
    );
    expect(categoryOf({ type: 'BUG' })).toBeNull();
    expect(categoryOf({ type: 'OTHER', defaultSeverity: 'Major' })).toBeNull();
  });
});

describe('sonarjs licences.mjs', () => {
  it('accepts MPL-2.0 and CC-BY-4.0 only for the packages that carry them', async () => {
    // @ts-expect-error: a plain ES module of the image, without type declarations
    const { licenceProblem } = await import('./licences.mjs');
    expect(licenceProblem('eslint', 'MIT')).toBeNull();
    expect(licenceProblem('eslint-plugin-sonarjs', 'LGPL-3.0-only')).toBeNull();
    expect(licenceProblem('axe-core', 'MPL-2.0')).toBeNull();
    expect(licenceProblem('caniuse-lite', 'CC-BY-4.0')).toBeNull();
    expect(licenceProblem('other', 'MPL-2.0')).toMatch(/other: MPL-2\.0/);
    expect(licenceProblem('other', 'CC-BY-4.0')).toMatch(/CC-BY-4\.0/);
    expect(licenceProblem('other', 'GPL-3.0')).toMatch(/GPL-3\.0/);
    expect(licenceProblem('other', undefined)).toMatch(/no licence/);
  });

  it.skipIf(!installed)(
    'the committed SONARJS-DEPENDENCIES.txt matches the installed tree',
    async () => {
      // @ts-expect-error: a plain ES module of the image, without type declarations
      const { dependencyNotice } = await import('./licences.mjs');
      const committed = readFileSync('deploy/scanner/licenses/SONARJS-DEPENDENCIES.txt', 'utf8');
      expect(dependencyNotice(path.join(DIR, 'node_modules')) === committed).toBe(true);
    },
  );
});

describe('sonarjs pins', () => {
  const pkg = JSON.parse(readFileSync(path.join(DIR, 'package.json'), 'utf8')) as {
    license: string;
    private: boolean;
    dependencies: Record<string, string>;
  };
  const installSh = readFileSync('tools/analyzers/install.sh', 'utf8');

  it('pins the LGPL eslint-plugin-sonarjs 2.0.4 and ESLint 9 exactly, as install.sh names them', () => {
    expect(pkg).toMatchObject({ license: 'MIT', private: true });
    expect(pkg.dependencies['eslint-plugin-sonarjs']).toBe('2.0.4');
    expect(pkg.dependencies['eslint']).toMatch(/^9\.\d+\.\d+$/);
    for (const version of Object.values(pkg.dependencies))
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(installSh).toMatch(/^SONARJS_VERSION=2\.0\.4$/m);
    expect(installSh).toMatch(/^SONARJS_COMMIT=273825f98b35b29b409fbf4f89efce075c651d96$/m);
    expect(installSh).toMatch(/^SONARJS_SOURCE_SHA256=[0-9a-f]{64}$/m);
  });

  it.each(['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])(
    '%s installs it from the lockfile and checks the source archive before unpacking it',
    (file) => {
      const text = readFileSync(file, 'utf8');
      expect(text).toContain('npm ci --omit=dev --ignore-scripts');
      expect(text).toContain('"${SONARJS_SOURCE_SHA256}  /tmp/sonarjs.tar.gz" | sha256sum -c -');
      const check = text.indexOf('/tmp/sonarjs.tar.gz" | sha256sum -c -');
      expect(check).toBeGreaterThan(0);
      expect(check).toBeLessThan(text.indexOf('tar -xzf /tmp/sonarjs.tar.gz'));
      expect(text).toContain('node categories.mjs /tmp/sonarjs-rules');
      expect(text).toContain('chmod -R a+rX /opt/qualor/sonarjs');
    },
  );
});

describe.skipIf(!installed)('sonarjs run.mjs helpers', () => {
  const load = async () => {
    // @ts-expect-error: a plain ES module of the image, without type declarations
    return (await import('./run.mjs')) as {
      usableExcludes: (g: string[], warn: (l: string) => void) => string[];
      lintGuarded: <T>(
        lint: () => Promise<T>,
        disabled: Set<string>,
        warn: (l: string) => void,
      ) => Promise<T>;
      summary: (
        mode: string,
        results: { messages: { fatal?: boolean }[] }[],
        disabled: Set<string>,
        keyOf: Map<string, string>,
      ) => unknown;
      rspecKeys: () => Map<string, string>;
    };
  };

  it('usableExcludes keeps plain globs and drops negated ones with a note', async () => {
    const { usableExcludes } = await load();
    const notes: string[] = [];
    expect(usableExcludes(['dist/**', '!**/node_modules/**', ' !x'], (l) => notes.push(l))).toEqual(
      ['dist/**'],
    );
    expect(notes).toHaveLength(2);
  });

  it('lintGuarded turns a crashing rule off and lints again, once per rule', async () => {
    const { lintGuarded } = await load();
    const disabled = new Set<string>();
    const notes: string[] = [];
    let calls = 0;
    const lint = async () => {
      calls += 1;
      if (!disabled.has('sonarjs/no-empty-function'))
        throw new Error("Error while loading rule 'sonarjs/no-empty-function': boom");
      if (!disabled.has('sonarjs/no-dead-store'))
        throw new Error('boom\nOccurred while linting /r/a.js:1\nRule: "sonarjs/no-dead-store"');
      return ['ok'];
    };
    expect(await lintGuarded(lint, disabled, (l) => notes.push(l))).toEqual(['ok']);
    expect(calls).toBe(3);
    expect([...disabled]).toEqual(['sonarjs/no-empty-function', 'sonarjs/no-dead-store']);
    expect(notes).toHaveLength(2);
    // Not a rule crash, or the same rule again: the error stands.
    await expect(
      lintGuarded(
        async () => Promise.reject(new Error('disk full')),
        new Set(),
        () => {},
      ),
    ).rejects.toThrow('disk full');
    await expect(
      lintGuarded(
        async () => Promise.reject(new Error('Rule: "sonarjs/no-dead-store"')),
        disabled,
        () => {},
      ),
    ).rejects.toThrow();
  });

  it('summary reports parse errors and the disabled rules by RSPEC key', async () => {
    const { summary, rspecKeys } = await load();
    const results = [{ messages: [{ fatal: true }] }, { messages: [{}] }, { messages: [] }];
    const disabled = new Set(['sonarjs/no-empty-function', 'sonarjs/no-dead-store']);
    expect(summary('fallback', results, disabled, rspecKeys())).toEqual({
      typeChecking: 'fallback',
      files: 3,
      parseErrors: 1,
      disabledRules: ['S1186', 'S1854'],
    });
  });
});
