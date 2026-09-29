import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Qualor's sonarjs pass (config.md §6). The real-tool tests run where the pass is installed: in
 * QUALOR_SONARJS_DIR when it is set, else in /opt/qualor/sonarjs when install-sonarjs.sh put it
 * there (CI, the qualor/scanner image, the analyzers toolbox), else in tools/analyzers/sonarjs
 * (`npm ci --omit=dev --ignore-scripts` there, and categories.json built next to run.mjs with
 * `node categories.mjs <rules dir>`). They are skipped where it is not installed, unless
 * QUALOR_REQUIRE_ANALYZERS=1 (the CI test jobs), which turns a missing pass into a failure.
 */
const SOURCE = path.resolve('tools/analyzers/sonarjs');
const INSTALLED = '/opt/qualor/sonarjs';
function sonarjsDir(env: NodeJS.ProcessEnv, exists: (p: string) => boolean): string {
  const configured = env['QUALOR_SONARJS_DIR'];
  if (configured) return path.resolve(configured);
  return exists(path.join(INSTALLED, 'run.mjs')) ? INSTALLED : SOURCE;
}
const DIR = sonarjsDir(process.env, existsSync);
const RUN = path.join(DIR, 'run.mjs');
const installed = existsSync(path.join(DIR, 'node_modules/eslint-plugin-sonarjs/package.json'));
const have = installed && existsSync(path.join(DIR, 'categories.json'));
const required = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';

describe('sonarjs pass installation', () => {
  it.runIf(required)('is installed where QUALOR_REQUIRE_ANALYZERS=1 requires it', () => {
    expect(have, `the sonarjs pass is not installed in ${DIR} (install-sonarjs.sh)`).toBe(true);
  });

  it.runIf(have && DIR !== SOURCE)("runs this checkout's run.mjs, not a stale install", () => {
    expect(readFileSync(RUN, 'utf8')).toBe(readFileSync(path.join(SOURCE, 'run.mjs'), 'utf8'));
  });

  it('looks in QUALOR_SONARJS_DIR, then /opt/qualor/sonarjs, then the source directory', () => {
    expect(sonarjsDir({ QUALOR_SONARJS_DIR: '/x/sonarjs' }, () => true)).toBe(
      path.resolve('/x/sonarjs'),
    );
    expect(sonarjsDir({}, (p) => p === path.join(INSTALLED, 'run.mjs'))).toBe(INSTALLED);
    expect(sonarjsDir({}, () => false)).toBe(SOURCE);
  });
});

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

describe.skipIf(!have && !required)('sonarjs run.mjs', { timeout: 120_000 }, () => {
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

  it('never executes code from the checkout: packages, parsers, resolvers or build config (untrusted checkout)', () => {
    // Every module, plugin, parser or executable config file the pass, a rule or a parser could
    // resolve relative to a linted file writes a marker when executed. None may run.
    const markers = mkdtempSync(path.join(os.tmpdir(), 'sonarjs-markers-'));
    const plant = (name: string) =>
      `require('fs').writeFileSync(${JSON.stringify(path.join(markers, name.replace(/[/@.]/g, '_')))}, 'ran');\n`;
    const pkg = (name: string, extra: object = {}) => ({
      [`node_modules/${name}/package.json`]: JSON.stringify({ name, main: 'index.js', ...extra }),
      [`node_modules/${name}/index.js`]: `${plant(name)}module.exports = {};\n`,
    });
    const packages = [
      'eslint-import-resolver-node',
      'eslint-import-resolver-typescript',
      'eslint-plugin-import',
      'eslint-module-utils',
      'react',
      'react-dom',
      'typescript',
      '@typescript-eslint/parser',
      '@typescript-eslint/typescript-estree',
      '@babel/core',
      '@babel/eslint-parser',
      '@babel/preset-env',
      'eslint',
      'eslint-plugin-sonarjs',
      'eslint-plugin-react',
      'eslint-plugin-jsx-a11y',
      'vue-eslint-parser',
      'browserslist-config-qualor-marker',
      'babel-plugin-qualor-marker',
      'ts-plugin-qualor-marker',
    ];
    const root = repo({
      ...Object.assign({}, ...packages.map((p) => pkg(p))),
      'node_modules/typescript/lib/typescript.js': plant('typescript-lib'),
      'package.json': JSON.stringify({
        name: 'untrusted',
        dependencies: { react: '*' },
        browserslist: ['extends browserslist-config-qualor-marker'],
        babel: { plugins: ['babel-plugin-qualor-marker'] },
      }),
      '.browserslistrc': 'extends browserslist-config-qualor-marker\n',
      'babel.config.js': plant('babel.config.js'),
      'babel.config.cjs': plant('babel.config.cjs'),
      '.babelrc.js': plant('.babelrc.js'),
      '.babelrc': JSON.stringify({ plugins: ['./babel-plugin.js'] }),
      'babel-plugin.js': `${plant('babel-plugin.js')}module.exports = () => ({});\n`,
      'eslint.config.js': plant('eslint.config.js'),
      'eslint.config.mjs': plant('eslint.config.mjs'),
      '.eslintrc.js': plant('.eslintrc.js'),
      'tsconfig.json': JSON.stringify({
        compilerOptions: {
          allowJs: true,
          jsx: 'react-jsx',
          plugins: [{ name: 'ts-plugin-qualor-marker' }],
        },
        include: ['src'],
      }),
      // S7060 resolves the imports; S125 looks at commented-out code; JSX runs the React
      // and jsx-a11y based rules; the TS files run the typescript-eslint parser and program.
      'src/a.js': [
        "import b from './b';",
        "import React from 'react';",
        "const self = require('./a');",
        '// if (b) {',
        '//   foo(b);',
        '// }',
        'export default [b, React, self];',
        '',
      ].join('\n'),
      'src/b.jsx': "import a from './a';\nexport default () => <img src={a} onClick={a} />;\n",
      'src/c.ts': "import { d } from './d';\nexport const c: number = d.length;\n",
      'src/d.tsx':
        'import React from \'react\';\nexport const d = [<div key="k">{React.version}</div>];\n',
    });
    for (const extra of [[], ['--type-checking', 'off']]) {
      const { log, info } = run(root, extra);
      expect(readdirSync(markers)).toEqual([]);
      expect(info.files).toBeGreaterThanOrEqual(4);
      // The resolver path did run: S7060 resolved the imports (src/a.js requires itself). The
      // Babel markers guard S125, whose Babel parse passes babelrc/configFile false and explicit
      // targets, but which never reaches Babel in 2.0.4 (its `__importDefault` of the ES-module
      // @babel/eslint-parser yields no `parse`), so it cannot be asserted to run here.
      expect(ruleIds(log)).toContain('S7060');
    }
  });

  it('still reports a module that imports itself (S7060), with the bundled resolver', () => {
    const root = repo({
      'src/self.js': "import x from './self';\nexport default x;\n",
      'src/other.js': "import x from './self';\nexport default x;\n",
    });
    const { log } = run(root);
    const hits = log.runs[0].results.filter((r: { ruleId: string }) => r.ruleId === 'S7060');
    expect(hits).toHaveLength(1);
    expect(hits[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/self.js');
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

  it('lints exactly the --files list, after checking each entry against the disk', () => {
    const outside = repo({ 'x.js': BRANCHES });
    const root = repo({
      'src/a.js': BRANCHES,
      'src/b.ts': BRANCHES,
      'src/..c.js': BRANCHES,
      'dist/gen.js': BRANCHES,
      'node_modules/p/i.js': BRANCHES,
      '.git/hooks/h.js': BRANCHES,
      'vendor/v.js': BRANCHES,
      'notes.txt': BRANCHES,
    });
    symlinkSync(path.join(root, 'vendor'), path.join(root, 'src/inner'), 'junction');
    const list = path.join(root, '..', `${path.basename(root)}.files.json`);
    writeFileSync(
      list,
      JSON.stringify([
        path.join(root, 'src/a.js'),
        'src/b.ts', // relative to --root
        'src/..c.js',
        path.join(root, 'node_modules/p/i.js'),
        path.join(root, '.git/hooks/h.js'),
        path.join(root, 'src/inner/v.js'), // through a junction
        path.join(outside, 'x.js'),
        path.join(root, '../x.js'),
        path.join(root, 'notes.txt'),
        path.join(root, 'src/missing.js'),
        path.join(root, 'src'),
        42,
      ]),
    );
    const out = path.join(root, '..', `${path.basename(root)}.sarif`);
    const r = spawnSync(process.execPath, [RUN, '--root', root, '--out', out, '--files', list], {
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('sonarjs: 9 listed file(s) not linted');
    expect(JSON.parse(r.stdout.trim()).files).toBe(3);
    const uris = JSON.parse(readFileSync(out, 'utf8')).runs[0].results.map(
      (x: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
        x.locations[0]!.physicalLocation.artifactLocation.uri,
    );
    // dist/gen.js is a source file under the root, but not on the list: not linted.
    expect([...new Set(uris)].sort()).toEqual(['src/..c.js', 'src/a.js', 'src/b.ts']);
    // An --exclude still narrows the list.
    const narrowed = run(root, ['--files', list, '--exclude', 'src/b.ts']);
    expect(narrowed.info.files).toBe(2);
  });

  it('fails (exit 2) on a --files list that is not a JSON array', () => {
    const root = repo({ 'a.js': BRANCHES });
    const list = path.join(root, '..', `${path.basename(root)}.files.json`);
    writeFileSync(list, '{"a.js": true}');
    const r = spawnSync(
      process.execPath,
      [RUN, '--root', root, '--out', path.join(root, 'o.sarif'), '--files', list],
      { encoding: 'utf8' },
    );
    expect(r.status).toBe(2);
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

  it.skipIf(!installed && !required)(
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
  const pkg = JSON.parse(readFileSync(path.join(SOURCE, 'package.json'), 'utf8')) as {
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

  it('install-sonarjs.sh installs it from the lockfile and checks the source archive before unpacking it', () => {
    const text = readFileSync('tools/analyzers/install-sonarjs.sh', 'utf8');
    // $NPM, not a literal `npm`: the ambient npm, or a pinned npm >= 11 fallback (see below).
    expect(text).toContain('$NPM ci --omit=dev --ignore-scripts');
    expect(text).toContain('"${SONARJS_SOURCE_SHA256}  $TMP/sonarjs.tar.gz" | sha256sum -c -');
    const check = text.indexOf('/sonarjs.tar.gz" | sha256sum -c -');
    expect(check).toBeGreaterThan(0);
    expect(check).toBeLessThan(text.indexOf('tar -xzf "$TMP/sonarjs.tar.gz"'));
    expect(text).toContain('node "$DEST/categories.mjs"');
    expect(text).toContain('chmod -R a+rX "$DEST"');
  });

  it.each(['deploy/scanner/Dockerfile', 'tools/analyzers/Dockerfile'])(
    '%s delegates to install-sonarjs.sh instead of duplicating its recipe (controller ruling 14)',
    (file) => {
      const text = readFileSync(file, 'utf8');
      expect(text).toContain('install-sonarjs.sh');
      expect(text).not.toContain('npm ci --omit=dev --ignore-scripts');
      expect(text).not.toMatch(/SONARJS_SOURCE_SHA256\}\s+\/tmp\/sonarjs\.tar\.gz/);
    },
  );
});

describe.skipIf(!installed && !required)('sonarjs run.mjs helpers', () => {
  const load = async () => {
    return (await import(pathToFileURL(RUN).href)) as {
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
