import { spawnSync } from 'node:child_process';
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
import { QUALOR_DEFAULT_HTMLHINT_RULES } from '../../../cli/src/analyzers/htmlhint-config';
import {
  QUALOR_DEFAULT_STYLELINT,
  sanitizeStylelintConfig,
  STYLELINT_BUNDLED,
} from '../../../cli/src/analyzers/stylelint-config';

/**
 * Qualor's HTML and CSS passes (config.md §6). The real-tool tests run where they are installed:
 * QUALOR_WEBLINT_DIR when set, else /opt/qualor/weblint (CI, the images), else this source
 * directory after `npm ci --omit=dev --ignore-scripts` here. They are skipped where nothing is
 * installed, unless QUALOR_REQUIRE_ANALYZERS=1, which turns that into a failure.
 */
const SOURCE = path.resolve('tools/analyzers/weblint');
const INSTALLED = '/opt/qualor/weblint';
function weblintDir(env: NodeJS.ProcessEnv, exists: (p: string) => boolean): string {
  const configured = env['QUALOR_WEBLINT_DIR'];
  if (configured) return path.resolve(configured);
  return exists(path.join(INSTALLED, 'stylelint.mjs')) ? INSTALLED : SOURCE;
}
const DIR = weblintDir(process.env, existsSync);
const have =
  existsSync(path.join(DIR, 'node_modules/stylelint/package.json')) &&
  existsSync(path.join(DIR, 'node_modules/htmlhint/package.json'));
const required = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';

describe('weblint installation', () => {
  it.runIf(required)('is installed where QUALOR_REQUIRE_ANALYZERS=1 requires it', () => {
    expect(have, `the HTML and CSS passes are not installed in ${DIR} (install-weblint.sh)`).toBe(
      true,
    );
  });

  it.runIf(have && DIR !== SOURCE)("runs this checkout's scripts, not a stale install", () => {
    for (const f of ['bundled.mjs', 'files.mjs', 'stylelint.mjs', 'htmlhint.mjs'])
      expect(readFileSync(path.join(DIR, f), 'utf8'), f).toBe(
        readFileSync(path.join(SOURCE, f), 'utf8'),
      );
  });

  it('looks in QUALOR_WEBLINT_DIR, then /opt/qualor/weblint, then the source directory', () => {
    expect(weblintDir({ QUALOR_WEBLINT_DIR: '/x/weblint' }, () => true)).toBe(
      path.resolve('/x/weblint'),
    );
    expect(weblintDir({}, (p) => p === path.join(INSTALLED, 'stylelint.mjs'))).toBe(INSTALLED);
    expect(weblintDir({}, () => false)).toBe(SOURCE);
  });

  it('bundles exactly the packages the CLI lets a config name', async () => {
    const { BUNDLED } = (await import(pathToFileURL(path.join(SOURCE, 'bundled.mjs')).href)) as {
      BUNDLED: typeof STYLELINT_BUNDLED;
    };
    expect(BUNDLED).toEqual(STYLELINT_BUNDLED);
    const pkg = JSON.parse(readFileSync(path.join(SOURCE, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    for (const name of [
      ...BUNDLED.extends,
      ...BUNDLED.plugins,
      ...BUNDLED.customSyntax,
      'stylelint',
      'htmlhint',
    ])
      expect(pkg.dependencies[name], name).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

function repo(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(os.tmpdir(), 'weblint-'));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    writeFileSync(path.join(root, f), text);
  }
  return root;
}

interface Pass {
  status: number | null;
  stderr: string;
  log: {
    runs: {
      tool: {
        driver: {
          name: string;
          version: string;
          rules: {
            id: string;
            helpUri?: string;
            properties?: { category?: string };
            shortDescription: { text: string };
          }[];
        };
      };
      results: {
        ruleId: string;
        level: string;
        message: { text: string };
        locations: {
          physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } };
        }[];
      }[];
    }[];
  } | null;
  info: Record<string, unknown> | null;
}

function pass(
  script: 'stylelint.mjs' | 'htmlhint.mjs',
  root: string,
  files: string[],
  extra: string[],
): Pass {
  const work = mkdtempSync(path.join(os.tmpdir(), 'weblint-work-'));
  const list = path.join(work, 'files.json');
  writeFileSync(list, JSON.stringify(files.map((f) => path.join(root, f))));
  const out = path.join(work, 'out.sarif');
  const r = spawnSync(
    process.execPath,
    [path.join(DIR, script), '--root', root, '--out', out, '--files', list, ...extra],
    { encoding: 'utf8', cwd: DIR },
  );
  const ok = r.status === 0;
  return {
    status: r.status,
    stderr: r.stderr,
    log: ok ? JSON.parse(readFileSync(out, 'utf8')) : null,
    info: ok ? JSON.parse(r.stdout.trim().split('\n').at(-1)!) : null,
  };
}

function stylelint(root: string, files: string[], config: object, extra: string[] = []): Pass {
  const cfg = path.join(mkdtempSync(path.join(os.tmpdir(), 'weblint-cfg-')), 'config.json');
  writeFileSync(cfg, JSON.stringify(config));
  return pass('stylelint.mjs', root, files, ['--config', cfg, ...extra]);
}

function htmlhint(
  root: string,
  files: string[],
  rules: object = QUALOR_DEFAULT_HTMLHINT_RULES,
): Pass {
  const cfg = path.join(mkdtempSync(path.join(os.tmpdir(), 'weblint-cfg-')), 'rules.json');
  writeFileSync(cfg, JSON.stringify(rules));
  return pass('htmlhint.mjs', root, files, ['--rules', cfg]);
}

const hits = (p: Pass) =>
  p
    .log!.runs[0]!.results.map(
      (r) =>
        `${r.ruleId} ${r.locations[0]!.physicalLocation.artifactLocation.uri}:${r.locations[0]!.physicalLocation.region.startLine}`,
    )
    .sort();

describe.skipIf(!have)('stylelint.mjs', () => {
  it("reports stylelint's own rule ids with a category, a help link and no '(rule)' suffix", () => {
    const root = repo({ 'src/a.css': '.a {\n}\n.b { colr: red; margin: 0px; }\n' });
    const p = stylelint(root, ['src/a.css'], { extends: ['stylelint-config-standard'] });
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual(
      expect.arrayContaining([
        'block-no-empty src/a.css:1',
        'property-no-unknown src/a.css:3',
        'length-zero-no-unit src/a.css:3',
      ]),
    );
    const rules = new Map(p.log!.runs[0]!.tool.driver.rules.map((r) => [r.id, r]));
    expect(rules.get('block-no-empty')?.properties?.category).toBe('possible-error');
    expect(rules.get('length-zero-no-unit')?.properties?.category).toBe('convention');
    expect(rules.get('block-no-empty')?.helpUri).toBe(
      'https://stylelint.io/user-guide/rules/block-no-empty',
    );
    expect(p.log!.runs[0]!.tool.driver.name).toBe('stylelint');
    expect(p.log!.runs[0]!.tool.driver.version).toBe('17.15.0');
    const msg = p.log!.runs[0]!.results.find((r) => r.ruleId === 'block-no-empty')!.message.text;
    expect(msg).not.toMatch(/\(block-no-empty\)$/);
  });

  it("Qualor's default config lints .scss with stylelint-scss and postcss-scss", () => {
    const root = repo({
      'src/b.scss': '$brand: #36c;\n// Buttons\n.button {\n  color: darken($brand, 10%);\n}\n',
    });
    const p = stylelint(root, ['src/b.scss'], QUALOR_DEFAULT_STYLELINT);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toContain('scss/no-global-function-names src/b.scss:4');
    expect(p.info?.['parseErrors']).toBe(0);
  });

  it('parses .scss under a project config without SCSS syntax (Review Focus 3); a real syntax error is counted, not reported', () => {
    const root = repo({
      'src/b.scss': '$x: 1px;\n// c\n.a { width: $x; }\n',
      'src/broken.css': '.a { color: red;\n',
    });
    const config = sanitizeStylelintConfig(
      { extends: 'stylelint-config-standard' },
      '.stylelintrc.json',
    );
    const p = stylelint(root, ['src/b.scss', 'src/broken.css'], config);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p).filter((h) => h.startsWith('CssSyntaxError'))).toEqual([]);
    expect(p.info?.['parseErrors']).toBe(1);
  });

  it('drops rules stylelint does not know and counts each invalid option once', () => {
    const root = repo({ 'a.css': 'a { color: red; }\n', 'b.css': 'b { color: blue; }\n' });
    const p = stylelint(root, ['a.css', 'b.css'], {
      rules: { 'no-such-rule': true, 'color-named': ['never', { bogus: 1 }] },
    });
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p).some((h) => h.startsWith('no-such-rule'))).toBe(false);
    expect(p.info?.['unknownRules']).toEqual(['no-such-rule']);
    expect(p.info?.['invalidOptions']).toBe(1);
  });

  it('honours root-relative override globs, ignoreFiles and a .stylelintignore', () => {
    const root = repo({
      'src/legacy/a.css': 'b {}\n',
      'src/b.css': 'b {}\n',
      'vendor/v.css': 'b {}\n',
      'gen/g.css': 'b {}\n',
      '.stylelintignore': 'gen/\n',
    });
    const config = {
      extends: ['stylelint-config-recommended'],
      ignoreFiles: ['vendor/**'],
      overrides: [{ files: ['src/legacy/**'], rules: { 'block-no-empty': null } }],
    };
    const p = stylelint(
      root,
      ['src/legacy/a.css', 'src/b.css', 'vendor/v.css', 'gen/g.css'],
      config,
      ['--ignore-file', path.join(root, '.stylelintignore')],
    );
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual(['block-no-empty src/b.css:1']);
  });

  it('refuses an ignore file outside the root', () => {
    const outside = repo({ '.stylelintignore': '*.css\n' });
    const root = repo({ 'a.css': 'b {}\n' });
    const p = stylelint(root, ['a.css'], { extends: ['stylelint-config-recommended'] }, [
      '--ignore-file',
      path.join(outside, '.stylelintignore'),
    ]);
    expect(p.status).toBe(2);
  });

  it('lints only listed regular files inside the root: no links, no node_modules, nothing outside', () => {
    const outside = repo({ 'x.css': 'b {}\n' });
    const root = repo({ 'a.css': 'b {}\n', 'node_modules/p/n.css': 'b {}\n', 'a.txt': 'b {}\n' });
    let linked: string[] = [];
    try {
      symlinkSync(path.join(outside, 'x.css'), path.join(root, 'link.css'));
      linked = ['link.css'];
    } catch {
      /* no symlinks on this host */
    }
    const p = stylelint(
      root,
      [
        'a.css',
        'node_modules/p/n.css',
        'a.txt',
        '../' + path.basename(outside) + '/x.css',
        ...linked,
      ],
      { extends: ['stylelint-config-recommended'] },
    );
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual(['block-no-empty a.css:1']);
    expect(p.info?.['files']).toBe(1);
  });

  it.each([
    [{ extends: ['./evil.js'] }],
    [{ extends: [path.resolve('/tmp/evil.js')] }],
    [{ plugins: ['stylelint-order'] }],
    [{ plugins: ['./evil.js'] }],
    [{ customSyntax: 'postcss-less' }],
    [{ customSyntax: './evil.js' }],
    [{ overrides: [{ files: ['*.css'], extends: ['@acme/config'] }] }],
    [{ overrides: [{ files: ['*.css'], customSyntax: './evil.js' }] }],
    [{ processors: ['x'] }],
    [{ referenceFiles: ['a.css'] }],
    [{ overrides: [{ files: ['*.css'], referenceFiles: ['a.css'] }] }],
  ])('refuses %j with exit 2 and runs nothing', (config) => {
    const root = repo({
      'a.css': 'a {}\n',
      'evil.js': "require('fs').writeFileSync(__dirname + '/RAN', 'x');\n",
    });
    const p = stylelint(root, ['a.css'], config);
    expect(p.status).toBe(2);
    expect(existsSync(path.join(root, 'RAN'))).toBe(false);
  });
});

describe.skipIf(!have)('the passes never change the configuration they are given (D11)', () => {
  it("resolveBundled leaves Qualor's default untouched and names only this install's packages", async () => {
    const { resolveBundled } = (await import(
      pathToFileURL(path.join(DIR, 'stylelint.mjs')).href
    )) as { resolveBundled: (c: object) => Record<string, unknown> };
    const before = structuredClone(QUALOR_DEFAULT_STYLELINT);
    const resolved = resolveBundled(QUALOR_DEFAULT_STYLELINT);
    expect(QUALOR_DEFAULT_STYLELINT).toEqual(before);
    const named = [
      ...(resolved['extends'] as string[]),
      ...(resolved['overrides'] as { extends: string[] }[]).flatMap((o) => o.extends),
    ];
    for (const p of named) {
      expect(path.isAbsolute(p), p).toBe(true);
      expect(path.relative(path.join(DIR, 'node_modules'), p).startsWith('..'), p).toBe(false);
    }
  });

  it('lintHtml gives HTMLHint a copy of the frozen default, which a directive cannot change', async () => {
    const { lintHtml } = (await import(pathToFileURL(path.join(DIR, 'htmlhint.mjs')).href)) as {
      lintHtml: (text: string, rules: object) => { rule: { id: string } }[];
    };
    const before = { ...QUALOR_DEFAULT_HTMLHINT_RULES };
    expect(
      lintHtml('<!-- htmlhint tag-pair:false -->\n<div>\n', QUALOR_DEFAULT_HTMLHINT_RULES),
    ).toEqual([]);
    expect(QUALOR_DEFAULT_HTMLHINT_RULES).toEqual(before);
    expect(lintHtml('<div>\n', QUALOR_DEFAULT_HTMLHINT_RULES).map((m) => m.rule.id)).toEqual([
      'tag-pair',
    ]);
  });
});

const MARKER_PACKAGES = [
  'stylelint',
  'stylelint-config-recommended',
  'stylelint-config-recommended-scss',
  'stylelint-config-standard',
  'stylelint-config-standard-scss',
  'stylelint-scss',
  'stylelint-order',
  'postcss',
  'postcss-scss',
  'postcss-less',
  'postcss-load-config',
  'postcss-marker-plugin',
  'browserslist',
  'browserslist-config-qualor-marker',
  'htmlhint',
  'strip-json-comments',
];
const MARKER_FILES = [
  'stylelint.config.js',
  'stylelint.config.cjs',
  '.stylelintrc.js',
  '.stylelintrc.cjs',
  '.config/stylelintrc.js',
  'postcss.config.js',
  'postcss.config.cjs',
  '.postcssrc.js',
  'src/postcss.config.js',
];

/**
 * Plants every package and config a tool could load from the checkout, at the root and next to
 * the linted files (resolution from a linted file's directory); each writes a marker if run.
 */
function plantMarkers(root: string): string {
  const marks = mkdtempSync(path.join(os.tmpdir(), 'weblint-marks-'));
  const js = (name: string) =>
    `require('fs').writeFileSync(${JSON.stringify(path.join(marks, name.replace(/[/\\]/g, '_')))}, 'ran');\nmodule.exports = {};\n`;
  const files: Record<string, string> = {};
  for (const dir of ['node_modules', 'src/node_modules']) {
    for (const p of MARKER_PACKAGES) {
      files[`${dir}/${p}/package.json`] = JSON.stringify({
        name: p,
        version: '99.0.0',
        main: 'index.js',
        exports: { '.': './index.js' },
      });
      files[`${dir}/${p}/index.js`] = js(`${dir}/${p}`);
    }
  }
  for (const f of MARKER_FILES) files[f] = js(f);
  files['stylelint.config.mjs'] =
    `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(path.join(marks, 'stylelint.config.mjs'))}, 'ran');\nexport default {};\n`;
  files['plugin.js'] = js('plugin.js');
  files['.htmlhintrc'] = '{ "tag-pair": false }';
  files['.stylelintrc.json'] = JSON.stringify({ plugins: ['./plugin.js'] });
  files['.postcssrc'] = JSON.stringify({ plugins: { 'postcss-marker-plugin': {} } });
  files['.postcssrc.json'] = JSON.stringify({ plugins: { 'postcss-marker-plugin': {} } });
  files['.browserslistrc'] = 'extends browserslist-config-qualor-marker\n';
  files['src/.browserslistrc'] = 'extends browserslist-config-qualor-marker\n';
  files['package.json'] = JSON.stringify({
    name: 'victim',
    stylelint: { plugins: ['./plugin.js'] },
    postcss: { plugins: { 'postcss-marker-plugin': {} } },
    browserslist: ['extends browserslist-config-qualor-marker'],
  });
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, f)), { recursive: true });
    writeFileSync(path.join(root, f), text);
  }
  return marks;
}

describe.skipIf(!have)(
  'the passes never run code from the checkout (config.md §6, Review Focus 1)',
  () => {
    it('stylelint with bare bundled names in the config, over CSS and SCSS (D9)', () => {
      const root = repo({ 'src/a.css': 'a {}\n', 'src/b.scss': '$x: 1;\n.a { b: $x; }\n' });
      const marks = plantMarkers(root);
      const config = sanitizeStylelintConfig(
        {
          extends: ['stylelint-config-standard', 'stylelint-config-recommended-scss'],
          plugins: ['stylelint-scss'],
          customSyntax: 'postcss-scss',
          overrides: [
            {
              files: ['**/*.scss'],
              extends: ['stylelint-config-standard-scss'],
              plugins: ['stylelint-scss'],
              customSyntax: 'postcss-scss',
            },
          ],
        },
        '.stylelintrc.json',
      );
      const p = stylelint(root, ['src/a.css', 'src/b.scss'], config);
      expect(p.status, p.stderr).toBe(0);
      expect(hits(p).length).toBeGreaterThan(0); // it really linted
      expect(readdirSync(marks)).toEqual([]);
    });

    it("stylelint with Qualor's default and with no config keys at all", () => {
      const root = repo({ 'src/a.css': 'a {}\n', 'src/b.scss': '$x: 1;\n.a { b: $x; }\n' });
      const marks = plantMarkers(root);
      expect(stylelint(root, ['src/a.css', 'src/b.scss'], QUALOR_DEFAULT_STYLELINT).status).toBe(0);
      expect(
        stylelint(
          root,
          ['src/a.css'],
          sanitizeStylelintConfig({ rules: { 'block-no-empty': true } }, 'x'),
        ).status,
      ).toBe(0);
      expect(readdirSync(marks)).toEqual([]);
    });

    it('htmlhint', () => {
      const root = repo({ 'index.html': '<div><p>x</div>\n' });
      const marks = plantMarkers(root);
      const p = htmlhint(root, ['index.html']);
      expect(p.status, p.stderr).toBe(0);
      expect(hits(p)).toContain('tag-pair index.html:1'); // the planted .htmlhintrc (tag-pair: false) is never read
      expect(readdirSync(marks)).toEqual([]);
    });
  },
);

describe.skipIf(!have)('htmlhint.mjs', () => {
  it("Qualor's default set is silent on an Angular template (Review Focus 2)", () => {
    const template = [
      '<div class="card" [class.active]="isActive" (click)="select()" *ngIf="items.length > 0">',
      '  <h2>{{ title && subtitle }}</h2>',
      '  @if (ok) {',
      '    <span id="hint" class="hint">Saved</span>',
      '  } @else {',
      '    <span id="hint" class="hint error">Failed</span>',
      '  }',
      '  <input [formControl]="name" aria-label="Name">',
      '  <img [src]="logo" alt="Logo">',
      '</div>',
      '',
    ].join('\n');
    const root = repo({ 'src/app/card.component.html': template });
    const p = htmlhint(root, ['src/app/card.component.html']);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual([]);
  });

  it("reports rule ids with HTMLHint's description and link", () => {
    const root = repo({
      'index.html':
        '<!DOCTYPE html>\n<html>\n<head>\n  <meta charset="utf-8">\n</head>\n<body><img src="a.png"></body>\n</html>\n',
    });
    const p = htmlhint(root, ['index.html']);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual([
      'alt-require index.html:6',
      'html-lang-require index.html:2',
      'title-require index.html:5',
    ]);
    const driver = p.log!.runs[0]!.tool.driver;
    expect(driver.name).toBe('htmlhint');
    expect(driver.version).toBe('1.9.2');
    const rule = driver.rules.find((r) => r.id === 'alt-require')!;
    expect(rule.helpUri).toBe('https://htmlhint.com/rules/alt-require');
    expect(rule.shortDescription.text.length).toBeGreaterThan(10);
  });

  it("a file's <!-- htmlhint … --> comment changes the rules for that file only (Review Focus 4)", () => {
    const root = repo({
      'a.html': '<!-- htmlhint tag-pair:false -->\n<div><p>x</div>\n',
      'b.html': '<div><p>y</div>\n',
    });
    const p = htmlhint(root, ['a.html', 'b.html']);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p).filter((h) => h.startsWith('tag-pair'))).toEqual(['tag-pair b.html:1']);
  });

  it('a file that crashes HTMLHint is counted and the others are still linted (D11)', () => {
    const root = repo({
      'a.html': '<!-- htmlhint constructor:true -->\n<div>\n',
      'b.html': '<div><p>y</div>\n',
    });
    const p = htmlhint(root, ['a.html', 'b.html']);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual(['tag-pair b.html:1']);
    expect(p.info).toEqual({ files: 2, parseErrors: 1 });
  });

  it('reports a repeated message on one line once', () => {
    const root = repo({ 'a.html': '<center>Old</center>\n' });
    const p = htmlhint(root, ['a.html']);
    expect(hits(p)).toEqual(['tag-no-obsolete a.html:1']);
  });

  it('lints only listed .html/.htm files inside the root', () => {
    const root = repo({
      'a.htm': '<div>\n',
      'b.css': '<div>\n',
      'node_modules/x/c.html': '<div>\n',
    });
    const p = htmlhint(root, ['a.htm', 'b.css', 'node_modules/x/c.html']);
    expect(p.status, p.stderr).toBe(0);
    expect(hits(p)).toEqual(['tag-pair a.htm:2']); // an unclosed tag is reported at the end
    expect(p.info?.['files']).toBe(1);
  });

  it('refuses rules that are not a JSON object with exit 2', () => {
    const root = repo({ 'a.html': '<div>\n' });
    expect(htmlhint(root, ['a.html'], ['tag-pair']).status).toBe(2);
  });
});

describe.skipIf(!have)('licences.mjs', () => {
  it('the committed WEBLINT-DEPENDENCIES.txt matches the installed tree, and every licence is allowed', async () => {
    const { dependencyNotice } = (await import(
      pathToFileURL(path.join(SOURCE, 'licences.mjs')).href
    )) as { dependencyNotice: (dir: string) => string };
    const committed = readFileSync('deploy/scanner/licenses/WEBLINT-DEPENDENCIES.txt', 'utf8');
    expect(dependencyNotice(path.join(DIR, 'node_modules'))).toBe(committed);
  });

  it('refuses a copyleft or missing licence', async () => {
    const { licenceProblem } = (await import(
      pathToFileURL(path.join(SOURCE, 'licences.mjs')).href
    )) as { licenceProblem: (n: string, l: unknown) => string | null };
    expect(licenceProblem('x', 'MIT')).toBeNull();
    expect(licenceProblem('x', 'MIT-0')).toBeNull();
    expect(licenceProblem('x', 'LGPL-3.0')).toBe('x: LGPL-3.0 is not an allowed licence');
    expect(licenceProblem('x', 'MPL-2.0')).toBe('x: MPL-2.0 is not an allowed licence');
    expect(licenceProblem('x', undefined)).toBe('x: no licence declared');
  });
});
