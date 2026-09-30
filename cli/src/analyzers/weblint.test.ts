import path from 'node:path';
import { readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext, scanWithRecordedSarif } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { htmlhintAnalyzer } from './htmlhint';
import { runAnalyzers } from './runner';
import { stylelintAnalyzer } from './stylelint';
import { logWeblintSummary, weblintFailureDetail } from './weblint';

const tmp = useTempDirs();
const NODE = '/usr/bin/node';

function fakeWeblintDir(): string {
  const dir = tmp('qualor-weblint-');
  writeFileSync(path.join(dir, 'stylelint.mjs'), '');
  writeFileSync(path.join(dir, 'htmlhint.mjs'), '');
  return dir;
}
const file = (root: string, p: string, language: ScopeFile['language']): ScopeFile => ({
  path: p,
  absPath: path.join(root, p),
  language,
  grammar: null,
  kind: 'main',
  size: 1,
});
function ctx(
  root: string,
  files: ScopeFile[],
  env: Record<string, string>,
  config = {},
  binaries: Record<string, string> = { node: NODE },
) {
  return { ...fakeContext(root, { binaries, workDir: tmp('qualor-work-'), env, config }), files };
}

describe('stylelint and htmlhint prepare (config.md §6, plan 8D)', () => {
  it('are skipped, not unavailable, without the qualor/scanner install (ruling G6)', async () => {
    const root = tmp();
    for (const [a, lang] of [
      [stylelintAnalyzer, 'css'],
      [htmlhintAnalyzer, 'html'],
    ] as const) {
      const p = await a.prepare(
        ctx(root, [file(root, 'x', lang)], { QUALOR_WEBLINT_DIR: path.join(tmp(), 'missing') }),
      );
      expect(p).toEqual({
        skip: 'the HTML and CSS linters are not installed (qualor/scanner image)',
      });
    }
    const config = parseConfig({ version: 1 });
    const [capture] = await runAnalyzers([stylelintAnalyzer], {
      root,
      config,
      files: [file(root, 'a.css', 'css')],
      log: silentLogger,
      env: { QUALOR_WEBLINT_DIR: path.join(tmp(), 'missing') },
    });
    expect(capture).toMatchObject({ engineId: 'stylelint', status: 'skipped' });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it('are unavailable with a relative or in-repository QUALOR_WEBLINT_DIR', async () => {
    const root = tmp();
    for (const a of [stylelintAnalyzer, htmlhintAnalyzer]) {
      for (const dir of ['weblint', path.join(root, 'weblint')]) {
        const p = await a.prepare(
          ctx(root, [file(root, 'a.css', 'css')], { QUALOR_WEBLINT_DIR: dir }),
        );
        expect(p).toEqual({
          unavailable: 'QUALOR_WEBLINT_DIR must be an absolute path outside the repository',
        });
      }
    }
  });

  it('are unavailable without node, and skipped with no file of their language', async () => {
    const root = tmp();
    const dir = fakeWeblintDir();
    const html = [file(root, 'index.html', 'html')];
    const css = [file(root, 'a.css', 'css')];
    expect(
      await stylelintAnalyzer.prepare(ctx(root, css, { QUALOR_WEBLINT_DIR: dir }, {}, {})),
    ).toEqual({ unavailable: 'stylelint needs node on PATH' });
    expect(
      await htmlhintAnalyzer.prepare(ctx(root, html, { QUALOR_WEBLINT_DIR: dir }, {}, {})),
    ).toEqual({ unavailable: 'htmlhint needs node on PATH' });
    expect(await stylelintAnalyzer.prepare(ctx(root, html, { QUALOR_WEBLINT_DIR: dir }))).toEqual({
      skip: 'no CSS or SCSS files in scope',
    });
    expect(await htmlhintAnalyzer.prepare(ctx(root, css, { QUALOR_WEBLINT_DIR: dir }))).toEqual({
      skip: 'no HTML files in scope',
    });
  });

  it('runs node on stylelint.mjs from the install directory with the in-scope CSS/SCSS files and the resolved config', async () => {
    const dir = fakeWeblintDir();
    const root = tmp();
    writeTree(root, {
      '.stylelintrc.json': '{ "extends": "stylelint-config-standard" }',
      'a.css': '',
      'b.scss': '',
      'c.html': '',
    });
    const c = ctx(
      root,
      [file(root, 'a.css', 'css'), file(root, 'b.scss', 'css'), file(root, 'c.html', 'html')],
      { QUALOR_WEBLINT_DIR: dir },
    );
    const p = await stylelintAnalyzer.prepare(c);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(p.run.command).toBe(NODE);
    expect(p.run.cwd).toBe(dir);
    expect(p.run.args.slice(0, 3)).toEqual([path.join(dir, 'stylelint.mjs'), '--root', root]);
    const arg = (name: string) => p.run.args[p.run.args.indexOf(name) + 1]!;
    expect(JSON.parse(readFileSync(arg('--files'), 'utf8'))).toEqual([
      path.join(root, 'a.css'),
      path.join(root, 'b.scss'),
    ]);
    expect(JSON.parse(readFileSync(arg('--config'), 'utf8'))).toMatchObject({
      extends: 'stylelint-config-standard',
    });
    expect(path.dirname(arg('--config'))).toBe(c.workDir);
    expect(p.run.args).not.toContain('--ignore-file');
    expect(p.run.okExitCodes).toEqual([0]);
    expect(p.run.version).toBeUndefined(); // from the SARIF driver
  });

  it('passes a copy of the project .stylelintignore in the work directory to the pass', async () => {
    const dir = fakeWeblintDir();
    const root = tmp();
    writeTree(root, { '.stylelintignore': 'vendor/\n', 'a.css': '' });
    const c = ctx(root, [file(root, 'a.css', 'css')], { QUALOR_WEBLINT_DIR: dir });
    const p = await stylelintAnalyzer.prepare(c);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const ignore = p.run.args[p.run.args.indexOf('--ignore-file') + 1]!;
    expect(path.dirname(ignore)).toBe(c.workDir);
    expect(readFileSync(ignore, 'utf8')).toBe('vendor/\n');
  });

  it.runIf(process.platform !== 'win32')(
    'passes the text of a .stylelintignore that links inside the repository (D8, final review)',
    async () => {
      const root = tmp();
      writeTree(root, { 'lint/ignore': 'gen/\n', 'a.css': '' });
      symlinkSync('lint/ignore', path.join(root, '.stylelintignore'));
      const c = ctx(root, [file(root, 'a.css', 'css')], { QUALOR_WEBLINT_DIR: fakeWeblintDir() });
      const p = await stylelintAnalyzer.prepare(c);
      if (!('run' in p)) throw new Error(JSON.stringify(p));
      const ignore = p.run.args[p.run.args.indexOf('--ignore-file') + 1]!;
      expect(path.dirname(ignore)).toBe(c.workDir);
      expect(readFileSync(ignore, 'utf8')).toBe('gen/\n');
    },
  );

  it("skips with the resolver's reason on an executable project config", async () => {
    const root = tmp();
    writeTree(root, { 'stylelint.config.js': 'x', 'a.css': '' });
    const p = await stylelintAnalyzer.prepare(
      ctx(root, [file(root, 'a.css', 'css')], { QUALOR_WEBLINT_DIR: fakeWeblintDir() }),
    );
    expect(p).toEqual({
      skip: expect.stringContaining('stylelint.config.js is executable configuration'),
    });
  });

  it('runs node on htmlhint.mjs with the in-scope HTML files and the rules', async () => {
    const dir = fakeWeblintDir();
    const root = tmp();
    const c = ctx(root, [file(root, 'index.html', 'html'), file(root, 'a.css', 'css')], {
      QUALOR_WEBLINT_DIR: dir,
    });
    const p = await htmlhintAnalyzer.prepare(c);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(p.run.command).toBe(NODE);
    expect(p.run.cwd).toBe(dir);
    expect(p.run.args.slice(0, 3)).toEqual([path.join(dir, 'htmlhint.mjs'), '--root', root]);
    const arg = (name: string) => p.run.args[p.run.args.indexOf(name) + 1]!;
    expect(JSON.parse(readFileSync(arg('--files'), 'utf8'))).toEqual([
      path.join(root, 'index.html'),
    ]);
    expect(JSON.parse(readFileSync(arg('--rules'), 'utf8'))).toHaveProperty('tag-pair', true);
    expect(path.dirname(arg('--rules'))).toBe(c.workDir);
    expect(p.run.okExitCodes).toEqual([0]);
  });

  it('skips htmlhint with the reason naming an unusable .htmlhintrc', async () => {
    const root = tmp();
    writeTree(root, { '.htmlhintrc': '{ nope', 'index.html': '' });
    const p = await htmlhintAnalyzer.prepare(
      ctx(root, [file(root, 'index.html', 'html')], { QUALOR_WEBLINT_DIR: fakeWeblintDir() }),
    );
    expect(p).toEqual({ skip: expect.stringContaining('.htmlhintrc') });
  });

  it('normalises recorded runs with the category and rule tables', () => {
    const css = scanWithRecordedSarif(
      'stylelint',
      'cli/test/analyzer-output/stylelint/basic.sarif',
    );
    expect(css.issues.find((i) => i.ruleKey === 'stylelint:block-no-empty')).toMatchObject({
      quality: 'reliability',
      severity: 'medium',
    });
    expect(css.issues.find((i) => i.ruleKey === 'stylelint:length-zero-no-unit')).toMatchObject({
      quality: 'maintainability',
      severity: 'low',
    });
    const html = scanWithRecordedSarif('htmlhint', 'cli/test/analyzer-output/htmlhint/basic.sarif');
    expect(html.issues.find((i) => i.ruleKey === 'htmlhint:attr-no-duplication')).toMatchObject({
      quality: 'reliability',
      severity: 'medium',
    });
    expect(html.issues.find((i) => i.ruleKey === 'htmlhint:alt-require')).toMatchObject({
      quality: 'maintainability',
      severity: 'medium',
    });
    expect(html.issues.find((i) => i.ruleKey === 'htmlhint:title-require')).toMatchObject({
      quality: 'maintainability',
      severity: 'low',
    });
  });

  it("logs the pass's own reason at warn when it exits 2, never in the report (final review, minor 6)", async () => {
    const dir = tmp('qualor-weblint-');
    // What files.mjs's run() writes for stylelint's ConfigurationError on `{}`, after a per-file line.
    writeFileSync(
      path.join(dir, 'stylelint.mjs'),
      [
        "process.stderr.write('stylelint: a.css not linted: boom\\n');",
        "process.stderr.write('stylelint: fatal: ConfigurationError: No rules found within configuration\\n');",
        "process.stderr.write('ConfigurationError: No rules found within configuration\\n    at x (y.js:1:1)\\n');",
        'process.exit(2);',
      ].join('\n'),
    );
    const root = tmp();
    writeTree(root, { 'a.css': 'a {}\n' });
    const lines: string[] = [];
    const [capture] = await runAnalyzers([stylelintAnalyzer], {
      root,
      config: parseConfig({ version: 1 }),
      files: [file(root, 'a.css', 'css')],
      log: createLogger('warn', (t) => lines.push(t)),
      env: { ...process.env, QUALOR_WEBLINT_DIR: dir },
    });
    expect(capture).toMatchObject({ status: 'failed', reason: 'exited with code 2' });
    expect(lines.join('\n')).toContain(
      'stylelint: ConfigurationError: No rules found within configuration',
    );
  });

  it('weblintFailureDetail: the fatal line, else the first line, one bounded line; nothing unless exit 2', () => {
    expect(
      weblintFailureDetail(
        'htmlhint',
        2,
        'x not linted\nhtmlhint: fatal: --rules must name a JSON object\n  at y\n',
      ),
    ).toBe('--rules must name a JSON object');
    expect(weblintFailureDetail('htmlhint', 2, '\nError: something\n  at y\n')).toBe(
      'Error: something',
    );
    expect(
      weblintFailureDetail('stylelint', 2, `stylelint: fatal: ${'x'.repeat(1000)}\u001b[31m`),
    ).toHaveLength(300);
    expect(weblintFailureDetail('stylelint', 2, 'a\u001b[2Jb')).toBe('a [2Jb');
    expect(weblintFailureDetail('stylelint', 2, '')).toBeNull();
    expect(weblintFailureDetail('stylelint', 1, 'stylelint: fatal: x')).toBeNull();
    // The shared stderr filter (fix round 2): a JVM-style option echo is never the detail.
    expect(
      weblintFailureDetail(
        'htmlhint',
        2,
        'Picked up JAVA_TOOL_OPTIONS: -Dpw=s3cret\nError: boom\n',
      ),
    ).toBe('Error: boom');
  });

  it('logs the pass summary: unknown rules and invalid options as warnings, never in the report', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    logWeblintSummary(
      log,
      'stylelint',
      '{"files":3,"listed":4,"parseErrors":1,"unknownRules":["order/properties-order"],"invalidOptions":2}\n',
    );
    const text = lines.join('\n');
    expect(text).toMatch(/order\/properties-order/);
    expect(text).toMatch(/2 invalid rule option/);
    expect(text).toMatch(/1 file\(s\) did not parse/);
    expect(text).toMatch(/linted 3 of 4 listed file/);
    lines.length = 0;
    logWeblintSummary(log, 'htmlhint', 'not json\n'); // ignored
    logWeblintSummary(log, 'htmlhint', '');
    expect(lines).toEqual([]);
  });
});
