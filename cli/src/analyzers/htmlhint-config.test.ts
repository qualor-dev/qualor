import { readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseJsonc, QUALOR_DEFAULT_HTMLHINT_RULES, resolveHtmlhintRules } from './htmlhint-config';

const tmp = useTempDirs();
const repo = (files: Record<string, string>) => {
  const root = tmp();
  writeTree(root, files);
  return root;
};
const skip = (r: ReturnType<typeof resolveHtmlhintRules>) => ('skip' in r ? r.skip : '');

describe('resolveHtmlhintRules (config.md §6, plan 8D)', () => {
  it("uses Qualor's fragment-safe set without a .htmlhintrc", () => {
    expect(resolveHtmlhintRules(repo({}), null)).toEqual({
      rules: QUALOR_DEFAULT_HTMLHINT_RULES,
      source: 'qualor-default',
    });
    expect(Object.keys(QUALOR_DEFAULT_HTMLHINT_RULES).sort()).toEqual([
      'alt-require',
      'attr-no-duplication',
      'attr-unsafe-chars',
      'doctype-html5',
      'frame-title-require',
      'html-lang-require',
      'meta-charset-require',
      'src-not-empty',
      'tag-no-obsolete',
      'tag-pair',
      'title-require',
    ]);
    // Noisy on templates (verified facts F10/F11): never in the default.
    for (const noisy of ['doctype-first', 'attr-lowercase', 'spec-char-escape', 'id-unique'])
      expect(QUALOR_DEFAULT_HTMLHINT_RULES).not.toHaveProperty(noisy);
  });

  it('reads a root .htmlhintrc with comments, as HTMLHint does', () => {
    const root = repo({
      '.htmlhintrc': '{\n  // required\n  "alt-require": true, /* off */ "tag-pair": false\n}\n',
    });
    expect(resolveHtmlhintRules(root, null)).toEqual({
      rules: { 'alt-require': true, 'tag-pair': false },
      source: '.htmlhintrc',
    });
  });

  it('configFile names another file, or qualor-default', () => {
    const root = repo({
      '.htmlhintrc': '{ "tag-pair": true }',
      'lint/html.json': '{ "alt-require": true }',
    });
    expect(resolveHtmlhintRules(root, 'lint/html.json')).toEqual({
      rules: { 'alt-require': true },
      source: 'lint/html.json',
    });
    expect(resolveHtmlhintRules(root, 'qualor-default')).toMatchObject({
      source: 'qualor-default',
    });
  });

  it('skips a .htmlhintrc that is not a JSON object, or too large', () => {
    expect(skip(resolveHtmlhintRules(repo({ '.htmlhintrc': '[1]' }), null))).toContain(
      '.htmlhintrc is not an object of HTMLHint rules',
    );
    expect(skip(resolveHtmlhintRules(repo({ '.htmlhintrc': '{ nope' }), null))).toContain(
      '.htmlhintrc is not valid JSON',
    );
    const big = repo({});
    writeFileSync(path.join(big, '.htmlhintrc'), `{"a":"${'x'.repeat(1024 * 1024)}"}`);
    expect(skip(resolveHtmlhintRules(big, null))).toContain('.htmlhintrc is larger than 1 MiB');
    expect(skip(resolveHtmlhintRules(repo({}), 'missing.json'))).toContain(
      'missing.json cannot be read',
    );
  });

  it.runIf(process.platform !== 'win32')(
    'never reads a .htmlhintrc that links out of the repository',
    () => {
      const outside = path.join(tmp(), 'rc.json');
      writeFileSync(outside, '{}');
      const root = repo({});
      symlinkSync(outside, path.join(root, '.htmlhintrc'));
      expect(skip(resolveHtmlhintRules(root, null))).toContain(
        '.htmlhintrc is outside the repository',
      );
    },
  );

  it('parseJsonc keeps comment-like text inside strings and strips a BOM', () => {
    expect(parseJsonc('\uFEFF{ "u": "http://x/*y*/" // c\n}')).toEqual({ u: 'http://x/*y*/' });
    expect(() => parseJsonc('{ /* open')).toThrow();
  });
});

describe('resolveHtmlhintRules reads rules as data only (config.md §6)', () => {
  it('refuses keys that are not HTMLHint rule ids, rulesdir included, and loads nothing', () => {
    const root = tmp();
    writeTree(root, {
      'rules/evil.js': `require('node:fs').writeFileSync(${JSON.stringify(path.join(root, 'evil.ran'))}, 'ran');`,
    });
    for (const key of [
      'rulesdir',
      'rulesDir',
      'plugins',
      'extends',
      '__proto__',
      '../x',
      'Tag-Pair',
    ]) {
      writeFileSync(path.join(root, '.htmlhintrc'), `{ ${JSON.stringify(key)}: "rules" }`);
      const reason = skip(resolveHtmlhintRules(root, null));
      expect(reason, key).toContain(`.htmlhintrc sets "${key}"`);
      expect(reason, key).toContain('configFile: qualor-default');
    }
    expect(readdirSync(root, { recursive: true }).map(String)).not.toContain('evil.ran');
  });

  it('refuses constructor and other Object.prototype names, which HTMLHint would call as rules', () => {
    for (const key of ['constructor', 'toString', 'valueOf', '__proto__']) {
      const root = repo({ '.htmlhintrc': `{ "tag-pair": true, ${JSON.stringify(key)}: true }` });
      const reason = skip(resolveHtmlhintRules(root, null));
      expect(reason, key).toContain(`.htmlhintrc sets "${key}", which is not an HTMLHint rule id`);
      expect(reason, key).toContain('configFile: qualor-default');
    }
  });

  it('drops $schema and keeps rule options as data', () => {
    const root = repo({
      '.htmlhintrc':
        '{ "$schema": "https://json.schemastore.org/htmlhintrc", "attr-lowercase": ["viewBox"], "space-tab-mixed-disabled": "space4" }',
    });
    expect(resolveHtmlhintRules(root, null)).toEqual({
      rules: { 'attr-lowercase': ['viewBox'], 'space-tab-mixed-disabled': 'space4' },
      source: '.htmlhintrc',
    });
  });

  it('refuses a configFile outside the repository, or a directory', () => {
    const outside = tmp();
    writeFileSync(path.join(outside, 'rc.json'), '{}');
    const root = repo({ 'dir/x': '' });
    expect(skip(resolveHtmlhintRules(root, path.join(outside, 'rc.json')))).toContain(
      'is outside the repository',
    );
    expect(skip(resolveHtmlhintRules(root, 'dir'))).toContain('dir is not a regular file');
  });
});
