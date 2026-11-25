import { describe, expect, it } from 'vitest';
import { ITEMS } from './index.js';
import {
  batchEntries,
  caseBlock,
  caseFindings,
  corpusCases,
  describeAnswer,
  errorFacts,
  escapeHtml,
  fieldPath,
  findingsLine,
  hiddenTypes,
  nodePaths,
  reconcileWiql,
  renderingHtml,
  shapeOf,
  tagIdOf,
  tagOfLength,
  tagsOf,
  trimLong,
  wiqlIds,
  xmlUnsafe,
} from './30-boards-facts.js';

const USER = '11111111-2222-4333-8444-555555555555';

describe('item 30 helpers', () => {
  it('is registered', () => {
    expect(ITEMS.map((i) => i.id)).toContain(30);
  });

  it('escapes the five characters Task 4 escapes, ampersand first', () => {
    expect(escapeHtml(`<a href="x">'&amp;'</a>`)).toBe(
      '&lt;a href=&quot;x&quot;&gt;&#39;&amp;amp;&#39;&lt;/a&gt;',
    );
    expect(escapeHtml('#123 @<id>')).toBe('#123 @&lt;id&gt;');
  });

  it('turns a node path into the field form: no leading backslash, no structure segment', () => {
    expect(fieldPath('\\qualor-probe\\Area')).toBe('qualor-probe');
    expect(fieldPath('\\qualor-probe\\Area\\probe30-1\\deeper')).toBe(
      'qualor-probe\\probe30-1\\deeper',
    );
    expect(fieldPath('\\My Project\\Iteration\\Iteration 1')).toBe('My Project\\Iteration 1');
  });

  it('lists every path of a node tree, root first', () => {
    const tree = {
      id: 1,
      path: '\\p\\Iteration',
      children: [
        {
          id: 2,
          path: '\\p\\Iteration\\Iteration 1',
          children: [{ id: 4, path: '\\p\\Iteration\\Iteration 1\\a' }],
        },
        { id: 3, path: '\\p\\Iteration\\Iteration 2' },
      ],
    };
    expect(nodePaths(tree)).toEqual([
      '\\p\\Iteration',
      '\\p\\Iteration\\Iteration 1',
      '\\p\\Iteration\\Iteration 1\\a',
      '\\p\\Iteration\\Iteration 2',
    ]);
    expect(nodePaths(null)).toEqual([]);
  });

  it('reads the status, typeKey and message of an answer, or none', () => {
    expect(
      errorFacts(400, {
        typeKey: 'RuleValidationException',
        message: `TF401320: ${'x'.repeat(400)}`,
      }),
    ).toEqual({
      status: 400,
      typeKey: 'RuleValidationException',
      message: `TF401320: ${'x'.repeat(290)}`,
    });
    expect(errorFacts(415, 'Unsupported')).toEqual({
      status: 415,
      typeKey: 'none',
      message: 'Unsupported',
    });
    expect(describeAnswer(404, { typeKey: 'T', message: 'm' })).toBe('HTTP 404 T: m');
    expect(describeAnswer(200, { count: 1, value: [{ id: 1, name: 'n' }] })).toBe(
      'HTTP 200 {count,value:[{id,name}]}',
    );
  });

  it('describes a shape two levels deep with at most 12 keys per object', () => {
    const wide = Object.fromEntries(Array.from({ length: 14 }, (_v, i) => [`k${i}`, i]));
    expect(shapeOf({ a: wide })).toBe('{a:{k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,…}}');
    expect(shapeOf({ a: { b: { c: 1 } } })).toBe('{a:{b:{…}}}');
    expect(shapeOf({ value: [null, { id: 1 }] })).toBe('{value:[{id}]}');
    expect(shapeOf(null)).toBe('null');
  });

  it('cuts long strings in a recording and keeps the rest', () => {
    const cut = trimLong({ a: 'x'.repeat(500), b: ['short', 3], c: null }, 300) as Record<
      string,
      unknown
    >;
    expect(cut['a']).toBe(`${'x'.repeat(200)}… [cut by the probe: 500 characters]`);
    expect(cut['b']).toEqual(['short', 3]);
    expect(cut['c']).toBeNull();
  });

  it('knows the text XML 1.0 cannot hold', () => {
    expect(xmlUnsafe('a\u0000b')).toBe(true);
    expect(xmlUnsafe('x\u000b/merge')).toBe(true);
    expect(xmlUnsafe('a\ud800b')).toBe(true);
    expect(xmlUnsafe('a\udc00b')).toBe(true);
    expect(xmlUnsafe('tab\tLF\nCR\r')).toBe(false);
    expect(xmlUnsafe('😀 界 \u0085')).toBe(false);
  });

  it('numbers the item-11 corpus and cuts values by code point, pairs kept whole', () => {
    const cases = corpusCases(USER, 5);
    expect(cases).toHaveLength(40);
    expect(cases[0]).toEqual({ n: 1, name: 'backtick', value: '`' });
    const emoji = cases.find((c) => c.name === 'emoji and ZWJ');
    expect(emoji && Array.from(emoji.value)).toHaveLength(5);
    expect(emoji && xmlUnsafe(emoji.value)).toBe(false);
    expect(cases.find((c) => c.name === 'Azure DevOps mention by id')?.value).toBe(
      `@<${USER.slice(0, 3)}`,
    );
  });

  it('writes a case after its marker, escaped, in pre, code or a plain paragraph', () => {
    const c = { n: 7, name: 'HTML', value: '<b>x</b>' };
    expect(caseBlock(c, 'pre')).toBe('<p>QCASE-07-pre</p><pre>&lt;b&gt;x&lt;/b&gt;</pre>');
    expect(caseBlock(c, 'code')).toBe(
      '<p>QCASE-07-code</p><p><code>&lt;b&gt;x&lt;/b&gt;</code></p>',
    );
    expect(caseBlock(c, 'plain')).toBe('<p>QCASE-07-plain</p><p>&lt;b&gt;x&lt;/b&gt;</p>');
    expect(renderingHtml([c, { ...c, n: 8 }], ['pre', 'plain'])).toBe(
      caseBlock(c, 'pre') +
        caseBlock(c, 'plain') +
        caseBlock({ ...c, n: 8 }, 'pre') +
        caseBlock({ ...c, n: 8 }, 'plain'),
    );
  });

  it('finds inert cases inert, the escaped legacy mention included', () => {
    const cases = corpusCases(USER);
    const html = renderingHtml(cases, ['pre', 'code', 'plain']);
    const findings = caseFindings(html);
    expect(findings).toHaveLength(120);
    expect(findings.every((f) => !f.link && !f.mention && !f.image && !f.markup)).toBe(true);
    expect(findingsLine(findings)).toBe('none');
  });

  it('finds a link, a mention, an image and other markup in the case they appear in', () => {
    const html =
      '<p>QCASE-01-pre</p><pre>#1</pre>' +
      '<p>QCASE-02-plain</p><p><a href="https://x/_workitems/edit/1" data-vss-mention="version:1.0">#1</a></p>' +
      '<p>QCASE-03-code </p><p><code><img src="x"></code></p>' +
      '<p>QCASE-04-plain</p><div><b>x</b></div>';
    const f = caseFindings(html);
    expect(f.map((x) => [x.n, x.form, x.link, x.mention, x.image, x.markup])).toEqual([
      [1, 'pre', false, false, false, false],
      [2, 'plain', true, true, false, true],
      [3, 'code', false, false, true, true],
      [4, 'plain', false, false, false, true],
    ]);
    expect(findingsLine(f)).toBe(
      '2 plain:link+mention+markup, 3 code:image+markup, 4 plain:markup',
    );
  });

  it('builds the reconcile query with @Me, a quoted identity, or no creator', () => {
    const since = '2026-11-25T10:00:00.000Z';
    expect(reconcileWiql(since)).toBe(
      "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS 'qualor'" +
        " AND [System.CreatedBy] = @Me AND [System.CreatedDate] >= '2026-11-25T10:00:00.000Z' ORDER BY [System.Id] DESC",
    );
    expect(reconcileWiql(since, "O'Brien <x@y>")).toContain(
      "[System.CreatedBy] = 'O''Brien <x@y>'",
    );
    expect(reconcileWiql('2026-11-25', null)).not.toContain('CreatedBy');
  });

  it('reads WIQL ids and batch entries, null entries counted', () => {
    expect(wiqlIds({ workItems: [{ id: 3, url: 'u' }, { id: 1 }] })).toEqual([3, 1]);
    expect(wiqlIds({ message: 'refused' })).toEqual([]);
    const b = batchEntries({
      count: 3,
      value: [{ id: 5, rev: 1, fields: { 'System.State': 'New' } }, null, { id: 6 }],
    });
    expect([...b.items.keys()]).toEqual([5, 6]);
    expect(b.items.get(5)).toEqual({ 'System.State': 'New' });
    expect(b.items.get(6)).toEqual({});
    expect(b.nulls).toBe(1);
    expect(batchEntries('x')).toEqual({ items: new Map(), nulls: 0 });
  });

  it('splits tags on semicolons, trimmed, in any order', () => {
    expect(tagsOf('probe30; qualor;  a,b ;')).toEqual(['probe30', 'qualor', 'a,b']);
    expect(tagsOf(undefined)).toEqual([]);
  });

  it('makes a tag of exactly n characters with no long alphanumeric run', () => {
    for (const n of [100, 101, 400]) {
      const tag = tagOfLength(n, `probe30-${n}`);
      expect(tag).toHaveLength(n);
      expect(tag.endsWith('z')).toBe(true);
      expect(/[A-Za-z0-9]{52,}/.test(tag)).toBe(false);
    }
  });

  it('names the hidden types, or null without the category or a list', () => {
    const json = {
      count: 2,
      value: [
        {
          name: 'Bug Category',
          referenceName: 'Microsoft.BugCategory',
          workItemTypes: [{ name: 'Bug', url: 'u' }],
        },
        {
          name: 'Hidden Types Category',
          referenceName: 'Microsoft.HiddenCategory',
          workItemTypes: [{ name: 'Code Review Request' }, { name: 'Shared Steps' }],
        },
      ],
    };
    expect(hiddenTypes(json)).toEqual(['Code Review Request', 'Shared Steps']);
    expect(hiddenTypes({ count: 0, value: [] })).toBeNull();
    expect(hiddenTypes('x')).toBeNull();
  });

  it('finds a tag id by its exact name', () => {
    const json = {
      count: 2,
      value: [
        { id: 'a1', name: 'probe30-a', url: 'u' },
        { id: 'b2', name: 'probe30', url: 'u' },
      ],
    };
    expect(tagIdOf(json, 'probe30')).toBe('b2');
    expect(tagIdOf(json, 'probe3')).toBeUndefined();
    expect(tagIdOf('x', 'probe30')).toBeUndefined();
  });
});
