import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import {
  branchesSchema,
  componentShowSchema,
  componentsPageSchema,
  currentUserSchema,
  gateByProjectSchema,
  gateListSchema,
  gateShowSchema,
  hotspotsPageSchema,
  issuesPageSchema,
  organizationsSchema,
  pageTotal,
  parseSonarVersion,
  profilesSchema,
  rulesPageSchema,
  stripControls,
  versionAtLeast,
} from './api';

const shapes = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/sonarqube-shapes',
);
const shape = (file: string): unknown =>
  JSON.parse(readFileSync(path.join(shapes, file), 'utf8')) as unknown;

describe('SonarQube answer schemas (import-sonarqube.md §5.4)', () => {
  it.each<[string, z.ZodType]>([
    ['users-current.json', currentUserSchema],
    ['qualityprofiles-search.json', profilesSchema],
    ['rules-search-active.json', rulesPageSchema],
    ['rules-search-9.9.json', rulesPageSchema],
    ['rules-search-inactive.json', rulesPageSchema],
    ['qualitygates-list.json', gateListSchema],
    ['qualitygates-show.json', gateShowSchema],
    ['qualitygates-get_by_project.json', gateByProjectSchema],
    ['components-search.json', componentsPageSchema],
    ['components-show.json', componentShowSchema],
    ['project_branches-list.json', branchesSchema],
    ['issues-search.json', issuesPageSchema],
    ['issues-search-facets.json', issuesPageSchema],
    ['hotspots-search.json', hotspotsPageSchema],
    ['organizations-search.json', organizationsSchema],
  ])('parses the documented shape %s', (file, schema) => {
    const parsed = schema.safeParse(shape(file));
    expect(parsed.error?.message).toBeUndefined();
  });

  it('refuses an answer without a field the import uses', () => {
    expect(gateShowSchema.safeParse({ conditions: [] }).success).toBe(false);
    expect(issuesPageSchema.safeParse({ issues: [] }).success).toBe(false); // no paging
  });

  it('refuses an unknown severity and an issue key with a slash', () => {
    const rules = shape('rules-search-active.json') as { rules: { severity: string }[] };
    rules.rules[0]!.severity = 'SEVERE';
    expect(rulesPageSchema.safeParse(rules).success).toBe(false);
    const issues = shape('issues-search.json') as { issues: { key: string }[] };
    issues.issues[0]!.key = 'a/b';
    expect(issuesPageSchema.safeParse(issues).success).toBe(false);
  });

  it('reads the total from paging, or from the top-level total of 9.9', () => {
    expect(pageTotal(rulesPageSchema.parse(shape('rules-search-active.json')))).toBe(2);
    expect(pageTotal(rulesPageSchema.parse(shape('rules-search-9.9.json')))).toBe(1);
    expect(pageTotal({})).toBeNull();
  });

  it('removes NUL, the C0 controls and DEL; multi-line text keeps tab, line feed and return', () => {
    expect(stripControls('a\u0000b\u001bc\td\ne\u007f')).toBe('abcde');
    expect(stripControls('a\u0000b\u001bc\td\r\ne\u007f', true)).toBe('abc\td\r\ne');
    const profiles = profilesSchema.parse({
      profiles: [{ key: 'k', name: 'Team\u0000 TS', language: 'ts' }],
    });
    expect(profiles.profiles[0]!.name).toBe('Team TS');
    expect(profiles.profiles[0]!.isDefault).toBe(false);
  });
});

/** NUL, a C0 control, the escape, the last C0 control and DEL: what §5.4 removes. */
const C = '\u0000\u0001\u001b\u001f\u007f';

type Path = (string | number)[];
type Obj = Record<string | number, unknown>;

/** A copy of `obj` with the string at `path` replaced by `f(old)`. */
function poke(obj: unknown, path: Path, f: (old: string) => string): unknown {
  const copy = structuredClone(obj) as Obj;
  let at = copy;
  for (const k of path.slice(0, -1)) at = at[k] as Obj;
  const last = path[path.length - 1]!;
  at[last] = f(at[last] as string);
  return copy;
}
const dig = (obj: unknown, path: Path): unknown =>
  path.reduce<unknown>((o, k) => (o as Obj)[k], obj);

describe('control characters in every SonarQube string (import-sonarqube.md §5.4)', () => {
  const stripped: [string, Path, z.ZodType][] = [
    ['users-current.json', ['login'], currentUserSchema],
    ['qualityprofiles-search.json', ['profiles', 0, 'key'], profilesSchema],
    ['qualityprofiles-search.json', ['profiles', 0, 'name'], profilesSchema],
    ['qualityprofiles-search.json', ['profiles', 0, 'parentKey'], profilesSchema],
    ['rules-search-active.json', ['rules', 0, 'key'], rulesPageSchema],
    ['rules-search-active.json', ['rules', 0, 'name'], rulesPageSchema],
    ['rules-search-active.json', ['rules', 1, 'params', 0, 'key'], rulesPageSchema],
    ['rules-search-active.json', ['rules', 1, 'params', 0, 'defaultValue'], rulesPageSchema],
    ['rules-search-active.json', ['actives', 'typescript:S1440', 0, 'qProfile'], rulesPageSchema],
    [
      'rules-search-active.json',
      ['actives', 'typescript:S107', 0, 'params', 0, 'key'],
      rulesPageSchema,
    ],
    [
      'rules-search-active.json',
      ['actives', 'typescript:S107', 0, 'params', 0, 'value'],
      rulesPageSchema,
    ],
    ['qualitygates-list.json', ['qualitygates', 0, 'name'], gateListSchema],
    ['qualitygates-show.json', ['name'], gateShowSchema],
    ['qualitygates-show.json', ['conditions', 0, 'error'], gateShowSchema],
    ['qualitygates-get_by_project.json', ['qualityGate', 'name'], gateByProjectSchema],
    ['components-search.json', ['components', 0, 'key'], componentsPageSchema],
    ['components-search.json', ['components', 0, 'name'], componentsPageSchema],
    ['components-show.json', ['component', 'key'], componentShowSchema],
    ['components-show.json', ['component', 'name'], componentShowSchema],
    ['project_branches-list.json', ['branches', 0, 'name'], branchesSchema],
    ['issues-search.json', ['issues', 0, 'rule'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'component'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'message'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'updateDate'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'comments', 0, 'markdown'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'comments', 0, 'createdAt'], issuesPageSchema],
    ['issues-search-facets.json', ['facets', 0, 'values', 0, 'val'], issuesPageSchema],
  ];
  it.each(stripped)('%s: removes them from %j', (file, at, schema) => {
    const raw = shape(file);
    const before = dig(raw, at) as string;
    const dirty = poke(raw, at, (s) => `${C}${s.slice(0, 1)}${C}${s.slice(1)}${C}`);
    expect(dig(schema.parse(dirty), at)).toBe(before);
  });

  it('removes them from gate ids, and keeps line breaks in messages and comments', () => {
    const list = gateListSchema.parse({
      qualitygates: [{ id: `a${C}1`, name: 'G' }],
      default: `a${C}1`,
    });
    expect(list.qualitygates[0]!.id).toBe('a1');
    expect(list.default).toBe('a1');
    const raw = poke(
      poke(shape('issues-search.json'), ['issues', 0, 'message'], () => `a${C}\nb`),
      ['issues', 0, 'comments', 0, 'markdown'],
      () => `c${C}\r\n\td`,
    );
    const issue = issuesPageSchema.parse(raw).issues[0]!;
    expect(issue.message).toBe('a\nb');
    expect(issue.comments![0]!.markdown).toBe('c\r\n\td');
  });

  it('removes them from the rule keys of the actives map', () => {
    const raw = shape('rules-search-active.json') as { actives: Record<string, unknown> };
    raw.actives[`typescript:${C}S9`] = raw.actives['typescript:S1440'];
    const parsed = rulesPageSchema.parse(raw);
    expect(Object.keys(parsed.actives!).sort()).toEqual([
      'typescript:S107',
      'typescript:S1440',
      'typescript:S9',
    ]);
  });

  const refused: [string, Path, z.ZodType][] = [
    ['qualityprofiles-search.json', ['profiles', 0, 'language'], profilesSchema],
    ['rules-search-active.json', ['rules', 0, 'lang'], rulesPageSchema],
    ['rules-search-active.json', ['rules', 0, 'impacts', 0, 'softwareQuality'], rulesPageSchema],
    [
      'rules-search-active.json',
      ['actives', 'typescript:S1440', 0, 'impacts', 0, 'softwareQuality'],
      rulesPageSchema,
    ],
    ['qualitygates-show.json', ['conditions', 0, 'metric'], gateShowSchema],
    ['qualitygates-show.json', ['conditions', 0, 'op'], gateShowSchema],
    ['issues-search.json', ['issues', 0, 'key'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'hash'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'resolution'], issuesPageSchema],
    ['issues-search.json', ['issues', 0, 'issueStatus'], issuesPageSchema],
    ['issues-search-facets.json', ['facets', 0, 'property'], issuesPageSchema],
  ];
  it.each(refused)('%s: refuses them in the code %j', (file, at, schema) => {
    const raw = shape(file);
    expect(schema.safeParse(raw).success).toBe(true);
    expect(schema.safeParse(poke(raw, at, (s) => `${s}${C}`)).success).toBe(false);
    expect(schema.safeParse(poke(raw, at, (s) => `${s}\u0000`)).success).toBe(false);
  });

  it('refuses a key or branch name that is empty once they are removed', () => {
    expect(branchesSchema.safeParse({ branches: [{ name: C, isMain: true }] }).success).toBe(false);
    const profiles = { profiles: [{ key: C, name: 'n', language: 'ts' }] };
    expect(profilesSchema.safeParse(profiles).success).toBe(false);
    const facets = poke(
      shape('issues-search-facets.json'),
      ['facets', 0, 'values', 0, 'val'],
      () => C,
    );
    expect(issuesPageSchema.safeParse(facets).success).toBe(false);
  });
});

describe('bounds of the answer schemas (import-sonarqube.md §5.3, §5.4)', () => {
  it('bounds branch names and facet values', () => {
    const branch = (name: string) => ({ branches: [{ name, isMain: true }] });
    expect(branchesSchema.safeParse(branch('b'.repeat(255))).success).toBe(true);
    expect(branchesSchema.safeParse(branch('b'.repeat(256))).success).toBe(false);
    const facets = (val: string) =>
      poke(shape('issues-search-facets.json'), ['facets', 0, 'values', 0, 'val'], () => val);
    expect(issuesPageSchema.safeParse(facets('r'.repeat(1024))).success).toBe(true);
    expect(issuesPageSchema.safeParse(facets('r'.repeat(1025))).success).toBe(false);
  });

  it('refuses an actives map with more than 500 rules', () => {
    const raw = shape('rules-search-active.json') as { actives: Record<string, unknown> };
    const one = raw.actives['typescript:S1440'];
    const actives = (n: number) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [`typescript:S${String(i)}`, one]));
    expect(rulesPageSchema.safeParse({ ...raw, actives: actives(500) }).success).toBe(true);
    expect(rulesPageSchema.safeParse({ ...raw, actives: actives(501) }).success).toBe(false);
  });

  it('takes a hash of 32 lowercase hex characters or "", nothing else', () => {
    const withHash = (hash: string) =>
      poke(shape('issues-search.json'), ['issues', 0, 'hash'], () => hash);
    expect(issuesPageSchema.parse(withHash('')).issues[0]!.hash).toBe('');
    expect(issuesPageSchema.parse(withHash('a'.repeat(32))).issues[0]!.hash).toBe('a'.repeat(32));
    for (const bad of ['A'.repeat(32), 'a'.repeat(31), 'a'.repeat(33), 'g'.repeat(32), ' ']) {
      expect(issuesPageSchema.safeParse(withHash(bad)).success).toBe(false);
    }
  });

  it('cuts a message to 4 000 characters and a comment to 20 000, with …', () => {
    const raw = poke(
      poke(shape('issues-search.json'), ['issues', 0, 'message'], () => 'm'.repeat(30_000)),
      ['issues', 0, 'comments', 0, 'markdown'],
      () => 'c'.repeat(30_000),
    );
    const issue = issuesPageSchema.parse(raw).issues[0]!;
    expect(issue.message).toBe(`${'m'.repeat(3_999)}…`);
    expect(issue.comments![0]!.markdown).toBe(`${'c'.repeat(19_999)}…`);
    const exact = poke(shape('issues-search.json'), ['issues', 0, 'message'], () =>
      'm'.repeat(4_000),
    );
    expect(issuesPageSchema.parse(exact).issues[0]!.message).toBe('m'.repeat(4_000));
  });

  it('bounds the page index', () => {
    const page = (pageIndex: number) => ({
      paging: { pageIndex, pageSize: 500, total: 1 },
      components: [],
    });
    expect(componentsPageSchema.safeParse(page(10_000)).success).toBe(true);
    expect(componentsPageSchema.safeParse(page(10_001)).success).toBe(false);
  });

  it('carries an unknown gate operator for the mapping to report, bounded to a pattern', () => {
    const gate = (op: string) => ({
      name: 'G',
      conditions: [
        { metric: 'new_coverage', op: 'LT', error: '80' },
        { metric: 'new_violations', op, error: '0' },
      ],
    });
    for (const op of ['GT', 'LT', 'EQ', 'NE', 'GTE', 'NOT_EQUAL', 'A'.repeat(16)]) {
      const parsed = gateShowSchema.safeParse(gate(op));
      expect(parsed.success, op).toBe(true);
      expect(parsed.data?.conditions[1]?.op).toBe(op);
    }
    for (const op of ['gt', '', 'A'.repeat(17), 'G T', 'G1', 'GT ']) {
      expect(gateShowSchema.safeParse(gate(op)).success, op).toBe(false);
    }
  });
});

describe('parseSonarVersion (import-sonarqube.md §4.1)', () => {
  it.each([
    ['9.9.4.87374', 9, 9],
    ['10.7.0.96327', 10, 7],
    ['2025.1.0.102418', 2025, 1],
    ['25.1.0.102122', 25, 1],
    ['10.4', 10, 4],
  ])('reads %s', (text, major, minor) => {
    expect(parseSonarVersion(text)).toEqual({ major, minor, text });
  });

  it('trims surrounding white space', () => {
    expect(parseSonarVersion(' 10.7.0.96327\r\n')).toEqual({
      major: 10,
      minor: 7,
      text: '10.7.0.96327',
    });
  });

  it.each([
    '',
    '10',
    '<html>',
    '10.4-SNAPSHOT',
    '1.2.3.4.5',
    `${'9'.repeat(70)}.1`,
    `10.7${' '.repeat(61)}`,
  ])('refuses %j', (text) => {
    expect(parseSonarVersion(text)).toBeNull();
  });

  it('orders versions', () => {
    const v = (t: string) => parseSonarVersion(t)!;
    expect(versionAtLeast(v('9.9.4.87374'), 9, 9)).toBe(true);
    expect(versionAtLeast(v('9.8.0.1'), 9, 9)).toBe(false);
    expect(versionAtLeast(v('10.3.0.1'), 10, 4)).toBe(false);
    expect(versionAtLeast(v('10.4.1.88267'), 10, 4)).toBe(true);
    expect(versionAtLeast(v('25.1.0.1'), 10, 4)).toBe(true);
  });
});
