import {
  importCommentKey,
  loadSonarMapping,
  matchStatuses,
  SONAR_MAPPING,
  type SonarIssue,
  type StatusCompetitorItem,
  type StatusImportItem,
  type StatusImportRequestItem,
} from '@qualor/shared';
import { afterEach, describe, expect, it } from 'vitest';
import { MemoryQualor } from '../../test/memory-qualor';
import {
  type FakeIssue,
  type FakeSonar,
  sampleSonarData,
  startFakeSonarQube,
} from '../../test/fake-sonarqube';
import { CliError, EXIT } from '../errors';
import { silentLogger } from '../log';
import { UnreachableError } from '../server/http';
import {
  buildStatusItems,
  buildWithCompetitors,
  chunkItems,
  importComment,
  MAX_COMPONENT_RULES,
  requestItemProblem,
  sendStatuses,
  sonarPath,
  sonarStatus,
} from './issues';
import { QualorApiError } from './qualor-api';
import { connectSonar } from './sonarqube/client';
import { fetchResolvedIssues } from './sonarqube/fetch';

const issue = (over: Partial<SonarIssue> = {}): SonarIssue => ({
  key: 'AYi-1',
  rule: 'external_eslint_repo:eqeqeq',
  component: 'acme:shop:src/a.ts',
  line: 2,
  hash: '0123456789abcdef0123456789abcdef',
  message: 'm',
  resolution: 'FALSE-POSITIVE',
  issueStatus: 'FALSE_POSITIVE',
  updateDate: '2026-09-10T10:00:00+0000',
  comments: [{ markdown: 'safe here' }],
  ...over,
});
const openIssue = (over: Partial<SonarIssue> = {}): SonarIssue =>
  issue({
    key: 'AYo-1',
    resolution: undefined,
    issueStatus: 'OPEN',
    comments: undefined,
    ...over,
  });
const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

describe('from SonarQube issues to import items (import-sonarqube.md §10.1-§10.3)', () => {
  it('reads the status from issueStatus, else from resolution', () => {
    expect(sonarStatus(issue())).toBe('false_positive');
    expect(sonarStatus(issue({ issueStatus: 'ACCEPTED', resolution: 'WONTFIX' }))).toBe('wont_fix');
    expect(sonarStatus(issue({ issueStatus: undefined, resolution: 'WONTFIX' }))).toBe('wont_fix');
    expect(sonarStatus(issue({ issueStatus: undefined, resolution: 'FIXED' }))).toBeNull();
  });

  it('writes the changelog comment of spec §10.2, bounded, without logins', () => {
    expect(importComment(issue(), 'false_positive')).toBe(
      'Imported from SonarQube issue AYi-1 (False positive on 2026-09-10): safe here',
    );
    expect(importComment(issue({ issueStatus: 'ACCEPTED', comments: [] }), 'wont_fix')).toBe(
      'Imported from SonarQube issue AYi-1 (Accepted on 2026-09-10)',
    );
    expect(
      importComment(
        issue({ issueStatus: undefined, resolution: 'WONTFIX', comments: [] }),
        'wont_fix',
      ),
    ).toContain("(Won't fix");
    const long = importComment(
      issue({ comments: [{ markdown: 'x'.repeat(5000) }] }),
      'false_positive',
    );
    expect(long).toHaveLength(2000);
    expect(long.endsWith('…')).toBe(true);
  });

  it('takes the latest non-blank comment, never a login, and writes only YYYY-MM-DD dates', () => {
    const withLogins = issue({
      comments: [
        { markdown: 'first', login: 'alice' },
        { markdown: 'latest', login: 'bob' },
        { markdown: '   ', login: 'carol' },
      ] as SonarIssue['comments'],
    });
    const c = importComment(withLogins, 'false_positive');
    expect(c).toBe('Imported from SonarQube issue AYi-1 (False positive on 2026-09-10): latest');
    for (const login of ['alice', 'bob', 'carol']) expect(c).not.toContain(login);
    expect(importComment(issue({ updateDate: 'yesterday' }), 'false_positive')).toBe(
      'Imported from SonarQube issue AYi-1 (False positive): safe here',
    );
    expect(importComment(issue({ updateDate: undefined }), 'false_positive')).toBe(
      'Imported from SonarQube issue AYi-1 (False positive): safe here',
    );
  });

  it('cleans the comment as the server stores it, and cuts it by UTF-16 units without splitting a pair', () => {
    const messy = importComment(
      issue({ comments: [{ markdown: '  a\r\nb\rc\u0085d\u007fe\tf  ' }] }),
      'false_positive',
    );
    expect(messy.endsWith(': a\nb\ncde\tf')).toBe(true);
    const emoji = importComment(
      issue({ comments: [{ markdown: '\u{1F600}'.repeat(3000) }] }),
      'false_positive',
    );
    expect(emoji.length).toBeLessThanOrEqual(2000);
    expect(emoji.endsWith('…')).toBe(true);
    expect(loneSurrogate.test(emoji)).toBe(false);
  });

  it('builds every comment with the shared header, so the server reads it back (S8c round trip)', () => {
    const a = importComment(issue({ key: 'AYi-1' }), 'false_positive');
    const b = importComment(
      issue({ key: 'AX_z.9:k-2', updateDate: '2025-01-02T00:00:00+0000' }),
      'false_positive',
    );
    expect(importCommentKey(a)).toMatch(/^head:/);
    expect(importCommentKey(a)).toBe(importCommentKey(b));
    const other = importComment(issue({ comments: [{ markdown: 'not safe' }] }), 'false_positive');
    expect(importCommentKey(other)).not.toBe(importCommentKey(a));
    const accepted = importComment(issue({ issueStatus: 'ACCEPTED' }), 'wont_fix');
    const wontFix = importComment(
      issue({ issueStatus: undefined, resolution: 'WONTFIX' }),
      'wont_fix',
    );
    expect(importCommentKey(accepted)).not.toBe(importCommentKey(wontFix));
    const cut = importComment(
      issue({ comments: [{ markdown: 'y'.repeat(5000) }] }),
      'false_positive',
    );
    expect(importCommentKey(cut)).toMatch(/^head:/);
  });

  it('turns components into repository paths, with --path-prefix, and refuses unsafe ones', () => {
    expect(sonarPath('acme:shop', 'acme:shop:src/a.ts', null)).toBe('src/a.ts');
    expect(sonarPath('acme:shop', 'acme:shop:src/a.ts', 'services/api')).toBe(
      'services/api/src/a.ts',
    );
    expect(sonarPath('acme:shop', 'acme:shop', null)).toBeNull();
    for (const bad of [
      'acme:shop:../x.ts',
      'acme:shop:/abs.ts',
      'acme:shop:a\\b.ts',
      'other:x.ts',
      'acme:shop:a//b.ts',
      'acme:shop:a/./b.ts',
      'acme:shop:a\u0000b.ts',
      `acme:shop:${'é'.repeat(513)}`,
    ]) {
      expect(sonarPath('acme:shop', bad, null)).toBe('invalid');
    }
    // The prefix is validated with the path: together they must still be what the endpoint takes.
    expect(sonarPath('acme:shop', `acme:shop:${'a'.repeat(1000)}`, 'x'.repeat(30))).toBe('invalid');
    expect(sonarPath('acme:shop', 'acme:shop:a.ts', '../up')).toBe('invalid');
    expect(sonarPath('acme:shop', 'acme:shop:a.ts', 'services/api/')).toBe('services/api/a.ts');
  });

  it('builds items, counting unmapped rules, invalid paths and unresolved issues', () => {
    const b = buildStatusItems(
      'acme:shop',
      [
        issue(),
        issue({ key: 'AYi-2', rule: 'typescript:S3776' }),
        issue({ key: 'AYi-3', component: 'acme:shop:../x' }),
        issue({ key: 'AYi-4', issueStatus: undefined, resolution: 'FIXED' }),
        issue({ key: 'AYi-5', hash: 'not-a-hash', line: undefined, textRange: { startLine: 7 } }),
      ],
      { pathPrefix: null },
    );
    expect(b.items.map((i) => i.ref)).toEqual(['AYi-1', 'AYi-5']);
    expect(b.items[0]).toMatchObject({
      ruleKeys: ['eslint:eqeqeq'],
      path: 'src/a.ts',
      line: 2,
      sonarLineHash: '0123456789abcdef0123456789abcdef',
      status: 'false_positive',
    });
    expect(b.items[1]).toMatchObject({ line: 7, sonarLineHash: null });
    expect(b.unmappedRules).toEqual(new Map([['typescript:S3776', 1]]));
    expect(b).toMatchObject({ pathInvalid: 1, ignored: 1 });
    expect(b.rules).toEqual(
      new Map([
        ['AYi-1', 'external_eslint_repo:eqeqeq'],
        ['AYi-5', 'external_eslint_repo:eqeqeq'],
      ]),
    );
    for (const i of b.items) expect(requestItemProblem(i)).toBeNull();
  });

  it('builds an item of an external_roslyn issue that targets the roslyn rule (§6.1)', () => {
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({
          rule: 'external_roslyn:CA1822',
          component: 'acme:shop:src/Shop/Cart.cs',
          line: 12,
        }),
      ],
      { pathPrefix: null, open: [], unreadRules: [] },
    );
    expect(b.unmappedRules.size).toBe(0);
    expect(b.items).toHaveLength(1);
    expect(b.items[0]).toMatchObject({
      ref: 'AYi-1',
      ruleKeys: ['roslyn:CA1822'],
      path: 'src/Shop/Cart.cs',
      line: 12,
      status: 'false_positive',
    });
    expect(b.items[0]?.competitorsUnknown).not.toBe(true);
  });

  it('applies --path-prefix and reports the items whose resulting path the endpoint refuses', () => {
    const b = buildStatusItems(
      'acme:shop',
      [issue(), issue({ key: 'AYi-2', component: `acme:shop:${'d/'.repeat(505)}f.ts` })],
      { pathPrefix: 'services/api' },
    );
    expect(b.items.map((i) => [i.ref, i.path])).toEqual([['AYi-1', 'services/api/src/a.ts']]);
    expect(b.pathInvalid).toBe(1);
  });

  it('cuts a message to 4 000 UTF-16 units, as the endpoint counts, without splitting a pair', () => {
    const b = buildStatusItems('acme:shop', [issue({ message: '\u{1F600}'.repeat(3999) })], {
      pathPrefix: null,
    });
    const m = b.items[0]?.message ?? '';
    expect(m.length).toBeLessThanOrEqual(4000);
    expect(loneSurrogate.test(m)).toBe(false);
    expect(m.endsWith('…')).toBe(true);
    expect(requestItemProblem(b.items[0]!)).toBeNull();
  });

  it('checks an item as the endpoint does', () => {
    const [ok] = buildStatusItems('acme:shop', [issue()], { pathPrefix: null }).items;
    expect(requestItemProblem(ok!)).toBeNull();
    expect(requestItemProblem({ ...ok!, ref: 'bad ref' })).toBe('ref');
    expect(requestItemProblem({ ...ok!, ruleKeys: [] })).toBe('ruleKeys');
    expect(requestItemProblem({ ...ok!, ruleKeys: ['NoEngine'] })).toBe('ruleKeys');
    expect(requestItemProblem({ ...ok!, path: 'a/../b' })).toBe('path');
    expect(requestItemProblem({ ...ok!, line: 0 })).toBe('line');
    expect(requestItemProblem({ ...ok!, sonarLineHash: 'ABC' })).toBe('sonarLineHash');
    expect(requestItemProblem({ ...ok!, message: 'a\u0000b' })).toBe('message');
    expect(requestItemProblem({ ...ok!, comment: ' \u0001 ' })).toBe('comment');
    expect(requestItemProblem({ ...ok!, comment: 'c'.repeat(2001) })).toBe('comment');
  });
});

describe('open competitors (import-sonarqube.md §10.1, rulings S3 and S7)', () => {
  it('builds open issues on a resolved item path as status-less competitors; drops the rest uncounted', () => {
    const b = buildStatusItems('acme:shop', [issue()], {
      pathPrefix: 'p',
      open: [
        openIssue({ key: 'AYo-1', rule: 'typescript:S1440' }),
        openIssue({ key: 'AYo-2', component: 'acme:shop:src/other.ts' }),
        openIssue({ key: 'AYo-3', rule: 'typescript:S3776' }),
        openIssue({ key: 'AYo-4', component: 'acme:shop:../x.ts' }),
      ],
      unreadRules: [],
    });
    expect(b.competitors).toEqual<StatusCompetitorItem[]>([
      {
        ref: 'AYo-1',
        ruleKeys: ['eslint:eqeqeq'],
        path: 'p/src/a.ts',
        line: 2,
        sonarLineHash: '0123456789abcdef0123456789abcdef',
        message: 'm',
        status: 'open',
      },
    ]);
    expect(b).toMatchObject({ pathInvalid: 0, ignored: 0, unmappedRules: new Map() });
    expect(b.items[0]?.competitorsUnknown).toBeUndefined();
    for (const i of b.competitors) expect(requestItemProblem(i)).toBeNull();
  });

  it('marks a resolved item competitorsUnknown when ANY unread rule shares a target with it (S7)', () => {
    // typescript:S1440 and external_eslint_repo:eqeqeq both target eslint:eqeqeq.
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({ key: 'AYi-1', rule: 'typescript:S1440' }),
        issue({ key: 'AYi-2', rule: 'external_eslint_repo:no-var' }),
      ],
      { pathPrefix: null, open: [], unreadRules: ['external_eslint_repo:eqeqeq'] },
    );
    expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
      ['AYi-1', true],
      ['AYi-2', false],
    ]);
    expect(b.competitorsUnknownRules).toEqual(['external_eslint_repo:eqeqeq']);
    const none = buildStatusItems('acme:shop', [issue({ rule: 'typescript:S1440' })], {
      pathPrefix: null,
      open: [],
      unreadRules: ['typescript:S3776', 'external_eslint_repo:no-var'],
    });
    expect(none.items[0]?.competitorsUnknown).toBeUndefined();
    expect(none.competitorsUnknownRules).toEqual([]);
  });

  it('never truncates rule targets: over 8 is marked, as a competitor it makes its rule unread', () => {
    const nine = Array.from({ length: 9 }, (_, n) => `eslint:r${n}`);
    const mapping = loadSonarMapping({
      languages: { ts: { language: 'typescript', engines: ['eslint'] } },
      aliases: {},
      repositories: [{ repository: 'external_eslint_repo', engine: 'eslint', reason: 'ESLint' }],
      rules: [
        {
          sonar: ['typescript:S9'],
          qualor: nine,
          relation: 'overlap',
          reviewed: false,
          reason: 'test',
        },
      ],
    });
    const wide = buildStatusItems('acme:shop', [issue({ rule: 'typescript:S9' })], {
      pathPrefix: null,
      mapping,
      open: [],
      unreadRules: [],
    });
    expect(wide.items[0]).toMatchObject({ competitorsUnknown: true });
    expect(wide.items[0]?.ruleKeys).toHaveLength(8);
    const b = buildStatusItems('acme:shop', [issue({ rule: 'external_eslint_repo:r3' })], {
      pathPrefix: null,
      mapping,
      open: [openIssue({ rule: 'typescript:S9' })],
      unreadRules: [],
    });
    expect(b.competitors).toEqual([]);
    expect(b.items[0]).toMatchObject({ competitorsUnknown: true });
    expect(b.competitorsUnknownRules).toEqual(['typescript:S9']);
  });

  it('reports a resolved issue found open again as changed, sends it as a competitor, applies nothing for it (S11)', () => {
    const b = buildStatusItems(
      'acme:shop',
      [issue({ key: 'AYi-1' }), issue({ key: 'AYi-2', line: 7 })],
      {
        pathPrefix: null,
        open: [openIssue({ key: 'AYi-1' })],
        unreadRules: [],
      },
    );
    expect(b.items.map((i) => i.ref)).toEqual(['AYi-2']);
    expect(b.changed.map((i) => [i.ref, i.path, i.line])).toEqual([['AYi-1', 'src/a.ts', 2]]);
    expect(b.rules.get('AYi-1')).toBe('external_eslint_repo:eqeqeq');
    expect(b.competitors.map((i) => [i.ref, i.status])).toEqual([['AYi-1', 'open']]);
  });

  it('counts the rule of an issue reopened between the reads as unread: its component is marked (fix 12c)', () => {
    // The s14probe case B: Y reopened while another S1440 issue was resolved (counts unchanged).
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({ key: 'J', rule: 'typescript:S1440', line: 20 }),
        issue({ key: 'Y', rule: 'typescript:S1440', line: 40 }),
        issue({ key: 'N', rule: 'external_eslint_repo:no-var', line: 50 }),
      ],
      { pathPrefix: null, open: [openIssue({ key: 'Y', rule: 'typescript:S1440', line: 40 })] },
    );
    expect(b.changed.map((i) => i.ref)).toEqual(['Y']);
    expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
      ['J', true],
      ['N', false],
    ]);
    expect(b.competitorsUnknownRules).toEqual(['typescript:S1440']);
  });

  it('counts the rule of a resolved item with more than 8 targets as unread: its component is marked (fix 12c)', () => {
    const nine = Array.from({ length: 9 }, (_, n) => `eslint:t${n}`);
    const m9 = loadSonarMapping({
      languages: { ts: { language: 'typescript', engines: ['eslint'] } },
      aliases: {},
      repositories: [],
      rules: [
        {
          sonar: ['typescript:R'],
          qualor: nine,
          relation: 'overlap',
          reviewed: false,
          reason: 'r',
        },
        {
          sonar: ['typescript:J'],
          qualor: ['eslint:t8'],
          relation: 'overlap',
          reviewed: false,
          reason: 'j',
        },
      ],
    });
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({ key: 'R', rule: 'typescript:R', line: 10, issueStatus: 'ACCEPTED' }),
        issue({ key: 'J', rule: 'typescript:J', line: 10 }),
      ],
      { pathPrefix: null, mapping: m9 },
    );
    expect(b.items.map((i) => [i.ref, i.ruleKeys.length, i.competitorsUnknown])).toEqual([
      ['R', 8, true],
      ['J', 1, true],
    ]);
    expect(b.competitorsUnknownRules).toEqual(['typescript:R']);
  });

  it('marks the resolved items of a path where a resolved issue was dropped as invalid (S11)', () => {
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({ key: 'AYi-1' }),
        issue({ key: 'AYi-bad', line: 20_000_000 }),
        issue({ key: 'AYi-3', component: 'acme:shop:src/b.ts' }),
      ],
      { pathPrefix: null, open: [], unreadRules: [] },
    );
    expect(b.invalid).toBe(1);
    expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
      ['AYi-1', true],
      ['AYi-3', false],
    ]);
  });

  it('marks the resolved items of a path where a resolved issue was ignored (S14 d)', () => {
    const b = buildStatusItems(
      'acme:shop',
      [
        issue({ key: 'AYi-1' }),
        issue({ key: 'AYi-fixed', issueStatus: 'FIXED', resolution: 'FIXED', line: 5 }),
        issue({ key: 'AYi-3', component: 'acme:shop:src/b.ts' }),
        // Unmapped: it competes for nothing, so it marks nothing.
        issue({
          key: 'AYi-um',
          rule: 'typescript:S3776',
          issueStatus: 'FIXED',
          component: 'acme:shop:src/b.ts',
        }),
      ],
      { pathPrefix: null, open: [], unreadRules: [] },
    );
    expect(b.ignored).toBe(2);
    expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
      ['AYi-1', true],
      ['AYi-3', false],
    ]);
  });

  it('refuses a path with a control character', () => {
    for (const bad of [
      'src/a\u0001.ts',
      'src/a\t.ts',
      'src/a\n.ts',
      'src/a\u007f.ts',
      'src/\u0085a.ts',
    ]) {
      expect(sonarPath('acme:shop', `acme:shop:${bad}`, null)).toBe('invalid');
    }
    expect(sonarPath('acme:shop', 'acme:shop:src/ä ö.ts', null)).toBe('src/ä ö.ts');
  });

  describe('reading them from SonarQube', () => {
    let fake: FakeSonar | undefined;
    afterEach(async () => {
      if (fake !== undefined) expect(fake.requests.every((r) => r.method === 'GET')).toBe(true);
      await fake?.close();
      fake = undefined;
    });
    const connect = () =>
      connectSonar({
        url: fake!.url,
        token: fake!.data.token,
        kind: 'auto',
        organization: null,
        auth: 'auto',
        timeoutMs: 5000,
        log: silentLogger,
        sleep: () => Promise.resolve(),
      });
    const extra = (key: string, rule: string, line: number): FakeIssue => ({
      key,
      rule,
      project: 'acme:shop',
      path: 'src/a.ts',
      line,
      message: 'm',
      status: 'OPEN',
    });

    it('asks for the open issues of every rule of the components, not only the resolved ones (S7, S14)', async () => {
      const data = sampleSonarData();
      data.issues.push(extra('AYo-eq', 'external_eslint_repo:eqeqeq', 5));
      fake = await startFakeSonarQube(data);
      const conn = await connect();
      const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
        pathPrefix: null,
        maxIssues: 1000,
      });
      const asked = fake.requests
        .filter(
          (r) => r.path === 'api/issues/search' && r.query['issueStatuses'] === 'OPEN,CONFIRMED',
        )
        .map((r) => r.query['rules']);
      const rules = SONAR_MAPPING.componentRules(SONAR_MAPPING.component('typescript:S1440')!);
      expect(rules).toContain('external_eslint_repo:eqeqeq');
      expect(new Set(asked)).toEqual(new Set([rules.join(',')]));
      expect(b.items.map((i) => i.ref).sort()).toEqual(['AYi-ac-1', 'AYi-fp-1']);
      expect(b.competitors.map((i) => i.ref).sort()).toEqual(['AYi-open', 'AYo-eq']);
      expect(b.items.every((i) => i.competitorsUnknown === undefined)).toBe(true);
      expect(JSON.stringify([...b.items, ...b.competitors])).not.toContain('someone');
    });

    it('marks the resolved items when the open read is capped', async () => {
      const data = sampleSonarData();
      data.issues.push(extra('AYo-eq', 'external_eslint_repo:eqeqeq', 5));
      fake = await startFakeSonarQube(data);
      const conn = await connect();
      const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
        pathPrefix: null,
        maxIssues: 1,
      });
      expect(b.items.every((i) => i.competitorsUnknown === true)).toBe(true);
      expect(b.competitorsUnknownRules.length).toBeGreaterThan(0);
    });

    it('marks the resolved items when the resolved read is capped (S11)', async () => {
      fake = await startFakeSonarQube(sampleSonarData());
      const conn = await connect();
      // Only AYi-fp-1 (eqeqeq) is read; AYi-ac-1 (typescript:S1440, also eslint:eqeqeq) is not.
      const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1);
      expect(resolved.issues.map((i) => i.key)).toEqual(['AYi-fp-1']);
      expect(resolved.unread).toEqual({
        kind: 'rules',
        rules: ['typescript:S1440', 'typescript:S3776'],
      });
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
        pathPrefix: null,
        maxIssues: 1000,
        unreadResolved: resolved.unread,
      });
      expect(b.items.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['AYi-fp-1', true]]);
      expect(b.competitorsUnknownRules).toEqual(['typescript:S1440']);
      // The same read in full marks nothing.
      const whole = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
      expect(whole.unread).toEqual({ kind: 'rules', rules: [] });
    });

    it('marks every item a rule not named by the facet could reach, when the resolved read is capped (S11)', async () => {
      fake = await startFakeSonarQube(sampleSonarData(), { facetCap: 1 });
      const conn = await connect();
      const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1);
      expect(resolved.unread.kind).toBe('all_but');
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
        pathPrefix: null,
        maxIssues: 1000,
        unreadResolved: resolved.unread,
      });
      expect(b.items.length).toBeGreaterThan(0);
      expect(b.items.every((i) => i.competitorsUnknown === true)).toBe(true);
    });

    it('reports an issue reopened between the two reads as changed (S11)', async () => {
      fake = await startFakeSonarQube(sampleSonarData());
      const conn = await connect();
      const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
      fake.data.issues.find((i) => i.key === 'AYi-fp-1')!.status = 'OPEN';
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
        pathPrefix: null,
        maxIssues: 1000,
        unreadResolved: resolved.unread,
      });
      expect(b.changed.map((i) => i.ref)).toEqual(['AYi-fp-1']);
      expect(b.items.map((i) => i.ref)).toEqual(['AYi-ac-1']);
      expect(b.competitors.map((i) => i.ref).sort()).toEqual(['AYi-fp-1', 'AYi-open']);
    });

    it('reads nothing more when no resolved item has a target', async () => {
      fake = await startFakeSonarQube(sampleSonarData({ issues: [] }));
      const conn = await connect();
      const before = fake.requests.length;
      const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', [], {
        pathPrefix: null,
        maxIssues: 1000,
      });
      expect(b.items).toEqual([]);
      expect(fake.requests.length).toBe(before);
    });

    describe('mapping components: closure, not hops (ruling S14)', () => {
      /** The reviewers' probes: U → t; O → t, t2; J → t2; K → t2, t3. */
      const rule = (sonar: string, qualor: string[]) => ({
        sonar: [sonar],
        qualor,
        relation: 'overlap' as const,
        reviewed: false,
        reason: 'probe',
      });
      const chain = loadSonarMapping({
        languages: { ts: { language: 'typescript', engines: ['eslint'] } },
        aliases: {},
        repositories: [{ repository: 'external_eslint_repo', engine: 'eslint', reason: 'ESLint' }],
        rules: [
          rule('typescript:U', ['eslint:t']),
          rule('typescript:O', ['eslint:t', 'eslint:t2']),
          rule('typescript:J', ['eslint:t2']),
          rule('typescript:K', ['eslint:t2', 'eslint:t3']),
        ],
      });
      const probeIssue = (
        key: string,
        r: string,
        line: number,
        message: string,
        status: FakeIssue['status'],
      ): FakeIssue => ({ key, rule: r, project: 'acme:shop', path: 'p', line, message, status });
      const cand = (id: string, ruleKey: string, line: number, message: string) => ({
        id,
        ruleKey,
        path: 'p',
        line,
        sonarLineHash: null,
        message,
      });
      const openAsked = () =>
        fake!.requests
          .filter(
            (r) => r.path === 'api/issues/search' && r.query['issueStatuses'] === 'OPEN,CONFIRMED',
          )
          .map((r) => r.query['rules']);

      it('marks J when a rule two targets away has resolved issues left unread (the 12a probe)', async () => {
        fake = await startFakeSonarQube(
          sampleSonarData({
            issues: [
              probeIssue('J', 'typescript:J', 20, 'm', 'FALSE_POSITIVE'),
              probeIssue('O1', 'typescript:O', 10, 'm', 'OPEN'),
              probeIssue('U', 'typescript:U', 30, 'm', 'FALSE_POSITIVE'),
            ],
          }),
        );
        const conn = await connect();
        // Only J is read; U (targets t only, shares nothing with J) is not.
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1);
        expect(resolved.issues.map((i) => i.key)).toEqual(['J']);
        expect(resolved.unread).toEqual({ kind: 'rules', rules: ['typescript:U'] });
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
          mapping: chain,
        });
        expect(b.items.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['J', true]]);
        expect(b.competitorsUnknownRules).toEqual(['typescript:U']);
        const m = matchStatuses(
          [...b.items, ...b.competitors],
          [cand('c_t', 'eslint:t', 10, 'm'), cand('c_t2', 'eslint:t2', 14, 'm')],
        ).find((x) => x.ref === 'J');
        expect(m?.competitorsUnknown === true || m?.ambiguous === true).toBe(true);
      });

      it('reads the open issues of the whole component, so J ends ambiguous (the S7 two-hop probe)', async () => {
        const data = sampleSonarData({
          issues: [
            probeIssue('D3', 'typescript:J', 20, 'n', 'FALSE_POSITIVE'),
            probeIssue('B1', 'typescript:O', 25, 'n', 'OPEN'),
            probeIssue('A0', 'typescript:U', 25, 'n', 'OPEN'),
          ],
        });
        fake = await startFakeSonarQube(data);
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
          mapping: chain,
        });
        // One hop from J reaches O and K, not U; the component reaches all four.
        expect(chain.competingRules(['typescript:J'])).not.toContain('typescript:U');
        const asked = chain.componentRules(chain.component('typescript:J')!);
        expect(asked).toContain('typescript:U');
        expect(openAsked()).toEqual([asked.join(','), asked.join(',')]);
        expect(b.competitors.map((i) => i.ref).sort()).toEqual(['A0', 'B1']);
        const cands = [
          cand('c0', 'eslint:t', 25, 'm'),
          cand('c1', 'eslint:t2', 10, 'm'),
          cand('c2', 'eslint:t2', 12, 'm'),
          cand('c3', 'eslint:t2', 14, 'n'),
        ];
        const full = matchStatuses([...b.items, ...b.competitors], cands);
        expect(full.find((x) => x.ref === 'D3')).toMatchObject({
          ambiguous: true,
          candidateId: null,
        });
        // Without U's open issue (the old one-hop read), J would pair c3.
        const oneHop = matchStatuses(
          [...b.items, ...b.competitors.filter((i) => i.ref !== 'A0')],
          cands,
        );
        expect(oneHop.find((x) => x.ref === 'D3')?.candidateId).toBe('c3');
        // And when U's open issues are not all read, J is marked.
        const capped = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1,
          unreadResolved: resolved.unread,
          mapping: chain,
        });
        expect(capped.items.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['D3', true]]);
      });

      it('probes the resolved issues again after the open read: a rule whose count changed marks its component (S14 c)', async () => {
        const data = sampleSonarData();
        data.issues.push({
          ...extra('AYi-nv', 'external_eslint_repo:no-var', 8),
          status: 'FALSE_POSITIVE',
        });
        fake = await startFakeSonarQube(data);
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        // Between the reads, AYi-open (S1440) is resolved and AYi-um-1 (S3776) reopened: the total
        // stays 4, the open read no longer sees AYi-open, and the resolved read never did.
        fake.data.issues.find((i) => i.key === 'AYi-open')!.status = 'FALSE_POSITIVE';
        fake.data.issues.find((i) => i.key === 'AYi-um-1')!.status = 'OPEN';
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
        });
        expect(b.competitors).toEqual([]);
        expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
          ['AYi-fp-1', true],
          ['AYi-ac-1', true],
          ['AYi-nv', false],
        ]);
        expect(b.competitorsUnknownRules).toEqual(['typescript:S1440']);
        const probes = fake.requests.filter(
          (r) =>
            r.path === 'api/issues/search' &&
            r.query['ps'] === '1' &&
            r.query['facets'] === 'rules',
        );
        expect(probes.at(-1)?.query).toMatchObject({
          issueStatuses: 'ACCEPTED,FALSE_POSITIVE',
          projects: 'acme:shop',
        });
      });

      it('marks every component when the resolved total changed between the probes (S14 c)', async () => {
        const data = sampleSonarData();
        data.issues.push({
          ...extra('AYi-nv', 'external_eslint_repo:no-var', 8),
          status: 'FALSE_POSITIVE',
        });
        fake = await startFakeSonarQube(data);
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        fake.data.issues.push({ ...extra('AYi-new', 'typescript:S3776', 40), status: 'ACCEPTED' });
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
        });
        expect(b.items.length).toBe(3);
        expect(b.items.every((i) => i.competitorsUnknown === true)).toBe(true);
      });

      it('adds no read for a singleton component: the open read names only the rule itself', async () => {
        expect(
          SONAR_MAPPING.componentRules(
            SONAR_MAPPING.component('external_eslint_repo:local/only-here')!,
          ),
        ).toEqual(['external_eslint_repo:local/only-here']);
        fake = await startFakeSonarQube(
          sampleSonarData({
            issues: [
              {
                ...extra('AYi-nv', 'external_eslint_repo:local/only-here', 8),
                status: 'FALSE_POSITIVE',
              },
            ],
          }),
        );
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        const before = fake.requests.length;
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
        });
        expect(b.items.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['AYi-nv', undefined]]);
        const after = fake.requests.slice(before);
        // The open read's probe (no open issue: no page), then the resolved re-probe; nothing else.
        expect(openAsked()).toEqual(['external_eslint_repo:local/only-here']);
        expect(after.map((r) => [r.path, r.query['issueStatuses'], r.query['ps']])).toEqual([
          ['api/issues/search', 'OPEN,CONFIRMED', '1'],
          ['api/issues/search', 'ACCEPTED,FALSE_POSITIVE', '1'],
        ]);
      });

      it('fails closed per component when a probe facet does not cover its total (fix 12c)', async () => {
        // S3776 (unmapped) holds the one facet value a probe lists; J and U are never listed.
        const s3776 = (key: string, line: number, status: FakeIssue['status']): FakeIssue => ({
          ...probeIssue(key, 'typescript:S3776', line, 'x', status),
        });
        fake = await startFakeSonarQube(
          sampleSonarData({
            issues: [
              probeIssue('J', 'typescript:J', 20, 'm', 'FALSE_POSITIVE'),
              probeIssue('U', 'typescript:U', 30, 'm', 'OPEN'),
              s3776('X1', 1, 'FALSE_POSITIVE'),
              s3776('X2', 2, 'FALSE_POSITIVE'),
              s3776('X3', 3, 'FALSE_POSITIVE'),
            ],
          }),
          { facetCap: 1 },
        );
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        expect(resolved.probe.counts).toEqual({ 'typescript:S3776': 3 });
        // Between the reads U is resolved and X3 reopened: the total stays 4, and U's count
        // change is in no facet.
        fake.data.issues.find((i) => i.key === 'U')!.status = 'FALSE_POSITIVE';
        fake.data.issues.find((i) => i.key === 'X3')!.status = 'OPEN';
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
          mapping: chain,
        });
        expect(b.items.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['J', true]]);
        // A component marked whole names no rule.
        expect(b.competitorsUnknownRules).toEqual([]);
      });

      it('does not read a component over the rule budget, and marks its items', async () => {
        const many = Array.from({ length: MAX_COMPONENT_RULES }, (_, n) => `typescript:B${n}`);
        const big = loadSonarMapping({
          languages: { ts: { language: 'typescript', engines: ['eslint'] } },
          aliases: {},
          repositories: [
            { repository: 'external_eslint_repo', engine: 'eslint', reason: 'ESLint' },
          ],
          rules: [{ ...rule('typescript:B0', ['eslint:big']), sonar: many }],
        });
        expect(big.componentRules(big.component('typescript:B0')!).length).toBeGreaterThan(
          MAX_COMPONENT_RULES,
        );
        fake = await startFakeSonarQube(
          sampleSonarData({
            issues: [
              { ...extra('AYi-b0', 'typescript:B0', 3), status: 'FALSE_POSITIVE' },
              { ...extra('AYi-nv', 'external_eslint_repo:no-var', 8), status: 'FALSE_POSITIVE' },
            ],
          }),
        );
        const conn = await connect();
        const resolved = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
        const b = await buildWithCompetitors(conn.client, conn, 'acme:shop', resolved.issues, {
          pathPrefix: null,
          maxIssues: 1000,
          unreadResolved: resolved.unread,
          probe: resolved.probe,
          mapping: big,
        });
        expect(openAsked()).toEqual(['external_eslint_repo:no-var']);
        expect(b.items.map((i) => [i.ref, i.competitorsUnknown ?? false])).toEqual([
          ['AYi-b0', true],
          ['AYi-nv', false],
        ]);
      });
    });
  });
});

describe('chunks and sending (import-sonarqube.md §11.2)', () => {
  const item = (ref: string, path: string | null): StatusImportItem => ({
    ref,
    ruleKeys: ['eslint:x'],
    path,
    line: 1,
    sonarLineHash: null,
    message: null,
    status: 'false_positive',
    comment: 'c',
  });
  const rival = (ref: string, path: string | null): StatusCompetitorItem => ({
    ref,
    ruleKeys: ['eslint:x'],
    path,
    line: 1,
    sonarLineHash: null,
    message: null,
    status: 'open',
  });
  const refs = (chunks: readonly (readonly StatusImportRequestItem[])[]) =>
    chunks.map((c) => c.map((i) => i.ref));
  const bodyBytes = (items: readonly StatusImportRequestItem[]) =>
    Buffer.byteLength(JSON.stringify({ dryRun: false, items }));
  const marked = (i: StatusImportRequestItem | undefined) =>
    i !== undefined && i.status !== 'open' && i.competitorsUnknown === true;

  it('keeps each path in one chunk, within the count bound', () => {
    const { chunks } = chunkItems([item('a', 'x.ts'), item('b', 'y.ts'), item('c', 'x.ts')], 2);
    expect(refs(chunks)).toEqual([['a', 'c'], ['b']]);
  });

  it('sends a path with its competitors in one request, and never a path without a resolved item', () => {
    const { chunks, unsent } = chunkItems(
      [
        item('a', 'x.ts'),
        rival('o1', 'x.ts'),
        item('b', 'y.ts'),
        rival('o2', 'z.ts'),
        rival('o3', 'y.ts'),
      ],
      3,
    );
    expect(refs(chunks)).toEqual([
      ['a', 'o1'],
      ['b', 'o3'],
    ]);
    expect(unsent).toEqual([]);
  });

  it('marks a path that does not fit with its competitors, and sends it whole without them', () => {
    const { chunks } = chunkItems(
      [
        item('a', 'x.ts'),
        item('b', 'x.ts'),
        rival('o1', 'x.ts'),
        rival('o2', 'x.ts'),
        item('c', 'y.ts'),
      ],
      3,
    );
    // x.ts is 4 items with its competitors: it goes as its 2 resolved items, marked.
    expect(refs(chunks)).toEqual([['a', 'b', 'c']]);
    expect(chunks[0]?.map(marked)).toEqual([true, true, false]);
  });

  it('never splits a path: one whose resolved items alone do not fit is reported, not sent', () => {
    const { chunks, unsent } = chunkItems(
      [item('a', 'x.ts'), item('b', 'x.ts'), item('c', 'x.ts'), item('d', 'y.ts')],
      2,
    );
    expect(refs(chunks)).toEqual([['d']]);
    expect(unsent.map((i) => i.ref)).toEqual(['a', 'b', 'c']);
  });

  it('bounds each request body in bytes, the envelope included', () => {
    const fat = (ref: string, path: string): StatusImportItem => ({
      ...item(ref, path),
      comment: 'c'.repeat(1900),
    });
    const items = Array.from({ length: 30 }, (_, n) => fat(`r${n}`, `f${n % 10}.ts`));
    const max = 12_000;
    const { chunks, unsent } = chunkItems(items, 1000, max);
    expect(unsent).toEqual([]);
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) expect(bodyBytes(c)).toBeLessThanOrEqual(max);
    expect(
      chunks
        .flat()
        .map((i) => i.ref)
        .sort(),
    ).toEqual(items.map((i) => i.ref).sort());
    const chunkOf = new Map<string, number>();
    chunks.forEach((c, n) => {
      for (const i of c) {
        const seen = chunkOf.get(i.path ?? '');
        if (seen !== undefined) expect(seen).toBe(n);
        chunkOf.set(i.path ?? '', n);
      }
    });
    // Exactly at the bound fits; one byte less does not.
    const one = [item('z', 'q.ts')];
    expect(chunkItems(one, 1000, bodyBytes(one)).chunks).toHaveLength(1);
    expect(chunkItems(one, 1000, bodyBytes(one) - 1).unsent.map((i) => i.ref)).toEqual(['z']);
  });

  it('splits a request Qualor finds too large, down to one path, and reports that path failed', async () => {
    const q = new MemoryQualor();
    q.statusHandler = (_p, items) =>
      new Set(items.map((i) => i.path)).size > 1 || items.some((i) => i.path === 'huge.ts')
        ? { kind: 'too_large' }
        : {
            kind: 'ok',
            results: items
              .filter((i) => i.status !== 'open')
              .map((i) => ({
                ref: i.ref,
                outcome: 'applied',
                issueId: null,
                status: 'false_positive',
              })),
            competitors: items.filter((i) => i.status === 'open').length,
          };
    const r = await sendStatuses(
      q,
      'p',
      [
        item('a', 'x.ts'),
        rival('o', 'x.ts'),
        item('b', 'y.ts'),
        item('c', 'huge.ts'),
        rival('p', 'huge.ts'),
      ],
      false,
    );
    expect(r).toMatchObject({ kind: 'done', failedRefs: ['c'], competitors: 1 });
    expect(r.kind === 'done' && r.results.map((x) => x.ref).sort()).toEqual(['a', 'b']);
    // The competitor always travelled with its path.
    for (const call of q.statusCalls) {
      if (call.items.some((i) => i.ref === 'o')) {
        expect(call.items.some((i) => i.ref === 'a')).toBe(true);
      }
    }
  });

  it('stops at once when the project has no analysis', async () => {
    const q = new MemoryQualor();
    expect(await sendStatuses(q, 'p', [item('a', 'x.ts')], true)).toEqual({ kind: 'not_analysed' });
  });

  it('keeps the results already answered when the analysis goes away mid-run', async () => {
    const q = new MemoryQualor();
    q.statusHandler = (_p, items) =>
      q.statusCalls.length > 1
        ? { kind: 'not_analysed' }
        : {
            kind: 'ok',
            results: items.map((i) => ({
              ref: i.ref,
              outcome: 'applied',
              issueId: '00000000-0000-7000-8000-0000000000aa',
              status: 'false_positive',
            })),
            competitors: 0,
          };
    const items = [item('a', 'a.ts'), item('b', 'b.ts'), item('c', 'c.ts')];
    const r = await sendStatuses(q, 'p', items, false, { maxCount: 1 });
    expect(r).toMatchObject({ kind: 'done', failedRefs: ['b', 'c'] });
    expect(r.kind === 'done' && r.results.map((x) => [x.ref, x.outcome])).toEqual([
      ['a', 'applied'],
    ]);
    expect(r.kind === 'done' && r.failures[0]).toContain('PROJECT_NOT_ANALYSED');
    expect(q.statusCalls).toHaveLength(2);
  });

  it('passes the dry-run flag and reports what the server answered', async () => {
    const q = new MemoryQualor();
    q.statusHandler = (_p, items, dryRun) => ({
      kind: 'ok',
      results: items
        .filter((i) => i.status !== 'open')
        .map((i) => ({
          ref: i.ref,
          outcome: dryRun ? 'would_apply' : 'applied',
          issueId: '00000000-0000-7000-8000-0000000000aa',
          status: 'open',
        })),
      competitors: 0,
    });
    const r = await sendStatuses(q, 'p', [item('a', 'x.ts')], true);
    expect(q.statusCalls.map((c) => c.dryRun)).toEqual([true]);
    expect(r).toEqual({
      kind: 'done',
      results: [
        {
          ref: 'a',
          outcome: 'would_apply',
          issueId: '00000000-0000-7000-8000-0000000000aa',
          status: 'open',
        },
      ],
      unsent: [],
      failedRefs: [],
      failures: [],
      competitors: 0,
    });
  });

  it('reports a path that cannot be sent whole as not_sent, apart from the server outcomes, and sends the rest (M-4)', async () => {
    const q = new MemoryQualor();
    q.statusHandler = (_p, items) => ({
      kind: 'ok',
      results: items.map((i) => ({
        ref: i.ref,
        outcome: 'unmatched',
        issueId: null,
        status: null,
      })),
      competitors: 0,
    });
    const many = Array.from({ length: 1001 }, (_, n) => item(`h${n}`, 'huge.ts'));
    const r = await sendStatuses(q, 'p', [...many, item('a', 'x.ts')], false);
    expect(q.statusCalls.map((c) => c.items.map((i) => i.ref))).toEqual([['a']]);
    expect(r.kind === 'done' && r.results.filter((x) => x.outcome === 'not_sent')).toHaveLength(
      1001,
    );
    expect(r.kind === 'done' && r.results.some((x) => x.outcome === 'competitors_unknown')).toBe(
      false,
    );
    expect(r.kind === 'done' && r.unsent).toEqual(many.map((i) => i.ref));
  });

  it('records a chunk the server refuses as failed and goes on; stops on authentication and on an unreachable Qualor', async () => {
    const q = new MemoryQualor();
    q.statusHandler = (_p, items) => {
      if (items.some((i) => i.path === 'bad.ts')) {
        throw new QualorApiError(422, 'VALIDATION_FAILED', 'Qualor answered 422 VALIDATION_FAILED');
      }
      return {
        kind: 'ok',
        results: items.map((i) => ({
          ref: i.ref,
          outcome: 'unmatched',
          issueId: null,
          status: null,
        })),
        competitors: 0,
      };
    };
    const items = [item('r0', 'bad.ts'), item('r1', 'ok.ts')];
    const r = await sendStatuses(q, 'p', items, false, { maxCount: 1 });
    expect(r).toMatchObject({ kind: 'done', failedRefs: ['r0'] });
    expect(r.kind === 'done' && r.failures[0]).toContain('422');
    expect(r.kind === 'done' && r.results.map((x) => x.ref)).toEqual(['r1']);
    for (const err of [new CliError(EXIT.AUTH, 'refused'), new UnreachableError('down')]) {
      q.statusHandler = () => {
        throw err;
      };
      await expect(sendStatuses(q, 'p', items, false)).rejects.toBe(err);
    }
  });

  it('treats a missing or foreign result as failed, never as applied', async () => {
    const q = new MemoryQualor();
    q.statusHandler = () => ({
      kind: 'ok',
      results: [{ ref: 'zz', outcome: 'applied', issueId: null, status: 'false_positive' }],
      competitors: 0,
    });
    const r = await sendStatuses(q, 'p', [item('a', 'x.ts')], false);
    expect(r).toMatchObject({ kind: 'done', results: [], failedRefs: ['a'] });
  });
});
