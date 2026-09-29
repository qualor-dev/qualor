import { issuesPageSchema, SONAR_MAPPING } from '@qualor/shared';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type FakeIssue,
  type FakeSonar,
  type FakeSonarData,
  fakeRules,
  sampleSonarData,
  startFakeSonarQube,
} from '../../../test/fake-sonarqube';
import { EXIT } from '../../errors';
import { silentLogger } from '../../log';
import { request, UnreachableError } from '../../server/http';
import { connectSonar } from './client';
import {
  countReviewedHotspots,
  fetchGates,
  fetchOpenIssues,
  fetchProfiles,
  fetchProjectSettings,
  fetchResolvedIssues,
  listProjects,
} from './fetch';

let fake: FakeSonar | undefined;
afterEach(async () => {
  if (fake !== undefined) expect(fake.requests.every((r) => r.method === 'GET')).toBe(true);
  await fake?.close();
  fake = undefined;
});
const connect = (over: { kind?: 'cloud'; organization?: string } = {}) =>
  connectSonar({
    url: fake!.url,
    token: fake!.data.token,
    kind: over.kind ?? 'auto',
    organization: over.organization ?? null,
    auth: 'auto',
    timeoutMs: 5000,
    log: silentLogger,
    sleep: () => Promise.resolve(),
  });
const issueSearches = () => fake!.requests.filter((r) => r.path === 'api/issues/search');

describe('reading SonarQube (import-sonarqube.md §4.4, §5)', () => {
  it('reads supported profiles with their active and left-off rules, and does not read others', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const { client } = await connect();
    const profiles = await fetchProfiles(client);
    const ts = profiles.find((p) => p.key === 'p-ts')!;
    expect(ts.active.map((r) => r.key).sort()).toEqual(['typescript:S1440', 'typescript:S3776']);
    expect(ts.active.find((r) => r.key === 'typescript:S1440')).toMatchObject({
      defaultSeverity: 'MAJOR',
      severity: 'CRITICAL',
    });
    expect(ts.inactive).toEqual(['typescript:S3504']);
    expect(ts.complete).toBe(true);
    expect(profiles.find((p) => p.key === 'p-py')).toMatchObject({ active: [], complete: true });
    expect(fake.requests.filter((r) => r.query['qprofile'] === 'p-py')).toHaveLength(0);
  });

  it("never takes another profile's activation of a rule: the profile is not read whole", async () => {
    const data = sampleSonarData();
    data.profiles[0]!.active['typescript:S1440'] = {
      qProfile: 'p-ts-default',
      severity: 'BLOCKER',
    };
    fake = await startFakeSonarQube(data);
    const { client } = await connect();
    const ts = (await fetchProfiles(client)).find((p) => p.key === 'p-ts')!;
    expect(ts.active.map((r) => r.key)).toEqual(['typescript:S3776']);
    expect(ts.complete).toBe(false);
    expect(client.warnings.map((w) => w.message).join('\n')).toMatch(
      /1 active rules whose activation/,
    );
  });

  it('reads 9.9 rule pages that carry only a top-level total', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ version: '9.9.4.87374' }));
    const profiles = await fetchProfiles((await connect()).client);
    expect(profiles.find((p) => p.key === 'p-ts')?.active).toHaveLength(2);
  });

  it('marks a profile whose active rules exceed the window incomplete, and warns', async () => {
    const data = sampleSonarData();
    const many = Array.from({ length: 25 }, (_, n) => ({
      key: `typescript:S${9000 + n}`,
      name: `Rule S${9000 + n}`,
      lang: 'ts',
      severity: 'MAJOR' as const,
    }));
    data.rules.push(...many);
    data.profiles[0]!.active = Object.fromEntries(many.map((r) => [r.key, {}]));
    fake = await startFakeSonarQube(data, { window: 20 });
    const { client } = await connect();
    const profiles = await fetchProfiles(client, undefined, { window: 20, pageSize: 10 });
    const ts = profiles.find((p) => p.key === 'p-ts')!;
    expect(ts.active).toHaveLength(20);
    expect(ts.complete).toBe(false);
    expect(client.warnings.map((w) => w.code)).toContain('SONARQUBE_RULE_WINDOW');
    // Never a page past the window.
    expect(
      fake.requests.every((r) => Number(r.query['p'] ?? 1) * Number(r.query['ps'] ?? 1) <= 20),
    ).toBe(true);
  });

  it('reads gates with their conditions', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const gates = await fetchGates((await connect()).client);
    expect(gates.find((g) => g.name === 'Sonar way')).toMatchObject({
      isDefault: true,
      conditions: expect.arrayContaining([{ metric: 'new_violations', op: 'GT', error: '0' }]),
    });
  });

  it('lists projects, or checks the named ones, and reads their settings', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const { client } = await connect();
    expect((await listProjects(client, [])).projects).toEqual([{ key: 'acme:shop', name: 'Shop' }]);
    expect(await listProjects(client, ['acme:shop', 'acme:gone'])).toEqual({
      projects: [{ key: 'acme:shop', name: 'Shop' }],
      missing: ['acme:gone'],
    });
    expect(await fetchProjectSettings(client, { key: 'acme:shop', name: 'Shop' })).toEqual({
      key: 'acme:shop',
      name: 'Shop',
      mainBranch: 'main',
      profiles: expect.arrayContaining([{ language: 'ts', profileKey: 'p-ts', isDefault: false }]),
      gate: { name: 'Strict', isDefault: false },
    });
  });

  it('reads resolved issues with issueStatuses from 10.4 and resolutions before', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    let conn = await connect();
    const modern = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
    expect(modern.issues.map((i) => i.key).sort()).toEqual(['AYi-ac-1', 'AYi-fp-1', 'AYi-um-1']);
    expect(await countReviewedHotspots(conn.client, conn, 'acme:shop')).toBe(2);
    expect(issueSearches()[0]?.query['issueStatuses']).toBe('ACCEPTED,FALSE_POSITIVE');
    await fake.close();
    fake = await startFakeSonarQube(sampleSonarData({ version: '9.9.4.87374' }));
    conn = await connect();
    await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
    expect(issueSearches()[0]?.query['resolutions']).toBe('FALSE-POSITIVE,WONTFIX');
  });

  it('reads SonarQube Cloud with resolutions and the organization on every issue query', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const conn = await connect({ kind: 'cloud', organization: 'acme' });
    const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
    expect(r.issues).toHaveLength(3);
    expect(issueSearches().every((q) => q.query['organization'] === 'acme')).toBe(true);
    expect(issueSearches()[0]?.query['resolutions']).toBe('FALSE-POSITIVE,WONTFIX');
    // Finding L1: Cloud's hotspot search takes `projectKey` (Server's `project` is a 400 there).
    expect(await countReviewedHotspots(conn.client, conn, 'acme:shop')).toBe(2);
    expect(fake.requests.filter((q) => q.path === 'api/hotspots/search')).toEqual([
      expect.objectContaining({
        query: { projectKey: 'acme:shop', status: 'REVIEWED', ps: '1' },
      }),
    ]);
    expect(conn.client.warnings).toEqual([]);
  });

  it('asks SonarQube Server for hotspots by `projectKey` before 10.2 and by `project` from 10.2', async () => {
    for (const [version, param] of [
      ['9.9.4.87374', 'projectKey'],
      ['10.1.0.73491', 'projectKey'],
      ['10.2.0.77647', 'project'],
      ['26.9.0.129388', 'project'],
    ] as const) {
      fake = await startFakeSonarQube(sampleSonarData({ version }));
      const conn = await connect();
      expect(await countReviewedHotspots(conn.client, conn, 'acme:shop')).toBe(2);
      expect(fake.requests.find((q) => q.path === 'api/hotspots/search')?.query).toEqual({
        [param]: 'acme:shop',
        status: 'REVIEWED',
        ps: '1',
      });
      expect(conn.client.warnings).toEqual([]);
      await fake.close();
    }
    fake = undefined;
  });

  for (const kind of ['server', 'cloud'] as const) {
    it(`keeps the resolved issues when the hotspot count fails (${kind}): a warning, and the count unknown`, async () => {
      fake = await startFakeSonarQube(
        sampleSonarData(kind === 'cloud' ? { kind, organization: 'acme' } : {}),
      );
      fake.fault = (q) =>
        q.path === 'api/hotspots/search' ? { status: 400, body: '{"errors":[]}' } : null;
      const conn = await connect(kind === 'cloud' ? { kind, organization: 'acme' } : {});
      const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
      expect(await countReviewedHotspots(conn.client, conn, 'acme:shop')).toBeNull();
      expect(r.issues.map((i) => i.key).sort()).toEqual(['AYi-ac-1', 'AYi-fp-1', 'AYi-um-1']);
      expect(r.notRead).toBe(0);
      expect(conn.client.warnings).toEqual([
        {
          code: 'HOTSPOTS_NOT_COUNTED',
          message: expect.stringMatching(/reviewed security hotspots.*not counted.*400/),
        },
      ]);
    });
  }

  it('counts no hotspots, with a warning, when the answer is not a hotspot page', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    fake.fault = (q) =>
      q.path === 'api/hotspots/search' ? { status: 200, body: '{"nothing":1}' } : null;
    const conn = await connect();
    expect(await countReviewedHotspots(conn.client, conn, 'acme:shop')).toBeNull();
    expect(conn.client.warnings.map((w) => w.code)).toEqual(['HOTSPOTS_NOT_COUNTED']);
  });

  it('still stops on an unreachable SonarQube during the hotspot count (spec §13)', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connectSonar({
      url: fake.url,
      token: fake.data.token,
      kind: 'auto',
      organization: null,
      auth: 'auto',
      timeoutMs: 5000,
      log: silentLogger,
      sleep: () => Promise.resolve(),
      transport: (ep, o) =>
        o.path === 'api/hotspots/search'
          ? Promise.reject(new UnreachableError('SonarQube is unreachable'))
          : request(ep, o),
    });
    await expect(countReviewedHotspots(conn.client, conn, 'acme:shop')).rejects.toBeInstanceOf(
      UnreachableError,
    );
  });

  it('reads past the result window through the rules facet, and reports what stays unread', async () => {
    const many: FakeIssue[] = Array.from({ length: 30 }, (_, n) => ({
      key: `AYi-${n}`,
      rule: n < 25 ? 'external_eslint_repo:eqeqeq' : 'typescript:S1440',
      project: 'acme:shop',
      path: `src/f${n}.ts`,
      line: 1,
      message: 'm',
      status: 'FALSE_POSITIVE' as const,
    }));
    fake = await startFakeSonarQube(sampleSonarData({ issues: many }), { window: 20 });
    const conn = await connect();
    const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000, {
      window: 20,
      pageSize: 10,
    });
    expect(r.total).toBe(30);
    expect(r.issues).toHaveLength(25); // 20 of the big rule (the window), all 5 of the other
    expect(r.notRead).toBe(5);
    expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
    expect(issueSearches().every((q) => Number(q.query['p']) * Number(q.query['ps']) <= 20)).toBe(
      true,
    );
  });

  it('counts what is not read from the final total, not the first one', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    // The facet probe still sees 10 resolved issues; by the time the pages are read, 3 are left.
    fake.fault = (q) =>
      q.path === 'api/issues/search' && q.query['facets'] === 'rules'
        ? {
            status: 200,
            body: JSON.stringify({
              total: 10,
              p: 1,
              ps: 1,
              paging: { pageIndex: 1, pageSize: 1, total: 10 },
              issues: [],
              components: [],
              facets: [{ property: 'rules', values: [{ val: 'typescript:S1440', count: 10 }] }],
            }),
          }
        : null;
    const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000);
    expect(r.issues).toHaveLength(3);
    expect(r.total).toBe(3);
    expect(r.notRead).toBe(0);
    expect(conn.client.warnings.map((w) => w.code)).not.toContain('SONARQUBE_ISSUE_WINDOW');
  });

  it('never reports nothing unread after a read whose total changed between pages', async () => {
    const five: FakeIssue[] = Array.from({ length: 5 }, (_, n) => ({
      key: `AYi-${n}`,
      rule: 'external_eslint_repo:eqeqeq',
      project: 'acme:shop',
      path: 'src/a.ts',
      line: n + 1,
      message: 'm',
      status: 'FALSE_POSITIVE' as const,
    }));
    fake = await startFakeSonarQube(sampleSonarData({ issues: five }));
    const conn = await connect();
    // Before page 2 the first issue is reopened: page 2 starts one further on and AYi-2 is
    // skipped, while the 4 read still reach the final total of 4.
    let n = 0;
    fake.fault = (q) => {
      if (q.path === 'api/issues/search' && q.query['facets'] === undefined && ++n === 2) {
        fake!.data.issues.shift();
      }
      return null;
    };
    const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 1000, { pageSize: 2 });
    expect(r.issues.map((i) => i.key)).not.toContain('AYi-2');
    expect(r.issues.length).toBeGreaterThanOrEqual(r.total);
    expect(r.notRead).toBeGreaterThan(0);
    expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
  });

  it('stops at --max-issues and reports the rest as not read', async () => {
    const many: FakeIssue[] = Array.from({ length: 30 }, (_, n) => ({
      key: `AYi-${n}`,
      rule: 'external_eslint_repo:eqeqeq',
      project: 'acme:shop',
      path: `src/f${n}.ts`,
      line: 1,
      message: 'm',
      status: 'FALSE_POSITIVE' as const,
    }));
    fake = await startFakeSonarQube(sampleSonarData({ issues: many }));
    const conn = await connect();
    const r = await fetchResolvedIssues(conn.client, conn, 'acme:shop', 12, { pageSize: 10 });
    expect(r.issues).toHaveLength(12);
    expect(r.notRead).toBe(18);
  });
});

describe('reading open competitors (import-sonarqube.md §10.1, ruling S3)', () => {
  const open = (n: number, rule: string, over: Partial<FakeIssue> = {}): FakeIssue => ({
    key: `AYo-${rule}-${n}`,
    rule,
    project: 'acme:shop',
    path: 'src/a.ts',
    line: n + 1,
    message: 'm',
    status: 'OPEN',
    ...over,
  });

  it('reads the open issues of the given rules only, OPEN and CONFIRMED from 10.4', async () => {
    const data = sampleSonarData();
    data.issues.push(
      open(1, 'typescript:S1440', { status: 'CONFIRMED' }),
      open(2, 'typescript:S3504'),
    );
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000);
    expect(r.issues.map((i) => i.key).sort()).toEqual(['AYi-open', 'AYo-typescript:S1440-1']);
    expect(r.unreadRules).toEqual([]);
    const q = issueSearches().at(-1)?.query ?? {};
    expect(q['issueStatuses']).toBe('OPEN,CONFIRMED');
    expect(q['rules']).toBe('typescript:S1440');
    expect(q['resolved']).toBeUndefined();
  });

  it('asks resolved=false, and the issues a person resolved as fixed, before 10.4 and on SonarQube Cloud (I-2)', async () => {
    for (const over of [
      { version: '9.9.4.87374' },
      { kind: 'cloud', organization: 'acme' },
    ] satisfies Partial<FakeSonarData>[]) {
      const data = sampleSonarData(over);
      // A person's "Resolve as fixed" leaves the issue in the code until the next analysis: it
      // competes like an open one. One SonarQube closed itself (FIXED, CLOSED) does not.
      data.issues.push(
        open(1, 'typescript:S1440', { status: 'RESOLVED_FIXED' }),
        open(2, 'typescript:S1440', { status: 'FIXED' }),
      );
      fake = await startFakeSonarQube(data);
      const conn = await connect(
        over.kind === 'cloud' ? { kind: 'cloud', organization: 'acme' } : {},
      );
      const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000);
      expect(r.issues.map((i) => i.key).sort()).toEqual(['AYi-open', 'AYo-typescript:S1440-1']);
      expect(r.unreadRules).toEqual([]);
      const pages = issueSearches().filter((x) => x.query['ps'] !== '1');
      expect(
        pages.map((x) => [x.query['resolved'], x.query['statuses'], x.query['resolutions']]),
      ).toEqual([
        ['false', undefined, undefined],
        [undefined, 'RESOLVED', 'FIXED'],
      ]);
      expect(issueSearches().every((x) => x.query['issueStatuses'] === undefined)).toBe(true);
      expect(fake.requests.every((x) => x.method === 'GET')).toBe(true);
      await fake.close();
      fake = undefined;
    }
  });

  it('fails closed when SonarQube refuses the fixed read: its rules are unread, the open issues kept (I-2)', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    // The Cloud query of issues resolved as fixed is not verified live: a refusal must not cost
    // the project's issues, only make its rules count as not read.
    fake.fault = (r) =>
      r.path === 'api/issues/search' && r.query['statuses'] === 'RESOLVED'
        ? { status: 400, body: JSON.stringify({ errors: [{ msg: 'bad parameter' }] }) }
        : null;
    const conn = await connect({ kind: 'cloud', organization: 'acme' });
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000);
    expect(r.issues.map((i) => i.key)).toEqual(['AYi-open']);
    expect(r.unreadRules).toEqual(['typescript:S1440']);
    // A refused token still ends the run (exit 5).
    fake.fault = (r) =>
      r.path === 'api/issues/search' && r.query['statuses'] === 'RESOLVED' ? { status: 401 } : null;
    await expect(
      fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000),
    ).rejects.toMatchObject({ exitCode: EXIT.AUTH });
  });

  it('counts a rule as unread when the fixed read is capped (I-2)', async () => {
    const data = sampleSonarData({ version: '9.9.4.87374' });
    data.issues.push(open(1, 'typescript:S1440', { status: 'RESOLVED_FIXED' }));
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    // The open read takes the one issue the cap allows; the fixed read cannot run.
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1);
    expect(r.issues.map((i) => i.key)).toEqual(['AYi-open']);
    expect(r.unreadRules).toEqual(['typescript:S1440']);
  });

  it('asks IN_SANDBOX from SonarQube Server 2025.5, and not before (I-2)', async () => {
    const data = sampleSonarData({ version: '2025.5.0.113872' });
    data.issues.push(open(1, 'typescript:S1440', { status: 'IN_SANDBOX' }));
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000);
    expect(r.issues.map((i) => i.key).sort()).toEqual(['AYi-open', 'AYo-typescript:S1440-1']);
    expect(issueSearches().map((x) => x.query['issueStatuses'])).toEqual([
      'OPEN,CONFIRMED,IN_SANDBOX',
      'OPEN,CONFIRMED,IN_SANDBOX',
    ]);
    await fake.close();
    // 2025.4 and a Community Build (year-numbered 25.x) have no sandbox: never asked.
    for (const version of ['2025.4.2.112048', '25.9.0.112764']) {
      fake = await startFakeSonarQube(sampleSonarData({ version }));
      const c2 = await connect();
      await fetchOpenIssues(c2.client, c2, 'acme:shop', ['typescript:S1440'], 1000);
      expect(issueSearches().map((x) => x.query['issueStatuses'])).toEqual([
        'OPEN,CONFIRMED',
        'OPEN,CONFIRMED',
      ]);
      await fake.close();
    }
    fake = undefined;
  });

  it('asks SonarQube Server only the rules it has: an unknown one would fail the rules facet with 500', async () => {
    const data = sampleSonarData({ version: '9.9.4.87374' });
    data.issues.push(open(1, 'java:S1481', { path: 'src/A.java' }));
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    // The fake fails like 9.9 does: a rule it never had, with the rules facet.
    await expect(
      conn.client.get(
        'api/issues/search',
        { projects: 'acme:shop', rules: 'pmd:UnusedPrivateField,java:S1481', facets: 'rules' },
        issuesPageSchema,
        'issue page',
      ),
    ).rejects.toMatchObject({ exitCode: EXIT.SERVER });
    const asking = ['pmd:UnusedPrivateField', 'java:S1481', 'java:S9999', 'squid:S1481'];
    const before = issueSearches().length;
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', asking, 1000);
    expect(r.issues.map((i) => i.key)).toEqual(['AYo-java:S1481-1']);
    expect(r.unreadRules).toEqual([]);
    const asked = issueSearches().slice(before);
    expect(asked.length).toBeGreaterThan(0);
    expect(asked.every((q) => q.query['rules'] === 'java:S1481')).toBe(true);
    // Each repository's rules are read once for the client, external rules included.
    await fetchOpenIssues(conn.client, conn, 'acme:shop', asking, 1000);
    const lists = fake.requests.filter(
      (q) => q.path === 'api/rules/search' && q.query['repositories'] !== undefined,
    );
    expect(lists.map((q) => q.query['repositories']).sort()).toEqual(['java', 'pmd', 'squid']);
    expect(lists.every((q) => q.query['include_external'] === 'true')).toBe(true);
  });

  it('leaves the rules of a repository whose rule list was not read whole unread, and does not ask them', async () => {
    const data = sampleSonarData();
    data.rules.push(...fakeRules(['typescript:S1', 'typescript:S2']));
    fake = await startFakeSonarQube(data, { window: 4 });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['typescript:S1440', 'external_eslint_repo:eqeqeq'],
      1000,
      { window: 4, pageSize: 2 },
    );
    expect(r.unreadRules).toEqual(['typescript:S1440']);
    expect(issueSearches().every((q) => q.query['rules'] === 'external_eslint_repo:eqeqeq')).toBe(
      true,
    );
    expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
  });

  it('reads no rule list on SonarQube Cloud', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const conn = await connect({ kind: 'cloud', organization: 'acme' });
    await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440', 'pmd:X'], 1000);
    expect(fake.requests.some((q) => q.path === 'api/rules/search')).toBe(false);
    expect(issueSearches()[0]?.query['rules']).toBe('pmd:X,typescript:S1440');
  });

  it('asks nothing without rules', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    expect(await fetchOpenIssues(conn.client, conn, 'acme:shop', [], 1000)).toEqual({
      issues: [],
      total: 0,
      unreadRules: [],
    });
    expect(issueSearches()).toHaveLength(0);
  });

  it('asks at most 100 rules per query', async () => {
    const rules = Array.from({ length: 250 }, (_, n) => `typescript:S${n}`);
    const data = sampleSonarData();
    data.rules.push(...fakeRules(rules));
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    await fetchOpenIssues(conn.client, conn, 'acme:shop', rules, 1000);
    const asked = issueSearches().map((q) => (q.query['rules'] ?? '').split(','));
    expect(asked.every((r) => r.length <= 100)).toBe(true);
    expect(new Set(asked.flat())).toEqual(new Set(rules));
  });

  it('reports the rules whose open issues pass the window, and only those', async () => {
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 25 }, (_, n) => open(n, 'external_eslint_repo:eqeqeq')),
        ...Array.from({ length: 3 }, (_, n) => open(n, 'typescript:S1440')),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20 });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['external_eslint_repo:eqeqeq', 'typescript:S1440', 'typescript:S3776'],
      1000,
      { window: 20, pageSize: 10 },
    );
    expect(r.total).toBe(28);
    expect(r.issues).toHaveLength(23);
    expect(r.unreadRules).toEqual(['external_eslint_repo:eqeqeq']);
    expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
    expect(issueSearches().every((q) => Number(q.query['p']) * Number(q.query['ps']) <= 20)).toBe(
      true,
    );
  });

  it('reports every rule a capped facet leaves uncounted', async () => {
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 22 }, (_, n) => open(n, 'external_eslint_repo:eqeqeq')),
        ...Array.from({ length: 2 }, (_, n) => open(n, 'typescript:S1440')),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20, facetCap: 1 });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['external_eslint_repo:eqeqeq', 'typescript:S1440'],
      1000,
      { window: 20, pageSize: 10 },
    );
    expect(r.unreadRules).toEqual(['external_eslint_repo:eqeqeq', 'typescript:S1440']);
  });

  it('judges a rule by its own facet count when the facet is sticky (R1 15 000, R9 30 000)', async () => {
    // SonarQube's rules facet ignores the query's own rules= filter: asking R1 alone, the facet
    // still lists R9, whose issues are not R1's and must neither be read nor count for R1.
    const issues: FakeIssue[] = [];
    for (let n = 0; n < 15_000; n++) {
      issues.push(open(n, 'typescript:S1440', { key: `R1-${n}`, path: `src/r1/${n % 50}.ts` }));
    }
    for (let n = 0; n < 30_000; n++) {
      issues.push(open(n, 'typescript:S3776', { key: `R9-${n}`, path: `src/r9/${n % 50}.ts` }));
    }
    fake = await startFakeSonarQube(sampleSonarData({ issues }), { stickyFacets: true });
    const conn = await connect();
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 100_000);
    expect(r.unreadRules).toEqual(['typescript:S1440']);
    expect(r.issues.every((i) => i.rule === 'typescript:S1440')).toBe(true);
    expect(r.issues).toHaveLength(10_000);
    expect(r.total).toBe(15_000);
    // No query read R9 on its own.
    expect(issueSearches().some((q) => q.query['rules'] === 'typescript:S3776')).toBe(false);
    expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
  }, 30_000);

  it('reads a batch whole and complete under a sticky facet that lists other rules', async () => {
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 5 }, (_, n) => open(n, 'typescript:S1440')),
        ...Array.from({ length: 40 }, (_, n) => open(n, 'typescript:S3776', { path: 'src/z.ts' })),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20, stickyFacets: true, facetCap: 1 });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['typescript:S1440', 'typescript:S3504'],
      1000,
      { window: 20, pageSize: 10 },
    );
    // The facet lists only S3776 (not asked); the batch's 5 issues fit the window and were read.
    expect(r.issues).toHaveLength(5);
    expect(r.unreadRules).toEqual([]);
  });

  it('slices by the batch rules only under a sticky facet, past the window', async () => {
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 15 }, (_, n) => open(n, 'typescript:S1440')),
        ...Array.from({ length: 10 }, (_, n) => open(n, 'typescript:S3504', { path: 'src/b.ts' })),
        ...Array.from({ length: 60 }, (_, n) => open(n, 'typescript:S3776', { path: 'src/z.ts' })),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20, stickyFacets: true });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['typescript:S1440', 'typescript:S3504'],
      1000,
      { window: 20, pageSize: 10 },
    );
    expect(r.total).toBe(25);
    expect(r.issues).toHaveLength(25);
    expect(r.unreadRules).toEqual([]);
    expect(issueSearches().some((q) => q.query['rules'] === 'typescript:S3776')).toBe(false);
  });

  it('reads the open issues of every rule sharing a target (ruling S7)', async () => {
    const data = sampleSonarData();
    data.issues.push(
      open(1, 'external_eslint_repo:eqeqeq', { line: 3 }),
      open(2, 'typescript:S3776', { line: 9 }),
    );
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    // The resolved issues' rules: typescript:S1440 and eqeqeq both target eslint:eqeqeq.
    const rules = SONAR_MAPPING.competingRules(['typescript:S1440']);
    expect(rules).toContain('external_eslint_repo:eqeqeq');
    expect(rules).toContain('typescript:S1440');
    expect(rules).not.toContain('typescript:S3776');
    const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', rules, 1000);
    expect(r.issues.map((i) => i.key).sort()).toEqual([
      'AYi-open',
      'AYo-external_eslint_repo:eqeqeq-1',
    ]);
    expect(r.unreadRules).toEqual([]);
  });

  it('reports the rules left unread by the --max-issues cap', async () => {
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 8 }, (_, n) => open(n, 'external_eslint_repo:eqeqeq')),
        ...Array.from({ length: 8 }, (_, n) => open(n, 'typescript:S1440', { path: 'src/b.ts' })),
      ],
    });
    fake = await startFakeSonarQube(data);
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['external_eslint_repo:eqeqeq', 'typescript:S1440'],
      10,
      { pageSize: 5 },
    );
    expect(r.issues).toHaveLength(10);
    // Sorted by file and line, src/a.ts's 8 come first: eqeqeq is complete, S1440 is not.
    expect(r.unreadRules).toEqual(['typescript:S1440']);
  });

  it('keeps a rule unread under --max-issues though a sticky facet lists a foreign rule', async () => {
    // The batch's 8 issues fit the window but the cap stops at 5; the facet also lists S3776 (40,
    // not asked). S3504 has no issue: the batch's facet values add up to the probe's total.
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 8 }, (_, n) => open(n, 'typescript:S1440')),
        ...Array.from({ length: 40 }, (_, n) => open(n, 'typescript:S3776', { path: 'src/z.ts' })),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20, stickyFacets: true });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['typescript:S1440', 'typescript:S3504'],
      5,
      { window: 20, pageSize: 10 },
    );
    expect(r.issues).toHaveLength(5);
    expect(r.issues.every((i) => i.rule === 'typescript:S1440')).toBe(true);
    expect(r.unreadRules).toEqual(['typescript:S1440']);
  });

  it('keeps every rule unread when foreign rules crowd a capped sticky facet', async () => {
    // Past the window, the facet (capped at 1 value) lists only S3776, which was not asked.
    const data = sampleSonarData({
      issues: [
        ...Array.from({ length: 25 }, (_, n) => open(n, 'typescript:S1440')),
        ...Array.from({ length: 60 }, (_, n) => open(n, 'typescript:S3776', { path: 'src/z.ts' })),
      ],
    });
    fake = await startFakeSonarQube(data, { window: 20, stickyFacets: true, facetCap: 1 });
    const conn = await connect();
    const r = await fetchOpenIssues(
      conn.client,
      conn,
      'acme:shop',
      ['typescript:S1440', 'typescript:S3504'],
      1000,
      { window: 20, pageSize: 10 },
    );
    expect(r.unreadRules).toEqual(['typescript:S1440', 'typescript:S3504']);
    expect(issueSearches().some((q) => q.query['rules'] === 'typescript:S3776')).toBe(false);
  });

  describe('completeness of a read (ruling S10)', () => {
    /** Runs `change` once, when the `nth` page (not the facet probe) of an issue read is asked. */
    const onPage = (nth: number, change: () => void) => {
      let n = 0;
      fake!.fault = (q) => {
        if (q.path === 'api/issues/search' && q.query['facets'] === undefined && ++n === nth) {
          change();
        }
        return null;
      };
    };
    const close = (key: string) => {
      const issues = fake!.data.issues;
      issues.splice(
        issues.findIndex((i) => i.key === key),
        1,
      );
    };
    const five = () =>
      sampleSonarData({
        issues: Array.from({ length: 5 }, (_, n) => open(n, 'typescript:S1440')),
      });

    it('leaves a rule unread when its total changes between pages of a whole read', async () => {
      fake = await startFakeSonarQube(five());
      const conn = await connect();
      // Before page 2, the first issue is closed: page 2 starts one further on, AYo-…-2 is missed.
      onPage(2, () => close('AYo-typescript:S1440-0'));
      const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000, {
        pageSize: 2,
      });
      expect(r.issues.map((i) => i.key)).not.toContain('AYo-typescript:S1440-2');
      expect(r.issues.length).toBeGreaterThanOrEqual(r.total);
      expect(r.unreadRules).toEqual(['typescript:S1440']);
      expect(conn.client.warnings.map((w) => w.code)).toContain('SONARQUBE_RESULTS_CHANGED');
    });

    it('leaves a rule unread when a shift repeats an issue under an unchanged total', async () => {
      fake = await startFakeSonarQube(five());
      const conn = await connect();
      // Before page 2, an issue opens first in file order and the last one closes.
      onPage(2, () => {
        close('AYo-typescript:S1440-4');
        fake!.data.issues.push(open(0, 'typescript:S1440', { key: 'AYo-new', path: 'src/0.ts' }));
      });
      const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000, {
        pageSize: 2,
      });
      expect(r.total).toBe(r.issues.length + 1);
      expect(r.unreadRules).toEqual(['typescript:S1440']);
      expect(conn.client.warnings.map((w) => w.code)).not.toContain('SONARQUBE_RESULTS_CHANGED');
    });

    it('leaves a rule unread when its slice changes total between pages, past the window', async () => {
      const data = sampleSonarData({
        issues: [
          ...Array.from({ length: 15 }, (_, n) => open(n, 'typescript:S1440')),
          ...Array.from({ length: 10 }, (_, n) =>
            open(n, 'typescript:S3504', { path: 'src/b.ts' }),
          ),
        ],
      });
      fake = await startFakeSonarQube(data, { window: 20 });
      const conn = await connect();
      // The S1440 slice is read first; before its page 2, one of its issues is closed.
      onPage(2, () => close('AYo-typescript:S1440-0'));
      const r = await fetchOpenIssues(
        conn.client,
        conn,
        'acme:shop',
        ['typescript:S1440', 'typescript:S3504'],
        1000,
        { window: 20, pageSize: 10 },
      );
      expect(r.unreadRules).toEqual(['typescript:S1440']);
    });

    it('does not trust the probe facet in a capped read when an issue is added before the pages', async () => {
      // S1440 has 3 issues in src/a.ts at the probe; S3504 2 in src/b.ts. The cap reads 3 in
      // file order. Before page 1 an S1440 issue opens in src/c.ts: the 3 read still equal the
      // probe's count for S1440, but that count is stale (the pages' total is not the probe's).
      const data = sampleSonarData({
        issues: [
          ...Array.from({ length: 3 }, (_, n) => open(n, 'typescript:S1440')),
          ...Array.from({ length: 2 }, (_, n) => open(n, 'typescript:S3504', { path: 'src/b.ts' })),
        ],
      });
      fake = await startFakeSonarQube(data);
      const conn = await connect();
      onPage(1, () =>
        fake!.data.issues.push(open(9, 'typescript:S1440', { key: 'AYo-late', path: 'src/c.ts' })),
      );
      const r = await fetchOpenIssues(
        conn.client,
        conn,
        'acme:shop',
        ['typescript:S1440', 'typescript:S3504'],
        3,
        { pageSize: 10 },
      );
      expect(r.issues.map((i) => i.rule)).toEqual([
        'typescript:S1440',
        'typescript:S1440',
        'typescript:S1440',
      ]);
      expect(r.unreadRules).toEqual(['typescript:S1440', 'typescript:S3504']);
    });

    it('accepts a probe total that differs from a stable read', async () => {
      fake = await startFakeSonarQube(five());
      const conn = await connect();
      // Between the probe and page 1, an issue is closed: the pages agree with each other.
      onPage(1, () => fake!.data.issues.pop());
      const r = await fetchOpenIssues(conn.client, conn, 'acme:shop', ['typescript:S1440'], 1000, {
        pageSize: 2,
      });
      expect(r).toMatchObject({ total: 4, unreadRules: [] });
      expect(r.issues).toHaveLength(4);
    });
  });
});
