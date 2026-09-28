import { sonarLineHash } from '@qualor/shared';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SONAR_READ_ENDPOINTS } from '../src/import/sonarqube/client';
import type { HttpResponse, RequestOptions, ServerEndpoint } from '../src/server/http';
import {
  type FakeSonar,
  type FakeSonarData,
  type FakeSonarOptions,
  sampleSonarData,
  startFakeSonarQube,
} from './fake-sonarqube';
import {
  guardTransport,
  LIVE_READ_ENDPOINTS,
  LiveBudgetExhausted,
  leakedCategories,
  liveEnabled,
  type LiveOptions,
  readLiveEnv,
  runLiveCheck,
  sonarSourceText,
} from './sonar-live';

/**
 * Plan 3A Task 17: the opt-in live check (`cli/test/sonar-live.live.test.ts`, spec §17.1) is
 * only ever run by hand against a real SonarQube. Its logic is checked here against the fake:
 * GET only, a capped budget, the line hash comparison, the sticky facet observation, and an
 * output that holds no name, key, path, code, message or secret of the organisation.
 */

let fake: FakeSonar | undefined;
afterEach(async () => {
  await fake?.close();
  fake = undefined;
});

const LINE_2 = 'if (a < 1 && b) {}';
const LINE_4 = '  const s = \'"x"\';';
const LINE_3 = 'if (a == 2) {}';
/** SonarQube's `code`: HTML with token spans and escaped characters. */
const SOURCE = [
  '<span class="cd">// header</span>',
  '<span class="k">if</span> (a &lt; <span class="c">1</span> &amp;&amp; b) {}',
  '<span class="k">if</span> (a == 2) {}',
  '  <span class="k">const</span> s = <span class="s">&#39;&quot;x&quot;&#39;</span>;',
  '',
  '',
  '',
  '',
  '   \t ',
];
const OTHER_HASH = '0123456789abcdef0123456789abcdef';

/** The sample, with line hashes: a match, a mismatch, a blank line, an unreadable file. */
function liveData(over: Partial<FakeSonarData> = {}): FakeSonarData {
  const base = sampleSonarData(over);
  return {
    ...base,
    issues: [
      ...base.issues.map((i) =>
        i.key === 'AYi-fp-1'
          ? { ...i, hash: sonarLineHash(LINE_2) }
          : i.key === 'AYi-ac-1'
            ? { ...i, hash: OTHER_HASH }
            : i.key === 'AYi-open'
              ? { ...i, hash: sonarLineHash(LINE_4) }
              : i,
      ),
      {
        key: 'AYi-blank',
        rule: 'typescript:S1440',
        project: 'acme:shop',
        path: 'src/a.ts',
        line: 9,
        hash: OTHER_HASH,
        message: 'On a blank line.',
        status: 'FALSE_POSITIVE',
      },
      {
        key: 'AYi-nosrc',
        rule: 'typescript:S1440',
        project: 'acme:shop',
        path: 'src/gone.ts',
        line: 1,
        hash: OTHER_HASH,
        message: 'In a file without source.',
        status: 'FALSE_POSITIVE',
        comments: ['the reviewer said so'],
      },
    ],
    sources: { 'acme:shop:src/a.ts': SOURCE },
  };
}

async function run(
  data: FakeSonarData,
  over: Partial<LiveOptions> = {},
  fakeOptions: FakeSonarOptions = {},
) {
  fake = await startFakeSonarQube(data, fakeOptions);
  return runLiveCheck({
    url: fake.url,
    token: data.token,
    organization: data.kind === 'cloud' ? (data.organization ?? null) : null,
    kind: data.kind,
    maxRequests: 200,
    maxProjects: 3,
    maxHashes: 20,
    maxIssues: 500,
    sleep: () => Promise.resolve(),
    ...over,
  });
}

/** Everything of the organisation the summary must never hold. */
function secretsOf(data: FakeSonarData): string[] {
  return [
    data.token,
    ...data.projects.flatMap((p) => [p.key, p.name]),
    ...data.profiles.flatMap((p) => [p.key, p.name]),
    ...data.gates.map((g) => g.name),
    ...data.issues.flatMap((i) => [
      i.key,
      i.message,
      ...(i.path === null ? [] : [i.path]),
      ...(i.hash === undefined ? [] : [i.hash]),
      ...(i.comments ?? []),
    ]),
    LINE_2,
    LINE_3,
    LINE_4.trim(),
    sonarLineHash(LINE_2),
    sonarLineHash(LINE_3),
    sonarLineHash(LINE_4),
    'header',
  ];
}

describe('the live check is opt-in (import-sonarqube.md §17.1)', () => {
  const env = (over: Record<string, string>) => ({
    QUALOR_LIVE_SONAR_URL: 'https://sonar.example.com',
    QUALOR_LIVE_SONAR_TOKEN: 'squ_x',
    ...over,
  });

  it('is enabled only with both the URL and the token', () => {
    expect(liveEnabled({})).toBe(false);
    expect(liveEnabled(env({ QUALOR_LIVE_SONAR_TOKEN: '' }))).toBe(false);
    expect(liveEnabled(env({ QUALOR_LIVE_SONAR_URL: '' }))).toBe(false);
    expect(liveEnabled(env({}))).toBe(true);
  });

  it('reads small defaults, and overrides within bounds', () => {
    const o = readLiveEnv(env({}));
    expect(o).toMatchObject({
      url: 'https://sonar.example.com',
      organization: null,
      kind: 'auto',
      maxRequests: 200,
      maxProjects: 3,
      maxHashes: 20,
      summaryPath: null,
    });
    const over = readLiveEnv(
      env({
        QUALOR_LIVE_SONAR_MAX_REQUESTS: '50',
        QUALOR_LIVE_SONAR_MAX_PROJECTS: '1',
        QUALOR_LIVE_SONAR_MAX_HASHES: '5',
      }),
    );
    expect(over).toMatchObject({ maxRequests: 50, maxProjects: 1, maxHashes: 5 });
    for (const bad of ['0', '-1', '1.5', 'x', '100000']) {
      expect(() => readLiveEnv(env({ QUALOR_LIVE_SONAR_MAX_REQUESTS: bad }))).toThrow(
        /QUALOR_LIVE_SONAR_MAX_REQUESTS/,
      );
    }
  });

  it('needs the organisation for SonarQube Cloud, and https', () => {
    expect(() => readLiveEnv(env({ QUALOR_LIVE_SONAR_URL: 'https://sonarcloud.io' }))).toThrow(
      /QUALOR_LIVE_SONAR_ORG/,
    );
    expect(
      readLiveEnv(
        env({ QUALOR_LIVE_SONAR_URL: 'https://sonarcloud.io', QUALOR_LIVE_SONAR_ORG: 'o' }),
      ),
    ).toMatchObject({ organization: 'o' });
    expect(() => readLiveEnv(env({ QUALOR_LIVE_SONAR_URL: 'http://sonar.example.com' }))).toThrow(
      /https/,
    );
  });

  it('writes a summary file only outside the repository', () => {
    expect(() => readLiveEnv(env({ QUALOR_LIVE_SONAR_SUMMARY: 'docs/live.json' }))).toThrow(
      /outside the repository/,
    );
  });
});

describe('the live check reads only, within a budget', () => {
  const ep: ServerEndpoint = { url: 'https://sonar.test', token: 't', timeoutMs: 1000 };
  const ok: HttpResponse = {
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{}',
  };

  it('refuses any method but GET, any path off its list and any body, before any I/O', async () => {
    const base = vi.fn(() => Promise.resolve(ok));
    const g = guardTransport(base, 10);
    const get = (o: Partial<RequestOptions>) =>
      g.transport(ep, { method: 'GET', path: 'api/users/current', ...o } as RequestOptions);
    await expect(get({ method: 'POST' })).rejects.toThrow(/refusing POST/);
    await expect(get({ method: 'DELETE' })).rejects.toThrow(/refusing DELETE/);
    await expect(get({ path: 'api/qualityprofiles/delete' })).rejects.toThrow(/read list/);
    await expect(get({ json: {} })).rejects.toThrow(/body/);
    expect(base).not.toHaveBeenCalled();
    await get({});
    await get({ path: 'api/sources/lines' });
    expect(base).toHaveBeenCalledTimes(2);
  });

  it('stops at its request budget', async () => {
    const base = vi.fn(() => Promise.resolve(ok));
    const g = guardTransport(base, 2);
    const get = () => g.transport(ep, { method: 'GET', path: 'api/users/current' });
    await get();
    await get();
    await expect(get()).rejects.toBeInstanceOf(LiveBudgetExhausted);
    expect(base).toHaveBeenCalledTimes(2);
    expect(g.used()).toBe(2);
  });

  it('reads source lines with its own list; the import never gains that endpoint', () => {
    expect(SONAR_READ_ENDPOINTS.has('api/sources/lines')).toBe(false);
    expect([...LIVE_READ_ENDPOINTS].sort()).toEqual(
      [...SONAR_READ_ENDPOINTS, 'api/sources/lines'].sort(),
    );
  });
});

describe('the line text SonarQube shows', () => {
  it('is the source line without its HTML markup', () => {
    expect(sonarSourceText(SOURCE[1]!)).toBe(LINE_2);
    expect(sonarSourceText(SOURCE[3]!)).toBe(LINE_4);
    expect(sonarSourceText('a &amp;lt; b &#x41;&#66;')).toBe('a &lt; b AB');
  });
});

describe('the live check against the fake SonarQube', () => {
  it('reads, maps and compares line hashes, and prints aggregates only', async () => {
    const data = liveData();
    const { summary, text } = await run(data);
    const requests = fake!.requests;
    expect(requests.length).toBeGreaterThan(0);
    for (const r of requests) {
      expect(r.method).toBe('GET');
      expect(LIVE_READ_ENDPOINTS.has(r.path)).toBe(true);
    }
    expect(summary.requests.used).toBe(requests.length);
    expect(summary.requests.budgetExhausted).toBe(false);
    expect(summary.failures).toEqual([]);

    // Ruling S1: fp-1 matches, ac-1 does not, AYi-blank is on a blank line, AYi-nosrc has no
    // source, fp-1's neighbour AYi-um-1 has no hash; the open issue tops up the sample.
    expect(summary.lineHash).toEqual({
      sampled: 5,
      compared: 3,
      match: 2,
      mismatch: 1,
      blankLines: 1,
      unreadable: 1,
      skippedNoHash: 1,
      byLanguage: {
        ts: { match: 1, mismatch: 1 },
        unknown: { match: 1, mismatch: 0 },
      },
    });
    expect(requests.filter((r) => r.path === 'api/sources/lines')).toHaveLength(5);
    for (const r of requests.filter((x) => x.path === 'api/sources/lines')) {
      expect(r.query['from']).toBe(r.query['to']);
    }

    expect(summary.facetHonoursFilter).toBe('yes');
    expect(summary.profiles).toMatchObject({
      total: 4,
      byLanguage: { ts: 2, java: 1, py: 1 },
      skipped: { language_unsupported: 1 },
    });
    expect(summary.profiles.activeRules).toBe(5);
    expect(summary.profiles.distinct.active).toBe(4);
    expect(
      summary.profiles.distinct.mapped +
        summary.profiles.distinct.pendingReview +
        summary.profiles.distinct.statusOnly +
        summary.profiles.distinct.unmapped,
    ).toBe(summary.profiles.distinct.active);
    expect(summary.gates.total).toBe(2);
    expect(summary.projects).toEqual({ total: 1, sampled: 1 });
    expect(summary.issues.resolved).toBe(5);
    expect(summary.issues.issueQuery).toBe('issueStatuses');

    const issues = summary.endpoints['api/issues/search']!;
    expect(issues.schema).toEqual({ accepted: issues.requests, rejected: 0 });
    expect(issues.unknownFields).toContain('issues[].type');
    expect(issues.unknownFields).toContain('components');
    expect(summary.endpoints['api/sources/lines']!.fields).toEqual(['sources']);
    expect(summary.endpoints['api/sources/lines']!.statuses).toEqual({ 200: 4, 404: 1 });
    // The actives map is keyed by rule keys: never reported as field names.
    expect(summary.endpoints['api/rules/search']!.unknownFields.join()).not.toMatch(/S1440/);

    for (const s of secretsOf(data)) expect(text.includes(s), s).toBe(false);
    expect(JSON.parse(text)).toEqual(summary);
  });

  it('observes a sticky facet as not honouring the filter', async () => {
    const { summary } = await run(liveData(), {}, { stickyFacets: true });
    expect(summary.facetHonoursFilter).toBe('no');
  });

  it('scopes SonarQube Cloud by organisation, never asks the version, never prints the key', async () => {
    const data = liveData({ kind: 'cloud', organization: 'acme-live-org' });
    const { summary, text } = await run(data);
    expect(summary.kind).toBe('cloud');
    expect(summary.issues.issueQuery).toBe('resolutions');
    for (const r of fake!.requests) {
      expect(r.path).not.toBe('api/server/version');
      expect(r.authorization).toBe(`Bearer ${data.token}`);
      if (r.path === 'api/sources/lines') expect(r.query['organization']).toBeUndefined();
    }
    expect(text).not.toContain('acme-live-org');
    for (const s of secretsOf(data)) expect(text.includes(s), s).toBe(false);
    // Finding L1: Cloud's resolved issues and its hotspots (by `projectKey`) are both read.
    expect(summary.failures).toEqual([]);
    expect(summary.issues).toMatchObject({
      resolved: 5,
      reviewedHotspots: 2,
      hotspotsNotCounted: 0,
    });
    expect(summary.endpoints['api/hotspots/search']!.statuses).toEqual({ 200: 1 });
  });

  it('keeps the issues of a project whose hotspot count fails (finding L1)', async () => {
    const data = liveData({ kind: 'cloud', organization: 'acme-live-org' });
    fake = await startFakeSonarQube(data);
    fake.fault = (r) => (r.path === 'api/hotspots/search' ? { status: 400, body: '{}' } : null);
    const { summary } = await runLiveCheck({
      url: fake.url,
      token: data.token,
      organization: 'acme-live-org',
      kind: 'cloud',
      maxRequests: 200,
      maxProjects: 3,
      maxHashes: 20,
      maxIssues: 500,
      sleep: () => Promise.resolve(),
    });
    expect(summary.failures).toEqual([]);
    expect(summary.issues).toMatchObject({
      resolved: 5,
      reviewedHotspots: null,
      hotspotsNotCounted: 1,
    });
    expect(summary.warnings).toMatchObject({ HOTSPOTS_NOT_COUNTED: 1 });
    expect(summary.lineHash.sampled).toBe(5);
    expect(summary.endpoints['api/hotspots/search']!.statuses).toEqual({ 400: 1 });
  });

  it('keeps the issues read when the budget runs out at the hotspot count', async () => {
    await run(liveData());
    const at = fake!.requests.findIndex((r) => r.path === 'api/hotspots/search');
    expect(at).toBeGreaterThan(0);
    await fake!.close();
    // The budget ends just before the hotspot request.
    const { summary } = await run(liveData(), { maxRequests: at });
    expect(summary.requests.budgetExhausted).toBe(true);
    expect(summary.failures.map((f) => f.phase)).toEqual(['hotspots']);
    expect(summary.issues).toMatchObject({ resolved: 5, reviewedHotspots: null });
  });

  it('stops when the budget is used up and still reports aggregates', async () => {
    const { summary, text } = await run(liveData(), { maxRequests: 6 });
    expect(fake!.requests.length).toBe(6);
    expect(summary.requests).toEqual({ used: 6, budget: 6, budgetExhausted: true });
    expect(summary.failures.map((f) => f.phase)).toContain('profiles');
    expect(text).not.toContain(fake!.data.token);
  });

  it('samples at most maxHashes issues', async () => {
    const { summary } = await run(liveData(), { maxHashes: 2 });
    expect(summary.lineHash.sampled).toBe(2);
    expect(fake!.requests.filter((r) => r.path === 'api/sources/lines')).toHaveLength(2);
  });

  it('refuses to print a summary that holds a name of the organisation', async () => {
    const data = liveData();
    // A gate whose name is a word the summary prints anyway: the check fails closed.
    data.gates = [{ name: 'mapped', conditions: [{ metric: 'violations', op: 'GT', error: '0' }] }];
    await expect(run(data)).rejects.toThrow(/gate name/);
  });

  it('redacts the organisation and the token from a failure', async () => {
    const data = liveData({ kind: 'cloud', organization: 'acme-live-org' });
    fake = await startFakeSonarQube(data);
    const err = await runLiveCheck({
      url: fake.url,
      token: data.token,
      organization: 'another-live-org',
      kind: 'cloud',
      maxRequests: 20,
      maxProjects: 3,
      maxHashes: 20,
      maxIssues: 500,
    }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    if (!(err instanceof Error)) return;
    expect(err.message).toMatch(/connect/);
    expect(err.cause).toBeUndefined();
    expect(err.message).not.toContain('another-live-org');
    expect(err.message).not.toContain(data.token);
  });

  it('names leaked categories, never the leaked value', () => {
    const sensitive = new Map([
      ['Team TS', 'profile name'],
      ['ab', 'project key'],
    ]);
    expect(leakedCategories('{"x":"Team TS"}', sensitive)).toEqual(['profile name']);
    // Values under 3 characters cannot be told from ordinary words and are not checked.
    expect(leakedCategories('{"ab":1}', sensitive)).toEqual([]);
  });
});
