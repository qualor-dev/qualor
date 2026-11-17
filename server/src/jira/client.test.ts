import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createFakeJira,
  defaultIssueTypes,
  jiraShape,
  type FakeJira,
  type FakeJiraField,
  type FakeJiraIssueType,
  type JiraInjectedAnswer,
} from '../../test/fake-jira';
import { trustTestCa } from '../../test/tls';
import type { JiraDeployment } from '../db/schema';
import { VERSION } from '../index';
import {
  JIRA_SHAPES,
  JiraClient,
  JiraError,
  mapBulkAnswer,
  type JiraClientOptions,
  type JiraErrorCode,
} from './client';

const SHAPES_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../test/jira-shapes',
);
const MiB = 1024 * 1024;
const QUAL = { id: '10000', key: 'QUAL', name: 'Qualor findings' };

async function failure(promise: Promise<unknown>): Promise<JiraError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof JiraError) return err;
    throw err;
  }
  throw new Error('expected a JiraError');
}

/** Fields of a Bug in QUAL that the fake creates. */
const bug = (summary: string, more: Record<string, unknown> = {}): Record<string, unknown> => ({
  project: { id: QUAL.id },
  issuetype: { id: '10001' },
  summary,
  ...more,
});

const fakes: FakeJira[] = [];
let untrust: () => void = () => undefined;

beforeAll(() => {
  untrust = trustTestCa();
});
afterAll(() => untrust());
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(fakes.splice(0).map((f) => f.close()));
});

/** A fake of the deployment with QUAL in it (Cloud over https, as Atlassian's sites are). */
async function fakeJira(
  deployment: JiraDeployment,
  options: Partial<Parameters<typeof createFakeJira>[0]> = {},
): Promise<FakeJira> {
  const fake = await createFakeJira({ deployment, https: deployment === 'cloud', ...options });
  fakes.push(fake);
  fake.addProject(QUAL);
  return fake;
}

/** A client of the fake, as `jiraClientFor` builds one (the fake's host is internal). */
function clientOf(fake: FakeJira, options: JiraClientOptions = {}, apiBase = fake.url): JiraClient {
  return new JiraClient(
    {
      deployment: fake.deployment,
      apiBase,
      auth:
        fake.deployment === 'cloud'
          ? { kind: 'basic', email: fake.email, token: fake.token }
          : { kind: 'bearer', token: fake.token },
      allowInternalHosts: true,
    },
    options,
  );
}

describe('the recorded shapes (server/test/jira-shapes/)', () => {
  it('parses every recorded shape with the schema the client uses', () => {
    const files = readdirSync(SHAPES_DIR).filter((f) => f.endsWith('.json'));
    const schemaOf: Record<string, keyof typeof JIRA_SHAPES | null> = {
      'myself.cloud.json': 'myself',
      'myself.dc.json': 'myself',
      'project-search.cloud.json': 'projectPage',
      'project.dc.json': 'projects',
      'createmeta-issuetypes.cloud.json': 'createmetaPage',
      'createmeta-issuetypes.dc.json': 'createmetaPage',
      'createmeta-fields.cloud.json': 'createmetaPage',
      'createmeta-fields.dc.json': 'createmetaPage',
      'issue-created.json': 'createdIssue',
      'bulk-partial.json': 'bulkAnswer',
      'search-jql.cloud.json': 'cloudSearchPage',
      'search.dc.json': 'dcSearchPage',
      'comment.json': 'comment',
      'error.json': 'errorBody',
    };
    expect(files.sort()).toEqual(Object.keys(schemaOf).sort());
    for (const file of files) {
      const schema = schemaOf[file];
      if (!schema) continue;
      const parsed = JIRA_SHAPES[schema].safeParse(jiraShape(file.slice(0, -5)));
      expect(parsed.success, file).toBe(true);
    }
    expect(mapBulkAnswer(3, jiraShape('bulk-partial'))).toMatchObject([
      { created: { key: expect.any(String) } },
      { failed: { code: 'field_refused', jiraText: expect.any(String) } },
      { created: { key: expect.any(String) } },
    ]);
  });
});

describe('Jira client (spec §6.7) against the fake Jira', () => {
  it('auth: Bearer on Data Center, Basic sent up front on Cloud, and the user agent on both', async () => {
    const dc = await fakeJira('data_center');
    expect(await clientOf(dc).myself()).toEqual({ displayName: expect.any(String) });
    expect(dc.requests).toHaveLength(1);
    expect(dc.requests[0]?.headers.authorization).toBe(`Bearer ${dc.token}`);
    expect(dc.requests[0]?.headers['user-agent']).toBe(`Qualor/${VERSION}`);

    const cloud = await fakeJira('cloud');
    expect(cloud.url).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
    expect(await clientOf(cloud).myself()).toEqual({ displayName: expect.any(String) });
    expect(cloud.requests).toHaveLength(1);
    const basic = Buffer.from(`${cloud.email}:${cloud.token}`).toString('base64');
    expect(cloud.requests[0]?.headers.authorization).toBe(`Basic ${basic}`);
    expect(cloud.requests[0]?.headers['user-agent']).toBe(`Qualor/${VERSION}`);

    // Each fake checks its own deployment's header.
    const wrong = new JiraClient({
      deployment: 'data_center',
      apiBase: dc.url,
      auth: { kind: 'basic', email: 'qualor@example.com', token: dc.token },
      allowInternalHosts: true,
    });
    expect(await failure(wrong.myself())).toMatchObject({ code: 'token_refused', status: 401 });
  });

  it('context path (Review Focus 1): every call goes under the context path', async () => {
    const fake = await fakeJira('data_center', { contextPath: '/jira' });
    const client = clientOf(fake, {}, `${fake.url}/jira`);
    await client.myself();
    await client.projectsVisible();
    await client.searchProjects('qual');
    await client.issueTypes('QUAL');
    await client.issueTypeFields('QUAL', '10001');
    const one = await client.createIssue(bug('one'));
    await client.createIssues([bug('two'), bug('three')]);
    await client.searchByIds([one.id]);
    await client.searchByLabels(['qualor']);
    await client.addComment(one.id, 'A comment.');
    expect(fake.requests).toHaveLength(client.requests);
    expect(fake.requests.length).toBe(10);
    for (const r of fake.requests) expect(r.path).toMatch(/^\/jira\/rest\/api\/2\//);
    // Without the context path the fake knows no such page.
    expect((await failure(clientOf(fake).myself())).code).toBe('not_found');
  });

  describe('errors', () => {
    const DENIED = { 'x-seraph-loginreason': 'AUTHENTICATION_DENIED' };
    it.each<[string, JiraErrorCode, JiraInjectedAnswer]>([
      [
        'a redirect',
        'redirected',
        { status: 302, headers: { location: 'https://sso.corp.example/' } },
      ],
      ['a 401 with the CAPTCHA header', 'captcha', { status: 401, headers: DENIED }],
      ['a 403 with the CAPTCHA header', 'captcha', { status: 403, headers: DENIED }],
      ['a 401', 'token_refused', { status: 401 }],
      ['a 403', 'permission_missing', { status: 403 }],
      ['a 404', 'not_found', { status: 404 }],
      ['a 413', 'limit_reached', { status: 413 }],
      ['a 422', 'limit_reached', { status: 422 }],
      ['a 500', 'server_error', { status: 500 }],
      ['a 503', 'server_error', { status: 503 }],
      ['a 409', 'http_error', { status: 409 }],
    ])('%s is %s, after one request', async (_what, code, answer) => {
      const fake = await fakeJira('data_center');
      fake.inject('GET', /\/myself$/, answer);
      const err = await failure(clientOf(fake).myself());
      expect(err).toMatchObject({ code, message: code, status: answer.status, jiraText: null });
      expect(err.name).toBe('JiraError');
      expect(fake.requests).toHaveLength(1);
    });

    it('a hang is timeout, a reset unreachable', async () => {
      const fake = await fakeJira('data_center');
      fake.inject('GET', /\/myself$/, { hang: true }, { reset: true });
      const client = clientOf(fake, { timeoutMs: 300 });
      expect(await failure(client.myself())).toMatchObject({ code: 'timeout', status: null });
      expect(await failure(client.myself())).toMatchObject({ code: 'unreachable', status: null });
    });

    it('a host that resolves nowhere is unresolved; a non-public or metadata address not_public', async () => {
      const fake = await fakeJira('data_center');
      const nowhere = new JiraClient(
        {
          deployment: 'data_center',
          apiBase: 'https://jira.corp.example',
          auth: { kind: 'bearer', token: fake.token },
          allowInternalHosts: false,
        },
        { resolve: () => Promise.reject(new Error('ENOTFOUND')) },
      );
      expect((await failure(nowhere.myself())).code).toBe('unresolved');
      const unlisted = new JiraClient({
        deployment: 'data_center',
        apiBase: fake.url,
        auth: { kind: 'bearer', token: fake.token },
        allowInternalHosts: false,
      });
      expect((await failure(unlisted.myself())).code).toBe('not_public');
      const metadata = new JiraClient(
        {
          deployment: 'data_center',
          apiBase: 'https://jira.corp.example',
          auth: { kind: 'bearer', token: fake.token },
          allowInternalHosts: true,
        },
        { resolve: () => Promise.resolve([{ address: '169.254.169.254', family: 4 }]) },
      );
      expect((await failure(metadata.myself())).code).toBe('not_public');
      expect(fake.requests).toHaveLength(0);
    });

    it('429 carries Retry-After clamped to 1 s – 15 min, in seconds or as an HTTP date', async () => {
      const now = Date.UTC(2026, 10, 17, 9, 0, 0);
      vi.useFakeTimers({ toFake: ['Date'], now });
      const fake = await fakeJira('data_center');
      fake.inject(
        'GET',
        /\/myself$/,
        { status: 429, headers: { 'retry-after': '0' } },
        { status: 429, headers: { 'retry-after': '3600' } },
        { status: 429, headers: { 'retry-after': new Date(now + 30_000).toUTCString() } },
        { status: 429 },
      );
      const client = clientOf(fake);
      for (const seconds of [1, 900, 30, null]) {
        expect(await failure(client.myself())).toMatchObject({
          code: 'rate_limited',
          status: 429,
          retryAfterSeconds: seconds,
        });
      }
    });
  });

  it('HTML is bad_answer (Review Focus 2): a sign-in page answered with 200', async () => {
    const fake = await fakeJira('data_center');
    fake.inject(
      'GET',
      /\/myself$/,
      {
        status: 200,
        headers: { 'content-type': 'text/html;charset=UTF-8' },
        body: '<!DOCTYPE html><html><body><form action="/login.jsp">Log in</form></body></html>',
      },
      { status: 200, body: { name: 'qualor' } },
      { status: 200 },
    );
    const client = clientOf(fake);
    expect(await failure(client.myself())).toMatchObject({ code: 'bad_answer', status: 200 });
    // JSON of another shape, and no body at all, are not understood either.
    expect((await failure(client.myself())).code).toBe('bad_answer');
    expect((await failure(client.myself())).code).toBe('bad_answer');
  });

  it('caps: 8 MiB per answer, 32 MiB for the Data Center project list', async () => {
    const fake = await fakeJira('data_center');
    const client = clientOf(fake);
    fake.inject('GET', /\/myself$/, { status: 200, body: { displayName: 'x'.repeat(9 * MiB) } });
    expect((await failure(client.myself())).code).toBe('bad_answer');
    /** A project list of about `mib` MiB. */
    const projects = (mib: number) =>
      Array.from({ length: mib * 16 }, (_, i) => ({
        id: String(20_000 + i),
        key: `P${i}`,
        name: `Project ${i}`,
        description: 'd'.repeat(64 * 1024),
      }));
    fake.inject(
      'GET',
      /\/rest\/api\/2\/project$/,
      { status: 200, body: projects(20) },
      { status: 200, body: projects(33) },
    );
    expect(await client.projectsVisible()).toBe(20 * 16);
    expect((await failure(client.projectsVisible())).code).toBe('bad_answer');
  });

  it('T3a: the Data Center project list has its own deadline, which a short timeoutMs does not cut', async () => {
    const fake = await fakeJira('data_center');
    const slow: JiraInjectedAnswer = {
      passThrough: true,
      before: () => new Promise((resolve) => setTimeout(resolve, 600)),
    };
    fake.inject('GET', /\/rest\/api\/2\/project$/, slow, { hang: true });
    fake.inject('GET', /\/myself$/, slow);
    const client = clientOf(fake, { timeoutMs: 300, projectListTimeoutMs: 1_000 });
    expect(await client.projectsVisible()).toBe(1);
    expect((await failure(client.projectsVisible())).code).toBe('timeout');
    expect((await failure(client.myself())).code).toBe('timeout');
  });

  describe('createmeta', () => {
    /** `n` fields: the Bug's own, then optional custom fields. */
    const fields = (n: number): FakeJiraField[] => {
      const own = defaultIssueTypes()[0]!.fields;
      return [
        ...own,
        ...Array.from({ length: n - own.length }, (_, i) => ({
          fieldId: `customfield_${11_000 + i}`,
          name: `Custom ${i}`,
          required: false,
        })),
      ];
    };

    it.each<JiraDeployment>(['cloud', 'data_center'])(
      '%s: follows the pages, leaves sub-tasks out, and reads every field',
      async (deployment) => {
        const fake = await fakeJira(deployment);
        const types: FakeJiraIssueType[] = [
          ...Array.from({ length: 110 }, (_, i) => ({
            id: String(10_100 + i),
            name: `Type ${i}`,
            fields: i === 0 ? fields(120) : fields(7),
          })),
          { id: '10003', name: 'Sub-task', subtask: true, fields: fields(7) },
        ];
        fake.addProject({ id: '10010', key: 'BIG', name: 'Big', issueTypes: types });
        const client = clientOf(fake);

        const issueTypes = await client.issueTypes('BIG');
        expect(issueTypes).toHaveLength(110);
        expect(issueTypes[0]).toEqual({ id: '10100', name: 'Type 0', subtask: false });
        expect(issueTypes.some((t) => t.name === 'Sub-task')).toBe(false);
        const typePages = fake.requests.map((r) => r.query);
        expect(typePages).toEqual([
          'startAt=0&maxResults=50',
          'startAt=50&maxResults=50',
          'startAt=100&maxResults=50',
        ]);

        fake.clearRequests();
        const read = await client.issueTypeFields('BIG', '10100');
        expect(read).toHaveLength(120);
        expect(fake.requests).toHaveLength(3);
        expect(fake.requests[0]?.path).toBe('/rest/api/2/issue/createmeta/BIG/issuetypes/10100');
        expect(read.find((f) => f.fieldId === 'reporter')).toEqual({
          fieldId: 'reporter',
          name: 'Reporter',
          required: true,
          hasDefaultValue: true,
          allowedValues: [],
        });
        expect(read.find((f) => f.fieldId === 'priority')?.allowedValues).toEqual([
          { id: '1', name: 'Highest' },
          { id: '2', name: 'High' },
          { id: '3', name: 'Medium' },
          { id: '4', name: 'Low' },
          { id: '5', name: 'Lowest' },
        ]);
        expect(read.find((f) => f.fieldId === 'customfield_11000')).toMatchObject({
          required: false,
          hasDefaultValue: false,
        });
      },
    );

    it('reads the first 1 000 fields of a type that has 1 200', async () => {
      const fake = await fakeJira('data_center');
      fake.addProject({
        id: '10011',
        key: 'HUGE',
        name: 'Huge',
        issueTypes: [{ id: '10001', name: 'Bug', fields: fields(1_200) }],
      });
      const client = clientOf(fake);
      const read = await client.issueTypeFields('HUGE', '10001');
      expect(read).toHaveLength(1_000);
      expect(read.at(-1)?.fieldId).toBe(`customfield_${11_000 + 1_000 - 8}`);
      expect(fake.requests).toHaveLength(20);
    });

    it('reads the Story of the default types with its required Components', async () => {
      const fake = await fakeJira('cloud');
      const story = await clientOf(fake).issueTypeFields('QUAL', '10002');
      expect(story.find((f) => f.fieldId === 'customfield_10010')).toEqual({
        fieldId: 'customfield_10010',
        name: 'Components',
        required: true,
        hasDefaultValue: false,
        allowedValues: [],
      });
    });
  });

  describe('picker', () => {
    /** 55 projects that match "pay" by key or name, in either case, and 5 that do not. */
    const addProjects = (fake: FakeJira) => {
      for (let i = 0; i < 60; i++) {
        const matching = i < 55;
        fake.addProject({
          id: String(30_000 + i),
          key: matching && i % 2 === 0 ? `PAY${i}` : `P${i}`,
          name: matching && i % 2 === 1 ? `Payments ${i}` : `Other ${i}`,
        });
      }
    };

    it('Data Center: filters the project list by key or name, at most 50', async () => {
      const fake = await fakeJira('data_center');
      addProjects(fake);
      const found = await clientOf(fake).searchProjects('pAy');
      expect(found).toHaveLength(50);
      for (const p of found) expect(`${p.key} ${p.name}`.toLowerCase()).toContain('pay');
      expect(found[0]).toEqual({ id: '30000', key: 'PAY0', name: 'Other 0' });
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'GET /rest/api/2/project',
      ]);
    });

    it('Cloud: sends the query and maxResults=50 to project/search', async () => {
      const fake = await fakeJira('cloud');
      addProjects(fake);
      const found = await clientOf(fake).searchProjects('pay');
      expect(found).toHaveLength(50);
      for (const p of found) expect(`${p.key} ${p.name}`.toLowerCase()).toContain('pay');
      expect(fake.requests).toHaveLength(1);
      expect(fake.requests[0]?.path).toBe('/rest/api/2/project/search');
      const query = new URLSearchParams(fake.requests[0]?.query);
      expect(query.get('query')).toBe('pay');
      expect(query.get('maxResults')).toBe('50');
    });

    it('counts the visible projects: Cloud from total, Data Center from the list', async () => {
      const cloud = await fakeJira('cloud');
      addProjects(cloud);
      expect(await clientOf(cloud).projectsVisible()).toBe(61);
      expect(new URLSearchParams(cloud.requests[0]?.query).get('maxResults')).toBe('1');
      const dc = await fakeJira('data_center');
      expect(await clientOf(dc).projectsVisible()).toBe(1);
    });
  });

  describe('creating (spec §6.4, §11.3)', () => {
    it('creates one issue through POST /issue', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      expect(await client.createIssue(bug('First', { labels: ['qualor'] }))).toEqual({
        id: '10001',
        key: 'QUAL-1',
      });
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual(['POST /rest/api/2/issue']);
      expect(JSON.parse(fake.requests[0]!.body)).toEqual({
        fields: bug('First', { labels: ['qualor'] }),
      });
      expect(fake.issue('QUAL-1')).toMatchObject({
        id: '10001',
        status: { name: 'To Do', category: 'new' },
        fields: { summary: 'First', labels: ['qualor'] },
      });
    });

    it('bulk mapping: elements 2 and 5 of 7 refused, each success on its own element', async () => {
      const fake = await fakeJira('data_center');
      fake.rejectElements([2, 5], {
        customfield_10010: 'Components is required.',
        labels: 'The label must not\ncontain spaces.',
      });
      const outcomes = await clientOf(fake).createIssues(
        Array.from({ length: 7 }, (_, i) => bug(`finding ${i}`)),
      );
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'POST /rest/api/2/issue/bulk',
      ]);
      expect(outcomes).toHaveLength(7);
      const keys = [0, 1, 3, 4, 6].map((i) => {
        const outcome = outcomes[i]!;
        if (!('created' in outcome)) throw new Error(`element ${i} failed`);
        expect(fake.issue(outcome.created.key)?.fields['summary']).toBe(`finding ${i}`);
        return outcome.created.key;
      });
      expect(keys).toEqual(['QUAL-1', 'QUAL-2', 'QUAL-3', 'QUAL-4', 'QUAL-5']);
      for (const i of [2, 5]) {
        expect(outcomes[i]).toEqual({ failed: expect.any(JiraError) });
        expect(outcomes[i]).toMatchObject({
          failed: {
            code: 'field_refused',
            status: 400,
            jiraText: 'Components is required.; The label must not contain spaces.',
          },
        });
      }
      expect(fake.issues()).toHaveLength(5);
    });

    it('mapBulkAnswer: null when the counts do not add up or an element is not one of those sent', () => {
      const created = (n: number) =>
        Array.from({ length: n }, (_, i) => ({ id: String(10_001 + i), key: `QUAL-${i + 1}` }));
      const refused = (i: number) => ({
        status: 400,
        elementErrors: { errorMessages: [], errors: { summary: 'Summary is required.' } },
        failedElementNumber: i,
      });
      expect(mapBulkAnswer(7, { issues: created(4), errors: [refused(2), refused(5)] })).toBeNull();
      expect(mapBulkAnswer(3, { issues: created(2), errors: [refused(3)] })).toBeNull();
      expect(mapBulkAnswer(3, { issues: created(1), errors: [refused(1), refused(1)] })).toBeNull();
      expect(mapBulkAnswer(2, '<html></html>')).toBeNull();
      expect(mapBulkAnswer(2, { issues: created(1), errors: [refused(0)] })).toEqual([
        {
          failed: expect.objectContaining({
            code: 'field_refused',
            jiraText: 'Summary is required.',
          }),
        },
        { created: { id: '10001', key: 'QUAL-1' } },
      ]);
      const forbidden = mapBulkAnswer(1, { issues: [], errors: [{ ...refused(0), status: 403 }] });
      expect(forbidden?.[0]).toMatchObject({
        failed: { code: 'permission_missing', status: 403, jiraText: null },
      });
    });

    it('mapBulkAnswer (T6b): an element with a bad id or key, or an error that refuses nothing, is a bad answer of its own', () => {
      const refusedWith = (status: number, i: number) => ({
        status,
        elementErrors: { errorMessages: ['x'], errors: {} },
        failedElementNumber: i,
      });
      const outcome = mapBulkAnswer(7, {
        issues: [
          { id: 'x', key: 'QUAL-1' },
          { id: '10002', key: 'not a key' },
          { id: '10003', key: `Q-${'1'.repeat(260)}` },
          { id: '10004', key: 'QUAL-4' },
        ],
        errors: [refusedWith(401, 1), refusedWith(429, 3), refusedWith(500, 5)],
      });
      expect(outcome).toMatchObject([
        { failed: { code: 'bad_answer', jiraText: null } },
        { failed: { code: 'bad_answer', status: 401, jiraText: null } },
        { failed: { code: 'bad_answer' } },
        { failed: { code: 'bad_answer', status: 429 } },
        { failed: { code: 'bad_answer' } },
        { failed: { code: 'bad_answer', status: 500 } },
        { created: { id: '10004', key: 'QUAL-4' } },
      ]);
    });

    it('a single create answered with a key that is not a Jira key is a bad answer (T6b)', async () => {
      const fake = await fakeJira('data_center');
      fake.inject('POST', /\/issue$/, { status: 201, body: { id: '10001', key: 'QUAL 1' } });
      const client = clientOf(fake);
      expect((await failure(client.createIssue(bug('a')))).code).toBe('bad_answer');
      fake.inject('POST', /\/issue$/, { status: 201, body: { id: '10001', key: 'QUAL 1' } });
      expect((await failure(client.createIssues([bug('a')]))).code).toBe('bad_answer');
    });

    it('a bulk answered 403 as a whole fails every element with permission_missing (P6)', async () => {
      const fake = await fakeJira('data_center');
      fake.inject('POST', /\/issue\/bulk$/, { status: 403 });
      const outcomes = await clientOf(fake).createIssues([bug('a'), bug('b'), bug('c')]);
      expect(outcomes).toHaveLength(3);
      for (const outcome of outcomes) {
        expect(outcome).toMatchObject({ failed: { code: 'permission_missing', status: 403 } });
      }
      expect(fake.issues()).toHaveLength(0);
    });

    it('a bulk whose every element Jira refuses is its 400 with the elements mapped', async () => {
      const fake = await fakeJira('data_center');
      const outcomes = await clientOf(fake).createIssues([
        bug('a', { environment: 'prod' }),
        { ...bug('b'), summary: undefined },
      ]);
      expect(outcomes).toMatchObject([
        {
          failed: {
            code: 'field_refused',
            jiraText:
              "Field 'environment' cannot be set. It is not on the appropriate screen, or unknown.",
          },
        },
        { failed: { code: 'field_refused', jiraText: 'Summary is required.' } },
      ]);
    });

    it('throws what concerns the whole call, and an answer that does not add up (R17)', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      fake.inject(
        'POST',
        /\/issue\/bulk$/,
        { status: 401 },
        { status: 201, body: { issues: [{ id: '10001', key: 'QUAL-1' }], errors: [] } },
        { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Log in</html>' },
      );
      expect((await failure(client.createIssues([bug('a'), bug('b')]))).code).toBe('token_refused');
      expect((await failure(client.createIssues([bug('a'), bug('b')]))).code).toBe('bad_answer');
      expect((await failure(client.createIssues([bug('a'), bug('b')]))).code).toBe('bad_answer');
    });

    it('sends a single element through POST /issue, and refuses more than 50', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      expect(await client.createIssues([bug('only')])).toEqual([
        { created: { id: '10001', key: 'QUAL-1' } },
      ]);
      fake.inject('POST', /\/issue$/, { status: 404 });
      expect(await client.createIssues([bug('gone')])).toMatchObject([
        { failed: { code: 'not_found', status: 404 } },
      ]);
      expect(await client.createIssues([])).toEqual([]);
      await expect(
        client.createIssues(Array.from({ length: 51 }, (_, i) => bug(`${i}`))),
      ).rejects.toThrow(RangeError);
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'POST /rest/api/2/issue',
        'POST /rest/api/2/issue',
      ]);
    });

    it('the fake refuses like Jira: fields off the screen, required fields, a bulk over 50', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      const story = await failure(
        client.createIssue({ ...bug('story'), issuetype: { id: '10002' } }),
      );
      expect(story).toMatchObject({ code: 'field_refused', jiraText: 'Components is required.' });
      const off = await failure(client.createIssue(bug('x', { customfield_99999: 'y' })));
      expect(off.jiraText).toBe(
        "Field 'customfield_99999' cannot be set. It is not on the appropriate screen, or unknown.",
      );
      const tooMany = await fetch(`${fake.url}/rest/api/2/issue/bulk`, {
        method: 'POST',
        headers: { authorization: `Bearer ${fake.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          issueUpdates: Array.from({ length: 51 }, () => ({ fields: bug('x') })),
        }),
      });
      expect(tooMany.status).toBe(400);
      expect(fake.issues()).toHaveLength(0);
    });

    it('adds a comment by issue id', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      const { id } = await client.createIssue(bug('commented'));
      await client.addComment(id, 'Qualor no longer finds this issue on main.');
      expect(fake.issue('QUAL-1')?.comments).toEqual([
        'Qualor no longer finds this issue on main.',
      ]);
      fake.deleteIssue('QUAL-1');
      expect((await failure(client.addComment(id, 'again'))).code).toBe('not_found');
    });

    it('a comment answered with a 200 sign-in page is a bad answer, not posted (M2)', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      const { id } = await client.createIssue(bug('commented'));
      fake.inject(
        'POST',
        /\/comment$/,
        {
          status: 200,
          headers: { 'content-type': 'text/html;charset=UTF-8' },
          body: '<html><body><form action="/login.jsp">Log in</form></body></html>',
        },
        { status: 201, body: { self: 'https://jira.corp.example/rest/api/2/issue/1/comment' } },
      );
      expect(await failure(client.addComment(id, 'fixed'))).toMatchObject({
        code: 'bad_answer',
        status: 200,
      });
      // JSON without the comment's id is not understood either.
      expect((await failure(client.addComment(id, 'fixed'))).code).toBe('bad_answer');
    });

    it('a lost answer (spec §11.2): the fake makes the issue, then hangs or resets', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake, { timeoutMs: 300 });
      const seen: number[] = [];
      fake.inject(
        'POST',
        /\/issue\/bulk$/,
        { afterCreate: 'hang' },
        { afterCreate: 'reset' },
        {
          passThrough: true,
          before: () => {
            seen.push(fake.issues().length);
            return Promise.resolve();
          },
        },
      );
      expect((await failure(client.createIssues([bug('a'), bug('b')]))).code).toBe('timeout');
      expect((await failure(client.createIssues([bug('c'), bug('d')]))).code).toBe('unreachable');
      expect(fake.issues().map((i) => i.key)).toEqual(['QUAL-1', 'QUAL-2', 'QUAL-3', 'QUAL-4']);
      expect(await client.createIssues([bug('e'), bug('f')])).toEqual([
        { created: { id: '10005', key: 'QUAL-5' } },
        { created: { id: '10006', key: 'QUAL-6' } },
      ]);
      expect(seen).toEqual([4]);
      expect(fake.requests).toHaveLength(3);
    });
  });

  describe('search (spec §6.5 steps 1 and 4)', () => {
    /** 100 Bugs, ids 10001–10100 and keys QUAL-1…QUAL-100, in two bulk calls. */
    async function hundred(client: JiraClient): Promise<string[]> {
      const ids: string[] = [];
      for (let call = 0; call < 2; call++) {
        const outcomes = await client.createIssues(
          Array.from({ length: 50 }, (_, i) => bug(`#${call * 50 + i}`)),
        );
        for (const o of outcomes) if ('created' in o) ids.push(o.created.id);
      }
      expect(ids).toHaveLength(100);
      return ids;
    }

    it('Cloud: a batch with deleted ids is halved until each is found or missing', async () => {
      const fake = await fakeJira('cloud');
      const client = clientOf(fake);
      const ids = await hundred(client);
      fake.deleteIssue('QUAL-37');
      fake.deleteIssue('QUAL-81');
      fake.clearRequests();
      const before = client.requests;
      const { found, missing } = await client.searchByIds(ids);
      expect(found.size).toBe(98);
      expect(missing).toEqual(['10037', '10081']);
      expect(found.get('10001')).toEqual({
        id: '10001',
        key: 'QUAL-1',
        statusName: 'To Do',
        statusCategory: 'new',
      });
      expect(client.requests - before).toBe(fake.requests.length);
      expect(fake.requests.length).toBeGreaterThan(3);
      for (const r of fake.requests) {
        expect(`${r.method} ${r.path}`).toBe('POST /rest/api/2/search/jql');
        expect(JSON.parse(r.body)).toMatchObject({
          jql: expect.stringMatching(/^id in \(\d+(,\d+)*\)$/),
          fields: ['status', 'labels'],
          maxResults: 100,
        });
      }
    });

    it('Data Center: one request with validateQuery warn finds the rest', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      const ids = await hundred(client);
      fake.deleteIssue('QUAL-37');
      fake.deleteIssue('QUAL-81');
      fake.setStatus('QUAL-2', 'In Progress', 'indeterminate');
      fake.clearRequests();
      const { found, missing } = await client.searchByIds(ids);
      expect(found.size).toBe(98);
      expect(missing).toEqual(['10037', '10081']);
      expect(found.get('10002')).toMatchObject({
        statusName: 'In Progress',
        statusCategory: 'indeterminate',
      });
      expect(fake.requests).toHaveLength(1);
      expect(`${fake.requests[0]?.method} ${fake.requests[0]?.path}`).toBe(
        'POST /rest/api/2/search',
      );
      expect(JSON.parse(fake.requests[0]!.body)).toMatchObject({
        fields: ['status', 'labels'],
        startAt: 0,
        maxResults: 100,
        validateQuery: 'warn',
      });
    });

    it('Cloud: follows nextPageToken (pages of 40: three requests)', async () => {
      const fake = await fakeJira('cloud', { searchPageSize: 40 });
      const client = clientOf(fake);
      const ids = await hundred(client);
      fake.clearRequests();
      const { found, missing } = await client.searchByIds(ids);
      expect(found.size).toBe(100);
      expect(missing).toEqual([]);
      expect(fake.requests).toHaveLength(3);
      const tokens = fake.requests.map(
        (r) => (JSON.parse(r.body) as { nextPageToken?: string }).nextPageToken,
      );
      expect(tokens[0]).toBeUndefined();
      expect(tokens[1]).toEqual(expect.any(String));
      expect(tokens[2]).toEqual(expect.any(String));
    });

    it('a moved issue is found by its id with its new key; a single id answering 404 is missing', async () => {
      const fake = await fakeJira('cloud');
      const client = clientOf(fake);
      const { id } = await client.createIssue(bug('moved'));
      fake.moveIssue('QUAL-1', 'SEC-7');
      expect((await client.searchByIds([id])).found.get(id)?.key).toBe('SEC-7');
      fake.inject('POST', /\/search\/jql$/, { status: 404 });
      expect(await client.searchByIds([id])).toEqual({ found: new Map(), missing: [id] });
    });

    it('Cloud: a CAPTCHA lockout answered with 400 is thrown, not halved', async () => {
      const fake = await fakeJira('cloud');
      fake.inject('POST', /\/search\/jql$/, {
        status: 400,
        headers: { 'X-Seraph-LoginReason': 'AUTHENTICATION_DENIED' },
      });
      const err = await failure(clientOf(fake).searchByIds(['10001', '10002']));
      expect(err).toMatchObject({ code: 'captcha' });
      expect(fake.requests).toHaveLength(1);
    });

    it('a searched issue whose id is not a Jira issue id is a bad answer', async () => {
      const fake = await fakeJira('data_center');
      const issue = jiraShape<{ issues: Record<string, unknown>[] }>('search.dc').issues[0]!;
      fake.inject('POST', /\/search$/, {
        body: {
          ...jiraShape<Record<string, unknown>>('search.dc'),
          total: 1,
          issues: [{ ...issue, id: '10001 OR 1=1' }],
        },
      });
      const err = await failure(clientOf(fake).searchByIds(['10001']));
      expect(err).toMatchObject({ code: 'bad_answer' });
    });

    it('Data Center (M3): a batch answering 400 is halved too; a lone id answering 400 is missing', async () => {
      const fake = await fakeJira('data_center');
      const client = clientOf(fake);
      const ids: string[] = [];
      for (const s of ['a', 'b', 'c']) ids.push((await client.createIssue(bug(s))).id);
      fake.clearRequests();
      // validateQuery "warn" did not help: the batch of three and its first half answer 400.
      fake.inject('POST', /\/search$/, { status: 400 }, { status: 400 });
      const { found, missing } = await client.searchByIds(ids);
      expect([...found.keys()].sort()).toEqual([...ids].sort());
      expect(missing).toEqual([]);
      expect(
        fake.requests.map((r) => (JSON.parse(r.body) as { jql: string }).jql.replace(/\d+/g, 'n')),
      ).toEqual(['id in (n,n,n)', 'id in (n,n)', 'id in (n)', 'id in (n)', 'id in (n)']);
      fake.inject('POST', /\/search$/, { status: 400 });
      expect(await client.searchByIds([ids[0]!])).toEqual({ found: new Map(), missing: [ids[0]] });
    });

    it('issues inside the search lag are not found yet', async () => {
      let now = Date.now();
      const fake = await fakeJira('data_center', { now: () => now });
      const client = clientOf(fake);
      const old = await client.createIssue(bug('old', { labels: ['qualor-old'] }));
      fake.searchLag(60_000);
      now += 120_000;
      const fresh = await client.createIssue(bug('fresh', { labels: ['qualor-fresh'] }));
      const { found, missing } = await client.searchByIds([old.id, fresh.id]);
      expect([...found.keys()]).toEqual([old.id]);
      expect(missing).toEqual([fresh.id]);
      expect([...(await client.searchByLabels(['qualor-old', 'qualor-fresh'])).keys()]).toEqual([
        'qualor-old',
      ]);
      now += 60_000;
      expect((await client.searchByIds([fresh.id])).found.has(fresh.id)).toBe(true);
    });

    it('120 labels take three requests, and each found label maps to its issue', async () => {
      const fake = await fakeJira('cloud');
      const client = clientOf(fake);
      const labels = Array.from(
        { length: 120 },
        (_, i) => `qualor-${String(i).padStart(32, '0')}-1`,
      );
      await client.createIssue(bug('first', { labels: ['qualor', labels[0]!] }));
      await client.createIssue(bug('last', { labels: ['qualor', labels[119]!] }));
      fake.clearRequests();
      const found = await client.searchByLabels(labels);
      expect(fake.requests).toHaveLength(3);
      expect([...found.keys()].sort()).toEqual([labels[0], labels[119]].sort());
      expect(found.get(labels[119]!)).toMatchObject({ key: 'QUAL-2', statusCategory: 'new' });
      expect((JSON.parse(fake.requests[0]!.body) as { jql: string }).jql).toBe(
        `labels in (${labels
          .slice(0, 50)
          .map((l) => `"${l}"`)
          .join(', ')})`,
      );
    });
  });

  it('budget: the request after the last allowed one throws budget, unsent', async () => {
    const fake = await fakeJira('data_center');
    const client = clientOf(fake, { maxRequests: 3 });
    for (let i = 0; i < 3; i++) {
      expect(client.remaining).toBe(3 - i);
      await client.myself();
    }
    expect(client.remaining).toBe(0);
    expect(await failure(client.myself())).toMatchObject({ code: 'budget', status: null });
    expect(client.requests).toBe(3);
    expect(fake.requests).toHaveLength(3);
  });

  describe('never the token (spec §11.5)', () => {
    it('Cloud: a 400 that echoes the Authorization header, the token and the email', async () => {
      const fake = await fakeJira('cloud');
      const basic = Buffer.from(`${fake.email}:${fake.token}`).toString('base64');
      const echo = {
        errorMessages: [`Authorization: Basic ${basic}`, `Bad token ${fake.token}`],
        errors: {
          reporter: `No account ${fake.email.toUpperCase()}`,
          labels: `${fake.email}:${fake.token}`,
        },
      };
      fake.inject('POST', /\/issue$/, { status: 400, body: echo });
      fake.inject('POST', /\/issue\/bulk$/, {
        status: 201,
        body: {
          issues: [{ id: '10001', key: 'QUAL-1' }],
          errors: [{ status: 400, elementErrors: echo, failedElementNumber: 1 }],
        },
      });
      const client = clientOf(fake);
      const err = await failure(client.createIssue(bug('x')));
      const [, element] = await client.createIssues([bug('a'), bug('b')]);
      const elementError = element && 'failed' in element ? element.failed : null;
      expect(err.code).toBe('field_refused');
      expect(err.jiraText).toContain('[redacted]');
      expect(elementError?.jiraText).toBe(err.jiraText);
      for (const text of [
        err.message,
        err.jiraText ?? '',
        inspect(err, { depth: 5, showHidden: true }),
        inspect(elementError, { depth: 5, showHidden: true }),
        inspect(client, { depth: 5, showHidden: true }),
      ]) {
        for (const secret of [fake.token, fake.email, fake.email.toUpperCase(), basic]) {
          expect(text).not.toContain(secret);
        }
      }
    });

    it('Data Center: the token of a Bearer header is cut out too', async () => {
      const fake = await fakeJira('data_center');
      fake.inject('POST', /\/issue$/, {
        status: 400,
        body: { errorMessages: [`Authorization: Bearer ${fake.token}`], errors: {} },
      });
      const err = await failure(clientOf(fake).createIssue(bug('x')));
      expect(err.jiraText).toBe('Authorization: Bearer [redacted]');
    });

    it('jiraText joins the messages, has no line breaks and at most 500 characters', async () => {
      const fake = await fakeJira('data_center');
      fake.inject('POST', /\/issue$/, {
        status: 400,
        body: { errorMessages: ['one\r\ntwo'], errors: { summary: 'x'.repeat(600) } },
      });
      const err = await failure(clientOf(fake).createIssue(bug('x')));
      expect(err.jiraText).toMatch(/^one two; x+$/);
      expect(err.jiraText).toHaveLength(500);
    });
  });

  it('the fake debug routes list the issues and set a status (Task 13 e2e)', async () => {
    const fake = await fakeJira('data_center', { debugRoutes: true });
    await clientOf(fake).createIssue(bug('seen'));
    fake.clearRequests();
    const set = await fetch(`${fake.url}/__fake/issues/QUAL-1/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'In Progress', category: 'indeterminate' }),
    });
    expect(set.status).toBe(204);
    const listed = (await (await fetch(`${fake.url}/__fake/issues`)).json()) as unknown[];
    expect(listed).toMatchObject([
      { key: 'QUAL-1', status: { name: 'In Progress', category: 'indeterminate' } },
    ]);
    expect(fake.requests).toHaveLength(0);
    const hidden = await fakeJira('data_center');
    expect((await fetch(`${hidden.url}/__fake/issues`)).status).toBe(404);
  });
});
