import {
  componentsPageSchema,
  currentUserSchema,
  profilesSchema,
  rulesPageSchema,
} from '@qualor/shared';
import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  type FakeProject,
  type FakeSonar,
  sampleSonarData,
  startFakeSonarQube,
} from '../../../test/fake-sonarqube';
import { CliError, EXIT } from '../../errors';
import { createLogger, silentLogger } from '../../log';
import type { ServerEndpoint } from '../../server/http';
import {
  connectSonar,
  type ConnectOptions,
  detectSonarKind,
  PAGE_SIZE,
  RESULT_WINDOW,
  SONAR_READ_ENDPOINTS,
  SonarClient,
  type SonarClientOptions,
  sonarGet,
} from './client';

let fake: FakeSonar | undefined;
afterEach(async () => {
  if (fake !== undefined) expect(fake.requests.every((r) => r.method === 'GET')).toBe(true);
  await fake?.close();
  fake = undefined;
});
const connect = (over: Partial<ConnectOptions> = {}) =>
  connectSonar({
    url: fake!.url,
    token: fake!.data.token,
    kind: 'auto',
    organization: null,
    auth: 'auto',
    timeoutMs: 5000,
    log: silentLogger,
    sleep: () => Promise.resolve(),
    ...over,
  });

describe('read-only by construction (import-sonarqube.md §4.5)', () => {
  const opts = (transport: SonarClientOptions['transport']): SonarClientOptions => ({
    endpoint: {
      url: 'https://sonar.test',
      token: 't0123456789',
      timeoutMs: 1000,
    } as ServerEndpoint,
    kind: 'server',
    organization: null,
    transport,
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'get', ' GET'])(
    'refuses %s before any I/O',
    async (method) => {
      const transport = vi.fn();
      await expect(
        sonarGet(opts(transport), method, 'api/issues/search', {}, 1024),
      ).rejects.toThrow(/read-only/);
      expect(transport).not.toHaveBeenCalled();
    },
  );

  it.each([
    'api/issues/do_transition',
    'api/issues/bulk_change',
    'api/issues/add_comment',
    'api/qualityprofiles/restore',
    'api/qualityprofiles/activate_rule',
    'api/qualitygates/destroy',
    'api/qualitygates/select',
    'api/issues/search/../do_transition',
    'api/issues/search/',
    '/api/issues/search',
    'api/issues/search?x=1',
    'API/ISSUES/SEARCH',
    'api/settings/set',
    'api/projects/delete',
    '',
  ])('refuses the path %j before any I/O', async (p) => {
    const transport = vi.fn();
    await expect(sonarGet(opts(transport), 'GET', p, {}, 1024)).rejects.toThrow(/read-only/);
    expect(transport).not.toHaveBeenCalled();
  });

  it('sends a GET on a listed path, and nothing else, through the transport', async () => {
    const transport = vi.fn().mockResolvedValue({ status: 200, headers: {}, body: '{}' });
    await sonarGet(opts(transport), 'GET', 'api/issues/search', { p: '1' }, 1024);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(transport.mock.calls[0]?.[1]).toEqual({
      method: 'GET',
      path: 'api/issues/search',
      query: { p: '1' },
      maxResponseBytes: 1024,
    });
  });

  it('lists only searches, lists and shows', () => {
    for (const p of SONAR_READ_ENDPOINTS) {
      expect(p).toMatch(/\/(search|list|show|current|version|get_by_project)$/);
    }
  });

  it('exposes no way to pass another method through the client', () => {
    const methods = Object.getOwnPropertyNames(SonarClient.prototype);
    expect(methods.sort()).toEqual(['constructor', 'get', 'kind', 'pages', 'version', 'warn']);
  });
});

describe('connectSonar (import-sonarqube.md §4)', () => {
  it('reads the version without credentials, then uses bearer on 10.x', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    expect(conn).toMatchObject({
      kind: 'server',
      version: { major: 10, minor: 7 },
      login: 'importer',
    });
    expect(fake.requests[0]).toMatchObject({
      path: 'api/server/version',
      authorization: undefined,
    });
    expect(fake.requests[1]?.authorization).toBe(`Bearer ${fake.data.token}`);
  });

  it('uses basic authentication on 9.9', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ version: '9.9.4.87374' }));
    await connect();
    expect(fake.requests[1]?.authorization).toMatch(/^Basic /);
  });

  it('follows --sonar-auth over the version', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    await connect({ auth: 'basic' });
    expect(fake.requests[1]?.authorization).toMatch(/^Basic /);
  });

  it('stops below 9.9 and on a version it cannot read (exit 2)', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ version: '8.9.10.61524' }));
    await expect(connect()).rejects.toMatchObject({ exitCode: EXIT.USAGE });
    fake.fault = (r) =>
      r.path === 'api/server/version'
        ? { status: 200, body: '<html>', headers: { 'content-type': 'text/html' } }
        : null;
    await expect(connect()).rejects.toMatchObject({ exitCode: EXIT.USAGE });
    // Nothing but the version was asked.
    expect(fake.requests.every((r) => r.path === 'api/server/version')).toBe(true);
  });

  it('exits 5 on a refused token or isLoggedIn false', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    await expect(connect({ token: 'squ_wrong000000000000' })).rejects.toMatchObject({
      exitCode: EXIT.AUTH,
    });
    fake.fault = (r) =>
      r.path === 'api/users/current' ? { status: 200, body: '{"isLoggedIn":false}' } : null;
    await expect(connect()).rejects.toMatchObject({ exitCode: EXIT.AUTH });
  });

  it('talks to SonarQube Cloud with bearer and organization, and never asks the version', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const conn = await connect({ kind: 'cloud', organization: 'acme' });
    expect(conn.version).toBeNull();
    expect(fake.requests.map((r) => r.path)).not.toContain('api/server/version');
    expect(fake.requests.every((r) => r.authorization === `Bearer ${fake!.data.token}`)).toBe(true);
    await conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list');
    expect(fake.requests.at(-1)?.query['organization']).toBe('acme');
    await conn.client.get('api/users/current', {}, currentUserSchema, 'current user');
    expect(fake.requests.at(-1)?.query['organization']).toBeUndefined();
  });

  it('needs --organization for Cloud, refuses it for Server, and checks it exists', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    await expect(connect({ kind: 'cloud' })).rejects.toMatchObject({ exitCode: EXIT.USAGE });
    await expect(connect({ kind: 'cloud', organization: 'other' })).rejects.toThrow(/other/);
    await expect(connect({ kind: 'server', organization: 'acme' })).rejects.toMatchObject({
      exitCode: EXIT.USAGE,
    });
  });

  it('recognises SonarQube Cloud by host', () => {
    expect(detectSonarKind('https://sonarcloud.io')).toBe('cloud');
    expect(detectSonarKind('https://sonarqube.us/')).toBe('cloud');
    expect(detectSonarKind('http://sonarcloud.io')).toBe('server');
    expect(detectSonarKind('https://sonar.acme.internal/sonarqube')).toBe('server');
  });
});

describe('SonarClient.get (import-sonarqube.md §5)', () => {
  it('stops on a redirect and names --url, sending nothing after it', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    fake.fault = () => ({
      status: 301,
      headers: { location: 'https://elsewhere.test/api/qualityprofiles/search' },
    });
    const before = fake.requests.length;
    await expect(
      conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list'),
    ).rejects.toThrow(/--url/);
    expect(fake.requests.length).toBe(before + 1);
  });

  it('retries 503 three times, then exits 4; retries a 429 after Retry-After', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const sleeps: number[] = [];
    const conn = await connect({
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    });
    const before = fake.requests.length;
    fake.fault = () => ({ status: 503 });
    await expect(
      conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list'),
    ).rejects.toMatchObject({ exitCode: EXIT.SERVER });
    expect(fake.requests.length - before).toBe(4);
    expect(sleeps).toEqual([1000, 2000, 4000]);
    let n = 0;
    fake.fault = () => (n++ === 0 ? { status: 429, headers: { 'retry-after': '7' } } : null);
    await expect(
      conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list'),
    ).resolves.toBeDefined();
    expect(sleeps.at(-1)).toBe(7000);
  });

  it('does not wait for a Retry-After over 60 s', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    const before = fake.requests.length;
    fake.fault = () => ({ status: 429, headers: { 'retry-after': '120' } });
    await expect(
      conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list'),
    ).rejects.toMatchObject({ exitCode: EXIT.SERVER });
    expect(fake.requests.length - before).toBe(1);
  });

  it('never retries a 500 or a 404', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    const before = fake.requests.length;
    fake.fault = () => ({ status: 500 });
    await expect(
      conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profile list'),
    ).rejects.toMatchObject({ exitCode: EXIT.SERVER });
    expect(fake.requests.length - before).toBe(1);
  });

  it.each([
    ['not JSON', { status: 200, body: '<html>', headers: { 'content-type': 'text/html' } }],
    ['invalid JSON', { status: 200, body: '{' }],
    ['a wrong shape', { status: 200, body: '{"profiles":"x"}' }],
  ])('exits 4 on %s without echoing the answer', async (_what, f) => {
    fake = await startFakeSonarQube(sampleSonarData());
    const conn = await connect();
    fake.fault = () => f;
    const err = await conn.client
      .get('api/qualityprofiles/search', {}, profilesSchema, 'profile list')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(EXIT.SERVER);
    expect((err as CliError).message).not.toContain('html');
  });

  it.each([
    ['10.7.0.96327', 'bearer'],
    ['9.9.4.87374', 'basic'],
  ])(
    'never puts the token in an error, though SonarQube %s echoes the %s credential',
    async (version) => {
      fake = await startFakeSonarQube(sampleSonarData({ version }), { echoCredentials: true });
      const token = fake.data.token;
      const basic = Buffer.from(`${token}:`).toString('base64');
      const secrets = [token, basic, basic.replace(/=+$/, '')];
      const lines: string[] = [];
      const conn = await connect({ log: createLogger('debug', (t) => lines.push(t)) });
      const auth = fake.requests.at(-1)?.authorization ?? '';
      // The fake really sends the credential back in its error answers.
      const echoed = await fetch(`${fake.url}/api/rules/search`, {
        headers: { authorization: auth },
      });
      expect(echoed.status).toBe(400);
      expect(await echoed.text()).toContain(auth.split(' ')[1]);
      const errors: unknown[] = [];
      const fail = async (p: Promise<unknown>) =>
        errors.push(
          await p.then(
            () => null,
            (e) => e,
          ),
        );
      // A real 400 of the fake (no qprofile), a 404 and a page past the window.
      await fail(conn.client.get('api/rules/search', {}, rulesPageSchema, 'rule page'));
      await fail(
        conn.client.get('api/components/show', { component: 'x:gone' }, profilesSchema, 'p'),
      );
      await fail(
        conn.client.get('api/components/search', { p: '99', ps: '500' }, profilesSchema, 'p'),
      );
      for (const status of [500, 503, 403, 401, 429]) {
        fake.fault = (r) => (r.path === 'api/qualityprofiles/search' ? { status } : null);
        await fail(conn.client.get('api/qualityprofiles/search', {}, profilesSchema, 'profiles'));
      }
      expect(errors).toHaveLength(8);
      expect(errors.every((e) => e instanceof CliError)).toBe(true);
      for (const e of errors as CliError[]) {
        // Every own and hidden property, the cause chain included, at any depth.
        const text = `${e.message}\n${e.stack ?? ''}\n${inspect(e, { showHidden: true, depth: null })}`;
        for (const s of secrets) expect(text).not.toContain(s);
      }
      const logged = [...lines, ...conn.client.warnings.map((w) => w.message)].join('\n');
      for (const s of secrets) expect(logged).not.toContain(s);
    },
  );
});

describe('SonarClient.warn', () => {
  it('records a warning for the report and logs it once, cleaned', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const lines: string[] = [];
    const { client } = await connect({ log: createLogger('debug', (t) => lines.push(t)) });
    client.warn('SONARQUBE_RESULTS_CHANGED', 'the list changed\u001b[31m while it was read');
    expect(client.warnings).toEqual([
      {
        code: 'SONARQUBE_RESULTS_CHANGED',
        message: 'the list changed\u001b[31m while it was read',
      },
    ]);
    expect(lines.filter((l) => l.startsWith('warn: '))).toEqual([
      'warn: the list changed while it was read\n',
    ]);
  });
});

describe('SonarClient.pages (import-sonarqube.md §5.2)', () => {
  const projects = (n: number): FakeProject[] =>
    Array.from({ length: n }, (_, k) => ({ key: `acme:p${k}`, name: `P${k}` }));

  it('reads every page up to the total', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ projects: projects(25) }), { window: 30 });
    const { client } = await connect();
    const r = await client.pages(
      'api/components/search',
      { qualifiers: 'TRK' },
      componentsPageSchema,
      (p) => p.components,
      (c) => c.key,
      'project page',
      RESULT_WINDOW,
      { window: 30, pageSize: 10 },
    );
    expect(r).toMatchObject({ total: 25, complete: true });
    expect(r.items).toHaveLength(25);
    expect(fake.requests.filter((q) => q.path === 'api/components/search')).toHaveLength(3);
  });

  it('stops at the result window and never asks a page past it', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ projects: projects(35) }), { window: 20 });
    const { client } = await connect();
    const r = await client.pages(
      'api/components/search',
      { qualifiers: 'TRK' },
      componentsPageSchema,
      (p) => p.components,
      (c) => c.key,
      'project page',
      RESULT_WINDOW,
      { window: 20, pageSize: 10 },
    );
    expect(r).toMatchObject({ total: 35, complete: false });
    expect(r.items).toHaveLength(20);
    const asked = fake.requests.filter((q) => q.path === 'api/components/search');
    expect(asked.map((q) => q.query['p'])).toEqual(['1', '2']);
    expect(asked.every((q) => Number(q.query['p']) * Number(q.query['ps']) <= 20)).toBe(true);
  });

  it('holds the default window to 10 000 results: at most 20 pages of 500', () => {
    expect(PAGE_SIZE).toBe(500);
    expect(RESULT_WINDOW).toBe(10_000);
    expect(RESULT_WINDOW / PAGE_SIZE).toBe(20);
  });

  it('stops at maxItems', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ projects: projects(25) }));
    const { client } = await connect();
    const r = await client.pages(
      'api/components/search',
      {},
      componentsPageSchema,
      (p) => p.components,
      (c) => c.key,
      'project page',
      12,
      { pageSize: 10 },
    );
    expect(r.items).toHaveLength(12);
    expect(r.complete).toBe(false);
    expect(fake.requests.filter((q) => q.path === 'api/components/search')).toHaveLength(2);
  });

  it.each([0, -1, Number.NaN])('refuses maxItems %s before asking anything', async (max) => {
    fake = await startFakeSonarQube(sampleSonarData({ projects: [] }));
    const { client } = await connect();
    const before = fake.requests.length;
    await expect(
      client.pages(
        'api/components/search',
        {},
        componentsPageSchema,
        (p) => p.components,
        (c) => c.key,
        'project page',
        max,
      ),
    ).rejects.toBeInstanceOf(CliError);
    expect(fake.requests.length).toBe(before);
  });

  it('warns when the total changes while it reads', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ projects: projects(15) }));
    const { client } = await connect();
    let n = 0;
    fake.fault = (q) => {
      if (q.path !== 'api/components/search' || n++ !== 1) return null;
      const body = JSON.stringify({
        paging: { pageIndex: 2, pageSize: 10, total: 16 },
        components: [{ key: 'acme:x', name: 'X' }],
      });
      return { status: 200, body };
    };
    await client.pages(
      'api/components/search',
      {},
      componentsPageSchema,
      (p) => p.components,
      (c) => c.key,
      'project page',
      RESULT_WINDOW,
      { pageSize: 10 },
    );
    expect(client.warnings.map((w) => w.code)).toContain('SONARQUBE_RESULTS_CHANGED');
  });

  describe('completeness (ruling S10)', () => {
    const read = (client: SonarClient) =>
      client.pages(
        'api/components/search',
        {},
        componentsPageSchema,
        (p) => p.components,
        (c) => c.key,
        'project page',
        RESULT_WINDOW,
        { pageSize: 2 },
      );

    it('is not complete when the total changes between pages, though enough were read', async () => {
      fake = await startFakeSonarQube(sampleSonarData({ projects: projects(5) }));
      const { client } = await connect();
      // After page 1, one project goes: page 2 starts one further on and p2 is never seen.
      let n = 0;
      fake.fault = (q) => {
        if (q.path === 'api/components/search' && n++ === 1) fake!.data.projects.shift();
        return null;
      };
      const r = await read(client);
      expect(r.items.map((p) => p.key)).toEqual(['acme:p0', 'acme:p1', 'acme:p3', 'acme:p4']);
      expect(r).toMatchObject({ total: 4, complete: false });
    });

    it('counts each item once: a shift that repeats one is not complete', async () => {
      fake = await startFakeSonarQube(sampleSonarData({ projects: projects(5) }));
      const { client } = await connect();
      // After page 1, one project comes first and the last goes: same total, p1 is sent twice.
      let n = 0;
      fake.fault = (q) => {
        if (q.path === 'api/components/search' && n++ === 1) {
          fake!.data.projects.pop();
          fake!.data.projects.unshift({ key: 'acme:new', name: 'New' });
        }
        return null;
      };
      const r = await read(client);
      expect(r.items.map((p) => p.key)).toEqual(['acme:p0', 'acme:p1', 'acme:p2', 'acme:p3']);
      expect(r).toMatchObject({ total: 5, complete: false });
      expect(client.warnings.map((w) => w.code)).not.toContain('SONARQUBE_RESULTS_CHANGED');
    });
  });
});
