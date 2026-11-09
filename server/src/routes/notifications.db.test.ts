import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  nextIp,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { createIngestHarness } from '../../test/ingest';
import { MAIL_ON, payloadOf, PUBLIC_URL, queued, watch } from '../../test/notify';
import { sampleReport } from '../../test/reports';
import { SESSION_COOKIE } from '../auth/sessions';
import {
  notificationPreferences,
  organizations,
  projects,
  projectWatches,
  users,
} from '../db/schema';
import { unsubscribeToken, vulnerabilityUnsubscribeToken } from '../notifications/unsubscribe';
import { communityLimits } from '../limits';

const ON = {
  branches: 'all',
  events: { gateFailed: true, gateRecovered: false, analysisFailed: true },
} as const;

type Body = 'form' | 'multipart' | 'json' | 'empty-json' | 'none';

/** The bodies RFC 8058 mail clients and the UI's page send; the route ignores them all. */
function bodyOf(body: Body): { headers?: Record<string, string>; payload?: string } {
  switch (body) {
    case 'form':
      return {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: 'List-Unsubscribe=One-Click',
      };
    case 'multipart':
      return {
        headers: { 'content-type': 'multipart/form-data; boundary=x' },
        payload:
          '--x\r\nContent-Disposition: form-data; name="List-Unsubscribe"\r\n\r\nOne-Click\r\n--x--\r\n',
      };
    case 'json':
      return { headers: { 'content-type': 'application/json' }, payload: '{}' };
    case 'empty-json':
      return { headers: { 'content-type': 'application/json' }, payload: '' };
    case 'none':
      return {};
  }
}

describe('watch, notification and unsubscribe routes (mail E3)', () => {
  let ctx: TestContext;
  let org: string;
  let owner: Session;
  let viewer: Session;
  let viewerId: string;
  let outsider: Session;
  let projectId: string;

  const call = (
    session: Session,
    method: 'GET' | 'PUT' | 'DELETE',
    url: string,
    payload?: unknown,
  ) =>
    ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const watchesOf = (userId: string, project: string) =>
    ctx.db
      .select()
      .from(projectWatches)
      .where(and(eq(projectWatches.userId, userId), eq(projectWatches.projectId, project)));
  const unsubscribe = (t: string, body: Body = 'form', ip = nextIp()) =>
    ctx.app.inject({
      method: 'POST',
      url: `/api/v0/notifications/unsubscribe?t=${encodeURIComponent(t)}`,
      remoteAddress: ip,
      ...bodyOf(body),
    });
  const openLink = (t: string, ip = nextIp()) =>
    ctx.app.inject({
      method: 'GET',
      url: `/api/v0/notifications/unsubscribe?t=${encodeURIComponent(t)}`,
      remoteAddress: ip,
    });

  beforeAll(async () => {
    ctx = await createTestContext({ config: { ...MAIL_ON, demoUser: 'guest' } });
    org = await organizationId(ctx, 'default');
    const o = await createUser(ctx, { username: 'nr-owner', email: 'owner@example.com' });
    await addMember(ctx, org, o.id, 'admin');
    owner = await login(ctx, o.username, o.password);
    const v = await createUser(ctx, { username: 'nr-viewer', email: 'viewer@example.com' });
    await addMember(ctx, org, v.id, 'viewer');
    viewer = await login(ctx, v.username, v.password);
    viewerId = v.id;
    const x = await createUser(ctx, { username: 'nr-outsider', email: 'outsider@example.com' });
    outsider = await login(ctx, x.username, x.password);
    projectId = (
      await createProject(ctx, owner, { organizationId: org, key: 'nr/zeta', name: 'Zeta' })
    ).id;
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('lets a reader watch, change and stop watching a project', async () => {
    expect((await call(viewer, 'GET', `/projects/${projectId}/watch`)).json()).toEqual({
      watching: false,
      emailReady: true,
      emailBlocker: null,
      vulnerabilityAlerts: false,
    });
    const put = await call(viewer, 'PUT', `/projects/${projectId}/watch`, ON);
    expect(put.statusCode, put.body).toBe(200);
    expect(put.json()).toEqual({
      watching: true,
      ...ON,
      events: { ...ON.events, newVulnerabilities: true },
      emailReady: true,
      emailBlocker: null,
      vulnerabilityAlerts: false,
    });
    const changed = await call(viewer, 'PUT', `/projects/${projectId}/watch`, {
      ...ON,
      branches: 'main',
    });
    expect(changed.json()).toMatchObject({ watching: true, branches: 'main' });
    expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
    expect((await call(viewer, 'GET', `/projects/${projectId}/watch`)).json()).toEqual({
      watching: true,
      ...ON,
      events: { ...ON.events, newVulnerabilities: true },
      branches: 'main',
      emailReady: true,
      emailBlocker: null,
      vulnerabilityAlerts: false,
    });
    expect((await call(viewer, 'DELETE', `/projects/${projectId}/watch`)).statusCode).toBe(204);
    expect((await call(viewer, 'DELETE', `/projects/${projectId}/watch`)).statusCode).toBe(204);
    expect((await call(viewer, 'GET', `/projects/${projectId}/watch`)).json()).toMatchObject({
      watching: false,
    });
  });

  it('stores the New vulnerabilities flag, and an older client that omits it keeps it (4b)', async () => {
    const url = `/projects/${projectId}/watch`;
    const off = await call(viewer, 'PUT', url, {
      ...ON,
      events: { ...ON.events, newVulnerabilities: false },
    });
    expect(off.statusCode, off.body).toBe(200);
    expect(off.json()).toMatchObject({ events: { newVulnerabilities: false } });
    expect((await watchesOf(viewerId, projectId))[0]?.newVulnerabilities).toBe(false);
    expect((await call(viewer, 'GET', url)).json()).toMatchObject({
      events: { newVulnerabilities: false },
    });
    expect((await call(viewer, 'GET', '/me/notifications')).json().watches[0].events).toMatchObject(
      { newVulnerabilities: false },
    );
    // A PUT without the field keeps the stored value.
    const kept = await call(viewer, 'PUT', url, { ...ON, branches: 'main' });
    expect(kept.json()).toMatchObject({ events: { newVulnerabilities: false } });
    expect((await watchesOf(viewerId, projectId))[0]?.newVulnerabilities).toBe(false);
    const on = await call(viewer, 'PUT', url, {
      ...ON,
      events: { ...ON.events, newVulnerabilities: true },
    });
    expect(on.json()).toMatchObject({ events: { newVulnerabilities: true } });
    // A new watch without the field gets true.
    await call(viewer, 'DELETE', url);
    const fresh = await call(viewer, 'PUT', url, ON);
    expect(fresh.json()).toMatchObject({ events: { newVulnerabilities: true } });
    expect(
      (
        await call(viewer, 'PUT', url, {
          ...ON,
          events: { ...ON.events, newVulnerabilities: 'no' },
        })
      ).statusCode,
    ).toBe(422);
    await call(viewer, 'DELETE', url);
  });

  it('answers 404 to someone who cannot read the project, and 422 to a bad body', async () => {
    for (const method of ['GET', 'PUT', 'DELETE'] as const) {
      const res = await call(
        outsider,
        method,
        `/projects/${projectId}/watch`,
        method === 'PUT' ? ON : undefined,
      );
      expect(res.statusCode, method).toBe(404);
    }
    for (const body of [
      { branches: 'some', events: ON.events },
      { branches: 'main' },
      { ...ON, events: { ...ON.events, extra: true } },
    ]) {
      expect((await call(viewer, 'PUT', `/projects/${projectId}/watch`, body)).statusCode).toBe(
        422,
      );
    }
    expect(await watchesOf(viewerId, projectId)).toEqual([]);
  });

  it('refuses the demo account (DEMO_READ_ONLY)', async () => {
    const guest = await createUser(ctx, { username: 'guest', email: 'guest@example.com' });
    await addMember(ctx, org, guest.id, 'viewer');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/demo',
      remoteAddress: nextIp(),
    });
    expect(res.statusCode, res.body).toBe(204);
    const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
    const me = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      cookies: { [SESSION_COOKIE]: cookie },
    });
    const headers = {
      cookie: `${SESSION_COOKIE}=${cookie}`,
      'x-qualor-csrf': (me.json() as { csrfToken: string }).csrfToken,
    };
    for (const [method, url, payload] of [
      ['PUT', `/api/v0/projects/${projectId}/watch`, ON],
      ['DELETE', `/api/v0/projects/${projectId}/watch`, undefined],
      ['PUT', '/api/v0/me/notifications', { email: false }],
    ] as const) {
      const refused = await ctx.app.inject({
        method,
        url,
        headers,
        ...(payload ? { payload } : {}),
      });
      expect(refused.statusCode, `${method} ${url}`).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'DEMO_READ_ONLY' });
    }
    expect(await watchesOf(guest.id, projectId)).toEqual([]);
  });

  it('says why no email would arrive: no address, or notification email off', async () => {
    const n = await createUser(ctx, { username: 'nr-noaddress' });
    await addMember(ctx, org, n.id, 'viewer');
    const noAddress = await login(ctx, n.username, n.password);
    expect((await call(noAddress, 'GET', `/projects/${projectId}/watch`)).json()).toMatchObject({
      emailReady: false,
      emailBlocker: 'no_address',
    });
    await ctx.db.insert(notificationPreferences).values({ userId: viewerId, email: false });
    try {
      expect((await call(viewer, 'GET', `/projects/${projectId}/watch`)).json()).toMatchObject({
        emailReady: false,
        emailBlocker: 'preference_off',
      });
    } finally {
      await ctx.db
        .delete(notificationPreferences)
        .where(eq(notificationPreferences.userId, viewerId));
    }
  });

  it('lists the visible watches by project name, with the preferences, and saves them', async () => {
    const alpha = await createProject(ctx, owner, {
      organizationId: org,
      key: 'nr/alpha',
      name: 'Alpha',
    });
    const [elsewhere] = await ctx.db
      .insert(organizations)
      .values({ key: 'nr-else', name: 'Else' })
      .returning();
    const [hidden] = await ctx.db
      .insert(projects)
      .values({ organizationId: elsewhere!.id, key: 'nr/hidden', name: 'Hidden' })
      .returning();
    await watch(ctx.db, viewerId, projectId, { branches: 'all' });
    await watch(ctx.db, viewerId, alpha.id);
    await watch(ctx.db, viewerId, hidden!.id);
    const listed = await call(viewer, 'GET', '/me/notifications');
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.json()).toEqual({
      preferences: { email: true, orgWebhookFailures: true },
      isOrgAdmin: false,
      emailAddress: 'viewer@example.com',
      mailConfigured: true,
      vulnerabilityAlerts: false,
      watches: [
        {
          project: { id: alpha.id, key: 'nr/alpha', name: 'Alpha' },
          branches: 'main',
          events: {
            gateFailed: true,
            gateRecovered: true,
            analysisFailed: true,
            newVulnerabilities: true,
          },
        },
        {
          project: { id: projectId, key: 'nr/zeta', name: 'Zeta' },
          branches: 'all',
          events: {
            gateFailed: true,
            gateRecovered: true,
            analysisFailed: true,
            newVulnerabilities: true,
          },
        },
      ],
    });
    expect((await call(owner, 'GET', '/me/notifications')).json()).toMatchObject({
      isOrgAdmin: true,
    });
    expect((await call(viewer, 'PUT', '/me/notifications', { email: false })).json()).toEqual({
      preferences: { email: false, orgWebhookFailures: true },
    });
    expect(
      (await call(viewer, 'PUT', '/me/notifications', { orgWebhookFailures: false })).json(),
    ).toEqual({
      preferences: { email: false, orgWebhookFailures: false },
    });
    expect((await call(viewer, 'PUT', '/me/notifications', {})).statusCode).toBe(200);
    expect((await call(viewer, 'GET', '/me/notifications')).json()).toMatchObject({
      preferences: { email: false, orgWebhookFailures: false },
    });
    expect((await call(viewer, 'PUT', '/me/notifications', { email: 'no' })).statusCode).toBe(422);
    expect((await call(viewer, 'PUT', '/me/notifications', { other: true })).statusCode).toBe(422);
    await ctx.db
      .delete(notificationPreferences)
      .where(eq(notificationPreferences.userId, viewerId));
    await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
  });

  it('stops watching with the RFC 8058 one-click POST, without signing in, idempotently', async () => {
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, projectId);
    for (const body of ['form', 'multipart', 'json', 'empty-json', 'none'] as const) {
      await watch(ctx.db, viewerId, projectId);
      const res = await unsubscribe(token, body);
      expect(res.statusCode, `${body}: ${res.body}`).toBe(200);
      expect(res.json()).toEqual({ project: { name: 'Zeta' } });
      expect(await watchesOf(viewerId, projectId), body).toEqual([]);
    }
    // Again, with nothing left to remove: the same answer.
    expect((await unsubscribe(token, 'form')).json()).toEqual({ project: { name: 'Zeta' } });
  });

  it('refuses a tampered token, one made under another key, and garbage with 400 TOKEN_INVALID', async () => {
    await watch(ctx.db, viewerId, projectId);
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, projectId);
    const [payload, tag] = token.split('.') as [string, string];
    for (const bad of [
      `${payload}.${tag.startsWith('A') ? 'B' : 'A'}${tag.slice(1)}`,
      unsubscribeToken('another-secret-key-that-is-at-least-32-chars', viewerId, projectId),
      'garbage',
      '',
    ]) {
      const res = await unsubscribe(bad);
      expect(res.statusCode, bad).toBe(400);
      expect(res.json()).toMatchObject({ code: 'TOKEN_INVALID' });
    }
    expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
    await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
  });

  it('answers 422 without a token, or with one far too long', async () => {
    for (const url of [
      '/api/v0/notifications/unsubscribe',
      `/api/v0/notifications/unsubscribe?t=${'a'.repeat(401)}`,
    ]) {
      for (const method of ['POST', 'GET'] as const) {
        const res = await ctx.app.inject({ method, url, remoteAddress: nextIp() });
        expect(res.statusCode, `${method} ${url}`).toBe(422);
      }
    }
  });

  it('only redirects a GET to the page that asks first: a link scanner never unsubscribes anyone', async () => {
    await watch(ctx.db, viewerId, projectId);
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, projectId);
    const res = await openLink(token);
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${PUBLIC_URL}/unsubscribe#t=${token}`);
    // Even a forged token only redirects: the page's POST is what checks it.
    expect((await openLink('garbage')).statusCode).toBe(303);
    expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
    await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
  });

  it('keeps the token out of the request log, for the POST and the GET', async () => {
    await watch(ctx.db, viewerId, projectId);
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, projectId);
    const from = ctx.logs.length;
    expect((await openLink(token)).statusCode).toBe(303);
    expect((await unsubscribe(token)).statusCode).toBe(200);
    expect((await unsubscribe('garbage-token-value')).statusCode).toBe(400);
    // Another spelling of the path that the router still matches: the matched route counts.
    const spelled = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/notifications/unsubscrib%65?t=${encodeURIComponent(token)}`,
      remoteAddress: nextIp(),
    });
    expect(spelled.statusCode).toBe(200);
    const lines = ctx.logs.slice(from).join('\n');
    expect(lines).toContain('"url":"/api/v0/notifications/unsubscribe"');
    for (const secret of [
      token,
      encodeURIComponent(token),
      token.split('.')[1]!,
      'garbage-token-value',
      '?t=',
    ]) {
      expect(lines).not.toContain(secret);
    }
  });

  it('refuses a body over 1 KB with 413, and keeps the watch', async () => {
    await watch(ctx.db, viewerId, projectId);
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, projectId);
    for (const contentType of ['application/x-www-form-urlencoded', 'application/json']) {
      const res = await ctx.app.inject({
        method: 'POST',
        url: `/api/v0/notifications/unsubscribe?t=${encodeURIComponent(token)}`,
        remoteAddress: nextIp(),
        headers: { 'content-type': contentType },
        payload: `List-Unsubscribe=One-Click&pad=${'x'.repeat(1024)}`,
      });
      expect(res.statusCode, contentType).toBe(413);
    }
    expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
    await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
  });

  it('answers project null once the project is gone', async () => {
    const gone = await createProject(ctx, owner, {
      organizationId: org,
      key: 'nr/gone',
      name: 'Gone',
    });
    await watch(ctx.db, viewerId, gone.id);
    const token = unsubscribeToken(ctx.config.secretKey, viewerId, gone.id);
    await ctx.db.delete(projects).where(eq(projects.id, gone.id));
    const res = await unsubscribe(token);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ project: null });
  });

  it('allows 30 unsubscribe requests a minute per address', async () => {
    const ip = nextIp();
    for (let i = 0; i < 30; i++)
      expect((await unsubscribe('garbage', 'form', ip)).statusCode).toBe(400);
    const limited = await unsubscribe('garbage', 'form', ip);
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ code: 'RATE_LIMITED' });
    const other = nextIp();
    for (let i = 0; i < 30; i++) expect((await openLink('garbage', other)).statusCode).toBe(303);
    expect((await openLink('garbage', other)).statusCode).toBe(429);
  });

  describe('the vulnerability emails stop (4b)', () => {
    const VULN = '/api/v0/notifications/unsubscribe/vulnerabilities';
    const stop = (t: string, ip = nextIp(), body: Body = 'form') =>
      ctx.app.inject({
        method: 'POST',
        url: `${VULN}?t=${encodeURIComponent(t)}`,
        remoteAddress: ip,
        ...bodyOf(body),
      });
    beforeEach(async () => {
      await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
    });
    const flags = async () =>
      (
        await ctx.db
          .select({ id: projectWatches.projectId, on: projectWatches.newVulnerabilities })
          .from(projectWatches)
          .where(eq(projectWatches.userId, viewerId))
      )
        .map((w) => w.on)
        .sort();

    it('switches the flag off on all the watches, keeps them, and is idempotent', async () => {
      const second = (
        await createProject(ctx, owner, { organizationId: org, key: 'nr/vuln-two', name: 'Two' })
      ).id;
      await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
      await watch(ctx.db, viewerId, projectId, { branches: 'main' });
      await watch(ctx.db, viewerId, second);
      const token = vulnerabilityUnsubscribeToken(ctx.config.secretKey, viewerId);
      for (const body of ['form', 'json', 'none'] as const) {
        const res = await stop(token, nextIp(), body);
        expect(res.statusCode, `${body}: ${res.body}`).toBe(200);
        expect(res.json()).toEqual({});
        expect(await flags(), body).toEqual([false, false]);
      }
      expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
      const [kept] = await watchesOf(viewerId, projectId);
      expect(kept).toMatchObject({ branches: 'main', gateFailed: true });
      await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
    });

    it('refuses a bad token, and a project token, with 400 TOKEN_INVALID', async () => {
      await watch(ctx.db, viewerId, projectId);
      for (const bad of [
        'garbage-token-value',
        unsubscribeToken(ctx.config.secretKey, viewerId, projectId),
      ]) {
        const res = await stop(bad);
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ code: 'TOKEN_INVALID' });
      }
      expect(await flags()).toEqual([true]);
      // And the project route refuses a vulnerability token.
      const vuln = vulnerabilityUnsubscribeToken(ctx.config.secretKey, viewerId);
      expect((await unsubscribe(vuln)).statusCode).toBe(400);
      expect(await watchesOf(viewerId, projectId)).toHaveLength(1);
      await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
    });

    it('redirects a GET to the page that asks first and changes nothing', async () => {
      await watch(ctx.db, viewerId, projectId);
      const token = vulnerabilityUnsubscribeToken(ctx.config.secretKey, viewerId);
      const res = await ctx.app.inject({
        method: 'GET',
        url: `${VULN}?t=${encodeURIComponent(token)}`,
        remoteAddress: nextIp(),
      });
      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe(`${PUBLIC_URL}/unsubscribe/vulnerabilities#t=${token}`);
      expect(await flags()).toEqual([true]);
      await ctx.db.delete(projectWatches).where(eq(projectWatches.userId, viewerId));
    });

    it('keeps the token out of the request log, including another spelling of the path', async () => {
      const token = vulnerabilityUnsubscribeToken(ctx.config.secretKey, viewerId);
      const from = ctx.logs.length;
      expect((await stop(token)).statusCode).toBe(200);
      const spelled = await ctx.app.inject({
        method: 'POST',
        url: `/api/v0/notifications/unsubscribe/vulnerabilitie%73?t=${encodeURIComponent(token)}`,
        remoteAddress: nextIp(),
      });
      expect(spelled.statusCode).toBe(200);
      const lines = ctx.logs.slice(from).join('\n');
      expect(lines).toContain(`"url":"${VULN}"`);
      for (const secret of [token, encodeURIComponent(token), token.split('.')[1]!]) {
        expect(lines).not.toContain(secret);
      }
    });

    it('allows 30 requests a minute per address', async () => {
      const ip = nextIp();
      for (let i = 0; i < 30; i++) expect((await stop('garbage', ip)).statusCode).toBe(400);
      expect((await stop('garbage', ip)).statusCode).toBe(429);
    });
  });
});

describe('without SMTP or a public URL (mail E3)', () => {
  it('says email is not set up, and redirects a stop link within the server', async () => {
    const ctx = await createTestContext();
    try {
      const org = await organizationId(ctx, 'default');
      const o = await createUser(ctx, { username: 'nm-owner', email: 'owner@example.com' });
      await addMember(ctx, org, o.id, 'admin');
      const session = await login(ctx, o.username, o.password);
      const project = await createProject(ctx, session, { organizationId: org, key: 'nm/one' });
      const res = await ctx.app.inject({
        method: 'GET',
        url: `/api/v0/projects/${project.id}/watch`,
        headers: session.headers,
      });
      expect(res.json()).toMatchObject({ emailReady: false, emailBlocker: 'not_configured' });
      expect(
        (
          await ctx.app.inject({
            method: 'GET',
            url: '/api/v0/me/notifications',
            headers: session.headers,
          })
        ).json(),
      ).toMatchObject({ mailConfigured: false });
      const token = unsubscribeToken(ctx.config.secretKey, o.id, project.id);
      const link = await ctx.app.inject({
        method: 'GET',
        url: `/api/v0/notifications/unsubscribe?t=${token}`,
        remoteAddress: nextIp(),
      });
      expect(link.statusCode).toBe(303);
      expect(link.headers.location).toBe(`/unsubscribe#t=${token}`);
    } finally {
      await ctx.close();
    }
  });
});

describe('the whole chain (mail E3 acceptance 1 and 4)', () => {
  it('watch through the API → failing analysis → queued message → its stop header removes the watch', async () => {
    const h = await createIngestHarness({ config: MAIL_ON, notify: true });
    try {
      // The harness's organisation admin (`ingest-admin`) has no address yet.
      await h.ctx.db
        .update(users)
        .set({ email: 'ingest-admin@example.com' })
        .where(eq(users.username, 'ingest-admin'));
      const p = await h.project('chain/one');
      const put = await h.ctx.app.inject({
        method: 'PUT',
        url: `/api/v0/projects/${p.id}/watch`,
        headers: h.orgAdmin.headers,
        payload: {
          branches: 'main',
          events: {
            gateFailed: true,
            gateRecovered: true,
            analysisFailed: true,
            newVulnerabilities: true,
          },
        },
      });
      expect(put.statusCode, put.body).toBe(200);
      expect(put.json()).toMatchObject({ watching: true, emailReady: true });
      await p.ingestOk(sampleReport({ projectKey: p.key }));
      const [row] = (await queued(h.ctx.db, 'notify.gate-failed')).filter((m) =>
        m.subject.startsWith('chain/one:'),
      );
      expect(row?.toAddress).toBe('ingest-admin@example.com');
      const headers = payloadOf(row!, h.ctx.config.secretKey).headers!;
      expect(headers['List-Unsubscribe-Post']).toBe('List-Unsubscribe=One-Click');
      const url = new URL(headers['List-Unsubscribe']!.slice(1, -1));
      expect(url.origin).toBe(PUBLIC_URL);
      const res = await h.ctx.app.inject({
        method: 'POST',
        url: `${url.pathname}${url.search}`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: 'List-Unsubscribe=One-Click',
        remoteAddress: nextIp(),
      });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({ project: { name: 'chain/one' } });
      expect(
        await h.ctx.db.select().from(projectWatches).where(eq(projectWatches.projectId, p.id)),
      ).toEqual([]);
    } finally {
      await h.close();
    }
  });
});

describe('the vulnerability alerts feature state (4b)', () => {
  let ctx: TestContext;
  let user: Session;
  let projectId: string;

  beforeAll(async () => {
    const limits = communityLimits();
    ctx = await createTestContext({
      config: { ...MAIL_ON },
      limits: { ...limits, vulnerabilities: { ...limits.vulnerabilities, alerts: true } },
    });
    const org = await organizationId(ctx, 'default');
    const u = await createUser(ctx, { username: 'va-user', email: 'va@example.com' });
    await addMember(ctx, org, u.id, 'admin');
    user = await login(ctx, u.username, u.password);
    projectId = (
      await createProject(ctx, user, { organizationId: org, key: 'va/one', name: 'One' })
    ).id;
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('is true on both answers with the licensed limit, watching or not', async () => {
    const get = (url: string) =>
      ctx.app.inject({ method: 'GET', url: `/api/v0${url}`, headers: user.headers });
    expect((await get(`/projects/${projectId}/watch`)).json()).toMatchObject({
      watching: false,
      vulnerabilityAlerts: true,
    });
    await ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/projects/${projectId}/watch`,
      headers: user.headers,
      payload: {
        branches: 'main',
        events: { gateFailed: true, gateRecovered: true, analysisFailed: true },
      },
    });
    expect((await get(`/projects/${projectId}/watch`)).json()).toMatchObject({
      watching: true,
      vulnerabilityAlerts: true,
    });
    expect((await get('/me/notifications')).json()).toMatchObject({ vulnerabilityAlerts: true });
  });
});
