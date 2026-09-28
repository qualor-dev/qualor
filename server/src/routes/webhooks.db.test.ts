import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_PASSWORD, addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  instanceSettings,
  jobs,
  organizations,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from '../webhooks/deliveries';
import {
  MAX_PENDING_DELIVERIES_FOR_REDELIVERY,
  MAX_RECENT_DELIVERIES_FOR_REDELIVERY,
  MAX_WEBHOOKS_PER_ORGANIZATION,
} from './webhooks';

interface Webhook {
  id: string;
  url: string;
  events: string[];
  active: boolean;
  projectId: string | null;
  secret?: string;
}

describe('webhooks API (api.md §3, server step 13)', () => {
  let h: IngestHarness;
  let member: Session;
  let outsider: Session;
  let key: Buffer;
  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    session: Session | Record<string, string> = h.orgAdmin,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: 'headers' in session ? (session as Session).headers : session,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const create = async (body: Record<string, unknown> = {}): Promise<Webhook> => {
    const res = await call('POST', '/webhooks', h.orgAdmin, {
      organizationId: h.organizationId,
      url: 'https://hooks.example.com/qualor',
      events: ['analysis.completed'],
      ...body,
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json() as Webhook;
  };
  const storedSecret = async (id: string) => {
    const [row] = await h.ctx.db
      .select()
      .from(webhookSubscriptions)
      .where(eq(webhookSubscriptions.id, id));
    return decryptSecret(key, row!.secretEnc, WEBHOOK_SECRET_AAD);
  };

  beforeAll(async () => {
    // The tests below insert organisations straight into the table; however many there are,
    // every one stays writable (enterprise.md §8).
    h = await createIngestHarness();
    key = encryptionKey(h.ctx.config.secretKey);
    const m = await createUser(h.ctx, { username: 'hook-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'hook-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
  });
  afterAll(async () => {
    await h.close();
  });

  it('generates a secret, returns it once, stores it encrypted and never logs it', async () => {
    const webhook = await create();
    expect(webhook).toMatchObject({
      url: 'https://hooks.example.com/qualor',
      events: ['analysis.completed'],
      active: true,
      projectId: null,
    });
    expect(webhook.secret).toMatch(/^whsec_[0-9A-Za-z]{32}$/);
    expect(await storedSecret(webhook.id)).toBe(webhook.secret);
    const [row] = await h.ctx.db
      .select()
      .from(webhookSubscriptions)
      .where(eq(webhookSubscriptions.id, webhook.id));
    expect(JSON.stringify(row!.secretEnc)).not.toContain(webhook.secret);
    const read = await call('GET', `/webhooks/${webhook.id}`);
    expect(read.json()).not.toHaveProperty('secret');
    const list = await call('GET', `/webhooks?organizationId=${h.organizationId}`);
    expect(JSON.stringify(list.json())).not.toContain(webhook.secret);
    expect(h.ctx.logs.join('\n')).not.toContain(webhook.secret);
  });

  it('keeps a provided secret without echoing it, and scopes a webhook to one project', async () => {
    const project = await h.project('acme/hooked');
    const webhook = await create({
      secret: 'a-provided-secret-value',
      projectId: project.id,
      events: ['gate.status_changed', 'analysis.completed'],
    });
    expect(webhook).not.toHaveProperty('secret');
    expect(webhook.projectId).toBe(project.id);
    expect(await storedSecret(webhook.id)).toBe('a-provided-secret-value');
  });

  it('validates the body: URL scheme and host, events, secret length, project', async () => {
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'hook-other', name: 'Other' })
      .returning();
    const cases: [Record<string, unknown>, string][] = [
      [{ url: 'http://hooks.example.com/' }, 'body.url'],
      [{ url: 'https://127.0.0.1/' }, 'body.url'],
      [{ url: 'https://169.254.169.254/' }, 'body.url'],
      [{ url: 'https://u:p@hooks.example.com/' }, 'body.url'],
      [{ events: [] }, 'body.events'],
      [{ events: ['analysis.completed', 'analysis.completed'] }, 'body.events'],
      [{ events: ['issue.created'] }, 'body.events.0'],
      [{ secret: 'short' }, 'body.secret'],
      [{ projectId: '019a0000-0000-7000-8000-000000000000' }, 'body.projectId'],
      [{ extra: true }, 'body'],
    ];
    for (const [body, path] of cases) {
      const res = await call('POST', '/webhooks', h.orgAdmin, {
        organizationId: h.organizationId,
        url: 'https://hooks.example.com/',
        events: ['analysis.completed'],
        ...body,
      });
      expect(res.statusCode, JSON.stringify(body)).toBe(422);
      expect(res.json().errors[0].path, JSON.stringify(body)).toBe(path);
    }
    const foreignOrg = await call('POST', '/webhooks', h.orgAdmin, {
      organizationId: other!.id,
      url: 'https://hooks.example.com/',
      events: ['analysis.completed'],
    });
    expect(foreignOrg.statusCode).toBe(404);
  });

  it('allows http and internal hosts once the instance settings do', async () => {
    await h.ctx.db
      .insert(instanceSettings)
      .values({ key: 'webhooks', value: { allowHttp: true, allowInternalHosts: true } });
    try {
      const webhook = await create({ url: 'http://127.0.0.1:9000/hook' });
      expect(webhook.url).toBe('http://127.0.0.1:9000/hook');
    } finally {
      await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'webhooks'));
    }
  });

  it('is for org admins only: 403 for members and admin-less tokens, 404 for outsiders', async () => {
    const webhook = await create();
    expect((await call('GET', `/webhooks/${webhook.id}`, member)).statusCode).toBe(403);
    expect(
      (await call('GET', `/webhooks?organizationId=${h.organizationId}`, member)).statusCode,
    ).toBe(403);
    expect((await call('GET', `/webhooks/${webhook.id}`, outsider)).statusCode).toBe(404);
    expect((await call('DELETE', `/webhooks/${webhook.id}`, outsider)).statusCode).toBe(404);
    const tokenRes = await call('POST', '/tokens', h.orgAdmin, { name: 'w', scopes: ['write'] });
    const token = bearer((tokenRes.json() as { token: string }).token);
    const scoped = await call('GET', `/webhooks/${webhook.id}`, token);
    expect([scoped.statusCode, scoped.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    expect((await call('GET', `/webhooks/${webhook.id}`, {})).statusCode).toBe(401);
  });

  it('changes the URL, events, active flag and secret', async () => {
    const webhook = await create();
    const res = await call('PATCH', `/webhooks/${webhook.id}`, h.orgAdmin, {
      url: 'https://other.example.com/hook',
      events: ['gate.status_changed'],
      active: false,
      secret: 'a-rotated-secret-value',
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      url: 'https://other.example.com/hook',
      events: ['gate.status_changed'],
      active: false,
    });
    expect(await storedSecret(webhook.id)).toBe('a-rotated-secret-value');
    const bad = await call('PATCH', `/webhooks/${webhook.id}`, h.orgAdmin, {
      url: 'https://10.0.0.1/',
    });
    expect(bad.json().errors[0].path).toBe('body.url');
    expect((await call('PATCH', `/webhooks/${webhook.id}`, h.orgAdmin, {})).statusCode).toBe(422);
  });

  it('lists deliveries newest first, redelivers one as a new pending delivery, deletes with history', async () => {
    const webhook = await create();
    const payloads = [{ n: 1 }, { n: 2 }, { n: 3 }];
    const ids: string[] = [];
    for (const payload of payloads) {
      const [row] = await h.ctx.db
        .insert(webhookDeliveries)
        .values({
          subscriptionId: webhook.id,
          event: 'analysis.completed',
          payload,
          status: 'failed',
          attempts: 7,
          responseCode: 500,
          responseExcerpt: 'boom',
        })
        .returning();
      ids.push(row!.id);
    }
    const first = await call('GET', `/webhooks/${webhook.id}/deliveries?limit=2`);
    const page1 = first.json() as { items: { id: string }[]; nextCursor: string };
    expect(page1.items.map((d) => d.id)).toEqual([ids[2], ids[1]]);
    const second = await call(
      'GET',
      `/webhooks/${webhook.id}/deliveries?limit=2&cursor=${encodeURIComponent(page1.nextCursor)}`,
    );
    expect((second.json() as { items: { id: string }[] }).items.map((d) => d.id)).toEqual([ids[0]]);

    const res = await call('POST', `/webhooks/${webhook.id}/deliveries/${ids[0]}/redeliver`);
    expect(res.statusCode, res.body).toBe(202);
    const redelivery = res.json() as { id: string; status: string; attempts: number };
    expect(redelivery).toMatchObject({
      status: 'pending',
      attempts: 0,
      event: 'analysis.completed',
    });
    const [stored] = await h.ctx.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, redelivery.id));
    expect(stored!.payload).toEqual({ n: 1 });
    const queued = await h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, WEBHOOK_QUEUE), eq(jobs.status, 'queued')));
    expect(queued.map((j) => j.payload)).toContainEqual({ deliveryId: redelivery.id });

    const otherHook = await create();
    expect(
      (await call('POST', `/webhooks/${otherHook.id}/deliveries/${ids[0]}/redeliver`)).statusCode,
    ).toBe(404);

    expect((await call('DELETE', `/webhooks/${webhook.id}`)).statusCode).toBe(204);
    expect(
      await h.ctx.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.subscriptionId, webhook.id)),
    ).toEqual([]);
    expect((await call('GET', `/webhooks/${webhook.id}`)).statusCode).toBe(404);
  });

  it(`refuses more than ${MAX_WEBHOOKS_PER_ORGANIZATION} webhooks per organisation (409)`, async () => {
    const [org] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'hook-crowded', name: 'Crowded' })
      .returning();
    await h.ctx.db.insert(webhookSubscriptions).values(
      Array.from({ length: MAX_WEBHOOKS_PER_ORGANIZATION }, () => ({
        organizationId: org!.id,
        url: 'https://hooks.example.com/',
        secretEnc: encryptSecret(key, 'x'.repeat(16), WEBHOOK_SECRET_AAD),
        events: ['analysis.completed'],
      })),
    );
    const adminSession = await login(h.ctx, 'admin', ADMIN_PASSWORD);
    const res = await call('POST', '/webhooks', adminSession, {
      organizationId: org!.id,
      url: 'https://hooks.example.com/',
      events: ['analysis.completed'],
    });
    expect([res.statusCode, res.json().code]).toEqual([409, 'WEBHOOK_LIMIT_REACHED']);
  });

  it('holds the webhook bound under concurrent creations', async () => {
    const [org] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'hook-race', name: 'Race' })
      .returning();
    await h.ctx.db.insert(webhookSubscriptions).values(
      Array.from({ length: MAX_WEBHOOKS_PER_ORGANIZATION - 1 }, () => ({
        organizationId: org!.id,
        url: 'https://hooks.example.com/',
        secretEnc: encryptSecret(key, 'x'.repeat(16), WEBHOOK_SECRET_AAD),
        events: ['analysis.completed'],
      })),
    );
    const adminSession = await login(h.ctx, 'admin', ADMIN_PASSWORD);
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        call('POST', '/webhooks', adminSession, {
          organizationId: org!.id,
          url: 'https://hooks.example.com/',
          events: ['analysis.completed'],
        }),
      ),
    );
    expect(results.map((r) => r.statusCode).sort()).toEqual([201, 409, 409, 409]);
    const [n] = await h.ctx.db
      .select({ n: sql<number>`count(*)::int` })
      .from(webhookSubscriptions)
      .where(eq(webhookSubscriptions.organizationId, org!.id));
    expect(n!.n).toBe(MAX_WEBHOOKS_PER_ORGANIZATION);
  });
  it('stores the normalised URL, and refuses NUL and a secret in any error or log', async () => {
    const webhook = await create({ url: 'HTTPS://Hooks.Example.COM:443/a/../qualor' });
    expect(webhook.url).toBe('https://hooks.example.com/qualor');
    const nul = await call('POST', '/webhooks', h.orgAdmin, {
      organizationId: h.organizationId,
      url: 'https://hooks.example.com/\u0000',
      events: ['analysis.completed'],
    });
    expect([nul.statusCode, nul.json().errors[0].path]).toEqual([422, 'body.url']);
    const provided = 'a-secret-that-must-never-be-echoed';
    const bad = await call('POST', '/webhooks', h.orgAdmin, {
      organizationId: h.organizationId,
      url: 'https://127.0.0.1/',
      secret: provided,
      events: ['analysis.completed'],
    });
    expect(bad.statusCode).toBe(422);
    expect(bad.body).not.toContain(provided);
    const patched = await call('PATCH', `/webhooks/${webhook.id}`, h.orgAdmin, {
      secret: provided,
      events: ['nope'],
    });
    expect(patched.statusCode).toBe(422);
    expect(patched.body).not.toContain(provided);
    expect(h.ctx.logs.join('\n')).not.toContain(provided);
  });

  it('regenerates a secret only on request, returning the new one once', async () => {
    const webhook = await create();
    const res = await call('POST', `/webhooks/${webhook.id}/regenerate-secret`);
    expect(res.statusCode, res.body).toBe(200);
    const regenerated = res.json() as Webhook;
    expect(regenerated.secret).toMatch(/^whsec_[0-9A-Za-z]{32}$/);
    expect(regenerated.secret).not.toBe(webhook.secret);
    expect(regenerated).toMatchObject({ id: webhook.id, url: webhook.url, active: true });
    expect(await storedSecret(webhook.id)).toBe(regenerated.secret);
    expect(JSON.stringify((await call('GET', `/webhooks/${webhook.id}`)).json())).not.toContain(
      regenerated.secret,
    );
    expect(h.ctx.logs.join('\n')).not.toContain(regenerated.secret);
    // An unchanged PATCH keeps the secret.
    await call('PATCH', `/webhooks/${webhook.id}`, h.orgAdmin, { active: false });
    expect(await storedSecret(webhook.id)).toBe(regenerated.secret);
    expect(
      (await call('POST', `/webhooks/${webhook.id}/regenerate-secret`, member)).statusCode,
    ).toBe(403);
    expect(
      (await call('POST', `/webhooks/${webhook.id}/regenerate-secret`, outsider)).statusCode,
    ).toBe(404);
  });

  it('bounds redelivery: pending deliveries and deliveries of the last hour per webhook (429)', async () => {
    const webhook = await create();
    const insert = (n: number, status: 'pending' | 'succeeded') =>
      h.ctx.db
        .insert(webhookDeliveries)
        .values(
          Array.from({ length: n }, (_, i) => ({
            subscriptionId: webhook.id,
            event: 'analysis.completed',
            payload: { i },
            status,
          })),
        )
        .returning({ id: webhookDeliveries.id });
    const [original] = await insert(1, 'succeeded');
    await insert(MAX_PENDING_DELIVERIES_FOR_REDELIVERY - 1, 'pending');
    const redeliver = () =>
      call('POST', `/webhooks/${webhook.id}/deliveries/${original!.id}/redeliver`);
    expect((await redeliver()).statusCode).toBe(202); // the bound-th pending delivery
    const refused = await redeliver();
    expect([refused.statusCode, refused.json().code]).toEqual([429, 'REDELIVERY_LIMIT_REACHED']);
    expect(refused.headers['retry-after']).toBeDefined();
    // Once they settle, the hourly bound still applies.
    await h.ctx.db
      .update(webhookDeliveries)
      .set({ status: 'failed' })
      .where(eq(webhookDeliveries.subscriptionId, webhook.id));
    await insert(MAX_RECENT_DELIVERIES_FOR_REDELIVERY, 'succeeded');
    expect((await redeliver()).statusCode).toBe(429);
    // Pending deliveries whose next attempt is long overdue (their job is gone) do not count
    // against the pending bound.
    await h.ctx.db
      .update(webhookDeliveries)
      .set({ createdAt: sql`now() - interval '61 minutes'` })
      .where(eq(webhookDeliveries.subscriptionId, webhook.id));
    await h.ctx.db.insert(webhookDeliveries).values(
      Array.from({ length: MAX_PENDING_DELIVERIES_FOR_REDELIVERY }, (_, i) => ({
        subscriptionId: webhook.id,
        event: 'analysis.completed',
        payload: { stale: i },
        status: 'pending' as const,
        attempts: 1,
        nextAttemptAt: sql`now() - interval '2 hours'`,
        createdAt: sql`now() - interval '3 hours'`,
      })),
    );
    expect((await redeliver()).statusCode).toBe(202);
    await h.ctx.db
      .update(webhookDeliveries)
      .set({ status: 'failed' })
      .where(eq(webhookDeliveries.subscriptionId, webhook.id));
    // Deliveries older than an hour do not count.
    await h.ctx.db
      .update(webhookDeliveries)
      .set({ createdAt: sql`now() - interval '61 minutes'` })
      .where(eq(webhookDeliveries.subscriptionId, webhook.id));
    expect((await redeliver()).statusCode).toBe(202);
  });

  it('counts only redeliveries against the hourly bound, not the deliveries analyses create', async () => {
    const webhook = await create();
    // What the ingestion stage stores: each delivery created as its analysis finishes (the
    // payload's finishedAt is the same transaction's statement time).
    const finished = new Date(Date.now() - 30 * 60_000);
    const stage = await h.ctx.db
      .insert(webhookDeliveries)
      .values(
        Array.from({ length: MAX_RECENT_DELIVERIES_FOR_REDELIVERY + 20 }, (_, i) => ({
          subscriptionId: webhook.id,
          event: 'analysis.completed',
          payload: { id: `analysis-${i}`, finishedAt: finished.toISOString() },
          status: 'succeeded' as const,
          createdAt: finished,
        })),
      )
      .returning({ id: webhookDeliveries.id });
    const redeliver = (id: string) =>
      call('POST', `/webhooks/${webhook.id}/deliveries/${id}/redeliver`);
    // An hour of busy analyses leaves room for redeliveries...
    expect((await redeliver(stage[0]!.id)).statusCode).toBe(202);
    // ... until redeliveries themselves reach the bound (settled at once here, so the pending
    // bound is out of the way).
    const settle = () =>
      h.ctx.db
        .update(webhookDeliveries)
        .set({ status: 'succeeded' })
        .where(eq(webhookDeliveries.subscriptionId, webhook.id));
    await settle();
    for (let i = 1; i < MAX_RECENT_DELIVERIES_FOR_REDELIVERY; i++) {
      const res = await redeliver(stage[i % stage.length]!.id);
      expect(res.statusCode, `redelivery ${i + 1}`).toBe(202);
      await settle();
    }
    const refused = await redeliver(stage[0]!.id);
    expect([refused.statusCode, refused.json().code]).toEqual([429, 'REDELIVERY_LIMIT_REACHED']);
  });

  it('serialises concurrent redeliveries against the pending bound', async () => {
    const webhook = await create();
    const [original] = await h.ctx.db
      .insert(webhookDeliveries)
      .values({
        subscriptionId: webhook.id,
        event: 'analysis.completed',
        payload: {},
        status: 'failed',
      })
      .returning({ id: webhookDeliveries.id });
    const results = await Promise.all(
      Array.from({ length: MAX_PENDING_DELIVERIES_FOR_REDELIVERY + 3 }, () =>
        call('POST', `/webhooks/${webhook.id}/deliveries/${original!.id}/redeliver`),
      ),
    );
    expect(results.filter((r) => r.statusCode === 202)).toHaveLength(
      MAX_PENDING_DELIVERIES_FOR_REDELIVERY,
    );
    expect(results.filter((r) => r.statusCode === 429)).toHaveLength(3);
  });
});
