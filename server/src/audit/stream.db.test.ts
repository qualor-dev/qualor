import { createHmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, type TestContext } from '../../test/app';
import { instanceSettings } from '../db/schema';
import { ProblemError } from '../http/problem';
import {
  createAuditRecorder,
  appendEvents,
  SYSTEM_ACTOR,
  type AuditActorContext,
} from './recorder';
import { pruneAuditEvents } from './retention';
import {
  auditSettingsView,
  MALFORMED_STREAM_STATE,
  MISSING_STREAM_STATE,
  regenerateStreamSecret,
  updateAuditSettings,
  type AuditSettingsInput,
} from './settings';
import {
  STREAM_BATCH_EVENTS,
  streamAuditEvents,
  streamBackoffMinutes,
  testAuditStream,
  type StreamDeps,
} from './stream';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';

const SECRET = ['whsec', 'stream-test-secret-value'].join('_');
const DAY = 86_400_000;
const START = new Date('2026-09-27T12:00:00.000Z');

const admin: AuditActorContext = {
  actor: {
    type: 'user',
    userId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    username: 'root',
    tokenId: null,
  },
  ip: '10.0.0.5',
  userAgent: 'test',
};

interface Received {
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}

describe('the SIEM stream (rbac-audit.md §14)', () => {
  let t: TestContext;
  let server: Server;
  let port: number;
  let received: Received[];
  let respond: (res: ServerResponse) => void;
  let clock: Date;
  let deps: StreamDeps;
  let warnings: string[];

  const recorder = createAuditRecorder({
    log: QUIET_AUDIT_LOG,
    isActive: () => true,
    now: () => clock,
  });
  const settingsDeps = () => ({ secretKey: t.config.secretKey, recorder });
  const signal = () => new AbortController().signal;
  const configure = (input: AuditSettingsInput) =>
    updateAuditSettings(t.db, settingsDeps(), admin, input);
  const configureStream = async (url: string, secret: string | undefined = SECRET) =>
    (await configure({ stream: { url, ...(secret === undefined ? {} : { secret }) } })).secret;
  const recordAt = (n: number, at: Date) =>
    appendEvents(
      t.db,
      SYSTEM_ACTOR,
      Array.from({ length: n }, () => ({ action: 'auth.sign_out' as const, details: {} })),
      at,
    );
  const record = (n: number) => recordAt(n, clock);
  const setWebhookRow = (value: { allowHttp: boolean; allowInternalHosts: boolean }) =>
    t.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('webhooks', ${JSON.stringify(value)}::jsonb)
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);
  const seqsOf = (r: Received) =>
    (JSON.parse(r.body) as { events: { seq: string }[] }).events.map((e) => e.seq);
  const status = async () => (await auditSettingsView(t.db)).stream!.status;

  beforeAll(async () => {
    t = await createTestContext();
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({
          url: req.url ?? '',
          headers: req.headers,
          body: Buffer.concat(chunks).toString(),
        });
        respond(res);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await t.close();
  });
  beforeEach(async () => {
    await t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
      await tx.execute(sql`DELETE FROM audit_events`);
    });
    await t.db.execute(
      sql`DELETE FROM instance_settings WHERE key IN ('audit', 'audit-chain', 'audit-stream')`,
    );
    // Review Focus 5, spec §19 criterion 12: the local receiver needs both settings.
    await setWebhookRow({ allowHttp: true, allowInternalHosts: true });
    received = [];
    warnings = [];
    respond = (res) => {
      res.statusCode = 204;
      res.end();
    };
    clock = START;
    deps = {
      db: t.db,
      secretKey: t.config.secretKey,
      version: '9.9.9-test',
      active: () => true,
      now: () => clock,
      log: { warn: (message) => warnings.push(message) },
    };
  });

  it('sends batches in seq order with a valid signature, and advances its cursor', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(3);
    expect(await streamAuditEvents(deps, new AbortController().signal)).toEqual({
      sent: 4,
      failed: false,
    });
    expect(received).toHaveLength(1);
    expect(received[0]!.url).toBe('/siem');
    const body = JSON.parse(received[0]!.body) as {
      stream: string;
      test: boolean;
      events: { seq: string; action: string; prevHash: string; hash: string }[];
    };
    expect(body).toMatchObject({ stream: 'qualor-audit', test: false });
    expect(body.events.map((e) => e.seq)).toEqual(['1', '2', '3', '4']); // 1: its own audit.settings_updated
    expect(body.events[0]!.action).toBe('audit.settings_updated');
    expect(body.events[1]!.prevHash).toBe(body.events[0]!.hash);
    const ts = received[0]!.headers['x-qualor-timestamp'] as string;
    expect(ts).toBe(String(Math.floor(START.getTime() / 1000)));
    const expected = createHmac('sha256', SECRET)
      .update(`${ts}.${received[0]!.body}`)
      .digest('hex');
    expect(received[0]!.headers['x-qualor-signature']).toBe(`sha256=${expected}`);
    expect(received[0]!.headers['x-qualor-event']).toBe('audit.events');
    expect(received[0]!.headers['x-qualor-delivery']).toBe('audit-1-4');
    expect(received[0]!.headers['user-agent']).toBe('Qualor-Webhook/9.9.9-test');
    expect(received[0]!.headers['content-type']).toBe('application/json');
    expect(await status()).toMatchObject({
      cursorSeq: '4',
      pending: 0,
      lastSuccessAt: START.toISOString(),
      lastError: null,
    });
    // Nothing new: no request.
    await streamAuditEvents(deps, signal());
    expect(received).toHaveLength(1);
  });

  it('a failing receiver is retried with backoff and gets the backlog in order once it answers', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    respond = (res) => {
      res.statusCode = 503;
      res.end('down');
    };
    await record(2);
    expect(await streamAuditEvents(deps, signal())).toEqual({ sent: 0, failed: true });
    let s = await status();
    expect(s).toMatchObject({
      cursorSeq: '0',
      pending: 3,
      lastError: expect.stringContaining('503'),
      failingSince: START.toISOString(),
    });
    expect(Date.parse(s.nextAttemptAt!) - clock.getTime()).toBe(60_000);
    await streamAuditEvents(deps, signal()); // before nextAttemptAt: no request
    expect(received).toHaveLength(1);
    clock = new Date(clock.getTime() + 61_000);
    await streamAuditEvents(deps, signal());
    expect(received).toHaveLength(2);
    s = await status();
    expect(Date.parse(s.nextAttemptAt!) - clock.getTime()).toBe(120_000);
    expect(s.failingSince).toBe(START.toISOString());
    respond = (res) => {
      res.statusCode = 204;
      res.end();
    };
    await record(1);
    clock = new Date(clock.getTime() + 121_000);
    await streamAuditEvents(deps, signal());
    expect(seqsOf(received.at(-1)!)).toEqual(['1', '2', '3', '4']);
    expect(await status()).toMatchObject({
      cursorSeq: '4',
      lastError: null,
      failingSince: null,
      nextAttemptAt: null,
    });
  });

  it('backs off 1, 2, 4 … minutes, at most 60', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 8, 20].map(streamBackoffMinutes)).toEqual([
      1, 2, 4, 8, 16, 32, 60, 60, 60,
    ]);
  });

  it('counts events that aged out while the receiver failed as skipped', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    respond = (res) => {
      res.statusCode = 503;
      res.end();
    };
    await recordAt(3, new Date(clock.getTime() - 400 * DAY));
    await record(2);
    await streamAuditEvents(deps, signal());
    await pruneAuditEvents(t.db, { retentionDays: 365, now: clock }); // removes seq 1–4, appends seq 7
    respond = (res) => {
      res.statusCode = 204;
      res.end();
    };
    clock = new Date(clock.getTime() + 61_000);
    await streamAuditEvents(deps, signal());
    const batch = JSON.parse(received.at(-1)!.body) as { events: { seq: string }[] };
    expect(batch.events.map((e) => e.seq)).toEqual(['5', '6', '7']);
    expect((await auditSettingsView(t.db)).stream!.status.skipped).toBe(4);
    expect(warnings).toEqual([
      'The audit stream skipped 4 events that retention removed before they were sent',
    ]);
  });

  it('refuses a URL that resolves to a private address unless internal hosts are allowed', async () => {
    await setWebhookRow({ allowHttp: true, allowInternalHosts: true });
    await configureStream('http://siem.internal.example/in');
    await setWebhookRow({ allowHttp: true, allowInternalHosts: false });
    await record(1);
    await streamAuditEvents(
      { ...deps, resolve: async () => [{ address: '10.0.0.1', family: 4 }] },
      signal(),
    );
    expect(received).toHaveLength(0);
    expect((await auditSettingsView(t.db)).stream!.status.lastError).toMatch(
      /not allowed|private|internal/i,
    );
  });

  it('re-checks a stored URL against the webhooks row before every batch', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await setWebhookRow({ allowHttp: true, allowInternalHosts: false });
    await record(1);
    await streamAuditEvents(deps, signal());
    expect(received).toHaveLength(0);
    expect((await status()).lastError).toMatch(/not allowed/);
    await setWebhookRow({ allowHttp: false, allowInternalHosts: true });
    clock = new Date(clock.getTime() + 61_000);
    await streamAuditEvents(deps, signal());
    expect(received).toHaveLength(0);
    expect((await status()).lastError).toMatch(/https/);
  });

  it('starts at the head when first configured, not at the beginning of history', async () => {
    await record(2);
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(1);
    await streamAuditEvents(deps, signal());
    const batch = JSON.parse(received[0]!.body) as { events: { seq: string }[] };
    expect(batch.events.map((e) => e.seq)).toEqual(['3', '4']); // 3: its own audit.settings_updated
  });

  it('starts at the anchor when every event was pruned', async () => {
    await recordAt(3, new Date(clock.getTime() - 400 * DAY));
    await pruneAuditEvents(t.db, { retentionDays: 365, now: clock }); // removes 1–3, appends 4
    // The table empties (as it does once every event has aged out); the anchor row says 3.
    await t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
      await tx.execute(sql`DELETE FROM audit_events`);
    });
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await streamAuditEvents(deps, signal());
    // The chain continues at 4 from the anchor; the stream's first event is that seq 4.
    expect(seqsOf(received[0]!)).toEqual(['4']);
    expect((await status()).skipped).toBe(0);
  });

  it('restarts at the head when the URL changes, and keeps its place otherwise', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(2);
    await streamAuditEvents(deps, signal());
    expect(seqsOf(received[0]!)).toEqual(['1', '2', '3']);
    // Same URL, a new retention period: the cursor stays.
    await configure({ retentionDays: 400 });
    await record(1);
    await streamAuditEvents(deps, signal());
    expect(seqsOf(received[1]!)).toEqual(['4', '5']);
    // Deactivated: nothing is sent; reactivated: the backlog follows in order.
    await configure({ stream: { url: `http://127.0.0.1:${port}/siem`, active: false } });
    await record(1);
    await streamAuditEvents(deps, signal());
    expect(received).toHaveLength(2);
    await configure({ stream: { url: `http://127.0.0.1:${port}/siem`, active: true } });
    await streamAuditEvents(deps, signal());
    expect(seqsOf(received[2]!)).toEqual(['6', '7', '8']);
    // A new URL: its first batch starts with its own configuration.
    await record(3);
    await configure({ stream: { url: `http://127.0.0.1:${port}/other` } });
    await streamAuditEvents(deps, signal());
    expect(received[3]!.url).toBe('/other');
    expect(seqsOf(received[3]!)).toEqual(['12']);
  });

  it('splits a backlog into batches of at most 500 events, in order, in one run', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(STREAM_BATCH_EVENTS + 10);
    expect(await streamAuditEvents(deps, signal())).toEqual({ sent: 511, failed: false });
    expect(received.map((r) => r.headers['x-qualor-delivery'])).toEqual([
      'audit-1-500',
      'audit-501-511',
    ]);
  });

  it('sends nothing while audit-log is inactive', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(1);
    await streamAuditEvents({ ...deps, active: () => false }, signal());
    expect(received).toHaveLength(0);
    expect(await testAuditStream({ ...deps, active: () => false })).toMatchObject({ ok: false });
    expect(received).toHaveLength(0);
  });

  it('sends nothing once the run is aborted', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(1);
    const controller = new AbortController();
    controller.abort();
    expect(await streamAuditEvents(deps, controller.signal)).toEqual({ sent: 0, failed: false });
    expect(received).toHaveLength(0);
  });

  it('sends a signed test batch without moving the cursor', async () => {
    expect(await testAuditStream(deps)).toEqual({
      ok: false,
      status: null,
      excerpt: 'No stream is configured',
    });
    await configureStream(`http://127.0.0.1:${port}/siem`);
    expect(await testAuditStream(deps)).toEqual({ ok: true, status: 204, excerpt: null });
    expect(JSON.parse(received[0]!.body)).toEqual({
      stream: 'qualor-audit',
      test: true,
      events: [],
    });
    expect(received[0]!.headers['x-qualor-delivery']).toBe('audit-test');
    const ts = received[0]!.headers['x-qualor-timestamp'] as string;
    const expected = createHmac('sha256', SECRET)
      .update(`${ts}.${received[0]!.body}`)
      .digest('hex');
    expect(received[0]!.headers['x-qualor-signature']).toBe(`sha256=${expected}`);
    expect((await status()).cursorSeq).toBe('0');
  });

  it('fails closed on a malformed or missing state row: nothing is sent, the view says why', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(2);
    for (const [broken, message] of [
      [{ cursorSeq: 'not-a-seq', skipped: 0 }, MALFORMED_STREAM_STATE],
      [null, MISSING_STREAM_STATE],
    ] as const) {
      if (broken === null) {
        await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'audit-stream'));
      } else {
        await t.db.execute(sql`
          UPDATE instance_settings SET value = ${JSON.stringify(broken)}::jsonb
           WHERE key = 'audit-stream'`);
      }
      expect(await streamAuditEvents(deps, signal())).toEqual({ sent: 0, failed: true });
      expect(received).toHaveLength(0);
      expect(await status()).toMatchObject({ cursorSeq: null, pending: 0, lastError: message });
      if (broken !== null) {
        // The broken row is left as it is, for the operator to see.
        const [row] = await t.db
          .select()
          .from(instanceSettings)
          .where(eq(instanceSettings.key, 'audit-stream'));
        expect(row!.value).toEqual(broken);
      }
    }
    // Reset: saving the stream again restarts it at the head, never at seq 0.
    await configureStream(`http://127.0.0.1:${port}/siem`);
    expect(await streamAuditEvents(deps, signal())).toEqual({ sent: 1, failed: false });
    expect(seqsOf(received[0]!)).toEqual(['4']); // 1–3 are history; 4 is the reset's own event
    expect(await status()).toMatchObject({ cursorSeq: '4', lastError: null });
  });

  it('never stores or logs the full URL or its query, even when the receiver echoes it', async () => {
    const url = `http://127.0.0.1:${port}/siem/in?token=${['sekrit', 'query', 'value'].join('-')}`;
    await configureStream(url);
    // The event records the origin only.
    const [event] = (
      await t.db.execute<{ details: string }>(
        sql`SELECT details::text AS details FROM audit_events WHERE action = 'audit.settings_updated'`,
      )
    ).rows;
    expect(event?.details).toContain(`"streamOrigin": "http://127.0.0.1:${port}"`);
    expect(event?.details).not.toContain('sekrit');
    respond = (res) => {
      res.statusCode = 503;
      res.end(`cannot take ${url} (path ${received.at(-1)?.url ?? ''})`);
    };
    await recordAt(1, new Date(clock.getTime() - 400 * DAY));
    await record(1);
    await streamAuditEvents(deps, signal());
    await pruneAuditEvents(t.db, { retentionDays: 365, now: clock });
    clock = new Date(clock.getTime() + 61_000);
    await streamAuditEvents(deps, signal());
    const tested = await testAuditStream(deps);
    const s = await status();
    expect(s.lastError).toContain('503');
    expect(tested.excerpt).toContain('[stream URL]');
    expect(warnings.length).toBeGreaterThan(0);
    const exposed = [s.lastError ?? '', tested.excerpt ?? '', ...warnings].join('\n');
    for (const part of ['sekrit-query-value', 'token=', '/siem/in']) {
      expect(exposed).not.toContain(part);
    }
    expect(t.logs.join('\n')).not.toContain('sekrit-query-value');
  });

  it('a secret that no longer decrypts is a failure with backoff, not a request', async () => {
    await configureStream(`http://127.0.0.1:${port}/siem`);
    await record(1);
    expect(
      await streamAuditEvents(
        { ...deps, secretKey: 'another-secret-key-of-enough-length' },
        signal(),
      ),
    ).toEqual({ sent: 0, failed: true });
    expect(received).toHaveLength(0);
    expect(await status()).toMatchObject({
      cursorSeq: '0',
      lastError: 'The stream secret no longer decrypts: set a new secret',
    });
  });
});

describe('audit settings (rbac-audit.md §13, §14.1)', () => {
  let t: TestContext;
  let clock: Date;
  const recorder = createAuditRecorder({
    log: QUIET_AUDIT_LOG,
    isActive: () => true,
    now: () => clock,
  });
  const settingsDeps = () => ({ secretKey: t.config.secretKey, recorder });

  beforeAll(async () => {
    t = await createTestContext();
  });
  afterAll(async () => t.close());
  beforeEach(async () => {
    clock = START;
    await t.db.execute(
      sql`DELETE FROM instance_settings WHERE key IN ('audit', 'audit-stream', 'webhooks')`,
    );
  });

  const expect422 = async (input: AuditSettingsInput, path: string) => {
    let error: unknown;
    try {
      await updateAuditSettings(t.db, settingsDeps(), admin, input);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(ProblemError);
    expect((error as ProblemError).status).toBe(422);
    expect((error as ProblemError).code).toBe('VALIDATION_FAILED');
    expect((error as ProblemError).errors?.map((e) => e.path)).toEqual([path]);
  };

  it('defaults to a year and no stream', async () => {
    expect(await auditSettingsView(t.db)).toEqual({ retentionDays: 365, stream: null });
  });

  it('validates the retention period, the URL with the webhooks’ rules, and a given secret', async () => {
    await expect422({ retentionDays: 29 }, 'body.retentionDays');
    await expect422({ retentionDays: 36_501 }, 'body.retentionDays');
    await expect422({ retentionDays: 90.5 }, 'body.retentionDays');
    await expect422({ stream: { url: 'http://siem.example.com/in' } }, 'body.stream.url');
    await expect422({ stream: { url: 'https://10.0.0.1/in' } }, 'body.stream.url');
    await expect422({ stream: { url: 'https://localhost/in' } }, 'body.stream.url');
    await expect422({ stream: { url: 'https://user:pw@siem.example.com/in' } }, 'body.stream.url');
    await expect422({ stream: { url: 'not a url' } }, 'body.stream.url');
    await expect422(
      { stream: { url: 'https://siem.example.com/in', secret: 'short' } },
      'body.stream.secret',
    );
    expect(await auditSettingsView(t.db)).toEqual({ retentionDays: 365, stream: null });
  });

  it('generates a secret once, stores it encrypted, and never shows it again', async () => {
    const { view, secret } = await updateAuditSettings(t.db, settingsDeps(), admin, {
      retentionDays: 400,
      stream: { url: 'https://siem.example.com/in/path?token=abc' },
    });
    expect(secret).toMatch(/^whsec_[0-9A-Za-z]{32}$/);
    expect(view).toMatchObject({
      retentionDays: 400,
      stream: { url: 'https://siem.example.com/in/path?token=abc', active: true, secretSet: true },
    });
    expect(JSON.stringify(view)).not.toContain(secret!);
    expect(JSON.stringify(await auditSettingsView(t.db))).not.toContain(secret!);
    const [row] = await t.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'audit'));
    expect(JSON.stringify(row!.value)).not.toContain(secret!);
    // The event holds the origin only: no path, no query, no secret.
    const events = await t.db.execute<{ details: unknown }>(
      sql`SELECT details FROM audit_events WHERE action = 'audit.settings_updated' ORDER BY seq DESC LIMIT 1`,
    );
    expect(events.rows[0]!.details).toEqual({
      changed: ['retentionDays', 'stream'],
      retentionDays: 400,
      streamOrigin: 'https://siem.example.com',
      streamActive: true,
    });
    // Changing something else returns no secret and keeps the stored one.
    const again = await updateAuditSettings(t.db, settingsDeps(), admin, { retentionDays: 500 });
    expect(again.secret).toBeNull();
    const [after] = await t.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'audit'));
    expect((after!.value as { stream: unknown }).stream).toEqual(
      (row!.value as { stream: unknown }).stream,
    );
  });

  it('a given secret is not returned; regenerating returns a new one once', async () => {
    const given = await updateAuditSettings(t.db, settingsDeps(), admin, {
      stream: { url: 'https://siem.example.com/in', secret: SECRET },
    });
    expect(given.secret).toBeNull();
    const fresh = await regenerateStreamSecret(t.db, settingsDeps(), admin);
    expect(fresh).toMatch(/^whsec_[0-9A-Za-z]{32}$/);
    const events = await t.db.execute<{ action: string; details: unknown }>(
      sql`SELECT action, details FROM audit_events ORDER BY seq DESC LIMIT 1`,
    );
    expect(events.rows[0]).toEqual({ action: 'audit.stream_secret_regenerated', details: {} });
    const dump = JSON.stringify(
      (await t.db.execute(sql`SELECT * FROM audit_events`)).rows.concat(
        (await t.db.execute(sql`SELECT * FROM instance_settings`)).rows,
      ),
    );
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(fresh);
  });

  it('regenerating without a stream is 404', async () => {
    let error: unknown;
    try {
      await regenerateStreamSecret(t.db, settingsDeps(), admin);
    } catch (err) {
      error = err;
    }
    expect((error as ProblemError).status).toBe(404);
  });

  it('removing the stream clears its state', async () => {
    await updateAuditSettings(t.db, settingsDeps(), admin, {
      stream: { url: 'https://siem.example.com/in' },
    });
    const { view } = await updateAuditSettings(t.db, settingsDeps(), admin, { stream: null });
    expect(view.stream).toBeNull();
    const rows = await t.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'audit-stream'));
    expect(rows).toHaveLength(0);
  });
});
