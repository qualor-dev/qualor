import { createHmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { finding, reportWith } from '../../test/reports';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  analyses,
  instanceSettings,
  jobs,
  organizations,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { AnalysisFailure, MAX_WARNINGS, type IngestionStage } from '../ingest/process';
import { DEFAULT_STAGES } from '../ingest/stages';
import { runUntilIdle } from '../queue/worker';
import { MAX_WEBHOOKS_PER_ORGANIZATION } from '../routes/webhooks';
import { webhookHandlers } from './deliver';
import { WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from './deliveries';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

interface Delivery {
  subscriptionId: string;
  event: string;
  payload: Record<string, unknown>;
}

describe('webhook ingestion stage (server step 13, after gateStage)', () => {
  let h: IngestHarness;
  let project: IngestProject;
  let other: IngestProject;
  let orgWide: { id: string; secret: string };
  let onlyOther: string;
  const secrets = new Map<string, string>();
  let inactive: string;
  let server: Server;
  let port: number;
  const received: { headers: IncomingMessage['headers']; body: string }[] = [];
  let day = 10;

  const call = (method: 'GET' | 'POST' | 'PATCH', url: string, payload?: unknown) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const hook = async (body: Record<string, unknown>) => {
    const res = await call('POST', '/webhooks', {
      organizationId: h.organizationId,
      url: `http://127.0.0.1:${port}/hook`,
      events: ['analysis.completed', 'gate.status_changed'],
      ...body,
    });
    expect(res.statusCode, res.body).toBe(201);
    const created = res.json() as { id: string; secret: string };
    secrets.set(created.id, created.secret);
    return created;
  };
  /** Ingests one analysis a day later than the last; `failing` adds a finding the gate fails on. */
  const analyse = async (target: IngestProject, failing: boolean) => {
    day += 1;
    return target.ingestOk(
      reportWith({
        projectKey: target.key,
        analysisDate: `2026-09-${String(day).padStart(2, '0')}T10:00:00Z`,
        findings: failing ? [finding({ line: 3 })] : [],
      }),
    );
  };
  const deliveriesOf = async (analysisId: string): Promise<Delivery[]> => {
    const rows = await h.ctx.db.select().from(webhookDeliveries);
    return rows
      .filter((r) => (r.payload as { id?: string }).id === analysisId)
      .map((r) => ({
        subscriptionId: r.subscriptionId,
        event: r.event,
        payload: r.payload as Record<string, unknown>,
      }));
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({ headers: req.headers, body: Buffer.concat(chunks).toString() });
        res.writeHead(200).end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
    await h.ctx.db
      .insert(instanceSettings)
      .values({ key: 'webhooks', value: { allowHttp: true, allowInternalHosts: true } });
    project = await h.project('acme/webhooked');
    other = await h.project('acme/unhooked');
    // A gate that fails on any issue, so a finding flips the status.
    const gate = (
      await call('POST', '/quality-gates', {
        organizationId: h.organizationId,
        name: 'No issues',
      })
    ).json() as { id: string };
    await call('POST', `/quality-gates/${gate.id}/conditions`, {
      metric: 'issues',
      operator: 'gt',
      threshold: 0,
    });
    await call('PATCH', `/projects/${project.id}`, { qualityGateId: gate.id });
    orgWide = await hook({});
    onlyOther = (await hook({ projectId: other.id })).id;
    inactive = (await hook({ active: false })).id;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await h.close();
  });

  it('enqueues analysis.completed with the exact GET /analyses/{id} payload, plus project and branch', async () => {
    const analysisId = await analyse(project, true);
    const deliveries = await deliveriesOf(analysisId);
    expect(deliveries.map((d) => [d.subscriptionId, d.event]).sort()).toEqual(
      [
        [orgWide.id, 'analysis.completed'],
        [orgWide.id, 'gate.status_changed'],
      ].sort(),
    );
    expect(
      deliveries.some((d) => d.subscriptionId === onlyOther || d.subscriptionId === inactive),
    ).toBe(false);
    const api = (await call('GET', `/analyses/${analysisId}`)).json() as Record<string, unknown>;
    const completed = deliveries.find((d) => d.event === 'analysis.completed')!;
    const { project: p, branch, ...analysis } = completed.payload;
    const { branch: apiBranch, ...apiAnalysis } = api;
    expect(analysis).toEqual(apiAnalysis);
    expect(branch).toEqual({ ...(apiBranch as object), isMain: true });
    expect(p).toEqual({ id: project.id, key: 'acme/webhooked', name: 'acme/webhooked' });
    expect(completed.payload).toMatchObject({ status: 'succeeded', gateStatus: 'failed' });
    const [stored] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(completed.payload.finishedAt).toBe(stored!.finishedAt!.toISOString());
    const changed = deliveries.find((d) => d.event === 'gate.status_changed')!;
    expect(changed.payload).toMatchObject({ previousGateStatus: null, gateStatus: 'failed' });
  });

  it('sends gate.status_changed only when the gate status changes', async () => {
    const same = await analyse(project, true);
    expect((await deliveriesOf(same)).map((d) => d.event)).toEqual(['analysis.completed']);
    const flipped = await analyse(project, false);
    const changed = (await deliveriesOf(flipped)).find((d) => d.event === 'gate.status_changed');
    expect(changed?.payload).toMatchObject({ previousGateStatus: 'failed', gateStatus: 'passed' });
  });

  it('covers a project-scoped webhook for its own project only', async () => {
    const analysisId = await analyse(other, false);
    expect((await deliveriesOf(analysisId)).map((d) => d.subscriptionId).sort()).toEqual(
      [orgWide.id, orgWide.id, onlyOther, onlyOther].sort(),
    );
  });

  it('enqueues nothing when the ingestion rolls back, and sends nothing before the worker runs', async () => {
    const before = await h.ctx.db.select().from(webhookDeliveries);
    // A stage after the webhook stage rejects the report: the whole transaction rolls back.
    const reject: IngestionStage = {
      name: 'reject',
      run: async () => {
        throw new AnalysisFailure('TEST_REJECTED', 'rejected after the webhook stage');
      },
    };
    const analysisId = await project.ingest(
      reportWith({ projectKey: project.key, analysisDate: '2026-09-28T10:00:00Z' }),
      [...DEFAULT_STAGES, reject],
    );
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(row!.error).toMatchObject({ code: 'TEST_REJECTED' });
    expect(await h.ctx.db.select().from(webhookDeliveries)).toHaveLength(before.length);
    expect(received).toEqual([]);
  });

  it('delivers the enqueued events signed with the generated secret (api.md §6.5)', async () => {
    await runUntilIdle(
      h.ctx.db,
      webhookHandlers({ db: h.ctx.db, secretKey: h.ctx.config.secretKey }),
      silent,
    );
    const sent = await h.ctx.db.select().from(webhookDeliveries);
    // Every delivery enqueued above was sent once (this project: 2 + 1 + 2, the other one: 4);
    // the inactive webhook got nothing.
    expect(received).toHaveLength(sent.length);
    for (const request of received) {
      const timestamp = String(request.headers['x-qualor-timestamp']);
      const [delivery] = await h.ctx.db
        .select()
        .from(webhookDeliveries)
        .where(inArray(webhookDeliveries.id, [String(request.headers['x-qualor-delivery'])]));
      const secret = secrets.get(delivery!.subscriptionId)!;
      const expected = createHmac('sha256', secret)
        .update(`${timestamp}.${request.body}`)
        .digest('hex');
      expect(request.headers['x-qualor-signature']).toBe(`sha256=${expected}`);
      expect(JSON.parse(request.body)).toEqual(delivery!.payload);
    }
    const pending = await h.ctx.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.status, 'pending'));
    expect(pending).toEqual([]);
  });
});

describe('webhook ingestion stage: filters, isolation and bounds', () => {
  let h: IngestHarness;
  let project: IngestProject;
  let otherOrg: string;
  let day = 10;
  const secretEnc = () =>
    encryptSecret(encryptionKey(h.ctx.config.secretKey), 'whsec_stage-test', WEBHOOK_SECRET_AAD);
  const subscribe = async (
    values: Partial<typeof webhookSubscriptions.$inferInsert> = {},
  ): Promise<string> =>
    (
      await h.ctx.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: h.organizationId,
          url: 'https://receiver.example/hook',
          secretEnc: secretEnc(),
          events: ['analysis.completed', 'gate.status_changed'],
          ...values,
        })
        .returning({ id: webhookSubscriptions.id })
    )[0]!.id;
  const nextDate = () => {
    day += 1;
    return `2026-09-${String(day).padStart(2, '0')}T10:00:00Z`;
  };
  const deliveriesFor = async (analysisId: string) =>
    (await h.ctx.db.select().from(webhookDeliveries)).filter(
      (r) => (r.payload as { id?: string }).id === analysisId,
    );

  beforeAll(async () => {
    h = await createIngestHarness();
    project = await h.project('acme/filtered');
    otherOrg = (
      await h.ctx.db
        .insert(organizations)
        .values({ key: 'elsewhere', name: 'Elsewhere' })
        .returning({ id: organizations.id })
    )[0]!.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it("filters by the webhook's events, skips inactive webhooks and other organisations", async () => {
    const completedOnly = await subscribe({ events: ['analysis.completed'] });
    const gateOnly = await subscribe({ events: ['gate.status_changed'] });
    const inactive = await subscribe({ active: false });
    const foreign = await subscribe({ organizationId: otherOrg });
    const analysisId = await project.ingestOk(
      reportWith({ projectKey: project.key, analysisDate: nextDate() }),
    );
    const rows = await deliveriesFor(analysisId);
    expect(rows.map((r) => [r.subscriptionId, r.event]).sort()).toEqual(
      [
        [completedOnly, 'analysis.completed'],
        [gateOnly, 'gate.status_changed'],
      ].sort(),
    );
    expect(rows.some((r) => r.subscriptionId === inactive || r.subscriptionId === foreign)).toBe(
      false,
    );
    // Each delivery has its own queued job on the webhook queue, committed with the analysis.
    const queued = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, WEBHOOK_QUEUE));
    const jobDeliveries = queued.map((j) => (j.payload as { deliveryId: string }).deliveryId);
    for (const row of rows) expect(jobDeliveries).toContain(row.id);
    // No secret and nothing of the webhook itself in the payload.
    for (const row of rows) {
      const text = JSON.stringify(row.payload);
      expect(text).not.toContain('whsec_');
      expect(text).not.toContain('receiver.example');
      expect(text).not.toContain(otherOrg);
    }
    await h.ctx.db
      .delete(webhookSubscriptions)
      .where(inArray(webhookSubscriptions.id, [completedOnly, gateOnly, inactive, foreign]));
  });

  it('sends nothing for a failed analysis (STALE_ANALYSIS)', async () => {
    const hook = await subscribe();
    const before = (await h.ctx.db.select().from(webhookDeliveries)).length;
    const stale = await project.ingest(
      reportWith({ projectKey: project.key, analysisDate: '2026-09-01T10:00:00Z' }),
    );
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, stale));
    expect(row).toMatchObject({ status: 'failed', error: { code: 'STALE_ANALYSIS' } });
    expect(await h.ctx.db.select().from(webhookDeliveries)).toHaveLength(before);
    await h.ctx.db.delete(webhookSubscriptions).where(eq(webhookSubscriptions.id, hook));
  });

  it('fans out to 50 webhooks with capped warnings in every payload', async () => {
    const hooks: string[] = [];
    for (let i = 0; i < MAX_WEBHOOKS_PER_ORGANIZATION; i += 1) hooks.push(await subscribe());
    const warnings = Array.from({ length: 150 }, (_, i) => ({
      code: 'W',
      message: `warning ${i}`,
    }));
    const analysisId = await project.ingestOk(
      reportWith({ projectKey: project.key, analysisDate: nextDate(), warnings }),
    );
    const rows = await deliveriesFor(analysisId);
    // The branch's gate status is unchanged since the first test: analysis.completed only.
    expect(rows).toHaveLength(MAX_WEBHOOKS_PER_ORGANIZATION);
    expect(new Set(rows.map((r) => r.subscriptionId))).toEqual(new Set(hooks));
    const api = (
      await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/analyses/${analysisId}`,
        headers: h.orgAdmin.headers,
      })
    ).json() as { warnings: unknown[] };
    expect(api.warnings).toHaveLength(MAX_WARNINGS);
    for (const row of rows) {
      expect((row.payload as { warnings: unknown[] }).warnings).toEqual(api.warnings);
    }
    const queued = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, WEBHOOK_QUEUE));
    const ids = new Set(queued.map((j) => (j.payload as { deliveryId: string }).deliveryId));
    for (const row of rows) expect(ids.has(row.id)).toBe(true);
  });
});
