import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { finding, reportWith } from '../../test/reports';
import { createTestContext, organizationId, type TestContext } from '../../test/app';
import { seedTargetRow } from '../../test/vulnerabilities';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { createDatabase } from '../db/client';
import { first } from '../db/rows';
import {
  branches,
  issues,
  jobs,
  organizations,
  projects,
  projectVersions,
  vulnerabilityAlertItems,
  vulnerabilityAlertTargets,
  vulnerabilityDecisions,
  vulnerabilityKev,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { COMMUNITY_VULNERABILITY_LIMITS, type Limits } from '../limits';
import { runUntilIdle } from '../queue/worker';
import { WEBHOOK_URL_AAD } from './deliveries';
import type { ChatDigestMessage } from './chat/messages';
import {
  DIGEST_QUEUE,
  buildDigest,
  digestHandlers,
  ensureDigestScheduled,
  runDigests,
  scheduleDigestAtBoot,
} from './digest';

/** Monday 2026-10-19 09:30 in Europe/Berlin (CEST). */
const MONDAY_BERLIN = new Date('2026-10-19T07:30:00Z');
/** The digest week of MONDAY_BERLIN: [2026-10-12T07:00Z, 2026-10-19T07:00Z). */
const SINCE = new Date('2026-10-12T07:00:00Z');
const UNTIL = new Date('2026-10-19T07:00:00Z');
const DAY = 86_400_000;
const limits: Pick<Limits, 'vulnerabilities'> = { vulnerabilities: COMMUNITY_VULNERABILITY_LIMITS };
const limitsOf = (alerts: boolean, priority: boolean): Pick<Limits, 'vulnerabilities'> => ({
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS, alerts, priority },
});

describe('weekly security digest (6G spec §4)', () => {
  let h: IngestHarness;
  let payments: IngestProject;
  let billing: IngestProject;
  let key: Buffer;

  const hook = async (values: Partial<typeof webhookSubscriptions.$inferInsert> = {}) =>
    (
      await h.ctx.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: h.organizationId,
          kind: 'slack',
          url: 'https://hooks.slack.com/services/T…/…/abcd',
          urlEnc: encryptSecret(
            key,
            'https://hooks.slack.com/services/T1/B1/abcd',
            WEBHOOK_URL_AAD,
          ),
          secretEnc: null,
          events: ['digest.weekly'],
          timezone: 'Europe/Berlin',
          ...values,
        })
        .returning({ id: webhookSubscriptions.id })
    )[0]!.id;
  const digestsOf = async (id: string) =>
    (
      await h.ctx.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.subscriptionId, id))
    )
      .filter((d) => d.event === 'digest.weekly')
      .map((d) => d.payload as ChatDigestMessage);
  const lastWeekOf = async (id: string) =>
    (await h.ctx.db.select().from(webhookSubscriptions).where(eq(webhookSubscriptions.id, id)))[0]
      ?.digestLastWeek;
  /** Makes a project's main-branch issues security issues first seen `daysAgo` before Monday. */
  const securityIssues = async (p: IngestProject, severity: string, daysAgo: number) => {
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(sql`${branches.projectId} = ${p.id} AND ${branches.isMain}`);
    await h.ctx.db
      .update(issues)
      .set({
        quality: 'security',
        severity,
        firstSeenAt: new Date(MONDAY_BERLIN.getTime() - daysAgo * 86_400_000),
      })
      .where(eq(issues.branchId, main!.id));
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    key = encryptionKey(h.ctx.config.secretKey);
    payments = await h.project('acme/payments');
    billing = await h.project('acme/billing');
    // A gate without conditions passes: the quiet week depends on new issues alone. Projects
    // created later keep the default gate, which fails on their first analysis's new issues.
    const call = (method: 'POST' | 'PATCH', url: string, payload: object) =>
      h.ctx.app.inject({ method, url: `/api/v0${url}`, headers: h.orgAdmin.headers, payload });
    const gate = (
      await call('POST', '/quality-gates', { organizationId: h.organizationId, name: 'Lenient' })
    ).json() as { id: string };
    for (const p of [payments, billing]) {
      const res = await call('PATCH', `/projects/${p.id}`, { qualityGateId: gate.id });
      expect(res.statusCode, res.body).toBe(200);
    }
    await payments.ingestOk(
      reportWith({
        projectKey: payments.key,
        findings: [finding({ line: 3 }), finding({ line: 9 })],
      }),
    );
    await billing.ingestOk(reportWith({ projectKey: billing.key, findings: [] }));
  });
  afterAll(async () => {
    await h.close();
  });
  beforeEach(async () => {
    await h.ctx.db.delete(webhookSubscriptions);
  });

  it('is not due before Monday 09:00 local, then sends once per week', async () => {
    await securityIssues(payments, 'high', 2);
    const id = await hook();
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => new Date('2026-10-19T06:59:00Z'),
    });
    expect(await digestsOf(id)).toHaveLength(0);
    expect(await lastWeekOf(id)).toBeNull();
    expect(
      await runDigests({
        db: h.ctx.db,
        limits: () => limits,
        now: () => MONDAY_BERLIN,
      }),
    ).toEqual({
      sent: 1,
      quiet: 0,
      failed: 0,
    });
    // The next hourly run of the same Monday sends nothing more.
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => new Date('2026-10-19T08:30:00Z'),
    });
    const sent = await digestsOf(id);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      week: '2026-W43',
      timezone: 'Europe/Berlin',
      // Anchored at Monday 09:00 local, not at the run's time.
      until: '2026-10-19T07:00:00.000Z',
      since: '2026-10-12T07:00:00.000Z',
      scope: { organization: { id: h.organizationId }, project: null },
      totals: { projects: 2, newSecurity: 2, openSecurity: 2 },
    });
    expect(sent[0]!.totals.newBySeverity).toEqual({
      blocker: 0,
      high: 2,
      medium: 0,
      low: 0,
      info: 0,
    });
    expect(sent[0]!.rows.map((r) => [r.name, r.gate])).toEqual([['acme/payments', 'passed']]);
    expect(sent[0]!.quietProjects).toBe(1);
    expect(sent[0]!.top).toHaveLength(2);
    expect(sent[0]!.top[0]).toMatchObject({
      projectId: payments.id,
      projectName: 'acme/payments',
      severity: 'high',
    });
    expect(await lastWeekOf(id)).toBe('2026-W43');
    // The next Monday is a new week.
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => new Date('2026-10-26T08:00:00Z'),
    });
    expect(await lastWeekOf(id)).toBe('2026-W44');
  });

  it('counts only issues first seen in the last 7 days as new; a quiet week sends nothing', async () => {
    await securityIssues(payments, 'medium', 8);
    const id = await hook();
    expect(
      await runDigests({
        db: h.ctx.db,
        limits: () => limits,
        now: () => MONDAY_BERLIN,
      }),
    ).toEqual({
      sent: 0,
      quiet: 1,
      failed: 0,
    });
    expect(await digestsOf(id)).toHaveLength(0);
    // Marked all the same: a quiet week is not looked at again.
    expect(await lastWeekOf(id)).toBe('2026-W43');
  });

  it('a project webhook covers only its project', async () => {
    await securityIssues(payments, 'high', 1);
    const id = await hook({ projectId: billing.id });
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => MONDAY_BERLIN,
    });
    expect(await digestsOf(id)).toHaveLength(0); // billing is quiet
    const forPayments = await hook({ projectId: payments.id });
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => MONDAY_BERLIN,
    });
    const [digest] = await digestsOf(forPayments);
    expect(digest!.scope.project).toEqual({ id: payments.id, name: 'acme/payments' });
    expect(digest!.totals.projects).toBe(1);
    expect(digest!.quietProjects).toBe(0);
  });

  it('a late run covers the same window: issues after Monday 09:00 wait for next week', async () => {
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(sql`${branches.projectId} = ${payments.id} AND ${branches.isMain}`);
    const paymentsIssues = await h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.branchId, main!.id));
    // One first seen on Sunday, one on Monday 10:00 Berlin (after the window's end).
    await h.ctx.db
      .update(issues)
      .set({ quality: 'security', severity: 'high', firstSeenAt: new Date('2026-10-18T12:00:00Z') })
      .where(eq(issues.id, paymentsIssues[0]!.id));
    await h.ctx.db
      .update(issues)
      .set({ quality: 'security', severity: 'high', firstSeenAt: new Date('2026-10-19T08:00:00Z') })
      .where(eq(issues.id, paymentsIssues[1]!.id));
    const id = await hook();
    // The server was down until Monday 23:00 Berlin.
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => new Date('2026-10-19T21:00:00Z'),
    });
    const [digest] = await digestsOf(id);
    expect(digest).toMatchObject({
      until: '2026-10-19T07:00:00.000Z',
      since: '2026-10-12T07:00:00.000Z',
      totals: { newSecurity: 1, openSecurity: 2 },
    });
    expect(digest!.top.map((t) => t.id)).toEqual([paymentsIssues[0]!.id]);
  });

  it('a failed gate is not a quiet week, even with nothing new', async () => {
    const lastAnalysis = sql`(SELECT last_analysis_id FROM branches WHERE project_id = ${billing.id} AND is_main)`;
    const before = await h.ctx.db.execute<{ gate_status: string | null }>(
      sql`SELECT gate_status FROM analyses WHERE id = ${lastAnalysis}`,
    );
    await h.ctx.db.execute(
      sql`UPDATE analyses SET gate_status = 'failed' WHERE id = ${lastAnalysis}`,
    );
    try {
      const id = await hook({ projectId: billing.id });
      await runDigests({
        db: h.ctx.db,
        limits: () => limits,
        now: () => MONDAY_BERLIN,
      });
      const [digest] = await digestsOf(id);
      expect(digest).toMatchObject({
        totals: { projects: 1, failing: 1, newSecurity: 0 },
        rows: [{ name: 'acme/billing', gate: 'failed', newSecurity: 0 }],
        quietProjects: 0,
        top: [],
      });
    } finally {
      await h.ctx.db.execute(
        sql`UPDATE analyses SET gate_status = ${before.rows[0]?.gate_status ?? null} WHERE id = ${lastAnalysis}`,
      );
    }
  });

  it('skips inactive webhooks, generic ones and webhooks without digest.weekly', async () => {
    await securityIssues(payments, 'high', 1);
    const off = await hook({ active: false });
    const noDigest = await hook({ events: ['gate.failed'] });
    const generic = await hook({
      kind: 'generic',
      url: 'https://hooks.example.com/qualor',
      urlEnc: null,
      secretEnc: encryptSecret(key, 's'.repeat(32), 'webhook_subscriptions.secret_enc'),
    });
    const result = await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => MONDAY_BERLIN,
    });
    expect(result).toEqual({ sent: 0, quiet: 0, failed: 0 });
    for (const id of [off, noDigest, generic]) {
      expect(await digestsOf(id)).toHaveLength(0);
      expect(await lastWeekOf(id)).toBeNull();
    }
  });

  it('two runs at once send one digest (Review Focus 4)', async () => {
    await securityIssues(payments, 'high', 1);
    const ids = await Promise.all(Array.from({ length: 4 }, () => hook()));
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        runDigests({
          db: h.ctx.db,
          limits: () => limits,
          now: () => MONDAY_BERLIN,
        }),
      ),
    );
    for (const id of ids) expect(await digestsOf(id)).toHaveLength(1);
    expect(results.reduce((n, r) => n + r.sent, 0)).toBe(4);
  });

  it('caps the rows at 20 and folds quiet projects into one line', async () => {
    await securityIssues(payments, 'high', 1);
    // 22 projects with new security issues, plus payments; billing is quiet.
    let last: IngestProject | undefined;
    for (let i = 0; i < 22; i++) {
      last = await h.project(`acme/many-${String(i).padStart(2, '0')}`);
      await last.ingestOk(reportWith({ projectKey: last.key, findings: [finding({ line: 1 })] }));
      await securityIssues(last, 'low', 1);
    }
    // The last one's main-branch gate failed.
    await h.ctx.db.execute(sql`
      UPDATE analyses SET gate_status = 'failed'
       WHERE id = (SELECT last_analysis_id FROM branches WHERE project_id = ${last!.id} AND is_main)`);
    const id = await hook();
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => MONDAY_BERLIN,
    });
    const [digest] = await digestsOf(id);
    expect(digest!.totals.projects).toBe(24);
    expect(digest!.rows).toHaveLength(20);
    expect(digest!.moreProjects).toBe(3);
    expect(digest!.quietProjects).toBe(1);
    // A failed gate first, then most new issues (payments has 2), then by name.
    expect(digest!.rows.map((r) => [r.name, r.gate])).toEqual([
      ['acme/many-21', 'failed'],
      ['acme/payments', 'passed'],
      ...Array.from({ length: 18 }, (_, i) => [
        `acme/many-${String(i).padStart(2, '0')}`,
        'passed',
      ]),
    ]);
    expect(digest!.totals.failing).toBe(1);
    expect(digest!.top).toHaveLength(3);
    // The worst severity first.
    expect(digest!.top.map((t) => t.severity)).toEqual(['high', 'high', 'low']);
  });

  it('keeps going when one webhook fails, and retries the failed one next hour (Review Focus 5)', async () => {
    await securityIssues(payments, 'high', 1);
    const broken = await hook();
    // A webhook whose URL no longer decrypts (QUALOR_SECRET_KEY changed) is still queued: the
    // delivery fails it with its own message, the digest never decrypts.
    const otherKey = await hook({
      urlEnc: encryptSecret(
        encryptionKey('x'.repeat(48)),
        'https://hooks.slack.com/services/T1/B1/abcd',
        WEBHOOK_URL_AAD,
      ),
    });
    const fine = await hook();
    // The delivery insert of `broken` fails, as a database error would.
    await h.ctx.db.execute(
      sql.raw(`
      CREATE FUNCTION digest_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.subscription_id = '${broken}' THEN RAISE EXCEPTION 'boom'; END IF;
        RETURN NEW;
      END $$;
      CREATE TRIGGER digest_test_fail BEFORE INSERT ON webhook_deliveries
        FOR EACH ROW EXECUTE FUNCTION digest_test_fail();`),
    );
    const warnings: unknown[] = [];
    try {
      const result = await runDigests({
        db: h.ctx.db,
        limits: () => limits,
        now: () => MONDAY_BERLIN,
        logger: { info: () => undefined, warn: (o: unknown) => warnings.push(o) },
      });
      expect(result).toEqual({ sent: 2, quiet: 0, failed: 1 });
    } finally {
      await h.ctx.db.execute(
        sql.raw(`
        DROP TRIGGER digest_test_fail ON webhook_deliveries;
        DROP FUNCTION digest_test_fail();`),
      );
    }
    expect(await digestsOf(fine)).toHaveLength(1);
    expect(await digestsOf(otherKey)).toHaveLength(1);
    expect(await digestsOf(broken)).toHaveLength(0);
    expect(warnings).toEqual([expect.objectContaining({ webhookId: broken })]);
    // Its week was rolled back with the delivery: the next hourly run sends it.
    expect(await lastWeekOf(broken)).toBeNull();
    await runDigests({
      db: h.ctx.db,
      limits: () => limits,
      now: () => new Date('2026-10-19T08:30:00Z'),
    });
    expect(await digestsOf(broken)).toHaveLength(1);
    expect(await digestsOf(fine)).toHaveLength(1);
  });

  describe('scheduling (R14)', () => {
    const queued = () =>
      h.ctx.db
        .select()
        .from(jobs)
        .where(sql`${jobs.queue} = ${DIGEST_QUEUE} AND ${jobs.status} = 'queued'`);
    beforeEach(async () => {
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, DIGEST_QUEUE));
    });

    it('keeps one run waiting, at minute 1 of the next hour', async () => {
      const before = new Date();
      expect(await scheduleDigestAtBoot(h.ctx.db)).toBe(true);
      expect(await ensureDigestScheduled(h.ctx.db)).toBe(false);
      expect(await scheduleDigestAtBoot(h.ctx.db)).toBe(false);
      const rows = await queued();
      expect(rows).toHaveLength(1);
      const runAt = rows[0]!.runAt;
      expect(runAt.getUTCMinutes()).toBe(1);
      expect(runAt.getUTCSeconds()).toBe(0);
      expect(runAt.getTime()).toBeGreaterThan(before.getTime());
      expect(runAt.getTime() - before.getTime()).toBeLessThanOrEqual(61 * 60_000);
    });

    it("keeps minute 1 in UTC whatever the session's time zone (+05:30)", async () => {
      const url = new URL(h.ctx.config.databaseUrl!);
      url.searchParams.set('options', '-c TimeZone=Asia/Kolkata');
      const kolkata = createDatabase(url.toString(), { max: 1 });
      try {
        const zone = await kolkata.db.execute<{ TimeZone: string }>(sql`SHOW TimeZone`);
        expect(zone.rows[0]!.TimeZone).toBe('Asia/Kolkata');
        expect(await ensureDigestScheduled(kolkata.db)).toBe(true);
      } finally {
        await kolkata.close();
      }
      const rows = await queued();
      expect(rows).toHaveLength(1);
      expect(rows[0]!.runAt.getUTCMinutes()).toBe(1);
      expect(rows[0]!.runAt.getUTCSeconds()).toBe(0);
    });

    it('schedules at once beside many replicas', async () => {
      await Promise.all(Array.from({ length: 5 }, () => ensureDigestScheduled(h.ctx.db)));
      expect(await queued()).toHaveLength(1);
    });

    it('does not schedule beside a running run; the run schedules the next one itself', async () => {
      await h.ctx.db.insert(jobs).values({
        queue: DIGEST_QUEUE,
        concurrencyKey: DIGEST_QUEUE,
        payload: {},
        status: 'running',
      });
      expect(await ensureDigestScheduled(h.ctx.db)).toBe(false);
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, DIGEST_QUEUE));
      // A due job runs the digests (marking the week), then queues the next hour's run.
      await securityIssues(payments, 'high', 1);
      const id = await hook();
      await h.ctx.db.insert(jobs).values({
        queue: DIGEST_QUEUE,
        concurrencyKey: DIGEST_QUEUE,
        payload: {},
      });
      const handlers = digestHandlers({
        db: h.ctx.db,
        limits: () => limits,
        now: () => MONDAY_BERLIN,
      });
      expect(await runUntilIdle(h.ctx.db, handlers, h.ctx.app.log)).toBe(1);
      expect(await digestsOf(id)).toHaveLength(1);
      const next = await queued();
      expect(next).toHaveLength(1);
      expect(next[0]!.runAt.getUTCMinutes()).toBe(1);
      // A retried job in the same hour sends nothing twice.
      await h.ctx.db
        .update(jobs)
        .set({ runAt: sql`now()` })
        .where(eq(jobs.id, next[0]!.id));
      expect(await runUntilIdle(h.ctx.db, handlers, h.ctx.app.log)).toBe(1);
      expect(await digestsOf(id)).toHaveLength(1);
    });
  });
});

describe('the vulnerability section of the weekly digest (0.15 plan 6 C6)', () => {
  let t: TestContext;
  let org: string;
  let otherOrg: string;
  let key: Buffer;
  let n = 0;
  let current: Pick<Limits, 'vulnerabilities'>;

  const hook = async (values: Partial<typeof webhookSubscriptions.$inferInsert> = {}) =>
    first(
      await t.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: org,
          kind: 'slack',
          url: 'https://hooks.slack.com/services/T…/…/abcd',
          urlEnc: encryptSecret(
            key,
            'https://hooks.slack.com/services/T1/B1/abcd',
            WEBHOOK_URL_AAD,
          ),
          secretEnc: null,
          events: ['digest.weekly'],
          timezone: 'Europe/Berlin',
          ...values,
        })
        .returning({ id: webhookSubscriptions.id }),
    ).id;
  /** One run for MONDAY_BERLIN; every webhook's week is unmarked first, so a test can run twice. */
  const send = async () => {
    await t.db.update(webhookSubscriptions).set({ digestLastWeek: null });
    await t.db.delete(webhookDeliveries);
    return runDigests({ db: t.db, limits: () => current, now: () => MONDAY_BERLIN });
  };
  const digestsOf = async (id: string) =>
    (await t.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.subscriptionId, id)))
      .filter((d) => d.event === 'digest.weekly')
      .map((d) => d.payload as ChatDigestMessage);
  const sectionOf = async (id: string) => (await digestsOf(id)).at(-1)?.vulnerabilities;

  const project = async (name: string, organizationId = org) => {
    n += 1;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `dv${n}/app`, name })
        .returning(),
    ).id;
    const main = first(
      await t.db
        .insert(branches)
        .values({ projectId, kind: 'branch', name: 'main', isMain: true })
        .returning(),
    ).id;
    return { projectId, main };
  };
  /** A vulnerability row on a target and its alert item found at `foundAt`. */
  const found = async (
    p: { projectId: string; main: string },
    vulnerabilityId: string,
    options: {
      severity?: 'critical' | 'high' | 'medium';
      foundAt?: Date;
      baseline?: boolean;
      ignored?: boolean;
      on?: string;
      packageName?: string;
    } = {},
  ) => {
    let target: { branchId: string } | { versionId: string } = { branchId: p.main };
    if (options.on !== undefined) {
      const versionId = first(
        await t.db
          .insert(projectVersions)
          .values({
            projectId: p.projectId,
            label: options.on,
            source: 'tag',
            tag: options.on,
            analyzedAt: SINCE,
          })
          .onConflictDoUpdate({
            target: [projectVersions.projectId, projectVersions.label],
            set: { updatedAt: new Date() },
          })
          .returning(),
      ).id;
      target = { versionId };
    }
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      ...target,
      packageName: options.packageName ?? 'lodash',
      vulnerabilityId,
      severity: options.severity ?? 'high',
      ignored: options.ignored ?? false,
    });
    const known = await t.db
      .select()
      .from(vulnerabilityAlertTargets)
      .where(
        'branchId' in target
          ? eq(vulnerabilityAlertTargets.branchId, target.branchId)
          : eq(vulnerabilityAlertTargets.versionId, target.versionId),
      );
    const alertTarget =
      known[0] ??
      first(
        await t.db
          .insert(vulnerabilityAlertTargets)
          .values({ projectId: p.projectId, ...target, dayOne: false })
          .returning(),
      );
    await t.db.insert(vulnerabilityAlertItems).values({
      targetId: alertTarget.id,
      vulnerabilityId,
      baseline: options.baseline ?? false,
      foundAt: options.foundAt ?? new Date(SINCE.getTime() + 2 * DAY),
    });
  };
  const exploited = (vulnerabilityId: string) =>
    t.db
      .insert(vulnerabilityKev)
      .values({ vulnerabilityId, dateAdded: '2026-10-30', listedAt: SINCE })
      .onConflictDoNothing();

  beforeAll(async () => {
    t = await createTestContext();
    org = await organizationId(t, 'default');
    otherOrg = first(
      await t.db.insert(organizations).values({ key: 'other-org', name: 'Other' }).returning(),
    ).id;
    key = encryptionKey(t.config.secretKey);
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await t.db.delete(webhookSubscriptions);
    await t.db.delete(projects);
    await t.db.delete(vulnerabilityKev);
    current = limitsOf(true, true);
  });

  it('lists a High item found inside the window with its project and target', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001');
    const id = await hook();
    expect(await send()).toEqual({ sent: 1, quiet: 0, failed: 0 });
    expect(await sectionOf(id)).toEqual({
      critical: 0,
      high: 1,
      exploited: 0,
      projects: [
        {
          projectId: p.projectId,
          name: 'Api',
          critical: 0,
          high: 1,
          exploited: 0,
          targets: ['main'],
          moreTargets: 0,
        },
      ],
      moreProjects: 0,
    });
  });

  it('leaves out baseline items, items outside [since, until), Medium and triaged rows', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001', { baseline: true });
    await found(p, 'CVE-2026-2002', { foundAt: new Date(SINCE.getTime() - 1) });
    await found(p, 'CVE-2026-2003', { foundAt: UNTIL });
    await found(p, 'CVE-2026-2004', { severity: 'medium' });
    await found(p, 'CVE-2026-2005', { ignored: true });
    await found(p, 'CVE-2026-2006');
    await found(p, 'CVE-2026-2007', { severity: 'critical' });
    await t.db.insert(vulnerabilityDecisions).values({
      projectId: p.projectId,
      branchId: p.main,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2026-2006',
      status: 'wont_fix',
    });
    const id = await hook();
    await send();
    expect(await sectionOf(id)).toMatchObject({
      critical: 1,
      high: 0,
      projects: [{ critical: 1, high: 0 }],
    });
    // The window includes its start.
    await found(p, 'CVE-2026-2008', { foundAt: SINCE });
    await send();
    expect(await sectionOf(id)).toMatchObject({ critical: 1, high: 1 });
  });

  it('covers the organisation, or the one project of a project webhook', async () => {
    const mine = await project('Mine');
    const sibling = await project('Sibling');
    const foreign = await project('Foreign', otherOrg);
    await found(mine, 'CVE-2026-2001');
    await found(sibling, 'CVE-2026-2002');
    await found(foreign, 'CVE-2026-2003');
    const orgWide = await hook();
    const single = await hook({ projectId: mine.projectId });
    await send();
    const wide = await sectionOf(orgWide);
    expect(wide?.projects.map((x) => x.name)).toEqual(['Mine', 'Sibling']);
    expect(wide?.high).toBe(2);
    const own = await sectionOf(single);
    expect(own?.projects.map((x) => x.name)).toEqual(['Mine']);
    expect(own?.high).toBe(1);
  });

  it('counts exploited rows with vuln.priority and has null without it', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001');
    await found(p, 'CVE-2026-2002', { severity: 'critical' });
    await exploited('CVE-2026-2002');
    const id = await hook();
    await send();
    expect(await sectionOf(id)).toMatchObject({
      exploited: 1,
      projects: [{ exploited: 1, critical: 1, high: 1 }],
    });
    current = limitsOf(true, false);
    await send();
    const section = await sectionOf(id);
    expect(section?.exploited).toBeNull();
    expect(section?.projects[0]?.exploited).toBeNull();
    expect(section).toMatchObject({ critical: 1, high: 1 });
  });

  it('adds no vulnerabilities key without vuln.alerts', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001', { severity: 'critical' });
    const id = await hook();
    current = limitsOf(false, true);
    // Without the licence the section is not news: a quiet week.
    expect(await send()).toEqual({ sent: 0, quiet: 1, failed: 0 });
    expect(await digestsOf(id)).toHaveLength(0);
  });

  it('omits the key, not null, when no row qualifies', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001', { baseline: true });
    const message = await buildDigest(
      t.db,
      { organizationId: org, projectId: null },
      { since: SINCE, until: UNTIL, week: '2026-W43', timezone: 'Europe/Berlin' },
      { vulnerabilities: { alerts: true, priority: true } },
    );
    expect('vulnerabilities' in message).toBe(false);
  });

  it('sends a week whose only news is one Critical item; a week with nothing stays quiet', async () => {
    const p = await project('Api');
    const id = await hook();
    expect(await send()).toEqual({ sent: 0, quiet: 1, failed: 0 });
    await found(p, 'CVE-2026-2001', { severity: 'critical' });
    expect(await send()).toEqual({ sent: 1, quiet: 0, failed: 0 });
    const [digest] = await digestsOf(id);
    expect(digest).toMatchObject({ totals: { newSecurity: 0, failing: 0 } });
    expect(digest!.vulnerabilities).toMatchObject({ critical: 1, high: 0 });
  });

  it('orders projects by exploited, critical, high, name; caps them at 10; totals cover all', async () => {
    let v = 2100;
    for (const name of ['Kilo', 'Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf']) {
      await found(await project(name), `CVE-2026-${v++}`);
    }
    const zulu = await project('Zulu');
    await found(zulu, 'CVE-2026-2200');
    await exploited('CVE-2026-2200');
    const yankee = await project('Yankee');
    await found(yankee, 'CVE-2026-2201', { severity: 'critical' });
    await found(yankee, 'CVE-2026-2202', { severity: 'critical' });
    const xray = await project('Xray');
    await found(xray, 'CVE-2026-2203');
    await found(xray, 'CVE-2026-2204');
    const id = await hook();
    await send();
    const section = (await sectionOf(id))!;
    expect(section.projects.map((x) => x.name)).toEqual([
      'Zulu',
      'Yankee',
      'Xray',
      'Alpha',
      'Bravo',
      'Charlie',
      'Delta',
      'Echo',
      'Foxtrot',
      'Golf',
    ]);
    expect(section.moreProjects).toBe(1);
    expect(section).toMatchObject({ critical: 2, high: 11, exploited: 1 });
  });

  it('caps the targets of a project at 5 and counts the rest', async () => {
    const p = await project('Api');
    await found(p, 'CVE-2026-2001');
    for (const label of ['v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7']) {
      await found(p, 'CVE-2026-2001', { on: label });
    }
    const id = await hook();
    await send();
    const [shown] = (await sectionOf(id))!.projects;
    expect(shown).toMatchObject({
      high: 1,
      targets: ['main', 'v1', 'v2', 'v3', 'v4'],
      moreTargets: 3,
    });
  });
});
