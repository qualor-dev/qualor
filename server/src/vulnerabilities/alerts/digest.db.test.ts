import { asc, eq, inArray, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  addMember,
  createTestContext,
  createUser,
  organizationId,
  type TestContext,
} from '../../../test/app';
import {
  MAIL_ON,
  payloadOf,
  PUBLIC_URL,
  queued,
  watch,
  type OutboxRow,
} from '../../../test/notify';
import { recheckTargets, recordThenRecheck } from '../../../test/vulnerability-alerts';
import { purlFor, seedCheck, seedInventory, seedTargetRow } from '../../../test/vulnerabilities';
import { encryptionKey, encryptSecret } from '../../crypto/secrets';
import { uuidv7 } from '../../db/ids';
import { LOCKS } from '../../db/locks';
import { first } from '../../db/rows';
import {
  branches,
  instanceSettings,
  jobs,
  mailMessages,
  organizations,
  projects,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  vulnerabilityAlertItems,
  vulnerabilityAlertTargets,
  vulnerabilityDecisions,
  vulnerabilityKev,
  vulnerabilityMatches,
  vulndbDatasets,
  webhookDeliveries,
  webhookSubscriptions,
} from '../../db/schema';
import { COMMUNITY_VULNERABILITY_LIMITS, type Limits } from '../../limits';
import { notifyDeps } from '../../notifications/deps';
import { VULNERABILITY_UNSUBSCRIBE_API } from '../../notifications/links';
import { enqueue } from '../../queue/queue';
import { runUntilIdle } from '../../queue/worker';
import { WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from '../../webhooks/deliveries';
import { RECHECK_QUEUE } from '../recheck';
import {
  DIGEST_QUEUE,
  ensureVulnerabilityDigestScheduled,
  MAX_WEBHOOK_VULNERABILITIES,
  runVulnerabilityDigest,
  scheduleVulnerabilityDigestAtBoot,
} from './digest';
import { sendExploitedAlerts } from './exploited';
import { alertHandlers, type AlertDeps } from './jobs';

const KIND = 'notify.vulnerabilities-digest';
const EVENT = 'vulnerabilities.found';
const OLD = 'CVE-2026-2000';
const NEW = 'CVE-2026-2001';
const NEW2 = 'CVE-2026-2002';
const NEW3 = 'CVE-2026-2003';
const NEW4 = 'CVE-2026-2004';
const NEW5 = 'CVE-2026-2005';
const NEW6 = 'CVE-2026-2006';
const NOTHING = { mails: 0, deliveries: 0, items: 0 };
const HOUR = 3_600_000;
const START = new Date('2099-01-01T00:00:00Z');
const BUILT = new Date('2098-12-31T12:00:00Z');
const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

const limitsOf = (alerts: boolean, priority: boolean): Pick<Limits, 'vulnerabilities'> => ({
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS, alerts, priority },
});

describe('the daily vulnerability digest', () => {
  let t: TestContext;
  let org: string;
  let otherOrg: string;
  let mira: string;
  let alex: string;
  let sam: string;
  let n = 0;
  let now: Date;
  let limits: Pick<Limits, 'vulnerabilities'>;

  const deps = (over: Partial<AlertDeps> = {}): AlertDeps => ({
    ...notifyDeps(t.config),
    db: t.db,
    limits: () => limits,
    now: () => now,
    logger: silent,
    ...over,
  });
  /** One run of the job, an hour after the last one. */
  const run = (over: Partial<AlertDeps> = {}) => {
    now = new Date(now.getTime() + HOUR);
    return runVulnerabilityDigest(deps(over));
  };
  const recordAndRecheck = () => recordThenRecheck(t.db, run, () => now);

  const newProject = async (name = 'Api') => {
    n += 1;
    const key = `dig${n}/api`;
    const projectId = first(
      await t.db.insert(projects).values({ organizationId: org, key, name }).returning(),
    ).id;
    await t.db.insert(projectVulnerabilitySettings).values({ projectId });
    const main = first(
      await t.db
        .insert(branches)
        .values({ projectId, kind: 'branch', name: 'main', isMain: true })
        .returning(),
    ).id;
    await seedCheck(t.db, {
      projectId,
      branchId: main,
      baselineAt: START,
      checkedAt: START,
      basis: 'analysis-1',
    });
    await seedInventory(t.db, { projectId, branchId: main });
    const vulnerable = (
      vulnerabilityId: string,
      options: {
        packageName?: string;
        severity?: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
        ignored?: boolean;
        title?: string | null;
        fixedVersion?: string | null;
      } = {},
    ) =>
      seedTargetRow(t.db, {
        projectId,
        branchId: main,
        packageName: options.packageName ?? 'lodash',
        vulnerabilityId,
        ignored: options.ignored ?? false,
        severity: options.severity ?? 'high',
        ...(options.title !== undefined && { title: options.title }),
        ...(options.fixedVersion !== undefined && { fixedVersion: options.fixedVersion }),
      });
    return { projectId, key, main, vulnerable };
  };

  /** Records the targets of every project so far, and seeds them, with mail of it cleared. */
  const pastDayOne = async () => {
    await recordAndRecheck();
    await run();
    await t.db.delete(mailMessages);
  };

  const mails = () => queued(t.db, KIND);
  const textOf = (row: OutboxRow) => payloadOf(row, t.config.secretKey).text;

  const items = () =>
    t.db
      .select({
        vulnerabilityId: vulnerabilityAlertItems.vulnerabilityId,
        baseline: vulnerabilityAlertItems.baseline,
        digestedAt: vulnerabilityAlertItems.digestedAt,
      })
      .from(vulnerabilityAlertItems)
      .orderBy(asc(vulnerabilityAlertItems.vulnerabilityId));
  const digested = async () =>
    Object.fromEntries((await items()).map((i) => [i.vulnerabilityId, i.digestedAt]));

  const secretEnc = () =>
    encryptSecret(encryptionKey(t.config.secretKey), 'whsec_digest-test', WEBHOOK_SECRET_AAD);
  const subscribe = async (values: Partial<typeof webhookSubscriptions.$inferInsert> = {}) =>
    first(
      await t.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: org,
          url: 'https://receiver.example/hook',
          secretEnc: secretEnc(),
          events: [EVENT],
          ...values,
        })
        .returning({ id: webhookSubscriptions.id }),
    ).id;
  const deliveries = () =>
    t.db
      .select({
        subscriptionId: webhookDeliveries.subscriptionId,
        event: webhookDeliveries.event,
        status: webhookDeliveries.status,
        payload: webhookDeliveries.payload,
      })
      .from(webhookDeliveries)
      .orderBy(asc(webhookDeliveries.subscriptionId));

  const useDatabaseBuiltAt = async (builtAt: Date) => {
    const id = uuidv7();
    await t.db.insert(vulndbDatasets).values({
      id,
      kind: 'trivy',
      digest: `sha256:${'a'.repeat(64)}`,
      sizeBytes: 1,
      builtAt,
      source: 'official',
      status: 'ready',
      chunkCount: 1,
    });
    await t.db
      .insert(instanceSettings)
      .values({ key: 'vulndb_state', value: { currentDatasetId: id } })
      .onConflictDoUpdate({
        target: instanceSettings.key,
        set: { value: { currentDatasetId: id } },
      });
  };

  beforeAll(async () => {
    t = await createTestContext({ config: { ...MAIL_ON } });
    org = await organizationId(t, 'default');
    otherOrg = first(
      await t.db
        .insert(organizations)
        .values({ key: 'elsewhere', name: 'Elsewhere' })
        .returning({ id: organizations.id }),
    ).id;
    mira = (await createUser(t, { username: 'mira', email: 'mira@example.com' })).id;
    alex = (await createUser(t, { username: 'alex', email: 'alex@example.com' })).id;
    sam = (await createUser(t, { username: 'sam', email: 'sam@example.com' })).id;
    for (const user of [mira, alex, sam]) await addMember(t, org, user, 'viewer');
  });
  beforeEach(async () => {
    // alertScope reads every project: each test starts from an empty instance.
    await t.db.delete(projects);
    await t.db.delete(webhookSubscriptions);
    await t.db.delete(vulnerabilityKev);
    await t.db.delete(mailMessages);
    await t.db.delete(jobs);
    await t.db
      .delete(instanceSettings)
      .where(inArray(instanceSettings.key, ['vulndb', 'vulndb_state']));
    await t.db.delete(vulndbDatasets);
    now = START;
    limits = limitsOf(true, true);
  });
  afterAll(async () => {
    await t.close();
  });

  describe('who gets a digest', () => {
    it('sends each watcher one digest, about their projects only', async () => {
      const p = await newProject('Payments');
      const q = await newProject('Search');
      await watch(t.db, mira, p.projectId);
      await watch(t.db, alex, p.projectId);
      await watch(t.db, sam, q.projectId);
      await pastDayOne();
      await p.vulnerable(NEW);
      await q.vulnerable(NEW2);

      expect(await run()).toEqual({ mails: 3, deliveries: 0, items: 2 });
      const [toAlex, toMira, toSam] = await mails();
      expect([toAlex!.toAddress, toMira!.toAddress, toSam!.toAddress]).toEqual([
        'alex@example.com',
        'mira@example.com',
        'sam@example.com',
      ]);
      expect([toAlex!.userId, toMira!.userId, toSam!.userId]).toEqual([alex, mira, sam]);
      for (const row of [toAlex!, toMira!]) {
        expect(row.subject).toContain('New vulnerabilities in Payments');
        expect(textOf(row)).toContain(NEW);
        expect(textOf(row)).not.toContain(NEW2);
      }
      expect(toSam!.subject).toContain('New vulnerabilities in Search');
      expect(textOf(toSam!)).toContain(NEW2);
      expect(textOf(toSam!)).not.toContain(NEW);
    });

    it('gives a person one email across every project they watch', async () => {
      const api = await newProject('Api');
      const billing = await newProject('Billing');
      await watch(t.db, mira, billing.projectId);
      await watch(t.db, mira, api.projectId);
      await watch(t.db, alex, billing.projectId);
      await pastDayOne();
      await api.vulnerable(NEW);
      await billing.vulnerable(NEW2);

      expect(await run()).toEqual({ mails: 2, deliveries: 0, items: 2 });
      const [toAlex, toMira] = await mails();
      expect(toAlex!.subject).toContain('New vulnerabilities in Billing');
      expect(toMira!.subject).toContain('New vulnerabilities in 2 projects');
      const text = textOf(toMira!);
      expect(text).toContain(NEW);
      expect(text).toContain(NEW2);
      expect(text.indexOf('Api')).toBeLessThan(text.indexOf('Billing'));
    });

    it('carries the one-click stop of the vulnerability emails and the database date', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await useDatabaseBuiltAt(BUILT);
      await pastDayOne();
      await p.vulnerable(NEW);
      await run();

      const [mail] = await mails();
      const payload = payloadOf(mail!, t.config.secretKey);
      expect(payload.headers?.['List-Unsubscribe']).toContain(VULNERABILITY_UNSUBSCRIBE_API);
      expect(payload.html).toContain('/unsubscribe/vulnerabilities#t=');
      expect(payload.html).toContain(`/projects/${p.projectId}/vulnerabilities`);
      expect(payload.text).toContain('Vulnerability data from 2098-12-31.');
    });

    it('does not fail, and names no date, without a current database', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW);
      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 1 });
      expect(textOf((await mails())[0]!)).not.toContain('Vulnerability data from');
    });
  });

  describe('what a digest lists', () => {
    it('stays silent until a target is seeded, then lists only what came after', async () => {
      const p = await newProject();
      await p.vulnerable(OLD);
      await watch(t.db, mira, p.projectId);

      expect(await run()).toEqual(NOTHING);
      expect(await items()).toEqual([]);
      await recheckTargets(t.db, now);

      expect(await run()).toEqual(NOTHING);
      expect(await items()).toEqual([{ vulnerabilityId: OLD, baseline: true, digestedAt: null }]);
      expect(await mails()).toEqual([]);

      await p.vulnerable(NEW, { packageName: 'axios' });
      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 1 });
      const text = textOf((await mails())[0]!);
      expect(text).toContain(NEW);
      expect(text).not.toContain(OLD);
      expect(await items()).toEqual([
        { vulnerabilityId: OLD, baseline: true, digestedAt: null },
        { vulnerabilityId: NEW, baseline: false, digestedAt: now },
      ]);
    });

    it('lists only High and Critical, open and not ignored, and marks all of them', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW, { packageName: 'a', severity: 'high' });
      await p.vulnerable(NEW2, { packageName: 'b', severity: 'critical' });
      await p.vulnerable(NEW3, { packageName: 'c', severity: 'medium' });
      await p.vulnerable(NEW4, { packageName: 'd', severity: 'high', ignored: true });
      await p.vulnerable(NEW5, { packageName: 'e', severity: 'high' });
      await p.vulnerable(NEW6, { packageName: 'f', severity: 'unknown' });
      await t.db.insert(vulnerabilityDecisions).values({
        projectId: p.projectId,
        packageName: 'e',
        vulnerabilityId: NEW5,
        branchId: p.main,
        status: 'wont_fix',
      });

      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 6 });
      const text = textOf((await mails())[0]!);
      expect(text.indexOf(NEW2)).toBeGreaterThan(-1);
      expect(text.indexOf(NEW2)).toBeLessThan(text.indexOf(NEW));
      for (const other of [NEW3, NEW4, NEW5, NEW6]) expect(text).not.toContain(other);
      expect(await digested()).toEqual({
        [NEW]: now,
        [NEW2]: now,
        [NEW3]: now,
        [NEW4]: now,
        [NEW5]: now,
        [NEW6]: now,
      });
    });

    it('queues no mail on a Medium-only day, yet marks the item', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW, { severity: 'medium' });

      expect(await run()).toEqual({ mails: 0, deliveries: 0, items: 1 });
      expect(await mails()).toEqual([]);
      expect(await digested()).toEqual({ [NEW]: now });
    });

    it('queues nothing on a second run: the items are digested', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await subscribe();
      await pastDayOne();
      await p.vulnerable(NEW);

      expect(await run()).toEqual({ mails: 1, deliveries: 1, items: 1 });
      const firstRun = now;
      expect(await run()).toEqual(NOTHING);
      expect(await mails()).toHaveLength(1);
      expect(await deliveries()).toHaveLength(1);
      expect(await digested()).toEqual({ [NEW]: firstRun });
    });

    it('leaves an item found after the cutoff for the next day', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW);
      // The KEV job, on a clock ahead of this run's, is the one that finds it.
      const later = new Date(now.getTime() + 3 * HOUR);
      await sendExploitedAlerts(deps({ now: () => later }));

      expect(await run()).toEqual(NOTHING);
      expect(await mails()).toEqual([]);
      expect(await digested()).toEqual({ [NEW]: null });

      now = later;
      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 1 });
      expect(await digested()).toEqual({ [NEW]: now });
    });

    it('marks an item when nobody watches it, and a later watcher gets no mail for it', async () => {
      const p = await newProject();
      await pastDayOne();
      await p.vulnerable(NEW);

      expect(await run()).toEqual({ mails: 0, deliveries: 0, items: 1 });
      await watch(t.db, mira, p.projectId);
      expect(await run()).toEqual(NOTHING);
      expect(await mails()).toEqual([]);
    });

    it('marks an item when email is off, and still creates the deliveries', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await subscribe();
      await pastDayOne();
      await p.vulnerable(NEW);

      const off = deps();
      expect(await run({ config: { ...off.config, smtp: null } })).toEqual({
        mails: 0,
        deliveries: 1,
        items: 1,
      });
      expect(await mails()).toEqual([]);
      expect(await digested()).toEqual({ [NEW]: now });
    });

    it('refuses a second digest on the same UTC day by its dedupe key, as a backstop', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW);
      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 1 });

      await p.vulnerable(NEW2, { packageName: 'axios' });
      expect(await run()).toEqual({ mails: 0, deliveries: 0, items: 1 });
      const [mail] = await mails();
      expect(mail!.dedupeKey).toBe(`vulnerabilities.digest:${mira}:2099-01-01`);
      expect(await mails()).toHaveLength(1);

      // The next UTC day has its own key.
      now = new Date('2099-01-02T05:00:00Z');
      await p.vulnerable(NEW3, { packageName: 'qs' });
      expect(await run()).toEqual({ mails: 1, deliveries: 0, items: 1 });
      expect((await mails()).map((m) => m.dedupeKey)).toEqual([
        `vulnerabilities.digest:${mira}:2099-01-01`,
        `vulnerabilities.digest:${mira}:2099-01-02`,
      ]);
    });
  });

  describe('the vulnerabilities.found webhook', () => {
    it('sends one delivery per project and generic subscription that lists the event', async () => {
      const p = await newProject('Payments');
      const q = await newProject('Search');
      const wanted = await subscribe();
      const onlyP = await subscribe({ projectId: p.projectId });
      await subscribe({ projectId: q.projectId });
      await subscribe({ events: ['analysis.completed', 'gate.status_changed'] });
      await subscribe({ active: false });
      await subscribe({ organizationId: otherOrg });
      await subscribe({
        kind: 'slack',
        url: 'https://hooks.slack.com/services/T/…',
        urlEnc: secretEnc(),
        secretEnc: null,
      });
      await useDatabaseBuiltAt(BUILT);
      await t.db.insert(vulnerabilityKev).values({ vulnerabilityId: NEW, dateAdded: '2026-10-30' });
      await pastDayOne();
      await p.vulnerable(NEW, {
        packageName: 'axios',
        severity: 'critical',
        title: 'Remote code execution',
        fixedVersion: '1.2.0',
      });
      await p.vulnerable(NEW2, { packageName: 'qs', severity: 'high' });
      // Medium only: no digest row, so this project gets no delivery.
      await q.vulnerable(NEW3, { severity: 'medium' });

      expect(await run()).toEqual({ mails: 0, deliveries: 2, items: 3 });

      const url = `${PUBLIC_URL}/projects/${p.projectId}/vulnerabilities`;
      const payload = {
        project: { id: p.projectId, key: p.key, name: 'Payments', url },
        database: { builtAt: BUILT.toISOString() },
        vulnerabilities: [
          {
            vulnerabilityId: NEW,
            severity: 'critical',
            title: 'Remote code execution',
            packageName: 'axios',
            installedVersions: ['1.0.0'],
            fixedVersion: '1.2.0',
            exploited: { dateAdded: '2026-10-30' },
            targets: ['main'],
          },
          {
            vulnerabilityId: NEW2,
            severity: 'high',
            title: null,
            packageName: 'qs',
            installedVersions: ['1.0.0'],
            fixedVersion: null,
            exploited: null,
            targets: ['main'],
          },
        ],
        more: 0,
      };
      expect(await deliveries()).toEqual(
        [wanted, onlyP].sort().map((subscriptionId) => ({
          subscriptionId,
          event: EVENT,
          status: 'pending',
          payload,
        })),
      );
      expect(
        await t.db.select({ id: jobs.id }).from(jobs).where(eq(jobs.queue, WEBHOOK_QUEUE)),
      ).toHaveLength(2);
    });

    it('answers a null url without a public URL and a null date without a database', async () => {
      const p = await newProject();
      await subscribe();
      await pastDayOne();
      await p.vulnerable(NEW);
      const off = deps();

      await run({ config: { ...off.config, publicUrl: null } });
      const [delivery] = await deliveries();
      expect(delivery!.payload).toMatchObject({
        project: { url: null },
        database: { builtAt: null },
      });
    });

    it('without vuln.priority says exploited is null, in the payload and the mail', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await subscribe();
      await t.db.insert(vulnerabilityKev).values({ vulnerabilityId: NEW, dateAdded: '2026-10-30' });
      limits = limitsOf(true, false);
      await pastDayOne();
      await p.vulnerable(NEW);

      expect(await run()).toEqual({ mails: 1, deliveries: 1, items: 1 });
      const [delivery] = await deliveries();
      expect(delivery!.payload).toMatchObject({
        vulnerabilities: [{ vulnerabilityId: NEW, exploited: null }],
      });
      expect(textOf((await mails())[0]!)).not.toContain('Exploited');
    });

    it('marks an exploited row in the mail with vuln.priority', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await t.db.insert(vulnerabilityKev).values({ vulnerabilityId: NEW, dateAdded: '2026-10-30' });
      await pastDayOne();
      await p.vulnerable(NEW);

      await run();
      expect(textOf((await mails())[0]!)).toContain('Exploited');
    });

    it('lists at most 1 000 vulnerabilities a project, and counts the rest in more', async () => {
      const p = await newProject();
      await subscribe();
      await pastDayOne();
      const count = MAX_WEBHOOK_VULNERABILITIES + 5;
      const ids = Array.from({ length: count }, (_, i) => `CVE-2099-${String(100_000 + i)}`);
      const purl = purlFor('big', '1.0.0');
      await t.db
        .insert(vulnerabilityMatches)
        .values(
          ids.map((vulnerabilityId) => ({ purl, vulnerabilityId, severity: 'high' as const })),
        );
      await t.db.insert(targetVulnerabilities).values(
        ids.map((vulnerabilityId) => ({
          projectId: p.projectId,
          branchId: p.main,
          ecosystem: 'npm',
          packageName: 'big',
          packageVersion: '1.0.0',
          purl,
          vulnerabilityId,
        })),
      );

      expect(await run()).toEqual({ mails: 0, deliveries: 1, items: count });
      const [delivery] = await deliveries();
      const payload = delivery!.payload as { vulnerabilities: unknown[]; more: number };
      expect(payload.vulnerabilities).toHaveLength(MAX_WEBHOOK_VULNERABILITIES);
      expect(payload.more).toBe(5);
    });
  });

  describe('without the feature', () => {
    it('without vuln.alerts sends nothing, marks nothing and forgets the alert memory', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await subscribe();
      await p.vulnerable(OLD);
      await pastDayOne();
      await p.vulnerable(NEW, { packageName: 'axios' });
      expect(await items()).toHaveLength(1);

      limits = limitsOf(false, true);
      expect(await run()).toEqual(NOTHING);
      expect(await mails()).toEqual([]);
      expect(await deliveries()).toEqual([]);
      expect(await t.db.select().from(vulnerabilityAlertTargets)).toEqual([]);
      expect(await items()).toEqual([]);
    });
  });

  describe('what a run leaves behind', () => {
    it('asks for a re-check of the projects whose targets it recorded, and only then', async () => {
      const p = await newProject();
      const rechecks = () =>
        t.db
          .select({ status: jobs.status, payload: jobs.payload })
          .from(jobs)
          .where(eq(jobs.queue, RECHECK_QUEUE));

      await run();
      expect(await rechecks()).toEqual([
        { status: 'queued', payload: { projectIds: [p.projectId] } },
      ]);

      await t.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      await recheckTargets(t.db, now);
      await run();
      expect(await rechecks()).toEqual([]);
    });

    it('sends each watcher one digest and each subscription one delivery when runs overlap', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await watch(t.db, alex, p.projectId);
      const webhook = await subscribe();
      await pastDayOne();
      await p.vulnerable(NEW);
      now = new Date(now.getTime() + HOUR);

      const results = await Promise.all([
        runVulnerabilityDigest(deps()),
        runVulnerabilityDigest(deps()),
      ]);
      expect(results.map((r) => r.mails).sort()).toEqual([0, 2]);
      expect(results.map((r) => r.deliveries).sort()).toEqual([0, 1]);
      expect((await mails()).map((m) => m.toAddress)).toEqual([
        'alex@example.com',
        'mira@example.com',
      ]);
      expect((await deliveries()).map((d) => d.subscriptionId)).toEqual([webhook]);
    });

    it.each([
      ['the digest', () => runVulnerabilityDigest],
      ['the exploited emails', () => sendExploitedAlerts],
    ] as const)('%s takes its clock only after it holds the lock', async (_name, job) => {
      let calls = 0;
      const clocked = deps({
        now: () => {
          calls += 1;
          return now;
        },
      });
      let release!: () => void;
      const released = new Promise<void>((resolve) => (release = resolve));
      let held!: () => void;
      const isHeld = new Promise<void>((resolve) => (held = resolve));
      const holder = t.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
        held();
        await released;
      });
      await isHeld;

      const running = job()(clocked);
      try {
        await vi.waitFor(
          async () => {
            const waiting = await t.db.execute(sql`
              SELECT 1 FROM pg_locks
               WHERE locktype = 'advisory' AND NOT granted AND objid = ${LOCKS.vulnerabilityAlerts}
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`);
            expect(waiting.rows).toHaveLength(1);
          },
          { timeout: 30_000, interval: 20 },
        );
        expect(calls).toBe(0);
      } finally {
        // Also on a failed assertion: a lock left held would hang every later test.
        release();
      }
      await holder;
      await running;
      expect(calls).toBe(1);
    });
  });

  describe('the schedule', () => {
    const scheduled = () =>
      t.db
        .select({
          status: jobs.status,
          key: jobs.concurrencyKey,
          runAt: jobs.runAt,
          attempts: jobs.attempts,
          lastError: jobs.lastError,
        })
        .from(jobs)
        .where(eq(jobs.queue, DIGEST_QUEUE))
        .orderBy(asc(jobs.runAt));

    it.each([
      ['2026-11-10T05:00:00.000Z', '2026-11-10T06:00:00.000Z'],
      ['2026-11-10T07:00:00.000Z', '2026-11-11T06:00:00.000Z'],
      ['2026-11-10T06:00:00.000Z', '2026-11-11T06:00:00.000Z'],
      ['2026-11-10T05:59:59.999Z', '2026-11-10T06:00:00.000Z'],
      ['2026-12-31T23:30:00.000Z', '2027-01-01T06:00:00.000Z'],
    ])('at %s the next run is at %s', async (at, expected) => {
      expect(await ensureVulnerabilityDigestScheduled(t.db, new Date(at))).toBe(true);
      expect(await scheduled()).toEqual([
        {
          status: 'queued',
          key: DIGEST_QUEUE,
          runAt: new Date(expected),
          attempts: 0,
          lastError: null,
        },
      ]);
    });

    it('is not moved by the session time zone', async () => {
      await t.db.transaction(async (tx) => {
        await tx.execute(sql`SET LOCAL TIME ZONE 'Asia/Kolkata'`);
        expect(await ensureVulnerabilityDigestScheduled(tx, new Date('2026-11-10T05:00:00Z'))).toBe(
          true,
        );
      });
      expect((await scheduled()).map((j) => j.runAt)).toEqual([
        new Date('2026-11-10T06:00:00.000Z'),
      ]);
    });

    it('leaves one queued job, however often it is asked for', async () => {
      const at = new Date('2026-11-10T05:00:00Z');
      expect(await ensureVulnerabilityDigestScheduled(t.db, at)).toBe(true);
      expect(await ensureVulnerabilityDigestScheduled(t.db, at)).toBe(false);
      expect(await scheduleVulnerabilityDigestAtBoot(t.db)).toBe(false);
      expect(await scheduled()).toHaveLength(1);
    });

    it('at boot queues the next run, at 06:00 UTC and in the future', async () => {
      expect(await scheduleVulnerabilityDigestAtBoot(t.db)).toBe(true);
      const [job] = await scheduled();
      expect(job!.runAt.toISOString()).toMatch(/T06:00:00\.000Z$/);
      const database = await t.db.execute<{ late: boolean }>(
        sql`SELECT ${job!.runAt.toISOString()}::timestamptz > now() AS late`,
      );
      expect(database.rows[0]!.late).toBe(true);
    });

    it('through the handler: runs, logs one line and queues the next run', async () => {
      const p = await newProject();
      await watch(t.db, mira, p.projectId);
      await pastDayOne();
      await p.vulnerable(NEW);
      await enqueue(t.db, { queue: DIGEST_QUEUE, concurrencyKey: DIGEST_QUEUE, payload: {} });
      const infos: unknown[] = [];
      const logger = { info: (fields: unknown) => void infos.push(fields), warn: () => undefined };
      now = new Date(now.getTime() + HOUR);

      await runUntilIdle(t.db, alertHandlers(deps({ logger })), silent);

      expect(await mails()).toHaveLength(1);
      expect(infos).toEqual([{ component: 'vulnerabilities', mails: 1, deliveries: 0, items: 1 }]);
      const rows = await scheduled();
      expect(rows.map((j) => j.status)).toEqual(['succeeded', 'queued']);
      expect(rows[1]!.runAt.toISOString()).toMatch(/T06:00:00\.000Z$/);
    });

    it('lets an error reach the queue, and still queues the next run', async () => {
      await enqueue(t.db, { queue: DIGEST_QUEUE, concurrencyKey: DIGEST_QUEUE, payload: {} });
      const handlers = alertHandlers(
        deps({
          limits: () => {
            throw new Error('no limits today');
          },
        }),
      );

      await runUntilIdle(t.db, handlers, silent);

      const rows = await scheduled();
      expect(rows).toHaveLength(2);
      expect(rows[0]).toMatchObject({
        status: 'queued',
        attempts: 1,
        lastError: 'no limits today',
      });
      expect(rows[1]).toMatchObject({ status: 'queued', attempts: 0, lastError: null });
      expect(rows[1]!.runAt.toISOString()).toMatch(/T06:00:00\.000Z$/);
    });
  });
});
