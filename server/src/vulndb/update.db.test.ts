import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestContext, createUser, type TestContext } from '../../test/app';
import { testSmtp } from '../../test/mail';
import {
  metadataJson,
  trivyArchive,
  UPDATED_AT,
} from '../../../packages/shared/test/trivy-archive';
import { instanceSettings, jobs, mailMessages, users, vulndbDatasets } from '../db/schema';
import { notifyIfVulndbStale } from '../mail/alerts/vulndb-stale';
import { runUntilIdle } from '../queue/worker';
import type { fetchHttpsFile, fetchLayerDescriptor, HttpsFile, openBlob, OciProblem } from './oci';
import { PRIORITY_STATE_KEY, readPriorityState, updatePriorityState } from './priority/state';
import {
  OFFICIAL_EPSS_URL,
  OFFICIAL_KEV_URL,
  OFFICIAL_REPOSITORY,
  writeVulndbSettings,
} from './settings';
import { readVulndbState, updateVulndbState, VULNDB_UPDATE_QUEUE } from './state';
import { currentDataset } from './store';
import type * as Store from './store';
import {
  ensureVulndbScheduled,
  requestVulndbUpdateNow,
  runVulndbUpdate,
  scheduleVulndbAtBoot,
  vulndbUpdateHandlers,
  type VulndbUpdateDeps,
} from './update';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

/** pruneDatasets, made to fail while `failing` is set. */
const prune = vi.hoisted(() => ({ failing: false }));
vi.mock('./store', async (importOriginal) => {
  const actual = await importOriginal<typeof Store>();
  return {
    ...actual,
    pruneDatasets: async (...args: Parameters<typeof actual.pruneDatasets>) => {
      if (prune.failing) throw new Error('prune failed');
      return actual.pruneDatasets(...args);
    },
  };
});
const DAY_MS = 24 * 60 * 60 * 1000;
const BUILT = Date.parse(UPDATED_AT);
const digestOf = (bytes: Buffer): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

interface FakeRegistry {
  archive: Buffer | OciProblem;
  descriptors: number;
  blobs: number;
  refs: string[];
  auths: unknown[];
  fetchLayerDescriptor: typeof fetchLayerDescriptor;
  openBlob: typeof openBlob;
}

/** A registry that serves one archive (or one problem), and counts what it was asked. */
function fakeRegistry(initial: Buffer | OciProblem): FakeRegistry {
  const fake: FakeRegistry = {
    archive: initial,
    descriptors: 0,
    blobs: 0,
    refs: [] as string[],
    auths: [] as unknown[],
    fetchLayerDescriptor: async (ref, auth) => {
      fake.descriptors += 1;
      fake.refs.push(ref);
      fake.auths.push(auth);
      if (!Buffer.isBuffer(fake.archive)) return fake.archive;
      return { digest: digestOf(fake.archive), size: fake.archive.length };
    },
    openBlob: async () => {
      fake.blobs += 1;
      const bytes = fake.archive as Buffer;
      return (async function* () {
        await Promise.resolve();
        yield bytes;
      })();
    },
  };
  return fake;
}

describe('vulnerability database updates', () => {
  let t: TestContext;
  let now: Date;
  let rechecks: unknown[];
  const deps = (
    registry: FakeRegistry,
    more: Partial<VulndbUpdateDeps> = {},
  ): VulndbUpdateDeps => ({
    db: t.db,
    config: { ...t.config, vulndb: { internalHosts: new Set() } },
    fetchLayerDescriptor: registry.fetchLayerDescriptor,
    openBlob: registry.openBlob,
    enqueueRecheck: (_db, scope) => {
      rechecks.push(scope);
      return Promise.resolve();
    },
    now: () => now,
    logger: silent,
    ...more,
  });
  /** Queues one run now and works the queue until it is idle once. */
  const runOnce = async (
    registry: FakeRegistry,
    more: Partial<VulndbUpdateDeps> = {},
  ): Promise<void> => {
    await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await requestVulndbUpdateNow(t.db);
    await runUntilIdle(t.db, vulndbUpdateHandlers(deps(registry, more)), silent);
  };
  const stale = async () =>
    (
      await t.db
        .select({ subject: mailMessages.subject, to: mailMessages.toAddress })
        .from(mailMessages)
        .where(eq(mailMessages.kind, 'vulndb.stale'))
    ).map((r) => r.to);
  const queued = () =>
    t.db.execute<{ secs: number }>(sql`
      SELECT extract(epoch FROM run_at - now())::int AS secs FROM jobs
       WHERE queue = ${VULNDB_UPDATE_QUEUE} AND status = 'queued' ORDER BY run_at`);
  const settings = (patch: Parameters<typeof writeVulndbSettings>[1]) =>
    t.db.transaction((tx) => writeVulndbSettings(tx, patch, t.config.secretKey));

  beforeAll(async () => {
    t = await createTestContext({ config: { smtp: testSmtp(2525) } });
    await t.db.update(users).set({ email: 'admin@example.com' }).where(eq(users.id, t.adminId));
    await createUser(t, {
      username: 'vulndb-ops',
      email: 'ops@example.com',
      isInstanceAdmin: true,
    });
    await createUser(t, { username: 'vulndb-nomail', isInstanceAdmin: true });
  });
  beforeEach(async () => {
    await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await t.db.delete(mailMessages);
    await t.db.delete(vulndbDatasets);
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, PRIORITY_STATE_KEY));
    await t.db.execute(sql`DELETE FROM vulnerability_kev`);
    await t.db.execute(sql`DELETE FROM vulnerability_epss`);
    now = new Date(BUILT + DAY_MS);
    rechecks = [];
  });
  afterAll(async () => {
    await t.close();
  });

  it('stores a new digest, makes it current and schedules the next run', async () => {
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    expect(registry.refs).toEqual([OFFICIAL_REPOSITORY]);
    expect(rechecks).toEqual([{ all: true }]);
    const state = await readVulndbState(t.db);
    const current = await currentDataset(t.db, state);
    expect(current).toMatchObject({ status: 'ready', source: 'official' });
    expect(current?.digest).toBe(digestOf(registry.archive as Buffer));
    expect(state).toMatchObject({
      lastCheckAt: now.toISOString(),
      nextCheckAt: new Date(now.getTime() + 6 * 3_600_000).toISOString(),
      lastError: null,
    });
    // The next run waits one interval (6 h by default).
    const next = (await queued()).rows;
    expect(next).toHaveLength(1);
    expect(next[0]!.secs).toBeGreaterThan(6 * 3600 - 60);
  });

  it('queues the re-check before it prunes; a failed prune is logged, not a lastError', async () => {
    const registry = fakeRegistry(trivyArchive());
    const warnings: string[] = [];
    prune.failing = true;
    try {
      await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      await requestVulndbUpdateNow(t.db);
      await runUntilIdle(
        t.db,
        vulndbUpdateHandlers({
          ...deps(registry),
          logger: {
            info: () => undefined,
            warn: (...args: unknown[]) => void warnings.push(String(args[1])),
          },
        }),
        silent,
      );
    } finally {
      prune.failing = false;
    }
    expect(rechecks).toEqual([{ all: true }]);
    const state = await readVulndbState(t.db);
    expect(state.lastError).toBeNull();
    expect((await currentDataset(t.db, state))?.digest).toBe(digestOf(registry.archive as Buffer));
    expect(warnings).toContain('old vulnerability datasets were not pruned');
  });

  it('downloads nothing when the digest is the current one', async () => {
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    now = new Date(now.getTime() + 3_600_000);
    await updateVulndbState(t.db, (s) => ({ ...s, lastError: { code: 'X', message: 'old' } }));
    await runOnce(registry);
    expect(registry.descriptors).toBe(2);
    expect(registry.blobs).toBe(1);
    expect(rechecks).toEqual([{ all: true }]);
    expect(await t.db.select().from(vulndbDatasets)).toHaveLength(1);
    expect(await readVulndbState(t.db)).toMatchObject({
      lastCheckAt: now.toISOString(),
      lastError: null,
    });
  });

  it('keeps the previous dataset current and records the problem when the source fails', async () => {
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    const before = (await readVulndbState(t.db)).currentDatasetId;
    registry.archive = { code: 'UNREACHABLE', message: 'The registry did not answer' };
    await runOnce(registry);
    expect(rechecks).toHaveLength(1);
    expect(await readVulndbState(t.db)).toMatchObject({
      currentDatasetId: before,
      lastError: { code: 'UNREACHABLE', message: 'The registry did not answer' },
    });
    // A hostile archive (Version 1): stored nothing, current stays, the code is the store's.
    registry.archive = trivyArchive({ metadata: metadataJson(1) });
    await runOnce(registry);
    expect(await readVulndbState(t.db)).toMatchObject({
      currentDatasetId: before,
      lastError: { code: 'INVALID_DATABASE' },
    });
    expect(await t.db.select().from(vulndbDatasets)).toHaveLength(1);
    // A blob that does not match its digest.
    const good = trivyArchive();
    registry.archive = good;
    registry.fetchLayerDescriptor = (async () => ({
      digest: `sha256:${'a'.repeat(64)}`,
      size: good.length,
    })) as typeof fetchLayerDescriptor;
    await runOnce(registry);
    expect(await readVulndbState(t.db)).toMatchObject({
      currentDatasetId: before,
      lastError: { code: 'DIGEST_MISMATCH' },
    });
    expect(rechecks).toHaveLength(1);
  });

  it("never touches the re-check's error", async () => {
    const recheckError = { code: 'DISK', message: 'The vulnerability database cannot be written' };
    await updateVulndbState(t.db, (s) => ({ ...s, lastRecheckError: recheckError }));
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    expect(await readVulndbState(t.db)).toMatchObject({
      lastError: null,
      lastRecheckError: recheckError,
    });
    registry.archive = { code: 'UNREACHABLE', message: 'The registry did not answer' };
    await runOnce(registry);
    expect(await readVulndbState(t.db)).toMatchObject({
      lastError: { code: 'UNREACHABLE' },
      lastRecheckError: recheckError,
    });
  });

  it('survives a source that throws', async () => {
    const registry = fakeRegistry(trivyArchive());
    registry.fetchLayerDescriptor = (() => {
      throw new Error('boom');
    }) as typeof fetchLayerDescriptor;
    await runOnce(registry);
    expect((await readVulndbState(t.db)).lastError).toEqual({
      code: 'UPDATE_FAILED',
      message: 'The update failed. See the server log',
    });
    expect((await queued()).rows).toHaveLength(1);
  });

  it('a stop cuts a slow download: the run ends at once, records nothing and retries in a minute', async () => {
    const registry = fakeRegistry(trivyArchive());
    const stop = new AbortController();
    let signalled: AbortSignal | undefined;
    let downloading!: () => void;
    const started = new Promise<void>((resolve) => {
      downloading = resolve;
    });
    registry.openBlob = async (_ref, _digest, _auth, opts) => {
      await Promise.resolve();
      signalled = opts.signal;
      return (async function* () {
        yield Buffer.alloc(1024);
        downloading();
        // A download that stalls: it fails on its own after 8 s, or at once when cut.
        await new Promise<void>((_resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('stalled')), 8_000);
          opts.signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              reject(new Error('cut'));
            },
            { once: true },
          );
        });
      })();
    };
    await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await requestVulndbUpdateNow(t.db);
    const run = runUntilIdle(
      t.db,
      vulndbUpdateHandlers({ ...deps(registry), shutdown: stop.signal }),
      silent,
    );
    await started;
    const stoppedAt = Date.now();
    stop.abort();
    await run;
    expect(Date.now() - stoppedAt).toBeLessThan(3_000);
    expect(signalled).toBe(stop.signal);
    expect(await readVulndbState(t.db)).toMatchObject({
      currentDatasetId: null,
      lastCheckAt: null,
      lastError: null,
    });
    expect(await t.db.select().from(vulndbDatasets)).toEqual([]);
    expect(rechecks).toEqual([]);
    // The next server (or another replica) checks again in a minute.
    const next = (await queued()).rows;
    expect(next).toHaveLength(1);
    expect(next[0]!.secs).toBeLessThanOrEqual(60);
  });

  it('does nothing but schedule when switched off', async () => {
    await settings({ enabled: false });
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    expect(registry.descriptors).toBe(0);
    expect(rechecks).toEqual([]);
    expect(await readVulndbState(t.db)).toMatchObject({ lastCheckAt: null, lastError: null });
    expect((await queued()).rows).toHaveLength(1);
  });

  it('only checks staleness for an uploaded file, and moves the check times on', async () => {
    await settings({ source: { kind: 'upload' } });
    await updateVulndbState(t.db, (s) => ({
      ...s,
      lastCheckAt: '2026-01-01T00:00:00.000Z',
      nextCheckAt: '2026-01-01T06:00:00.000Z',
      lastError: { code: 'KEEP', message: 'kept' },
    }));
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    expect(registry.descriptors).toBe(0);
    expect(rechecks).toEqual([]);
    expect(await readVulndbState(t.db)).toMatchObject({
      lastCheckAt: now.toISOString(),
      nextCheckAt: new Date(now.getTime() + 6 * 3_600_000).toISOString(),
      lastError: { code: 'KEEP' },
    });
    expect((await queued()).rows).toHaveLength(1);
  });

  it('uses the mirror repository and its decrypted credentials', async () => {
    await settings({
      source: {
        kind: 'mirror',
        repository: 'registry.corp:5000/mirror/trivy-db:2',
        username: 'svc',
        password: 'hunter2',
      },
    });
    const registry = fakeRegistry(trivyArchive());
    await runOnce(registry);
    expect(registry.refs).toEqual(['registry.corp:5000/mirror/trivy-db:2']);
    expect(registry.auths).toEqual([{ username: 'svc', password: 'hunter2' }]);
    expect(await t.db.select({ source: vulndbDatasets.source }).from(vulndbDatasets)).toEqual([
      { source: 'mirror' },
    ]);
  });

  it('reports an unreadable mirror password as AUTH without calling the registry', async () => {
    await settings({
      source: {
        kind: 'mirror',
        repository: 'registry.corp:5000/mirror/trivy-db:2',
        password: 'hunter2',
      },
    });
    const registry = fakeRegistry(trivyArchive());
    const other = {
      ...deps(registry),
      config: { ...deps(registry).config, secretKey: 'z'.repeat(32) },
    };
    await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await requestVulndbUpdateNow(t.db);
    await runUntilIdle(t.db, vulndbUpdateHandlers(other), silent);
    expect(registry.descriptors).toBe(0);
    expect((await readVulndbState(t.db)).lastError).toMatchObject({ code: 'AUTH' });
    expect((await readVulndbState(t.db)).lastError?.message).toMatch(/Enter the password again/);
  });

  describe('scheduling', () => {
    it('two Update now presses leave one queued job', async () => {
      expect(await requestVulndbUpdateNow(t.db)).toBe(true);
      expect(await requestVulndbUpdateNow(t.db)).toBe(true);
      const all = await t.db.select().from(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(all).toHaveLength(1);
      expect(all[0]?.concurrencyKey).toBe(VULNDB_UPDATE_QUEUE);
    });

    it('Update now during a running update queues one follow-up run, due now', async () => {
      await requestVulndbUpdateNow(t.db);
      await t.db.update(jobs).set({ status: 'running' }).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(await requestVulndbUpdateNow(t.db)).toBe(true);
      expect(await requestVulndbUpdateNow(t.db)).toBe(true);
      const all = await t.db.select().from(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(all.map((j) => j.status).sort()).toEqual(['queued', 'running']);
      expect((await queued()).rows[0]!.secs).toBeLessThanOrEqual(0);
      // A scheduled run (the reaper's) adds none: one is queued already.
      expect(await ensureVulndbScheduled(t.db)).toBe(false);
    });

    it('the run that ends while a follow-up waits does not add another', async () => {
      const registry = fakeRegistry(trivyArchive());
      await requestVulndbUpdateNow(t.db);
      await t.db.update(jobs).set({ status: 'running' }).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      await requestVulndbUpdateNow(t.db);
      await runVulndbUpdate(deps(registry));
      const all = await t.db.select().from(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(all.filter((j) => j.status === 'queued')).toHaveLength(1);
    });

    it('moves a waiting run to now', async () => {
      await ensureVulndbScheduled(t.db);
      expect((await queued()).rows[0]!.secs).toBeGreaterThan(6 * 3600 - 60);
      await requestVulndbUpdateNow(t.db);
      const rows = (await queued()).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]!.secs).toBeLessThanOrEqual(0);
    });

    it('boot brings a late run forward to a minute and keeps one across replicas', async () => {
      await ensureVulndbScheduled(t.db);
      await scheduleVulndbAtBoot(t.db);
      await scheduleVulndbAtBoot(t.db);
      const rows = (await queued()).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]!.secs).toBeGreaterThan(50);
      expect(rows[0]!.secs).toBeLessThanOrEqual(60);
    });

    it('ensure adds a run only when none is queued or running', async () => {
      expect(await ensureVulndbScheduled(t.db)).toBe(true);
      expect(await ensureVulndbScheduled(t.db)).toBe(false);
    });
  });

  describe('staleness mail', () => {
    it('sends once per stale dataset to administrators with an address, whatever the licence', async () => {
      const registry = fakeRegistry(trivyArchive());
      now = new Date(BUILT + 4 * DAY_MS);
      await runOnce(registry);
      expect((await stale()).sort()).toEqual(['admin@example.com', 'ops@example.com']);
      const [row] = await t.db
        .select({ subject: mailMessages.subject })
        .from(mailMessages)
        .where(eq(mailMessages.kind, 'vulndb.stale'))
        .limit(1);
      expect(row?.subject).toBe('The Qualor vulnerability database is out of date');
      expect((await readVulndbState(t.db)).staleNotifiedDigest).toBe(
        digestOf(registry.archive as Buffer),
      );
      await runOnce(registry);
      expect(await stale()).toHaveLength(2);
    });

    it('mails a failing update that leaves old data, and a new stale dataset mails again', async () => {
      const registry = fakeRegistry(trivyArchive());
      await runOnce(registry);
      expect(await stale()).toHaveLength(0);
      registry.archive = { code: 'UNREACHABLE', message: 'The registry did not answer' };
      now = new Date(BUILT + 4 * DAY_MS);
      await runOnce(registry);
      expect(await stale()).toHaveLength(2);
      // A fresh dataset resets the record ...
      // Staleness counts from the earlier of the build and the storing time, and the storing time
      // is the database's real clock: this dataset is built, stored and judged around the real now.
      const realNow = Date.now();
      registry.archive = trivyArchive({
        metadata: metadataJson(2, new Date(realNow).toISOString()),
      });
      now = new Date(realNow + DAY_MS / 2);
      await runOnce(registry);
      expect((await readVulndbState(t.db)).staleNotifiedDigest).toBeNull();
      expect(await stale()).toHaveLength(2);
      // ... so the next time it goes stale, administrators hear about it again.
      registry.archive = { code: 'UNREACHABLE', message: 'The registry did not answer' };
      now = new Date(realNow + 5 * DAY_MS);
      await runOnce(registry);
      expect(await stale()).toHaveLength(4);
    });

    it('is also checked for an uploaded file, and sends nothing for fresh data', async () => {
      await settings({ source: { kind: 'upload' } });
      const registry = fakeRegistry(trivyArchive());
      const { storeDataset, makeDatasetCurrent } = await import('./store');
      const stored = await storeDataset(t.db, {
        kind: 'trivy',
        source: 'upload',
        chunks: (async function* () {
          await Promise.resolve();
          yield trivyArchive();
        })(),
        maxBytes: 1 << 30,
      });
      if ('problem' in stored) throw new Error(stored.problem.message);
      await makeDatasetCurrent(t.db, stored.dataset.id);
      await runOnce(registry);
      expect(await stale()).toHaveLength(0);
      now = new Date(BUILT + 4 * DAY_MS);
      await runOnce(registry);
      expect(await stale()).toHaveLength(2);
    });

    it('a build time in the future does not suppress the mail', async () => {
      const [row] = await t.db
        .insert(vulndbDatasets)
        .values({
          kind: 'trivy',
          digest: `sha256:${'b'.repeat(64)}`,
          sizeBytes: 1,
          source: 'official',
          status: 'ready',
          builtAt: new Date(now.getTime() + 30 * DAY_MS),
          createdAt: new Date(now.getTime() - 4 * DAY_MS),
        })
        .returning();
      await updateVulndbState(t.db, (s) => ({ ...s, currentDatasetId: row!.id }));
      const sent = await notifyIfVulndbStale({ db: t.db, config: t.config, now: () => now });
      expect(sent).toBe(true);
      expect(await stale()).toHaveLength(2);
    });

    it('does not record the send while email is off, so a later run still sends it', async () => {
      const registry = fakeRegistry(trivyArchive());
      now = new Date(BUILT + 4 * DAY_MS);
      const noMail = deps(registry);
      noMail.config = { ...noMail.config, smtp: null };
      await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      await requestVulndbUpdateNow(t.db);
      await runUntilIdle(t.db, vulndbUpdateHandlers(noMail), silent);
      expect(await stale()).toHaveLength(0);
      expect((await readVulndbState(t.db)).staleNotifiedDigest).toBeNull();
      await runOnce(registry);
      expect(await stale()).toHaveLength(2);
    });
  });

  describe('KEV and EPSS (vuln.priority)', () => {
    const PRIORITY = () => ({ vulnerabilities: { priority: true, alerts: false, sbom: false } });
    const KEV_SUBJECT = 'The Qualor list of exploited vulnerabilities is out of date';
    const EPSS_SUBJECT = 'The Qualor exploit probability data is out of date';
    const UNREACHABLE: OciProblem = { code: 'UNREACHABLE', message: 'No connection within 3 s' };

    const kevFile = (ids: string[]): Buffer =>
      Buffer.from(
        JSON.stringify({
          catalogVersion: '2026.10.30',
          dateReleased: now.toISOString(),
          vulnerabilities: ids.map((cveID) => ({ cveID, dateAdded: '2026-02-03' })),
        }),
      );
    const epssFile = (ids: string[]): Buffer =>
      gzipSync(
        `#model_version:v2025.03.14,score_date:${now.toISOString()}\ncve,epss,percentile\n` +
          ids.map((id) => `${id},0.5,0.75\n`).join(''),
      );
    const file = (body: Buffer): HttpsFile => ({
      kind: 'file',
      body,
      etag: null,
      lastModified: null,
    });

    /** A file server whose answer the test changes; it records the URLs it was asked for. */
    function fakeFiles(initial: (url: string) => Promise<HttpsFile | OciProblem>) {
      const fake = {
        urls: [] as string[],
        answer: initial,
        fetch: (async (url) => {
          fake.urls.push(url);
          return fake.answer(url);
        }) as typeof fetchHttpsFile,
      };
      return fake;
    }
    const freshFiles = () =>
      fakeFiles(async (url) =>
        file(url === OFFICIAL_KEV_URL ? kevFile(['CVE-2024-0001']) : epssFile(['CVE-2024-0001'])),
      );
    const mailsWith = async (subject: string): Promise<string[]> =>
      (
        await t.db
          .select({ to: mailMessages.toAddress })
          .from(mailMessages)
          .where(eq(mailMessages.subject, subject))
      )
        .map((r) => r.to)
        .sort();
    const priorityRow = () =>
      t.db.select().from(instanceSettings).where(eq(instanceSettings.key, PRIORITY_STATE_KEY));

    it('checks KEV, then EPSS, after the Trivy database', async () => {
      const files = freshFiles();
      await runOnce(fakeRegistry(trivyArchive()), {
        limits: PRIORITY,
        fetchHttpsFile: files.fetch,
      });
      expect(files.urls).toEqual([OFFICIAL_KEV_URL, OFFICIAL_EPSS_URL]);
      const state = await readPriorityState(t.db);
      expect(state.kev).toMatchObject({ count: 1, lastError: null });
      expect(state.epss).toMatchObject({ count: 1, lastError: null });
      expect((await readVulndbState(t.db)).lastError).toBeNull();
    });

    it('fetches nothing without the feature, and leaves the priority state alone', async () => {
      const files = freshFiles();
      await runOnce(fakeRegistry(trivyArchive()), { fetchHttpsFile: files.fetch });
      expect(files.urls).toEqual([]);
      expect(await priorityRow()).toEqual([]);
    });

    it('fetches nothing for an uploaded source', async () => {
      await settings({ source: { kind: 'upload' } });
      const files = freshFiles();
      await runOnce(fakeRegistry(trivyArchive()), {
        limits: PRIORITY,
        fetchHttpsFile: files.fetch,
      });
      expect(files.urls).toEqual([]);
      expect(await priorityRow()).toEqual([]);
    });

    it('fetches nothing while monitoring is off', async () => {
      await settings({ enabled: false });
      const files = freshFiles();
      await runOnce(fakeRegistry(trivyArchive()), {
        limits: PRIORITY,
        fetchHttpsFile: files.fetch,
      });
      expect(files.urls).toEqual([]);
      expect(await priorityRow()).toEqual([]);
    });

    it('a stop during the KEV download records nothing, skips EPSS and retries in a minute', async () => {
      const stop = new AbortController();
      const files = fakeFiles(async () => {
        await Promise.resolve();
        stop.abort();
        return { code: 'UNREACHABLE', message: 'The download was cut' };
      });
      await t.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      await requestVulndbUpdateNow(t.db);
      await runUntilIdle(
        t.db,
        vulndbUpdateHandlers(
          deps(fakeRegistry(trivyArchive()), {
            limits: PRIORITY,
            fetchHttpsFile: files.fetch,
            shutdown: stop.signal,
          }),
        ),
        silent,
      );
      expect(files.urls).toEqual([OFFICIAL_KEV_URL]);
      const state = await readPriorityState(t.db);
      expect(state.kev).toMatchObject({ lastError: null, lastCheckAt: null });
      expect(state.epss).toMatchObject({ lastError: null, lastCheckAt: null });
      const next = (await queued()).rows;
      expect(next).toHaveLength(1);
      expect(next[0]!.secs).toBeLessThanOrEqual(60);
    });

    it('mails each admin once when KEV goes stale, and again after a fresh file', async () => {
      // No Trivy dataset, so no Trivy stale mail.
      const registry = fakeRegistry(UNREACHABLE);
      const files = freshFiles();
      const run = () => runOnce(registry, { limits: PRIORITY, fetchHttpsFile: files.fetch });
      await run();
      expect(await mailsWith(KEV_SUBJECT)).toEqual([]);

      files.answer = async () => UNREACHABLE;
      const start = now.getTime();
      now = new Date(start + 4 * DAY_MS);
      await run();
      expect(await mailsWith(KEV_SUBJECT)).toEqual(['admin@example.com', 'ops@example.com']);
      expect(await mailsWith(EPSS_SUBJECT)).toEqual(['admin@example.com', 'ops@example.com']);
      const { kev } = await readPriorityState(t.db);
      expect(kev.staleNotifiedDigest).toBe(kev.digest);
      now = new Date(start + 4 * DAY_MS + 3_600_000);
      await run();
      expect(await mailsWith(KEV_SUBJECT)).toHaveLength(2);

      // A fresh file clears the record ...
      now = new Date(start + 5 * DAY_MS);
      files.answer = async (url) =>
        file(url === OFFICIAL_KEV_URL ? kevFile(['CVE-2024-0002']) : epssFile(['CVE-2024-0002']));
      await run();
      expect((await readPriorityState(t.db)).kev.staleNotifiedDigest).toBeNull();
      expect(await mailsWith(KEV_SUBJECT)).toHaveLength(2);

      // ... so the next time it goes stale, administrators hear about it again.
      files.answer = async () => UNREACHABLE;
      now = new Date(start + 9 * DAY_MS);
      await run();
      expect(await mailsWith(KEV_SUBJECT)).toHaveLength(4);
    });

    it('mails a stale uploaded file whatever the source, and only with the feature', async () => {
      await settings({ source: { kind: 'upload' } });
      const old = new Date(now.getTime() - 4 * DAY_MS).toISOString();
      await updatePriorityState(t.db, 'kev', (s) => ({
        ...s,
        source: 'upload',
        storedAt: old,
        refreshedAt: old,
        digest: `sha256:${'c'.repeat(64)}`,
      }));
      const files = freshFiles();
      await runOnce(fakeRegistry(trivyArchive()), { fetchHttpsFile: files.fetch });
      expect(await mailsWith(KEV_SUBJECT)).toEqual([]);
      expect((await readPriorityState(t.db)).kev.staleNotifiedDigest).toBeNull();

      await runOnce(fakeRegistry(trivyArchive()), {
        limits: PRIORITY,
        fetchHttpsFile: files.fetch,
      });
      expect(await mailsWith(KEV_SUBJECT)).toEqual(['admin@example.com', 'ops@example.com']);
      expect(files.urls).toEqual([]);
    });
  });
});
