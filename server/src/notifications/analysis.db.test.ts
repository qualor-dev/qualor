import { eq, inArray, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { addMember, bearer, createUser } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { MAIL_ON, payloadOf, queued, watch, type OutboxRow } from '../../test/notify';
import {
  gzipJson,
  reportWith,
  sampleReport,
  uploadReport,
  type ReportOverrides,
} from '../../test/reports';
import type { Db, Tx } from '../db/client';
import { analyses, analysisReports, jobs, mailMessages } from '../db/schema';
import { jobHandlers } from '../ingest/handlers';
import {
  AnalysisFailure,
  markFailed,
  reconcileDeadAnalyses,
  type IngestionStage,
} from '../ingest/process';
import { ANALYSIS_QUEUE } from '../ingest/service';
import { DEFAULT_STAGES } from '../ingest/stages';
import { DEFAULT_MAX_ATTEMPTS, enqueue } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import { analysisFailedKey, notifyAnalysesFailed, notifyAnalysisFailed } from './analysis';
import { notifyDeps } from './deps';

const MAIN = { name: 'main', kind: 'branch' as const };

/**
 * A Db whose transactions throw at the `failAt`-th insert into mail_messages (a render bug or a
 * refused row looks the same to the caller); `inserts()` counts the mail_messages inserts tried.
 */
function failingOnMailInsert(db: Db, failAt: number): { db: Db; inserts: () => number } {
  let rows = 0;
  const insertInto = (target: Tx) => (table: unknown) => {
    if (table === mailMessages && ++rows === failAt) {
      throw new Error('could not queue mira@example.com');
    }
    return target.insert(table as typeof mailMessages);
  };
  const handler: ProxyHandler<Tx> = {
    get(target, prop) {
      if (prop === 'insert') return insertInto(target);
      const value: unknown = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  };
  const failing = {
    transaction: (fn: (tx: unknown) => Promise<number>) =>
      db.transaction((tx) => fn(new Proxy(tx, handler))),
  } as unknown as Db;
  return { db: failing, inserts: () => rows };
}

describe('analysis failure notifications (mail E3 N2, N7)', () => {
  let h: IngestHarness;
  let mainWatcher: string;
  let allWatcher: string;
  let minute = 0;
  let projects = 0;
  const at = () => new Date(Date.UTC(2026, 9, 13, 9, minute++)).toISOString();
  const report = (p: IngestProject, overrides: ReportOverrides = {}): Report =>
    sampleReport({ projectKey: p.key, analysisDate: at(), ...overrides });
  const reject: IngestionStage = {
    name: 'reject',
    run: async () => {
      throw new AnalysisFailure('TEST_REJECTED', 'a stage rejected the report');
    },
  };
  const run = (stages?: readonly IngestionStage[]) =>
    runUntilIdle(
      h.ctx.db,
      jobHandlers({
        db: h.ctx.db,
        upload: h.ctx.config.upload,
        stages,
        logger: h.ctx.app.log,
        notify: notifyDeps(h.ctx.config),
      }),
      h.ctx.app.log,
    );
  const upload = (p: IngestProject, body: unknown) =>
    uploadReport(h.ctx, bearer(p.token), p.key, gzipJson(body));
  /** A fresh project (dedupe keys are per project): mira watches main, alex every branch. */
  const project = async () => {
    const p = await h.project(`fail/${projects++}`);
    await watch(h.ctx.db, mainWatcher, p.id);
    await watch(h.ctx.db, allWatcher, p.id, { branches: 'all' });
    return p;
  };
  const failures = async (p: IngestProject) =>
    (await queued(h.ctx.db, 'notify.analysis-failed')).filter((m) =>
      m.dedupeKey?.startsWith(`analysis.failed:${p.id}:`),
    );
  const text = (row: OutboxRow) => payloadOf(row, h.ctx.config.secretKey).text;

  beforeAll(async () => {
    h = await createIngestHarness({ config: MAIL_ON, notify: true });
    const mira = await createUser(h.ctx, { username: 'mira', email: 'mira@example.com' });
    const alex = await createUser(h.ctx, { username: 'alex', email: 'alex@example.com' });
    for (const u of [mira, alex]) await addMember(h.ctx, h.organizationId, u.id, 'viewer');
    mainWatcher = mira.id;
    allWatcher = alex.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('mails every watcher once when the branch is unknown (REPORT_MISSING, REPORT_INVALID, BRANCH_REQUIRED)', async () => {
    const missing = await project();
    const gone = await upload(missing, report(missing));
    await h.ctx.db.delete(analysisReports).where(eq(analysisReports.analysisId, gone));
    const invalid = await project();
    await upload(invalid, 'not a report');
    const detached = await project();
    await upload(detached, report(detached, { branch: null }));
    await run();
    for (const [p, code] of [
      [missing, 'REPORT_MISSING'],
      [invalid, 'REPORT_INVALID'],
      [detached, 'BRANCH_REQUIRED'],
    ] as const) {
      const rows = await failures(p);
      expect(
        rows.map((m) => m.toAddress),
        code,
      ).toEqual(['alex@example.com', 'mira@example.com']);
      expect(rows[0]!.dedupeKey).toBe(analysisFailedKey(p.id, null));
      expect(text(rows[0]!), code).toContain(code);
    }
  });

  it('mails every watcher once for an invalid version label (VERSION_LABEL_INVALID)', async () => {
    const p = await project();
    await upload(
      p,
      reportWith({
        projectKey: p.key,
        analysisDate: at(),
        branch: null,
        tag: `v${'1'.repeat(100)}`,
        version: '',
        findings: [],
        files: [],
      }),
    );
    await run();
    const rows = await failures(p);
    expect(rows.map((m) => m.toAddress)).toEqual(['alex@example.com', 'mira@example.com']);
    expect(rows[0]!.dedupeKey).toBe(analysisFailedKey(p.id, null));
    expect(text(rows[0]!)).toContain('VERSION_LABEL_INVALID');
  });

  it('names the branch the report gave, and applies the scope to it', async () => {
    const elsewhere = await project();
    await upload(
      elsewhere,
      report(elsewhere, { projectKey: 'acme/elsewhere', branch: 'feature/y' }),
    );
    const onMain = await project();
    await upload(onMain, report(onMain, { projectKey: 'acme/elsewhere' }));
    await run();
    const y = await failures(elsewhere);
    expect(y.map((m) => m.toAddress)).toEqual(['alex@example.com']);
    expect(text(y[0]!)).toContain('feature/y');
    expect(text(y[0]!)).toContain('PROJECT_KEY_MISMATCH');
    expect((await failures(onMain)).map((m) => m.toAddress)).toEqual([
      'alex@example.com',
      'mira@example.com',
    ]);

    const rejected = await project();
    await rejected.ingest(report(rejected), [...DEFAULT_STAGES, reject]);
    const rows = await failures(rejected);
    expect(rows.map((m) => m.toAddress)).toEqual(['alex@example.com', 'mira@example.com']);
    expect(rows[0]!.dedupeKey).toBe(analysisFailedKey(rejected.id, MAIN));
    expect(text(rows[0]!)).toContain('TEST_REJECTED');
  });

  it('mails a broken pipeline at most once per branch every 6 hours', async () => {
    const p = await project();
    await p.ingest(report(p), [...DEFAULT_STAGES, reject]);
    await p.ingest(report(p), [...DEFAULT_STAGES, reject]);
    expect(await failures(p)).toHaveLength(2);
    await h.ctx.db
      .update(mailMessages)
      .set({ createdAt: sql`now() - interval '7 hours'` })
      .where(eq(mailMessages.dedupeKey, analysisFailedKey(p.id, MAIN)));
    await p.ingest(report(p), [...DEFAULT_STAGES, reject]);
    expect(await failures(p)).toHaveLength(4);
  });

  it('keeps a branch and a merge request of the same name in separate windows', async () => {
    const p = await project();
    await p.ingest(report(p, { branch: '42' }), [...DEFAULT_STAGES, reject]);
    await p.ingest(
      report(p, {
        branch: 'feature/x',
        mergeRequest: { id: '42', sourceBranch: 'feature/x', targetBranch: 'main' },
      }),
      [...DEFAULT_STAGES, reject],
    );
    const rows = await failures(p);
    expect(rows.map((m) => m.toAddress)).toEqual(['alex@example.com', 'alex@example.com']);
    expect(rows.map((m) => m.dedupeKey)).toEqual([
      analysisFailedKey(p.id, { name: '42', kind: 'branch' }),
      analysisFailedKey(p.id, { name: '42', kind: 'merge_request' }),
    ]);
  });

  it('mails once after the last retry (PROCESSING_ERROR)', async () => {
    const p = await project();
    const boom: IngestionStage = {
      name: 'boom',
      run: async () => {
        throw new Error('stage exploded');
      },
    };
    const id = await upload(p, report(p));
    for (let attempt = 0; attempt < DEFAULT_MAX_ATTEMPTS; attempt++) {
      await run([boom]);
      await h.ctx.db.execute(sql`
        UPDATE jobs SET run_at = now() - interval '1 second'
         WHERE queue = ${ANALYSIS_QUEUE} AND status = 'queued' AND payload ->> 'analysisId' = ${id}`);
    }
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, id));
    expect(row?.error?.code).toBe('PROCESSING_ERROR');
    expect(await failures(p)).toHaveLength(2);
    await h.ctx.db.delete(jobs).where(sql`${jobs.payload} ->> 'analysisId' = ${id}`);
  });

  it('never mails a stale analysis (a newer one superseded it)', async () => {
    const p = await project();
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'stale',
        analysisDate: '2026-10-13T12:00:00Z',
        findings: [],
      }),
    );
    const older = await p.ingest(
      reportWith({
        projectKey: p.key,
        branch: 'stale',
        analysisDate: '2026-10-13T11:00:00Z',
        findings: [],
      }),
    );
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, older));
    expect(row?.error?.code).toBe('STALE_ANALYSIS');
    expect(await failures(p)).toEqual([]);
  });

  it('mails a failure once: a second markFailed changes nothing and a rerun of its job mails nobody', async () => {
    const p = await project();
    const id = await upload(p, 'not a report');
    await run();
    expect(await failures(p)).toHaveLength(2);
    // Out of the 6-hour window, so only "changed nothing" can keep a second email away.
    await h.ctx.db
      .update(mailMessages)
      .set({ createdAt: sql`now() - interval '7 hours'` })
      .where(eq(mailMessages.dedupeKey, analysisFailedKey(p.id, null)));
    expect(await markFailed(h.ctx.db, id, { code: 'TEST_FAILED', message: 'again' })).toBe(false);
    // A duplicate run of its job (at-least-once): the analysis is no longer queued, nothing mails.
    await enqueue(h.ctx.db, { queue: ANALYSIS_QUEUE, payload: { analysisId: id } });
    await run();
    expect(await failures(p)).toHaveLength(2);
  });

  it('queues one email per watcher when two failures of a branch are mailed at once', async () => {
    const p = await project();
    const ids = [await upload(p, report(p)), await upload(p, report(p))];
    const error = { code: 'TEST_FAILED', message: 'failed by the test' };
    for (const id of ids) expect(await markFailed(h.ctx.db, id, error)).toBe(true);
    const hint = { name: 'main', kind: 'branch' as const, isMain: true };
    await Promise.all(
      ids.map((analysisId) =>
        notifyAnalysisFailed(h.ctx.db, notifyDeps(h.ctx.config), { analysisId, branchHint: hint }),
      ),
    );
    expect(await failures(p)).toHaveLength(2);
    await h.ctx.db.delete(jobs).where(inArray(sql`${jobs.payload} ->> 'analysisId'`, ids));
  });

  it('never throws when queueing fails: logs the error class only, queues nothing, the analysis stays failed', async () => {
    const p = await project();
    const id = await upload(p, report(p));
    expect(
      await markFailed(h.ctx.db, id, { code: 'TEST_FAILED', message: 'failed by the test' }),
    ).toBe(true);
    // The second watcher's outbox row fails (a render bug or a refused row looks the same here):
    // the first one, already inserted, rolls back with it.
    const failing = failingOnMailInsert(h.ctx.db, 2);
    const warn = vi.fn();
    expect(
      await notifyAnalysisFailed(
        failing.db,
        notifyDeps(h.ctx.config),
        { analysisId: id, branchHint: { ...MAIN, isMain: true } },
        { warn },
      ),
    ).toBe(0);
    expect(failing.inserts()).toBe(2);
    expect(warn).toHaveBeenCalledExactlyOnceWith(
      { analysisId: id, errorClass: 'Error' },
      'analysis failure notifications could not be queued',
    );
    expect(await failures(p)).toEqual([]);
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, id));
    expect(row?.status).toBe('failed');
    await h.ctx.db.delete(jobs).where(eq(sql`${jobs.payload} ->> 'analysisId'`, id));
  });

  it('reconcileDeadAnalyses returns the analyses it failed, and each one is mailed', async () => {
    const a = await project();
    const b = await project();
    const ids = [await upload(a, report(a)), await upload(b, report(b))];
    await h.ctx.db
      .update(jobs)
      .set({ status: 'dead' })
      .where(inArray(sql`${jobs.payload} ->> 'analysisId'`, ids));
    const failed = await reconcileDeadAnalyses(h.ctx.db);
    expect(failed).toEqual(expect.arrayContaining(ids));
    await notifyAnalysesFailed(h.ctx.db, notifyDeps(h.ctx.config), failed);
    expect(await failures(a)).toHaveLength(2);
    expect(await failures(b)).toHaveLength(2);
    await h.ctx.db.delete(jobs).where(inArray(sql`${jobs.payload} ->> 'analysisId'`, ids));
  });
});
