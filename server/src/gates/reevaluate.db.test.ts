import type { Report } from '@qualor/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, finding, reportWith } from '../../test/reports';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  runDecorations,
  scmTestConfig,
  silentLogger,
} from '../../test/scm';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  analyses,
  branches,
  issues,
  jobs,
  measures,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { analysisConcurrencyKey } from '../ingest/service';
import { enqueue } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import { markerOf } from '../scm/markdown';
import { SCM_QUEUE } from '../scm/queue';
import { statusName } from '../scm/render';
import { WEBHOOK_SECRET_AAD } from '../webhooks/deliveries';
import { enqueueReevaluations, GATE_QUEUE, gateHandlers, reevaluateBranch } from './reevaluate';

describe('re-evaluating the gate after a transition (scm.md §7)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;

  const branchOf = async (projectId: string, kind: 'branch' | 'merge_request') => {
    const [row] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, projectId), eq(branches.kind, kind)));
    return row!;
  };
  const latest = async (branchId: string) => {
    const branch = (await h.ctx.db.select().from(branches).where(eq(branches.id, branchId)))[0]!;
    const [analysis] = await h.ctx.db
      .select()
      .from(analyses)
      .where(eq(analyses.id, branch.lastAnalysisId!));
    return analysis!;
  };
  const measure = async (analysisId: string, key: string, scope: 'new' | 'overall') => {
    const [row] = await h.ctx.db
      .select({ value: measures.value })
      .from(measures)
      .where(
        and(
          eq(measures.analysisId, analysisId),
          eq(measures.metricKey, key),
          eq(measures.scope, scope),
        ),
      );
    return row?.value;
  };
  const openIssues = (branchId: string) =>
    h.ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, branchId), eq(issues.status, 'open')));
  const gateJobs = () =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, GATE_QUEUE), eq(jobs.status, 'queued')));
  const decorationsOf = async (analysisId: string) =>
    (
      await h.ctx.db
        .select()
        .from(jobs)
        .where(and(eq(jobs.queue, SCM_QUEUE), eq(jobs.status, 'queued')))
    ).filter((j) => (j.payload as { analysisId?: string }).analysisId === analysisId);
  const transition = (ids: string[], to: string, comment?: string) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/issues/bulk-transition',
      headers: h.orgAdmin.headers,
      payload: { ids, to, ...(comment ? { comment } : {}) },
    });
  const runGates = (logger = silentLogger) =>
    runUntilIdle(h.ctx.db, gateHandlers({ db: h.ctx.db, logger }), silentLogger);
  /** A report of the main branch with two new issues on src/a.ts. */
  const mainReport = (projectKey: string, parts: Parameters<typeof reportWith>[0] = {}) =>
    reportWith({
      projectKey,
      findings: [finding({ line: 3 }), finding({ line: 4, ruleId: 'no-eval' })],
      files: [
        {
          path: 'src/a.ts',
          language: 'typescript',
          kind: 'main',
          sha256: 'c'.repeat(64),
          lines: 10,
          newLines: [[1, 10]],
        },
      ],
      ...parts,
    });
  const withProvider = (report: Report, provider: Report['scm']['provider']): Report => ({
    ...report,
    scm: { ...report.scm, provider },
  });

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 300, path: 'acme/reeval' });
    h = await createIngestHarness({ config: scmTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('turns a merge request gate to passed when its only new issue is a false positive', async () => {
    const project = await mappedProject(h, fake, 'reeval/mr', 300);
    await h.ctx.db.insert(webhookSubscriptions).values({
      organizationId: h.organizationId,
      url: 'https://hooks.example.com/q',
      secretEnc: encryptSecret(
        encryptionKey(h.ctx.config.secretKey),
        'x'.repeat(20),
        WEBHOOK_SECRET_AAD,
      ),
      events: ['gate.status_changed'],
    });
    await project.ingestOk(mergeRequestReport(12, '1'.repeat(40), { projectKey: project.key }));
    const mr = await branchOf(project.id, 'merge_request');
    const before = await latest(mr.id);
    expect(before.gateStatus).toBe('failed');
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, SCM_QUEUE));
    // The branch's first analysis already sent gate.status_changed (previous status null).
    await h.ctx.db.delete(webhookDeliveries);
    const [issue] = await openIssues(mr.id);

    const res = await transition([issue!.id], 'false_positive', 'not a problem here');
    expect(res.statusCode).toBe(200);
    const [job] = await gateJobs();
    expect(job).toMatchObject({
      payload: { branchId: mr.id },
      concurrencyKey: analysisConcurrencyKey(project.id),
    });
    expect(await runGates()).toBe(1);

    const after = await latest(mr.id);
    expect(after.id).toBe(before.id);
    expect(after.gateStatus).toBe('passed');
    expect(after.gateResult).toMatchObject({
      status: 'passed',
      conditions: [{ metric: 'new_issues', value: 0, status: 'passed' }],
    });
    expect(await measure(after.id, 'issues', 'new')).toBe(0);
    expect(await measure(after.id, 'false_positive_issues', 'overall')).toBe(1);
    const deliveries = await h.ctx.db.select().from(webhookDeliveries);
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0]).toMatchObject({ event: 'gate.status_changed' });
    expect(deliveries[0]?.payload).toMatchObject({
      id: after.id,
      gateStatus: 'passed',
      previousGateStatus: 'failed',
      project: { id: project.id },
      branch: { id: mr.id, kind: 'merge_request', isMain: false },
    });
    // The merge request is decorated again.
    const decorations = await h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, SCM_QUEUE), eq(jobs.status, 'queued')));
    expect(decorations.map((j) => j.payload)).toEqual([
      { analysisId: after.id, attempt: 0, gitlab: null, reevaluation: true },
    ]);
    // A second run changes nothing.
    expect(await reevaluateBranch(h.ctx.db, mr.id)).toBe('unchanged');
    // Reopening the issue fails the gate again.
    await transition([issue!.id], 'open');
    await runGates();
    expect((await latest(mr.id)).gateStatus).toBe('failed');
    expect(await h.ctx.db.select().from(webhookDeliveries)).toHaveLength(2);
  });

  it('queues one job per branch however many of its issues change, none for a refused change', async () => {
    const project = await h.project('reeval/bulk');
    await project.ingestOk(mainReport(project.key));
    const main = await branchOf(project.id, 'branch');
    const ids = (await openIssues(main.id)).map((i) => i.id);
    expect(ids).toHaveLength(2);
    await transition(ids, 'resolved');
    await transition(ids, 'resolved'); // INVALID_TRANSITION for both: nothing changes
    expect(await gateJobs()).toHaveLength(1);
    // Toggling back and forth while a re-evaluation waits queues nothing more (a member cannot
    // flood the queue, nor GitLab through it).
    await transition(ids, 'open');
    await transition(ids, 'resolved');
    await transition([ids[0]!], 'open');
    await transition([ids[0]!], 'resolved');
    expect(await gateJobs()).toHaveLength(1);
    await runGates();
    expect((await latest(main.id)).gateStatus).toBe('passed');
    expect(await measure((await latest(main.id)).id, 'issues', 'overall')).toBe(0);
  });

  it('never loses a transition that commits while its branch’s queued re-evaluation waits', async () => {
    const project = await h.project('reeval/race');
    await project.ingestOk(mainReport(project.key));
    const main = await branchOf(project.id, 'branch');
    const [a, b] = await openIssues(main.id);
    await transition([a!.id], 'resolved');
    expect(await gateJobs()).toHaveLength(1);
    // T1: a transition that sees the queued job (so queues none) and has not committed yet.
    let entered!: () => void;
    let release!: () => void;
    const inside = new Promise<void>((resolve) => (entered = resolve));
    const released = new Promise<void>((resolve) => (release = resolve));
    const t1 = h.ctx.db.transaction(async (tx) => {
      await tx.update(issues).set({ status: 'resolved' }).where(eq(issues.id, b!.id));
      await enqueueReevaluations(tx, [b!.id]);
      entered();
      await released;
    });
    let whileOpen: number | undefined;
    try {
      await inside;
      // The worker may not take the job T1 relies on before T1 commits ...
      whileOpen = await runGates();
    } finally {
      release();
      await t1;
    }
    // ... and takes it once T1 has: it then sees both transitions.
    expect([whileOpen, await runGates()]).toEqual([0, 1]);
    const after = await latest(main.id);
    expect(after.gateStatus).toBe('passed');
    expect(await measure(after.id, 'issues', 'overall')).toBe(0);
  });

  it('recomputes the severity measures after an override, without touching the gate', async () => {
    const project = await h.project('reeval/severity');
    await project.ingestOk(reportWith({ projectKey: project.key }));
    const main = await branchOf(project.id, 'branch');
    const [issue] = await openIssues(main.id);
    const before = await latest(main.id);
    expect(await measure(before.id, 'blocker_issues', 'overall')).toBe(0);
    const res = await h.ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/issues/${issue!.id}`,
      headers: h.orgAdmin.headers,
      payload: { severity: 'blocker' },
    });
    expect(res.statusCode).toBe(200);
    expect(await gateJobs()).toEqual([expect.objectContaining({ payload: { branchId: main.id } })]);
    expect(await reevaluateBranch(h.ctx.db, main.id)).toBe('measures');
    const after = await latest(main.id);
    expect(await measure(after.id, 'blocker_issues', 'overall')).toBe(1);
    expect(await measure(after.id, 'medium_issues', 'overall')).toBe(0);
    expect(await measure(after.id, 'reliability_rating', 'overall')).toBe(1);
    expect(after.gateResult).toEqual(before.gateResult);
    await runGates();
  });

  it('leaves an error gate (no baseline) as it is', async () => {
    const project = await h.project('reeval/error');
    await project.ingestOk(
      reportWith({
        projectKey: project.key,
        branch: 'feature/y',
        baseline: { revision: null, kind: 'none', status: 'unavailable' },
        files: [
          {
            path: 'src/a.ts',
            language: 'typescript',
            kind: 'main',
            sha256: 'c'.repeat(64),
            lines: 10,
          },
        ],
      }),
    );
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.name, 'feature/y')));
    const before = await latest(branch!.id);
    expect(before.gateStatus).toBe('error');
    const [issue] = await openIssues(branch!.id);
    await transition([issue!.id], 'wont_fix', 'accepted');
    await runGates();
    const after = await latest(branch!.id);
    expect(after.gateStatus).toBe('error');
    expect(await measure(after.id, 'accepted_issues', 'overall')).toBe(1);
  });

  describe('decorating again (scm.md §7 step 4)', () => {
    it('records the report’s SCM context on the analysis at ingestion', async () => {
      const project = await mappedProject(h, fake, 'reeval/context', 300);
      const gitlab = {
        projectId: '300',
        pipelineId: '99002',
        mergeRequestEventType: 'detached',
      } as const;
      const mrAnalysis = await project.ingestOk(
        mergeRequestReport(12, '1'.repeat(40), { projectKey: project.key, gitlab }),
      );
      const mainAnalysis = await project.ingestOk(
        withProvider(reportWith({ projectKey: project.key }), 'none'),
      );
      const contextOf = async (id: string) =>
        (await h.ctx.db.select().from(analyses).where(eq(analyses.id, id)))[0]?.scmContext;
      expect(await contextOf(mrAnalysis)).toEqual({
        provider: 'gitlab',
        mergeRequestId: '12',
        gitlab,
      });
      expect(await contextOf(mainAnalysis)).toEqual({
        provider: 'none',
        mergeRequestId: null,
        gitlab: null,
      });
    });

    it('passes the stored GitLab CI context on to the decoration', async () => {
      const project = await mappedProject(h, fake, 'reeval/ci-context', 300);
      const gitlab = { projectId: '300', mergeRequestEventType: 'merged_result' } as const;
      await project.ingestOk(
        mergeRequestReport(12, '1'.repeat(40), { projectKey: project.key, gitlab }),
      );
      const mr = await branchOf(project.id, 'merge_request');
      const analysis = await latest(mr.id);
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, SCM_QUEUE));
      const [issue] = await openIssues(mr.id);
      await transition([issue!.id], 'false_positive', 'fine here');
      await runGates();
      expect((await decorationsOf(analysis.id)).map((j) => j.payload)).toEqual([
        { analysisId: analysis.id, attempt: 0, gitlab, reevaluation: true },
      ]);
    });

    it('never decorates a local scan, though its gate and webhooks change', async () => {
      const project = await mappedProject(h, fake, 'reeval/local', 300);
      await project.ingestOk(withProvider(mainReport(project.key), 'none'));
      const main = await branchOf(project.id, 'branch');
      const analysis = await latest(main.id);
      expect(analysis.gateStatus).toBe('failed');
      expect(await decorationsOf(analysis.id)).toEqual([]);
      await transition(
        (await openIssues(main.id)).map((i) => i.id),
        'wont_fix',
        'accepted',
      );
      expect(await reevaluateBranch(h.ctx.db, main.id)).toBe('status');
      expect((await latest(main.id)).gateStatus).toBe('passed');
      expect(await decorationsOf(analysis.id)).toEqual([]);
      await runGates();
    });

    it('does not decorate an analysis without a stored SCM context, and logs why', async () => {
      const project = await mappedProject(h, fake, 'reeval/legacy', 300);
      await project.ingestOk(mainReport(project.key));
      const main = await branchOf(project.id, 'branch');
      const analysis = await latest(main.id);
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, SCM_QUEUE));
      // An analysis ingested before the column existed.
      await h.ctx.db.update(analyses).set({ scmContext: null }).where(eq(analyses.id, analysis.id));
      await transition(
        (await openIssues(main.id)).map((i) => i.id),
        'resolved',
      );
      const warnings: { details: unknown; message: string }[] = [];
      await runGates({
        ...silentLogger,
        warn: (details: unknown, message: string) => {
          warnings.push({ details, message });
        },
      } as typeof silentLogger);
      expect((await latest(main.id)).gateStatus).toBe('passed');
      expect(await decorationsOf(analysis.id)).toEqual([]);
      expect(warnings).toEqual([
        {
          details: { analysisId: analysis.id, branchId: main.id },
          message: expect.stringContaining('not decorated again') as unknown as string,
        },
      ]);
      // A context that is not what Qualor writes counts as none: fail closed.
      await h.ctx.db
        .update(analyses)
        .set({ scmContext: { provider: 'gitlab', gitlab: { pipelineId: 'x; DROP' } } })
        .where(eq(analyses.id, analysis.id));
      await transition(
        (await h.ctx.db.select().from(issues).where(eq(issues.branchId, main.id))).map((i) => i.id),
        'open',
      );
      warnings.length = 0;
      await runGates({
        ...silentLogger,
        warn: (details: unknown, message: string) => {
          warnings.push({ details, message });
        },
      } as typeof silentLogger);
      expect((await latest(main.id)).gateStatus).toBe('failed');
      expect(await decorationsOf(analysis.id)).toEqual([]);
      expect(warnings).toEqual([
        {
          details: { analysisId: analysis.id, branchId: main.id },
          message: expect.stringContaining(
            'SCM context of the analysis is not valid',
          ) as unknown as string,
        },
      ]);
      expect(warnings[0]?.message).not.toContain('ingested before');
    });

    it('does not decorate again when the changed issue has no thread and the gate holds', async () => {
      const project = await mappedProject(h, fake, 'reeval/measures-only', 300);
      await project.ingestOk(mainReport(project.key));
      const main = await branchOf(project.id, 'branch');
      const analysis = await latest(main.id);
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, SCM_QUEUE));
      const [issue] = await openIssues(main.id);
      await h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/issues/${issue!.id}`,
        headers: h.orgAdmin.headers,
        payload: { severity: 'blocker' },
      });
      // A main-branch issue never has an inline thread: the job is not marked to redecorate.
      expect((await gateJobs()).map((j) => j.payload)).toEqual([{ branchId: main.id }]);
      await runGates();
      expect(await measure(analysis.id, 'blocker_issues', 'overall')).toBe(1);
      expect(await decorationsOf(analysis.id)).toEqual([]);
    });

    it('decorates again when an issue with a thread changes, though the gate holds (ruling G5)', async () => {
      fake.addProject({ id: 302, path: 'acme/reeval-g5' });
      const head = '1'.repeat(40);
      fake.addMergeRequest(302, {
        iid: 12,
        title: 'Thread follows the issue',
        state: 'opened',
        sourceBranch: 'feature/x',
        targetBranch: 'main',
        headSha: head,
        baseSha: 'b'.repeat(40),
        startSha: 'b'.repeat(40),
        diffs: [
          { oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: '@@ -1,2 +1,4 @@\n a\n b\n+c\n+d\n' },
        ],
      });
      const project = await mappedProject(h, fake, 'reeval/g5', 302);
      // A gate that looks at coverage only: no issue transition changes its result.
      const gate = await h.ctx.app.inject({
        method: 'POST',
        url: '/api/v0/quality-gates',
        headers: h.orgAdmin.headers,
        payload: { organizationId: h.organizationId, name: 'Coverage only (G5)' },
      });
      const gateId = (gate.json() as { id: string }).id;
      await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/quality-gates/${gateId}/conditions`,
        headers: h.orgAdmin.headers,
        payload: { metric: 'new_coverage', operator: 'lt', threshold: 80 },
      });
      const assigned = await h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/projects/${project.id}`,
        headers: h.orgAdmin.headers,
        payload: { qualityGateId: gateId },
      });
      expect(assigned.statusCode).toBe(200);
      await project.ingestOk(
        mergeRequestReport(12, head, {
          projectKey: project.key,
          engines: [engine('eslint')],
          files: [file('src/a.ts', { newLines: [[1, 10]] })],
          findings: [
            finding({ path: 'src/a.ts', line: 3 }),
            finding({ path: 'src/a.ts', line: 4, ruleId: 'no-eval' }),
          ],
        }),
      );
      await runDecorations(h, decorationDeps(h));
      const threads = () =>
        Object.fromEntries(
          fake
            .discussions(302, 12)
            .filter((d) => markerOf(d.notes[0]?.body ?? '')?.kind === 'issue')
            .map((d) => [d.notes[0]?.position?.['new_line'], d.notes[0]?.resolved]),
        );
      expect(threads()).toEqual({ 3: false, 4: false });
      const mr = await branchOf(project.id, 'merge_request');
      const analysis = await latest(mr.id);
      const gateBefore = analysis.gateResult;
      const issueAt = async (line: number) =>
        (await openIssues(mr.id)).find((i) => i.startLine === line)!;

      // A job queued earlier without the mark (say, for an issue without a thread) gets it.
      await enqueue(h.ctx.db, {
        queue: GATE_QUEUE,
        payload: { branchId: mr.id },
        concurrencyKey: analysisConcurrencyKey(project.id),
      });
      await transition([(await issueAt(3)).id], 'false_positive', 'intended');
      expect((await gateJobs()).map((j) => j.payload)).toEqual([
        { branchId: mr.id, redecorate: true },
      ]);
      await runGates();
      expect((await latest(mr.id)).gateResult).toEqual(gateBefore);
      expect(await decorationsOf(analysis.id)).toHaveLength(1);
      await runDecorations(h, decorationDeps(h));
      expect(threads()).toEqual({ 3: true, 4: false });

      // A severity override of an issue with a thread decorates again too.
      const overridden = await h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/issues/${(await issueAt(4)).id}`,
        headers: h.orgAdmin.headers,
        payload: { severity: 'blocker' },
      });
      expect(overridden.statusCode).toBe(200);
      await runGates();
      expect(await decorationsOf(analysis.id)).toHaveLength(1);
      await runDecorations(h, decorationDeps(h));
    });

    it('turns the commit status to success, edits the summary and resolves the thread (§11 criterion 3)', async () => {
      fake.addProject({ id: 301, path: 'acme/reeval-e2e' });
      const head = '1'.repeat(40);
      fake.addMergeRequest(301, {
        iid: 12,
        title: 'False positive',
        state: 'opened',
        sourceBranch: 'feature/x',
        targetBranch: 'main',
        headSha: head,
        baseSha: 'b'.repeat(40),
        startSha: 'b'.repeat(40),
        diffs: [
          { oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: '@@ -1,2 +1,4 @@\n a\n b\n+c\n+d\n' },
        ],
      });
      const project = await mappedProject(h, fake, 'reeval/e2e', 301);
      await project.ingestOk(
        mergeRequestReport(12, head, {
          projectKey: project.key,
          engines: [engine('eslint')],
          files: [file('src/a.ts', { newLines: [[1, 10]] })],
          findings: [finding({ path: 'src/a.ts', line: 3 })],
        }),
      );
      await runDecorations(h, decorationDeps(h));
      const summary = () =>
        fake
          .discussions(301, 12)
          .flatMap((d) => d.notes)
          .find((n) => markerOf(n.body)?.kind === 'summary')?.body ?? '';
      const thread = () =>
        fake.discussions(301, 12).find((d) => markerOf(d.notes[0]?.body ?? '')?.kind === 'issue');
      const status = () =>
        fake.statuses.filter((s) => s.projectId === 301 && s.name === statusName(project.key));
      expect(status().map((s) => s.state)).toEqual(['failed']);
      expect(summary()).toContain('quality gate failed');
      expect(thread()?.notes[0]?.resolved).toBe(false);

      const mr = await branchOf(project.id, 'merge_request');
      const [issue] = await openIssues(mr.id);
      await transition([issue!.id], 'false_positive', 'intended');
      await runGates();
      await runDecorations(h, decorationDeps(h));
      expect(status().map((s) => s.state)).toEqual(['failed', 'success']);
      expect(summary()).toContain('quality gate passed');
      expect(thread()?.notes[0]?.resolved).toBe(true);
      // Nothing more to do: a second re-evaluation and decoration change nothing.
      fake.clearRequests();
      expect(await reevaluateBranch(h.ctx.db, mr.id)).toBe('unchanged');
      await runDecorations(h, decorationDeps(h));
      expect(fake.requests.filter((r) => r.method !== 'GET')).toEqual([]);
    });
  });
});
