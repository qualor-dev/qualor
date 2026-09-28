import { and, eq, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { file, finding, reportWith, type ReportParts } from '../../test/reports';
import { analyses, gateConditions, instanceSettings, projects, qualityGates } from '../db/schema';
import { AnalysisFailure, reconcileDeadAnalyses } from '../ingest/process';
import { DEFAULT_STAGES } from '../ingest/stages';
import { webhookStage } from '../webhooks/stage';
import { effectiveGate, gateStage, SMALL_CHANGESET_SETTING } from './stage';

describe('gate evaluation after ingestion (gates.md §6, server step 11)', () => {
  let h: IngestHarness;
  let minute = 0;
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 8, 22, 10, minute++)).toISOString(),
      ...parts,
    });
  const analysis = async (id: string) =>
    (await h.ctx.db.select().from(analyses).where(eq(analyses.id, id)))[0]!;
  const mr = {
    branch: 'feature/x',
    mergeRequest: { id: '1', targetBranch: 'main', sourceBranch: 'feature/x' },
  };
  /** 12 changed lines, none covered. */
  const smallChange = (p: IngestProject, findings: Report['findings'] = []) =>
    report(p, {
      ...mr,
      files: [
        file('src/a.ts', {
          lines: 100,
          newLines: [[1, 12]],
          coverage: { covered: [], uncovered: [[1, 12]], branches: [] },
        }),
      ],
      findings,
    });

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('fails an MR on new_issues for a finding on a new line, and passes it for an old line (§9.5)', async () => {
    const p = await h.project('gate/new-issue');
    await p.ingestOk(report(p, { files: [file('src/a.ts', { lines: 100 })], findings: [] }));
    const onNewLine = await p.ingestOk(smallChange(p, [finding({ line: 3 })]));
    const failed = await analysis(onNewLine);
    expect(failed.gateStatus).toBe('failed');
    expect(failed.gateResult).toMatchObject({
      status: 'failed',
      gate: { name: 'Qualor way' },
      conditions: [
        { metric: 'new_issues', operator: 'gt', threshold: 0, value: 1, status: 'failed' },
      ],
      ignoredConditions: [
        { metric: 'new_coverage', reason: 'small_changeset' },
        { metric: 'new_duplicated_lines_density', reason: 'small_changeset' },
      ],
    });
    // A newly enabled rule flagging an unchanged line is not new code.
    const onOldLine = await p.ingestOk(smallChange(p, [finding({ line: 50, ruleId: 'new-rule' })]));
    expect((await analysis(onOldLine)).gateStatus).toBe('passed');
  });

  it('passes 12 new lines at 0 % coverage (small changeset, §9.6), unless the instance lowers the threshold', async () => {
    const p = await h.project('gate/small');
    await p.ingestOk(report(p, { files: [file('src/a.ts', { lines: 100 })], findings: [] }));
    expect((await analysis(await p.ingestOk(smallChange(p)))).gateStatus).toBe('passed');
    await h.ctx.db.insert(instanceSettings).values({ key: SMALL_CHANGESET_SETTING, value: 5 });
    try {
      const strict = await analysis(await p.ingestOk(smallChange(p)));
      expect(strict.gateResult).toMatchObject({
        status: 'failed',
        conditions: expect.arrayContaining([
          expect.objectContaining({ metric: 'new_coverage', value: 0, status: 'failed' }),
        ]),
      });
    } finally {
      await h.ctx.db
        .delete(instanceSettings)
        .where(eq(instanceSettings.key, SMALL_CHANGESET_SETTING));
    }
  });

  it('is error when the baseline is unavailable, and keeps the CLI warning on the result', async () => {
    const p = await h.project('gate/unavailable');
    const noNewLines = file('src/a.ts');
    delete noNewLines.newLines;
    const id = await p.ingestOk(
      report(p, {
        files: [noNewLines],
        baseline: { revision: null, kind: 'server_baseline', status: 'unavailable' },
        warnings: [
          { code: 'BASELINE_ENDPOINT_UNAVAILABLE', message: 'old server' },
          { code: 'BASELINE_ENDPOINT_UNAVAILABLE', message: 'old server, again' },
        ],
      }),
    );
    expect((await analysis(id)).gateResult).toMatchObject({
      status: 'error',
      warnings: ['BASELINE_ENDPOINT_UNAVAILABLE', 'NEW_CODE_UNAVAILABLE'],
    });
  });

  it("uses the project's own gate, evaluates overall conditions on main only, and is none without any gate", async () => {
    const p = await h.project('gate/custom');
    const [gate] = await h.ctx.db
      .insert(qualityGates)
      .values({ organizationId: h.organizationId, name: 'No issues at all' })
      .returning();
    await h.ctx.db
      .insert(gateConditions)
      .values({ gateId: gate!.id, metricKey: 'issues', operator: 'gt', threshold: 0 });
    await h.ctx.db.update(projects).set({ qualityGateId: gate!.id }).where(eq(projects.id, p.id));
    const withIssue = { files: [file('src/a.ts')], findings: [finding({ line: 70 })] };
    const onMain = await analysis(await p.ingestOk(report(p, withIssue)));
    expect(onMain.gateResult).toMatchObject({
      status: 'failed',
      gate: { id: gate!.id, name: 'No issues at all' },
    });
    const onMr = await analysis(await p.ingestOk(report(p, { ...mr, ...withIssue })));
    expect(onMr.gateResult).toMatchObject({
      status: 'passed',
      ignoredConditions: [{ metric: 'issues', reason: 'overall_on_branch' }],
    });

    const bare = await h.project('gate/none');
    await h.ctx.db.execute(
      sql`UPDATE quality_gates SET is_default = false WHERE organization_id = ${h.organizationId}`,
    );
    try {
      const none = await analysis(await bare.ingestOk(report(bare, withIssue)));
      expect(none).toMatchObject({
        gateStatus: 'none',
        gateResult: { status: 'none', gate: null },
      });
    } finally {
      await h.ctx.db.execute(sql`
        UPDATE quality_gates SET is_default = true
         WHERE organization_id = ${h.organizationId} AND is_builtin`);
    }
  });

  it('skips a stored condition on a metric the catalog no longer has, with a warning (ruling G5)', async () => {
    const p = await h.project('gate/unknown-metric');
    const [gate] = await h.ctx.db
      .insert(qualityGates)
      .values({ organizationId: h.organizationId, name: 'Old catalog' })
      .returning();
    await h.ctx.db.insert(gateConditions).values([
      { gateId: gate!.id, metricKey: 'removed_metric', operator: 'gt', threshold: 0 },
      { gateId: gate!.id, metricKey: 'issues', operator: 'gt', threshold: 0 },
    ]);
    await h.ctx.db.update(projects).set({ qualityGateId: gate!.id }).where(eq(projects.id, p.id));
    const row = await analysis(
      await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [finding({ line: 7 })] })),
    );
    expect(row.gateResult).toMatchObject({
      status: 'failed',
      conditions: [{ metric: 'issues', value: 1, status: 'failed' }],
      warnings: ['GATE_CONDITION_UNKNOWN_METRIC'],
    });
  });

  it('ignores a malformed small-changeset setting and keeps the default (ruling G6)', async () => {
    const p = await h.project('gate/bad-setting');
    await p.ingestOk(report(p, { files: [file('src/a.ts', { lines: 100 })], findings: [] }));
    await h.ctx.db.insert(instanceSettings).values({ key: SMALL_CHANGESET_SETTING, value: 'five' });
    try {
      expect((await analysis(await p.ingestOk(smallChange(p)))).gateStatus).toBe('passed');
    } finally {
      await h.ctx.db
        .delete(instanceSettings)
        .where(eq(instanceSettings.key, SMALL_CHANGESET_SETTING));
    }
  });

  it('falls back to the default gate when the project row it was given names a deleted gate', async () => {
    const p = await h.project('gate/stale-id');
    const [gate] = await h.ctx.db
      .insert(qualityGates)
      .values({ organizationId: h.organizationId, name: 'Soon gone' })
      .returning();
    await h.ctx.db.update(projects).set({ qualityGateId: gate!.id }).where(eq(projects.id, p.id));
    const [stale] = await h.ctx.db.select().from(projects).where(eq(projects.id, p.id));
    expect((await effectiveGate(h.ctx.db, stale!))?.id).toBe(gate!.id);
    await h.ctx.db.delete(qualityGates).where(eq(qualityGates.id, gate!.id));
    // The FK set quality_gate_id to NULL; the caller's row still holds the old id.
    expect(await effectiveGate(h.ctx.db, stale!)).toMatchObject({ name: 'Qualor way' });
    // An id that does not resolve at all (not even re-read from projects) falls back too.
    const ghost = { ...stale!, id: '01900000-0000-7000-8000-000000000001' };
    expect(await effectiveGate(h.ctx.db, ghost)).toMatchObject({ name: 'Qualor way' });

    // During ingestion: the gate is deleted after the project row was loaded.
    const [doomed] = await h.ctx.db
      .insert(qualityGates)
      .values({ organizationId: h.organizationId, name: 'Deleted mid-ingestion' })
      .returning();
    await h.ctx.db.insert(gateConditions).values({
      gateId: doomed!.id,
      metricKey: 'new_lines',
      operator: 'gt',
      threshold: 1_000_000,
    });
    await h.ctx.db.update(projects).set({ qualityGateId: doomed!.id }).where(eq(projects.id, p.id));
    const deleteGate = {
      name: 'delete-gate',
      run: async (ctx: { tx: typeof h.ctx.db }) => {
        await ctx.tx.delete(qualityGates).where(eq(qualityGates.id, doomed!.id));
      },
    };
    const id = await p.ingestOk(
      report(p, { files: [file('src/a.ts')], findings: [finding({ line: 5 })] }),
      // The webhook stage reads the gate result, so it stays after gateStage.
      [
        ...DEFAULT_STAGES.filter((s) => s !== gateStage && s !== webhookStage),
        deleteGate,
        gateStage,
        webhookStage,
      ],
    );
    expect((await analysis(id)).gateResult).toMatchObject({
      status: 'passed',
      gate: { name: 'Qualor way' },
    });
  });

  it('sees one consistent default while set-default moves it, never none (fix round 2)', async () => {
    const p = await h.project('gate/set-default-race');
    const [project] = await h.ctx.db.select().from(projects).where(eq(projects.id, p.id));
    const [oldDefault] = await h.ctx.db
      .select()
      .from(qualityGates)
      .where(
        and(eq(qualityGates.organizationId, h.organizationId), eq(qualityGates.isDefault, true)),
      );
    const [next] = await h.ctx.db
      .insert(qualityGates)
      .values({ organizationId: h.organizationId, name: 'Next default' })
      .returning();
    await h.ctx.db
      .insert(gateConditions)
      .values({ gateId: next!.id, metricKey: 'issues', operator: 'gt', threshold: 0 });
    let moved!: () => void;
    const held = new Promise<void>((resolve) => (moved = resolve));
    let release!: () => void;
    const commit = new Promise<void>((resolve) => (release = resolve));
    // set-default's statements, held open (uncommitted) on another connection of the pool.
    const setDefault = h.ctx.db.transaction(async (tx) => {
      await tx
        .update(qualityGates)
        .set({ isDefault: false })
        .where(eq(qualityGates.id, oldDefault!.id));
      await tx.update(qualityGates).set({ isDefault: true }).where(eq(qualityGates.id, next!.id));
      moved();
      await commit;
    });
    try {
      await held;
      // Both rows are write-locked by the open transaction; the lookup (as ingestion runs it,
      // inside a transaction) must neither block nor lose the default: it sees the committed one.
      const during = await h.ctx.db.transaction((tx) => effectiveGate(tx, project!));
      expect(during).toMatchObject({ id: oldDefault!.id, name: 'Qualor way' });
      expect(during?.conditions).toHaveLength(3);
    } finally {
      release();
      await setDefault;
    }
    try {
      const after = await h.ctx.db.transaction((tx) => effectiveGate(tx, project!));
      expect(after).toEqual({
        id: next!.id,
        name: 'Next default',
        conditions: [{ metric: 'issues', operator: 'gt', threshold: 0 }],
      });
    } finally {
      await h.ctx.db.transaction(async (tx) => {
        await tx
          .update(qualityGates)
          .set({ isDefault: false })
          .where(eq(qualityGates.id, next!.id));
        await tx
          .update(qualityGates)
          .set({ isDefault: true })
          .where(eq(qualityGates.id, oldDefault!.id));
      });
    }
  });

  it('exposes the result on GET /analyses/{id}', async () => {
    const p = await h.project('gate/api');
    const id = await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/analyses/${id}`,
      headers: bearer(p.token),
    });
    expect(res.json()).toMatchObject({ gateStatus: 'passed', gateResult: { status: 'passed' } });
  });

  it('marks a failed ingestion gate_status error, whether a stage rejects it or its job dies', async () => {
    const p = await h.project('gate/failed');
    const reject = {
      name: 'reject',
      run: async () => {
        throw new AnalysisFailure('TEST_REJECTED', 'rejected by a test stage');
      },
    };
    const rejected = await p.ingest(report(p, { files: [file('src/a.ts')] }), [
      ...DEFAULT_STAGES,
      reject,
    ]);
    expect(await analysis(rejected)).toMatchObject({ status: 'failed', gateStatus: 'error' });

    const [stuck] = await h.ctx.db
      .insert(analyses)
      .values({ projectId: p.id, status: 'processing' })
      .returning();
    await h.ctx.db.execute(sql`
      INSERT INTO jobs (id, queue, payload, status)
      VALUES (gen_random_uuid(), 'analysis', ${JSON.stringify({ analysisId: stuck!.id })}::jsonb, 'dead')`);
    await reconcileDeadAnalyses(h.ctx.db);
    expect(await analysis(stuck!.id)).toMatchObject({ status: 'failed', gateStatus: 'error' });
  });
});
