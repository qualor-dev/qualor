import { and, asc, eq, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, finding, reportWith, type ReportParts } from '../../test/reports';
import { branches, issueChanges, issues } from '../db/schema';
import { changelogPage, copyChangelogs } from './inherit';

describe('branch and MR inheritance (data-model.md §5.4)', () => {
  let h: IngestHarness;
  let minute = 0;
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 8, 22, 10, minute++)).toISOString(),
      ...parts,
    });
  const mr = (id: string, target = 'main') => ({
    branch: 'feature/x',
    mergeRequest: { id, targetBranch: target, sourceBranch: 'feature/x' },
  });
  const issuesOn = async (p: IngestProject, kind: 'branch' | 'merge_request', name: string) => {
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.kind, kind), eq(branches.name, name)));
    return h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.branchId, branch!.id))
      .orderBy(asc(issues.startLine));
  };
  const base = [1, 2, 3, 4].map((n) => finding({ line: n, ruleId: `rule-${n}` }));
  const shifted = (by: number) =>
    base.map((f, i) => ({ ...f, location: { path: 'src/a.ts', startLine: i + 1 + by } }));

  /** Main with four issues: false_positive (with a comment), wont_fix, resolved, open. */
  async function mainWithStatuses(p: IngestProject) {
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: base }));
    const main = await issuesOn(p, 'branch', 'main');
    const [fp, wontFix, resolved] = main;
    await h.ctx.db.execute(sql`
      UPDATE issues SET status = CASE id WHEN ${fp!.id}::uuid THEN 'false_positive'
          WHEN ${wontFix!.id}::uuid THEN 'wont_fix' ELSE 'resolved' END,
        resolved_at = now() - interval '2 days', resolved_by = ${h.ctx.adminId},
        severity = 'info', severity_overridden = (id = ${fp!.id}::uuid)
      WHERE id IN (${fp!.id}::uuid, ${wontFix!.id}::uuid, ${resolved!.id}::uuid)`);
    await h.ctx.db.insert(issueChanges).values({
      issueId: fp!.id,
      userId: h.ctx.adminId,
      field: 'status',
      oldValue: 'open',
      newValue: 'false_positive',
      comment: 'test data, not a real key',
      createdAt: new Date('2026-09-20T08:00:00Z'),
    });
    return main;
  }

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it("gives an MR's first analysis the target branch's false_positive, wont_fix, first_seen_at and changelog (§8.6)", async () => {
    const p = await h.project('inherit/mr');
    const main = await mainWithStatuses(p);
    await p.ingestOk(
      report(p, {
        ...mr('7'),
        files: [file('src/a.ts', { newLines: [[1, 2]] })],
        findings: shifted(2),
      }),
    );
    const onMr = await issuesOn(p, 'merge_request', '7');
    expect(onMr.map((i) => [i.status, i.firstSeenAt.getTime(), i.startLine])).toEqual(
      main.map((m, n) => [
        ['false_positive', 'wont_fix', 'open', 'open'][n],
        m.firstSeenAt.getTime(),
        n + 3,
      ]),
    );
    expect(onMr.map((i) => i.id)).not.toContain(main[0]!.id);
    expect(onMr[0]).toMatchObject({
      resolvedBy: h.ctx.adminId,
      severity: 'info',
      severityOverridden: true,
    });
    expect(onMr[2]).toMatchObject({
      resolvedAt: null,
      resolvedBy: null,
      severityOverridden: false,
    });
    const copied = await h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, onMr[0]!.id));
    expect(copied).toMatchObject([
      {
        userId: h.ctx.adminId,
        oldValue: 'open',
        newValue: 'false_positive',
        comment: 'test data, not a real key',
        createdAt: new Date('2026-09-20T08:00:00Z'),
      },
    ]);
  });

  it('inherits only on the first analysis of the branch', async () => {
    const p = await h.project('inherit/once');
    await mainWithStatuses(p);
    await p.ingestOk(report(p, { ...mr('8'), files: [file('src/a.ts')], findings: base }));
    const [fp] = await issuesOn(p, 'merge_request', '8');
    await h.ctx.db.update(issues).set({ status: 'open' }).where(eq(issues.id, fp!.id));
    // A second copy of rule-1's finding: one copy matches the MR's own (reopened) issue, the
    // other matches none of the MR's issues but would match main's false_positive if the second
    // analysis inherited.
    const twice = [...base, { ...base[0]! }];
    await p.ingestOk(report(p, { ...mr('8'), files: [file('src/a.ts')], findings: twice }));
    const onMr = await issuesOn(p, 'merge_request', '8');
    expect(onMr.find((i) => i.id === fp!.id)).toMatchObject({ status: 'open' });
    expect(onMr.filter((i) => i.ruleId === fp!.ruleId).map((i) => i.status)).toEqual([
      'open',
      'open',
    ]);
  });

  it('never inherits after a first analysis with no findings, or with a failed engine (§5.4 note)', async () => {
    // The first analysis is the only one that inherits, whatever it found: a branch whose first
    // analysis reported nothing (or whose analyzer failed) starts its later issues `open`, with
    // their own first_seen_at and no copied changelog.
    const p = await h.project('inherit/empty-first');
    const main = await mainWithStatuses(p);
    const firsts: ReportParts[] = [
      { ...mr('20'), files: [file('src/a.ts')], findings: [] },
      {
        ...mr('21'),
        engines: [engine('eslint', [], 'failed')],
        files: [file('src/a.ts')],
        findings: [],
      },
    ];
    for (const first of firsts) {
      await p.ingestOk(report(p, first));
      const name = first.mergeRequest!.id;
      await p.ingestOk(report(p, { ...mr(name), files: [file('src/a.ts')], findings: base }));
      const onMr = await issuesOn(p, 'merge_request', name);
      expect(
        onMr.map((i) => i.status),
        `MR ${name}`,
      ).toEqual(['open', 'open', 'open', 'open']);
      expect(onMr.map((i) => i.firstSeenAt.getTime())).not.toContain(
        main[0]!.firstSeenAt.getTime(),
      );
      const changes = await h.ctx.db
        .select()
        .from(issueChanges)
        .where(eq(issueChanges.issueId, onMr[0]!.id));
      expect(changes).toEqual([]);
    }
  });

  it('does not inherit into a branch that already has issues, even without a previous analysis', async () => {
    const p = await h.project('inherit/has-issues');
    await mainWithStatuses(p);
    await p.ingestOk(report(p, { ...mr('11'), files: [file('src/a.ts')], findings: base }));
    const [fp] = await issuesOn(p, 'merge_request', '11');
    await h.ctx.db.update(issues).set({ status: 'open' }).where(eq(issues.id, fp!.id));
    // The branch's last analysis row is gone (retention, or a deleted analysis).
    await h.ctx.db
      .update(branches)
      .set({ lastAnalysisId: null })
      .where(and(eq(branches.projectId, p.id), eq(branches.name, '11')));
    const twice = [...base, { ...base[0]! }];
    await p.ingestOk(report(p, { ...mr('11'), files: [file('src/a.ts')], findings: twice }));
    const onMr = await issuesOn(p, 'merge_request', '11');
    expect(onMr.filter((i) => i.ruleId === fp!.ruleId).map((i) => i.status)).toEqual([
      'open',
      'open',
    ]);
  });

  it('copies each changelog in chronological order, across source chunks and result pages', async () => {
    const p = await h.project('inherit/chunks');
    const main = await mainWithStatuses(p);
    const at = (m: number) => new Date(Date.UTC(2026, 8, 20, 9, m));
    // Inserted newest first, so id order and chronological order disagree on the source.
    const extra = [
      { issueId: main[1]!.id, field: 'comment' as const, comment: 'w3', createdAt: at(4) },
      { issueId: main[1]!.id, field: 'comment' as const, comment: 'w2', createdAt: at(3) },
      {
        issueId: main[0]!.id,
        field: 'severity' as const,
        oldValue: 'high',
        newValue: 'info',
        createdAt: at(2),
      },
      { issueId: main[0]!.id, field: 'comment' as const, comment: 'f1', createdAt: at(1) },
      {
        issueId: main[1]!.id,
        field: 'status' as const,
        oldValue: 'open',
        newValue: 'wont_fix',
        createdAt: at(0),
      },
    ];
    for (const row of extra)
      await h.ctx.db.insert(issueChanges).values({ ...row, userId: h.ctx.adminId });
    const source = async (issueId: string) =>
      (
        await h.ctx.db
          .select()
          .from(issueChanges)
          .where(eq(issueChanges.issueId, issueId))
          .orderBy(asc(issueChanges.createdAt), asc(issueChanges.id))
      ).map((c) => [c.field, c.oldValue, c.newValue, c.comment, c.createdAt.getTime(), c.userId]);
    // A copy's id order must be its chronological order: loadCandidates' preCloseStatus reads
    // the latest status change by id.
    const copied = async (issueId: string) =>
      (
        await h.ctx.db
          .select()
          .from(issueChanges)
          .where(eq(issueChanges.issueId, issueId))
          .orderBy(asc(issueChanges.id))
      ).map((c) => [c.field, c.oldValue, c.newValue, c.comment, c.createdAt.getTime(), c.userId]);

    await p.ingestOk(report(p, { ...mr('12'), files: [file('src/a.ts')], findings: base }));
    const onMr = await issuesOn(p, 'merge_request', '12');
    for (const [n, m] of main.entries()) {
      expect(await copied(onMr[n]!.id)).toEqual(await source(m.id));
    }

    // Again with one source per chunk and two rows per page, so every boundary is crossed.
    const targets = onMr.map((i) => i.id);
    await h.ctx.db.execute(
      sql`DELETE FROM issue_changes WHERE issue_id IN (${sql.join(
        targets.map((id) => sql`${id}::uuid`),
        sql`, `,
      )})`,
    );
    await h.ctx.db.transaction((tx) =>
      copyChangelogs(
        tx,
        main.map((m, n) => ({ id: targets[n]!, inherited_from: m.id })),
        { sourceChunk: 1, pageRows: 2 },
      ),
    );
    for (const [n, m] of main.entries()) {
      expect(await copied(onMr[n]!.id)).toEqual(await source(m.id));
    }
    expect((await copied(onMr[1]!.id)).map((c) => c[3])).toEqual([null, 'w2', 'w3']);

    // And with every source in one chunk and pages that end inside an issue's changelog, so a
    // page's last issue is carried over to the next page (D-M2).
    for (const pageRows of [1, 2, 3]) {
      await h.ctx.db.execute(
        sql`DELETE FROM issue_changes WHERE issue_id IN (${sql.join(
          targets.map((id) => sql`${id}::uuid`),
          sql`, `,
        )})`,
      );
      await h.ctx.db.transaction((tx) =>
        copyChangelogs(
          tx,
          main.map((m, n) => ({ id: targets[n]!, inherited_from: m.id })),
          { sourceChunk: 10, pageRows },
        ),
      );
      for (const [n, m] of main.entries()) {
        expect(await copied(onMr[n]!.id), `pageRows ${pageRows}`).toEqual(await source(m.id));
      }
    }
  });

  it('reads the changelog pages through the (issue_id, id) index, without a sort (D-M2)', async () => {
    const ids = ['0190a000-0000-7000-8000-000000000001', '0190a000-0000-7000-8000-000000000002'];
    const after = { issueId: ids[0]!, id: '0190a000-0000-7000-8000-000000000009' };
    const plan = await h.ctx.db.transaction(async (tx) => {
      // The test tables are tiny, so make the planner show what it does with a real table.
      await tx.execute(sql`SET LOCAL enable_seqscan = off`);
      await tx.execute(sql`SET LOCAL enable_bitmapscan = off`);
      const result = await tx.execute<{ 'QUERY PLAN': unknown }>(
        sql`EXPLAIN (FORMAT JSON) ${changelogPage(ids, after, 100)}`,
      );
      return JSON.stringify(result.rows[0]!['QUERY PLAN']);
    });
    expect(plan).toContain('"Index Name":"issue_changes_issue_idx"');
    expect(plan).not.toContain('"Node Type":"Sort"');
  });

  it("uses the main branch as a feature branch's reference, and nothing when the MR target is unknown", async () => {
    const p = await h.project('inherit/branch');
    await mainWithStatuses(p);
    await p.ingestOk(report(p, { branch: 'feature/y', files: [file('src/a.ts')], findings: base }));
    expect((await issuesOn(p, 'branch', 'feature/y')).map((i) => i.status)).toEqual([
      'false_positive',
      'wont_fix',
      'open',
      'open',
    ]);
    await p.ingestOk(
      report(p, { ...mr('9', 'release/9'), files: [file('src/a.ts')], findings: base }),
    );
    expect((await issuesOn(p, 'merge_request', '9')).map((i) => i.status)).toEqual([
      'open',
      'open',
      'open',
      'open',
    ]);
  });

  it('keeps an inherited file-less issue out of new code', async () => {
    const p = await h.project('inherit/fileless');
    const fileless = finding({ path: null, engineId: 'eslint', ruleId: 'project-rule' });
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [fileless] }));
    await p.ingestOk(
      report(p, {
        ...mr('10'),
        files: [file('src/a.ts')],
        findings: [fileless, { ...fileless, ruleId: 'other-project-rule' }],
      }),
    );
    const onMr = await h.ctx.db
      .select({ ruleId: issues.ruleId, inNewCode: issues.inNewCode })
      .from(issues)
      .innerJoin(branches, eq(branches.id, issues.branchId))
      .where(and(eq(branches.projectId, p.id), eq(branches.name, '10')));
    expect(onMr.map((i) => i.inNewCode).sort()).toEqual([false, true]);
  });
});
