import { asc, eq, sql } from 'drizzle-orm';
import type { Quality, Report, Severity } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, finding, reportWith, type ReportParts } from '../../test/reports';
import { issueChanges, issues, profileRules, projectProfiles, qualityProfiles } from '../db/schema';
import { REOPEN_WINDOW_DAYS } from './plan';
import { writePlan } from './writes';

describe('issue tracking (server step 8, data-model.md §5.2 and §6)', () => {
  let h: IngestHarness;
  let minute = 0;
  /** Each analysis of a test gets a later analysisDate, so none is STALE_ANALYSIS. */
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 8, 22, 10, minute++)).toISOString(),
      ...parts,
    });
  const issuesOf = (p: IngestProject) =>
    h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.projectId, p.id))
      .orderBy(asc(issues.startLine), asc(issues.id));
  const changesOf = (issueId: string) =>
    h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issueId))
      .orderBy(asc(issueChanges.id));

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('creates issues on the first analysis and keeps their ids when nothing changed', async () => {
    const p = await h.project('track/stable');
    const parts = {
      files: [file('src/a.ts', { newLines: [[3, 3]] })],
      findings: [finding({ line: 3, severity: 'high' }), finding({ line: 8 })],
    } satisfies ReportParts;
    const first = await p.ingestOk(report(p, parts));
    const created = await issuesOf(p);
    expect(created).toMatchObject([
      {
        startLine: 3,
        status: 'open',
        severity: 'high',
        quality: 'maintainability',
        kind: 'issue',
        inNewCode: true,
        firstSeenAnalysisId: first,
        lastSeenAnalysisId: first,
        duplicateOfIssueId: null,
      },
      { startLine: 8, status: 'open', severity: 'medium', inNewCode: false },
    ]);
    const second = await p.ingestOk(report(p, parts));
    const again = await issuesOf(p);
    expect(again.map((i) => i.id)).toEqual(created.map((i) => i.id));
    expect(again.map((i) => [i.firstSeenAnalysisId, i.lastSeenAnalysisId])).toEqual([
      [first, second],
      [first, second],
    ]);
    expect(await changesOf(created[0]!.id)).toEqual([]);
  });

  it('closes an issue that is no longer reported, and reopens the same issue within 30 days', async () => {
    const p = await h.project('track/reopen');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    const [issue] = await issuesOf(p);
    const gone = await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const [closed] = await issuesOf(p);
    expect(closed).toMatchObject({ id: issue!.id, status: 'closed', duplicateOfIssueId: null });
    expect(closed!.closedAt).not.toBeNull();
    const back = await p.ingestOk(report(p, withFinding));
    expect(await issuesOf(p)).toMatchObject([{ id: issue!.id, status: 'open', closedAt: null }]);
    expect(
      (await changesOf(issue!.id)).map((c) => [
        c.field,
        c.oldValue,
        c.newValue,
        c.analysisId,
        c.userId,
      ]),
    ).toEqual([
      ['status', 'open', 'closed', gone, null],
      ['status', 'closed', 'open', back, null],
    ]);
  });

  it('opens a new issue when a closed one comes back after more than 30 days', async () => {
    const p = await h.project('track/expired');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const [old] = await issuesOf(p);
    await h.ctx.db.execute(
      sql`UPDATE issues SET closed_at = now() - interval '31 days' WHERE id = ${old!.id}`,
    );
    await p.ingestOk(report(p, withFinding));
    const rows = await issuesOf(p);
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.id === old!.id)?.status).toBe('closed');
    expect(rows.find((r) => r.id !== old!.id)?.status).toBe('open');
  });

  for (const status of ['failed', 'timeout', 'skipped', 'absent'] as const) {
    it(`leaves the issues of an engine that is ${status} untouched (data-model.md §8.4)`, async () => {
      const p = await h.project(`track/engine-${status}`);
      await p.ingestOk(
        report(p, {
          engines: [engine('eslint'), engine('semgrep')],
          files: [file('src/a.ts')],
          findings: [
            finding({ line: 1 }),
            finding({ line: 2, ruleId: 'eqeqeq' }),
            finding({ line: 3, engineId: 'semgrep', ruleId: 'ts-eval' }),
          ],
        }),
      );
      const before = await issuesOf(p);
      await p.ingestOk(
        report(p, {
          engines: [
            ...(status === 'absent' ? [] : [engine('eslint', [], status)]),
            engine('semgrep'),
          ],
          files: [file('src/a.ts')],
          findings: [],
        }),
      );
      const after = await issuesOf(p);
      expect(after.map((i) => [i.id, i.status, i.lastSeenAnalysisId])).toEqual([
        [before[0]!.id, 'open', before[0]!.lastSeenAnalysisId],
        [before[1]!.id, 'open', before[1]!.lastSeenAnalysisId],
        [before[2]!.id, 'closed', before[2]!.lastSeenAnalysisId],
      ]);
    });
  }

  it('closes the issue of a rule a profile turns off, and reopens it when the rule is back on', async () => {
    const p = await h.project('track/profile-change');
    const parts = {
      files: [file('src/a.ts')],
      findings: [finding({ line: 4, ruleId: 'toggled' })],
    };
    await p.ingestOk(report(p, parts));
    const [issue] = await issuesOf(p);
    const [profile] = await h.ctx.db
      .insert(qualityProfiles)
      .values({ organizationId: h.organizationId, name: 'Toggle TS', language: 'typescript' })
      .returning();
    await h.ctx.db
      .insert(projectProfiles)
      .values({ projectId: p.id, language: 'typescript', profileId: profile!.id });
    await h.ctx.db
      .insert(profileRules)
      .values({ profileId: profile!.id, ruleId: issue!.ruleId, active: false });
    await p.ingestOk(report(p, parts));
    expect(await issuesOf(p)).toMatchObject([{ id: issue!.id, status: 'closed' }]);
    await h.ctx.db
      .update(profileRules)
      .set({ active: true })
      .where(eq(profileRules.profileId, profile!.id));
    await p.ingestOk(report(p, parts));
    expect(await issuesOf(p)).toMatchObject([{ id: issue!.id, status: 'open' }]);
  });

  it('reopens a resolved issue that is detected again and leaves wont_fix and false_positive as they are', async () => {
    const p = await h.project('track/statuses');
    const base = [1, 2, 3].map((n) => finding({ line: n, ruleId: `rule-${n}` }));
    // Same code (same hashes), moved down by `shift` lines.
    const at = (shift: number) => ({
      files: [file('src/a.ts')],
      findings: base.map((f, i) => ({
        ...f,
        location: { path: 'src/a.ts', startLine: i + 1 + shift },
      })),
    });
    await p.ingestOk(report(p, at(0)));
    const [resolved, wontFix, falsePositive] = await issuesOf(p);
    await h.ctx.db.execute(sql`
      UPDATE issues SET status = CASE id
          WHEN ${resolved!.id}::uuid THEN 'resolved'
          WHEN ${wontFix!.id}::uuid THEN 'wont_fix'
          ELSE 'false_positive' END,
        resolved_at = now(), resolved_by = ${h.ctx.adminId}
      WHERE project_id = ${p.id}`);
    const later = await p.ingestOk(report(p, at(5)));
    const rows = await issuesOf(p);
    expect(rows.map((r) => [r.id, r.status, r.startLine, r.lastSeenAnalysisId])).toEqual([
      [resolved!.id, 'open', 6, later],
      [wontFix!.id, 'wont_fix', 7, later],
      [falsePositive!.id, 'false_positive', 8, later],
    ]);
    expect(rows[0]).toMatchObject({ resolvedAt: null, resolvedBy: null });
    expect(rows[1]!.resolvedBy).toBe(h.ctx.adminId);
    expect((await changesOf(resolved!.id)).map((c) => [c.oldValue, c.newValue])).toEqual([
      ['resolved', 'open'],
    ]);
    expect(await changesOf(wontFix!.id)).toEqual([]);
  });

  it('keeps a user severity override and refreshes every other severity', async () => {
    const p = await h.project('track/severity');
    await p.ingestOk(
      report(p, {
        files: [file('src/a.ts')],
        findings: [
          finding({ line: 1, severity: 'medium' }),
          finding({ line: 2, severity: 'medium' }),
        ],
      }),
    );
    const [overridden] = await issuesOf(p);
    await h.ctx.db
      .update(issues)
      .set({ severity: 'blocker', severityOverridden: true })
      .where(eq(issues.id, overridden!.id));
    await p.ingestOk(
      report(p, {
        files: [file('src/a.ts')],
        findings: [finding({ line: 1, severity: 'low' }), finding({ line: 2, severity: 'low' })],
      }),
    );
    expect((await issuesOf(p)).map((i) => [i.severity, i.severityOverridden])).toEqual([
      ['blocker', true],
      ['low', false],
    ]);
  });

  it('stores report text without NUL characters instead of failing the analysis', async () => {
    const p = await h.project('track/nul');
    await p.ingestOk(
      report(p, {
        files: [file('src/a.ts')],
        findings: [
          finding({
            line: 1,
            message: 'bad\u0000byte',
            snippet: { startLine: 1, lines: ['a\u0000b'] },
          }),
        ],
      }),
    );
    expect(await issuesOf(p)).toMatchObject([
      { message: 'badbyte', snippet: { startLine: 1, lines: ['ab'] } },
    ]);
  });

  it('stores secondary locations as reported, even outside files[]', async () => {
    const p = await h.project('track/secondary');
    const secondaryLocations = [{ path: 'vendor/lib.ts', startLine: 4, message: 'declared here' }];
    await p.ingestOk(
      report(p, {
        files: [file('src/a.ts')],
        findings: [finding({ line: 1, secondaryLocations })],
      }),
    );
    expect(await issuesOf(p)).toMatchObject([{ secondaryLocations }]);
  });

  it('dates issues by the database clock, whatever the (skewed) analysisDate says', async () => {
    const p = await h.project('track/clock');
    const skewed = (findings: Report['findings']) =>
      reportWith({
        projectKey: p.key,
        analysisDate: `2099-01-01T00:00:0${minute++ % 10}Z`,
        files: [file('src/a.ts')],
        findings,
      });
    await p.ingestOk(skewed([finding({ line: 1 })]));
    await p.ingestOk(skewed([]));
    const result = await h.ctx.db.execute<{ fresh: boolean }>(sql`
      SELECT first_seen_at > now() - interval '5 minutes' AND first_seen_at <= now()
         AND closed_at > now() - interval '5 minutes' AND closed_at <= now() AS fresh
      FROM issues WHERE project_id = ${p.id}`);
    expect(result.rows).toEqual([{ fresh: true }]);
  });

  // --- U5 fix round 1 -------------------------------------------------------------------------

  it('restores wont_fix (with its resolver) when a closed issue is re-detected, never auto-reopening it (#2)', async () => {
    const p = await h.project('track/wontfix-cycle');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    const [issue] = await issuesOf(p);
    await h.ctx.db
      .update(issues)
      .set({ status: 'wont_fix', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    const gone = await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const [closed] = await issuesOf(p);
    // An unmatched non-open issue of any status is closed, with a changelog entry (#7 asks this
    // be covered for `resolved` too; see the resolved-cycle test below for that case).
    expect(closed).toMatchObject({ id: issue!.id, status: 'closed', resolvedBy: h.ctx.adminId });
    expect(closed!.resolvedAt).not.toBeNull();
    const back = await p.ingestOk(report(p, withFinding));
    const rows = await issuesOf(p);
    expect(rows).toMatchObject([
      { id: issue!.id, status: 'wont_fix', closedAt: null, resolvedBy: h.ctx.adminId },
    ]);
    expect(rows[0]!.resolvedAt).not.toBeNull();
    expect((await changesOf(issue!.id)).map((c) => [c.oldValue, c.newValue, c.analysisId])).toEqual(
      [
        ['wont_fix', 'closed', gone],
        ['closed', 'wont_fix', back],
      ],
    );
  });

  it('restores false_positive (with its resolver) when a closed issue is re-detected (#2)', async () => {
    const p = await h.project('track/falsepositive-cycle');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    const [issue] = await issuesOf(p);
    await h.ctx.db
      .update(issues)
      .set({ status: 'false_positive', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    await p.ingestOk(report(p, withFinding));
    const rows = await issuesOf(p);
    expect(rows).toMatchObject([
      { id: issue!.id, status: 'false_positive', closedAt: null, resolvedBy: h.ctx.adminId },
    ]);
    expect(rows[0]!.resolvedAt).not.toBeNull();
  });

  it('re-opens to open, not back to resolved, after a resolved issue is closed then re-detected (#2)', async () => {
    const p = await h.project('track/resolved-cycle');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    const [issue] = await issuesOf(p);
    await h.ctx.db
      .update(issues)
      .set({ status: 'resolved', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    const gone = await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    expect(await issuesOf(p)).toMatchObject([{ id: issue!.id, status: 'closed' }]);
    const back = await p.ingestOk(report(p, withFinding));
    expect(await issuesOf(p)).toMatchObject([
      { id: issue!.id, status: 'open', closedAt: null, resolvedAt: null, resolvedBy: null },
    ]);
    expect((await changesOf(issue!.id)).map((c) => [c.oldValue, c.newValue, c.analysisId])).toEqual(
      [
        ['resolved', 'closed', gone],
        ['closed', 'open', back],
      ],
    );
  });

  it('tracks a fileless finding end to end: created, matched, then closed (#7)', async () => {
    const p = await h.project('track/fileless');
    const withFinding = {
      files: [],
      findings: [finding({ path: null, ruleId: 'global-rule', message: 'Project-wide problem.' })],
    } satisfies ReportParts;
    const first = await p.ingestOk(report(p, withFinding));
    const created = await issuesOf(p);
    expect(created).toMatchObject([
      { path: null, startLine: null, status: 'open', inNewCode: true, firstSeenAnalysisId: first },
    ]);
    const second = await p.ingestOk(report(p, withFinding));
    expect(await issuesOf(p)).toMatchObject([
      { id: created[0]!.id, inNewCode: false, lastSeenAnalysisId: second },
    ]);
    await p.ingestOk(report(p, { files: [], findings: [] }));
    expect(await issuesOf(p)).toMatchObject([{ id: created[0]!.id, status: 'closed' }]);
  });

  it('refreshes in_new_code on a matched issue as the new-code range changes (#7)', async () => {
    const p = await h.project('track/newcode-refresh');
    await p.ingestOk(
      report(p, { files: [file('src/a.ts', { newLines: [] })], findings: [finding({ line: 5 })] }),
    );
    const [issue] = await issuesOf(p);
    expect(issue).toMatchObject({ inNewCode: false });
    await p.ingestOk(
      report(p, {
        files: [file('src/a.ts', { newLines: [[5, 5]] })],
        findings: [finding({ line: 5 })],
      }),
    );
    expect(await issuesOf(p)).toMatchObject([{ id: issue!.id, inNewCode: true }]);
  });

  it('reopens the same issue just inside the 30-day window (DB clock) (#7)', async () => {
    const p = await h.project('track/reopen-boundary-in');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const [old] = await issuesOf(p);
    await h.ctx.db.execute(sql`
      UPDATE issues
         SET closed_at = now() - make_interval(days => ${REOPEN_WINDOW_DAYS}) + interval '1 minute'
       WHERE id = ${old!.id}`);
    await p.ingestOk(report(p, withFinding));
    expect(await issuesOf(p)).toMatchObject([{ id: old!.id, status: 'open' }]);
  });

  it('does not reopen an issue just outside the 30-day window (DB clock) (#7)', async () => {
    const p = await h.project('track/reopen-boundary-out');
    const withFinding = { files: [file('src/a.ts')], findings: [finding({ line: 5 })] };
    await p.ingestOk(report(p, withFinding));
    await p.ingestOk(report(p, { files: [file('src/a.ts')], findings: [] }));
    const [old] = await issuesOf(p);
    await h.ctx.db.execute(sql`
      UPDATE issues
         SET closed_at = now() - make_interval(days => ${REOPEN_WINDOW_DAYS}) - interval '1 minute'
       WHERE id = ${old!.id}`);
    await p.ingestOk(report(p, withFinding));
    const rows = await issuesOf(p);
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.id === old!.id)?.status).toBe('closed');
    expect(rows.find((r) => r.id !== old!.id)?.status).toBe('open');
  });

  it('never lets a stale plan clobber a status that changed after it was read (lost-update guard) (#3)', async () => {
    const p = await h.project('track/lost-update');
    const analysisId = await p.ingestOk(
      report(p, { files: [file('src/a.ts')], findings: [finding({ line: 1 })] }),
    );
    const [issue] = await issuesOf(p);
    // Simulates a concurrent transition (e.g. the future issues API of server step 12) landing
    // after this plan was already built from a stale read of status = 'open'.
    await h.ctx.db
      .update(issues)
      .set({ status: 'wont_fix', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    await writePlan(
      h.ctx.db,
      {
        updates: [
          {
            id: issue!.id,
            rule_id: issue!.ruleId,
            fingerprint: issue!.fingerprint,
            line_hash: issue!.lineHash,
            context_hash: issue!.contextHash,
            path: issue!.path,
            start_line: issue!.startLine,
            start_column: issue!.startColumn,
            end_line: issue!.endLine,
            end_column: issue!.endColumn,
            message: issue!.message,
            severity: issue!.severity as Severity,
            quality: issue!.quality as Quality,
            kind: issue!.kind,
            status: 'open',
            in_new_code: issue!.inNewCode,
            snippet: issue!.snippet,
            secondary_locations: issue!.secondaryLocations,
            from_status: 'open',
          },
        ],
        inserts: [],
        closes: [],
        live: [],
      },
      { projectId: p.id, branchId: issue!.branchId, analysisId },
    );
    expect(await issuesOf(p)).toMatchObject([
      { id: issue!.id, status: 'wont_fix', resolvedBy: h.ctx.adminId },
    ]);
    // The blocked transition ('open' → 'open', since the guard left it untouched) is never
    // logged: the changelog only ever records what actually happened (#3 of fix round 2).
    expect(await changesOf(issue!.id)).toEqual([]);
  });

  it('never logs a transition when a concurrent writer already set exactly the planned value (exact lost-update guard) (#C)', async () => {
    const p = await h.project('track/lost-update-exact');
    const analysisId = await p.ingestOk(
      report(p, { files: [file('src/a.ts')], findings: [finding({ line: 1 })] }),
    );
    const [issue] = await issuesOf(p);
    // A concurrent writer independently sets the row to EXACTLY the status this stale plan also
    // intends ('wont_fix'), landing after the plan read 'open' as its from_status. The guard must
    // still correctly block (the row's real prior status wasn't 'open'), even though the
    // post-update value happens to coincide with the plan's own planned new value.
    await h.ctx.db
      .update(issues)
      .set({ status: 'wont_fix', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    await writePlan(
      h.ctx.db,
      {
        updates: [
          {
            id: issue!.id,
            rule_id: issue!.ruleId,
            fingerprint: issue!.fingerprint,
            line_hash: issue!.lineHash,
            context_hash: issue!.contextHash,
            path: issue!.path,
            start_line: issue!.startLine,
            start_column: issue!.startColumn,
            end_line: issue!.endLine,
            end_column: issue!.endColumn,
            message: issue!.message,
            severity: issue!.severity as Severity,
            quality: issue!.quality as Quality,
            kind: issue!.kind,
            status: 'wont_fix', // coincidentally the same value the concurrent writer landed on
            in_new_code: issue!.inNewCode,
            snippet: issue!.snippet,
            secondary_locations: issue!.secondaryLocations,
            from_status: 'open', // planned from a stale read
          },
        ],
        inserts: [],
        closes: [],
        live: [],
      },
      { projectId: p.id, branchId: issue!.branchId, analysisId },
    );
    expect(await issuesOf(p)).toMatchObject([
      { id: issue!.id, status: 'wont_fix', resolvedBy: h.ctx.adminId },
    ]);
    // A naive RETURNING-only check (i.status = r.status post-update) would see 'wont_fix' =
    // 'wont_fix' and wrongly conclude the plan's transition applied. It didn't: the guard blocked
    // it, and this must not be logged (U5 fix round 3, #C).
    expect(await changesOf(issue!.id)).toEqual([]);
  });

  it('never lets a stale plan close an issue whose status already changed (lost-update guard on close) (#3)', async () => {
    const p = await h.project('track/lost-update-close');
    const analysisId = await p.ingestOk(
      report(p, { files: [file('src/a.ts')], findings: [finding({ line: 1 })] }),
    );
    const [issue] = await issuesOf(p);
    // Simulates a concurrent transition landing after the plan already read status = 'open' and
    // (correctly, at the time) decided to close this now-unmatched issue.
    await h.ctx.db
      .update(issues)
      .set({ status: 'wont_fix', resolvedAt: new Date(), resolvedBy: h.ctx.adminId })
      .where(eq(issues.id, issue!.id));
    await writePlan(
      h.ctx.db,
      { updates: [], inserts: [], closes: [{ id: issue!.id, from_status: 'open' }], live: [] },
      { projectId: p.id, branchId: issue!.branchId, analysisId },
    );
    expect(await issuesOf(p)).toMatchObject([
      { id: issue!.id, status: 'wont_fix', resolvedBy: h.ctx.adminId },
    ]);
    expect(await changesOf(issue!.id)).toEqual([]);
  });
});
