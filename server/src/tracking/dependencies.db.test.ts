import { and, asc, eq } from 'drizzle-orm';
import { filelessHash, type Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, reportWith, type ReportParts } from '../../test/reports';
import { analyses, branches, issues, measures } from '../db/schema';

/**
 * Plan 2B: a vulnerable dependency is an ordinary issue of the `trivy` engine on its lockfile.
 * Its hashes are the package's identity (report-format.md §7.3), and whether it is new code is
 * gates.md §5's line rule applied to its lock entry: a merge request that adds or changes the
 * entry brings its vulnerabilities in as new; a vulnerability published later against an
 * unchanged entry is not new.
 */
describe('dependency vulnerabilities (plan 2B)', () => {
  let h: IngestHarness;
  let minute = 0;
  const LOCK = 'web/package-lock.json';
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 8, 25, 10, minute++)).toISOString(),
      ...parts,
    });
  const trivyEngine = {
    ...engine('trivy', [
      { id: 'CVE-2021-44906', quality: 'security', kind: 'issue', defaultSeverity: 'blocker' },
    ]),
    database: { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11.019457553Z' },
  } satisfies Report['engines'][number];
  const lockfile = (newLines: [number, number][] | 'all' = []) =>
    file(LOCK, { language: 'other', lines: 40, newLines });
  const vuln = (
    id: string,
    pkg: string,
    line: number,
    severity: 'blocker' | 'high' = 'blocker',
  ) => {
    const hash = filelessHash(`trivy:${id}`, pkg, LOCK);
    return {
      engineId: 'trivy',
      ruleId: id,
      message: `${pkg}: ${id}`,
      severity,
      location: { path: LOCK, startLine: line, endLine: line },
      lineHash: hash,
      contextHash: hash,
    } satisfies Report['findings'][number];
  };
  const issuesOf = (p: IngestProject, branchId: string) =>
    h.ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.projectId, p.id), eq(issues.branchId, branchId)))
      .orderBy(asc(issues.id));
  const branchOf = async (p: IngestProject, kind: 'branch' | 'merge_request') => {
    const [row] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.kind, kind)));
    return row!;
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

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('keeps a vulnerability when its lock entry moves, and stores the database date', async () => {
    const p = await h.project('deps/moves');
    const first = await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile()],
        findings: [vuln('CVE-2021-44906', 'minimist@1.2.5', 15)],
      }),
    );
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, first));
    expect(row!.engines).toEqual([
      expect.objectContaining({
        id: 'trivy',
        database: { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11.019457553Z' },
      }),
    ]);
    const main = await branchOf(p, 'branch');
    const [before] = await issuesOf(p, main.id);
    expect(before).toMatchObject({ status: 'open', severity: 'blocker', quality: 'security' });

    // Another package was added above it (lines 14–19): the entry moved from lines 14–19 to
    // 20–25, its version line from 15 to 21.
    await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile([[14, 19]])],
        findings: [vuln('CVE-2021-44906', 'minimist@1.2.5', 21)],
      }),
    );
    const after = await issuesOf(p, main.id);
    expect(after).toHaveLength(1);
    expect(after[0]).toMatchObject({ id: before!.id, startLine: 21, status: 'open' });
  });

  it('counts a vulnerability published later against an unchanged entry as old code', async () => {
    const p = await h.project('deps/published');
    await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile()],
        findings: [vuln('CVE-2021-44906', 'minimist@1.2.5', 15)],
      }),
    );
    // A newer database knows a second vulnerability of the same, unchanged, package.
    const second = await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile()],
        findings: [
          vuln('CVE-2021-44906', 'minimist@1.2.5', 15),
          vuln('CVE-2099-0001', 'minimist@1.2.5', 15, 'high'),
        ],
      }),
    );
    const main = await branchOf(p, 'branch');
    const found = await issuesOf(p, main.id);
    expect(found.map((i) => [i.startLine, i.inNewCode, i.status])).toEqual([
      [15, false, 'open'],
      [15, false, 'open'],
    ]);
    expect(await measure(second, 'security_issues', 'overall')).toBe(2);
    expect(await measure(second, 'security_issues', 'new')).toBe(0);
    expect(await measure(second, 'security_rating', 'overall')).toBe(5);
  });

  it('fails the merge request that adds a vulnerable dependency, on new_issues', async () => {
    const p = await h.project('deps/mr');
    await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile()],
        findings: [vuln('CVE-2021-44906', 'minimist@1.2.5', 15)],
      }),
    );
    // The merge request adds lodash 4.17.20 below minimist (lines 20–25, its version line 21);
    // minimist's entry is unchanged.
    const mr = await p.ingestOk(
      report(p, {
        branch: 'feature/lodash',
        mergeRequest: { id: '7', targetBranch: 'main', sourceBranch: 'feature/lodash' },
        baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
        engines: [trivyEngine],
        files: [lockfile([[20, 25]])],
        findings: [
          vuln('CVE-2021-44906', 'minimist@1.2.5', 15),
          vuln('CVE-2021-23337', 'lodash@4.17.20', 21, 'high'),
        ],
      }),
    );
    const branch = await branchOf(p, 'merge_request');
    const found = await issuesOf(p, branch.id);
    expect(found.map((i) => [i.message, i.inNewCode])).toEqual([
      ['minimist@1.2.5: CVE-2021-44906', false],
      ['lodash@4.17.20: CVE-2021-23337', true],
    ]);
    expect(await measure(mr, 'security_issues', 'new')).toBe(1);
    expect(await measure(mr, 'security_rating', 'new')).toBe(4);
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, mr));
    expect(row!.gateStatus).toBe('failed');
    expect(row!.gateResult).toMatchObject({
      conditions: expect.arrayContaining([
        expect.objectContaining({ metric: 'new_issues', value: 1, status: 'failed' }),
      ]),
    });
  });

  it('closes the vulnerability when the dependency is upgraded, and tracks the new version apart', async () => {
    const p = await h.project('deps/upgrade');
    await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile()],
        findings: [vuln('CVE-2021-44906', 'minimist@1.2.5', 15)],
      }),
    );
    // 1.2.5 → 1.2.6 fixes CVE-2021-44906; a (made-up) CVE of 1.2.6 is another issue. As in a
    // real diff, only the entry's version, resolved and integrity lines (15–17) change: its key
    // line 14 (`"node_modules/minimist": {`) does not, so the finding must sit on line 15
    // (ruling T3) to be new code.
    await p.ingestOk(
      report(p, {
        engines: [trivyEngine],
        files: [lockfile([[15, 17]])],
        findings: [vuln('CVE-2099-0002', 'minimist@1.2.6', 15, 'high')],
      }),
    );
    const main = await branchOf(p, 'branch');
    const found = await issuesOf(p, main.id);
    expect(found.map((i) => [i.message, i.status, i.inNewCode])).toEqual([
      ['minimist@1.2.5: CVE-2021-44906', 'closed', false],
      ['minimist@1.2.6: CVE-2099-0002', 'open', true],
    ]);
  });
});
