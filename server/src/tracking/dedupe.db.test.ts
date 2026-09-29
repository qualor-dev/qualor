import { readFileSync } from 'node:fs';
import { and, asc, eq, isNull, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, finding, reportWith } from '../../test/reports';
import { issues, rules } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import { rulesStage } from '../rules/stage';
import { applyTrackingPlan, buildTrackingPlan } from './stage';

interface NormalizedSample {
  version: string;
  rules: Report['engines'][number]['rules'];
  findings: Report['findings'];
}

/** The committed, real Gitleaks and Semgrep output for fixtures/mixed-secrets (Phase 0 Task 14). */
function sample(engineId: 'gitleaks' | 'semgrep'): NormalizedSample {
  const url = new URL(
    `../../../packages/shared/test/sarif-samples/${engineId}.normalized.json`,
    import.meta.url,
  );
  return JSON.parse(readFileSync(url, 'utf8')) as NormalizedSample;
}

function mixedSecretsReport(key: string, analysisDate: string, only?: 'semgrep'): Report {
  const engines = (['gitleaks', 'semgrep'] as const).map((id) => {
    const s = sample(id);
    return { ...engine(id, s.rules), version: s.version };
  });
  const findings = (['gitleaks', 'semgrep'] as const)
    .filter((id) => only === undefined || id === only)
    .flatMap((id) => sample(id).findings);
  const paths = ['src/config.ts', 'src/run.ts', 'java/src/main/java/com/acme/Shell.java'];
  return reportWith({
    projectKey: key,
    analysisDate,
    engines,
    files: paths.map((p) => file(p, { language: p.endsWith('.java') ? 'java' : 'typescript' })),
    findings,
  });
}

describe('cross-engine dedupe (data-model.md §5.3)', () => {
  let h: IngestHarness;
  const visible = (p: IngestProject) =>
    h.ctx.db
      .select({ id: issues.id, key: rules.key })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .where(
        and(
          eq(issues.projectId, p.id),
          eq(issues.status, 'open'),
          isNull(issues.duplicateOfIssueId),
        ),
      )
      .orderBy(asc(rules.key));
  const byRule = async (p: IngestProject, key: string) =>
    (
      await h.ctx.db
        .select({ issue: issues })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .where(and(eq(issues.projectId, p.id), eq(rules.key, key)))
    )[0]?.issue;

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('shows the Gitleaks + Semgrep pair of fixtures/mixed-secrets as one visible issue (§8.5)', async () => {
    const p = await h.project('dedupe/mixed-secrets');
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T10:00:00Z'));
    expect((await visible(p)).map((r) => r.key)).toEqual([
      'gitleaks:generic-api-key',
      'semgrep:java-runtime-exec',
      'semgrep:ts-eval',
    ]);
    const primary = await byRule(p, 'gitleaks:generic-api-key');
    expect(await byRule(p, 'semgrep:hardcoded-api-key')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
  });

  it('hides both copies when one engine reports the same secret twice next to another engine', async () => {
    const p = await h.project('dedupe/twice');
    const report = mixedSecretsReport(p.key, '2026-09-22T10:00:00Z');
    const semgrepSecret = report.findings.find((f) => f.ruleId === 'hardcoded-api-key')!;
    report.findings.push({ ...semgrepSecret });
    await p.ingestOk(report);
    const primary = await byRule(p, 'gitleaks:generic-api-key');
    const copies = await h.ctx.db
      .select({ issue: issues })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .where(and(eq(issues.projectId, p.id), eq(rules.key, 'semgrep:hardcoded-api-key')));
    expect(copies).toHaveLength(2);
    expect(new Set(copies.map((c) => c.issue.fingerprint)).size).toBe(2);
    expect(copies.every((c) => c.issue.duplicateOfIssueId === primary!.id)).toBe(true);
    expect((await visible(p)).map((r) => r.key)).toContain('gitleaks:generic-api-key');
    expect(await visible(p)).toHaveLength(3);
  });

  it('promotes the duplicate when its primary is closed', async () => {
    const p = await h.project('dedupe/promote');
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T10:00:00Z'));
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T11:00:00Z', 'semgrep'));
    expect(await byRule(p, 'gitleaks:generic-api-key')).toMatchObject({ status: 'closed' });
    expect(await byRule(p, 'semgrep:hardcoded-api-key')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: null,
    });
  });

  it('keeps a duplicate pointing at a primary whose close a concurrent change blocked', async () => {
    const p = await h.project('dedupe/blocked-close');
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T10:00:00Z'));
    const primary = await byRule(p, 'gitleaks:generic-api-key');
    // The tracking stage, with a concurrent writer (say, a user marking the secret wont_fix)
    // landing between the plan (which closes the Gitleaks issue) and the writes.
    const racing: IngestionStage = {
      name: 'tracking',
      async run(ctx) {
        const built = await buildTrackingPlan(ctx);
        expect(built.plan.closes.map((c) => c.id)).toContain(primary!.id);
        await ctx.tx.execute(
          sql`UPDATE issues SET status = 'wont_fix' WHERE id = ${primary!.id}::uuid`,
        );
        await applyTrackingPlan(ctx, built);
      },
    };
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T11:00:00Z', 'semgrep'), [
      rulesStage,
      racing,
    ]);
    expect(await byRule(p, 'gitleaks:generic-api-key')).toMatchObject({ status: 'wont_fix' });
    expect(await byRule(p, 'semgrep:hardcoded-api-key')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
  });

  it('never points a duplicate at a primary whose planned reopen was blocked (liveAfterWrites, blocked update)', async () => {
    const p = await h.project('dedupe/blocked-reopen');
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T10:00:00Z'));
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T11:00:00Z', 'semgrep'));
    const primary = await byRule(p, 'gitleaks:generic-api-key');
    expect(primary).toMatchObject({ status: 'closed' });
    // Both engines report the secret again, so the plan reopens the closed Gitleaks issue and
    // would make it the Semgrep issue's primary; but the closed row is deleted (say, by
    // retention) between the plan and the writes, which blocks the planned update.
    const racing: IngestionStage = {
      name: 'tracking',
      async run(ctx) {
        const built = await buildTrackingPlan(ctx);
        expect(built.plan.updates.map((u) => u.id)).toContain(primary!.id);
        expect(built.plan.live.map((l) => l.id)).toContain(primary!.id);
        await ctx.tx.execute(sql`DELETE FROM issues WHERE id = ${primary!.id}::uuid`);
        await applyTrackingPlan(ctx, built);
      },
    };
    await p.ingestOk(mixedSecretsReport(p.key, '2026-09-22T12:00:00Z'), [rulesStage, racing]);
    expect(await byRule(p, 'semgrep:hardcoded-api-key')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: null,
    });
  });

  it('dedupes a curated pair without a CWE, and never an unrelated rule on the same line', async () => {
    const p = await h.project('dedupe/pairs');
    const evalRule = 'javascript.browser.security.eval-detected.eval-detected';
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint'), engine('semgrep')],
        files: [file('src/a.ts')],
        findings: [
          finding({ ruleId: 'no-eval', line: 4 }),
          finding({ engineId: 'semgrep', ruleId: evalRule, line: 4 }),
          finding({ ruleId: 'no-console', line: 4 }),
        ],
      }),
    );
    const primary = await byRule(p, `semgrep:${evalRule}`);
    expect(await byRule(p, 'eslint:no-eval')).toMatchObject({ duplicateOfIssueId: primary!.id });
    expect(await byRule(p, 'eslint:no-console')).toMatchObject({ duplicateOfIssueId: null });
  });

  it('dedupes the ESLint rule a decorated sonarjs rule wraps, ESLint primary (Task 8)', async () => {
    const p = await h.project('dedupe/sonarjs-decorated');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint'), engine('sonarjs')],
        files: [file('src/a.ts')],
        findings: [
          finding({ ruleId: 'no-empty-function', line: 4 }),
          finding({ engineId: 'sonarjs', ruleId: 'S1186', line: 4 }),
          finding({ ruleId: 'no-console', line: 4 }),
        ],
      }),
    );
    const primary = await byRule(p, 'eslint:no-empty-function');
    expect(await byRule(p, 'sonarjs:S1186')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    expect(await byRule(p, 'eslint:no-console')).toMatchObject({ duplicateOfIssueId: null });
  });
});
