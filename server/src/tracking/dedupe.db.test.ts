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

  it("dedupes the project's own eslint-plugin-sonarjs rule and the sonarjs pass's key, ESLint primary", async () => {
    const p = await h.project('dedupe/sonarjs-own-plugin');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint'), engine('sonarjs')],
        files: [file('src/a.ts')],
        findings: [
          finding({ ruleId: 'sonarjs/no-duplicated-branches', line: 4 }),
          finding({ engineId: 'sonarjs', ruleId: 'S1871', line: 4 }),
        ],
      }),
    );
    const primary = await byRule(p, 'eslint:sonarjs/no-duplicated-branches');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'sonarjs:S1871')).toMatchObject({ duplicateOfIssueId: primary!.id });
  });

  it("dedupes a project's own imported Ruff SARIF (ext-ruff) against the built-in ruff rule of the same code, ruff primary", async () => {
    const p = await h.project('dedupe/ext-ruff');
    const py = (path: string) => file(path, { language: 'python' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('ruff'), engine('ext-ruff')],
        files: [py('app.py')],
        findings: [
          finding({ engineId: 'ext-ruff', ruleId: 'F401', path: 'app.py', line: 1 }),
          finding({ engineId: 'ruff', ruleId: 'F401', path: 'app.py', line: 1 }),
          finding({ engineId: 'ext-ruff', ruleId: 'F811', path: 'app.py', line: 1 }),
          finding({ engineId: 'ext-ruff', ruleId: 'E711', path: 'app.py', line: 3 }),
          finding({ engineId: 'ruff', ruleId: 'E711', path: 'app.py', line: 4 }),
        ],
      }),
    );
    const primary = await byRule(p, 'ruff:F401');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-ruff:F401')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    // Another code on the same line, and the same code on another line, stay separate issues.
    expect(await byRule(p, 'ext-ruff:F811')).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-ruff:E711')).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ruff:E711')).toMatchObject({ duplicateOfIssueId: null });
  });

  it("dedupes a project's own imported stylelint SARIF (ext-stylelint) against the built-in stylelint rule of the same id, stylelint primary (plan 8D ruling D4)", async () => {
    const p = await h.project('dedupe/ext-stylelint');
    const css = (path: string) => file(path, { language: 'css' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('stylelint'), engine('ext-stylelint')],
        files: [css('src/a.css')],
        findings: [
          finding({
            engineId: 'ext-stylelint',
            ruleId: 'block-no-empty',
            path: 'src/a.css',
            line: 1,
          }),
          finding({ engineId: 'stylelint', ruleId: 'block-no-empty', path: 'src/a.css', line: 1 }),
          finding({
            engineId: 'ext-stylelint',
            ruleId: 'length-zero-no-unit',
            path: 'src/a.css',
            line: 1,
          }),
          finding({
            engineId: 'ext-stylelint',
            ruleId: 'color-no-invalid-hex',
            path: 'src/a.css',
            line: 3,
          }),
        ],
      }),
    );
    const primary = await byRule(p, 'stylelint:block-no-empty');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-stylelint:block-no-empty')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    // A different rule id on the same line, and the same rule id on another line, stay separate.
    expect(await byRule(p, 'ext-stylelint:length-zero-no-unit')).toMatchObject({
      duplicateOfIssueId: null,
    });
    expect(await byRule(p, 'ext-stylelint:color-no-invalid-hex')).toMatchObject({
      duplicateOfIssueId: null,
    });
  });

  it("dedupes a project's own imported HTMLHint SARIF (ext-htmlhint) against the built-in HTMLHint rule of the same id, htmlhint primary (plan 8D ruling D4)", async () => {
    const p = await h.project('dedupe/ext-htmlhint');
    const html = (path: string) => file(path, { language: 'html' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('htmlhint'), engine('ext-htmlhint')],
        files: [html('src/index.html')],
        findings: [
          finding({
            engineId: 'ext-htmlhint',
            ruleId: 'tag-pair',
            path: 'src/index.html',
            line: 1,
          }),
          finding({ engineId: 'htmlhint', ruleId: 'tag-pair', path: 'src/index.html', line: 1 }),
          finding({
            engineId: 'ext-htmlhint',
            ruleId: 'alt-require',
            path: 'src/index.html',
            line: 1,
          }),
        ],
      }),
    );
    const primary = await byRule(p, 'htmlhint:tag-pair');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-htmlhint:tag-pair')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    expect(await byRule(p, 'ext-htmlhint:alt-require')).toMatchObject({ duplicateOfIssueId: null });
  });

  it("dedupes a project's own imported detekt SARIF (ext-detekt, ids detekt.<ruleset>.<Rule>) against the built-in detekt rule, detekt primary (plan 8E ruling E5)", async () => {
    const p = await h.project('dedupe/ext-detekt');
    const kt = (path: string) => file(path, { language: 'kotlin' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('detekt'), engine('ext-detekt')],
        files: [kt('src/Main.kt')],
        findings: [
          finding({
            engineId: 'ext-detekt',
            ruleId: 'detekt.style.MagicNumber',
            path: 'src/Main.kt',
            line: 1,
          }),
          finding({ engineId: 'detekt', ruleId: 'MagicNumber', path: 'src/Main.kt', line: 1 }),
          finding({
            engineId: 'ext-detekt',
            ruleId: 'detekt.style.ReturnCount',
            path: 'src/Main.kt',
            line: 1,
          }),
        ],
      }),
    );
    const primary = await byRule(p, 'detekt:MagicNumber');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-detekt:detekt.style.MagicNumber')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    expect(await byRule(p, 'ext-detekt:detekt.style.ReturnCount')).toMatchObject({
      duplicateOfIssueId: null,
    });
  });

  it("dedupes a project's own imported SwiftLint SARIF (ext-swiftlint, identical ids) against the built-in SwiftLint rule, swiftlint primary (plan 8F ruling F4)", async () => {
    const p = await h.project('dedupe/ext-swiftlint');
    const sw = (path: string) => file(path, { language: 'swift' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('swiftlint'), engine('ext-swiftlint')],
        files: [sw('Sources/Main.swift')],
        findings: [
          finding({
            engineId: 'ext-swiftlint',
            ruleId: 'force_cast',
            path: 'Sources/Main.swift',
            line: 1,
          }),
          finding({
            engineId: 'swiftlint',
            ruleId: 'force_cast',
            path: 'Sources/Main.swift',
            line: 1,
          }),
          finding({
            engineId: 'ext-swiftlint',
            ruleId: 'force_try',
            path: 'Sources/Main.swift',
            line: 1,
          }),
        ],
      }),
    );
    const primary = await byRule(p, 'swiftlint:force_cast');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-swiftlint:force_cast')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    expect(await byRule(p, 'ext-swiftlint:force_try')).toMatchObject({ duplicateOfIssueId: null });
  });

  it("dedupes a project's own imported RuboCop SARIF (ext-rubocop, identical ids) against the built-in RuboCop rule, rubocop primary (plan 9B)", async () => {
    const p = await h.project('dedupe/ext-rubocop');
    const rb = (path: string) => file(path, { language: 'ruby' });
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('rubocop'), engine('ext-rubocop')],
        files: [rb('app/models/order.rb')],
        findings: [
          finding({
            engineId: 'ext-rubocop',
            ruleId: 'Lint/UselessAssignment',
            path: 'app/models/order.rb',
            line: 1,
          }),
          finding({
            engineId: 'rubocop',
            ruleId: 'Lint/UselessAssignment',
            path: 'app/models/order.rb',
            line: 1,
          }),
          finding({
            engineId: 'ext-rubocop',
            ruleId: 'Security/Eval',
            path: 'app/models/order.rb',
            line: 1,
          }),
        ],
      }),
    );
    const primary = await byRule(p, 'rubocop:Lint/UselessAssignment');
    expect(primary).toMatchObject({ duplicateOfIssueId: null });
    expect(await byRule(p, 'ext-rubocop:Lint/UselessAssignment')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: primary!.id,
    });
    expect(await byRule(p, 'ext-rubocop:Security/Eval')).toMatchObject({
      duplicateOfIssueId: null,
    });
  });
});
