import { reportFingerprints } from '@qualor/shared';
import { AnalysisFailure, type IngestionStage } from '../ingest/process';
import type { AcceptedFinding } from '../ingest/state';
import { ruleKey, upsertReportedRules } from './catalog';
import { governingLanguage, loadProfileSet, ruleSetting } from './profiles';
import { SERVER_ENGINES } from './server-engines';

/**
 * Server step 7: upsert the rule catalog from the report, then keep only the findings whose rule
 * is active in the effective profile (profiles filter, they do not configure analyzers),
 * re-graded by the profile's severity override. Dropped findings are counted in one warning and
 * never stored (data-model.md §4.4). A finding of a server engine (rules/server-engines.ts) is
 * dropped: only the server makes those (the licence policy stage, the AI review), so a report can
 * neither open nor keep such an issue.
 *
 * 0.13: a rule's scope keeps a `main` rule off the report's `test` files and a `test` rule off its
 * `main` files. The scope is the profile's nearest override, else the one this report's own rule
 * metadata gives, else `all`: a report without scopes (an older scanner, an external SARIF) loses
 * nothing to another report's. Those findings are counted in a warning per kind of code and never
 * stored either, so tracking closes their issues.
 */
export const rulesStage: IngestionStage = {
  name: 'rules',
  async run(ctx) {
    const { report, tx } = ctx;
    const rules = await upsertReportedRules(tx, report);
    const profiles = await loadProfileSet(
      tx,
      ctx.project,
      [...rules.values()].map((r) => r.id),
    );
    // Shared with the CLI's GitLab report files (scm.md §9), so both name a finding alike.
    const fingerprints = reportFingerprints(report.findings);
    const languageOf = new Map(report.files.map((f) => [f.path, f.language]));
    const kindOf = new Map(report.files.map((f) => [f.path, f.kind]));
    const accepted: AcceptedFinding[] = [];
    let filtered = 0;
    /** Findings a rule's scope dropped, by the kind of code they were on. */
    const outOfScope = { test: 0, main: 0 };
    let serverOnly = 0;
    report.findings.forEach((finding, index) => {
      if (SERVER_ENGINES.has(finding.engineId)) {
        serverOnly += 1;
        return;
      }
      const key = ruleKey(finding.engineId, finding.ruleId);
      const rule = rules.get(key);
      // upsertReportedRules creates every referenced rule, so this should never happen — but if
      // it ever does (a stage-ordering bug, not the reporter's fault), retrying can't fix it:
      // fail the analysis at once (ruling U4) rather than let the job retry forever.
      if (!rule) throw new AnalysisFailure('RULE_NOT_UPSERTED', `rule ${key} was not upserted`);
      const language = governingLanguage(
        finding.engineId,
        finding.location ? (languageOf.get(finding.location.path) ?? null) : null,
      );
      const setting = ruleSetting(profiles, language, rule.id);
      if (!setting.active) {
        filtered += 1;
        return;
      }
      // A file-less finding, or one on a file the report does not list, has no kind of code: its
      // rule's scope never drops it.
      const kind = finding.location ? kindOf.get(finding.location.path) : undefined;
      const scope = setting.scopeOverride ?? rule.reportScope ?? 'all';
      if (kind !== undefined && scope !== 'all' && scope !== kind) {
        outOfScope[kind] += 1;
        return;
      }
      accepted.push({
        index,
        finding,
        rule,
        severity: setting.severityOverride ?? finding.severity ?? rule.defaultSeverity,
        fingerprint: fingerprints[index] ?? '',
      });
    });
    if (filtered > 0) {
      ctx.warnings.push({
        code: 'FINDINGS_FILTERED_BY_PROFILE',
        message: `${filtered} finding(s) were dropped because their rule is not active in the quality profile`,
        count: filtered,
      });
    }
    for (const kind of ['test', 'main'] as const) {
      const count = outOfScope[kind];
      if (count === 0) continue;
      ctx.warnings.push({
        code: 'FINDINGS_FILTERED_BY_SCOPE',
        message: `${count} finding(s) were dropped because their rule does not apply to ${kind} code`,
        count,
      });
    }
    if (serverOnly > 0) {
      ctx.logger.debug(
        { analysisId: ctx.analysisId, dropped: serverOnly },
        'dropped report findings of a server-only engine',
      );
    }
    ctx.state.findings = accepted;
  },
};
