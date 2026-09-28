import { reportFingerprints } from '@qualor/shared';
import { AnalysisFailure, type IngestionStage } from '../ingest/process';
import type { AcceptedFinding } from '../ingest/state';
import { ruleKey, upsertReportedRules } from './catalog';
import { governingLanguage, loadProfileSet, ruleSetting } from './profiles';

/**
 * Server step 7: upsert the rule catalog from the report, then keep only the findings whose rule
 * is active in the effective profile (profiles filter, they do not configure analyzers),
 * re-graded by the profile's severity override. Dropped findings are counted in one warning and
 * never stored (data-model.md §4.4).
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
    const accepted: AcceptedFinding[] = [];
    let filtered = 0;
    report.findings.forEach((finding, index) => {
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
    ctx.state.findings = accepted;
  },
};
