import { computeFingerprints } from '../hash';
import type { ReportFinding } from './schema';

/**
 * data-model.md §5.1: the fingerprint of every finding of a report, in report order, exactly as
 * the server computes it at ingestion. The CLI writes the same values into GitLab's Code Quality
 * and SAST reports (scm.md §9), so GitLab and Qualor agree on which finding is which. It depends
 * only on the rule, the path, the line and context hashes and the position among equal findings,
 * so a rescan of the same code gives the same values.
 */
export function reportFingerprints(findings: readonly ReportFinding[]): string[] {
  return computeFingerprints(
    findings.map((f) => ({
      ruleKey: `${f.engineId}:${f.ruleId}`,
      path: f.location?.path ?? null,
      lineHash: f.lineHash,
      contextHash: f.contextHash,
      startLine: f.location?.startLine ?? 0,
      startColumn: f.location?.startColumn ?? 0,
    })),
  );
}
