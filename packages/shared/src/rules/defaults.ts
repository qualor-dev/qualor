import type { Quality, Severity } from '../report/taxonomy';

/**
 * Engines whose findings are vulnerable dependencies, not the project's own code (plan 2B): GitLab
 * gets them in its Dependency Scanning report, not in SAST (scm.md §9).
 */
export const DEPENDENCY_ENGINES: ReadonlySet<string> = new Set(['trivy']);

/**
 * report-format.md §7.1: the per-engine defaults of a rule that arrives without metadata. The
 * server applies them at ingestion (rules without metadata), and the CLI when it decides which
 * findings are security findings for GitLab's SAST report (scm.md §9).
 */
export function engineRuleDefaults(engineId: string): {
  quality: Quality;
  defaultSeverity: Severity;
} {
  if (engineId === 'gitleaks') return { quality: 'security', defaultSeverity: 'blocker' };
  // Every Trivy finding is a vulnerable dependency (plan 2B).
  if (engineId === 'trivy') return { quality: 'security', defaultSeverity: 'medium' };
  // Qualor's own security rules (plan 6B-1): a rule the server meets without metadata is still a
  // security rule; its kind and severity normally come from the pack (report-format.md §7.1).
  if (engineId === 'qualor') return { quality: 'security', defaultSeverity: 'medium' };
  // sonarjs (phase 8A) has no metadata-free default of its own: like eslint, an unmetered rule
  // falls through to plain maintainability/medium.
  return { quality: 'maintainability', defaultSeverity: 'medium' };
}
