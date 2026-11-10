import type { VexJustification } from '../vulnerabilities/decisions';
import type {
  ComplianceReportScope,
  ComplianceReportStatus,
  ComplianceStandardRef,
} from '../db/schema';

export type { ComplianceReportScope, ComplianceReportStatus, ComplianceStandardRef };
export type Severity = 'blocker' | 'high' | 'medium' | 'low' | 'info';
export type FindingSection = 'code' | 'secret' | 'dependency';
export type TriageStatus = 'false_positive' | 'wont_fix';

export interface ComplianceProjectSource {
  id: string;
  key: string;
  name: string;
  branch: { id: string; name: string } | null;
  analysis: {
    id: string;
    date: string | null;
    revision: string | null;
    versionLabel: string | null;
  } | null;
  gate: {
    status: 'passed' | 'failed' | 'error' | 'none';
    failedConditions: {
      metric: string;
      op: 'gt' | 'lt';
      threshold: number;
      actual: number | null;
    }[];
  } | null;
  /** Up to 12 succeeded analyses of the branch, oldest first. */
  trend: {
    analysisId: string;
    date: string | null;
    security_issues: number | null;
    security_rating: number | null;
  }[];
}

/** Exact counts, one row per (status, section, rule, severity, kind, inNewCode). */
export interface ComplianceFindingGroup {
  status: 'open' | TriageStatus;
  section: FindingSection;
  rule: string;
  severity: Severity;
  kind: 'issue' | 'hotspot';
  inNewCode: boolean;
  cwe: number[];
  count: number;
  oldestFirstSeenAt: string;
}

/**
 * The server's facts about the vulnerability of a dependency finding. `kev` and `epss` are null
 * without `vuln.priority`, and when the vulnerability has none.
 */
export interface ComplianceVulnerability {
  id: string;
  packageName: string;
  fixedVersions: string[];
  kev: { dateAdded: string } | null;
  epss: { score: number; percentile: number } | null;
}

export interface ComplianceFindingRow {
  id: string;
  project: string;
  path: string | null;
  line: number | null;
  rule: string;
  ruleName: string;
  engine: string;
  severity: Severity;
  kind: 'issue' | 'hotspot';
  cwe: number[];
  message: string;
  inNewCode: boolean;
  firstSeenAt: string;
  section: FindingSection;
  /** Null for code and secrets, and when no vulnerability row of the server matches. */
  vulnerability: ComplianceVulnerability | null;
}

export interface ComplianceTriageRow {
  id: string;
  project: string;
  path: string | null;
  line: number | null;
  rule: string;
  severity: Severity;
  cwe: number[];
  status: TriageStatus;
  section: FindingSection;
  by: string | null;
  at: string | null;
  comment: string | null;
  /** The reason of the effective decision of a dependency finding; null otherwise. */
  reason: VexJustification | null;
  vulnerability: ComplianceVulnerability | null;
}

/** The datasets a report was built from; KEV and EPSS are null without `vuln.priority`. */
export interface ComplianceDatasets {
  vulnerabilityDatabase: { builtAt: string | null; digest: string } | null;
  kev: { refreshedAt: string; digest: string } | null;
  epss: { dataDate: string | null; refreshedAt: string; digest: string } | null;
}

export interface ComplianceSource {
  /** The transaction's now(), ISO with milliseconds. */
  generatedAt: string;
  /** The report row's created_by_name (the job has no request). */
  createdBy: string;
  scope: {
    kind: ComplianceReportScope;
    organization: { id: string; key: string; name: string };
    project: { id: string; key: string; name: string } | null;
    branch: { id: string; name: string } | null;
    /** Set for the report of a version, which holds its dependencies only (plan 5, V12). */
    version: { id: string; label: string } | null;
  };
  projects: ComplianceProjectSource[];
  groups: ComplianceFindingGroup[];
  /**
   * At most limit + 1 rows. A branch report sorts by (severityRank, project key, path, line, id);
   * a version report by (severity rank, vulnerability id, package, version, row id).
   */
  findings: ComplianceFindingRow[];
  /** At most limit + 1 rows, newest decision first. */
  triage: ComplianceTriageRow[];
  datasets: ComplianceDatasets;
}

export const MAX_ORGANIZATION_PROJECTS = 2_000;
export const TRIAGE_COMMENT_MAX = 1_000;
export const TREND_POINTS = 12;
