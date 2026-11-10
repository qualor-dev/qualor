// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type {
  ComplianceDatasets,
  ComplianceFindingRow,
  ComplianceProjectSource,
  ComplianceTriageRow,
  ComplianceVulnerability,
} from '@qualor/server/plugin-contract';

/** 4E-1 §2.3: the canonical report. Field order is the canonical key order. */
export const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
export type SeverityCounts = Record<(typeof SEVERITIES)[number], number>;

export interface CategorySummary {
  id: string;
  title: string;
  open: number;
  bySeverity: SeverityCounts;
  inNewCode: number;
  rules: number;
  oldestFirstSeenAt: string | null;
}

export interface StandardSummary {
  id: string;
  categories: CategorySummary[];
  notMapped: { open: number; bySeverity: SeverityCounts; inNewCode: number; rules: number };
  distinctTotal: number;
}

export interface ReportSummary {
  findings: { total: number; bySeverity: SeverityCounts; inNewCode: number };
  standards: StandardSummary[];
  secrets: { open: number };
  dependencies: { open: number; bySeverity: SeverityCounts };
  triage: { falsePositive: number; wontFix: number };
  truncated: boolean;
}

/** The server's facts about the vulnerability of a dependency finding (schema 2). */
export type ReportVulnerability = ComplianceVulnerability;
export type ReportDatasets = ComplianceDatasets;

export interface ReportFinding {
  id: string;
  project: string;
  path: string | null;
  line: number | null;
  rule: string;
  ruleName: string;
  engine: string;
  severity: ComplianceFindingRow['severity'];
  kind: ComplianceFindingRow['kind'];
  cwe: number[];
  message: string;
  categories: Record<string, string[]>;
  inNewCode: boolean;
  firstSeenAt: string;
  section: ComplianceFindingRow['section'];
  vulnerability: ReportVulnerability | null;
}

export interface ReportTriage {
  id: string;
  project: string;
  path: string | null;
  line: number | null;
  rule: string;
  severity: ComplianceTriageRow['severity'];
  cwe: number[];
  categories: Record<string, string[]>;
  status: ComplianceTriageRow['status'];
  section: ComplianceTriageRow['section'];
  by: string | null;
  at: string | null;
  comment: string | null;
  reason: ComplianceTriageRow['reason'];
  vulnerability: ReportVulnerability | null;
}

export interface ReportProject {
  id: string;
  key: string;
  name: string;
  branch: string | null;
  analysis: ComplianceProjectSource['analysis'];
  gate: ComplianceProjectSource['gate'];
  trend: ComplianceProjectSource['trend'];
}

/** The SBOM a project report attaches (schema 2); the file itself is stored beside the report. */
export interface ReportSbom {
  format: 'CycloneDX 1.6';
  sha256: string;
  components: number;
}

export interface ReportJson {
  /** 2 for every new report; a stored version 1 is read with the new fields empty. */
  schemaVersion: 1 | 2;
  id: string;
  generatedAt: string;
  generatedBy: string;
  server: { version: string };
  scope: {
    kind: 'project' | 'organization';
    organization: { id: string; name: string };
    project: { id: string; key: string; name: string } | null;
    branch: { id: string; name: string } | null;
    /**
     * Set for the report of a version, which holds its dependencies only (schema 2). `tracked` is
     * whether the server tracks the version when the report is built; `checkedAt` is the time of
     * its last vulnerability check, as ISO.
     */
    version: { id: string; label: string; tracked: boolean; checkedAt: string } | null;
  };
  standards: {
    id: string;
    version: string;
    title: string;
    source: string;
    licence: string;
    sourceSha256: string;
  }[];
  datasets: ReportDatasets;
  /** Null for an organisation report, or a target without an inventory. */
  sbom: ReportSbom | null;
  projects: ReportProject[];
  summary: ReportSummary;
  findings: ReportFinding[];
  triage: ReportTriage[];
}
