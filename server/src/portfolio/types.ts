import type { Granularity } from './periods';

/** 4E-2 §2: the portfolio read model, shared by core's contract and the Enterprise service. */
export type PortfolioScopeInput =
  { scope: 'organization'; organizationId: string } | { scope: 'all' };

export type PortfolioSort =
  | 'key'
  | 'gate'
  | 'security'
  | 'reliability'
  | 'issues'
  | 'ncloc'
  | 'coverage'
  | 'lastAnalysis'
  | 'vulnerableReleases'
  | 'exploited';

export type Rating = 'A' | 'B' | 'C' | 'D' | 'E';

export interface SeverityCounts {
  blocker: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface PortfolioAggregate {
  projects: number;
  analysed: number;
  abandoned: number;
  gate: { passed: number; failed: number; error: number; none: number };
  passedShare: number | null;
  securityRating: Record<Rating, number>;
  reliabilityRating: Record<Rating, number>;
  ncloc: number;
  coverage: number | null;
  duplication: number | null;
  issues: number;
  bySeverity: SeverityCounts;
  securityIssues: number;
  reliabilityIssues: number;
  maintainabilityIssues: number;
  newIssues: number;
}

export interface PortfolioProjectRow {
  organization: { key: string; name: string };
  project: { id: string; key: string; name: string };
  lastAnalysisAt: string | null;
  abandoned: boolean;
  gate: 'passed' | 'failed' | 'error' | 'none' | null;
  securityRating: Rating | null;
  reliabilityRating: Rating | null;
  ncloc: number | null;
  coverage: number | null;
  duplication: number | null;
  issues: number | null;
  bySeverity: SeverityCounts | null;
  newIssues: number | null;
  secrets: number;
  vulnerableDependencies: number;
  /** Tracked versions with an open vulnerability; null while monitoring is off. */
  vulnerableReleases: number | null;
  /** Open KEV vulnerabilities on main and tracked versions; null while off or without `vuln.priority`. */
  exploited: number | null;
}

export interface PortfolioTrendPoint extends PortfolioAggregate {
  start: string;
  end: string;
  analyses: number;
  triage: number;
}

export interface PortfolioOverview {
  generatedAt: string;
  scope: {
    kind: 'organization' | 'all';
    organization: { id: string; key: string; name: string } | null;
  };
  granularity: Granularity;
  totals: PortfolioAggregate & {
    secrets: number;
    vulnerableDependencies: number;
    /** The sum of the rows' values; null when every row is null. */
    vulnerableReleases: number | null;
    exploited: number | null;
  };
  organizations: (PortfolioAggregate & { id: string; key: string; name: string })[] | null;
  trend: PortfolioTrendPoint[];
  attention: {
    /** The projects with exploited vulnerabilities, most first; null without `vuln.priority`. */
    exploited: PortfolioProjectRow[] | null;
    failingGates: PortfolioProjectRow[];
    worstSecurity: PortfolioProjectRow[];
    mostSevere: PortfolioProjectRow[];
    abandoned: PortfolioProjectRow[];
  };
}
