// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createHash } from 'node:crypto';
import type { ComplianceFindingGroup, ComplianceSource } from '@qualor/server/plugin-contract';
import { STANDARDS, type StandardData } from './standard';
import type {
  CategorySummary,
  ReportJson,
  ReportSummary,
  ReportVulnerability,
  SeverityCounts,
  StandardSummary,
} from './report';

/** 4E-1 §2.3: findings and triage each keep at most this many entries. */
export const DETAIL_LIMIT = 50_000;

/** The categories of a standard a finding belongs to: by CWE, or by severity (PCI high-risk). */
export function categoriesOf(
  standard: StandardData,
  cwe: readonly number[],
  severity: string,
): string[] {
  return standard.categories
    .filter(
      (c) =>
        c.cwe.some((n) => cwe.includes(n)) ||
        (c.severities !== undefined && c.severities.includes(severity)),
    )
    .map((c) => c.id);
}

function zeroSeverities(): SeverityCounts {
  return { blocker: 0, high: 0, medium: 0, low: 0, info: 0 };
}

interface Tally {
  open: number;
  bySeverity: SeverityCounts;
  inNewCode: number;
  rules: Set<string>;
  oldest: string | null;
}

function newTally(): Tally {
  return { open: 0, bySeverity: zeroSeverities(), inNewCode: 0, rules: new Set(), oldest: null };
}

function add(t: Tally, g: ComplianceFindingGroup): void {
  t.open += g.count;
  t.bySeverity[g.severity] += g.count;
  if (g.inNewCode) t.inNewCode += g.count;
  t.rules.add(g.rule);
  if (t.oldest === null || g.oldestFirstSeenAt < t.oldest) t.oldest = g.oldestFirstSeenAt;
}

function summarise(
  groups: readonly ComplianceFindingGroup[],
  standards: readonly StandardData[],
  truncated: boolean,
): ReportSummary {
  const open = groups.filter((g) => g.status === 'open');
  const all = newTally();
  const secrets = newTally();
  const deps = newTally();
  for (const g of open) {
    add(all, g);
    if (g.section === 'secret') add(secrets, g);
    if (g.section === 'dependency') add(deps, g);
  }
  const standardSummaries: StandardSummary[] = standards.map((std) => {
    const cats = new Map<string, Tally>();
    for (const c of std.categories) cats.set(c.id, newTally());
    const unmapped = newTally();
    for (const g of open) {
      const ids = categoriesOf(std, g.cwe, g.severity);
      if (ids.length === 0) add(unmapped, g);
      for (const id of ids) {
        const t = cats.get(id);
        if (t) add(t, g);
      }
    }
    const categories: CategorySummary[] = std.categories.map((c) => {
      const t = cats.get(c.id) ?? newTally();
      return {
        id: c.id,
        title: c.title,
        open: t.open,
        bySeverity: t.bySeverity,
        inNewCode: t.inNewCode,
        rules: t.rules.size,
        oldestFirstSeenAt: t.oldest,
      };
    });
    return {
      id: std.id,
      categories,
      notMapped: {
        open: unmapped.open,
        bySeverity: unmapped.bySeverity,
        inNewCode: unmapped.inNewCode,
        rules: unmapped.rules.size,
      },
      distinctTotal: all.open,
    };
  });
  const countOf = (status: string): number =>
    groups.filter((g) => g.status === status).reduce((n, g) => n + g.count, 0);
  return {
    findings: { total: all.open, bySeverity: all.bySeverity, inNewCode: all.inNewCode },
    standards: standardSummaries,
    secrets: { open: secrets.open },
    dependencies: { open: deps.open, bySeverity: deps.bySeverity },
    triage: { falsePositive: countOf('false_positive'), wontFix: countOf('wont_fix') },
    truncated,
  };
}

/** The facts in the canonical key order. */
function vulnerabilityOf(v: ReportVulnerability | null): ReportVulnerability | null {
  return v
    ? {
        id: v.id,
        packageName: v.packageName,
        fixedVersions: [...v.fixedVersions],
        kev: v.kev ? { dateAdded: v.kev.dateAdded } : null,
        epss: v.epss ? { score: v.epss.score, percentile: v.epss.percentile } : null,
      }
    : null;
}

/** Builds the report from a collected source; every literal is in §2.3 key order. */
export function assembleReport(input: {
  id: string;
  generatedBy: string;
  serverVersion: string;
  source: ComplianceSource;
  standards?: readonly StandardData[];
  limit?: number;
}): {
  json: ReportJson;
  canonical: Buffer;
  sha256: string;
  summary: ReportSummary;
  /** The SBOM file the report names, for core to store beside it. */
  sbom: { json: string; sha256: string } | null;
} {
  const { source } = input;
  const standards = input.standards ?? STANDARDS;
  const limit = input.limit ?? DETAIL_LIMIT;
  const truncated = source.findings.length > limit || source.triage.length > limit;
  const categoryMap = (cwe: number[], severity: string): Record<string, string[]> => {
    const out: Record<string, string[]> = {};
    for (const std of standards) out[std.id] = categoriesOf(std, cwe, severity);
    return out;
  };
  const summary = summarise(source.groups, standards, truncated);
  const json: ReportJson = {
    schemaVersion: 2,
    id: input.id,
    generatedAt: source.generatedAt,
    generatedBy: input.generatedBy,
    server: { version: input.serverVersion },
    scope: {
      kind: source.scope.kind,
      organization: { id: source.scope.organization.id, name: source.scope.organization.name },
      project: source.scope.project
        ? {
            id: source.scope.project.id,
            key: source.scope.project.key,
            name: source.scope.project.name,
          }
        : null,
      branch: source.scope.branch
        ? { id: source.scope.branch.id, name: source.scope.branch.name }
        : null,
      version: source.scope.version
        ? { id: source.scope.version.id, label: source.scope.version.label }
        : null,
    },
    standards: standards.map((s) => ({
      id: s.id,
      version: s.version,
      title: s.title,
      source: s.source,
      licence: s.licence,
      sourceSha256: s.sourceSha256,
    })),
    datasets: {
      vulnerabilityDatabase: source.datasets.vulnerabilityDatabase
        ? {
            builtAt: source.datasets.vulnerabilityDatabase.builtAt,
            digest: source.datasets.vulnerabilityDatabase.digest,
          }
        : null,
      kev: source.datasets.kev
        ? { refreshedAt: source.datasets.kev.refreshedAt, digest: source.datasets.kev.digest }
        : null,
      epss: source.datasets.epss
        ? {
            dataDate: source.datasets.epss.dataDate,
            refreshedAt: source.datasets.epss.refreshedAt,
            digest: source.datasets.epss.digest,
          }
        : null,
    },
    sbom: source.sbom
      ? { format: 'CycloneDX 1.6', sha256: source.sbom.sha256, components: source.sbom.components }
      : null,
    projects: source.projects.map((p) => ({
      id: p.id,
      key: p.key,
      name: p.name,
      branch: p.branch ? p.branch.name : null,
      analysis: p.analysis
        ? {
            id: p.analysis.id,
            date: p.analysis.date,
            revision: p.analysis.revision,
            versionLabel: p.analysis.versionLabel,
          }
        : null,
      gate: p.gate
        ? {
            status: p.gate.status,
            failedConditions: p.gate.failedConditions.map((c) => ({
              metric: c.metric,
              op: c.op,
              threshold: c.threshold,
              actual: c.actual,
            })),
          }
        : null,
      trend: p.trend.map((t) => ({
        analysisId: t.analysisId,
        date: t.date,
        security_issues: t.security_issues,
        security_rating: t.security_rating,
      })),
    })),
    summary,
    findings: source.findings.slice(0, limit).map((f) => ({
      id: f.id,
      project: f.project,
      path: f.path,
      line: f.line,
      rule: f.rule,
      ruleName: f.ruleName,
      engine: f.engine,
      severity: f.severity,
      kind: f.kind,
      cwe: [...f.cwe],
      message: f.message,
      categories: categoryMap(f.cwe, f.severity),
      inNewCode: f.inNewCode,
      firstSeenAt: f.firstSeenAt,
      section: f.section,
      vulnerability: vulnerabilityOf(f.vulnerability),
    })),
    triage: source.triage.slice(0, limit).map((t) => ({
      id: t.id,
      project: t.project,
      path: t.path,
      line: t.line,
      rule: t.rule,
      severity: t.severity,
      cwe: [...t.cwe],
      categories: categoryMap(t.cwe, t.severity),
      status: t.status,
      section: t.section,
      by: t.by,
      at: t.at,
      comment: t.comment,
      reason: t.reason,
      vulnerability: vulnerabilityOf(t.vulnerability),
    })),
  };
  const canonical = Buffer.from(JSON.stringify(json), 'utf8');
  return {
    json,
    canonical,
    sha256: createHash('sha256').update(canonical).digest('hex'),
    summary,
    sbom: source.sbom ? { json: source.sbom.json, sha256: source.sbom.sha256 } : null,
  };
}

/**
 * The report in the bytes. A stored version 1 has no vulnerability facts, reasons, dataset
 * dates or SBOM: it is read with those empty, so every format renders it as before.
 */
export function parseCanonical(bytes: Buffer): ReportJson {
  const parsed = JSON.parse(bytes.toString('utf8')) as ReportJson;
  if (parsed.schemaVersion === 2) return parsed;
  if (parsed.schemaVersion !== 1) throw new Error('unsupported report schema version');
  return {
    ...parsed,
    scope: { ...parsed.scope, version: null },
    datasets: { vulnerabilityDatabase: null, kev: null, epss: null },
    sbom: null,
    findings: parsed.findings.map((f) => ({ ...f, vulnerability: null })),
    triage: parsed.triage.map((r) => ({ ...r, reason: null, vulnerability: null })),
  };
}
