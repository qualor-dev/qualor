import { sql } from 'drizzle-orm';
import { jsonChunks, uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import type { AcceptedFinding } from '../ingest/state';
import type { FindingDecision } from '../tracking/plan';
import {
  DEFAULT_VULNERABILITY_SETTINGS,
  isTrackedBranch,
  vulnerabilitySettingsOf,
  type VulnerabilitySettings,
} from '../versions/settings';
import type { DecisionPair } from './decisions';

/** The engine whose issues share the project's vulnerability decisions. */
export const TRIVY_ENGINE = 'trivy';

/** The longest package name a decision keys (plan 2b, Global Constraints). */
const PACKAGE_NAME_MAX = 512;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `text` as a regular expression that matches it literally. */
const literal = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * D2: the package a Trivy finding is about, which keys its vulnerability decision together with
 * the vulnerability id (the rule id). It is the finding's `properties.dependency.name` when that is
 * a string of 1–512 characters. Else it is the first word of a message in Trivy's format
 * `"<name> <version>: <id> …"` (report-format.md §7.1). Else, and for every other engine, null.
 */
export function packageNameOf(finding: {
  engineId: string;
  ruleId: string;
  message: string;
  properties?: unknown;
}): string | null {
  if (finding.engineId !== TRIVY_ENGINE) return null;
  const dependency = isRecord(finding.properties) ? finding.properties.dependency : undefined;
  const name = isRecord(dependency) ? dependency.name : undefined;
  if (typeof name === 'string' && name.length >= 1 && name.length <= PACKAGE_NAME_MAX) return name;
  const pattern = new RegExp(`^(\\S+) \\S+: ${literal(finding.ruleId)}(?:\\s|$)`);
  const fromMessage = pattern.exec(finding.message)?.[1];
  return fromMessage !== undefined && fromMessage.length <= PACKAGE_NAME_MAX ? fromMessage : null;
}

/** What {@link writesDecision} reads of an issue. */
export interface DecisionCandidate {
  engineId: string;
  packageName: string | null;
  branch: { name: string; isMain: boolean; kind: string };
}

/**
 * D4: whether triage of this issue writes the project-wide decision of its pair. It does for a
 * Trivy issue with a package name on `main` or a tracked branch, never on a merge request. The
 * monitoring switches play no part (D5).
 */
export function writesDecision(settings: VulnerabilitySettings, issue: DecisionCandidate): boolean {
  return (
    issue.engineId === TRIVY_ENGINE &&
    issue.packageName !== null &&
    isTrackedBranch(settings, issue.branch)
  );
}

/** An issue whose triage writes its pair's decision, with its branch (ruling R5). */
export interface DecidingIssue extends DecisionPair {
  branchId: string;
}

/**
 * The issues of `issueIds` and their duplicates for which {@link writesDecision} holds, with
 * their pairs. One query reads the issues, one more the settings of their projects. Read without
 * locks, before a transition locks anything: what it reads (engine, package, branch) is not what
 * a transition or an ingestion changes under each other.
 */
export async function decidingIssues(
  db: Executor,
  issueIds: readonly string[],
): Promise<Map<string, DecidingIssue>> {
  const deciding = new Map<string, DecidingIssue>();
  if (issueIds.length === 0) return deciding;
  const rows = (
    await db.execute<{
      id: string;
      project_id: string;
      branch_id: string;
      package_name: string;
      vulnerability_id: string;
      name: string;
      is_main: boolean;
      kind: string;
    }>(sql`
      SELECT i.id, i.project_id, i.branch_id, i.package_name,
             r.engine_rule_id AS vulnerability_id, b.name, b.is_main, b.kind
        FROM issues i
        JOIN rules r ON r.id = i.rule_id
        JOIN branches b ON b.id = i.branch_id
       WHERE (i.id IN ${uuidList(issueIds)} OR i.duplicate_of_issue_id IN ${uuidList(issueIds)})
         AND r.engine_id = ${TRIVY_ENGINE} AND i.package_name IS NOT NULL`)
  ).rows;
  if (rows.length === 0) return deciding;
  const settings = await vulnerabilitySettingsOf(db, [...new Set(rows.map((r) => r.project_id))]);
  for (const row of rows) {
    const candidate = {
      engineId: TRIVY_ENGINE,
      packageName: row.package_name,
      branch: { name: row.name, isMain: row.is_main, kind: row.kind },
    };
    if (
      !writesDecision(settings.get(row.project_id) ?? DEFAULT_VULNERABILITY_SETTINGS, candidate)
    ) {
      continue;
    }
    deciding.set(row.id, {
      projectId: row.project_id,
      branchId: row.branch_id,
      packageName: row.package_name,
      vulnerabilityId: row.vulnerability_id,
    });
  }
  return deciding;
}

const pairKey = (packageName: string, vulnerabilityId: string): string =>
  JSON.stringify([packageName, vulnerabilityId]);

/**
 * D4 at ingestion: the decision in force on the branch for each Trivy finding with a package
 * name, by its position in `findings`, when it is not Open. The decision in force is the branch's
 * own row of the pair, else the project's. One query for the whole analysis (one per chunk of
 * 5 000 pairs).
 */
export async function findingDecisions(
  tx: Executor,
  at: { projectId: string; branchId: string },
  findings: readonly AcceptedFinding[],
): Promise<Map<number, FindingDecision>> {
  const pairs = new Map<string, { package_name: string; vulnerability_id: string }>();
  for (const f of findings) {
    if (f.packageName === null) continue;
    pairs.set(pairKey(f.packageName, f.finding.ruleId), {
      package_name: f.packageName,
      vulnerability_id: f.finding.ruleId,
    });
  }
  const inForce = new Map<string, FindingDecision>();
  for (const chunk of jsonChunks(pairs.values())) {
    const rows = await tx.execute<{
      package_name: string;
      vulnerability_id: string;
      status: 'open' | 'false_positive' | 'wont_fix';
      comment: string | null;
      decided_by: string | null;
    }>(sql`
      SELECT DISTINCT ON (d.package_name, d.vulnerability_id)
             d.package_name, d.vulnerability_id, d.status, d.comment, d.decided_by
        FROM vulnerability_decisions d
        JOIN jsonb_to_recordset(${chunk}::jsonb) AS p(package_name text, vulnerability_id text)
          ON p.package_name = d.package_name AND p.vulnerability_id = d.vulnerability_id
       WHERE d.project_id = ${at.projectId}
         AND (d.branch_id = ${at.branchId} OR (d.branch_id IS NULL AND d.version_id IS NULL))
       ORDER BY d.package_name, d.vulnerability_id, d.branch_id IS NULL`);
    for (const row of rows.rows) {
      if (row.status === 'open') continue;
      inForce.set(pairKey(row.package_name, row.vulnerability_id), {
        status: row.status,
        comment: row.comment,
        decidedBy: row.decided_by,
      });
    }
  }
  const decisions = new Map<number, FindingDecision>();
  findings.forEach((f, i) => {
    const decision =
      f.packageName === null ? undefined : inForce.get(pairKey(f.packageName, f.finding.ruleId));
    if (decision) decisions.set(i, decision);
  });
  return decisions;
}
