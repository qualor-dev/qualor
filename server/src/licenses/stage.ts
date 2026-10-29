import {
  computeFingerprints,
  EMPTY_LICENSE_POLICY,
  filelessHash,
  LICENSE_GROUPS,
  licenseClassifier,
  normalizeRepoPath,
  REPORT_BOUNDS,
  validateRepoPath,
  type Classification,
  type DependencyEntry,
  type IssueKind,
  type LicensePolicy,
  type Quality,
  type Severity,
} from '@qualor/shared';
import { and, eq, inArray, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { rules } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import {
  requireState,
  type AcceptedFinding,
  type IngestedFinding,
  type ResolvedRule,
} from '../ingest/state';
import { mergeDependencyEntries, type DependencyRowInput } from '../measures/store';
import { LICENSE_ENGINE } from '../rules/server-engines';
import { storedPolicyFor } from './settings';

export const FORBIDDEN_RULE_KEY = `${LICENSE_ENGINE}:forbidden`;
export const UNKNOWN_RULE_KEY = `${LICENSE_ENGINE}:unknown`;

/** The CLI's engine entry for its licence pass (cli/src/analyzers/trivy-licenses.ts). */
const LICENSE_PASS_ENGINE = 'trivy-licenses';

/** The analysis warning for inventory entries whose lockfile path is not a repository path. */
export const DEPENDENCY_PATHS_INVALID = 'DEPENDENCY_PATHS_INVALID';

/** The analysis warning for a stored policy that does not parse: the stage did not run. */
export const LICENSE_POLICY_INVALID = 'LICENSE_POLICY_INVALID';

/** The CLI's warning for an inventory cut at the report's bound (cli/src/scan/dependencies.ts). */
const DEPENDENCIES_TRUNCATED = 'DEPENDENCIES_TRUNCATED';

interface BuiltinRule {
  key: string;
  engineRuleId: string;
  name: string;
  description: string;
  severity: Severity;
}

/** 6M §6: the built-in rules of the licence policy, with Qualor's own descriptions. */
const LICENSE_RULES: readonly BuiltinRule[] = [
  {
    key: FORBIDDEN_RULE_KEY,
    engineRuleId: 'forbidden',
    name: 'Forbidden licence',
    description: "A dependency's licence is forbidden by the organisation's licence policy.",
    severity: 'high',
  },
  {
    key: UNKNOWN_RULE_KEY,
    engineRuleId: 'unknown',
    name: 'Unknown licence',
    description: 'A dependency has no licence Qualor could read.',
    severity: 'info',
  },
];

const QUALITY: Quality = 'licensing';
const KIND: IssueKind = 'issue';

/**
 * Creates the two licence rules when they are missing, repairs one a report created (origin
 * `reported`, before reports were barred from the `license` engine), and reads them back.
 *
 * A built-in row is never touched: the insert is `ON CONFLICT DO NOTHING` and the repair matches
 * only `origin = 'reported'`, so neither takes a row lock on the usual path. The read-back is
 * checked: rules are global, and a licence finding must never take another quality (6M L6).
 */
export async function ensureLicenseRules(tx: Executor): Promise<Map<string, ResolvedRule>> {
  await tx
    .insert(rules)
    .values(
      LICENSE_RULES.map((r) => ({
        id: uuidv7(),
        key: r.key,
        engineId: LICENSE_ENGINE,
        engineRuleId: r.engineRuleId,
        name: r.name,
        descriptionMd: r.description,
        defaultSeverity: r.severity,
        quality: QUALITY,
        kind: KIND,
        origin: 'builtin' as const,
      })),
    )
    .onConflictDoNothing({ target: rules.key });
  for (const r of LICENSE_RULES) {
    await tx
      .update(rules)
      .set({
        origin: 'builtin',
        engineId: LICENSE_ENGINE,
        engineRuleId: r.engineRuleId,
        name: r.name,
        descriptionMd: r.description,
        helpUri: null,
        languages: [],
        defaultSeverity: r.severity,
        quality: QUALITY,
        kind: KIND,
        tags: [],
        cwe: [],
        status: 'ready',
        updatedAt: sql`now()`,
      })
      .where(and(eq(rules.key, r.key), eq(rules.origin, 'reported')));
  }
  const rows = await tx
    .select({
      id: rules.id,
      key: rules.key,
      engineId: rules.engineId,
      defaultSeverity: rules.defaultSeverity,
      quality: rules.quality,
      kind: rules.kind,
      cwe: rules.cwe,
    })
    .from(rules)
    .where(
      inArray(
        rules.key,
        LICENSE_RULES.map((r) => r.key),
      ),
    );
  const resolved = new Map<string, ResolvedRule>();
  for (const r of rows) {
    if (r.engineId !== LICENSE_ENGINE || r.quality !== QUALITY || r.kind !== KIND) {
      throw new Error(
        `licence rule ${r.key} is ${r.engineId}/${r.quality}/${r.kind}, not ${LICENSE_ENGINE}/${QUALITY}/${KIND}`,
      );
    }
    resolved.set(r.key, {
      ...r,
      defaultSeverity: r.defaultSeverity as Severity,
      quality: QUALITY,
      // No report gives a server rule metadata; its findings never pass the scope check.
      reportScope: null,
    });
  }
  return resolved;
}

const GROUP_LABELS = new Map(LICENSE_GROUPS.map((g) => [g.id, g.label]));

function byCodeUnits(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function compareEntries(a: DependencyRowInput, b: DependencyRowInput): number {
  return (
    byCodeUnits(a.path, b.path) ||
    byCodeUnits(a.ecosystem, b.ecosystem) ||
    byCodeUnits(a.name, b.name) ||
    byCodeUnits(a.version, b.version)
  );
}

/**
 * Where a finding on this entry goes: its lockfile and line; the lockfile alone when the
 * scanner gave no line, or when the path is not a repository path as written but normalises to
 * one (`./web/package-lock.json`, backslashes: the line then may not be that file's); null when
 * no repository path can be made of it.
 */
function locationOf(entry: DependencyRowInput): IngestedFinding['location'] {
  if (validateRepoPath(entry.path) === null) {
    return entry.line === null
      ? { path: entry.path }
      : { path: entry.path, startLine: entry.line, endLine: entry.line };
  }
  try {
    const path = normalizeRepoPath(entry.path);
    return validateRepoPath(path) === null ? { path } : null;
  } catch {
    return null;
  }
}

/** The finding of one inventory entry under one rule: the package in its lockfile. */
function licenseFinding(
  entry: DependencyRowInput,
  location: NonNullable<IngestedFinding['location']>,
  rule: ResolvedRule,
  message: string,
): IngestedFinding {
  // The package's identity, as Trivy's findings use it (sarif/normalize.ts): stable when the
  // lockfile is re-ordered or the entry moves; a version bump is another package.
  const hash = filelessHash(rule.key, `${entry.name}@${entry.version}`, entry.path);
  return {
    engineId: LICENSE_ENGINE,
    ruleId: rule.key.slice(LICENSE_ENGINE.length + 1),
    message,
    severity: rule.defaultSeverity,
    location,
    lineHash: hash,
    contextHash: hash,
  };
}

/** The message of a forbidden entry, naming the licence group that forbids it, if one does. */
function forbiddenMessage(entry: DependencyRowInput, version: string, group: string | undefined) {
  const by = group ? ` (${group})` : '';
  return `${entry.name} ${version} is licensed ${entry.licenses.join(' AND ')}, which the organisation's licence policy forbids${by}.`;
}

/** The rule and message of the finding one entry's verdict asks for, or null when it asks none. */
function flagOf(
  entry: DependencyRowInput,
  verdict: Classification,
  warnUnknown: boolean,
  forbiddenRule: ResolvedRule,
  unknownRule: ResolvedRule,
): { rule: ResolvedRule; message: string } | null {
  const version = entry.version || 'unknown version';
  if (verdict.verdict === 'forbidden') {
    const group = verdict.group === null ? undefined : GROUP_LABELS.get(verdict.group);
    return { rule: forbiddenRule, message: forbiddenMessage(entry, version, group) };
  }
  if (verdict.verdict === 'unknown' && warnUnknown) {
    return {
      rule: unknownRule,
      message: `${entry.name} ${version} has no licence Qualor could read.`,
    };
  }
  return null;
}

/**
 * The findings of the inventory under the policy, and how many flagged entries had no repository
 * path to put a finding on.
 */
function judgeEntries(
  entries: readonly DependencyEntry[],
  policy: LicensePolicy,
  forbiddenRule: ResolvedRule,
  unknownRule: ResolvedRule,
): { made: { finding: IngestedFinding; rule: ResolvedRule }[]; unplaced: number } {
  const classify = licenseClassifier(policy);
  const made: { finding: IngestedFinding; rule: ResolvedRule }[] = [];
  let unplaced = 0;
  // Merged as the inventory store merges them: one finding per (path, ecosystem, name, version).
  for (const entry of mergeDependencyEntries(entries).sort(compareEntries)) {
    const flag = flagOf(
      entry,
      classify(entry.licenses),
      policy.warnUnknown,
      forbiddenRule,
      unknownRule,
    );
    if (flag === null) continue;
    const location = locationOf(entry);
    // Never file-less: a file-less finding first seen now would count as new code.
    if (location === null) {
      unplaced += 1;
      continue;
    }
    made.push({
      rule: flag.rule,
      finding: licenseFinding(entry, location, flag.rule, flag.message),
    });
  }
  return { made, unplaced };
}

/**
 * 6M §6: judges the report's dependency inventory against the organisation's licence policy and
 * adds a finding of engine `license` per forbidden entry (and per unknown one when the policy
 * warns on unknown licences), before tracking, so they become ordinary issues.
 *
 * It runs only when the feature is licensed, the report carries an inventory, and the report's
 * licence pass (`trivy-licenses`), when it names one, has status ok: a partial inventory must not
 * close anything. Then it tells tracking that the `license` engine ran (`serverOkEngines`), which
 * closes the licence issues not found again: without a policy, every one of them. Otherwise it does
 * nothing, and tracking leaves every open licence issue as it is (a lapsed licence, an older CLI,
 * a failed or timed-out pass). A report's own `license` findings never get here: the rules stage
 * drops them.
 *
 * A stored policy that does not parse is not the empty policy: the stage then does nothing but
 * warn `LICENSE_POLICY_INVALID`. A truncated inventory (the report warns `DEPENDENCIES_TRUNCATED`,
 * or it is as long as the report's bound) is partial too: its findings are added, so issues open
 * and update, but tracking is not told the engine ran, so the issues of the packages past the cut
 * stay as they are.
 */
export const licensePolicyStage: IngestionStage = {
  name: 'license-policy',
  async run(ctx) {
    const findings = requireState(ctx.state, 'findings');
    const entries = ctx.report.dependencies;
    if (!ctx.limits.licenses.policy || entries === undefined) return;
    const pass = ctx.report.engines.filter((e) => e.id === LICENSE_PASS_ENGINE);
    if (pass.some((e) => e.status !== 'ok')) return;

    const stored = await storedPolicyFor(ctx.tx, ctx.project.organizationId);
    if (stored.state === 'invalid') {
      // Judging against the empty policy would close every licence issue (final review M4).
      ctx.logger.warn(
        { analysisId: ctx.analysisId, organizationId: ctx.project.organizationId },
        "the organisation's stored licence policy does not parse: licences not judged",
      );
      ctx.warnings.push({
        code: LICENSE_POLICY_INVALID,
        message:
          "the organisation's stored licence policy could not be read: the dependency licences were not judged, and the licence issues stay as they are",
        count: 1,
      });
      return;
    }
    const policy = stored.state === 'policy' ? stored.policy : EMPTY_LICENSE_POLICY;
    const resolved = await ensureLicenseRules(ctx.tx);
    const forbiddenRule = resolved.get(FORBIDDEN_RULE_KEY);
    const unknownRule = resolved.get(UNKNOWN_RULE_KEY);
    if (!forbiddenRule || !unknownRule) throw new Error('the licence rules were not created');

    const { made, unplaced } = judgeEntries(entries, policy, forbiddenRule, unknownRule);
    if (unplaced > 0) {
      ctx.warnings.push({
        code: DEPENDENCY_PATHS_INVALID,
        message: `${unplaced} dependencies the licence policy flags were left out: their lockfile path is not a repository path`,
        count: unplaced,
      });
    }

    const fingerprints = computeFingerprints(
      made.map(({ finding, rule }) => ({
        ruleKey: rule.key,
        path: finding.location?.path ?? null,
        lineHash: finding.lineHash,
        contextHash: finding.contextHash,
        startLine: finding.location?.startLine ?? 0,
        startColumn: 0,
      })),
    );
    const base = ctx.report.findings.length;
    const accepted: AcceptedFinding[] = made.map(({ finding, rule }, i) => ({
      index: base + i,
      finding,
      rule,
      severity: rule.defaultSeverity,
      fingerprint: fingerprints[i] ?? '',
    }));
    ctx.state.findings = [...findings, ...accepted];
    const truncated =
      entries.length >= REPORT_BOUNDS.dependencies ||
      ctx.report.warnings.some((w) => w.code === DEPENDENCIES_TRUNCATED);
    if (!truncated) ctx.state.serverOkEngines = [LICENSE_ENGINE];
    ctx.logger.debug(
      { analysisId: ctx.analysisId, entries: entries.length, findings: accepted.length, truncated },
      'judged the dependency licences',
    );
  },
};
