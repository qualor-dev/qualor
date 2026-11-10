import {
  findingConfidence,
  type Confidence,
  type IssueKind,
  type Quality,
  type Report,
  type Severity,
} from '@qualor/shared';
import { uuidv7 } from '../db/ids';
import type { AcceptedFinding } from '../ingest/state';
import type { NewCodeClassifier } from '../newcode/lines';
import { SERVER_ENGINES } from '../rules/server-engines';
import { matchFindings, renamer, type Trackable } from './match';

export type IssueStatus = 'open' | 'resolved' | 'wont_fix' | 'false_positive' | 'closed';

/** data-model.md §5.2: closed issues stay matchable (and reopen) for this long. */
export const REOPEN_WINDOW_DAYS = 30;

/** An existing issue of the branch that tracking may match: not closed, or closed recently. */
export interface CandidateIssue {
  id: string;
  ruleId: string;
  ruleKey: string;
  engineId: string;
  cwe: readonly number[];
  path: string | null;
  lineHash: string;
  contextHash: string;
  startLine: number | null;
  startColumn: number | null;
  message: string;
  status: IssueStatus;
  severity: Severity;
  severityOverridden: boolean;
  duplicateOfIssueId: string | null;
  /**
   * Only meaningful when `status` is `closed`: the status this issue had right before the
   * system closed it (the `old_value` of the most recent system status change to `closed`), or
   * null if there is none. Used to restore it correctly if it is re-detected — data-model.md §6
   * says a `wont_fix`/`false_positive` issue is "never re-opened automatically", so closing it and
   * later re-detecting it must not silently turn it back into `open` (U5 fix round 1, #2).
   */
  preCloseStatus: IssueStatus | null;
}

/** What a new issue takes over from its match on the reference branch (data-model.md §5.4). */
export interface InheritedIssue {
  sourceIssueId: string;
  status: 'open' | 'wont_fix' | 'false_positive';
  firstSeenAt: Date;
  resolvedAt: Date | null;
  resolvedBy: string | null;
  /** The user's severity override, when the reference issue has one. */
  severityOverride: Severity | null;
}

/**
 * The vulnerability decision in force for a finding's pair on the branch (vuln plan 2b, D4). A
 * new issue takes its status when it is not Open, over the one it would inherit. On `main` and
 * the tracked branches, a matched issue that reopens takes its status whatever it is (final
 * review F1).
 */
export interface FindingDecision {
  status: 'open' | 'false_positive' | 'wont_fix';
  comment: string | null;
  /** Who made it: the issue is resolved by them, as a decision resolves existing issues. */
  decidedBy: string | null;
}

/** Row shape bound through jsonb_to_recordset by writes.ts (snake_case = column names). */
export interface IssueWrite {
  id: string;
  rule_id: string;
  fingerprint: string;
  line_hash: string;
  context_hash: string;
  path: string | null;
  start_line: number | null;
  start_column: number | null;
  end_line: number | null;
  end_column: number | null;
  message: string;
  severity: Severity;
  quality: Quality;
  kind: IssueKind;
  status: IssueStatus;
  in_new_code: boolean;
  snippet: unknown;
  secondary_locations: unknown;
  /** Qualor's C# taint engine's confidence (R-9), null when the finding has none. */
  confidence: Confidence | null;
  /** The package of a Trivy finding (vuln plan 2b, D2), null for every other finding. */
  package_name: string | null;
}

export interface IssueInsert extends IssueWrite {
  severity_overridden: boolean;
  first_seen_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  /** Set when the issue inherits from the reference branch: its changelog is copied. */
  inherited_from: string | null;
}

export interface IssueUpdate extends IssueWrite {
  /**
   * The candidate's status as read when this plan was built. writes.ts only applies the status
   * (and closed_at/resolved_at/resolved_by) transition when the row's current status still
   * equals this — mirroring the severity_overridden guard — so a plan built from a stale read
   * cannot clobber a status some other, concurrent transition already changed (U5 fix round 1,
   * #3; a lost-update guard, not something today's single-job-per-project serialisation can
   * exercise on its own, but the issues API of server step 12 will run concurrently with it).
   */
  from_status: IssueStatus;
  /**
   * Set when a vulnerability decision gave this reopening issue a status other than the one it
   * would reopen to (final review F1). A status other than open is then resolved now by
   * `decided_by`, and the changelog row carries `decision_comment`.
   */
  decided?: boolean;
  decided_by?: string | null;
  decision_comment?: string | null;
}

export interface StatusChange {
  issueId: string;
  oldValue: IssueStatus;
  newValue: IssueStatus;
}

/**
 * A new issue whose status a vulnerability decision set (D4): its changelog row, written by the
 * system with the decision's comment after the inherited changelog is copied, so it comes last.
 */
export interface DecidedIssue extends StatusChange {
  comment: string | null;
}

/**
 * A candidate to close, with the status it must still have for the close to apply. writes.ts
 * guards `closeUnmatched` on this the same way `IssueUpdate.from_status` guards `updateMatched`
 * (U5 fix round 2, #3): a plan is built from a snapshot of the candidates, and by the time it is
 * written something else may have already changed the row, in which case closing it here — and
 * logging a changelog entry that never really happened — would be wrong.
 */
export interface CloseWrite {
  id: string;
  from_status: IssueStatus;
}

/** An issue that is not closed after this analysis, as cross-engine dedupe needs it. */
export interface LiveIssue {
  id: string;
  engineId: string;
  ruleKey: string;
  cwe: readonly number[];
  path: string | null;
  startLine: number | null;
  status: IssueStatus;
  duplicateOfIssueId: string | null;
}

export interface TrackingPlan {
  updates: IssueUpdate[];
  inserts: IssueInsert[];
  /**
   * Unlike `updates` and `inserts`, this plan carries no `StatusChange[]` for the changelog:
   * writes.ts derives it from what `updateMatched`/`closeUnmatched` actually applied (their SQL's
   * `RETURNING`), not from what was planned here, so a transition the lost-update guard blocks is
   * never logged as having happened (U5 fix round 2, #3).
   */
  closes: CloseWrite[];
  live: LiveIssue[];
  /** The new issues a vulnerability decision gave their status. */
  decided: DecidedIssue[];
}

export interface PlanInput {
  report: Report;
  findings: readonly AcceptedFinding[];
  candidates: readonly CandidateIssue[];
  classifier: NewCodeClassifier;
  /** Database `now()` of the ingestion transaction. */
  now: Date;
  /** By position in `findings`; see data-model.md §5.4. */
  inherited?: ReadonlyMap<number, InheritedIssue>;
  /** By position in `findings`: the vulnerability decision in force (vuln plan 2b, D4). */
  decisions?: ReadonlyMap<number, FindingDecision>;
  /**
   * The branch mirrors the vulnerability decisions (D4: `main` or a tracked branch), so a
   * reopening Trivy issue takes the decision in force (final review F1).
   */
  mirrored?: boolean;
  /**
   * The server engines (rules/server-engines.ts) that ran for this analysis with status ok.
   * Whether one ran comes from here, never from the report: a report entry claiming one with
   * status ok would otherwise close its issues without the server having judged anything.
   */
  serverOkEngines?: readonly string[];
}

export function findingTrackable(f: AcceptedFinding): Trackable {
  return {
    ruleKey: f.rule.key,
    path: f.finding.location?.path ?? null,
    lineHash: f.finding.lineHash,
    contextHash: f.finding.contextHash,
    line: f.finding.location?.startLine ?? null,
    column: f.finding.location?.startColumn ?? null,
    message: f.finding.message,
    closed: false,
  };
}

export function candidateTrackable(
  c: CandidateIssue,
  rename: (path: string | null) => string | null,
): Trackable {
  return {
    ruleKey: c.ruleKey,
    path: rename(c.path),
    lineHash: c.lineHash,
    contextHash: c.contextHash,
    line: c.startLine,
    column: c.startColumn,
    message: c.message,
    closed: c.status === 'closed',
  };
}

/**
 * data-model.md §6: a matched candidate is never left `closed`. A `resolved` issue always
 * re-opens to `open` (its match is a plain "it's back"). A `closed` issue restores the status it
 * had right before the system closed it: `wont_fix`/`false_positive` are "never re-opened
 * automatically" (so they stay), while a pre-close `resolved` (or `open`, or an untraceable close)
 * still re-opens to `open` (U5 fix round 1, #2). Every other status (`open`, `wont_fix`,
 * `false_positive` matched without ever having been closed) is unchanged.
 */
function reopenedStatus(candidate: CandidateIssue): IssueStatus {
  if (candidate.status === 'closed') {
    const preClose = candidate.preCloseStatus;
    return preClose === 'wont_fix' || preClose === 'false_positive' ? preClose : 'open';
  }
  if (candidate.status === 'resolved') return 'open';
  return candidate.status;
}

/**
 * F1: on a mirrored branch a reopening issue mirrors the decision in force, Open included; none
 * when that is the status it reopens to anyway.
 */
function reopeningDecision(
  input: PlanInput,
  findingIndex: number,
  candidate: CandidateIssue,
  reopened: IssueStatus,
): FindingDecision | undefined {
  const reopening = candidate.status === 'closed' || candidate.status === 'resolved';
  const decision = input.mirrored && reopening ? input.decisions?.get(findingIndex) : undefined;
  return decision?.status === reopened ? undefined : decision;
}

function write(
  f: AcceptedFinding,
  id: string,
  status: IssueStatus,
  inNewCode: boolean,
  severity: Severity,
): IssueWrite {
  const location = f.finding.location;
  return {
    id,
    rule_id: f.rule.id,
    fingerprint: f.fingerprint,
    line_hash: f.finding.lineHash,
    context_hash: f.finding.contextHash,
    path: location?.path ?? null,
    start_line: location?.startLine ?? null,
    start_column: location?.startColumn ?? null,
    end_line: location?.endLine ?? null,
    end_column: location?.endColumn ?? null,
    message: f.finding.message,
    severity,
    quality: f.rule.quality,
    kind: f.rule.kind,
    status,
    in_new_code: inNewCode,
    snippet: f.finding.snippet ?? null,
    // Stored as reported. Their paths may lie outside files[]; nothing joins on them (ruling T6).
    secondary_locations: f.finding.secondaryLocations ?? [],
    confidence: findingConfidence(f.finding) ?? null,
    package_name: f.packageName,
  };
}

/**
 * data-model.md §5.2 steps 0–4 and §6 (system transitions) for one analysis, without I/O:
 * matched issues are updated (see {@link reopenedStatus} for how a `closed` or `resolved` one is
 * reopened; on a mirrored branch a reopening Trivy issue takes the decision in force instead,
 * final review F1), unmatched findings become new issues, and an unmatched candidate is closed
 * only when its engine reported `status: ok` in this report — an analyzer that failed, timed
 * out, was skipped or is absent leaves its issues untouched. A server engine's status is the
 * server's own (`serverOkEngines`), whatever the report says.
 */
export function planTracking(input: PlanInput): TrackingPlan {
  const { report, findings, candidates, classifier, now } = input;
  const rename = renamer(report.scm.renames);
  const matched = matchFindings(
    findings.map(findingTrackable),
    candidates.map((c) => candidateTrackable(c, rename)),
  );
  const okEngines = new Set(
    report.engines.filter((e) => e.status === 'ok' && !SERVER_ENGINES.has(e.id)).map((e) => e.id),
  );
  for (const id of input.serverOkEngines ?? []) if (SERVER_ENGINES.has(id)) okEngines.add(id);
  const plan: TrackingPlan = {
    updates: [],
    inserts: [],
    closes: [],
    live: [],
    decided: [],
  };
  const matchedCandidates = new Set<number>();
  const liveOf = (id: string, f: AcceptedFinding, status: IssueStatus, dup: string | null) =>
    plan.live.push({
      id,
      engineId: f.rule.engineId,
      ruleKey: f.rule.key,
      cwe: f.rule.cwe,
      path: f.finding.location?.path ?? null,
      startLine: f.finding.location?.startLine ?? null,
      status,
      duplicateOfIssueId: dup,
    });

  findings.forEach((f, i) => {
    const location = f.finding.location;
    const candidateIndex = matched.get(i);
    const candidate = candidateIndex === undefined ? undefined : candidates[candidateIndex];
    if (candidateIndex !== undefined && candidate) {
      matchedCandidates.add(candidateIndex);
      const reopened = reopenedStatus(candidate);
      const decided = reopeningDecision(input, i, candidate, reopened);
      const status: IssueStatus = decided?.status ?? reopened;
      const inNewCode = classifier.inNewCode(
        location?.path ?? null,
        location?.startLine ?? null,
        false,
      );
      const severity = candidate.severityOverridden ? candidate.severity : f.severity;
      plan.updates.push({
        ...write(f, candidate.id, status, inNewCode, severity),
        from_status: candidate.status,
        ...(decided && {
          decided: true,
          decided_by: decided.decidedBy,
          decision_comment: decided.comment,
        }),
      });
      liveOf(
        candidate.id,
        f,
        status,
        candidate.status === 'closed' ? null : candidate.duplicateOfIssueId,
      );
      return;
    }
    const inherited = input.inherited?.get(i);
    const id = uuidv7();
    const inheritedStatus = inherited?.status ?? 'open';
    // D4: a new Trivy issue takes the decision in force, when it is not Open, over the status it
    // would inherit.
    const decision = input.decisions?.get(i);
    const decided =
      decision === undefined || decision.status === 'open' || decision.status === inheritedStatus
        ? undefined
        : { ...decision, status: decision.status };
    const status: IssueStatus = decided?.status ?? inheritedStatus;
    const inNewCode = classifier.inNewCode(
      location?.path ?? null,
      location?.startLine ?? null,
      inherited === undefined,
    );
    plan.inserts.push({
      ...write(f, id, status, inNewCode, inherited?.severityOverride ?? f.severity),
      severity_overridden: (inherited?.severityOverride ?? null) !== null,
      first_seen_at: (inherited?.firstSeenAt ?? now).toISOString(),
      resolved_at: decided ? now.toISOString() : (inherited?.resolvedAt?.toISOString() ?? null),
      resolved_by: decided ? decided.decidedBy : (inherited?.resolvedBy ?? null),
      inherited_from: inherited?.sourceIssueId ?? null,
    });
    if (decided) {
      plan.decided.push({
        issueId: id,
        oldValue: inheritedStatus,
        newValue: decided.status,
        comment: decided.comment,
      });
    }
    liveOf(id, f, status, null);
  });

  candidates.forEach((c, i) => {
    if (matchedCandidates.has(i) || c.status === 'closed') return;
    if (okEngines.has(c.engineId)) {
      plan.closes.push({ id: c.id, from_status: c.status });
      return;
    }
    plan.live.push({
      id: c.id,
      engineId: c.engineId,
      ruleKey: c.ruleKey,
      cwe: c.cwe,
      path: c.path,
      startLine: c.startLine,
      status: c.status,
      duplicateOfIssueId: c.duplicateOfIssueId,
    });
  });
  return plan;
}
