import {
  IMPORT_STATUSES,
  matchStatuses,
  sanitizeImportComment,
  snippetLineHash,
  STATUS_IMPORT_MAX_CANDIDATES,
  statusMatchItem,
  type ImportStatus,
  type StatusCandidate,
  type StatusImportItem,
  type StatusImportRequestItem,
  type StatusImportResult,
} from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { AccessContext } from '../auth/access';
import type { UserRow } from '../auth/sessions';
import { textList } from '../db/bulk';
import type { Db, Executor } from '../db/client';
import { branches } from '../db/schema';
import { ProblemError, validationFailed } from '../http/problem';
import type { IssueStatus } from '../tracking/plan';
import {
  lockIssues,
  setLockTimeout,
  TRANSITION_LOCK_TIMEOUT_MS,
  transitionIssuesIn,
  type TransitionResult,
} from './transitions';

/** Spec §11.2: more candidate issues than this for one request is 413 IMPORT_TOO_LARGE. */
export const MAX_IMPORT_CANDIDATES = STATUS_IMPORT_MAX_CANDIDATES;

/**
 * Spec §10.2, §11.2, the changelog comment as stored (`sanitizeImportComment` of
 * packages/shared). The CLI already removes control characters; the server does it again for any
 * other client. It is never longer than the input (the route bounds it at 2 000 characters).
 */
export { sanitizeImportComment };

/**
 * A request item: a SonarQube issue resolved by a person (`false_positive`, `wont_fix`) with its
 * changelog comment and, when SonarQube's open issues of its rule could not all be read, the
 * `competitorsUnknown` marker; or an open one, a competitor only.
 */
export type ImportRequestItem = StatusImportRequestItem;

/** A result, with `status` (the issue's status after the request) typed as Qualor's. */
export type ImportResult = Omit<StatusImportResult, 'status'> & { status: IssueStatus | null };

export interface StatusImportResponse {
  branchId: string;
  analysisId: string;
  /** One per item whose status is `false_positive` or `wont_fix`, in request order. */
  results: ImportResult[];
  /** The number of `open` items (competitors only, never applied nor listed in `results`). */
  competitors: number;
}

const isStatusItem = (i: ImportRequestItem): i is StatusImportItem => i.status !== 'open';

type CandidateRow = {
  id: string;
  rule_key: string;
  path: string | null;
  start_line: number | null;
  message: string;
  snippet: unknown;
  status: IssueStatus;
  duplicate_of_issue_id: string | null;
};

/**
 * Spec §10.4, §10.5, §11.2: matches the items (resolved ones and `open` competitors) to the
 * issues of the project's main branch that are not closed and, unless `dryRun`, sets the statuses
 * of the resolved items' matched `open` issues. An `open` item, one marked `competitorsUnknown`,
 * and any item the matcher links to a marked one (ruling S12) are never applied. The caller has checked that `user` administers the
 * project's organisation.
 *
 * Candidates are read and matched outside any lock. All the transitions then run in ONE
 * transaction: every issue to change (and its duplicates) is locked first in one id-ordered
 * statement, the lock order of every transition and ingestion, and each status's transition runs
 * through {@link transitionIssuesIn} (visibility, the lost-update guard, mirroring onto
 * duplicates, the changelog with each item's own comment, the gate re-evaluation). A lock held
 * longer than `lockTimeoutMs` fails the whole request (SQLSTATE 55P03, 503 over HTTP) with
 * nothing written. An issue that changed after matching ends `already_set` or `conflict` from the
 * status the transition found; a status someone set in Qualor is never overwritten.
 *
 * Comments: each resolved item's `comment` must already be 1–2 000 characters (the route's schema
 * bounds it, spec §11.2); this function does not check the length again. It stores the comment
 * through {@link sanitizeImportComment}, which never makes it longer, and refuses one left blank
 * by that (422, before anything is read). An `open` item's comment is ignored.
 */
export async function importIssueStatuses(
  access: AccessContext & { db: Db },
  user: UserRow,
  projectId: string,
  requested: readonly ImportRequestItem[],
  dryRun: boolean,
  options: {
    maxCandidates?: number;
    lockTimeoutMs?: number;
    /** rbac-audit.md §8, one `issue.statuses_imported` per import that is not a dry run. */
    audit?: { recorder: AuditRecorder; context: AuditActorContext };
  } = {},
): Promise<StatusImportResponse> {
  const db = access.db;
  /** The summary event, in the transaction that applied the statuses (when there was one). */
  const recordImport = async (executor: Executor, response: StatusImportResponse) => {
    const audit = options.audit;
    if (dryRun || !audit?.recorder.active()) return;
    const outcomes = response.results.map((r) => r.outcome);
    const n = (outcome: ImportResult['outcome']) => outcomes.filter((o) => o === outcome).length;
    const refs = await projectRefs(executor, projectId);
    await audit.recorder.record(executor, audit.context, [
      {
        action: 'issue.statuses_imported',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'project', id: projectId, label: refs.project.key },
        details: {
          items: response.results.length,
          applied: n('applied'),
          alreadySet: n('already_set'),
          conflicts: n('conflict'),
          unmatched: n('unmatched'),
          ambiguous: n('ambiguous'),
          competitorsUnknown: n('competitors_unknown'),
        },
      },
    ]);
  };
  const maxCandidates = options.maxCandidates ?? MAX_IMPORT_CANDIDATES;
  // Spec §11.2: refs are unique (the matcher relies on it), and data-model.md §6 requires a
  // comment for both statuses. Checked before anything is read.
  const seen = new Set<string>();
  requested.forEach((item, n) => {
    if (seen.has(item.ref)) {
      throw validationFailed([{ path: `body.items.${n}.ref`, message: 'duplicate ref' }]);
    }
    seen.add(item.ref);
    if (item.status !== 'open' && sanitizeImportComment(item.comment) === '') {
      throw validationFailed([{ path: `body.items.${n}.comment`, message: 'must not be blank' }]);
    }
  });
  const items = requested.filter(isStatusItem);
  const competitors = requested.length - items.length;
  const comments = items.map((i) => sanitizeImportComment(i.comment));
  const [main] = await db
    .select({ id: branches.id, lastAnalysisId: branches.lastAnalysisId })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), eq(branches.isMain, true)));
  if (main === undefined || main.lastAnalysisId === null) {
    throw new ProblemError(
      409,
      'PROJECT_NOT_ANALYSED',
      'The project’s main branch has no analysis yet; scan it, then import again',
    );
  }
  if (items.length === 0) {
    const response = {
      branchId: main.id,
      analysisId: main.lastAnalysisId,
      results: [],
      competitors,
    };
    await recordImport(db, response);
    return response;
  }
  const analysisId = main.lastAnalysisId;
  // Open competitors take part in the matching (spec §10.4): their rules and paths select
  // candidates too.
  const ruleKeys = [...new Set(requested.flatMap((i) => i.ruleKeys))];
  const paths = [...new Set(requested.flatMap((i) => (i.path === null ? [] : [i.path])))];
  const fileLess = requested.some((i) => i.path === null);
  const rows = (
    await db.execute<CandidateRow>(sql`
      SELECT i.id, r.key AS rule_key, i.path, i.start_line, i.message, i.snippet, i.status,
             i.duplicate_of_issue_id
        FROM issues i JOIN rules r ON r.id = i.rule_id
       WHERE i.branch_id = ${main.id}
         AND i.status <> 'closed'
         AND r.key IN ${textList(ruleKeys)}
         AND (i.path IN ${textList(paths)} OR (${fileLess} AND i.path IS NULL))
       LIMIT ${maxCandidates + 1}`)
  ).rows;
  if (rows.length > maxCandidates) {
    throw new ProblemError(
      413,
      'IMPORT_TOO_LARGE',
      `These items select more than ${maxCandidates} candidate issues; send fewer paths per request`,
    );
  }
  const candidates: StatusCandidate[] = rows.map((r) => ({
    id: r.id,
    ruleKey: r.rule_key,
    path: r.path,
    line: r.start_line,
    message: r.message,
    sonarLineHash: snippetLineHash(r.snippet, r.start_line),
    duplicateOf: r.duplicate_of_issue_id,
  }));
  const statusOf = new Map(rows.map((r) => [r.id, r.status]));
  const matchOf = new Map(
    matchStatuses(requested.map(statusMatchItem), candidates).map((m) => [m.ref, m]),
  );

  const results = new Map<string, ImportResult>();
  const toApply: Record<ImportStatus, Map<string, string>> = {
    false_positive: new Map(),
    wont_fix: new Map(),
  };
  const refOf = new Map<string, string>();
  items.forEach((item, n) => {
    const set = (
      outcome: StatusImportResult['outcome'],
      issueId: string | null,
      status: IssueStatus | null,
    ) => results.set(item.ref, { ref: item.ref, outcome, issueId, status });
    const m = matchOf.get(item.ref);
    const id = m?.candidateId ?? null;
    const current = id === null ? undefined : statusOf.get(id);
    if (item.competitorsUnknown === true || m?.competitorsUnknown === true) {
      // Spec §10.1, ruling S12: competitors of this item, or of an item of its component, may
      // be missing, so no match in the component is trusted.
      set('competitors_unknown', null, null);
    } else if (m === undefined || id === null || current === undefined) {
      set(m?.ambiguous === true ? 'ambiguous' : 'unmatched', null, null);
    } else if (current === item.status) {
      set('already_set', id, current);
    } else if (current !== 'open') {
      set('conflict', id, current);
    } else if (dryRun) {
      set('would_apply', id, current);
    } else {
      toApply[item.status].set(id, comments[n] ?? '');
      refOf.set(id, item.ref);
    }
  });

  const response = (): StatusImportResponse => ({
    branchId: main.id,
    analysisId,
    results: items.map(
      (i) =>
        results.get(i.ref) ?? { ref: i.ref, outcome: 'unmatched', issueId: null, status: null },
    ),
    competitors,
  });
  const applyOutcomes = (outcomes: readonly [ImportStatus, TransitionResult][]) => {
    for (const [to, outcome] of outcomes) {
      for (const id of outcome.succeeded) {
        const ref = refOf.get(id);
        if (ref !== undefined)
          results.set(ref, { ref, outcome: 'applied', issueId: id, status: to });
      }
      for (const f of outcome.failed) {
        const ref = refOf.get(f.id);
        if (ref === undefined) continue;
        // The route required project.issues.import, which includes issue.triage, so FORBIDDEN
        // cannot happen here; were it to, the item is not applied, like an unmatched one.
        results.set(
          ref,
          f.code !== 'INVALID_TRANSITION'
            ? { ref, outcome: 'unmatched', issueId: null, status: null }
            : {
                ref,
                outcome: f.from === to ? 'already_set' : 'conflict',
                issueId: f.id,
                status: f.from ?? null,
              },
        );
      }
    }
  };

  const pending = IMPORT_STATUSES.filter((to) => toApply[to].size > 0);
  if (pending.length === 0) {
    const done = response();
    await recordImport(db, done);
    return done;
  }
  return db.transaction(async (tx) => {
    await setLockTimeout(tx, options.lockTimeoutMs ?? TRANSITION_LOCK_TIMEOUT_MS);
    await lockIssues(
      tx,
      pending.flatMap((to) => [...toApply[to].keys()]),
    );
    const done: [ImportStatus, TransitionResult][] = [];
    for (const to of pending) {
      const own = toApply[to];
      // No `audit` here: the import is one summary event, not one per issue.
      done.push([
        to,
        await transitionIssuesIn(tx, user, [...own.keys()], to, null, { comments: own }),
      ]);
    }
    applyOutcomes(done);
    const final = response();
    await recordImport(tx, final);
    return final;
  });
}
