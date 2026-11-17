import type { Severity } from '@qualor/shared';
import { inArray, sql } from 'drizzle-orm';
import { uuidList, withoutNul } from '../db/bulk';
import type { Db } from '../db/client';
import { jiraLinks, projectJiraSettings } from '../db/schema';
import {
  ELEMENT_CODES,
  isJiraIssueKey,
  JIRA_BULK_MAX,
  JiraError,
  type BulkOutcome,
} from './client';
import {
  codeIssueContent,
  issueFields,
  issueSeverityOf,
  vulnerabilityContent,
  type JiraContent,
  type VulnerabilityFacts,
} from './content';
import { codeIssueFacts, vulnerabilityFacts } from './facts';
import { enqueueJiraCreate } from './jobs';
import { JIRA_FAILURE_TEXT, pairKey, type JiraFailureCode, type JiraLinkRow } from './links';
import type { JiraMappingRow } from './mapping';
import {
  backgroundCodeOf,
  clearAfterAnswer,
  isCredentialCode,
  isCredentialProblem,
  replaceConnectionProblem,
} from './problems';
import type { JiraJobDeps, JiraRunContext } from './run';

/** spec §6.4: the never-attempted pending rows one run takes at most (R18 queues the next). */
export const CREATE_PER_RUN = 200;
/** A 429 without a `Retry-After` is tried again after this long. */
const RATE_LIMITED_WAIT_SECONDS = 60;

export interface CreateOutcome {
  /** Rows that got their Jira issue (a row dismissed meanwhile keeps the key, R19). */
  created: number;
  failed: number;
  /** Rows sent without an answer: pending with `attempted_at`, for the pass to reconcile. */
  unanswered: number;
  /** Why the run stopped before its rows ran out, if it did. */
  stop: null | 'credential' | 'transient' | 'rate_limited' | 'budget';
}

type Stop = CreateOutcome['stop'];

/** The stops after which a call's rows never reached Jira, or must not wait as if they had. */
const RELEASING: ReadonlySet<Stop> = new Set(['credential', 'rate_limited', 'budget']);

interface Created {
  row: JiraLinkRow;
  issueId: string;
  key: string;
}

interface Failed {
  row: JiraLinkRow;
  code: JiraFailureCode;
  message: string;
}

/** Code-unit order (not locale-dependent). */
const compare = (a: string, b: string): number => (a === b ? 0 : a < b ? -1 : 1);

/** One JSON value for `jsonb_to_recordset`; Postgres refuses U+0000, which Jira's words may hold. */
export const recordset = (rows: readonly object[]): string =>
  JSON.stringify(rows, (_key, value: unknown) =>
    typeof value === 'string' ? withoutNul(value) : value,
  );

/** The fence of every write to a link: a row re-armed meanwhile is another create's. */
export const fenceOf = (row: Pick<JiraLinkRow, 'id' | 'generation'>) => ({
  id: row.id,
  generation: row.generation,
});

/** The rows a created answer makes `created`: pending, or failed `outcome_unknown` by the pass. */
const LATE_CREATED = sql.raw(
  `l.state = 'pending' OR (l.state = 'failed' AND l.failure ->> 'code' = 'outcome_unknown')`,
);

/**
 * R1: up to `n` of the connection's never-attempted pending rows, oldest first, stamped with
 * `attempted_at` by one statement that commits before the call. `SKIP LOCKED` and the condition
 * on `attempted_at` let a create job and a sync pass of the organisation never take one row twice.
 */
async function claim(db: Db, connectionId: string, n: number): Promise<JiraLinkRow[]> {
  const rows = await db
    .update(jiraLinks)
    .set({ attemptedAt: sql`now()`, updatedAt: sql`now()` })
    .where(
      sql`${jiraLinks.id} IN (
        SELECT id FROM jira_links
         WHERE connection_id = ${connectionId} AND state = 'pending' AND attempted_at IS NULL
         ORDER BY created_at, id
         LIMIT ${n}
         FOR UPDATE SKIP LOCKED)`,
    )
    .returning();
  return rows.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || compare(a.id, b.id));
}

/** Rows whose call never reached Jira: never attempted again, so the next run sends them. */
export async function release(db: Db, rows: readonly JiraLinkRow[]): Promise<void> {
  if (rows.length === 0) return;
  await db.execute(sql`
    UPDATE jira_links l SET attempted_at = NULL, updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows.map(fenceOf))}::jsonb) AS c(id uuid, generation int)
     WHERE l.id = c.id AND l.generation = c.generation AND l.state = 'pending'`);
}

/**
 * The answers of one call, in one short transaction fenced on `(id, generation)`: a row re-armed
 * meanwhile is another create's. The state changes only from `pending` (R19): a row dismissed
 * while its create was in flight keeps the key and id Jira gave, and fails nothing. A created
 * answer also takes a row the pass failed `outcome_unknown` meanwhile: the issue is known now.
 */
async function record(
  db: Db,
  created: readonly Created[],
  failed: readonly Failed[],
): Promise<{ created: number; failed: number }> {
  if (created.length === 0 && failed.length === 0) return { created: 0, failed: 0 };
  return db.transaction(async (tx) => {
    let made = 0;
    let refused = 0;
    if (created.length > 0) {
      const json = recordset(
        created.map((c) => ({ ...fenceOf(c.row), issue_id: c.issueId, key: c.key })),
      );
      const result = await tx.execute(sql`
        UPDATE jira_links l
           SET state = CASE WHEN ${LATE_CREATED} THEN 'created' ELSE l.state END,
               failure = CASE WHEN ${LATE_CREATED} THEN NULL ELSE l.failure END,
               jira_issue_id = c.issue_id, jira_key = c.key, updated_at = now()
          FROM jsonb_to_recordset(${json}::jsonb)
               AS c(id uuid, generation int, issue_id text, key text)
         WHERE l.id = c.id AND l.generation = c.generation`);
      made = result.rowCount ?? 0;
    }
    if (failed.length > 0) {
      const json = recordset(
        failed.map((f) => ({ ...fenceOf(f.row), code: f.code, message: f.message })),
      );
      const result = await tx.execute(sql`
        UPDATE jira_links l
           SET state = 'failed', failure = jsonb_build_object('code', c.code, 'message', c.message),
               updated_at = now()
          FROM jsonb_to_recordset(${json}::jsonb)
               AS c(id uuid, generation int, code text, message text)
         WHERE l.id = c.id AND l.generation = c.generation AND l.state = 'pending'`);
      refused = result.rowCount ?? 0;
    }
    return { created: made, failed: refused };
  });
}

/** The mapping of each project, by project id; a project without one is absent. */
async function mappingsOf(
  db: Db,
  projectIds: readonly string[],
): Promise<Map<string, JiraMappingRow>> {
  const rows = await db
    .select()
    .from(projectJiraSettings)
    .where(inArray(projectJiraSettings.projectId, uuidList([...new Set(projectIds)])));
  return new Map(rows.map((m) => [m.projectId, m]));
}

interface Prepared {
  /** The rows to send, each with its create's fields, in the order they go. */
  send: { row: JiraLinkRow; fields: Record<string, unknown> }[];
  /** R8: rows that cannot be sent (no mapping any more, no finding, or a closed code issue). */
  failed: Failed[];
}

/** A failure with its fixed text. */
const failure = (row: JiraLinkRow, code: Exclude<JiraFailureCode, 'field_refused'>): Failed => ({
  row,
  code,
  message: JIRA_FAILURE_TEXT[code],
});

/** The fields of each claimed row's create (spec §6.4), from its mapping and its finding's facts. */
async function prepare(
  deps: JiraJobDeps,
  rows: readonly JiraLinkRow[],
  priority: boolean,
): Promise<Prepared> {
  const mappings = await mappingsOf(
    deps.db,
    rows.map((r) => r.projectId),
  );
  const mapped = rows.filter((r) => mappings.has(r.projectId));
  const codeFacts = await codeIssueFacts(
    deps.db,
    mapped.flatMap((r) => (r.kind === 'issue' && r.issueId !== null ? [r.issueId] : [])),
  );
  const pairsOf = new Map<string, { packageName: string; vulnerabilityId: string }[]>();
  for (const r of mapped) {
    if (r.kind !== 'vulnerability' || r.packageName === null || r.vulnerabilityId === null) {
      continue;
    }
    const pair = { packageName: r.packageName, vulnerabilityId: r.vulnerabilityId };
    const list = pairsOf.get(r.projectId);
    if (list) list.push(pair);
    else pairsOf.set(r.projectId, [pair]);
  }
  const pairFacts = new Map<string, Map<string, VulnerabilityFacts>>();
  for (const [projectId, pairs] of pairsOf) {
    pairFacts.set(projectId, await vulnerabilityFacts(deps.db, projectId, pairs, { priority }));
  }

  const prepared: Prepared = { send: [], failed: [] };
  for (const row of rows) {
    const mapping = mappings.get(row.projectId);
    if (!mapping) {
      prepared.failed.push(failure(row, 'not_mapped'));
      continue;
    }
    let built: { content: JiraContent; severity: Severity } | null = null;
    if (row.kind === 'issue') {
      const facts = row.issueId === null ? undefined : codeFacts.get(row.issueId);
      // R7: a closed issue gets no Jira issue (one re-armed before it closed is gone, R8).
      if (facts && !facts.closed)
        built = { content: codeIssueContent(facts, deps.publicUrl), severity: facts.severity };
    } else {
      const facts = pairFacts
        .get(row.projectId)
        ?.get(pairKey(row.packageName ?? '', row.vulnerabilityId ?? ''));
      if (facts) {
        built = {
          content: vulnerabilityContent(facts, deps.publicUrl),
          severity: issueSeverityOf(facts.severity),
        };
      }
    }
    if (built === null) {
      prepared.failed.push(failure(row, 'finding_gone'));
      continue;
    }
    prepared.send.push({ row, fields: issueFields(mapping, built.content, built.severity, row) });
  }
  return prepared;
}

/**
 * What a failed call means for a run (spec §6.4, §6.5, R16): 429 and the request budget stop it;
 * a credential failure (401, captcha, redirect, not public) or a transient one (timeout, no
 * answer, 5xx) is recorded on the connection and stops it; anything else (a bad answer) stops
 * nothing. The record is conditional on the run's view of the problem (`ctx.connection`).
 */
export async function stopFor(ctx: JiraRunContext, err: JiraError): Promise<Stop> {
  if (err.code === 'rate_limited') return 'rate_limited';
  if (err.code === 'budget') return 'budget';
  const background = backgroundCodeOf(err);
  if (background === null) return null;
  await replaceConnectionProblem(ctx.deps.db, ctx.connection, background);
  return isCredentialCode(background) ? 'credential' : 'transient';
}

/**
 * When the next create job runs: after a 429's `Retry-After`; at once after a run that took its
 * limit with an answered call (R18: a run Jira never answered, a sign-in proxy, waits for the
 * pass instead of pushing the whole backlog through); else none.
 */
function followUpDelay(
  stop: Stop,
  full: boolean,
  answered: boolean,
  retryAfter: number,
): number | null {
  if (stop === 'rate_limited') return retryAfter;
  if (stop === null && full && answered) return 0;
  return null;
}

/**
 * The status of the issues just created, read in the same run (spec §6.4), with their key now. A
 * key not of Jira's form is a bad answer of its element (T6b): that row's status waits for the
 * pass. Fenced on `(id, generation)` and the Jira issue id.
 */
async function readStatus(ctx: JiraRunContext, created: readonly Created[]): Promise<void> {
  const { found } = await ctx.client.searchByIds(created.map((c) => c.issueId));
  const rows = created.flatMap((c) => {
    const state = found.get(c.issueId);
    if (!state || !isJiraIssueKey(state.key)) return [];
    return [
      {
        ...fenceOf(c.row),
        issue_id: c.issueId,
        key: state.key,
        name: state.statusName,
        category: state.statusCategory,
      },
    ];
  });
  if (rows.length === 0) return;
  await ctx.deps.db.execute(sql`
    UPDATE jira_links l
       SET jira_key = c.key, status_name = c.name, status_category = c.category,
           status_checked_at = now(), updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows)}::jsonb)
           AS c(id uuid, generation int, issue_id text, key text, name text, category text)
     WHERE l.id = c.id AND l.generation = c.generation AND l.jira_issue_id = c.issue_id`);
}

/** Whether the connection still has never-attempted pending rows. */
async function waiting(db: Db, connectionId: string): Promise<boolean> {
  const result = await db.execute<{ waiting: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM jira_links
       WHERE connection_id = ${connectionId} AND state = 'pending' AND attempted_at IS NULL
    ) AS waiting`);
  return result.rows[0]?.waiting === true;
}

/**
 * spec §6.4: the create step. The connection's never-attempted pending rows, oldest first, at
 * most `limit`, in calls of at most 50 (`POST /issue/bulk`, or `POST /issue` for one). Each call's
 * rows are claimed (`attempted_at` set and committed) before it and its answers written after it:
 * no transaction is open across a Jira call.
 *
 * - Created → `created` with the Jira issue's id and key; their status is read after the last call.
 * - Refused element (400, 403, 404, 413, 422; a whole-call refusal fails every row, P6) → `failed`
 *   with its code; for 400 the message is Jira's words. No mapping → `not_mapped`; no finding, or
 *   a closed code issue (R7) → `finding_gone` (R8), unsent.
 * - No answer (timeout, reset, 5xx, an unreadable or unmatched answer) → `pending` with
 *   `attempted_at`: the pass reconciles it and never resends blindly. A timeout or an unreachable
 *   Jira is recorded as the transient problem and stops the run.
 * - 401, captcha, redirect, not public → the credential problem; the call's rows are released
 *   (`attempted_at` cleared) and the run stops. While such a problem is set, nothing is sent.
 * - 429 → the rows are released and the create runs again after `Retry-After` (1 s – 15 min).
 *
 * Any answered call clears a transient problem; every problem write is conditional on the run's
 * view (`ctx.connection.problem`), which follows them. A run that took `limit` rows while more
 * wait, and had an answered call, queues the next create job (R18).
 */
export async function createPending(
  ctx: JiraRunContext,
  limit = CREATE_PER_RUN,
): Promise<CreateOutcome> {
  const { deps, connection, client } = ctx;
  const { db } = deps;
  const outcome: CreateOutcome = { created: 0, failed: 0, unanswered: 0, stop: null };
  if (isCredentialProblem(connection.problem)) return { ...outcome, stop: 'credential' };
  const priority = deps.limits().vulnerabilities.priority;
  /** An answered call clears a transient problem (the run's view follows its writes). */
  let answeredCalls = 0;
  const answered = async (): Promise<void> => {
    answeredCalls += 1;
    await clearAfterAnswer(db, connection);
  };
  let retryAfter = RATE_LIMITED_WAIT_SECONDS;
  const stopOn = async (err: unknown): Promise<Stop> => {
    if (!(err instanceof JiraError)) throw err;
    if (err.code === 'rate_limited') {
      retryAfter = err.retryAfterSeconds ?? RATE_LIMITED_WAIT_SECONDS;
    }
    return stopFor(ctx, err);
  };

  const made: Created[] = [];
  let taken = 0;
  while (outcome.stop === null && taken < limit) {
    const rows = await claim(db, connection.id, Math.min(JIRA_BULK_MAX, limit - taken));
    if (rows.length === 0) break;
    taken += rows.length;
    let prepared: Prepared;
    try {
      prepared = await prepare(deps, rows, priority);
    } catch (err) {
      // Nothing was sent: the rows go back for the next run.
      await release(db, rows);
      throw err;
    }
    const sent = prepared.send.map((s) => s.row);
    let answers: BulkOutcome | null = null;
    if (sent.length > 0) {
      try {
        answers = await client.createIssues(prepared.send.map((s) => s.fields));
      } catch (err) {
        outcome.stop = await stopOn(err);
        if (RELEASING.has(outcome.stop)) await release(db, sent);
        else outcome.unanswered += sent.length;
      }
    }
    const created: Created[] = [];
    const failed = [...prepared.failed];
    answers?.forEach((answer, i) => {
      const row = sent[i];
      if (!row) return;
      if ('created' in answer) {
        created.push({ row, issueId: answer.created.id, key: answer.created.key });
      } else if (ELEMENT_CODES.has(answer.failed.code)) {
        const code = answer.failed.code as JiraFailureCode;
        failed.push({ row, code, message: answer.failed.jiraText ?? JIRA_FAILURE_TEXT[code] });
      } else {
        // An element whose answer is not understood: the issue may exist.
        outcome.unanswered += 1;
      }
    });
    const written = await record(db, created, failed);
    outcome.created += written.created;
    outcome.failed += written.failed;
    made.push(...created);
    if (answers !== null) await answered();
  }

  if (outcome.stop === null && made.length > 0) {
    try {
      await readStatus(ctx, made);
      await answered();
    } catch (err) {
      outcome.stop = await stopOn(err);
    }
  }
  const again = followUpDelay(outcome.stop, taken >= limit, answeredCalls > 0, retryAfter);
  if (again !== null && (await waiting(db, connection.id))) {
    await enqueueJiraCreate(db, connection.organizationId, again);
  }
  return outcome;
}
