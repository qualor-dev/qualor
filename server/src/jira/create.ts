import type { Severity } from '@qualor/shared';
import { inArray, sql } from 'drizzle-orm';
import { uuidList, withoutNul } from '../db/bulk';
import type { Db } from '../db/client';
import { jiraLinks, projectJiraSettings } from '../db/schema';
import { compare } from '../vulnerabilities/order';
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
import { codeIssueFacts, vulnerabilityFacts, type CodeIssueRecord } from './facts';
import { enqueueJiraCreate } from './jobs';
import { JIRA_FAILURE_TEXT, pairKey, type JiraFailureCode, type JiraLinkRow } from './links';
import type { JiraMappingRow } from './mapping';
import type { VulnerabilityPair } from './presence';
import {
  backgroundCodeOf,
  clearAfterAnswer,
  connectionUnmoved,
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
 * None once the connection has another address than the run's client (M1).
 */
async function claim(ctx: JiraRunContext, n: number): Promise<JiraLinkRow[]> {
  const rows = await ctx.deps.db
    .update(jiraLinks)
    .set({ attemptedAt: sql`now()`, updatedAt: sql`now()` })
    .where(
      sql`${jiraLinks.id} IN (
        SELECT id FROM jira_links
         WHERE connection_id = ${ctx.connection.id} AND state = 'pending' AND attempted_at IS NULL
           AND ${connectionUnmoved(ctx.connection)}
         ORDER BY created_at, id
         LIMIT ${n}
         FOR UPDATE SKIP LOCKED)`,
    )
    .returning();
  return rows.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || compare(a.id, b.id));
}

/** Rows whose call never reached Jira: never attempted again, so the next run sends them. */
export async function release(ctx: JiraRunContext, rows: readonly JiraLinkRow[]): Promise<void> {
  if (rows.length === 0) return;
  await ctx.deps.db.execute(sql`
    UPDATE jira_links l SET attempted_at = NULL, updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows.map(fenceOf))}::jsonb) AS c(id uuid, generation int)
     WHERE l.id = c.id AND l.generation = c.generation AND l.state = 'pending'
       AND ${connectionUnmoved(ctx.connection)}`);
}

/**
 * The answers of one call, in one short transaction fenced on `(id, generation)`: a row re-armed
 * meanwhile is another create's. The state changes only from `pending` (R19): a row dismissed
 * while its create was in flight keeps the key and id Jira gave, and fails nothing. A created
 * answer also takes a row the pass failed `outcome_unknown` meanwhile: the issue is known now.
 * Nothing is written once the connection has another address than the run's (M1).
 */
async function record(
  ctx: JiraRunContext,
  created: readonly Created[],
  failed: readonly Failed[],
): Promise<{ created: number; failed: number }> {
  if (created.length === 0 && failed.length === 0) return { created: 0, failed: 0 };
  const unmoved = connectionUnmoved(ctx.connection);
  return ctx.deps.db.transaction(async (tx) => {
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
         WHERE l.id = c.id AND l.generation = c.generation AND ${unmoved}`);
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
         WHERE l.id = c.id AND l.generation = c.generation AND l.state = 'pending'
           AND ${unmoved}`);
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

/** The facts of the rows' findings: code issues by issue id, pairs by project and {@link pairKey}. */
interface Findings {
  code: Map<string, CodeIssueRecord>;
  pairs: Map<string, Map<string, VulnerabilityFacts>>;
}

/** The vulnerability pairs of the rows, by project. */
function pairsByProject(rows: readonly JiraLinkRow[]): Map<string, VulnerabilityPair[]> {
  const byProject = new Map<string, VulnerabilityPair[]>();
  for (const r of rows) {
    if (r.kind !== 'vulnerability' || r.packageName === null || r.vulnerabilityId === null) {
      continue;
    }
    const pair = { packageName: r.packageName, vulnerabilityId: r.vulnerabilityId };
    const list = byProject.get(r.projectId);
    if (list) list.push(pair);
    else byProject.set(r.projectId, [pair]);
  }
  return byProject;
}

async function findingsOf(
  db: Db,
  rows: readonly JiraLinkRow[],
  priority: boolean,
): Promise<Findings> {
  const code = await codeIssueFacts(
    db,
    rows.flatMap((r) => (r.kind === 'issue' && r.issueId !== null ? [r.issueId] : [])),
  );
  const pairs = new Map<string, Map<string, VulnerabilityFacts>>();
  for (const [projectId, list] of pairsByProject(rows)) {
    pairs.set(projectId, await vulnerabilityFacts(db, projectId, list, { priority }));
  }
  return { code, pairs };
}

/** A row's content and severity from its finding's facts; null when there is no finding to send. */
function contentOf(
  row: JiraLinkRow,
  findings: Findings,
  publicUrl: string | null,
): { content: JiraContent; severity: Severity } | null {
  if (row.kind === 'issue') {
    const facts = row.issueId === null ? undefined : findings.code.get(row.issueId);
    // R7: a closed issue gets no Jira issue (one re-armed before it closed is gone, R8).
    if (!facts || facts.closed) return null;
    return { content: codeIssueContent(facts, publicUrl), severity: facts.severity };
  }
  const facts = findings.pairs
    .get(row.projectId)
    ?.get(pairKey(row.packageName ?? '', row.vulnerabilityId ?? ''));
  if (!facts) return null;
  return {
    content: vulnerabilityContent(facts, publicUrl),
    severity: issueSeverityOf(facts.severity),
  };
}

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
  const findings = await findingsOf(
    deps.db,
    rows.filter((r) => mappings.has(r.projectId)),
    priority,
  );
  const prepared: Prepared = { send: [], failed: [] };
  for (const row of rows) {
    const mapping = mappings.get(row.projectId);
    if (!mapping) {
      prepared.failed.push(failure(row, 'not_mapped'));
      continue;
    }
    const built = contentOf(row, findings, deps.publicUrl);
    if (built === null) prepared.failed.push(failure(row, 'finding_gone'));
    else
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
     WHERE l.id = c.id AND l.generation = c.generation AND l.jira_issue_id = c.issue_id
       AND ${connectionUnmoved(ctx.connection)}`);
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
  const outcome: CreateOutcome = { created: 0, failed: 0, unanswered: 0, stop: null };
  if (isCredentialProblem(ctx.connection.problem)) return { ...outcome, stop: 'credential' };
  const run: CreateRun = {
    ctx,
    priority: ctx.deps.limits().vulnerabilities.priority,
    outcome,
    made: [],
    answeredCalls: 0,
    retryAfter: RATE_LIMITED_WAIT_SECONDS,
  };
  const { db } = ctx.deps;
  let taken = 0;
  while (outcome.stop === null && taken < limit) {
    const rows = await claim(ctx, Math.min(JIRA_BULK_MAX, limit - taken));
    if (rows.length === 0) break;
    taken += rows.length;
    await createCall(run, rows);
  }
  await readCreatedStatus(run);
  const again = followUpDelay(outcome.stop, taken >= limit, run.answeredCalls > 0, run.retryAfter);
  if (again !== null && (await waiting(db, ctx.connection.id))) {
    await enqueueJiraCreate(db, ctx.connection.organizationId, again);
  }
  return outcome;
}

/** One create run's state across its calls. */
interface CreateRun {
  readonly ctx: JiraRunContext;
  /** `vuln.priority`: the Exploited and EPSS lines. */
  readonly priority: boolean;
  readonly outcome: CreateOutcome;
  /** The rows created so far: their status is read after the last call. */
  readonly made: Created[];
  /** The calls Jira answered (R18: a run without one queues no follow-up). */
  answeredCalls: number;
  /** When the next run goes after a 429. */
  retryAfter: number;
}

/** An answered call clears a transient problem (the run's view follows its writes). */
async function answered(run: CreateRun): Promise<void> {
  run.answeredCalls += 1;
  await clearAfterAnswer(run.ctx.deps.db, run.ctx.connection);
}

/** The stop of a failed call ({@link stopFor}); a 429 also sets when the next run goes. */
async function stopOn(run: CreateRun, err: unknown): Promise<Stop> {
  if (!(err instanceof JiraError)) throw err;
  if (err.code === 'rate_limited') {
    run.retryAfter = err.retryAfterSeconds ?? RATE_LIMITED_WAIT_SECONDS;
  }
  return stopFor(run.ctx, err);
}

/**
 * The prepared rows sent in one call: Jira's answers, or null when nothing was sent or the call
 * failed. A failed call's rows are released when they never reached Jira (or must not wait), else
 * left with `attempted_at` for the pass to reconcile.
 */
async function send(run: CreateRun, prepared: Prepared): Promise<BulkOutcome | null> {
  if (prepared.send.length === 0) return null;
  try {
    return await run.ctx.client.createIssues(prepared.send.map((s) => s.fields));
  } catch (err) {
    run.outcome.stop = await stopOn(run, err);
    const sent = prepared.send.map((s) => s.row);
    if (RELEASING.has(run.outcome.stop)) await release(run.ctx, sent);
    else run.outcome.unanswered += sent.length;
    return null;
  }
}

/** The answers of one call, by element: created, refused, or not understood (the issue may exist). */
function sortAnswers(
  run: CreateRun,
  sent: readonly JiraLinkRow[],
  answers: BulkOutcome,
): { created: Created[]; failed: Failed[] } {
  const sorted: { created: Created[]; failed: Failed[] } = { created: [], failed: [] };
  answers.forEach((answer, i) => {
    const row = sent[i];
    if (!row) return;
    if ('created' in answer) {
      sorted.created.push({ row, issueId: answer.created.id, key: answer.created.key });
    } else if (ELEMENT_CODES.has(answer.failed.code)) {
      const code = answer.failed.code as JiraFailureCode;
      sorted.failed.push({ row, code, message: answer.failed.jiraText ?? JIRA_FAILURE_TEXT[code] });
    } else {
      run.outcome.unanswered += 1;
    }
  });
  return sorted;
}

/** One call: the claimed rows prepared, sent, and their answers written. */
async function createCall(run: CreateRun, rows: readonly JiraLinkRow[]): Promise<void> {
  let prepared: Prepared;
  try {
    prepared = await prepare(run.ctx.deps, rows, run.priority);
  } catch (err) {
    // Nothing was sent: the rows go back for the next run.
    await release(run.ctx, rows);
    throw err;
  }
  const answers = await send(run, prepared);
  const sorted =
    answers === null
      ? { created: [], failed: [] }
      : sortAnswers(
          run,
          prepared.send.map((s) => s.row),
          answers,
        );
  const written = await record(run.ctx, sorted.created, [...prepared.failed, ...sorted.failed]);
  run.outcome.created += written.created;
  run.outcome.failed += written.failed;
  run.made.push(...sorted.created);
  if (answers !== null) await answered(run);
}

/** spec §6.4: the status of the run's created issues, after its last call, unless it stopped. */
async function readCreatedStatus(run: CreateRun): Promise<void> {
  if (run.outcome.stop !== null || run.made.length === 0) return;
  try {
    await readStatus(run.ctx, run.made);
    await answered(run);
  } catch (err) {
    run.outcome.stop = await stopOn(run, err);
  }
}
