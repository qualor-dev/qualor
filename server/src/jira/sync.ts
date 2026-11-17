import { and, asc, eq, gt, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Db } from '../db/client';
import { jiraLinks, projectJiraSettings, projects } from '../db/schema';
import { issueUrl } from '../scm/decoration-data';
import { targetRefsOf } from '../vulnerabilities/list';
import type { Target } from '../vulnerabilities/targets';
import {
  ELEMENT_CODES,
  isJiraIssueId,
  isJiraIssueKey,
  JIRA_LABEL_BATCH,
  JIRA_SEARCH_BATCH,
  JiraError,
  type JiraIssueState,
} from './client';
import {
  fixedComment,
  foundAgainComment,
  reconciliationLabel,
  vulnerabilitiesUrl,
  type CodeIssueFacts,
  type CommentFacts,
} from './content';
import { createPending, fenceOf, recordset, release, stopFor } from './create';
import { codeIssueFacts } from './facts';
import { JIRA_FAILURE_TEXT, type JiraLinkRow } from './links';
import { goneIssueIds, pairKey, pairPlaces, presenceScopes, type PresenceScope } from './presence';
import {
  backgroundCodeOf,
  clearAfterAnswer,
  isCredentialCode,
  isCredentialProblem,
  replaceConnectionProblem,
} from './problems';
import type { JiraRunContext } from './run';

/** spec §6.5 step 1: a create unanswered this long is looked for by its label ... */
export const RECONCILE_AFTER_SECONDS = 120;
/** ... and, not found after this long, sent again (Cloud's search may lag behind a create). */
export const RESEND_AFTER_SECONDS = 600;
/** Step 4: the created rows whose status one pass reads, oldest read first. */
export const STATUS_PER_PASS = 5_000;
/** Step 5: the fixed and found-again comments of one pass. */
export const COMMENTS_PER_PASS = 100;
/** Step 4: an id missing from this many passes in a row makes the link `missing`. */
export const MISSING_AFTER_PASSES = 2;
/** spec §6.1: a CAPTCHA lockout is probed at most this often (each attempt extends it). */
export const CAPTCHA_PROBE_SECONDS = 3_600;

export interface PassOutcome {
  /** Unanswered creates found by their label. */
  reconciled: number;
  created: number;
  /** Links the automatic rule made (Task 9). */
  auto: number;
  /** Links whose status was read. */
  statuses: number;
  /** Links that became `missing`. */
  missing: number;
  /** Comments Jira took (a refused one is recorded, R14, but not counted). */
  comments: number;
  /** Why the pass ended before its last step, if it did. */
  stop: null | 'credential' | 'transient' | 'rate_limited' | 'budget' | 'captcha_wait';
}

type Stop = PassOutcome['stop'];

interface Pass {
  readonly ctx: JiraRunContext;
  readonly outcome: PassOutcome;
  /** When the pass started (UTC), `YYYY-MM-DD`: a vulnerability comment's day. */
  readonly day: string;
}

const dayOf = (d: Date): string => d.toISOString().slice(0, 10);

const ago = (seconds: number) => sql`now() - make_interval(secs => ${seconds})`;

const labelOf = (row: Pick<JiraLinkRow, 'id' | 'generation'>): string =>
  reconciliationLabel(row.id, row.generation);

/** A failed Jira call: the pass ends when it concerns the connection, the budget or a 429. */
async function failed(pass: Pass, err: unknown): Promise<void> {
  if (!(err instanceof JiraError)) throw err;
  pass.outcome.stop = await stopFor(pass.ctx, err);
}

/**
 * One Jira call of the pass: its answer, or null when it failed ({@link failed}). An answered
 * call clears a transient problem.
 */
async function call<T>(pass: Pass, request: () => Promise<T>): Promise<T | null> {
  let answer: T;
  try {
    answer = await request();
  } catch (err) {
    await failed(pass, err);
    return null;
  }
  await clearAfterAnswer(pass.ctx.deps.db, pass.ctx.connection);
  return answer;
}

// ─── Probe (spec §6.1) ──────────────────────────────────────────────────────────────────────────

/**
 * A failed probe ends the pass. A credential answer is recorded again, so a captcha's hour runs
 * from this probe; a timeout says nothing of the credential, whose problem stays.
 */
async function probeFailed(pass: Pass, err: unknown): Promise<Stop> {
  if (!(err instanceof JiraError)) throw err;
  if (err.code === 'rate_limited') return 'rate_limited';
  const code = backgroundCodeOf(err);
  if (code !== null && isCredentialCode(code)) {
    await replaceConnectionProblem(pass.ctx.deps.db, pass.ctx.connection, code);
    return 'credential';
  }
  return code === null ? 'credential' : 'transient';
}

/**
 * While a credential problem is set, one `GET /myself` first: its success clears the problem (if
 * it is still the one the pass read) and the pass goes on; a captcha lockout is probed at most
 * once an hour.
 */
async function probe(pass: Pass): Promise<void> {
  const { connection, client, deps } = pass.ctx;
  const { problem } = connection;
  if (problem === null || !isCredentialProblem(problem)) return;
  const age = (Date.now() - Date.parse(problem.at)) / 1000;
  if (problem.code === 'captcha' && age < CAPTCHA_PROBE_SECONDS) {
    pass.outcome.stop = 'captcha_wait';
    return;
  }
  try {
    await client.myself();
  } catch (err) {
    pass.outcome.stop = await probeFailed(pass, err);
    return;
  }
  await replaceConnectionProblem(deps.db, connection, null);
  // Another writer's credential problem since the pass read the row.
  if (isCredentialProblem(connection.problem)) pass.outcome.stop = 'credential';
}

// ─── Step 1: reconcile ──────────────────────────────────────────────────────────────────────────

interface Attempted {
  row: JiraLinkRow;
  /** The mapping's `labels_available`; null for a project without a mapping. */
  labels: boolean | null;
  /** Sent more than {@link RESEND_AFTER_SECONDS} ago. */
  stale: boolean;
}

/** Up to 50 pending rows sent more than 2 minutes ago without an answer, after `after` by id. */
function attemptedRows(ctx: JiraRunContext, after: string | null): Promise<Attempted[]> {
  return ctx.deps.db
    .select({
      row: jiraLinks,
      labels: projectJiraSettings.labelsAvailable,
      stale: sql<boolean>`${jiraLinks.attemptedAt} < ${ago(RESEND_AFTER_SECONDS)}`,
    })
    .from(jiraLinks)
    .leftJoin(projectJiraSettings, eq(projectJiraSettings.projectId, jiraLinks.projectId))
    .where(
      and(
        eq(jiraLinks.connectionId, ctx.connection.id),
        eq(jiraLinks.state, 'pending'),
        sql`${jiraLinks.attemptedAt} < ${ago(RECONCILE_AFTER_SECONDS)}`,
        after === null ? undefined : gt(jiraLinks.id, after),
      ),
    )
    .orderBy(asc(jiraLinks.id))
    .limit(JIRA_LABEL_BATCH);
}

/**
 * Rows whose create may or may not have made an issue, with no way to find out: `failed`,
 * `outcome_unknown`, never sent again by themselves (the member may retry).
 */
async function failUnknown(db: Db, rows: readonly JiraLinkRow[]): Promise<void> {
  if (rows.length === 0) return;
  await db.execute(sql`
    UPDATE jira_links l
       SET state = 'failed',
           failure = jsonb_build_object('code', 'outcome_unknown',
                                        'message', ${JIRA_FAILURE_TEXT.outcome_unknown}::text),
           updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows.map(fenceOf))}::jsonb) AS c(id uuid, generation int)
     WHERE l.id = c.id AND l.generation = c.generation AND l.state = 'pending'
       AND l.attempted_at IS NOT NULL`);
}

/**
 * Rows whose issue was found: `created` with its id, key and status, as a create's answer would
 * have made them (a row dismissed meanwhile keeps the key and id, R19). Returns how many.
 */
async function recordFound(
  db: Db,
  found: readonly { row: JiraLinkRow; issue: JiraIssueState }[],
): Promise<number> {
  if (found.length === 0) return 0;
  const json = recordset(
    found.map(({ row, issue }) => ({
      ...fenceOf(row),
      issue_id: issue.id,
      key: issue.key,
      name: issue.statusName,
      category: issue.statusCategory,
    })),
  );
  const result = await db.execute(sql`
    UPDATE jira_links l
       SET state = CASE WHEN l.state = 'pending' THEN 'created' ELSE l.state END,
           jira_issue_id = c.issue_id, jira_key = c.key, status_name = c.name,
           status_category = c.category, status_checked_at = now(), missed_passes = 0,
           updated_at = now()
      FROM jsonb_to_recordset(${json}::jsonb)
           AS c(id uuid, generation int, issue_id text, key text, name text, category text)
     WHERE l.id = c.id AND l.generation = c.generation`);
  return result.rowCount ?? 0;
}

/**
 * What a label search says of each searched row: found (a key not of Jira's form is a bad answer:
 * the issue exists, so the row waits); not found after 10 minutes, sent again, or failed
 * `outcome_unknown` for a project without a mapping (it would not be sent anew); else it waits.
 */
function sortSearched(
  searched: readonly Attempted[],
  found: ReadonlyMap<string, JiraIssueState>,
): {
  found: { row: JiraLinkRow; issue: JiraIssueState }[];
  resend: JiraLinkRow[];
  lost: JiraLinkRow[];
} {
  const sorted = {
    found: [] as { row: JiraLinkRow; issue: JiraIssueState }[],
    resend: [] as JiraLinkRow[],
    lost: [] as JiraLinkRow[],
  };
  for (const { row, labels, stale } of searched) {
    const issue = found.get(labelOf(row));
    if (issue !== undefined) {
      if (isJiraIssueKey(issue.key)) sorted.found.push({ row, issue });
    } else if (stale) {
      (labels === null ? sorted.lost : sorted.resend).push(row);
    }
  }
  return sorted;
}

async function reconcileChunk(pass: Pass, rows: readonly Attempted[]): Promise<void> {
  const { db } = pass.ctx.deps;
  // The screen has no labels: the row cannot be looked for.
  await failUnknown(
    db,
    rows.filter((r) => r.labels === false).map((r) => r.row),
  );
  const searched = rows.filter((r) => r.labels !== false);
  if (searched.length === 0) return;
  const found = await call(pass, () =>
    pass.ctx.client.searchByLabels(searched.map((r) => labelOf(r.row))),
  );
  if (found === null) return;
  const sorted = sortSearched(searched, found);
  pass.outcome.reconciled += await recordFound(db, sorted.found);
  await release(db, sorted.resend);
  await failUnknown(db, sorted.lost);
}

/**
 * spec §6.5 step 1: each pending row sent more than 2 minutes ago without an answer is looked for
 * by its label (`labels in (…)`, 50 per call), never sent again blindly.
 */
async function reconcile(pass: Pass): Promise<void> {
  let after: string | null = null;
  for (;;) {
    const rows = await attemptedRows(pass.ctx, after);
    const last = rows.at(-1);
    if (last === undefined) return;
    await reconcileChunk(pass, rows);
    if (pass.outcome.stop !== null || rows.length < JIRA_LABEL_BATCH) return;
    after = last.row.id;
  }
}

// ─── Steps 2 and 3: create, the automatic rule ──────────────────────────────────────────────────

/** spec §6.5 step 2: the create step of §6.4 for the never-attempted pending rows. */
async function create(pass: Pass): Promise<void> {
  const result = await createPending(pass.ctx);
  pass.outcome.created += result.created;
  pass.outcome.stop = result.stop;
}

/** The links step 3 makes: none until Task 9's automatic rule (`runAutoRule`) takes this place. */
const automaticLinks = (): Promise<number> => Promise.resolve(0);

/**
 * spec §6.5 step 3, the automatic rule (§6.6). Ruling P5: when it made rows and the budget
 * allows, the create step runs once more, so they need not wait for the next pass.
 */
async function automaticRule(pass: Pass): Promise<void> {
  const made = await automaticLinks();
  pass.outcome.auto += made;
  if (made > 0 && pass.ctx.client.remaining > 0) await create(pass);
}

// ─── Step 4: status ─────────────────────────────────────────────────────────────────────────────

interface StatusRow {
  id: string;
  generation: number;
  jiraIssueId: string;
}

/** The statuses of one batch, fenced on `(id, generation)` and the Jira issue id. */
async function writeStatuses(
  pass: Pass,
  batch: readonly StatusRow[],
  result: { found: ReadonlyMap<string, JiraIssueState>; missing: readonly string[] },
): Promise<void> {
  const { db } = pass.ctx.deps;
  const read = batch.flatMap((r) => {
    const state = result.found.get(r.jiraIssueId);
    // T6b: a key not of Jira's form is a bad answer of its own; the row is read again next pass.
    if (state === undefined || !isJiraIssueKey(state.key)) return [];
    return [
      {
        ...fenceOf(r),
        issue_id: r.jiraIssueId,
        key: state.key,
        name: state.statusName,
        category: state.statusCategory,
      },
    ];
  });
  if (read.length > 0) {
    const written = await db.execute(sql`
      UPDATE jira_links l
         SET jira_key = c.key, status_name = c.name, status_category = c.category,
             status_checked_at = now(), missed_passes = 0, updated_at = now()
        FROM jsonb_to_recordset(${recordset(read)}::jsonb)
             AS c(id uuid, generation int, issue_id text, key text, name text, category text)
       WHERE l.id = c.id AND l.generation = c.generation AND l.jira_issue_id = c.issue_id
         AND l.state = 'created'`);
    pass.outcome.statuses += written.rowCount ?? 0;
  }
  const gone = new Set(result.missing);
  const missed = batch
    .filter((r) => gone.has(r.jiraIssueId))
    .map((r) => ({ ...fenceOf(r), issue_id: r.jiraIssueId }));
  if (missed.length === 0) return;
  // Its status is not read: it keeps its place at the front of the next pass's order.
  const marked = await db.execute<{ state: string }>(sql`
    UPDATE jira_links l
       SET missed_passes = l.missed_passes + 1,
           state = CASE WHEN l.missed_passes + 1 >= ${MISSING_AFTER_PASSES} THEN 'missing'
                        ELSE l.state END,
           updated_at = now()
      FROM jsonb_to_recordset(${recordset(missed)}::jsonb)
           AS c(id uuid, generation int, issue_id text)
     WHERE l.id = c.id AND l.generation = c.generation AND l.jira_issue_id = c.issue_id
       AND l.state = 'created'
    RETURNING l.state`);
  pass.outcome.missing += marked.rows.filter((r) => r.state === 'missing').length;
}

/**
 * spec §6.5 step 4: the status of the `created` rows, oldest read first (never read first of
 * all), at most 5 000 per pass, `id in (…)` 100 per call. Each batch is written as it is read, so
 * a stop keeps what was read. A moved issue keeps its id and its new key is stored; an id missing
 * from two passes in a row makes the link `missing`.
 */
async function readStatuses(pass: Pass): Promise<void> {
  const rows = await pass.ctx.deps.db
    .select({
      id: jiraLinks.id,
      generation: jiraLinks.generation,
      jiraIssueId: jiraLinks.jiraIssueId,
    })
    .from(jiraLinks)
    .where(and(eq(jiraLinks.connectionId, pass.ctx.connection.id), eq(jiraLinks.state, 'created')))
    .orderBy(sql`${jiraLinks.statusCheckedAt} ASC NULLS FIRST`, asc(jiraLinks.id))
    .limit(STATUS_PER_PASS);
  const readable = rows.filter(
    (r): r is StatusRow => r.jiraIssueId !== null && isJiraIssueId(r.jiraIssueId),
  );
  for (let i = 0; i < readable.length && pass.outcome.stop === null; i += JIRA_SEARCH_BATCH) {
    const batch = readable.slice(i, i + JIRA_SEARCH_BATCH);
    const result = await call(pass, () =>
      pass.ctx.client.searchByIds(batch.map((r) => r.jiraIssueId)),
    );
    if (result !== null) await writeStatuses(pass, batch, result);
  }
}

// ─── Step 5: fixed and found again ──────────────────────────────────────────────────────────────

type CreatedRow = Pick<
  JiraLinkRow,
  | 'id'
  | 'generation'
  | 'projectId'
  | 'kind'
  | 'issueId'
  | 'packageName'
  | 'vulnerabilityId'
  | 'jiraIssueId'
  | 'reportedFixedAt'
>;

/** Whether a link's finding is gone, and where a present pair is found now. */
interface Judgement {
  gone: boolean;
  places: string[];
}

interface DueComment {
  row: CreatedRow;
  fixed: boolean;
  body: string;
}

/** The `created` rows of the connection, oldest first. */
function createdRows(ctx: JiraRunContext): Promise<CreatedRow[]> {
  return ctx.deps.db
    .select({
      id: jiraLinks.id,
      generation: jiraLinks.generation,
      projectId: jiraLinks.projectId,
      kind: jiraLinks.kind,
      issueId: jiraLinks.issueId,
      packageName: jiraLinks.packageName,
      vulnerabilityId: jiraLinks.vulnerabilityId,
      jiraIssueId: jiraLinks.jiraIssueId,
      reportedFixedAt: jiraLinks.reportedFixedAt,
    })
    .from(jiraLinks)
    .where(and(eq(jiraLinks.connectionId, ctx.connection.id), eq(jiraLinks.state, 'created')))
    .orderBy(asc(jiraLinks.createdAt), asc(jiraLinks.id));
}

const pairOf = (r: CreatedRow) => ({
  packageName: r.packageName ?? '',
  vulnerabilityId: r.vulnerabilityId ?? '',
});

/**
 * The vulnerability links judged per project, one presence query each; a project with monitoring
 * off (no scope) is not judged at all. Returns the scopes.
 */
async function judgeVulnerabilities(
  db: Db,
  rows: readonly CreatedRow[],
  judged: Map<string, Judgement>,
): Promise<Map<string, PresenceScope | null>> {
  const byProject = new Map<string, CreatedRow[]>();
  for (const r of rows) {
    const list = byProject.get(r.projectId);
    if (list === undefined) byProject.set(r.projectId, [r]);
    else list.push(r);
  }
  const scopes = await presenceScopes(db, [...byProject.keys()]);
  for (const [projectId, list] of byProject) {
    const scope = scopes.get(projectId);
    if (!scope) continue;
    const { present } = await pairPlaces(db, projectId, scope, list.map(pairOf));
    for (const r of list) {
      const places = present.get(pairKey(r.packageName ?? '', r.vulnerabilityId ?? ''));
      judged.set(r.id, { gone: places === undefined, places: places ?? [] });
    }
  }
  return scopes;
}

/** Each judged row's {@link Judgement}, by link id, and the presence scopes of its projects. */
async function judge(
  db: Db,
  rows: readonly CreatedRow[],
): Promise<{ judged: Map<string, Judgement>; scopes: Map<string, PresenceScope | null> }> {
  const judged = new Map<string, Judgement>();
  const codes = rows.flatMap((r) =>
    r.kind === 'issue' && r.issueId !== null ? [{ id: r.id, issueId: r.issueId }] : [],
  );
  const closed = await goneIssueIds(
    db,
    codes.map((c) => c.issueId),
  );
  for (const c of codes) judged.set(c.id, { gone: closed.has(c.issueId), places: [] });
  const scopes = await judgeVulnerabilities(
    db,
    rows.filter((r) => r.kind === 'vulnerability'),
    judged,
  );
  return { judged, scopes };
}

const refOf = (t: Target): { kind: 'branch' | 'version'; id: string } =>
  t.kind === 'branch' ? { kind: 'branch', id: t.branchId } : { kind: 'version', id: t.versionId };

/** What the comments of the due rows say beyond the link row: names, days, tracked targets. */
interface CommentSources {
  code: Map<string, CodeIssueFacts>;
  projectNames: Map<string, string>;
  /** The tracked targets' names of each project with a fixed vulnerability comment due. */
  tracked: Map<string, string[]>;
}

async function commentSources(
  db: Db,
  due: readonly { row: CreatedRow; judgement: Judgement }[],
  scopes: ReadonlyMap<string, PresenceScope | null>,
): Promise<CommentSources> {
  const code = await codeIssueFacts(
    db,
    due.flatMap((d) => (d.row.kind === 'issue' && d.row.issueId !== null ? [d.row.issueId] : [])),
  );
  const vulnerable = due.filter((d) => d.row.kind === 'vulnerability');
  const ids = [...new Set(vulnerable.map((d) => d.row.projectId))];
  const named =
    ids.length === 0
      ? []
      : await db
          .select({ id: projects.id, name: projects.name })
          .from(projects)
          .where(inArray(projects.id, uuidList(ids)));
  const tracked = new Map<string, string[]>();
  for (const projectId of new Set(
    vulnerable.filter((d) => d.judgement.gone).map((d) => d.row.projectId),
  )) {
    const targets = scopes.get(projectId)?.targets ?? [];
    tracked.set(
      projectId,
      (await targetRefsOf(db, projectId, targets.map(refOf))).map((t) => t.name),
    );
  }
  return { code, projectNames: new Map(named.map((p) => [p.id, p.name])), tracked };
}

/**
 * Ruling P4: a comment's facts from the link row, the project and the tracked targets (the pair
 * may be gone). R20: a code issue's fixed day is its `closed_at`, its found-again day its last
 * analysis's; a vulnerability's is the pass's. A fixed vulnerability's `foundIn` is the tracked
 * targets ("on the tracked branches and versions"), a found-again one's where it is now.
 */
function commentFacts(
  pass: Pass,
  d: { row: CreatedRow; judgement: Judgement },
  sources: CommentSources,
): CommentFacts | null {
  const { publicUrl } = pass.ctx.deps;
  const { row, judgement } = d;
  if (row.kind === 'issue') {
    const f = row.issueId === null ? undefined : sources.code.get(row.issueId);
    if (f === undefined) return null;
    const when = judgement.gone ? f.closedAt : f.lastSeenAt;
    return {
      kind: 'code',
      projectName: f.projectName,
      branchName: f.branchName,
      ruleKey: f.ruleKey,
      day: when === null ? pass.day : dayOf(when),
      link: issueUrl(publicUrl, f.projectId, f.issueId),
    };
  }
  const projectName = sources.projectNames.get(row.projectId);
  if (projectName === undefined) return null;
  return {
    kind: 'vulnerability',
    projectName,
    ...pairOf(row),
    foundIn: judgement.gone ? (sources.tracked.get(row.projectId) ?? []) : judgement.places,
    day: pass.day,
    link: vulnerabilitiesUrl(publicUrl, row.projectId),
  };
}

/**
 * The transitions of this pass, at most 100, oldest link first: a `created` row whose finding is
 * gone and not reported fixed gets the fixed comment; one reported fixed whose finding is present
 * again the found-again comment. Vulnerability links of a project with monitoring off are not
 * judged.
 */
async function dueComments(pass: Pass): Promise<DueComment[]> {
  const { db } = pass.ctx.deps;
  const rows = await createdRows(pass.ctx);
  const { judged, scopes } = await judge(db, rows);
  const due = rows
    .flatMap((row) => {
      const judgement = judged.get(row.id);
      if (judgement === undefined || judgement.gone === (row.reportedFixedAt !== null)) return [];
      return [{ row, judgement }];
    })
    .slice(0, COMMENTS_PER_PASS);
  const sources = await commentSources(db, due, scopes);
  return due.flatMap((d) => {
    const facts = commentFacts(pass, d, sources);
    if (facts === null) return [];
    const fixed = d.judgement.gone;
    return [{ row: d.row, fixed, body: fixed ? fixedComment(facts) : foundAgainComment(facts) }];
  });
}

/** The transition, written whether Jira took the comment or refused it (R14). */
async function recordTransition(db: Db, d: DueComment): Promise<void> {
  await db
    .update(jiraLinks)
    .set({ reportedFixedAt: d.fixed ? sql`now()` : null, updatedAt: sql`now()` })
    .where(
      and(
        eq(jiraLinks.id, d.row.id),
        eq(jiraLinks.generation, d.row.generation),
        eq(jiraLinks.state, 'created'),
        d.fixed ? isNull(jiraLinks.reportedFixedAt) : isNotNull(jiraLinks.reportedFixedAt),
      ),
    );
}

/**
 * One comment: `posted`; `refused` when Jira refuses it (400, 403, 404, 413, 422; R14: warned,
 * recorded, not tried again); null when the call failed (not recorded: tried next pass).
 */
async function postComment(pass: Pass, d: DueComment): Promise<'posted' | 'refused' | null> {
  const { client, deps } = pass.ctx;
  try {
    await client.addComment(d.row.jiraIssueId ?? '', d.body);
  } catch (err) {
    if (!(err instanceof JiraError) || !ELEMENT_CODES.has(err.code)) {
      await failed(pass, err);
      return null;
    }
    deps.logger?.warn(
      { linkId: d.row.id, code: err.code, status: err.status },
      'Jira refused a comment; the transition is recorded without it',
    );
    await clearAfterAnswer(deps.db, pass.ctx.connection);
    return 'refused';
  }
  await clearAfterAnswer(deps.db, pass.ctx.connection);
  return 'posted';
}

/** spec §6.5 step 5: the fixed and found-again comments, at most 100 per pass. */
async function comment(pass: Pass): Promise<void> {
  for (const d of await dueComments(pass)) {
    const posted = await postComment(pass, d);
    if (posted !== null) await recordTransition(pass.ctx.deps.db, d);
    if (posted === 'posted') pass.outcome.comments += 1;
    if (pass.outcome.stop !== null) return;
  }
}

// ─── The pass ───────────────────────────────────────────────────────────────────────────────────

/** spec §6.5: the probe while a credential problem is set, then steps 1 to 5 in order. */
const STEPS: readonly ((pass: Pass) => Promise<void>)[] = [
  probe,
  reconcile,
  create,
  automaticRule,
  readStatuses,
  comment,
];

/**
 * spec §6.5: one sync pass of the organisation's connection. Each step reads its rows by
 * `connection_id` (`jira_links_pass_idx`), writes fenced on `(id, generation)`, and holds no
 * transaction across a Jira call. A credential failure at any step records the problem and ends
 * the pass; a transient one records `timeout` or `unreachable` and ends it; a 429 or the request
 * budget ends it. One info line per pass, with its counts and duration.
 */
export async function runSyncPass(ctx: JiraRunContext): Promise<PassOutcome> {
  const started = Date.now();
  const pass: Pass = {
    ctx,
    outcome: {
      reconciled: 0,
      created: 0,
      auto: 0,
      statuses: 0,
      missing: 0,
      comments: 0,
      stop: null,
    },
    day: dayOf(new Date(started)),
  };
  for (const step of STEPS) {
    await step(pass);
    if (pass.outcome.stop !== null) break;
  }
  ctx.deps.logger?.info(
    {
      organizationId: ctx.connection.organizationId,
      connectionId: ctx.connection.id,
      requests: ctx.client.requests,
      durationMs: Date.now() - started,
      ...pass.outcome,
    },
    'Jira sync pass',
  );
  return pass.outcome;
}
