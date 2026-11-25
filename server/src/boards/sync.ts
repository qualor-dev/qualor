import { and, asc, eq, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Db } from '../db/client';
import {
  boardsLinks,
  projectBoardsSettings,
  projects,
  scmConnections,
  type BoardsStateCategory,
  type ScmProblemValue,
} from '../db/schema';
import { vulnerabilitiesUrl, type CodeIssueFacts, type CommentFacts } from '../jira/content';
import { recordset } from '../jira/create';
import { codeIssueFacts } from '../jira/facts';
import {
  goneIssueIds,
  pairKey,
  pairPlaces,
  presenceScopes,
  type PresenceScope,
} from '../jira/presence';
import {
  AzureError,
  MAX_WORK_ITEM_BATCH,
  WORK_ITEM_QUERY_TOP,
  type AzureWorkItem,
  type AzureWorkItemType,
} from '../scm/azure/client';
import { issueUrl } from '../scm/decoration-data';
import { clearScmProblem } from '../scm/problems';
import { ScmError } from '../scm/provider';
import { targetId, targetRefsOf } from '../vulnerabilities/list';
import { runBoardsAutoRule } from './auto-rule';
import { fixedNote, foundAgainNote, keyOfDescription, reconciliationKey } from './content';
import {
  BOARDS_FAILURE_TEXT,
  boardsConnectionUnmoved,
  CREATE_PER_RUN,
  createFailureOf,
  createPendingWorkItems,
  releaseLinks,
  stateCategoryOf,
  stopFor,
  type BoardsFailure,
  type BoardsStop,
  type WorkItemTypeCache,
} from './create';
import { enqueueBoardsCreate } from './jobs';
import { BOARDS_BLOCKING_CODES, isBoardsBlockingProblem, type BoardsLinkRow } from './links';
import { QUALOR_TAG } from './mapping';
import type { BoardsRunContext } from './run';

/*
 * Azure DevOps design §7.8: the Jira sync pass (jira/sync.ts, spec §6.5) for Azure Boards, one per
 * Azure DevOps connection: the probe, reconcile (WIQL by tag, identity and time, then the key in
 * the description), create, the automatic rule, the states (`workitemsbatch`) and the notes
 * (`System.History`). Every step reads its rows by `connection_id` and works on each link's own
 * Azure DevOps project; no transaction spans a request.
 */

/** A create unanswered this long is looked for (a lost answer; the WIQL index showed no lag) ... */
export const RECONCILE_AFTER_SECONDS = 120;
/** ... and, not found after this long, sent again. */
export const RESEND_AFTER_SECONDS = 600;
/** The WIQL looks back this far before the oldest unanswered create: the two clocks may differ. */
export const RECONCILE_SLACK_SECONDS = 60;
/** The `created` rows whose state one pass reads, oldest read first. */
export const STATE_PER_PASS = 5_000;
/** The fixed and found-again notes of one pass. */
export const NOTES_PER_PASS = 100;
/** An id missing from this many passes in a row makes the link `missing`. */
export const MISSING_AFTER_PASSES = 2;
/** Unanswered rows one pass reads: 10 Azure DevOps projects of 200 work items each. */
const UNANSWERED_PER_PASS = 2_000;

/**
 * The most requests of each step of a pass (plan Task 7), 366 in all with the second create, so a
 * pass stays within a client's 400: reconcile 2 per Azure DevOps project (a WIQL query and a batch
 * read), the states 25 batches of 200, the type lists (and the project list a moved work item
 * needs) of the whole pass 20. A step that would go past the client's budget ends the pass with
 * `budget` before it starts.
 */
export const PASS_BUDGET = {
  probe: 1,
  reconcile: 20,
  create: CREATE_PER_RUN,
  states: STATE_PER_PASS / MAX_WORK_ITEM_BATCH,
  notes: NOTES_PER_PASS,
  typeLists: 20,
} as const;

export interface BoardsPassOutcome {
  /** Unanswered creates found by their key. */
  reconciled: number;
  created: number;
  /** Links the automatic rule made. */
  auto: number;
  /** Links whose state was read. */
  states: number;
  /** Links that became `missing`. */
  missing: number;
  /** Notes Azure DevOps took (a refused one is recorded on its link, but not counted). */
  notes: number;
  /** Why the pass ended before its last step, if it did. */
  stop: BoardsStop;
}

interface Pass {
  readonly ctx: BoardsRunContext;
  readonly outcome: BoardsPassOutcome;
  /** When the pass started (UTC), `YYYY-MM-DD`: a vulnerability note's day. */
  readonly day: string;
  /** The type lists of the pass, by Azure DevOps project id, shared with its create steps. */
  readonly types: WorkItemTypeCache;
  /** The Azure DevOps projects whose type list failed in this pass. */
  readonly unreadableTypes: Set<string>;
  /** Azure DevOps project ids by lower-case name; read when first needed. */
  names: Map<string, string> | null;
  /** The organisation's project list was read in this pass (at most once). */
  projectsListed: boolean;
  /** The requests that list took. */
  projectListRequests: number;
}

const dayOf = (d: Date): string => d.toISOString().slice(0, 10);

const ago = (seconds: number) => sql`now() - make_interval(secs => ${seconds})`;

/** The claim fence of a pending row: `(id, generation)` and the `attempted_at` read. */
const claimOf = (row: Pick<BoardsLinkRow, 'id' | 'generation' | 'attemptedAt'>) => ({
  id: row.id,
  generation: row.generation,
  stamp: row.attemptedAt?.toISOString() ?? null,
});

const isBadAnswer = (err: unknown): boolean => err instanceof ScmError && err.kind === 'bad_answer';

/**
 * Azure DevOps refused the call itself (a 400 or another HTTP refusal, a 403, a 404): it concerns
 * the links asked about, never the connection.
 */
function refusedByAzure(err: unknown): boolean {
  if (!(err instanceof AzureError)) return false;
  if (err.kind === 'not_found') return true;
  if (err.kind === 'auth') return err.reason === 'permission_missing';
  return err.kind === 'refused' && err.reason === 'http';
}

/** A failed call's effect on the pass ({@link stopFor}): it ends on a credential, transient, 429 or budget failure. */
async function failed(pass: Pass, err: unknown): Promise<void> {
  if (!(err instanceof ScmError)) throw err;
  const stop = await stopFor(pass.ctx, err);
  if (stop !== null) pass.outcome.stop = stop;
}

/** Whether `need` more requests fit the client's budget; if not, the pass ends with `budget`. */
function fits(pass: Pass, need: number): boolean {
  if (pass.ctx.client.remaining >= need) return true;
  pass.outcome.stop = 'budget';
  return false;
}

const typeListsUsed = (pass: Pass): number =>
  pass.types.size + pass.unreadableTypes.size + pass.projectListRequests;

/** The type lists the pass may still read. */
const typeListsLeft = (pass: Pass): number =>
  Math.max(0, PASS_BUDGET.typeLists - typeListsUsed(pass));

// ─── States' categories ─────────────────────────────────────────────────────────────────────────

/** The project ids by lower-case name the connection's mappings know. */
async function mappedNames(pass: Pass): Promise<Map<string, string>> {
  if (pass.names !== null) return pass.names;
  const rows = await pass.ctx.deps.db
    .select({
      id: projectBoardsSettings.azureProjectId,
      name: projectBoardsSettings.azureProjectName,
    })
    .from(projectBoardsSettings)
    .where(eq(projectBoardsSettings.connectionId, pass.ctx.connection.id));
  pass.names = new Map(rows.map((r) => [r.name.toLowerCase(), r.id]));
  return pass.names;
}

/**
 * The id of the Azure DevOps project a work item is in now (`System.TeamProject` is its name, a
 * work item path takes its GUID): from the connection's mappings, else from the organisation's
 * project list, read at most once per pass (a moved work item, a renamed project, a link whose
 * mapping is gone). Null when the name is not found or the list is not read.
 */
async function projectIdOf(pass: Pass, name: string): Promise<string | null> {
  const names = await mappedNames(pass);
  const known = names.get(name.toLowerCase());
  if (known !== undefined || pass.projectsListed) return known ?? null;
  if (pass.outcome.stop !== null || typeListsLeft(pass) === 0) return null;
  pass.projectsListed = true;
  const before = pass.ctx.client.requestCount;
  try {
    for (const p of await pass.ctx.client.projects()) names.set(p.name.toLowerCase(), p.id);
  } catch (err) {
    if (!refusedByAzure(err) && !isBadAnswer(err)) await failed(pass, err);
  } finally {
    pass.projectListRequests += pass.ctx.client.requestCount - before;
  }
  return names.get(name.toLowerCase()) ?? null;
}

/**
 * The project's type list, read once per pass (shared with the create steps), or null: the pass's
 * type lists are spent, it stopped, or the list failed (a refusal or an unreadable answer leaves
 * the project's categories unknown for this pass; any other failure ends the pass).
 */
async function typesOf(pass: Pass, azureProjectId: string): Promise<AzureWorkItemType[] | null> {
  const cached = pass.types.get(azureProjectId);
  if (cached) return cached;
  if (pass.unreadableTypes.has(azureProjectId)) return null;
  if (pass.outcome.stop !== null || typeListsLeft(pass) === 0) return null;
  try {
    const types = await pass.ctx.client.workItemTypes(azureProjectId);
    pass.types.set(azureProjectId, types);
    return types;
  } catch (err) {
    pass.unreadableTypes.add(azureProjectId);
    if (!refusedByAzure(err) && !isBadAnswer(err)) await failed(pass, err);
    return null;
  }
}

interface Category {
  /** The type's states were read: `category` is the answer (null for a state the type lacks). */
  known: boolean;
  category: BoardsStateCategory | null;
}

/**
 * Part B g/k: a state's category from the states of the work item's type in the project it is in
 * now (a moved work item keeps its id, not its project). Unknown when that type list cannot be
 * read in this pass; the write then keeps the stored category while the state name is unchanged.
 */
async function categoryOf(pass: Pass, item: AzureWorkItem, linkProject: string): Promise<Category> {
  const projectId =
    item.projectName === null ? linkProject : await projectIdOf(pass, item.projectName);
  if (projectId === null) return { known: false, category: null };
  const types = await typesOf(pass, projectId);
  if (types === null) return { known: false, category: null };
  const wanted = item.typeName?.toLowerCase();
  const type = types.find((t) => t.name.toLowerCase() === wanted);
  return { known: true, category: stateCategoryOf(type, item.state) };
}

/** The category column as a states write sets it (see {@link Category}). */
const CATEGORY = sql.raw(`CASE WHEN c.name IS NULL THEN l.state_category
                               WHEN c.known THEN c.category
                               WHEN l.state_name IS NOT DISTINCT FROM c.name THEN l.state_category
                               ELSE NULL END`);

// ─── Probe ──────────────────────────────────────────────────────────────────────────────────────

/**
 * The blocking problems cleared, under the connection row's lock and only while it has the run's
 * address; returns the problem stored afterwards (any other code stays: `permission_missing`, a
 * service hook's).
 */
function clearBlocking(ctx: BoardsRunContext): Promise<ScmProblemValue | null> {
  return ctx.deps.db.transaction(async (tx) => {
    const [held] = await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.id, ctx.connection.id),
          eq(scmConnections.baseUrl, ctx.connection.baseUrl),
        ),
      )
      .for('no key update');
    if (!held) return ctx.connection.problem;
    await clearScmProblem(tx, ctx.connection.id, BOARDS_BLOCKING_CODES);
    const [row] = await tx
      .select({ problem: scmConnections.problem })
      .from(scmConnections)
      .where(eq(scmConnections.id, ctx.connection.id));
    return row?.problem ?? null;
  });
}

/**
 * While a problem that stops Boards is stored, one `connectionData` first: its success clears the
 * blocking codes and the pass goes on; a failure ends the pass (a refused credential recorded
 * again).
 */
async function probe(pass: Pass): Promise<void> {
  const { ctx } = pass;
  if (!isBoardsBlockingProblem(ctx.connection.problem)) return;
  if (!fits(pass, PASS_BUDGET.probe)) return;
  try {
    await ctx.client.connectionData();
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    pass.outcome.stop = (await stopFor(ctx, err)) ?? 'credential';
    return;
  }
  ctx.connection.problem = await clearBlocking(ctx);
  // Another writer's blocking problem since the pass read the row, or the connection moved.
  if (isBoardsBlockingProblem(ctx.connection.problem)) pass.outcome.stop = 'credential';
}

// ─── Reconcile ──────────────────────────────────────────────────────────────────────────────────

interface Unanswered {
  row: BoardsLinkRow;
  /** Sent more than {@link RESEND_AFTER_SECONDS} ago. */
  stale: boolean;
}

/** The pending rows sent more than 2 minutes ago without an answer, oldest first. */
function unansweredRows(ctx: BoardsRunContext): Promise<Unanswered[]> {
  return ctx.deps.db
    .select({
      row: boardsLinks,
      stale: sql<boolean>`${boardsLinks.attemptedAt} < ${ago(RESEND_AFTER_SECONDS)}`,
    })
    .from(boardsLinks)
    .where(
      and(
        eq(boardsLinks.connectionId, ctx.connection.id),
        eq(boardsLinks.state, 'pending'),
        sql`${boardsLinks.attemptedAt} < ${ago(RECONCILE_AFTER_SECONDS)}`,
        boardsConnectionUnmoved(ctx.connection),
      ),
    )
    .orderBy(asc(boardsLinks.attemptedAt), asc(boardsLinks.id))
    .limit(UNANSWERED_PER_PASS);
}

/** Part B f: Qualor's work items of the project created since `since` (ISO, UTC, ms), newest first. */
const reconcileQuery = (since: string): string =>
  `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS '${QUALOR_TAG}' AND [System.CreatedBy] = @Me AND [System.CreatedDate] >= '${since}' ORDER BY [System.Id] DESC`;

/**
 * Rows whose create may or may not have made a work item, with no way to find out: `failed`,
 * `outcome_unknown`, never sent again by themselves (a member may retry). `attempted_at` stays, so
 * a create answer that still comes makes the row `created`.
 */
async function failUnknown(ctx: BoardsRunContext, rows: readonly BoardsLinkRow[]): Promise<void> {
  if (rows.length === 0) return;
  await ctx.deps.db.execute(sql`
    UPDATE boards_links l
       SET state = 'failed',
           failure = jsonb_build_object('code', 'outcome_unknown',
                                        'message', ${BOARDS_FAILURE_TEXT.outcome_unknown}::text),
           updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows.map(claimOf))}::jsonb)
           AS c(id uuid, generation int, stamp timestamptz)
     WHERE l.id = c.id AND l.generation = c.generation AND l.attempted_at = c.stamp
       AND l.state = 'pending' AND ${boardsConnectionUnmoved(ctx.connection)}`);
}

interface Found {
  row: BoardsLinkRow;
  item: AzureWorkItem;
}

/**
 * Rows whose work item was found: `created` with its id and state, as the create's answer would
 * have made them (a row dismissed meanwhile keeps the id, Jira's R19). Fenced on the claim read: a
 * row a create run took again since is that run's. Returns how many.
 */
async function recordFound(pass: Pass, found: readonly Found[]): Promise<number> {
  if (found.length === 0) return 0;
  const values = [];
  for (const { row, item } of found) {
    const { category } = await categoryOf(pass, item, row.azureProjectId);
    values.push({ ...claimOf(row), work_item_id: item.id, name: item.state, category });
  }
  const result = await pass.ctx.deps.db.execute(sql`
    UPDATE boards_links l
       SET state = CASE WHEN l.state = 'pending' THEN 'created' ELSE l.state END,
           work_item_id = c.work_item_id, state_name = c.name, state_category = c.category,
           state_checked_at = now(), missed_passes = 0, updated_at = now()
      FROM jsonb_to_recordset(${recordset(values)}::jsonb)
           AS c(id uuid, generation int, stamp timestamptz, work_item_id int, name text,
                category text)
     WHERE l.id = c.id AND l.generation = c.generation AND l.attempted_at = c.stamp
       AND l.state IN ('pending', 'dismissed') AND ${boardsConnectionUnmoved(pass.ctx.connection)}`);
  return result.rowCount ?? 0;
}

/** Each work item by the key in its description; for a key found twice, the first made. */
function byKey(items: readonly AzureWorkItem[]): Map<string, AzureWorkItem> {
  const found = new Map<string, AzureWorkItem>();
  for (const item of items) {
    const key = keyOfDescription(item.description);
    if (key === null) continue;
    const known = found.get(key);
    if (known === undefined || item.id < known.id) found.set(key, item);
  }
  return found;
}

/**
 * One Azure DevOps project's unanswered rows: one WIQL query from the oldest one's send minus a
 * minute, then one batch read of the ids (with the descriptions), matched by key.
 *
 * - Found → `created`.
 * - Not found and sent more than 10 minutes ago → `attempted_at` cleared (the create sends it
 *   again), in one statement that checks the row is still pending at the stamp read, so a row a
 *   create run took again and sent since is never reset ({@link releaseLinks}).
 * - The query refused (400, 403, 404) → every row `failed outcome_unknown`. The query full (200
 *   ids: older work items may be cut off), or an unreadable answer → the rows that would be sent
 *   again fail `outcome_unknown` instead: Qualor cannot tell, and never sends blindly.
 * - Younger rows not found wait for the next pass.
 */
async function reconcileProject(
  pass: Pass,
  azureProjectId: string,
  rows: readonly Unanswered[],
): Promise<void> {
  const { ctx } = pass;
  const stale = rows.filter((r) => r.stale).map((r) => r.row);
  const oldest = rows.reduce(
    (min, r) => Math.min(min, r.row.attemptedAt?.getTime() ?? min),
    Date.now(),
  );
  const since = new Date(oldest - RECONCILE_SLACK_SECONDS * 1_000).toISOString();
  let ids: number[];
  try {
    ids = await ctx.client.queryWorkItemIds(azureProjectId, reconcileQuery(since));
  } catch (err) {
    if (refusedByAzure(err))
      await failUnknown(
        ctx,
        rows.map((r) => r.row),
      );
    else if (isBadAnswer(err)) await failUnknown(ctx, stale);
    else await failed(pass, err);
    return;
  }
  let items: AzureWorkItem[];
  try {
    items = await ctx.client.workItemsBatch(ids);
  } catch (err) {
    if (refusedByAzure(err) || isBadAnswer(err)) await failUnknown(ctx, stale);
    else await failed(pass, err);
    return;
  }
  const full = ids.length >= WORK_ITEM_QUERY_TOP;
  const keyed = byKey(items);
  const found: Found[] = [];
  const resend: BoardsLinkRow[] = [];
  const unknown: BoardsLinkRow[] = [];
  for (const { row, stale: old } of rows) {
    const item = keyed.get(reconciliationKey(row.id, row.generation));
    if (item !== undefined) found.push({ row, item });
    else if (old) (full ? unknown : resend).push(row);
  }
  pass.outcome.reconciled += await recordFound(pass, found);
  await releaseLinks(ctx, resend);
  await failUnknown(ctx, unknown);
}

/**
 * Design §7.8 reconcile: the pending rows sent more than 2 minutes ago without an answer, looked
 * for per Azure DevOps project (2 requests each, at most 10 projects per pass, the oldest first),
 * never sent again blindly.
 */
async function reconcile(pass: Pass): Promise<void> {
  const rows = await unansweredRows(pass.ctx);
  if (rows.length === 0 || !fits(pass, PASS_BUDGET.reconcile)) return;
  const byProject = new Map<string, Unanswered[]>();
  for (const r of rows) {
    const list = byProject.get(r.row.azureProjectId);
    if (list === undefined) byProject.set(r.row.azureProjectId, [r]);
    else list.push(r);
  }
  let left = PASS_BUDGET.reconcile / 2;
  for (const [azureProjectId, list] of byProject) {
    if (left === 0 || pass.outcome.stop !== null) return;
    left -= 1;
    await reconcileProject(pass, azureProjectId, list);
  }
}

// ─── Create, the automatic rule ─────────────────────────────────────────────────────────────────

/** Whether the connection has never-attempted pending rows. */
async function waiting(ctx: BoardsRunContext): Promise<boolean> {
  const result = await ctx.deps.db.execute<{ waiting: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM boards_links
       WHERE connection_id = ${ctx.connection.id} AND state = 'pending' AND attempted_at IS NULL
    ) AS waiting`);
  return result.rows[0]?.waiting === true;
}

/** The create's most requests: its creates and the type lists the pass may still read. */
const createNeed = (pass: Pass): number => PASS_BUDGET.create + typeListsLeft(pass);

async function runCreate(pass: Pass): Promise<void> {
  const result = await createPendingWorkItems(pass.ctx, { types: pass.types });
  pass.outcome.created += result.created;
  pass.outcome.stop = result.stop;
}

/** The create step for the never-attempted pending rows (at most 100), sharing the pass's type lists. */
async function create(pass: Pass): Promise<void> {
  if (!(await waiting(pass.ctx)) || !fits(pass, createNeed(pass))) return;
  await runCreate(pass);
}

/**
 * The automatic rule. When it made rows, the create step runs once more if the budget allows it,
 * so they need not wait for the next pass; otherwise a create job sends them.
 */
async function automaticRule(pass: Pass): Promise<void> {
  const made = await runBoardsAutoRule(pass.ctx);
  pass.outcome.auto += made;
  if (made === 0) return;
  if (pass.ctx.client.remaining >= createNeed(pass)) await runCreate(pass);
  else await enqueueBoardsCreate(pass.ctx.deps.db, pass.ctx.connection.id);
}

// ─── States ─────────────────────────────────────────────────────────────────────────────────────

interface StateRow {
  id: string;
  generation: number;
  workItemId: number;
  azureProjectId: string;
}

/** A states write's fence: the row is still `created` with this generation and work item. */
const stateFenceOf = (r: StateRow) => ({
  id: r.id,
  generation: r.generation,
  work_item_id: r.workItemId,
});

const STATE_FENCE = sql.raw(`l.id = c.id AND l.generation = c.generation
       AND l.work_item_id = c.work_item_id AND l.state = 'created'`);

/** The states of one batch read, and its ids that are missing (deleted, or out of sight). */
async function writeStates(
  pass: Pass,
  batch: readonly StateRow[],
  items: readonly AzureWorkItem[],
): Promise<void> {
  const { db } = pass.ctx.deps;
  const unmoved = boardsConnectionUnmoved(pass.ctx.connection);
  const byId = new Map(items.map((i) => [i.id, i]));
  const read = [];
  const missed = [];
  for (const r of batch) {
    const item = byId.get(r.workItemId);
    if (item === undefined) {
      missed.push(stateFenceOf(r));
      continue;
    }
    const { known, category } = await categoryOf(pass, item, r.azureProjectId);
    read.push({ ...stateFenceOf(r), name: item.state, category, known });
  }
  if (read.length > 0) {
    const written = await db.execute(sql`
      UPDATE boards_links l
         SET state_name = coalesce(c.name, l.state_name), state_category = ${CATEGORY},
             state_checked_at = now(), missed_passes = 0, updated_at = now()
        FROM jsonb_to_recordset(${recordset(read)}::jsonb)
             AS c(id uuid, generation int, work_item_id int, name text, category text,
                  known boolean)
       WHERE ${STATE_FENCE} AND ${unmoved}`);
    pass.outcome.states += written.rowCount ?? 0;
  }
  if (missed.length === 0) return;
  // Its state is not read: it keeps its place at the front of the next pass's order.
  const marked = await db.execute<{ state: string }>(sql`
    UPDATE boards_links l
       SET missed_passes = l.missed_passes + 1,
           state = CASE WHEN l.missed_passes + 1 >= ${MISSING_AFTER_PASSES} THEN 'missing'
                        ELSE l.state END,
           updated_at = now()
      FROM jsonb_to_recordset(${recordset(missed)}::jsonb)
           AS c(id uuid, generation int, work_item_id int)
     WHERE ${STATE_FENCE} AND ${unmoved}
    RETURNING l.state`);
  pass.outcome.missing += marked.rows.filter((r) => r.state === 'missing').length;
}

/** Rows whose state could not be read in this pass: checked now, so the next ones go first. */
async function skipStates(pass: Pass, batch: readonly StateRow[]): Promise<void> {
  await pass.ctx.deps.db.execute(sql`
    UPDATE boards_links l SET state_checked_at = now(), updated_at = now()
      FROM jsonb_to_recordset(${recordset(batch.map(stateFenceOf))}::jsonb)
           AS c(id uuid, generation int, work_item_id int)
     WHERE ${STATE_FENCE} AND ${boardsConnectionUnmoved(pass.ctx.connection)}`);
}

/**
 * One batch read without the descriptions. An unreadable answer is halved and each half read once
 * more, down to a single id, which is skipped for this pass; a refused batch is skipped whole.
 * Either way the step never stalls on a few work items. Each read counts against `reads`; rows not
 * read keep their place for the next pass.
 */
async function readBatch(
  pass: Pass,
  batch: readonly StateRow[],
  reads: { left: number },
): Promise<void> {
  if (reads.left <= 0 || pass.outcome.stop !== null) return;
  reads.left -= 1;
  let items: AzureWorkItem[];
  try {
    items = await pass.ctx.client.workItemsBatch(
      batch.map((r) => r.workItemId),
      { description: false },
    );
  } catch (err) {
    if (isBadAnswer(err) && batch.length > 1) {
      const half = Math.ceil(batch.length / 2);
      await readBatch(pass, batch.slice(0, half), reads);
      await readBatch(pass, batch.slice(half), reads);
    } else if (isBadAnswer(err) || refusedByAzure(err)) {
      await skipStates(pass, batch);
    } else {
      await failed(pass, err);
    }
    return;
  }
  await writeStates(pass, batch, items);
}

/**
 * Design §7.8 states: the `created` rows, oldest read first (never read first of all), at most
 * 5 000 per pass in batches of 200 on the organisation route (it reads moved work items). Each
 * batch is written as it is read, fenced on the row's id, generation and work item id, so a stop
 * keeps what was read. A moved work item keeps its id and its new state is stored; an id missing
 * from two passes in a row makes the link `missing`.
 */
async function readStates(pass: Pass): Promise<void> {
  const rows = await pass.ctx.deps.db
    .select({
      id: boardsLinks.id,
      generation: boardsLinks.generation,
      workItemId: boardsLinks.workItemId,
      azureProjectId: boardsLinks.azureProjectId,
    })
    .from(boardsLinks)
    .where(
      and(
        eq(boardsLinks.connectionId, pass.ctx.connection.id),
        eq(boardsLinks.state, 'created'),
        isNotNull(boardsLinks.workItemId),
        boardsConnectionUnmoved(pass.ctx.connection),
      ),
    )
    .orderBy(sql`${boardsLinks.stateCheckedAt} ASC NULLS FIRST`, asc(boardsLinks.id))
    .limit(STATE_PER_PASS);
  const readable = rows.filter((r): r is StateRow => r.workItemId !== null);
  if (readable.length === 0) return;
  const batches = Math.ceil(readable.length / MAX_WORK_ITEM_BATCH);
  if (!fits(pass, Math.min(batches, PASS_BUDGET.states) + typeListsLeft(pass))) return;
  const reads = { left: PASS_BUDGET.states };
  for (let i = 0; i < readable.length; i += MAX_WORK_ITEM_BATCH) {
    if (pass.outcome.stop !== null || reads.left <= 0) return;
    await readBatch(pass, readable.slice(i, i + MAX_WORK_ITEM_BATCH), reads);
  }
}

// ─── Notes: fixed and found again ───────────────────────────────────────────────────────────────

type CreatedRow = Pick<
  BoardsLinkRow,
  | 'id'
  | 'generation'
  | 'projectId'
  | 'azureProjectId'
  | 'kind'
  | 'issueId'
  | 'packageName'
  | 'vulnerabilityId'
  | 'workItemId'
  | 'reportedFixedAt'
>;

/** Whether a link's finding is gone, and where a present pair is found now. */
interface Judgement {
  gone: boolean;
  places: string[];
}

interface DueNote {
  row: CreatedRow & { workItemId: number };
  fixed: boolean;
  html: string;
}

/** The `created` rows of the connection, oldest first. */
function createdRows(ctx: BoardsRunContext): Promise<CreatedRow[]> {
  return ctx.deps.db
    .select({
      id: boardsLinks.id,
      generation: boardsLinks.generation,
      projectId: boardsLinks.projectId,
      azureProjectId: boardsLinks.azureProjectId,
      kind: boardsLinks.kind,
      issueId: boardsLinks.issueId,
      packageName: boardsLinks.packageName,
      vulnerabilityId: boardsLinks.vulnerabilityId,
      workItemId: boardsLinks.workItemId,
      reportedFixedAt: boardsLinks.reportedFixedAt,
    })
    .from(boardsLinks)
    .where(
      and(
        eq(boardsLinks.connectionId, ctx.connection.id),
        eq(boardsLinks.state, 'created'),
        isNotNull(boardsLinks.workItemId),
        boardsConnectionUnmoved(ctx.connection),
      ),
    )
    .orderBy(asc(boardsLinks.createdAt), asc(boardsLinks.id));
}

const pairOf = (r: CreatedRow) => ({
  packageName: r.packageName ?? '',
  vulnerabilityId: r.vulnerabilityId ?? '',
});

/**
 * Jira's judgement (jira/sync.ts): a code issue is gone once `closed`; a pair is gone when no
 * tracked target or tracked branch holds it, judged per project with one presence query; a
 * project with monitoring off (no scope) is not judged at all. Returns the scopes too.
 */
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
  const byProject = new Map<string, CreatedRow[]>();
  for (const r of rows) {
    if (r.kind !== 'vulnerability') continue;
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
  return { judged, scopes };
}

/** What the notes of the due rows say beyond the link row: names, days, tracked targets. */
interface NoteSources {
  code: Map<string, CodeIssueFacts>;
  projectNames: Map<string, string>;
  /** The tracked targets' names of each project with a fixed vulnerability note due. */
  tracked: Map<string, string[]>;
}

async function noteSources(
  db: Db,
  due: readonly { row: CreatedRow; judgement: Judgement }[],
  scopes: ReadonlyMap<string, PresenceScope | null>,
): Promise<NoteSources> {
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
      (await targetRefsOf(db, projectId, targets.map(targetId))).map((t) => t.name),
    );
  }
  return { code, projectNames: new Map(named.map((p) => [p.id, p.name])), tracked };
}

/**
 * Jira's comment facts (ruling P4, R20): a code issue's fixed day is its `closed_at`, its
 * found-again day its last analysis's; a vulnerability's is the pass's. A fixed vulnerability is
 * no longer on the tracked targets, a found-again one is where it is now.
 */
function noteFacts(
  pass: Pass,
  d: { row: CreatedRow; judgement: Judgement },
  sources: NoteSources,
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
 * gone and not reported fixed gets the fixed note; one reported fixed whose finding is present
 * again the found-again note. Vulnerability links of a project with monitoring off are not judged.
 */
async function dueNotes(pass: Pass): Promise<DueNote[]> {
  const { db } = pass.ctx.deps;
  const rows = await createdRows(pass.ctx);
  const { judged, scopes } = await judge(db, rows);
  const due = rows
    .flatMap((row) => {
      const judgement = judged.get(row.id);
      if (judgement === undefined || judgement.gone === (row.reportedFixedAt !== null)) return [];
      return [{ row, judgement }];
    })
    .slice(0, NOTES_PER_PASS);
  const sources = await noteSources(db, due, scopes);
  return due.flatMap((d) => {
    const facts = noteFacts(pass, d, sources);
    const { workItemId } = d.row;
    if (facts === null || workItemId === null) return [];
    const fixed = d.judgement.gone;
    return [
      {
        row: { ...d.row, workItemId },
        fixed,
        html: fixed ? fixedNote(facts) : foundAgainNote(facts),
      },
    ];
  });
}

/**
 * The transition, written whether Azure DevOps took the note or refused it (Jira's R14: a refused
 * note is not tried again); a refusal is kept as the link's `failure`, a note taken clears it.
 */
async function recordTransition(
  ctx: BoardsRunContext,
  d: DueNote,
  failure: BoardsFailure | null,
): Promise<void> {
  await ctx.deps.db
    .update(boardsLinks)
    .set({ reportedFixedAt: d.fixed ? sql`now()` : null, failure, updatedAt: sql`now()` })
    .where(
      and(
        eq(boardsLinks.id, d.row.id),
        eq(boardsLinks.generation, d.row.generation),
        eq(boardsLinks.state, 'created'),
        eq(boardsLinks.workItemId, d.row.workItemId),
        d.fixed ? isNull(boardsLinks.reportedFixedAt) : isNotNull(boardsLinks.reportedFixedAt),
        boardsConnectionUnmoved(ctx.connection),
      ),
    );
}

/**
 * One note: a plain `System.History` PATCH on the link's own Azure DevOps project, without `test
 * /rev` (a note never races a person's edit; a closed work item takes notes, Part B i). Returns
 * `{ failure: null }` when Azure DevOps took it (an unreadable answer counts: the PATCH was
 * answered, and a second one would add the note twice), the failure when it refused it (400,
 * 403, 404, 413), null when the call failed otherwise (not recorded: tried next pass).
 */
async function postNote(pass: Pass, d: DueNote): Promise<{ failure: BoardsFailure | null } | null> {
  const { client, deps } = pass.ctx;
  try {
    await client.updateWorkItem(d.row.azureProjectId, d.row.workItemId, [
      { op: 'add', path: '/fields/System.History', value: d.html },
    ]);
  } catch (err) {
    const refused = createFailureOf(err);
    if (refused !== null) {
      deps.logger?.warn(
        { linkId: d.row.id, code: refused.code },
        'Azure DevOps refused a note; the transition is recorded without it',
      );
      return { failure: refused };
    }
    if (isBadAnswer(err)) return { failure: null };
    await failed(pass, err);
    return null;
  }
  return { failure: null };
}

/** Design §7.8 notes: the fixed and found-again notes, at most 100 per pass. */
async function notes(pass: Pass): Promise<void> {
  const due = await dueNotes(pass);
  if (due.length === 0 || !fits(pass, due.length)) return;
  for (const d of due) {
    const posted = await postNote(pass, d);
    if (posted !== null) await recordTransition(pass.ctx, d, posted.failure);
    if (posted !== null && posted.failure === null) pass.outcome.notes += 1;
    if (pass.outcome.stop !== null) return;
  }
}

// ─── The pass ───────────────────────────────────────────────────────────────────────────────────

/** The probe while a blocking problem is stored, then the steps in order. */
const STEPS: readonly ((pass: Pass) => Promise<void>)[] = [
  probe,
  reconcile,
  create,
  automaticRule,
  readStates,
  notes,
];

/**
 * Design §7.8: one pass of an Azure DevOps connection's Boards links. A refused credential at any
 * step records the problem and ends the pass; a transient failure, a 429 or the request budget
 * (checked before each step, {@link PASS_BUDGET}) ends it; a 403 is a link's matter, never the
 * connection's. One info line per pass, with its counts and duration.
 */
export async function runBoardsPass(ctx: BoardsRunContext): Promise<BoardsPassOutcome> {
  const started = Date.now();
  const pass: Pass = {
    ctx,
    outcome: {
      reconciled: 0,
      created: 0,
      auto: 0,
      states: 0,
      missing: 0,
      notes: 0,
      stop: null,
    },
    day: dayOf(new Date(started)),
    types: new Map(),
    unreadableTypes: new Set(),
    names: null,
    projectsListed: false,
    projectListRequests: 0,
  };
  for (const step of STEPS) {
    await step(pass);
    if (pass.outcome.stop !== null) break;
  }
  ctx.deps.logger?.info(
    {
      organizationId: ctx.connection.organizationId,
      connectionId: ctx.connection.id,
      requests: ctx.client.requestCount,
      durationMs: Date.now() - started,
      ...pass.outcome,
    },
    'Azure Boards pass',
  );
  return pass.outcome;
}
