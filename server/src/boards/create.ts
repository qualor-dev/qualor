import { and, eq, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Db } from '../db/client';
import {
  BOARDS_STATE_CATEGORIES,
  boardsLinks,
  projectBoardsSettings,
  scmConnections,
  type BoardsStateCategory,
} from '../db/schema';
import type { VulnerabilityFacts } from '../jira/content';
import { followUpDelay, recordset } from '../jira/create';
import { codeIssueFacts, vulnerabilityFacts, type CodeIssueRecord } from '../jira/facts';
import { cutText } from '../jira/markup';
import { pairKey, type VulnerabilityPair } from '../jira/presence';
import { AzureError, type AzureJsonPatch, type AzureWorkItemType } from '../scm/azure/client';
import { problemCode } from '../scm/azure/connections';
import type { ScmConnectionRow } from '../scm/connections';
import { ScmError } from '../scm/provider';
import { recordScmProblem, type ScmBackgroundProblemCode } from '../scm/problems';
import { compare } from '../vulnerabilities/order';
import {
  codeIssueWorkItem,
  reconciliationKey,
  vulnerabilityWorkItem,
  workItemOps,
  type WorkItemContent,
} from './content';
import { enqueueBoardsCreate } from './jobs';
import { BOARDS_BLOCKING_CODES, isBoardsBlockingProblem, type BoardsLinkRow } from './links';
import { analyzeWorkItemType, AZURE_WORDS_MAX, type BoardsMappingRow } from './mapping';
import type { BoardsRunContext } from './run';

/*
 * Azure DevOps design §7.8: the Jira create step (jira/create.ts) for Azure Boards. Azure DevOps
 * has no bulk create, so each row is one POST of its own; the claim, the release, the fences, the
 * stops and the follow-up are Jira's.
 */

/**
 * The never-attempted pending rows one run takes at most: one create request each, plus one type
 * list per Azure DevOps project, well within a client's 400 requests. A full run queues the next.
 */
export const CREATE_PER_RUN = 100;
/** Rows claimed and prepared together; each is still checked just before its own create. */
const CLAIM_CHUNK = 20;
/** A 429 without a `Retry-After` is tried again after this long. */
const RATE_LIMITED_WAIT_SECONDS = 60;
/** The `typeKey` of a create for a type the project no longer has (Part B d). */
const TYPE_NOT_FOUND = 'WorkItemTypeNotFoundException';

/** Why a link failed, as a stable code the UI turns into its own words. */
export type BoardsFailureCode =
  | 'field_refused'
  | 'permission_missing'
  | 'not_found'
  | 'limit_reached'
  | 'not_mapped'
  | 'finding_gone'
  | 'outcome_unknown'
  | 'type_unsupported'
  | 'note_refused';

/**
 * The fixed texts of the failures. `field_refused` has none: it carries Azure DevOps' own words
 * (cut to 500 characters), the one place they are stored, or an empty message when the refusal had
 * none, so a reader tells the two apart by structure, never by wording.
 */
export const BOARDS_FAILURE_TEXT: Record<Exclude<BoardsFailureCode, 'field_refused'>, string> = {
  permission_missing:
    'The identity of the Azure DevOps connection may not create work items in this project or area (HTTP 403).',
  not_found:
    'Azure DevOps answered that the project does not exist or the identity cannot see it (HTTP 404). Map the project again.',
  limit_reached: 'Azure DevOps refused the work item as too large or over one of its limits.',
  not_mapped: 'The project is not mapped to Azure Boards any more. Map it, then retry.',
  finding_gone: 'The finding is closed or can no longer have a work item.',
  outcome_unknown:
    'Azure DevOps did not answer the create, and Qualor could not find out whether the work item was made. It may exist in Azure Boards: check before you retry.',
  type_unsupported:
    'The mapped work item type no longer exists or needs fields Qualor does not set: map the project again',
  note_refused: "Azure DevOps refused Qualor's note on this work item.",
};

/** Why a run stopped before its rows ran out, if it did. */
export type BoardsStop = null | 'credential' | 'transient' | 'rate_limited' | 'budget';

export interface BoardsCreateOutcome {
  /** Rows that got their work item (a row dismissed meanwhile keeps the id). */
  created: number;
  failed: number;
  /** Rows sent without an answer: pending with `attempted_at`, for the pass to reconcile. */
  unanswered: number;
  stop: BoardsStop;
}

/** The type lists of a run (or a pass), by Azure DevOps project id: read once each. */
export type WorkItemTypeCache = Map<string, AzureWorkItemType[]>;

/**
 * A failure a row records: its code, and its text (for `field_refused`, Azure's words, empty when
 * it gave none).
 */
export interface BoardsFailure {
  code: BoardsFailureCode;
  message: string;
}

interface Failed extends BoardsFailure {
  row: BoardsLinkRow;
}

interface Created {
  row: BoardsLinkRow;
  workItemId: number;
  stateName: string | null;
  stateCategory: BoardsStateCategory | null;
}

/** A row ready to send: the type it resolved to and the create's JSON Patch. */
interface Ready {
  row: BoardsLinkRow;
  type: AzureWorkItemType;
  ops: AzureJsonPatch[];
}

const fixed = (code: Exclude<BoardsFailureCode, 'field_refused'>): BoardsFailure => ({
  code,
  message: BOARDS_FAILURE_TEXT[code],
});

/**
 * The connection row still has the address of the run's client. A connection moved to another
 * organisation keeps its id, so a run that outlived the move claims, reads and writes none of its
 * rows (Jira's M1); a deleted connection takes its rows with it.
 */
export function boardsConnectionUnmoved(connection: Pick<ScmConnectionRow, 'id' | 'baseUrl'>): SQL {
  return sql`EXISTS (
    SELECT 1 FROM scm_connections sc
     WHERE sc.id = ${connection.id} AND sc.base_url = ${connection.baseUrl})`;
}

const BLOCKING: ReadonlySet<string> = new Set(BOARDS_BLOCKING_CODES);

/** The category of a state of the type (`InProgress` → `inprogress`); null for one it lacks. */
export function stateCategoryOf(
  type: Pick<AzureWorkItemType, 'states'> | undefined,
  name: string | null,
): BoardsStateCategory | null {
  if (type === undefined || name === null) return null;
  const wanted = name.toLowerCase();
  const category = type.states.find((s) => s.name.toLowerCase() === wanted)?.category;
  const lower = category?.toLowerCase() ?? '';
  return (BOARDS_STATE_CATEGORIES as readonly string[]).includes(lower)
    ? (lower as BoardsStateCategory)
    : null;
}

/**
 * The failure a refused create records on its row, or null when `err` is not a refusal of the
 * row: 400 and the other refusals (the long-text 500 included) → `field_refused` with Azure's
 * words, or an empty message without any; 403 → `permission_missing`; 404 → `type_unsupported` for a type the project no longer
 * has, else `not_found`; 413 → `limit_reached`; a type name the client refuses to send →
 * `type_unsupported`.
 */
export function createFailureOf(err: unknown): BoardsFailure | null {
  if (!(err instanceof AzureError)) return null;
  switch (err.kind) {
    case 'auth':
      return err.reason === 'permission_missing' ? fixed('permission_missing') : null;
    case 'not_found':
      return fixed(err.azureTypeKey === TYPE_NOT_FOUND ? 'type_unsupported' : 'not_found');
    case 'refused':
      if (err.reason === 'invalid_input') return fixed('type_unsupported');
      if (err.reason !== 'http') return null;
      if (err.status === 413) return fixed('limit_reached');
      return {
        code: 'field_refused',
        message: err.azureMessage?.trim() ? cutText(err.azureMessage, AZURE_WORDS_MAX) : '',
      };
    default:
      return null;
  }
}

async function connectionUnmoved(ctx: BoardsRunContext): Promise<boolean> {
  const found = await ctx.deps.db.execute<{ unmoved: boolean }>(
    sql`SELECT ${boardsConnectionUnmoved(ctx.connection)} AS unmoved`,
  );
  return found.rows[0]?.unmoved === true;
}

/**
 * Records `code` as the connection's problem (Ruling 5: the slot decoration shares) while the
 * connection still has `connection`'s address: checked and written under the connection row's
 * lock, so an address move cannot slip in between. Whether the address still held.
 */
export function recordUnmovedProblem(
  db: Db,
  connection: Pick<ScmConnectionRow, 'id' | 'baseUrl'>,
  code: ScmBackgroundProblemCode,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [held] = await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(eq(scmConnections.id, connection.id), eq(scmConnections.baseUrl, connection.baseUrl)),
      )
      .for('no key update');
    if (!held) return false;
    await recordScmProblem(tx, connection.id, code);
    return true;
  });
}

/** {@link recordUnmovedProblem} for the run's connection; the run's view follows. */
async function recordProblem(ctx: BoardsRunContext, code: ScmBackgroundProblemCode): Promise<void> {
  const written = await recordUnmovedProblem(ctx.deps.db, ctx.connection, code);
  if (written && ctx.connection.problem?.code !== code) {
    ctx.connection.problem = { code, at: new Date().toISOString() };
  }
}

/**
 * What a failed Azure DevOps call means for a run: 429 and the request budget stop it; a refused
 * credential ({@link BOARDS_BLOCKING_CODES}: 401, a sign-in answer, Microsoft Entra refusing the
 * principal) is recorded on the connection and stops it; a transient failure (timeout, no answer, a
 * 5xx) or an address the policy refuses stops it and records nothing (it passes by itself). A 403,
 * a bad answer or a 404 stops nothing: a 403 is never written to the connection, since it may
 * concern one area or one right only (the step fails the link `permission_missing`).
 */
export async function stopFor(ctx: BoardsRunContext, err: ScmError): Promise<BoardsStop> {
  if (err.kind === 'rate_limited') return 'rate_limited';
  if (err.kind === 'budget') return 'budget';
  const code = problemCode(err);
  if (BLOCKING.has(code)) {
    await recordProblem(ctx, code as ScmBackgroundProblemCode);
    return 'credential';
  }
  if (err.kind === 'auth' && err.reason === 'permission_missing') return null;
  if (err.kind === 'transient' || err.kind === 'refused' || err.kind === 'auth') return 'transient';
  return null;
}

/**
 * `attempted_at` as a run stamps it: to the millisecond, so the `Date` a row carries back holds the
 * stamp exactly and every later write of the run can be conditional on it.
 */
const STAMP = sql`date_trunc('milliseconds', now())`;

/**
 * A row's claim as the run's writes check it: `(id, generation)` and the `attempted_at` the run
 * stamped. A row whose stamp changed since (the pass's reconcile reset it, another run claimed
 * it) is no longer this run's: nothing of this run is written to it.
 */
const claimOf = (row: BoardsLinkRow) => ({
  id: row.id,
  generation: row.generation,
  stamp: row.attemptedAt?.toISOString() ?? null,
});

/**
 * Up to `n` of the connection's never-attempted pending rows, oldest first, stamped with
 * `attempted_at` ({@link STAMP}) in one short transaction that commits before any call.
 * `SKIP LOCKED` and the condition on `attempted_at` let a create job and a pass of the connection
 * never take one row twice; none once the connection is gone or has another address. As Jira's
 * ruling T8a, the ids are picked first (`LIMIT n … FOR UPDATE SKIP LOCKED`), then exactly those
 * rows are updated.
 */
export async function claimPendingLinks(
  ctx: BoardsRunContext,
  n: number,
): Promise<BoardsLinkRow[]> {
  const rows = await ctx.deps.db.transaction(async (tx) => {
    const picked = await tx
      .select({ id: boardsLinks.id })
      .from(boardsLinks)
      .where(
        and(
          eq(boardsLinks.connectionId, ctx.connection.id),
          eq(boardsLinks.state, 'pending'),
          isNull(boardsLinks.attemptedAt),
          boardsConnectionUnmoved(ctx.connection),
        ),
      )
      .orderBy(boardsLinks.createdAt, boardsLinks.id)
      .limit(n)
      .for('update', { skipLocked: true });
    if (picked.length === 0) return [];
    return tx
      .update(boardsLinks)
      .set({ attemptedAt: STAMP, updatedAt: sql`now()` })
      .where(
        inArray(
          boardsLinks.id,
          picked.map((p) => p.id),
        ),
      )
      .returning();
  });
  return rows.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || compare(a.id, b.id));
}

/**
 * Rows whose create never reached Azure DevOps: never attempted again, so the next run sends them.
 * Only rows still holding the stamp each carries ({@link claimOf}): a row another run claimed since
 * stays that run's.
 */
export async function releaseLinks(
  ctx: BoardsRunContext,
  rows: readonly BoardsLinkRow[],
): Promise<void> {
  if (rows.length === 0) return;
  await ctx.deps.db.execute(sql`
    UPDATE boards_links l SET attempted_at = NULL, updated_at = now()
      FROM jsonb_to_recordset(${recordset(rows.map(claimOf))}::jsonb)
           AS c(id uuid, generation int, stamp timestamptz)
     WHERE l.id = c.id AND l.generation = c.generation AND l.attempted_at = c.stamp
       AND l.state = 'pending' AND ${boardsConnectionUnmoved(ctx.connection)}`);
}

const MAKES_CREATED = `l.state = 'pending' OR (l.state = 'failed' AND l.failure ->> 'code' = 'outcome_unknown')`;
/** The rows a created answer makes `created`: pending, or failed `outcome_unknown` by the pass. */
const LATE_CREATED = sql.raw(MAKES_CREATED);
/** The rows a created answer writes at all: those, and a row dismissed in flight (R19). */
const CREATED_WRITABLE = sql.raw(`(l.state = 'dismissed' OR ${MAKES_CREATED})`);

/**
 * Answers, in one short transaction fenced on the row's claim ({@link claimOf}): a row re-armed
 * meanwhile, or reset and claimed by another run, is another create's. A failure is written only
 * to a `pending` row. A created answer makes `created` a `pending` row (or one the pass failed
 * `outcome_unknown` meanwhile), and gives a row dismissed while its create was in flight the work
 * item id Azure DevOps gave (Jira's R19); it never touches a `created` or `missing` row. Nothing is
 * written once the connection is gone or has another address.
 */
async function record(
  ctx: BoardsRunContext,
  created: readonly Created[],
  failed: readonly Failed[],
): Promise<{ created: number; failed: number }> {
  if (created.length === 0 && failed.length === 0) return { created: 0, failed: 0 };
  const unmoved = boardsConnectionUnmoved(ctx.connection);
  return ctx.deps.db.transaction(async (tx) => {
    let made = 0;
    let refused = 0;
    if (created.length > 0) {
      const json = recordset(
        created.map((c) => ({
          ...claimOf(c.row),
          work_item_id: c.workItemId,
          state_name: c.stateName,
          state_category: c.stateCategory,
        })),
      );
      const result = await tx.execute(sql`
        UPDATE boards_links l
           SET state = CASE WHEN ${LATE_CREATED} THEN 'created' ELSE l.state END,
               failure = CASE WHEN ${LATE_CREATED} THEN NULL ELSE l.failure END,
               work_item_id = c.work_item_id, state_name = c.state_name,
               state_category = c.state_category,
               state_checked_at = CASE WHEN c.state_name IS NULL THEN l.state_checked_at ELSE now() END,
               updated_at = now()
          FROM jsonb_to_recordset(${json}::jsonb)
               AS c(id uuid, generation int, stamp timestamptz, work_item_id int, state_name text,
                    state_category text)
         WHERE l.id = c.id AND l.generation = c.generation AND l.attempted_at = c.stamp
           AND ${CREATED_WRITABLE} AND ${unmoved}`);
      made = result.rowCount ?? 0;
    }
    if (failed.length > 0) {
      const json = recordset(
        failed.map((f) => ({ ...claimOf(f.row), code: f.code, message: f.message })),
      );
      const result = await tx.execute(sql`
        UPDATE boards_links l
           SET state = 'failed', failure = jsonb_build_object('code', c.code, 'message', c.message),
               updated_at = now()
          FROM jsonb_to_recordset(${json}::jsonb)
               AS c(id uuid, generation int, stamp timestamptz, code text, message text)
         WHERE l.id = c.id AND l.generation = c.generation AND l.attempted_at = c.stamp
           AND l.state = 'pending' AND ${unmoved}`);
      refused = result.rowCount ?? 0;
    }
    return { created: made, failed: refused };
  });
}

/** The mapping of each project, by project id; a project without one is absent. */
async function mappingsOf(
  db: Db,
  projectIds: readonly string[],
): Promise<Map<string, BoardsMappingRow>> {
  const rows = await db
    .select()
    .from(projectBoardsSettings)
    .where(inArray(projectBoardsSettings.projectId, uuidList([...new Set(projectIds)])));
  return new Map(rows.map((m) => [m.projectId, m]));
}

/** The facts of the rows' findings: code issues by issue id, pairs by project and {@link pairKey}. */
interface Findings {
  code: Map<string, CodeIssueRecord>;
  pairs: Map<string, Map<string, VulnerabilityFacts>>;
}

async function findingsOf(
  db: Db,
  rows: readonly BoardsLinkRow[],
  priority: boolean,
): Promise<Findings> {
  const code = await codeIssueFacts(
    db,
    rows.flatMap((r) => (r.kind === 'issue' && r.issueId !== null ? [r.issueId] : [])),
  );
  const byProject = new Map<string, VulnerabilityPair[]>();
  for (const r of rows) {
    if (r.kind !== 'vulnerability' || r.packageName === null || r.vulnerabilityId === null) {
      continue;
    }
    const list = byProject.get(r.projectId) ?? [];
    list.push({ packageName: r.packageName, vulnerabilityId: r.vulnerabilityId });
    byProject.set(r.projectId, list);
  }
  const pairs = new Map<string, Map<string, VulnerabilityFacts>>();
  for (const [projectId, list] of byProject) {
    pairs.set(projectId, await vulnerabilityFacts(db, projectId, list, { priority }));
  }
  return { code, pairs };
}

/**
 * A row's work item content from its finding's facts, with its reconciliation key; null when
 * there is no finding to send (a closed code issue, Jira's R7; a pair no longer present).
 */
function contentOf(
  row: BoardsLinkRow,
  findings: Findings,
  publicUrl: string | null,
): WorkItemContent | null {
  const key = reconciliationKey(row.id, row.generation);
  if (row.kind === 'issue') {
    const facts = row.issueId === null ? undefined : findings.code.get(row.issueId);
    if (!facts || facts.closed) return null;
    return codeIssueWorkItem(facts, publicUrl, key);
  }
  const facts = findings.pairs
    .get(row.projectId)
    ?.get(pairKey(row.packageName ?? '', row.vulnerabilityId ?? ''));
  return facts ? vulnerabilityWorkItem(facts, publicUrl, key) : null;
}

/**
 * Where the mapping places a work item. The link keeps its own Azure DevOps project; the mapping's
 * area and iteration paths name nodes of the mapping's project, so a link of another project (one
 * retried after a remap) goes to its project's roots.
 */
function placementOf(mapping: BoardsMappingRow, row: BoardsLinkRow) {
  const own = mapping.azureProjectId === row.azureProjectId;
  return {
    tags: mapping.tags,
    areaPath: own ? mapping.areaPath : null,
    iterationPath: own ? mapping.iterationPath : null,
  };
}

/** One create run's state across its chunks. */
interface CreateRun {
  readonly ctx: BoardsRunContext;
  /** `vuln.priority`: the Exploited and EPSS lines. */
  readonly priority: boolean;
  readonly types: WorkItemTypeCache;
  readonly outcome: BoardsCreateOutcome;
  /** The calls Azure DevOps answered (Jira's R18: a run without one queues no follow-up). */
  answered: number;
  /** When the next run goes after a 429. */
  retryAfter: number;
  /** The connection is gone or moved: nothing more is sent. */
  gone: boolean;
  /**
   * Rows nothing was sent for that must not be claimed again in this run (a stop, or their
   * project's type list answered unreadably): released when the run ends.
   */
  readonly held: BoardsLinkRow[];
  /** The Azure DevOps projects whose type list answered unreadably in this run. */
  readonly unreadable: Set<string>;
}

/** Whether a failed call was answered by Azure DevOps (a refusal), not refused before sending. */
const answeredBy = (err: unknown): boolean => err instanceof ScmError && err.status !== null;

/** A failed call's stop ({@link stopFor}); a 429 also sets when the next run goes. */
async function stopOn(run: CreateRun, err: unknown): Promise<BoardsStop> {
  if (!(err instanceof ScmError)) throw err;
  if (err.kind === 'rate_limited') {
    run.retryAfter = err.retryAfterSeconds ?? RATE_LIMITED_WAIT_SECONDS;
  }
  return stopFor(run.ctx, err);
}

/** Plan Ruling 7: the project's type list, read once per run (or pass) and project. */
async function typesOf(run: CreateRun, azureProjectId: string): Promise<AzureWorkItemType[]> {
  const cached = run.types.get(azureProjectId);
  if (cached) return cached;
  const types = await run.ctx.client.workItemTypes(azureProjectId);
  run.answered += 1;
  run.types.set(azureProjectId, types);
  return types;
}

/** What a chunk comes to before any create: rows to send and rows that fail. */
interface Prepared {
  ready: Ready[];
  failed: Failed[];
}

/**
 * The chunk's rows checked against their mapping and finding (no mapping → `not_mapped`; no
 * finding → `finding_gone`), then, per Azure DevOps project, against its type list: the mapped
 * type is found by reference name, so a renamed type keeps working, and a type gone or needing a
 * field Qualor does not set → `type_unsupported`. A type list that fails stops the run or, for an
 * unreadable answer, holds its project's rows until the next run.
 */
async function prepare(run: CreateRun, rows: readonly BoardsLinkRow[]): Promise<Prepared> {
  const { db, publicUrl } = run.ctx.deps;
  const prepared: Prepared = { ready: [], failed: [] };
  const mappings = await mappingsOf(
    db,
    rows.map((r) => r.projectId),
  );
  const findings = await findingsOf(
    db,
    rows.filter((r) => mappings.has(r.projectId)),
    run.priority,
  );
  const byProject = new Map<
    string,
    { row: BoardsLinkRow; mapping: BoardsMappingRow; content: WorkItemContent }[]
  >();
  for (const row of rows) {
    const mapping = mappings.get(row.projectId);
    if (!mapping) {
      prepared.failed.push({ row, ...fixed('not_mapped') });
      continue;
    }
    const content = contentOf(row, findings, publicUrl);
    if (content === null) {
      prepared.failed.push({ row, ...fixed('finding_gone') });
      continue;
    }
    const list = byProject.get(row.azureProjectId) ?? [];
    list.push({ row, mapping, content });
    byProject.set(row.azureProjectId, list);
  }
  for (const [azureProjectId, list] of byProject) {
    if (run.outcome.stop !== null || run.unreadable.has(azureProjectId)) {
      run.held.push(...list.map((c) => c.row));
      continue;
    }
    let types: AzureWorkItemType[];
    try {
      types = await typesOf(run, azureProjectId);
    } catch (err) {
      const refused = createFailureOf(err);
      if (refused !== null) {
        if (answeredBy(err)) run.answered += 1;
        prepared.failed.push(...list.map((c) => ({ row: c.row, ...refused })));
        continue;
      }
      run.outcome.stop = await stopOn(run, err);
      if (run.outcome.stop === null) run.unreadable.add(azureProjectId);
      run.held.push(...list.map((c) => c.row));
      continue;
    }
    for (const c of list) {
      const type = types.find((t) => t.referenceName === c.mapping.workItemTypeRef);
      const support = type === undefined ? null : analyzeWorkItemType(type);
      if (type === undefined || support === null || !support.supported) {
        prepared.failed.push({ row: c.row, ...fixed('type_unsupported') });
        continue;
      }
      const ops = workItemOps(c.content, placementOf(c.mapping, c.row), support.reproSteps);
      prepared.ready.push({ row: c.row, type, ops });
    }
  }
  return prepared;
}

/**
 * The row taken again just before its create, as the run's own: `attempted_at` stamped anew
 * where it still holds this run's stamp, the row is `pending` at its generation and the connection
 * has the run's address. The new stamp restarts the pass's reconcile clock at the call (a row sent
 * minutes after its chunk was claimed is never reset under it). Else the row is skipped: dismissed
 * or re-armed since its claim, or reset by the reconcile and claimed by another run; or the run
 * ends when the connection is gone or moved.
 */
async function retake(
  run: CreateRun,
  row: BoardsLinkRow,
): Promise<BoardsLinkRow | 'skip' | 'gone'> {
  const { ctx } = run;
  if (row.attemptedAt === null) return 'skip';
  const [held] = await ctx.deps.db
    .update(boardsLinks)
    .set({ attemptedAt: STAMP, updatedAt: sql`now()` })
    .where(
      and(
        eq(boardsLinks.id, row.id),
        eq(boardsLinks.generation, row.generation),
        eq(boardsLinks.state, 'pending'),
        eq(boardsLinks.attemptedAt, row.attemptedAt),
        boardsConnectionUnmoved(ctx.connection),
      ),
    )
    .returning({ attemptedAt: boardsLinks.attemptedAt });
  if (held) return { ...row, attemptedAt: held.attemptedAt };
  return (await connectionUnmoved(ctx)) ? 'skip' : 'gone';
}

/**
 * One row's create: `created` with the work item's id, its state and the state's category from
 * the type; a refusal fails the row; any other failure stops the run (the row released when the
 * call never reached Azure DevOps or must not wait, else left with `attempted_at`).
 */
async function send(run: CreateRun, ready: Ready): Promise<void> {
  const { ctx, outcome } = run;
  const row = await retake(run, ready.row);
  if (row === 'gone') {
    run.gone = true;
    return;
  }
  if (row === 'skip') return;
  try {
    const item = await ctx.client.createWorkItem(row.azureProjectId, ready.type.name, ready.ops);
    run.answered += 1;
    const created: Created = {
      row,
      workItemId: item.id,
      stateName: item.state,
      stateCategory: stateCategoryOf(ready.type, item.state),
    };
    outcome.created += (await record(ctx, [created], [])).created;
  } catch (err) {
    const refused = createFailureOf(err);
    if (refused !== null) {
      if (answeredBy(err)) run.answered += 1;
      outcome.failed += (await record(ctx, [], [{ row, ...refused }])).failed;
      return;
    }
    outcome.stop = await stopOn(run, err);
    if (outcome.stop === null || outcome.stop === 'transient') outcome.unanswered += 1;
    else await releaseLinks(ctx, [row]);
  }
}

/**
 * One chunk: its rows prepared, the failures written, then each ready row sent on its own. When a
 * send throws something unexpected, the rows after it go back (never the one in flight, which may
 * have reached Azure DevOps) and the error goes on.
 */
async function createChunk(run: CreateRun, rows: readonly BoardsLinkRow[]): Promise<void> {
  const { ctx, outcome } = run;
  let prepared: Prepared;
  try {
    prepared = await prepare(run, rows);
  } catch (err) {
    // Nothing was sent: the rows go back for the next run.
    await releaseLinks(ctx, rows);
    throw err;
  }
  outcome.failed += (await record(ctx, [], prepared.failed)).failed;
  const after = (i: number) => prepared.ready.slice(i).map((r) => r.row);
  for (const [i, ready] of prepared.ready.entries()) {
    if (outcome.stop !== null || run.gone) {
      await releaseLinks(ctx, after(i));
      return;
    }
    try {
      await send(run, ready);
    } catch (err) {
      await releaseLinks(ctx, after(i + 1));
      throw err;
    }
  }
}

/** Whether the connection still has never-attempted pending rows. */
async function waiting(db: Db, connectionId: string): Promise<boolean> {
  const result = await db.execute<{ waiting: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM boards_links
       WHERE connection_id = ${connectionId} AND state = 'pending' AND attempted_at IS NULL
    ) AS waiting`);
  return result.rows[0]?.waiting === true;
}

/**
 * Design §7.8: the create step. The connection's never-attempted pending rows, oldest first, at
 * most `limit`, each in a create of its own (`POST …/workitems/$<type>`) on the link's own
 * connection and Azure DevOps project; the mapping gives the type (by reference name, resolved by
 * one type list per project, `types` shared with the caller's other steps), the area and
 * iteration paths and the tags. Rows are claimed (`attempted_at` set and committed) before any
 * call and each answer written right after its call: no transaction is open across a request.
 *
 * - Created → `created` with the work item's id, state name and category (from the type's states).
 * - Refused (400 and other refusals with Azure's words, the long-text 500 too; 403; 404; 413) →
 *   `failed` with its code. No mapping → `not_mapped`; no finding → `finding_gone`; the type gone
 *   or unsupported → `type_unsupported`; all unsent.
 * - No answer (timeout, reset, 5xx, an unreadable answer) → `pending` with `attempted_at`: the pass
 *   reconciles it and never resends blindly. A transient failure stops the run, records nothing.
 * - 401 or a sign-in answer → the connection's problem (`recordScmProblem`); the rows are released
 *   and the run stops. While such a problem is set, nothing is sent.
 * - 429 → released, and the create runs again after `Retry-After`; the budget → released.
 *
 * A run that took `limit` rows while more wait, and had an answered call, queues the next create
 * job at once (Jira's `followUpDelay`, R18).
 */
export async function createPendingWorkItems(
  ctx: BoardsRunContext,
  options: { limit?: number; types?: WorkItemTypeCache } = {},
): Promise<BoardsCreateOutcome> {
  const limit = options.limit ?? CREATE_PER_RUN;
  const outcome: BoardsCreateOutcome = { created: 0, failed: 0, unanswered: 0, stop: null };
  if (isBoardsBlockingProblem(ctx.connection.problem)) return { ...outcome, stop: 'credential' };
  const run: CreateRun = {
    ctx,
    priority: ctx.deps.limits().vulnerabilities.priority,
    types: options.types ?? new Map(),
    outcome,
    answered: 0,
    retryAfter: RATE_LIMITED_WAIT_SECONDS,
    gone: false,
    held: [],
    unreadable: new Set(),
  };
  let taken = 0;
  try {
    while (outcome.stop === null && !run.gone && taken < limit) {
      const rows = await claimPendingLinks(ctx, Math.min(CLAIM_CHUNK, limit - taken));
      if (rows.length === 0) break;
      taken += rows.length;
      await createChunk(run, rows);
    }
  } finally {
    await releaseLinks(ctx, run.held);
  }
  const { db } = ctx.deps;
  const again = followUpDelay(outcome.stop, taken >= limit, run.answered > 0, run.retryAfter);
  if (again !== null && (await waiting(db, ctx.connection.id))) {
    await enqueueBoardsCreate(db, ctx.connection.id, again);
  }
  return outcome;
}
