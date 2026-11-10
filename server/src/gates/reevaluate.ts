import { reevaluateGate, type GateResult } from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { analysisDto } from '../analyses/dto';
import { uuidList } from '../db/bulk';
import type { Db, Executor, Tx } from '../db/client';
import { LOCKS } from '../db/locks';
import { analyses, branches, jobs, measures, projects, scmConnections } from '../db/schema';
import { analysisConcurrencyKey } from '../ingest/service';
import type { MeasureValues } from '../ingest/state';
import { issueMeasures } from '../measures/compute';
import { resolvedIssueCounts, visibleIssueCounts } from '../measures/store';
import type { NotifyDeps } from '../notifications/deps';
import { notifyGateChangeSafely } from '../notifications/gate';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { readScmContext } from '../scm/context';
import { enqueueDecoration } from '../scm/queue';
import { createDeliveries, type NewDelivery } from '../webhooks/deliveries';
import { chatGateDeliveries } from '../webhooks/chat/gate';
import { subscriptionsToNotify } from '../webhooks/stage';

/** scm.md §7: re-evaluations run on their own queue, in the analysis worker. */
export const GATE_QUEUE = 'gate';

const payloadSchema = z.object({
  branchId: z.uuid(),
  /** Ruling G5: a changed issue may have a Qualor thread, so decorate even if the gate holds. */
  redecorate: z.literal(true).optional(),
});

type Logger = Pick<FastifyBaseLogger, 'info' | 'warn'>;

/**
 * scm.md §7: one re-evaluation job per branch of the given issues, in the caller's transaction
 * (a transition or a severity override), keyed like ingestion (`analysis:project:<id>`, ruling R3)
 * so it never runs beside an ingestion of the project.
 *
 * Coalesced: a branch that already has one queued gets no second one. That job is locked
 * (`FOR UPDATE`) until the caller commits, so a worker's claim (`FOR UPDATE SKIP LOCKED`) cannot
 * take it and run it without this transaction's change; once claimed (no longer queued), the
 * next transition queues a new one. Transitions of one branch take this step one at a time (an
 * advisory lock per branch, taken in `hashtext` order so two branches whose hashes collide never
 * deadlock), so however often a member toggles its issues, at most one re-evaluation waits per
 * branch.
 *
 * Ruling G5: when a changed issue may have a Qualor inline thread (an issue in new code, with a
 * path and a line, on a merge request branch), the job is marked `redecorate`, so the merge
 * request is decorated again even when the gate result holds and the thread follows the issue.
 */
export async function enqueueReevaluations(
  tx: Executor,
  issueIds: readonly string[],
): Promise<void> {
  if (issueIds.length === 0) return;
  const result = await tx.execute<{
    branch_id: string;
    project_id: string;
    may_have_thread: boolean;
  }>(sql`
    SELECT i.branch_id, i.project_id,
           bool_or(b.kind = 'merge_request' AND i.kind = 'issue' AND i.in_new_code
                   AND i.path IS NOT NULL AND i.start_line IS NOT NULL
                   AND i.duplicate_of_issue_id IS NULL) AS may_have_thread
      FROM issues i JOIN branches b ON b.id = i.branch_id
     WHERE i.id IN ${uuidList([...issueIds])}
     GROUP BY i.branch_id, i.project_id
     ORDER BY hashtext(i.branch_id::text), i.branch_id`);
  for (const row of result.rows) {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(${LOCKS.gateReevaluation}, hashtext(${row.branch_id}))`,
    );
    const [queued] = await tx
      .select({ id: jobs.id, payload: jobs.payload })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, GATE_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'branchId' = ${row.branch_id}`,
        ),
      )
      .limit(1)
      .for('update');
    if (queued) {
      const redecorate = (queued.payload as { redecorate?: unknown } | null)?.redecorate === true;
      if (row.may_have_thread && !redecorate) {
        await tx
          .update(jobs)
          .set({ payload: sql`${jobs.payload} || '{"redecorate":true}'::jsonb` })
          .where(eq(jobs.id, queued.id));
      }
      continue;
    }
    await enqueue(tx, {
      queue: GATE_QUEUE,
      payload: { branchId: row.branch_id, ...(row.may_have_thread ? { redecorate: true } : {}) },
      concurrencyKey: analysisConcurrencyKey(row.project_id),
    });
  }
}

/** The stored measures of an analysis, keyed like gate metrics (`coverage`, `new_coverage`). */
async function storedMeasures(tx: Executor, analysisId: string): Promise<MeasureValues> {
  const rows = await tx
    .select({ key: measures.metricKey, scope: measures.scope, value: measures.value })
    .from(measures)
    .where(eq(measures.analysisId, analysisId));
  return Object.fromEntries(rows.map((r) => [r.scope === 'new' ? `new_${r.key}` : r.key, r.value]));
}

function sameResult(a: GateResult, b: GateResult): boolean {
  return (
    a.status === b.status &&
    a.conditions.length === b.conditions.length &&
    a.conditions.every(
      (c, i) => c.value === b.conditions[i]?.value && c.status === b.conditions[i]?.status,
    )
  );
}

export type ReevaluationResult = 'nothing' | 'unchanged' | 'measures' | 'gate' | 'status';

type BranchRow = typeof branches.$inferSelect;
type AnalysisRow = typeof analyses.$inferSelect;
type ProjectRow = typeof projects.$inferSelect;

/** What a re-evaluation reads and judges again. */
interface Reevaluable {
  branch: BranchRow;
  analysis: AnalysisRow;
  project: ProjectRow;
  previous: GateResult;
}

/** The branch's latest analysis, when it succeeded and holds a gate result to judge again. */
async function reevaluable(tx: Tx, branchId: string): Promise<Reevaluable | null> {
  const [row] = await tx
    .select({ branch: branches, analysis: analyses, project: projects })
    .from(branches)
    .innerJoin(analyses, eq(analyses.id, branches.lastAnalysisId))
    .innerJoin(projects, eq(projects.id, branches.projectId))
    .where(eq(branches.id, branchId));
  if (!row || row.analysis.status !== 'succeeded') return null;
  const previous = row.analysis.gateResult as GateResult | null;
  if (!previous || typeof previous !== 'object' || !Array.isArray(previous.conditions)) {
    return null;
  }
  return { ...row, previous };
}

/** Writes the recomputed measures (keyed like gate metrics) over the analysis's stored ones. */
async function updateMeasures(
  tx: Tx,
  analysisId: string,
  changed: readonly [string, number | null][],
): Promise<void> {
  for (const [key, value] of changed) {
    const isNew = key.startsWith('new_');
    await tx
      .update(measures)
      .set({ value })
      .where(
        and(
          eq(measures.analysisId, analysisId),
          eq(measures.metricKey, isNew ? key.slice(4) : key),
          eq(measures.scope, isNew ? 'new' : 'overall'),
        ),
      );
  }
}

/**
 * A changed gate status: `gate.status_changed` deliveries for the generic and the chat webhooks,
 * and the mail to the branch's watchers (E3), in the caller's transaction.
 */
async function recordStatusChange(
  tx: Tx,
  change: Reevaluable & { next: GateResult; stored: MeasureValues; fresh: MeasureValues },
  notify: NotifyDeps | null,
  logger: Logger | undefined,
): Promise<void> {
  const { branch, analysis, project, previous, next, stored, fresh } = change;
  const subscriptions = await subscriptionsToNotify(tx, project);
  const payload = {
    ...analysisDto({ ...analysis, gateStatus: next.status, gateResult: next }, branch),
    project: { id: project.id, key: project.key, name: project.name },
    branch: { id: branch.id, kind: branch.kind, name: branch.name, isMain: branch.isMain },
    previousGateStatus: previous.status,
  };
  await createDeliveries(tx, [
    ...subscriptions
      .filter((s) => s.kind === 'generic' && s.events.includes('gate.status_changed'))
      .map((s): NewDelivery => ({
        subscriptionId: s.id,
        event: 'gate.status_changed',
        payload,
      })),
    // 6G: the same transition for Slack and Teams webhooks, main branch only.
    ...chatGateDeliveries(subscriptions, {
      project: { id: project.id, key: project.key, name: project.name },
      branch: { id: branch.id, name: branch.name, isMain: branch.isMain },
      analysisId: analysis.id,
      revision: analysis.revision,
      at: new Date(),
      previous: previous.status,
      next,
      measures: { ...stored, ...fresh },
      cause: 'reevaluation',
    }),
  ]);
  // mail E3: the same change mailed to the branch's watchers, in this transaction.
  await notifyGateChangeSafely(
    tx,
    notify,
    {
      project,
      branch,
      analysis: { id: analysis.id, revision: analysis.revision },
      previous: previous.status,
      next,
      measures: { ...stored, ...fresh },
      cause: 'reevaluation',
    },
    logger,
  );
}

/** Why an analysis whose stored SCM context cannot be read is not decorated again, per provider. */
const UNREADABLE_CONTEXT: Record<'missing' | 'invalid', Record<'gitlab' | 'github', string>> = {
  missing: {
    gitlab:
      'quality gate re-evaluated but not decorated again on GitLab: the analysis has no stored SCM context (ingested before it was recorded), so whether it came from GitLab CI is unknown',
    github:
      'quality gate re-evaluated but not decorated again on GitHub: the analysis has no stored SCM context (ingested before it was recorded), so whether it came from GitHub Actions is unknown',
  },
  invalid: {
    gitlab:
      'quality gate re-evaluated but not decorated again on GitLab: the stored SCM context of the analysis is not valid',
    github:
      'quality gate re-evaluated but not decorated again on GitHub: the stored SCM context of the analysis is not valid',
  },
};

/**
 * Decorates the merge request again, only for a project mapped to an SCM connection and an
 * analysis whose stored SCM context says it came from that provider's CI (see `reevaluateBranch`).
 */
async function decorateAgain(
  tx: Tx,
  { project, analysis, branch }: Reevaluable,
  logger: Logger | undefined,
): Promise<void> {
  if (project.scmConnectionId === null || project.scmProjectRef === null) return;
  const [connection] = await tx
    .select({ provider: scmConnections.provider })
    .from(scmConnections)
    .where(eq(scmConnections.id, project.scmConnectionId));
  const stored = readScmContext(analysis.scmContext);
  const where = { analysisId: analysis.id, branchId: branch.id };
  // No connection: nothing to decorate.
  if (!connection) return;
  if (stored.kind !== 'ok') {
    logger?.warn(where, UNREADABLE_CONTEXT[stored.kind][connection.provider]);
    return;
  }
  // github.md §5.1: an analysis decorates only through a connection of its own provider.
  if (stored.context.provider !== connection.provider) return;
  if (stored.context.provider === 'gitlab') {
    await enqueueDecoration(tx, {
      analysisId: analysis.id,
      branchId: branch.id,
      gitlab: stored.context.gitlab,
      reevaluation: true,
    });
    return;
  }
  // Stored only when the report had one (D2): an older CLI's GitHub analysis has none.
  const github = stored.context.github ?? null;
  if (github === null) {
    // Ruling C1: without the GitHub context, which revision was checked out (and so which
    // lines a review thread may be on) is unknown; fail closed.
    logger?.warn(
      where,
      'quality gate re-evaluated but not decorated again on GitHub: the analysis has no stored GitHub Actions context (sent by an older CLI)',
    );
    return;
  }
  await enqueueDecoration(tx, {
    analysisId: analysis.id,
    branchId: branch.id,
    gitlab: null,
    github,
    reevaluation: true,
  });
}

/** What a re-evaluation changed: the status over the gate result over the measures alone. */
function reevaluationResult(
  measuresChanged: boolean,
  gateChanged: boolean,
  statusChanged: boolean,
): ReevaluationResult {
  if (!measuresChanged && !gateChanged) return 'unchanged';
  if (statusChanged) return 'status';
  return gateChanged ? 'gate' : 'measures';
}

/**
 * scm.md §7: the branch's latest analysis, with its issue measures recomputed from the branch's
 * current issues and its stored gate result judged again. Writes only what changed; a changed
 * status records `gate.status_changed` deliveries. A changed gate result, or `redecorate` (ruling
 * G5: a changed issue may have an inline thread), decorates the merge request again, only for a
 * project mapped to an SCM connection and an analysis whose stored SCM context
 * (`analyses.scm_context`, D2) says it came from that provider's CI (github.md §8): a local
 * scan never decorates, and an analysis without a readable context (one ingested before the
 * column existed, an invalid one, or a GitHub one without its `github` context) is not decorated
 * again (fail closed, logged, each case with its own message). Idempotent: a second run finds
 * nothing to change.
 */
export async function reevaluateBranch(
  db: Db,
  branchId: string,
  options: {
    logger?: Logger | undefined;
    redecorate?: boolean;
    notify?: NotifyDeps | undefined;
  } = {},
): Promise<ReevaluationResult> {
  const { logger } = options;
  return db.transaction(async (tx) => {
    const state = await reevaluable(tx, branchId);
    if (!state) return 'nothing';
    const { branch, analysis, previous } = state;

    const stored = await storedMeasures(tx, analysis.id);
    const { accepted, falsePositives } = await resolvedIssueCounts(tx, branch.id);
    const fresh = issueMeasures(
      await visibleIssueCounts(tx, branch.id),
      accepted,
      falsePositives,
      analysis.baselineStatus === 'unavailable',
    );
    const changed = Object.entries(fresh).filter(([key, value]) => stored[key] !== value);
    await updateMeasures(tx, analysis.id, changed);
    const next = reevaluateGate(previous, { ...stored, ...fresh });
    const gateChanged = !sameResult(previous, next);
    if (gateChanged) {
      await tx
        .update(analyses)
        .set({ gateStatus: next.status, gateResult: next, updatedAt: sql`now()` })
        .where(eq(analyses.id, analysis.id));
    }
    const statusChanged = previous.status !== next.status;
    if (statusChanged) {
      await recordStatusChange(
        tx,
        { ...state, next, stored, fresh },
        options.notify ?? null,
        logger,
      );
    }
    // A changed verdict moves the commit status and the summary; a changed issue that may have a
    // thread (G5, `redecorate`) moves its thread, whatever the gate says. Anything else is not
    // worth SCM requests.
    if (gateChanged || options.redecorate === true) {
      await decorateAgain(tx, state, logger);
    }
    return reevaluationResult(changed.length > 0, gateChanged, statusChanged);
  });
}

/** The `gate` queue's handler (scm.md §7); main.ts runs it in the analysis worker. */
export function gateHandlers(deps: {
  db: Db;
  logger?: Logger | undefined;
  notify?: NotifyDeps | undefined;
}): JobHandlers {
  return {
    [GATE_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed re-evaluation job payload; completing');
        return;
      }
      const result = await reevaluateBranch(deps.db, parsed.data.branchId, {
        logger: deps.logger,
        redecorate: parsed.data.redecorate === true,
        notify: deps.notify,
      });
      if (result !== 'nothing' && result !== 'unchanged') {
        deps.logger?.info({ branchId: parsed.data.branchId, result }, 'quality gate re-evaluated');
      }
    },
  };
}
