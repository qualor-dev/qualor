import { reevaluateGate, type GateResult } from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { analysisDto } from '../analyses/dto';
import { uuidList } from '../db/bulk';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { analyses, branches, jobs, measures, projects, scmConnections } from '../db/schema';
import { analysisConcurrencyKey } from '../ingest/service';
import type { MeasureValues } from '../ingest/state';
import { issueMeasures } from '../measures/compute';
import { resolvedIssueCounts, visibleIssueCounts } from '../measures/store';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { readScmContext } from '../scm/context';
import { enqueueDecoration } from '../scm/queue';
import { createDeliveries, type NewDelivery } from '../webhooks/deliveries';
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
  options: { logger?: Logger | undefined; redecorate?: boolean } = {},
): Promise<ReevaluationResult> {
  const { logger } = options;
  return db.transaction(async (tx) => {
    const [row] = await tx
      .select({ branch: branches, analysis: analyses, project: projects })
      .from(branches)
      .innerJoin(analyses, eq(analyses.id, branches.lastAnalysisId))
      .innerJoin(projects, eq(projects.id, branches.projectId))
      .where(eq(branches.id, branchId));
    if (!row || row.analysis.status !== 'succeeded') return 'nothing';
    const previous = row.analysis.gateResult as GateResult | null;
    if (!previous || typeof previous !== 'object' || !Array.isArray(previous.conditions)) {
      return 'nothing';
    }
    const { branch, analysis, project } = row;

    const stored = await storedMeasures(tx, analysis.id);
    const { accepted, falsePositives } = await resolvedIssueCounts(tx, branch.id);
    const fresh = issueMeasures(
      await visibleIssueCounts(tx, branch.id),
      accepted,
      falsePositives,
      analysis.baselineStatus === 'unavailable',
    );
    const changed = Object.entries(fresh).filter(([key, value]) => stored[key] !== value);
    for (const [key, value] of changed) {
      const isNew = key.startsWith('new_');
      await tx
        .update(measures)
        .set({ value })
        .where(
          and(
            eq(measures.analysisId, analysis.id),
            eq(measures.metricKey, isNew ? key.slice(4) : key),
            eq(measures.scope, isNew ? 'new' : 'overall'),
          ),
        );
    }
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
      const subscriptions = (await subscriptionsToNotify(tx, project)).filter((s) =>
        s.events.includes('gate.status_changed'),
      );
      const payload = {
        ...analysisDto({ ...analysis, gateStatus: next.status, gateResult: next }, branch),
        project: { id: project.id, key: project.key, name: project.name },
        branch: { id: branch.id, kind: branch.kind, name: branch.name, isMain: branch.isMain },
        previousGateStatus: previous.status,
      };
      await createDeliveries(
        tx,
        subscriptions.map((s): NewDelivery => ({
          subscriptionId: s.id,
          event: 'gate.status_changed',
          payload,
        })),
      );
    }
    // A changed verdict moves the commit status and the summary; a changed issue that may have a
    // thread (G5, `redecorate`) moves its thread, whatever the gate says. Anything else is not
    // worth SCM requests.
    if (
      (gateChanged || options.redecorate === true) &&
      project.scmConnectionId !== null &&
      project.scmProjectRef !== null
    ) {
      const [connection] = await tx
        .select({ provider: scmConnections.provider })
        .from(scmConnections)
        .where(eq(scmConnections.id, project.scmConnectionId));
      const stored = readScmContext(analysis.scmContext);
      const where = { analysisId: analysis.id, branchId: branch.id };
      if (!connection) {
        // No connection: nothing to decorate.
      } else if (stored.kind === 'missing') {
        logger?.warn(
          where,
          connection.provider === 'gitlab'
            ? 'quality gate re-evaluated but not decorated again on GitLab: the analysis has no stored SCM context (ingested before it was recorded), so whether it came from GitLab CI is unknown'
            : 'quality gate re-evaluated but not decorated again on GitHub: the analysis has no stored SCM context (ingested before it was recorded), so whether it came from GitHub Actions is unknown',
        );
      } else if (stored.kind === 'invalid') {
        logger?.warn(
          where,
          connection.provider === 'gitlab'
            ? 'quality gate re-evaluated but not decorated again on GitLab: the stored SCM context of the analysis is not valid'
            : 'quality gate re-evaluated but not decorated again on GitHub: the stored SCM context of the analysis is not valid',
        );
      } else if (stored.context.provider !== connection.provider) {
        // github.md §5.1: an analysis decorates only through a connection of its own provider.
      } else if (stored.context.provider === 'gitlab') {
        await enqueueDecoration(tx, {
          analysisId: analysis.id,
          branchId: branch.id,
          gitlab: stored.context.gitlab,
          reevaluation: true,
        });
      } else {
        // Stored only when the report had one (D2): an older CLI's GitHub analysis has none.
        const github = stored.context.github ?? null;
        if (github === null) {
          // Ruling C1: without the GitHub context, which revision was checked out (and so which
          // annotations are right) is unknown; fail closed.
          logger?.warn(
            where,
            'quality gate re-evaluated but not decorated again on GitHub: the analysis has no stored GitHub Actions context (sent by an older CLI)',
          );
        } else {
          await enqueueDecoration(tx, {
            analysisId: analysis.id,
            branchId: branch.id,
            gitlab: null,
            github,
            reevaluation: true,
          });
        }
      }
    }
    if (changed.length === 0 && !gateChanged) return 'unchanged';
    return statusChanged ? 'status' : gateChanged ? 'gate' : 'measures';
  });
}

/** The `gate` queue's handler (scm.md §7); main.ts runs it in the analysis worker. */
export function gateHandlers(deps: { db: Db; logger?: Logger | undefined }): JobHandlers {
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
      });
      if (result !== 'nothing' && result !== 'unchanged') {
        deps.logger?.info({ branchId: parsed.data.branchId, result }, 'quality gate re-evaluated');
      }
    },
  };
}
