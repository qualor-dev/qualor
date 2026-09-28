import type { GateResult } from '@qualor/shared';
import { and, asc, eq, isNull, or, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { webhookSubscriptions } from '../db/schema';
import {
  analysisFields,
  capWarnings,
  type IngestionContext,
  type IngestionStage,
} from '../ingest/process';
import { requireState } from '../ingest/state';
import { analysisDto } from '../analyses/dto';
import { createDeliveries, type NewDelivery } from './deliveries';

/** `statement_timestamp()`: the time the ingestion will store as `finished_at` (see below). */
async function statementTime(tx: Executor): Promise<Date> {
  const result = await tx.execute<{ now: Date | string }>(sql`SELECT statement_timestamp() AS now`);
  const value = result.rows[0]?.now;
  if (value === undefined) throw new Error('SELECT statement_timestamp() returned no row');
  return value instanceof Date ? value : new Date(value);
}

/**
 * api.md §3: the `analysis.completed` payload is exactly what `GET /analyses/{id}` will return
 * once the ingestion transaction commits — the analysis row as `ingest` is about to store it
 * (the report's fields, the capped warnings, the gate result, `succeeded`, and `finished_at`,
 * which ingestion takes from `ctx.state.finishedAt`) — plus the project and the branch.
 */
export function analysisPayload(ctx: IngestionContext, gate: GateResult, finishedAt: Date) {
  const final = {
    ...ctx.analysis,
    ...analysisFields(ctx.report, ctx.branch.id),
    warnings: capWarnings(ctx.warnings),
    status: 'succeeded' as const,
    error: null,
    gateStatus: gate.status,
    gateResult: gate,
    finishedAt,
  };
  return {
    ...analysisDto(final, ctx.branch),
    project: { id: ctx.project.id, key: ctx.project.key, name: ctx.project.name },
    branch: {
      id: ctx.branch.id,
      kind: ctx.branch.kind,
      name: ctx.branch.name,
      isMain: ctx.branch.isMain,
    },
  };
}

/**
 * The active webhooks of the project's organisation that cover the project, locked FOR KEY SHARE
 * in id order until the ingestion commits: a concurrent `DELETE /webhooks/{id}` waits for the
 * ingestion (and then deletes the new deliveries with the webhook) instead of making the delivery
 * insert fail its foreign key and abort the whole ingestion. KEY SHARE conflicts with nothing but
 * a delete or a key change: a PATCH, a redelivery or another ingestion never waits on it.
 */
export async function subscriptionsToNotify(
  tx: Executor,
  project: { id: string; organizationId: string },
): Promise<{ id: string; events: string[] }[]> {
  return tx
    .select({ id: webhookSubscriptions.id, events: webhookSubscriptions.events })
    .from(webhookSubscriptions)
    .where(
      and(
        eq(webhookSubscriptions.organizationId, project.organizationId),
        eq(webhookSubscriptions.active, true),
        or(isNull(webhookSubscriptions.projectId), eq(webhookSubscriptions.projectId, project.id)),
      ),
    )
    .orderBy(asc(webhookSubscriptions.id))
    .for('key share');
}

/**
 * Server step 13, after `gateStage` (ruling W5): enqueues one delivery per matching event for
 * every active webhook of the project's organisation that covers the project, in the ingestion
 * transaction — nothing is sent here (a rolled-back analysis sends nothing; the delivery worker
 * sends after commit). `gate.status_changed` fires when the gate status differs from the branch's
 * previous analysis, including a branch's first analysis (previous status `null`). At most 50
 * webhooks per organisation (routes/webhooks.ts), so at most 100 deliveries, written in bounded
 * batches (deliveries.ts).
 *
 * It must stay the last stage (ingest/stages.ts, checked by stages.test.ts): its payload is the
 * analysis exactly as ingestion is about to store it, so no stage may change the analysis after.
 */
export const webhookStage: IngestionStage = {
  name: 'webhooks',
  async run(ctx) {
    const gate = requireState(ctx.state, 'gate');
    const finishedAt = await statementTime(ctx.tx);
    ctx.state.finishedAt = finishedAt;
    const subscriptions = await subscriptionsToNotify(ctx.tx, ctx.project);
    if (subscriptions.length === 0) return;
    const payload = analysisPayload(ctx, gate, finishedAt);
    const previousGateStatus = ctx.previousAnalysis?.gateStatus ?? null;
    const statusChanged = previousGateStatus !== gate.status;
    const deliveries: NewDelivery[] = [];
    for (const subscription of subscriptions) {
      if (subscription.events.includes('analysis.completed')) {
        deliveries.push({ subscriptionId: subscription.id, event: 'analysis.completed', payload });
      }
      if (statusChanged && subscription.events.includes('gate.status_changed')) {
        deliveries.push({
          subscriptionId: subscription.id,
          event: 'gate.status_changed',
          payload: { ...payload, previousGateStatus },
        });
      }
    }
    await createDeliveries(ctx.tx, deliveries);
  },
};
