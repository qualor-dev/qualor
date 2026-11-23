import {
  AZURE_BUILD_ID,
  AZURE_GUID,
  GITHUB_CHECKOUTS,
  GITHUB_ID,
  type Report,
} from '@qualor/shared';
import { and, eq, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { branches, jobs } from '../db/schema';
import { enqueue } from '../queue/queue';

/** scm.md §4.2: decoration jobs run on their own queue and worker. */
export const SCM_QUEUE = 'scm';
/** scm.md §4.3: the first attempt and 5 retries. */
export const MAX_DECORATION_ATTEMPTS = 6;
/** The job's own retries, for database failures around an attempt (like webhook jobs). */
export const DECORATION_JOB_MAX_ATTEMPTS = 3;
/**
 * scm.md §7, ruling G7: a re-evaluation's decoration of a branch runs at least this long after the
 * branch's previous one, so toggling issues re-decorates a merge request at most this often.
 */
export const REDECORATION_INTERVAL_SECONDS = 15;

export type GitLabContext = NonNullable<Report['scm']['gitlab']>;
export type GitHubContext = NonNullable<Report['scm']['github']>;
export type AzureContext = NonNullable<Report['scm']['azure']>;

export const decorationPayload = z.object({
  analysisId: z.uuid(),
  /** Attempts made before this job's (0 for the first). */
  attempt: z.number().int().min(0).max(MAX_DECORATION_ATTEMPTS),
  /** The report's GitLab CI context (scm.md §3); null for a re-evaluation. */
  gitlab: z
    .object({
      projectId: z.string().optional(),
      pipelineId: z.string().optional(),
      mergeRequestEventType: z.enum(['detached', 'merged_result', 'merge_train']).optional(),
    })
    .nullable(),
  /** The report's GitHub Actions context (github.md §3); absent in 2A jobs, null elsewhere. */
  github: z
    .object({
      repositoryId: z.string().regex(GITHUB_ID).optional(),
      runId: z.string().regex(GITHUB_ID).optional(),
      checkout: z.enum(GITHUB_CHECKOUTS).optional(),
    })
    .nullable()
    .optional(),
  /** The report's Azure Pipelines context; absent unless an Azure DevOps analysis sent one. */
  azure: z
    .object({
      projectId: z.string().regex(AZURE_GUID).optional(),
      repositoryId: z.string().regex(AZURE_GUID).optional(),
      buildId: z.string().regex(AZURE_BUILD_ID).optional(),
      checkout: z.enum(GITHUB_CHECKOUTS).optional(),
    })
    .nullable()
    .optional(),
  /** Enqueued by a gate re-evaluation (scm.md §7), not an ingestion: bounded per branch. */
  reevaluation: z.literal(true).optional(),
});
export type DecorationPayload = z.infer<typeof decorationPayload>;

/** scm.md §4.1: one branch's decorations never run at once. */
export function decorationKey(branchId: string): string {
  return `scm:branch:${branchId}`;
}

/**
 * scm.md §4.3: the delay before retry `attempt` (1 = the first retry): 1, 2, 4, 8, 16 minutes.
 */
export function decorationRetryDelaySeconds(attempt: number): number {
  return 60 * 2 ** (attempt - 1);
}

/**
 * Serialises the enqueueing of one branch's decorations until the transaction ends. Ingestion
 * takes it after the analysis and the branch, before the branch's review snapshots and runs (its
 * SCM stage, then its review snapshot stage); a review run's end takes it before the run's row,
 * so that the end and its decoration are one step (review/run-ends.ts).
 */
export async function lockBranchQueue(db: Executor, branchId: string): Promise<void> {
  await db.execute(
    sql`SELECT pg_advisory_xact_lock(${LOCKS.scmDecoration}, hashtext(${branchId}))`,
  );
}

/** {@link lockBranchQueue} without waiting: false while another transaction holds it. */
export async function tryLockBranchQueue(db: Executor, branchId: string): Promise<boolean> {
  const result = await db.execute<{ locked: boolean }>(
    sql`SELECT pg_try_advisory_xact_lock(${LOCKS.scmDecoration}, hashtext(${branchId})) AS locked`,
  );
  return result.rows[0]?.locked === true;
}

/**
 * A new decoration of the branch (an analysis, or a re-evaluation). It supersedes the branch's
 * queued decorations (retries of older ones included): every run reconciles GitLab with the
 * branch's latest state, and a queued retry would otherwise hold the concurrency key (queued jobs
 * of a key run in id order) until its time came.
 */
export async function enqueueDecoration(
  db: Executor,
  input: {
    analysisId: string;
    branchId: string;
    gitlab: GitLabContext | null;
    /** The report's GitHub Actions context (github.md §3); left out of the payload when null. */
    github?: GitHubContext | null;
    /** The report's Azure Pipelines context; left out of the payload when null. */
    azure?: AzureContext | null;
    /** A gate re-evaluation's (scm.md §7): runs no sooner than the interval after the last one. */
    reevaluation?: boolean;
  },
): Promise<void> {
  const key = decorationKey(input.branchId);
  // Held until the caller's transaction (the ingestion's, say) commits: a retry enqueued meanwhile
  // waits, then sees this decoration queued and is not queued itself.
  await lockBranchQueue(db, input.branchId);
  await db
    .delete(jobs)
    .where(and(eq(jobs.queue, SCM_QUEUE), eq(jobs.concurrencyKey, key), eq(jobs.status, 'queued')));
  const reevaluation = input.reevaluation === true;
  await enqueue(db, {
    queue: SCM_QUEUE,
    concurrencyKey: key,
    payload: {
      analysisId: input.analysisId,
      attempt: 0,
      gitlab: input.gitlab,
      // Only when there is one: a GitLab decoration's payload stays byte for byte plan 2A's.
      ...(input.github ? { github: input.github } : {}),
      ...(input.azure ? { azure: input.azure } : {}),
      ...(reevaluation ? { reevaluation: true as const } : {}),
    } satisfies DecorationPayload,
    maxAttempts: DECORATION_JOB_MAX_ATTEMPTS,
    // Ruling G7: the queued ones were just deleted, so the last re-decoration is one that ran (or
    // runs); a toggle while this one waits replaces it with the same time, never a later one.
    ...(reevaluation ? { runAt: redecorationTime(key) } : {}),
  });
}

/**
 * A new decoration of `analysisId`, as {@link enqueueDecoration} queues one, but only while the
 * analysis is its branch's newest: a newer analysis has queued its own decoration, which this one
 * would replace, and the merge request part of an older analysis' decoration does nothing anyway.
 * For a job that ends after the analysis was ingested (an AI review run). The check and the
 * enqueueing are one step for the branch: a newer analysis being ingested meanwhile is waited for,
 * then seen. In a transaction that holds the branch's lock already (an end of a review run), it
 * is one step with what that transaction did. Answers whether it was queued.
 */
export async function enqueueLatestDecoration(
  db: Executor,
  input: Parameters<typeof enqueueDecoration>[1],
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await lockBranchQueue(tx, input.branchId);
    const [branch] = await tx
      .select({ lastAnalysisId: branches.lastAnalysisId })
      .from(branches)
      .where(eq(branches.id, input.branchId));
    if (branch?.lastAnalysisId !== input.analysisId) return false;
    await enqueueDecoration(tx, input);
    return true;
  });
}

/** `now()`, or the interval after the branch's last re-evaluation decoration if that is later. */
function redecorationTime(key: string): SQL {
  return sql`GREATEST(now(), (
    SELECT max(${jobs.createdAt}) + make_interval(secs => ${REDECORATION_INTERVAL_SECONDS})
      FROM ${jobs}
     WHERE ${jobs.queue} = ${SCM_QUEUE} AND ${jobs.concurrencyKey} = ${key}
       AND ${jobs.status} <> 'queued' AND ${jobs.payload} ->> 'reevaluation' = 'true'))`;
}

/**
 * The same decoration again later (a retry, or a job that found its organisation's slots taken),
 * unless a newer decoration of the branch is already queued: it covers this one. False when it was
 * not queued for that reason (the caller logs a retry as superseded).
 */
export async function requeueDecoration(
  db: Executor,
  branchId: string,
  payload: DecorationPayload,
  runAt: SQL,
): Promise<boolean> {
  const key = decorationKey(branchId);
  return db.transaction(async (tx) => {
    // The check and the insert are one step for the branch: a newer decoration being enqueued in
    // another transaction (an ingestion's) is waited for, then seen.
    await lockBranchQueue(tx, branchId);
    const [queued] = await tx
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(eq(jobs.queue, SCM_QUEUE), eq(jobs.concurrencyKey, key), eq(jobs.status, 'queued')),
      )
      .limit(1);
    if (queued) return false;
    await enqueue(tx, {
      queue: SCM_QUEUE,
      concurrencyKey: key,
      payload,
      runAt,
      maxAttempts: DECORATION_JOB_MAX_ATTEMPTS,
    });
    return true;
  });
}

/** `now() + seconds` on the database clock. */
export function inSeconds(seconds: number): SQL {
  return sql`now() + make_interval(secs => ${seconds})`;
}
