import { and, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import { AZURE_FILE } from './ci-setup';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { projects, repositorySetupItems, repositorySetupRuns, scmConnections } from '../db/schema';
import type { SetupAzurePolicy } from '../db/schema';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { AzureError } from '../scm/azure/client';
import { azureClientFor } from '../scm/azure/connections';
import type { DecorationDeps } from '../scm/decorate';
import { decorationRetryDelaySeconds, inSeconds, MAX_DECORATION_ATTEMPTS } from '../scm/queue';

/**
 * The deferred Build validation policy of an Azure DevOps CI setup: once the first main-branch
 * analysis arrives (the setup pull request is merged and the pipeline ran), the policy that runs
 * Qualor's pipeline on pull requests into the main branch is added, non-blocking. The ingestion
 * stage only queues this job; every Azure DevOps request is made here.
 */
export const AZURE_POLICY_QUEUE = 'azure-policy';

export const AZURE_POLICY_TEXT = {
  manual:
    'The Azure DevOps identity needs Edit policies on the repository: add the Build validation policy by hand',
  disabled:
    'A Build validation policy for the Qualor pipeline exists but is disabled: enable it in the branch policies',
  unreachable:
    'Azure DevOps could not be reached to add the Build validation policy: add it by hand',
  failed: 'The Build validation policy could not be added: add it by hand',
} as const;

export const azurePolicyKey = (projectId: string): string => `azure-policy:${projectId}`;

const payloadSchema = z.object({
  projectId: z.uuid(),
  attempt: z.number().int().min(0).max(MAX_DECORATION_ATTEMPTS).default(0),
});
type Payload = z.infer<typeof payloadSchema>;

/** Whether a setup of the project awaits its policy: one cheap indexed query. */
export async function hasPendingAzurePolicy(db: Executor, projectId: string): Promise<boolean> {
  const [row] = await db
    .select({ one: sql<number>`1` })
    .from(repositorySetupItems)
    .where(
      and(
        eq(repositorySetupItems.projectId, projectId),
        eq(repositorySetupItems.azurePolicy, 'pending'),
      ),
    )
    .limit(1);
  return row !== undefined;
}

/** Queues the job for the project. */
export async function enqueueAzurePolicy(db: Executor, projectId: string): Promise<void> {
  await enqueue(db, {
    queue: AZURE_POLICY_QUEUE,
    concurrencyKey: azurePolicyKey(projectId),
    payload: { projectId, attempt: 0 } satisfies Payload,
    maxAttempts: 3,
  });
}

interface Settled {
  state: SetupAzurePolicy;
  error: string | null;
}

const itemKey = sql<string>`${repositorySetupItems.runId} || ':' || ${repositorySetupItems.position}`;

/**
 * Settles the project's pending items of the repository whose pipeline is `pipelineId` with the
 * outcome, in one transaction. The items are read again here, locked: one that turned pending
 * while the job talked to Azure DevOps is settled too. An item of another pipeline stays pending:
 * it gets its own policy at a later main-branch analysis.
 */
async function settle(
  deps: DecorationDeps,
  target: { projectId: string; repositoryId: string; pipelineId: number | null },
  outcome: Settled,
) {
  await deps.db.transaction(async (tx) => {
    const locked = await tx
      .select({ key: itemKey })
      .from(repositorySetupItems)
      .where(
        and(
          eq(repositorySetupItems.projectId, target.projectId),
          eq(repositorySetupItems.azurePolicy, 'pending'),
          eq(sql`lower(${repositorySetupItems.repositoryRef})`, target.repositoryId),
          target.pipelineId === null
            ? isNull(repositorySetupItems.azurePipelineId)
            : eq(repositorySetupItems.azurePipelineId, target.pipelineId),
        ),
      )
      .for('update');
    if (locked.length === 0) return;
    await tx
      .update(repositorySetupItems)
      .set({ azurePolicy: outcome.state, azurePolicyError: outcome.error })
      .where(
        and(
          eq(repositorySetupItems.azurePolicy, 'pending'),
          inArray(
            itemKey,
            locked.map((l) => l.key),
          ),
        ),
      );
  });
}

async function run(deps: DecorationDeps, payload: Payload): Promise<void> {
  const [project] = await deps.db
    .select({
      ref: projects.scmProjectRef,
      main: projects.mainBranchName,
      connection: scmConnections,
    })
    .from(projects)
    .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(projects.id, payload.projectId));
  if (!project || project.ref === null || project.connection.provider !== 'azure') return;
  const repositoryId = project.ref.toLowerCase();
  // Newest first: the newest item's pipeline is the one the policy runs.
  const pending = await deps.db
    .select({ key: itemKey, pipelineId: repositorySetupItems.azurePipelineId })
    .from(repositorySetupItems)
    .innerJoin(repositorySetupRuns, eq(repositorySetupRuns.id, repositorySetupItems.runId))
    .where(
      and(
        eq(repositorySetupItems.projectId, payload.projectId),
        eq(repositorySetupItems.azurePolicy, 'pending'),
        eq(sql`lower(${repositorySetupItems.repositoryRef})`, repositoryId),
      ),
    )
    .orderBy(desc(repositorySetupRuns.createdAt), desc(repositorySetupItems.position));
  const newest = pending[0];
  if (!newest) return;
  const done = (state: SetupAzurePolicy, error: string | null) =>
    settle(
      deps,
      { projectId: payload.projectId, repositoryId, pipelineId: newest.pipelineId },
      { state, error },
    );
  if (newest.pipelineId === null) {
    await done('failed', AZURE_POLICY_TEXT.failed);
    return;
  }
  const found = azureClientFor(project.connection, deps.scm, deps.runtime);
  if ('problem' in found) {
    await done('failed', AZURE_POLICY_TEXT.failed);
    return;
  }
  const refName = `refs/heads/${project.main}`;
  try {
    const { client } = found;
    const { projectId } = await client.repository(repositoryId);
    // The pipeline's file must be on main first: until the setup pull request is merged, a pull
    // request would run a pipeline whose file is not on its target branch. Stays pending.
    const head = await client.branchHead(repositoryId, project.main);
    if (head === null) return;
    const file = await client.fileText(repositoryId, AZURE_FILE, head);
    if ('skipped' in file && file.skipped === 'missing') return;
    const existing = (await client.buildPolicies(projectId, repositoryId, refName)).filter(
      (p) => p.definitionId === newest.pipelineId,
    );
    // A disabled one is a person's choice. An enabled one is adopted, a blocking one (a person
    // made it so) left as it is.
    if (existing.length > 0 && !existing.some((p) => p.isEnabled)) {
      await done('manual', AZURE_POLICY_TEXT.disabled);
      return;
    }
    if (existing.length === 0) {
      await client.createBuildPolicy(projectId, {
        definitionId: newest.pipelineId,
        repositoryId,
        refName,
      });
    }
    await done('on', null);
  } catch (err) {
    if (!(err instanceof AzureError)) throw err;
    if (err.kind === 'auth') {
      await done('manual', AZURE_POLICY_TEXT.manual);
    } else if (err.kind === 'transient' || err.kind === 'rate_limited') {
      const next = payload.attempt + 1;
      if (next < MAX_DECORATION_ATTEMPTS) {
        const delay = Math.max(decorationRetryDelaySeconds(next), err.retryAfterSeconds ?? 0);
        await enqueue(deps.db, {
          queue: AZURE_POLICY_QUEUE,
          concurrencyKey: azurePolicyKey(payload.projectId),
          payload: { projectId: payload.projectId, attempt: next } satisfies Payload,
          runAt: inSeconds(delay),
          maxAttempts: 3,
        });
        return;
      }
      await done('failed', AZURE_POLICY_TEXT.unreachable);
    } else {
      await done('failed', AZURE_POLICY_TEXT.failed);
    }
  }
}

/** The `azure-policy` queue's handler, run by the `scm` worker (scm/decorate.ts `scmHandlers`). */
export function azurePolicyHandlers(deps: DecorationDeps): JobHandlers {
  return {
    [AZURE_POLICY_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed Azure policy job payload; completing');
        return;
      }
      await run(deps, parsed.data);
    },
  };
}
