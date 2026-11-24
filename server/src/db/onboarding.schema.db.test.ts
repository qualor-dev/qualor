import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { checkViolation, refusal } from '../../test/refusals';
import { first } from './rows';
import {
  organizations,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  setupChecklistClosures,
  users,
} from './schema';

type RunInsert = typeof repositorySetupRuns.$inferInsert;
type ItemInsert = typeof repositorySetupItems.$inferInsert;

/** `value` in a column whatever its type allows: for a value the checks must refuse. */
const bad = <T>(name: string, value: unknown): Partial<T> => ({ [name]: value }) as Partial<T>;

describe('the onboarding tables (migration 0019_onboarding)', () => {
  let t: TestDatabase;
  let organizationId: string;
  let userId: string;
  let connectionId: string;

  const newRun = async (over: Partial<RunInsert> = {}) =>
    first(
      await t.db
        .insert(repositorySetupRuns)
        .values({ organizationId, connectionId, createdBy: userId, ...over })
        .returning(),
    );
  const itemValues = (runId: string, over: Partial<ItemInsert> = {}): ItemInsert => ({
    runId,
    position: 0,
    repositoryRef: 'acme/api',
    repositoryName: 'api',
    ...over,
  });

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = first(
      await t.db.insert(organizations).values({ key: 'onb', name: 'Onboarding' }).returning(),
    ).id;
    userId = first(
      await t.db
        .insert(users)
        .values({ username: 'onb-user', displayName: 'Onb', passwordHash: 'x' })
        .returning(),
    ).id;
    connectionId = first(
      await t.db
        .insert(scmConnections)
        .values({
          organizationId,
          provider: 'gitlab',
          baseUrl: 'https://gitlab.example.com',
          tokenEnc: { v: 1, iv: 'a', ct: 'b', tag: 'c' },
        })
        .returning(),
    ).id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('defaults a connection to no CI setup and a run to queued', async () => {
    const connection = first(await t.db.select().from(scmConnections));
    expect(connection.ciSetupAllowed).toBe(false);
    const run = await newRun();
    expect(run).toMatchObject({ status: 'queued', ciSetup: false, finishedAt: null });
    const item = first(
      await t.db.insert(repositorySetupItems).values(itemValues(run.id)).returning(),
    );
    expect(item).toMatchObject({
      projectOutcome: 'pending',
      ciOutcome: 'pending',
      tokenEnc: null,
      projectId: null,
    });
  });

  it('refuses an unknown run status', async () => {
    expect(await refusal(newRun(bad<RunInsert>('status', 'paused')))).toEqual(
      checkViolation('repository_setup_runs_status_check'),
    );
    for (const status of ['queued', 'running', 'done'] as const) {
      expect(await refusal(newRun({ status }))).toBeNull();
    }
  });

  it('refuses an unknown project or CI outcome', async () => {
    const run = await newRun();
    expect(
      await refusal(
        t.db
          .insert(repositorySetupItems)
          .values(itemValues(run.id, bad<ItemInsert>('projectOutcome', 'exists'))),
      ),
    ).toEqual(checkViolation('repository_setup_items_project_outcome_check'));
    expect(
      await refusal(
        t.db
          .insert(repositorySetupItems)
          .values(itemValues(run.id, bad<ItemInsert>('ciOutcome', 'pushed'))),
      ),
    ).toEqual(checkViolation('repository_setup_items_ci_outcome_check'));
    let position = 10;
    for (const projectOutcome of ['pending', 'created', 'adopted', 'failed'] as const) {
      position += 1;
      expect(
        await refusal(
          t.db
            .insert(repositorySetupItems)
            .values(itemValues(run.id, { position, projectOutcome })),
        ),
      ).toBeNull();
    }
    for (const ciOutcome of [
      'pending',
      'merge_request',
      'snippet',
      'already',
      'skipped',
      'failed',
    ] as const) {
      position += 1;
      expect(
        await refusal(
          t.db.insert(repositorySetupItems).values(itemValues(run.id, { position, ciOutcome })),
        ),
      ).toBeNull();
    }
  });

  it('keys an item by run and position, and removes items with their run', async () => {
    const run = await newRun();
    await t.db.insert(repositorySetupItems).values(itemValues(run.id));
    expect(
      (await refusal(t.db.insert(repositorySetupItems).values(itemValues(run.id))))?.code,
    ).toBe('23505');
    await t.db.delete(repositorySetupRuns).where(eq(repositorySetupRuns.id, run.id));
    expect(
      await t.db.select().from(repositorySetupItems).where(eq(repositorySetupItems.runId, run.id)),
    ).toEqual([]);
  });

  it('keeps a run when its connection goes, and one closure per user and organisation', async () => {
    const other = first(
      await t.db
        .insert(scmConnections)
        .values({
          organizationId,
          provider: 'gitlab',
          baseUrl: 'https://other.example.com',
          tokenEnc: { v: 1, iv: 'a', ct: 'b', tag: 'c' },
        })
        .returning(),
    );
    const run = await newRun({ connectionId: other.id });
    await t.db.delete(scmConnections).where(eq(scmConnections.id, other.id));
    expect(
      first(await t.db.select().from(repositorySetupRuns).where(eq(repositorySetupRuns.id, run.id)))
        .connectionId,
    ).toBe(null);
    await t.db.insert(setupChecklistClosures).values({ userId, organizationId });
    expect(
      (await refusal(t.db.insert(setupChecklistClosures).values({ userId, organizationId })))?.code,
    ).toBe('23505');
    expect(
      (
        await refusal(
          t.db.insert(setupChecklistClosures).values({ userId: randomUUID(), organizationId }),
        )
      )?.code,
    ).toBe('23503');
  });
});

describe('the Azure DevOps CI setup columns (migration 0036_azure_ci_setup)', () => {
  let t: TestDatabase;
  let organizationId: string;
  let runId: string;

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = first(
      await t.db.insert(organizations).values({ key: 'azci', name: 'Azure CI' }).returning(),
    ).id;
    runId = first(await t.db.insert(repositorySetupRuns).values({ organizationId }).returning()).id;
  });
  afterAll(async () => {
    await t.close();
  });

  const item = (position: number, over: Partial<ItemInsert> = {}): ItemInsert => ({
    runId,
    position,
    repositoryRef: `acme/api-${position}`,
    repositoryName: `api-${position}`,
    ...over,
  });

  it('defaults the Azure columns of an item and of a run to null', async () => {
    const row = first(await t.db.insert(repositorySetupItems).values(item(0)).returning());
    expect(row).toMatchObject({
      azurePipelineId: null,
      azureQueue: null,
      azurePolicy: null,
      azurePolicyError: null,
    });
    expect(first(await t.db.select().from(repositorySetupRuns)).azurePool).toBeNull();
  });

  it('stores the pipeline id, the pool name, the queue state and the policy error', async () => {
    const row = first(
      await t.db
        .insert(repositorySetupItems)
        .values(item(1, { azurePipelineId: 28, azurePolicyError: 'fixed text' }))
        .returning(),
    );
    expect(row).toMatchObject({ azurePipelineId: 28, azurePolicyError: 'fixed text' });
    const run = first(
      await t.db
        .insert(repositorySetupRuns)
        .values({ organizationId, azurePool: 'Default' })
        .returning(),
    );
    expect(run.azurePool).toBe('Default');
  });

  it('refuses an unknown azure_queue and accepts null and each value', async () => {
    expect(
      await refusal(
        t.db.insert(repositorySetupItems).values(item(10, bad<ItemInsert>('azureQueue', 'x'))),
      ),
    ).toEqual(checkViolation('repository_setup_items_azure_queue_check'));
    let position = 10;
    for (const azureQueue of [null, 'authorized', 'open', 'manual'] as const) {
      position += 1;
      expect(
        await refusal(t.db.insert(repositorySetupItems).values(item(position, { azureQueue }))),
      ).toBeNull();
    }
  });

  it('refuses an unknown azure_policy and accepts null and each value', async () => {
    expect(
      await refusal(
        t.db.insert(repositorySetupItems).values(item(30, bad<ItemInsert>('azurePolicy', 'x'))),
      ),
    ).toEqual(checkViolation('repository_setup_items_azure_policy_check'));
    let position = 30;
    for (const azurePolicy of [null, 'pending', 'on', 'manual', 'failed'] as const) {
      position += 1;
      expect(
        await refusal(t.db.insert(repositorySetupItems).values(item(position, { azurePolicy }))),
      ).toBeNull();
    }
  });
});
