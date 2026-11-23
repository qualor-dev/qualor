import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { first } from '../db/rows';
import { organizations, scmConnections } from '../db/schema';
import { clearScmProblem, recordScmProblem } from './problems';

/* The one problem slot of a connection: credential codes overwrite hook codes, never the reverse. */

describe('the connection problem slot', () => {
  let t: TestDatabase;
  let id: string;
  let organizationId: string;
  const problem = async () =>
    first(await t.db.select().from(scmConnections).where(eq(scmConnections.id, id))).problem;

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = first(
      await t.db.insert(organizations).values({ key: 'problems', name: 'Problems' }).returning(),
    ).id;
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await t.db.delete(scmConnections);
    id = first(
      await t.db
        .insert(scmConnections)
        .values({
          organizationId,
          provider: 'azure',
          azureAuth: 'pat',
          baseUrl: 'https://dev.azure.com/x',
          tokenEnc: { v: 1 } as never,
        })
        .returning(),
    ).id;
  });

  it('a credential code overwrites a hook code', async () => {
    await recordScmProblem(t.db, id, 'hook_disabled');
    await recordScmProblem(t.db, id, 'token_refused');
    expect(await problem()).toMatchObject({ code: 'token_refused' });
  });

  it('a hook code never overwrites a credential code, and replaces another hook code', async () => {
    await recordScmProblem(t.db, id, 'token_refused');
    await recordScmProblem(t.db, id, 'hook_probation');
    expect(await problem()).toMatchObject({ code: 'token_refused' });
    await t.db.update(scmConnections).set({ problem: null });
    await recordScmProblem(t.db, id, 'hook_probation');
    await recordScmProblem(t.db, id, 'hook_disabled');
    expect(await problem()).toMatchObject({ code: 'hook_disabled' });
  });

  it('clears only the given codes', async () => {
    await recordScmProblem(t.db, id, 'hook_disabled');
    await clearScmProblem(t.db, id, ['token_refused']);
    expect(await problem()).toMatchObject({ code: 'hook_disabled' });
    await clearScmProblem(t.db, id, ['hook_probation', 'hook_disabled']);
    expect(await problem()).toBeNull();
  });
});
