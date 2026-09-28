import { count } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { bootstrap } from '../auth/bootstrap';
import { organizations, users } from '../db/schema';
import { ProblemError } from '../http/problem';
import { createOrganization } from './service';

async function seeded(): Promise<{ t: TestDatabase; adminId: string }> {
  const t = await createTestDatabase();
  await bootstrap(t.db, { username: 'admin', password: 'correct horse battery staple' });
  const [admin] = await t.db.select().from(users);
  return { t, adminId: admin!.id };
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'OK';
  } catch (err) {
    if (err instanceof ProblemError) return err.code;
    throw err;
  }
}

describe('createOrganization (data-model.md §4.1, §8.2)', () => {
  it('a fourth and a fifth organisation can be created in the community edition', async () => {
    const { t, adminId } = await seeded();
    try {
      for (const key of ['second', 'third', 'fourth', 'fifth']) {
        expect(await codeOf(createOrganization(t.db, { key, name: key, creatorId: adminId }))).toBe(
          'OK',
        );
      }
      const [n] = await t.db.select({ n: count() }).from(organizations);
      expect(n!.n).toBe(5);
    } finally {
      await t.close();
    }
  });

  it('two creators racing for the same key get one OK and one ORG_KEY_TAKEN (data-model.md §8 item 2)', async () => {
    const { t, adminId } = await seeded();
    try {
      const results = await Promise.all(
        Array.from({ length: 2 }, () =>
          codeOf(createOrganization(t.db, { key: 'same', name: 'Same', creatorId: adminId })),
        ),
      );
      expect(results.sort()).toEqual(['OK', 'ORG_KEY_TAKEN']);
      const [n] = await t.db.select({ n: count() }).from(organizations);
      expect(n!.n).toBe(2);
    } finally {
      await t.close();
    }
  });
});
