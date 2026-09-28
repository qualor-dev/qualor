import { count, eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { memberships, organizations, users } from '../db/schema';
import { bootstrap, BootstrapError } from './bootstrap';
import { verifyPassword } from './password';

const admin = { username: 'admin', password: 'correct horse battery staple' };

async function withDb(run: (t: TestDatabase) => Promise<void>): Promise<void> {
  const t = await createTestDatabase();
  try {
    await run(t);
  } finally {
    await t.close();
  }
}

async function counts(t: TestDatabase): Promise<[number, number]> {
  const [orgs] = await t.db.select({ n: count() }).from(organizations);
  const [people] = await t.db.select({ n: count() }).from(users);
  return [orgs!.n, people!.n];
}

describe('bootstrap (first boot)', () => {
  it('creates the default organisation and an instance admin who administers it', () =>
    withDb(async (t) => {
      expect(await bootstrap(t.db, admin)).toEqual({
        createdOrganization: true,
        createdAdmin: true,
      });
      const [user] = await t.db.select().from(users).where(eq(users.username, 'admin'));
      expect(user).toMatchObject({
        isInstanceAdmin: true,
        active: true,
        passwordChangeRequired: false,
      });
      expect(user!.passwordHash).toMatch(/^\$argon2id\$/);
      expect(await verifyPassword(user!.passwordHash, admin.password)).toBe(true);
      const [org] = await t.db.select().from(organizations);
      expect(org!.key).toBe('default');
      const [membership] = await t.db.select().from(memberships);
      expect(membership).toMatchObject({
        organizationId: org!.id,
        userId: user!.id,
        role: 'admin',
      });
    }));

  it('is idempotent and ignores the password once users exist', () =>
    withDb(async (t) => {
      await bootstrap(t.db, admin);
      expect(await bootstrap(t.db, { username: 'admin', password: undefined })).toEqual({
        createdOrganization: false,
        createdAdmin: false,
      });
      expect(await counts(t)).toEqual([1, 1]);
    }));

  it('refuses to start without a bootstrap password and writes nothing', () =>
    withDb(async (t) => {
      await expect(bootstrap(t.db, { username: 'admin', password: undefined })).rejects.toThrow(
        BootstrapError,
      );
      expect(await counts(t)).toEqual([0, 0]);
    }));

  it('creates exactly one admin and one organisation when replicas boot together', () =>
    withDb(async (t) => {
      await Promise.all([1, 2, 3].map(() => bootstrap(t.db, admin)));
      expect(await counts(t)).toEqual([1, 1]);
    }));
});
