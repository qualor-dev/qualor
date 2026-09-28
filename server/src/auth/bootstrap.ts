import { count, eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { memberships, organizations, users } from '../db/schema';
import { ensureBuiltins } from '../orgs/builtins';
import { hashPassword } from './password';

export const DEFAULT_ORGANIZATION_KEY = 'default';

export class BootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BootstrapError';
  }
}

export interface BootstrapResult {
  createdOrganization: boolean;
  createdAdmin: boolean;
}

/**
 * First boot (data-model.md §4.1, ruling R9): create the `default` organisation and the first
 * instance admin; on every boot, make sure each organisation has its built-in profiles and gate.
 * Idempotent; the advisory lock makes replicas that boot together safe.
 */
export async function bootstrap(
  db: Db,
  admin: { username: string; password: string | undefined },
): Promise<BootstrapResult> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.bootstrap})`);
    let createdOrganization = false;
    const [orgCount] = await tx.select({ n: count() }).from(organizations);
    if ((orgCount?.n ?? 0) === 0) {
      await tx.insert(organizations).values({ key: DEFAULT_ORGANIZATION_KEY, name: 'Default' });
      createdOrganization = true;
    }
    // Every boot: organisations created before built-ins existed get them now (idempotent).
    for (const org of await tx.select({ id: organizations.id }).from(organizations)) {
      await ensureBuiltins(tx, org.id);
    }
    const [userCount] = await tx.select({ n: count() }).from(users);
    if ((userCount?.n ?? 0) > 0) return { createdOrganization, createdAdmin: false };
    if (!admin.password) {
      throw new BootstrapError(
        'No users exist yet: set QUALOR_BOOTSTRAP_ADMIN_PASSWORD (at least 12 characters) to create the first admin.',
      );
    }
    const user = first(
      await tx
        .insert(users)
        .values({
          username: admin.username,
          displayName: 'Administrator',
          passwordHash: await hashPassword(admin.password),
          isInstanceAdmin: true,
        })
        .returning(),
    );
    const [defaultOrg] = await tx
      .select()
      .from(organizations)
      .where(eq(organizations.key, DEFAULT_ORGANIZATION_KEY));
    if (defaultOrg) {
      await tx
        .insert(memberships)
        .values({ organizationId: defaultOrg.id, userId: user.id, role: 'admin' });
    }
    return { createdOrganization, createdAdmin: true };
  });
}
