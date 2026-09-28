import { and, count, eq, inArray, ne, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { instanceSettings, ssoConnections, users } from '../db/schema';
import { conflict, validationFailed, type FieldError } from '../http/problem';

/** sso-scim.md §10: who may sign in with a password. */
export type PasswordPolicy = 'everyone' | 'break_glass_only';
export interface SignInSettings {
  passwordSignIn: PasswordPolicy;
  breakGlassUserIds: string[];
}
/** What the effective policy depends on beyond the stored row: the licence and the variable. */
export interface PolicyFacts {
  /** The `sso` feature is active. */
  sso: boolean;
  /** QUALOR_FORCE_PASSWORD_SIGN_IN=true (§10.4). */
  forced: boolean;
}

/** §10.2: `break_glass_only` only while the row says so, `sso` is active and nothing forces it. */
export function effectivePasswordPolicy(
  stored: SignInSettings,
  facts: PolicyFacts,
): PasswordPolicy {
  return stored.passwordSignIn === 'break_glass_only' && facts.sso && !facts.forced
    ? 'break_glass_only'
    : 'everyone';
}

/**
 * Ruling SS6: the one place that decides whether a password may sign a user in. `forced` is true
 * only when the stored policy would have refused and QUALOR_FORCE_PASSWORD_SIGN_IN allowed it.
 */
export function mayUsePassword(
  user: { id: string; active: boolean; isInstanceAdmin: boolean },
  stored: SignInSettings,
  facts: PolicyFacts,
): { allowed: boolean; forced: boolean } {
  const breakGlass =
    user.active && user.isInstanceAdmin && stored.breakGlassUserIds.includes(user.id);
  if (breakGlass || effectivePasswordPolicy(stored, { ...facts, forced: false }) === 'everyone') {
    return { allowed: true, forced: false };
  }
  return facts.forced ? { allowed: true, forced: true } : { allowed: false, forced: false };
}

// ─── The stored row (`instance_settings` key `sign-in`, §10.1) ──────────────────────────────────

export const SIGN_IN_SETTINGS_KEY = 'sign-in';
/** at most 10 break-glass admins. */
export const MAX_BREAK_GLASS_USERS = 10;
const STORED = z.strictObject({
  passwordSignIn: z.enum(['everyone', 'break_glass_only']),
  breakGlassUserIds: z.array(z.uuid()).max(MAX_BREAK_GLASS_USERS),
});
/** A fresh default each time, so no caller can change another caller's copy. */
const defaults = (): SignInSettings => ({ passwordSignIn: 'everyone', breakGlassUserIds: [] });

export interface SignInLog {
  warn(fields: Record<string, unknown>, message: string): void;
}

let loggedMalformed = false;

/**
 * The stored setting. A missing row reads as `everyone`; a malformed one too (it fails open, never
 * a lock-out) and is logged once per process, without its content.
 */
export async function readSignInSettings(db: Executor, log?: SignInLog): Promise<SignInSettings> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, SIGN_IN_SETTINGS_KEY));
  if (!row) return defaults();
  const parsed = STORED.safeParse(row.value);
  if (parsed.success) return parsed.data;
  if (!loggedMalformed && log) {
    loggedMalformed = true;
    log.warn(
      { component: 'sign-in' },
      'the sign-in setting is malformed; password sign-in is open to everyone',
    );
  }
  return defaults();
}

/**
 * The listed users that exist, in list order: `usable` when active, an instance admin and with a
 * password (§10.1, §10.3). Unknown ids are left out.
 */
export async function usableBreakGlass(
  db: Executor,
  ids: readonly string[],
): Promise<{ userId: string; username: string; usable: boolean }[]> {
  if (ids.length === 0) return [];
  const rows = await db
    .select({
      id: users.id,
      username: users.username,
      active: users.active,
      isInstanceAdmin: users.isInstanceAdmin,
      hasPassword: sql<boolean>`${users.passwordHash} IS NOT NULL`,
    })
    .from(users)
    .where(inArray(users.id, [...ids]));
  const byId = new Map(rows.map((r) => [r.id, r]));
  return [...new Set(ids)].flatMap((id) => {
    const r = byId.get(id);
    return r
      ? [
          {
            userId: r.id,
            username: r.username,
            usable: r.active && r.isInstanceAdmin && r.hasPassword,
          },
        ]
      : [];
  });
}

/**
 * §10.3: while the STORED policy is `break_glass_only`, refuses (409 LAST_BREAK_GLASS_ADMIN) a
 * change that deactivates or demotes a listed user when no other listed user stays usable. The
 * stored policy, not the effective one (ruling, Task 12 fix round 1): a demotion made while
 * QUALOR_FORCE_PASSWORD_SIGN_IN is set or `sso` has lapsed would otherwise lock everyone out once
 * the variable is removed or the licence renewed. Takes the instance-admin lock (re-entrant for a
 * caller that holds it, as `PATCH /users/:id` does), and gives the same answer before or after the
 * caller wrote the change in `tx`.
 */
export async function assertBreakGlassKept(
  tx: Executor,
  change: { userId: string; active?: boolean; isInstanceAdmin?: boolean },
): Promise<void> {
  if (change.active !== false && change.isInstanceAdmin !== false) return;
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
  const stored = await readSignInSettings(tx);
  if (stored.passwordSignIn !== 'break_glass_only') return;
  if (!stored.breakGlassUserIds.includes(change.userId)) return;
  const remaining = (await usableBreakGlass(tx, stored.breakGlassUserIds)).filter(
    (u) => u.usable && u.userId !== change.userId,
  );
  if (remaining.length === 0) {
    throw conflict(
      'LAST_BREAK_GLASS_ADMIN',
      'At least one break-glass administrator must remain while password sign-in is limited',
    );
  }
}

/** Enabled connections, all or all but `except`. */
async function enabledConnectionCount(tx: Executor, except?: string): Promise<number> {
  const [row = { n: 0 }] = await tx
    .select({ n: count() })
    .from(ssoConnections)
    .where(
      except === undefined
        ? eq(ssoConnections.enabled, true)
        : and(eq(ssoConnections.enabled, true), ne(ssoConnections.id, except)),
    );
  return row.n;
}

/**
 * while the STORED policy is `break_glass_only`, refuses (409 LAST_SSO_CONNECTION) to
 * disable or delete the last enabled connection, which would leave everyone but the break-glass
 * admins without a way in. Takes the instance-admin lock, which a settings save holds while it
 * checks for an enabled connection: the caller takes it before `LOCKS.ssoConnections` (that
 * order, in every path), so the two cannot pass each other.
 */
export async function assertSsoConnectionKept(tx: Executor, connectionId: string): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
  const stored = await readSignInSettings(tx);
  if (stored.passwordSignIn !== 'break_glass_only') return;
  const [self] = await tx
    .select({ enabled: ssoConnections.enabled })
    .from(ssoConnections)
    .where(eq(ssoConnections.id, connectionId));
  if (!self?.enabled) return;
  if ((await enabledConnectionCount(tx, connectionId)) === 0) {
    throw conflict(
      'LAST_SSO_CONNECTION',
      'Password sign-in is limited to break-glass administrators: keep one connection enabled, or allow password sign-in for everyone first',
    );
  }
}

/**
 * `PUT /ee/sso/settings` (§10.1, §17): validates (422 on the field), and for `break_glass_only`
 * needs a usable listed admin and an enabled connection; saves the row and records
 * `sso.sign_in_settings_updated`, under the instance-admin lock so a concurrent demotion cannot
 * slip between the check and the save.
 */
export async function updateSignInSettings(
  deps: { db: Db; audit: AuditRecorder },
  actor: AuditActorContext,
  input: SignInSettings,
): Promise<SignInSettings> {
  const parsed = STORED.safeParse(input);
  if (!parsed.success) {
    throw validationFailed(
      parsed.error.issues.map((issue) => ({
        path: ['body', ...issue.path.map(String)].join('.'),
        message: issue.message,
      })),
    );
  }
  const settings: SignInSettings = {
    passwordSignIn: parsed.data.passwordSignIn,
    breakGlassUserIds: [...new Set(parsed.data.breakGlassUserIds)],
  };
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
    if (settings.passwordSignIn === 'break_glass_only') {
      const errors: FieldError[] = [];
      const usable = (await usableBreakGlass(tx, settings.breakGlassUserIds)).some((u) => u.usable);
      if (!usable) {
        errors.push({
          path: 'body.breakGlassUserIds',
          message: 'List at least one active instance administrator with a password',
        });
      }
      if ((await enabledConnectionCount(tx)) === 0) {
        errors.push({
          path: 'body.passwordSignIn',
          message: 'Enable a single sign-on connection first',
        });
      }
      if (errors.length > 0) throw validationFailed(errors);
    }
    await tx
      .insert(instanceSettings)
      .values({ key: SIGN_IN_SETTINGS_KEY, value: settings })
      .onConflictDoUpdate({
        target: instanceSettings.key,
        set: { value: settings, updatedAt: new Date() },
      });
    await deps.audit.record(tx, actor, [
      {
        action: 'sso.sign_in_settings_updated',
        target: { type: 'sign_in_settings', id: SIGN_IN_SETTINGS_KEY },
        details: {
          passwordSignIn: settings.passwordSignIn,
          breakGlassUserIds: settings.breakGlassUserIds,
        },
      },
    ]);
    return settings;
  });
}
