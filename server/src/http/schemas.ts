import { z } from 'zod';
import { isStorableText } from '../audit/canonical';
import type { UserRow } from '../auth/sessions';
import { TOKEN_SCOPES, type apiTokens } from '../db/schema';

/**
 * Postgres `text` cannot hold U+0000: a parameter containing it fails the statement (SQLSTATE
 * 22021), so every free-text input that reaches the database is checked first.
 */
export function hasNoNul(s: string): boolean {
  return !s.includes('\u0000');
}

export const NUL_MESSAGE = 'Must not contain NUL characters';
export const SURROGATE_MESSAGE = 'Must be well-formed Unicode (no lone surrogate)';

/**
 * `schema` that also rejects U+0000 and text that is not well-formed Unicode (a lone UTF-16
 * surrogate: the database would store U+FFFD in its place, and the audit chain's canonical JSON
 * refuses it), with one 422 error on the field (api.md §2.1): NUL's message when it holds one.
 */
export function noNul<T extends z.ZodString>(schema: T): T {
  return schema
    .refine(hasNoNul, NUL_MESSAGE)
    .refine((s) => !hasNoNul(s) || isStorableText(s), SURROGATE_MESSAGE);
}

/** Free text stored in or compared with a `text` column: 1..`max` characters, storable (noNul). */
export function text(max: number): z.ZodString {
  return noNul(z.string().min(1).max(max));
}

export const timestamp = z.iso.datetime();
export const gateStatusSchema = z.enum(['passed', 'failed', 'error', 'none']);
export const idParams = z.strictObject({ id: z.uuid() });
export const noContent = z.undefined();

export function iso(date: Date): string {
  return date.toISOString();
}

export function isoOrNull(date: Date | null): string | null {
  return date ? date.toISOString() : null;
}

export const userSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  displayName: z.string().nullable(),
  email: z.string().nullable(),
  isInstanceAdmin: z.boolean(),
  active: z.boolean(),
  passwordChangeRequired: z.boolean(),
  /** sso-scim.md §16.2: false for an SSO-only user (no password to sign in with). */
  hasPassword: z.boolean(),
  /** sso-scim.md §16.2: how many SSO identities the user has, and whether SCIM made one. */
  sso: z.object({ identities: z.number().int().min(0), scim: z.boolean() }),
  lastLoginAt: timestamp.nullable(),
  createdAt: timestamp,
});
export type UserDto = z.infer<typeof userSchema>;
/** A user's SSO identities, as userSchema's `sso` shows them. */
export type UserSsoSummary = UserDto['sso'];
/** A user without identities (a new user, or any user before plan 4D's first sign-in). */
export const NO_SSO: UserSsoSummary = Object.freeze({ identities: 0, scim: false });

export function userDto(user: UserRow, sso: UserSsoSummary): UserDto {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    isInstanceAdmin: user.isInstanceAdmin,
    active: user.active,
    passwordChangeRequired: user.passwordChangeRequired,
    hasPassword: user.passwordHash !== null,
    sso: { identities: sso.identities, scim: sso.scim },
    lastLoginAt: isoOrNull(user.lastLoginAt),
    createdAt: iso(user.createdAt),
  };
}

export const tokenSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  prefix: z.string(),
  scopes: z.array(z.enum(TOKEN_SCOPES)),
  expiresAt: timestamp.nullable(),
  lastUsedAt: timestamp.nullable(),
  createdAt: timestamp,
});
/** Returned once, at creation: the only time the plaintext token leaves the server. */
export const createdTokenSchema = tokenSchema.extend({ token: z.string() });

export function tokenDto(row: typeof apiTokens.$inferSelect): z.infer<typeof tokenSchema> {
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    scopes: row.scopes,
    expiresAt: isoOrNull(row.expiresAt),
    lastUsedAt: isoOrNull(row.lastUsedAt),
    createdAt: iso(row.createdAt),
  };
}

export function expiresAtFrom(days: number | undefined): Date | null {
  return days === undefined ? null : new Date(Date.now() + days * 86_400_000);
}
