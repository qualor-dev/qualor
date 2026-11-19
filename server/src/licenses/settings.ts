import { canonicalTerm, licensePolicySchema, type LicensePolicy } from '@qualor/shared';
import { eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { instanceSettings, organizations } from '../db/schema';
import { ProblemError } from '../http/problem';
import { dropOrganizationEntry, instanceSetting } from '../settings';

/** 6M §4: the `instance_settings` row of the organisation licence policies. */
export const LICENSE_POLICY_SETTINGS_KEY = 'licensePolicy';

/** An organisation without an entry has no policy. */
export interface LicensePolicySettings {
  organizations: Record<string, LicensePolicy>;
}

export const DEFAULT_LICENSE_POLICY_SETTINGS: LicensePolicySettings = { organizations: {} };

/**
 * The stored row's shape, its entries unchecked. Members other than `organizations` (a newer
 * version's) are kept, so a write carries them over.
 */
const storedRowSchema = z.looseObject({
  organizations: z.record(z.string(), z.unknown()).default({}),
});

/**
 * The stored row as it is read. An entry that does not parse (an operator's edit, or a newer
 * version's policy) is left out on its own, so it never takes the other organisations' policies
 * with it; a write keeps it as it is stored ({@link writeLicensePolicy}). The licence stage does
 * not read it through this: see {@link storedPolicyFor}.
 */
export const licensePolicySettingsSchema: z.ZodType<LicensePolicySettings> =
  storedRowSchema.transform(({ organizations: entries }) => {
    const valid: Record<string, LicensePolicy> = {};
    for (const [id, entry] of Object.entries(entries)) {
      const parsed = licensePolicySchema.safeParse(entry);
      if (parsed.success) valid[id] = parsed.data;
    }
    return { organizations: valid };
  });

export async function readLicensePolicies(db: Executor): Promise<LicensePolicySettings> {
  return instanceSetting(
    db,
    LICENSE_POLICY_SETTINGS_KEY,
    licensePolicySettingsSchema,
    DEFAULT_LICENSE_POLICY_SETTINGS,
  );
}

/**
 * The organisation's stored policy as the licence stage needs it (final review M4): `none` when
 * nothing is stored for it (no row, or no entry: the empty policy applies), `invalid` when the row
 * or its entry is stored but does not parse (an operator's edit, or a policy a newer version
 * wrote: a group id this one does not know). Judging against the empty policy then would close
 * every licence issue of the organisation, so the stage does not run.
 */
export type StoredLicensePolicy =
  { state: 'none' } | { state: 'policy'; policy: LicensePolicy } | { state: 'invalid' };

export async function storedPolicyFor(
  db: Executor,
  organizationId: string,
): Promise<StoredLicensePolicy> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, LICENSE_POLICY_SETTINGS_KEY));
  if (!row) return { state: 'none' };
  const stored = storedRowSchema.safeParse(row.value);
  if (!stored.success) return { state: 'invalid' };
  const entries = stored.data.organizations;
  if (!Object.hasOwn(entries, organizationId)) return { state: 'none' };
  const parsed = licensePolicySchema.safeParse(entries[organizationId]);
  return parsed.success ? { state: 'policy', policy: parsed.data } : { state: 'invalid' };
}

/** The organisation's policy, or `null` when it has none (or its entry does not parse). */
export async function policyFor(
  db: Executor,
  organizationId: string,
): Promise<LicensePolicy | null> {
  return (await readLicensePolicies(db)).organizations[organizationId] ?? null;
}

/** The stored row as it is, its entries unchecked: what a write starts from. */
export interface StoredLicensePolicies {
  /** The row's members, `organizations` included; empty without a row. */
  row: Record<string, unknown>;
  /** Each organisation's entry as it is stored, readable or not. */
  entries: Record<string, unknown>;
}

/**
 * The stored row, read raw under the advisory lock every write of the row takes, so a change made
 * from it in `tx` never overwrites another write. `null` when the row's outer shape is broken
 * (`organizations` is not an object): no entry can be told from another then, so nothing may be
 * written over it ({@link licensePoliciesUnreadable}).
 */
export async function lockStoredLicensePolicies(
  tx: Executor,
): Promise<StoredLicensePolicies | null> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.licensePolicy})`);
  const [stored] = await tx
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, LICENSE_POLICY_SETTINGS_KEY));
  if (!stored) return { row: {}, entries: {} };
  const parsed = storedRowSchema.safeParse(stored.value);
  if (!parsed.success) return null;
  return { row: parsed.data, entries: parsed.data.organizations };
}

/** The stored row cannot be read: writing over it would lose every organisation's policy. */
export const LICENSE_POLICIES_UNREADABLE = 'LICENSE_POLICIES_UNREADABLE';

export const licensePoliciesUnreadable = (): ProblemError =>
  new ProblemError(409, LICENSE_POLICIES_UNREADABLE, 'The stored licence policies cannot be read', {
    detail: `The instance setting "${LICENSE_POLICY_SETTINGS_KEY}" is not an object with an "organizations" object, so no policy can be changed; fix the row, or delete it to remove every organisation's policy`,
  });

const isUuid = (id: string): boolean => z.uuid().safeParse(id).success;

/**
 * Sets (or with `null` removes) the organisation's policy, under the lock. Every other
 * organisation's entry is carried over as it is stored, even one this version cannot read (final
 * review): only the entries of organisations deleted since are dropped (6M §4). Throws
 * {@link licensePoliciesUnreadable} when the row's outer shape is broken, and changes nothing.
 * Call it inside a transaction.
 */
export async function writeLicensePolicy(
  tx: Executor,
  organizationId: string,
  policy: LicensePolicy | null,
): Promise<void> {
  const stored = await lockStoredLicensePolicies(tx);
  if (stored === null) throw licensePoliciesUnreadable();
  const others = Object.keys(stored.entries).filter((id) => id !== organizationId && isUuid(id));
  const existing =
    others.length === 0
      ? new Set<string>()
      : new Set(
          (
            await tx
              .select({ id: organizations.id })
              .from(organizations)
              .where(inArray(organizations.id, others))
          ).map((r) => r.id),
        );
  const next: Record<string, unknown> = {};
  for (const [id, kept] of Object.entries(stored.entries)) {
    if (existing.has(id)) next[id] = kept;
  }
  if (policy !== null) next[organizationId] = policy;
  const value = { ...stored.row, organizations: next };
  await tx
    .insert(instanceSettings)
    .values({ key: LICENSE_POLICY_SETTINGS_KEY, value })
    .onConflictDoUpdate({ target: instanceSettings.key, set: { value, updatedAt: sql`now()` } });
}

/**
 * Removes the organisation's policy from the row, under the lock every write of the row takes,
 * for the delete of the organisation (0.16 issue #37). The other organisations' entries, readable
 * or not, and the row's other members stay as they are stored. A missing row or entry, or a row
 * whose outer shape is broken, is left as it is. Call it inside a transaction.
 */
export async function dropOrganizationLicensePolicy(
  tx: Executor,
  organizationId: string,
): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.licensePolicy})`);
  await dropOrganizationEntry(tx, LICENSE_POLICY_SETTINGS_KEY, organizationId);
}

/** Code-unit order (not locale-dependent). */
function byCodeUnits(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

const sortedUnique = <T extends string>(values: readonly T[]): T[] =>
  [...new Set(values)].sort(byCodeUnits);

/**
 * 6M §5: the policy as it is stored: every id in its canonical spelling (`gpl-3.0` is
 * GPL-3.0-only), and each list sorted with each entry once. Validate the ids first
 * (`invalidLicenseIds`): an unknown id comes back as written.
 */
export function normalizeLicensePolicy(policy: LicensePolicy): LicensePolicy {
  return {
    mode: policy.mode,
    forbiddenGroups: sortedUnique(policy.forbiddenGroups),
    forbidden: sortedUnique(policy.forbidden.map(canonicalTerm)),
    allowed: sortedUnique(policy.allowed.map(canonicalTerm)),
    warnUnknown: policy.warnUnknown,
  };
}

const sameList = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

/** Two stored (normalised) policies are the same, or both absent. */
export function sameLicensePolicy(a: LicensePolicy | null, b: LicensePolicy | null): boolean {
  if (a === null || b === null) return a === b;
  return (
    a.mode === b.mode &&
    a.warnUnknown === b.warnUnknown &&
    sameList(a.forbiddenGroups, b.forbiddenGroups) &&
    sameList(a.forbidden, b.forbidden) &&
    sameList(a.allowed, b.allowed)
  );
}
