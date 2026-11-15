import {
  COMMONS_CLAUSE,
  canonicalTerm,
  invalidLicenseIds,
  LICENSE_GROUPS,
  licensePolicySchema,
  SPDX_EXCEPTION_IDS,
  SPDX_LICENSE_IDS,
  type LicenseGroupId,
  type LicensePolicy,
} from '@qualor/shared';
import { eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { organizations } from '../db/schema';
import { ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import {
  LICENSE_POLICY_SETTINGS_KEY,
  licensePoliciesUnreadable,
  lockStoredLicensePolicies,
  normalizeLicensePolicy,
  policyFor,
  sameLicensePolicy,
  writeLicensePolicy,
} from '../licenses/settings';

/** 6M: the enterprise feature behind `limits.licenses.policy`. */
export const LICENSE_POLICY_FEATURE = 'license-policy';

const GROUP_IDS = LICENSE_GROUPS.map((g) => g.id) as [LicenseGroupId, ...LicenseGroupId[]];

const groupSchema = z.object({
  id: z.enum(GROUP_IDS),
  label: z.string(),
  description: z.string(),
  /** SPDX ids and "id WITH exception" terms. */
  members: z.array(z.string()),
});

const policyStateSchema = z.object({
  /** The enterprise feature license-policy is active: the policy is applied and may be changed. */
  available: z.boolean(),
  /** The organisation's policy, kept while the feature is inactive; `null`: none. */
  policy: licensePolicySchema.nullable(),
});

const policyAnswerSchema = policyStateSchema.extend({
  groups: z.array(groupSchema),
  /** What a policy entry may name, for autocompletion: canonical spellings only. */
  spdxIds: z.object({
    /** SPDX licence ids, deprecated ones left out, and the Commons Clause. */
    licenses: z.array(z.string()),
    /** SPDX exception ids, and the Commons Clause, for "id WITH exception". */
    exceptions: z.array(z.string()),
  }),
});

/** The ids a policy entry may name in their current spelling (deprecated ids canonicalise away). */
let spdxIds: { licenses: string[]; exceptions: string[] } | undefined;
function autocompleteIds(): { licenses: string[]; exceptions: string[] } {
  spdxIds ??= {
    licenses: [...SPDX_LICENSE_IDS.filter((id) => canonicalTerm(id) === id), COMMONS_CLAUSE],
    exceptions: [...SPDX_EXCEPTION_IDS, COMMONS_CLAUSE],
  };
  return spdxIds;
}

const notLicensed = (): ProblemError =>
  new ProblemError(
    403,
    'FEATURE_NOT_LICENSED',
    `The enterprise feature "${LICENSE_POLICY_FEATURE}" is not licensed`,
  );

const invalidIds = (invalid: string[]): ProblemError =>
  new ProblemError(400, 'INVALID_LICENSE_ID', 'Unknown SPDX licence identifiers', {
    detail: `Not SPDX licence ids or terms: ${invalid.join(', ')}`,
    extensions: { details: { invalid } },
  });

/**
 * 6M §5: an organisation's licence policy. Anyone in the organisation reads it; its admins change
 * it while the enterprise feature license-policy is active. A stored policy is kept, and returned,
 * without the feature, but not applied.
 */
export const licensePolicyRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const available = (): boolean => deps.edition.limits().licenses.policy;

  app.get(
    '/organizations/:id/license-policy',
    {
      schema: {
        tags: ['organizations'],
        summary:
          "The organisation's licence policy (org.read), the licence groups and the SPDX ids it may name; `available` is false without the enterprise feature license-policy",
        params: idParams,
        response: { 200: policyAnswerSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.read');
      return {
        available: available(),
        policy: await policyFor(deps.db, organizationId),
        groups: LICENSE_GROUPS.map((g) => ({ ...g, members: [...g.members] })),
        spdxIds: autocompleteIds(),
      };
    },
  );

  app.put(
    '/organizations/:id/license-policy',
    {
      config: {
        openapi: {
          problems: [400, 409],
          problemDescriptions: {
            400: 'INVALID_LICENSE_ID: an entry of `forbidden` or `allowed` is not an SPDX licence id or "id WITH exception" term; `details.invalid` lists them',
            403: 'FEATURE_NOT_LICENSED: the enterprise feature license-policy is not active',
            409: 'LICENSE_POLICIES_UNREADABLE: the stored licence policies (instance setting `licensePolicy`) are not an object with an `organizations` object; nothing is changed until an operator fixes or deletes the row',
          },
        },
      },
      schema: {
        tags: ['organizations'],
        summary:
          "Set the organisation's licence policy, or remove it with `policy: null` (org.licenses.manage); the ids are stored in their canonical SPDX spelling, each list sorted",
        params: idParams,
        body: z.strictObject({ policy: licensePolicySchema.nullable() }),
        response: { 200: policyStateSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      const organization = await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.licenses.manage',
      );
      if (!available()) throw notLicensed();
      const sent: LicensePolicy | null = request.body.policy;
      if (sent !== null) {
        const invalid = invalidLicenseIds(sent);
        if (invalid.length > 0) throw invalidIds(invalid);
      }
      const next = sent === null ? null : normalizeLicensePolicy(sent);
      await deps.db.transaction(async (tx) => {
        const stored = await lockStoredLicensePolicies(tx);
        if (stored === null) {
          request.log.error(
            { organizationId, setting: LICENSE_POLICY_SETTINGS_KEY },
            'the stored licence policies cannot be read: the policy was not changed',
          );
          throw licensePoliciesUnreadable();
        }
        // An entry this version cannot read is no policy (`before: null`), but it is still
        // replaced or, with `null`, removed: it would otherwise keep LICENSE_POLICY_INVALID firing.
        const stated = Object.hasOwn(stored.entries, organizationId);
        const readable = stated
          ? licensePolicySchema.safeParse(stored.entries[organizationId])
          : undefined;
        const before = readable?.success ? readable.data : null;
        if (readable?.success ? sameLicensePolicy(before, next) : !stated && next === null) return;
        await writeLicensePolicy(tx, organizationId, next);
        if (deps.audit.active()) {
          const [row] = await tx
            .select({ name: organizations.name })
            .from(organizations)
            .where(eq(organizations.id, organizationId));
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'organization.license_policy_changed',
              organization: { id: organizationId, key: organization.organizationKey },
              target: { type: 'organization', id: organizationId, label: row?.name ?? null },
              details: { before, after: next },
            },
          ]);
        }
      });
      return { available: true, policy: next };
    },
  );
};
