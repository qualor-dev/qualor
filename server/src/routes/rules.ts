import { ISSUE_KINDS, QUALITIES, ruleHelpUri, SEVERITIES } from '@qualor/shared';
import { and, asc, eq, gt, ilike, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  type AccessContext,
  accessOf,
  requireOrganizationAccess,
  requirePermission,
  requireUser,
} from '../auth/access';
import { grantInOrganization, memberOf, organizationFacts } from '../auth/facts';
import { organizationPermissions } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import { memberships, organizations, rules } from '../db/schema';
import { decodeKeyset, encodeKeyset } from '../http/keyset';
import { notFound } from '../http/problem';
import { iso, noNul, text, timestamp } from '../http/schemas';
import { containsPattern } from '../issues/query';

export type RuleRow = typeof rules.$inferSelect;

export const ruleSchema = z.object({
  key: z.string(),
  engine: z.string(),
  engineRuleId: z.string(),
  name: z.string(),
  descriptionMd: z.string().nullable(),
  helpUri: z.string().nullable(),
  languages: z.array(z.string()),
  defaultSeverity: z.enum(SEVERITIES),
  quality: z.enum(QUALITIES),
  kind: z.enum(ISSUE_KINDS),
  tags: z.array(z.string()),
  cwe: z.array(z.number().int()),
  status: z.enum(['ready', 'deprecated', 'removed']),
  origin: z.enum(['builtin', 'reported']),
  createdAt: timestamp,
  updatedAt: timestamp,
});

export function ruleDto(row: RuleRow): z.infer<typeof ruleSchema> {
  return {
    key: row.key,
    engine: row.engineId,
    engineRuleId: row.engineRuleId,
    name: row.name,
    descriptionMd: row.descriptionMd,
    // A link stored before it died (rules.sonarsource.com) shows as the live page; a Qualor rule
    // without one links to its page in qualor-rules.
    helpUri: ruleHelpUri(row.key, row.helpUri),
    languages: row.languages,
    defaultSeverity: row.defaultSeverity as z.infer<typeof ruleSchema>['defaultSeverity'],
    quality: row.quality as z.infer<typeof ruleSchema>['quality'],
    kind: row.kind,
    tags: row.tags,
    cwe: row.cwe,
    status: row.status,
    origin: row.origin,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

/**
 * Rule keys are `engine:ruleId` (an engine id of at most 40 characters, a rule id of at most 512,
 * report-format.md §5), so every key ingestion can create is addressable.
 */
export const ruleKeyParam = text(40 + 1 + 512);

/** Keyset cursor over `rules.key` (unique), shared with the profile rule listing. */
export const ruleCursor = z.strictObject({ k: ruleKeyParam });

export function ruleCursorOf(key: string): string {
  return encodeKeyset({ k: key });
}

export function afterRuleKey(cursor: string | undefined) {
  const after = decodeKeyset(cursor, ruleCursor);
  return after ? gt(rules.key, after.k) : undefined;
}

/** `q`: a case-insensitive substring of the rule key or name. */
export function ruleSearch(q: string | undefined) {
  if (q === undefined) return undefined;
  const pattern = containsPattern(q);
  return or(ilike(rules.key, pattern), ilike(rules.name, pattern));
}

/** The `q` query parameter of the rule listings. */
export const ruleQuery = noNul(z.string().trim().min(1).max(200)).optional();

/**
 * Ruling X2: `rules` rows are global, but an organisation sees only the rules it has
 * met — a built-in rule, a rule one of its projects has an issue for, or a rule one of its
 * profiles has a row for — never the keys and names another organisation's reports introduced.
 * The issue test joins through `branches` so that both plans the planner chooses between are
 * index-only scans of `issues_rule_idx (branch_id, rule_id, status)`: one probe per rule and
 * branch of the organisation, or (hashed) one pass over the organisation's branches. Measured
 * with 300k issues and 3 200 rules over three organisations: 0.7–13 ms for a page of 51.
 */
export function ruleVisibleTo(organizationId: SQL | string): SQL {
  return sql`(${rules.origin} = 'builtin'
    OR EXISTS (SELECT 1 FROM profile_rules vpr
                 JOIN quality_profiles vqp ON vqp.id = vpr.profile_id
                WHERE vpr.rule_id = ${rules.id} AND vqp.organization_id = ${organizationId})
    OR EXISTS (SELECT 1 FROM issues vi
                 JOIN branches vb ON vb.id = vi.branch_id
                 JOIN projects vp ON vp.id = vb.project_id
                WHERE vi.rule_id = ${rules.id} AND vp.organization_id = ${organizationId}))`;
}

/**
 * The rule with this key as the organisation sees it, in one query: a missing organisation, one
 * the caller does not belong to, a missing rule and a rule the organisation cannot see (ruling
 * X2) are the same 404 `Rule not found`.
 */
export async function ruleFor(
  access: AccessContext,
  principal: UserPrincipal,
  organizationId: string,
  key: string,
): Promise<RuleRow> {
  const [row] = await access.db
    .select({
      rule: rules,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, organizations.id),
    })
    .from(organizations)
    .leftJoin(memberships, memberOf(principal.user, organizations.id))
    .leftJoin(rules, and(eq(rules.key, key), ruleVisibleTo(sql`${organizations.id}`)))
    .where(eq(organizations.id, organizationId));
  if (!row) throw notFound('Rule');
  const permissions = organizationPermissions(organizationFacts(principal.user, row));
  requirePermission(principal, permissions, 'org.read', 'org.read', 'Rule');
  // A rule the organisation has not met is the same 404 (ruling X2), after the permission check.
  if (!row.rule) throw notFound('Rule');
  return row.rule;
}

export const ruleRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/rules',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['rules'],
        summary:
          'The rules an organisation has met (built-in, or referenced by its issues or profiles), by key, keyset-paginated',
        querystring: z.strictObject({
          organizationId: z.uuid(),
          limit: z.coerce.number().int().min(1).max(500).default(50),
          cursor: z.string().max(1_024).optional(),
          q: ruleQuery,
          engine: text(64).optional(),
          language: text(64).optional(),
          quality: z.enum(QUALITIES).optional(),
          severity: z.enum(SEVERITIES).optional(),
        }),
        response: {
          200: z.object({ items: z.array(ruleSchema), nextCursor: z.string().nullable() }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { organizationId, limit, cursor, q, engine, language, quality, severity } =
        request.query;
      const after = afterRuleKey(cursor);
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.read');
      const rows = await deps.db
        .select()
        .from(rules)
        .where(
          and(
            after,
            ruleSearch(q),
            engine === undefined ? undefined : eq(rules.engineId, engine),
            language === undefined ? undefined : sql`${language} = ANY(${rules.languages})`,
            quality === undefined ? undefined : eq(rules.quality, quality),
            severity === undefined ? undefined : eq(rules.defaultSeverity, severity),
            ruleVisibleTo(organizationId),
          ),
        )
        .orderBy(asc(rules.key))
        .limit(limit + 1);
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return {
        items: items.map(ruleDto),
        nextCursor: rows.length > limit && last ? ruleCursorOf(last.key) : null,
      };
    },
  );

  app.get(
    '/rules/:key',
    {
      schema: {
        tags: ['rules'],
        summary:
          'One rule the organisation has met; the key is URL-encoded (eslint%3Ano-unused-vars)',
        params: z.strictObject({ key: ruleKeyParam }),
        querystring: z.strictObject({ organizationId: z.uuid() }),
        response: { 200: ruleSchema },
      },
    },
    async (request) =>
      ruleDto(
        await ruleFor(
          accessOf(deps),
          requireUser(request),
          request.query.organizationId,
          request.params.key,
        ),
      ),
  );
};
