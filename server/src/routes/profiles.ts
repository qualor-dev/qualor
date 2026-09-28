import { ENGINE_ID_PATTERN, SEVERITIES } from '@qualor/shared';
import { and, asc, count, eq, gt, inArray, notInArray, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  QUALITY_PROFILE_CHANGE_FIELDS,
  type AuditAction,
  type AuditDetails,
} from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import { organizationRef, projectRefs } from '../audit/refs';
import {
  type AccessContext,
  accessOf,
  requireOrganizationAccess,
  requirePermission,
  requireUser,
} from '../auth/access';
import { grantInOrganization, memberOf, organizationFacts } from '../auth/facts';
import { organizationPermissions, type OrganizationPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { Executor } from '../db/client';
import {
  isForeignKeyViolation,
  PG_UNIQUE_VIOLATION,
  pgConstraint,
  pgErrorCode,
} from '../db/errors';
import { uuidList } from '../db/bulk';
import { first } from '../db/rows';
import {
  memberships,
  organizations,
  profileRules,
  projectProfiles,
  qualityProfiles,
  rules,
} from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound, validationFailed } from '../http/problem';
import { idParams, iso, noContent, noNul, timestamp } from '../http/schemas';
import { BUILTIN_NAME, PROFILE_LANGUAGES } from '../orgs/builtins';
import { projectForUser } from '../projects/access';
import { engineRuleDefaults } from '../rules/catalog';
import { LANGUAGE_BOUND_ENGINES, MAX_PROFILE_DEPTH } from '../rules/profiles';
import {
  afterRuleKey,
  ruleCursorOf,
  ruleKeyParam,
  ruleQuery,
  ruleSearch,
  ruleVisibleTo,
  type RuleRow,
} from './rules';

export type ProfileRow = typeof qualityProfiles.$inferSelect;

/**
 * Resource bounds (E1 wave), not edition limits: profiles per organisation (built-ins included;
 * 409 `PROFILE_LIMIT_REACHED`) ...
 */
export const MAX_PROFILES_PER_ORGANIZATION = 100;
/**
 * ... and rules a profile sets itself (409 `PROFILE_RULE_LIMIT_REACHED`). Together they bound the
 * rule rows `PUT /quality-profiles/{id}/rules/{ruleKey}` can create by key (ruling X5): such a
 * rule is removed again once no profile sets it and nothing else refers to it
 * ({@link removeBareRules}), so an organisation keeps at most 100 x 10 000 of them, and setting
 * and removing rules in a loop leaves nothing behind.
 */
export const MAX_RULES_PER_PROFILE = 10_000;

/**
 * Serialises profile creation in an organisation (its row, FOR NO KEY UPDATE: foreign-key checks
 * of unrelated inserts are not blocked) and refuses a profile beyond the bound.
 */
async function requireProfileRoom(tx: Executor, organizationId: string): Promise<void> {
  await tx
    .select({ id: organizations.id })
    .from(organizations)
    .where(eq(organizations.id, organizationId))
    .for('no key update');
  const [existing] = await tx
    .select({ n: count() })
    .from(qualityProfiles)
    .where(eq(qualityProfiles.organizationId, organizationId));
  if ((existing?.n ?? 0) >= MAX_PROFILES_PER_ORGANIZATION) {
    throw conflict(
      'PROFILE_LIMIT_REACHED',
      `An organisation has at most ${MAX_PROFILES_PER_ORGANIZATION} quality profiles`,
    );
  }
}

/**
 * Removes those of `ruleIds` that are bare reported rules nothing refers to any more: no profile
 * sets them, no issue uses them, and no report ever gave them metadata (a rule ruling X5 let a PUT
 * create, or one ingestion created bare for a finding a profile then filtered out). Rules are
 * global, so this runs in the caller's transaction after its own profile rows are gone:
 * - each rule is locked first, skipping one another transaction holds (a foreign-key check in
 *   flight: a PUT or an ingestion referring to it), and the references are checked in a later
 *   statement, so they include every reference committed while the lock was taken;
 * - a writer that read the rule's id before and refers to it after this commits fails its
 *   foreign-key check: a PUT answers 409 `CONFLICT` and an ingestion is retried by its job, and
 *   either re-creates the rule.
 */
export async function removeBareRules(tx: Executor, ruleIds: readonly string[]): Promise<void> {
  if (ruleIds.length === 0) return;
  const locked = await tx.execute<{ id: string }>(sql`
    SELECT id FROM rules
     WHERE id IN ${uuidList(ruleIds)}
       AND origin = 'reported' AND name = engine_rule_id
       AND description_md IS NULL AND help_uri IS NULL
       AND languages = '{}' AND tags = '{}' AND cwe = '{}'
     ORDER BY id
     FOR UPDATE SKIP LOCKED`);
  const ids = locked.rows.map((r) => r.id);
  if (ids.length === 0) return;
  await tx.execute(sql`
    DELETE FROM rules r
     WHERE r.id IN ${uuidList(ids)}
       AND NOT EXISTS (SELECT 1 FROM profile_rules pr WHERE pr.rule_id = r.id)
       AND NOT EXISTS (SELECT 1 FROM issues i WHERE i.rule_id = r.id)`);
}

/** `quality_profiles.parent_id` → `quality_profiles.id`, ON DELETE RESTRICT (0001_init.sql). */
const PARENT_FOREIGN_KEY = 'quality_profiles_parent_id_quality_profiles_id_fk';

export const profileSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  name: z.string(),
  language: z.enum(PROFILE_LANGUAGES),
  parentId: z.uuid().nullable(),
  isDefault: z.boolean(),
  isBuiltin: z.boolean(),
  unknownRules: z.enum(['activate', 'ignore']),
  createdAt: timestamp,
  updatedAt: timestamp,
});

export function profileDto(row: ProfileRow): z.infer<typeof profileSchema> {
  return {
    id: row.id,
    organizationId: row.organizationId,
    name: row.name,
    language: row.language as (typeof PROFILE_LANGUAGES)[number],
    parentId: row.parentId,
    isDefault: row.isDefault,
    isBuiltin: row.isBuiltin,
    unknownRules: row.unknownRules,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

const profileName = noNul(z.string().trim().min(1).max(100));

/** Compatibility-folded, lower-cased, letters and digits only. */
function nameSkeleton(name: string): string {
  return name
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, '');
}

const RESERVED = nameSkeleton(BUILTIN_NAME);

/**
 * Ruling B1 / P5: "Qualor way" names the built-in profiles, in any case, spacing or punctuation
 * (none, non-breaking or zero-width spaces, `Qualor-way`, `Qualor_way`, `Qualor.way`, full-width
 * letters), so a copy can never pass for one. 422 on `body.name`.
 */
export function requireUnreservedName(name: string): void {
  if (nameSkeleton(name) === RESERVED) {
    throw validationFailed([
      { path: 'body.name', message: `"${BUILTIN_NAME}" is reserved for the built-in profiles` },
    ]);
  }
}

/**
 * The unique indexes as problems the client can act on: the (organisation, language, name) index
 * is a taken name; the one-default index (not reachable while set-default locks the language
 * first) a concurrent change. Decided by the constraint, never by a check before the write.
 */
function uniqueConflict(err: unknown): never {
  if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) {
    if (pgConstraint(err) === 'quality_profiles_one_default') {
      throw conflict('CONFLICT', 'The default profile was changed concurrently; retry');
    }
    throw conflict(
      'PROFILE_NAME_TAKEN',
      'The organisation already has a profile of this language with this name',
    );
  }
  throw err;
}

/**
 * The profile named in the path, like `gateFor` (routes/gates.ts): a missing profile and a profile
 * of an organisation the caller does not belong to are the same 404, answered by one query (the
 * access facts are joined); 403 when the caller's role or token lacks `permission`.
 */
export async function profileFor(
  access: AccessContext,
  principal: UserPrincipal,
  id: string,
  permission: OrganizationPermission,
): Promise<ProfileRow> {
  const [row] = await access.db
    .select({
      profile: qualityProfiles,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, qualityProfiles.organizationId),
    })
    .from(qualityProfiles)
    .leftJoin(memberships, memberOf(principal.user, qualityProfiles.organizationId))
    .where(eq(qualityProfiles.id, id));
  if (!row) throw notFound('Quality profile');
  const permissions = organizationPermissions(organizationFacts(principal.user, row));
  requirePermission(principal, permissions, permission, 'org.read', 'Quality profile');
  return row.profile;
}

export function requireEditableProfile(profile: ProfileRow): void {
  if (profile.isBuiltin) {
    throw conflict(
      'BUILTIN_READ_ONLY',
      'The built-in profiles are read-only; copy one to change it',
    );
  }
}

/**
 * Locks the profiles of one organisation and language in id order, so concurrent set-default,
 * delete, copy and create-with-parent calls serialise instead of tripping
 * `quality_profiles_one_default` or deleting a parent a new child is being attached to.
 */
async function lockLanguage(tx: Executor, organizationId: string, language: string) {
  return tx
    .select()
    .from(qualityProfiles)
    .where(
      and(
        eq(qualityProfiles.organizationId, organizationId),
        eq(qualityProfiles.language, language),
      ),
    )
    .orderBy(asc(qualityProfiles.id))
    .for('update');
}

/**
 * data-model.md §4.4: the parent must be a profile of the same organisation and language (`siblings`
 * are exactly those, locked), and the new profile may be at most the third level. The parent is
 * fixed at creation (PATCH cannot change it), so the parent chain can never form a cycle.
 */
function requireValidParent(siblings: readonly ProfileRow[], parentId: string): void {
  const byId = new Map(siblings.map((p) => [p.id, p]));
  const parent = byId.get(parentId);
  if (!parent) {
    throw validationFailed([
      {
        path: 'body.parentId',
        message: 'No profile of this organisation and language has this id',
      },
    ]);
  }
  let levels = 2; // the new profile and its parent
  // Bounded by the depth limit, so even a (never created) cycle cannot loop forever.
  for (let p = parent.parentId; p !== null && levels <= MAX_PROFILE_DEPTH; levels += 1) {
    p = byId.get(p)?.parentId ?? null;
  }
  if (levels > MAX_PROFILE_DEPTH) {
    throw validationFailed([
      {
        path: 'body.parentId',
        message: `Profiles inherit at most ${MAX_PROFILE_DEPTH} levels deep`,
      },
    ]);
  }
}

/**
 * Ruling X4 (replaces P4's limit on writes): every rule a finding could be routed to a profile of
 * `language` by ingestion (ruling P2, rules/profiles.ts `governingLanguage`). `*` decides any
 * engine's rule (file-less findings, files of language `other` such as `pom.xml`, and every
 * engine not tied to a language); a language profile decides the language-bound engines' rules
 * (ESLint, PMD, SpotBugs), whatever languages a rule names. Only the engine prefix of the key
 * counts, so the answer never depends on what the catalog holds.
 */
export function governable(language: string, engineId: string): boolean {
  return language === '*' || LANGUAGE_BOUND_ENGINES.has(engineId);
}

/** {@link governable} as a condition on `rules` (`undefined`: every rule). */
export function rulesGovernableBy(language: string): SQL | undefined {
  return language === '*' ? undefined : inArray(rules.engineId, [...LANGUAGE_BOUND_ENGINES]);
}

/**
 * Ruling P4, kept as the default view of a profile's rule list: a language profile lists the
 * rules of the language-bound engines that name the language or name none; `*` lists every other
 * engine's rules. (The list adds any rule with a row in the profile's chain, and `scope=all`
 * lists everything {@link governable}.)
 */
export function rulesGovernedBy(language: string): SQL {
  const bound = [...LANGUAGE_BOUND_ENGINES];
  if (language === '*') return notInArray(rules.engineId, bound);
  return sql`(${inArray(rules.engineId, bound)}
    AND (${language} = ANY(${rules.languages}) OR cardinality(${rules.languages}) = 0))`;
}

/**
 * The profile first, then its ancestors (at most {@link MAX_PROFILE_DEPTH}), walked the way
 * ingestion walks them (rules/profiles.ts `loadProfileSet`).
 */
async function profileChain(db: Executor, profile: ProfileRow): Promise<string[]> {
  const siblings = await db
    .select({ id: qualityProfiles.id, parentId: qualityProfiles.parentId })
    .from(qualityProfiles)
    .where(
      and(
        eq(qualityProfiles.organizationId, profile.organizationId),
        eq(qualityProfiles.language, profile.language),
      ),
    );
  const parentOf = new Map(siblings.map((p) => [p.id, p.parentId]));
  const chain = [profile.id];
  for (
    let p = profile.parentId;
    p !== null && chain.length < MAX_PROFILE_DEPTH && !chain.includes(p);
    p = parentOf.get(p) ?? null
  ) {
    chain.push(p);
  }
  return chain;
}

export const profileRuleSchema = z.object({
  rule: z.object({
    key: z.string(),
    name: z.string(),
    engine: z.string(),
    languages: z.array(z.string()),
    defaultSeverity: z.enum(SEVERITIES),
    quality: z.string(),
    kind: z.string(),
  }),
  active: z.boolean(),
  severityOverride: z.enum(SEVERITIES).nullable(),
  /** `profile`: this profile's own row; `inherited`: an ancestor's row; `default`: no row. */
  source: z.enum(['profile', 'inherited', 'default']),
  sourceProfileId: z.uuid().nullable(),
});
type ProfileRuleDto = z.infer<typeof profileRuleSchema>;

/** What a profile rule entry shows of its rule. */
type RuleView = Pick<
  RuleRow,
  'key' | 'name' | 'engineId' | 'languages' | 'defaultSeverity' | 'quality' | 'kind'
>;

interface EffectiveRow {
  rule: RuleView;
  rowActive: boolean | null;
  severityOverride: string | null;
  sourceProfileId: string | null;
}

function profileRuleDto(profile: ProfileRow, row: EffectiveRow): ProfileRuleDto {
  const { rule } = row;
  return {
    rule: {
      key: rule.key,
      name: rule.name,
      engine: rule.engineId,
      languages: rule.languages,
      defaultSeverity: rule.defaultSeverity as ProfileRuleDto['rule']['defaultSeverity'],
      quality: rule.quality,
      kind: rule.kind,
    },
    active: row.rowActive ?? profile.unknownRules === 'activate',
    severityOverride: (row.severityOverride as ProfileRuleDto['severityOverride']) ?? null,
    source:
      row.sourceProfileId === null
        ? 'default'
        : row.sourceProfileId === profile.id
          ? 'profile'
          : 'inherited',
    sourceProfileId: row.sourceProfileId,
  };
}

/**
 * The nearest row of a rule in the profile chain, as `effectiveRules` selects it. A named type:
 * tree-sitter's TypeScript grammar cannot parse an object type literal as the type argument of a
 * tagged template (`sql<{ … }>`), which Qualor's own scan then reports as PARSE_ERRORS.
 */
interface NearestRow {
  active: boolean;
  severity: string | null;
  profile: string;
}

/**
 * data-model.md §4.4 with inheritance resolved the way ingestion resolves it (rules/profiles.ts
 * `ruleSetting`): the nearest row in the chain wins; a rule with no row anywhere follows this
 * profile's `unknown_rules`. Only the rules the profile's organisation has met (ruling X2).
 */
async function effectiveRules(
  db: Executor,
  profile: ProfileRow,
  where: (SQL | undefined)[],
  options: { active: boolean | undefined; scope: 'default' | 'all'; limit: number },
): Promise<EffectiveRow[]> {
  const chain = await profileChain(db, profile);
  const nearest = sql`(
    SELECT json_build_object('active', pr.active, 'severity', pr.severity_override,
                             'profile', pr.profile_id)
      FROM profile_rules pr
      JOIN jsonb_array_elements_text(${JSON.stringify(chain)}::jsonb) WITH ORDINALITY
           AS c(id, ord) ON c.id::uuid = pr.profile_id
     WHERE pr.rule_id = ${rules.id}
     ORDER BY c.ord
     LIMIT 1)`;
  const activeFilter =
    options.active === undefined
      ? undefined
      : sql`COALESCE((${nearest} ->> 'active')::boolean, ${profile.unknownRules === 'activate'})
            = ${options.active}`;
  // Ruling X4: the default view is P4's set plus every rule set anywhere in the chain, so a rule
  // that was set (say a JavaScript-only ESLint rule on a TypeScript profile) is always listed.
  const scope =
    options.scope === 'all'
      ? rulesGovernableBy(profile.language)
      : and(
          rulesGovernableBy(profile.language),
          or(rulesGovernedBy(profile.language), sql`${nearest} IS NOT NULL`),
        );
  const rows = await db
    .select({
      rule: rules,
      nearest: sql<NearestRow | null>`${nearest}`,
    })
    .from(rules)
    .where(and(scope, ...where, activeFilter, ruleVisibleTo(profile.organizationId)))
    .orderBy(asc(rules.key))
    .limit(options.limit);
  return rows.map((r) => ({
    rule: r.rule,
    rowActive: r.nearest?.active ?? null,
    severityOverride: r.nearest?.severity ?? null,
    sourceProfileId: r.nearest?.profile ?? null,
  }));
}

/** report-format.md §7.1: a rule id is 1–512 characters, as reports and the status import take it. */
const MAX_RULE_ID_LENGTH = 512;

/**
 * A rule key is `<engine>:<rule id>` (rules/catalog.ts `ruleKey`), as a report can send it. The
 * rule id is bounded like a report's, so every key accepted here fits the audit event's
 * `ruleKey` (audit/catalogue.ts `AUDIT_RULE_KEY_PATTERN`).
 */
export function parseRuleKey(key: string): { engineId: string; engineRuleId: string } {
  const colon = key.indexOf(':');
  const engineId = colon < 0 ? '' : key.slice(0, colon);
  const engineRuleId = colon < 0 ? '' : key.slice(colon + 1);
  if (
    !ENGINE_ID_PATTERN.test(engineId) ||
    engineRuleId.length === 0 ||
    engineRuleId.length > MAX_RULE_ID_LENGTH
  ) {
    throw validationFailed([
      {
        path: 'params.ruleKey',
        message: `A rule key is <engine>:<rule id> (the rule id at most ${MAX_RULE_ID_LENGTH} characters), e.g. eslint:no-eval`,
      },
    ]);
  }
  return { engineId, engineRuleId };
}

/** 422 on `params.ruleKey` unless a finding of this engine could be routed to the profile. */
function requireGovernable(
  profile: ProfileRow,
  key: string,
): { engineId: string; engineRuleId: string } {
  const parsed = parseRuleKey(key);
  if (!governable(profile.language, parsed.engineId)) {
    throw validationFailed([
      {
        path: 'params.ruleKey',
        message: `A ${profile.language} profile does not decide ${parsed.engineId} rules`,
      },
    ]);
  }
  return parsed;
}

/**
 * The row ingestion's bare path writes for a rule a finding names without metadata
 * (rules/catalog.ts `ruleRowsFromReport`), which is also all a PUT response shows of a rule the
 * organisation had not met (ruling X5).
 */
function bareRule(parsed: { engineId: string; engineRuleId: string }, key: string): RuleView {
  const defaults = engineRuleDefaults(parsed.engineId);
  return {
    key,
    name: parsed.engineRuleId,
    engineId: parsed.engineId,
    languages: [],
    defaultSeverity: defaults.defaultSeverity,
    quality: defaults.quality,
    kind: 'issue',
  };
}

const ruleParams = z.strictObject({ id: z.uuid(), ruleKey: ruleKeyParam });

const projectProfileSchema = z.object({
  language: z.enum(PROFILE_LANGUAGES),
  profile: profileSchema.nullable(),
  /** `project`: set on the project; `default`: the organisation's default for the language. */
  source: z.enum(['project', 'default']),
});

/**
 * The profile each language of the project uses (data-model.md §4.4 `project_profiles`), chosen
 * as ingestion chooses it (rules/profiles.ts `loadProfileSet`).
 */
async function projectProfileList(
  db: Executor,
  project: { id: string; organizationId: string },
): Promise<z.infer<typeof projectProfileSchema>[]> {
  const all = await db
    .select()
    .from(qualityProfiles)
    .where(eq(qualityProfiles.organizationId, project.organizationId));
  const chosen = await db
    .select()
    .from(projectProfiles)
    .where(eq(projectProfiles.projectId, project.id));
  return PROFILE_LANGUAGES.map((language) => {
    const own = chosen.find((c) => c.language === language);
    const ownProfile = own && all.find((p) => p.id === own.profileId);
    const profile = ownProfile ?? all.find((p) => p.language === language && p.isDefault);
    return {
      language,
      profile: profile ? profileDto(profile) : null,
      source: ownProfile ? ('project' as const) : ('default' as const),
    };
  });
}

export const profileRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  /** rbac-audit.md §8, §9: one event about `profile`, written in the change's transaction `tx`. */
  const audit = async <A extends AuditAction>(
    tx: Executor,
    request: FastifyRequest,
    profile: Pick<ProfileRow, 'id' | 'organizationId' | 'name'>,
    action: A,
    details: AuditDetails<A>,
  ): Promise<void> => {
    if (!deps.audit.active()) return;
    const event = {
      action,
      organization: await organizationRef(tx, profile.organizationId),
      target: { type: 'quality_profile', id: profile.id, label: profile.name },
      details,
    } as AuditEventInput;
    await deps.audit.record(tx, actorOf(request), [event]);
  };

  app.get(
    '/quality-profiles',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['profiles'],
        summary: 'Quality profiles of an organisation, optionally of one language',
        querystring: z.strictObject({
          ...pageQuery,
          organizationId: z.uuid(),
          language: z.enum(PROFILE_LANGUAGES).optional(),
        }),
        response: { 200: pageSchema(profileSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { organizationId, language, limit, cursor } = request.query;
      const after = decodeCursor(cursor);
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.read');
      const rows = await deps.db
        .select()
        .from(qualityProfiles)
        .where(
          and(
            eq(qualityProfiles.organizationId, organizationId),
            language === undefined ? undefined : eq(qualityProfiles.language, language),
            after ? gt(qualityProfiles.id, after) : undefined,
          ),
        )
        .orderBy(asc(qualityProfiles.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return { items: page.items.map(profileDto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/quality-profiles',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['profiles'],
        summary: 'Create an empty profile, optionally inheriting from a parent',
        body: z.strictObject({
          organizationId: z.uuid(),
          name: profileName,
          language: z.enum(PROFILE_LANGUAGES),
          parentId: z.uuid().optional(),
        }),
        response: { 201: profileSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const { organizationId, name, language, parentId } = request.body;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.profiles.manage',
      );
      requireUnreservedName(name);
      try {
        const created = await deps.db.transaction(async (tx) => {
          await requireProfileRoom(tx, organizationId);
          const siblings = await lockLanguage(tx, organizationId, language);
          if (parentId !== undefined) requireValidParent(siblings, parentId);
          const row = first(
            await tx
              .insert(qualityProfiles)
              .values({ organizationId, name, language, parentId: parentId ?? null })
              .returning(),
          );
          await audit(tx, request, row, 'quality_profile.created', {
            name: row.name,
            language: row.language,
          });
          return row;
        });
        return reply.code(201).send(profileDto(created));
      } catch (err) {
        return uniqueConflict(err);
      }
    },
  );

  app.get(
    '/quality-profiles/:id',
    {
      schema: {
        tags: ['profiles'],
        summary: 'A quality profile',
        params: idParams,
        response: { 200: profileSchema },
      },
    },
    async (request) =>
      profileDto(
        await profileFor(accessOf(deps), requireUser(request), request.params.id, 'org.read'),
      ),
  );

  app.patch(
    '/quality-profiles/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary:
          'Rename a profile or change what it does with unknown rules (the parent is fixed; built-in: 409)',
        params: idParams,
        body: z
          .strictObject({
            name: profileName.optional(),
            unknownRules: z.enum(['activate', 'ignore']).optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: profileSchema },
      },
    },
    async (request) => {
      const profile = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      requireEditableProfile(profile);
      if (request.body.name !== undefined) requireUnreservedName(request.body.name);
      let updated: ProfileRow | undefined;
      try {
        updated = await deps.db.transaction(async (tx) => {
          const [row] = await tx
            .update(qualityProfiles)
            .set(request.body)
            .where(eq(qualityProfiles.id, profile.id))
            .returning();
          if (!row) return undefined;
          const changes = QUALITY_PROFILE_CHANGE_FIELDS.filter((f) => row[f] !== profile[f]).map(
            (field) => ({ field, from: profile[field], to: row[field] }),
          );
          if (changes.length > 0) {
            await audit(tx, request, row, 'quality_profile.updated', { changes });
          }
          return row;
        });
      } catch (err) {
        return uniqueConflict(err);
      }
      // Deleted concurrently, between the check above and this update.
      if (!updated) throw notFound('Quality profile');
      return profileDto(updated);
    },
  );

  app.delete(
    '/quality-profiles/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary:
          'Delete a profile; its projects fall back to the default, a deleted default hands over to the built-in (built-in or with children: 409)',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const profile = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      requireEditableProfile(profile);
      const hasChildren = () =>
        conflict(
          'PROFILE_HAS_CHILDREN',
          'Other profiles inherit from this one; delete or re-create them first',
        );
      try {
        await deps.db.transaction(async (tx) => {
          const siblings = await lockLanguage(tx, profile.organizationId, profile.language);
          const current = siblings.find((p) => p.id === profile.id);
          if (!current) throw notFound('Quality profile');
          if (siblings.some((p) => p.parentId === profile.id)) throw hasChildren();
          const own = await tx
            .select({ ruleId: profileRules.ruleId })
            .from(profileRules)
            .where(eq(profileRules.profileId, profile.id));
          await tx.delete(qualityProfiles).where(eq(qualityProfiles.id, profile.id));
          await removeBareRules(
            tx,
            own.map((r) => r.ruleId),
          );
          // Ruling F2: the language never ends up without a default; the built-in takes over.
          const builtin = siblings.find((p) => p.isBuiltin);
          if (current.isDefault && builtin) {
            await tx
              .update(qualityProfiles)
              .set({ isDefault: true })
              .where(eq(qualityProfiles.id, builtin.id));
          }
          await audit(tx, request, current, 'quality_profile.deleted', {
            name: current.name,
            language: current.language,
          });
        });
      } catch (err) {
        // A child created while this call waited on the language lock is not in the lock
        // statement's snapshot, so the check above misses it; the parent's RESTRICT foreign key
        // does not, and names the constraint.
        if (isForeignKeyViolation(pgErrorCode(err)) && pgConstraint(err) === PARENT_FOREIGN_KEY) {
          throw hasChildren();
        }
        throw err;
      }
      return reply.code(204).send();
    },
  );

  app.post(
    '/quality-profiles/:id/copy',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary: 'Copy a profile with its rule settings (the way to edit a built-in one)',
        params: idParams,
        body: z.strictObject({ name: profileName }),
        response: { 201: profileSchema },
      },
    },
    async (request, reply) => {
      const source = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      requireUnreservedName(request.body.name);
      try {
        const copy = await deps.db.transaction(async (tx) => {
          await requireProfileRoom(tx, source.organizationId);
          // Serialises with a delete of the source or of its parent (see lockLanguage).
          const siblings = await lockLanguage(tx, source.organizationId, source.language);
          const current = siblings.find((p) => p.id === source.id);
          if (!current) throw notFound('Quality profile');
          const created = first(
            await tx
              .insert(qualityProfiles)
              .values({
                organizationId: current.organizationId,
                name: request.body.name,
                language: current.language,
                parentId: current.parentId,
                unknownRules: current.unknownRules,
              })
              .returning(),
          );
          const rows = await tx
            .select()
            .from(profileRules)
            .where(eq(profileRules.profileId, current.id));
          if (rows.length > 0) {
            await tx.insert(profileRules).values(
              rows.map((r) => ({
                profileId: created.id,
                ruleId: r.ruleId,
                active: r.active,
                severityOverride: r.severityOverride,
              })),
            );
          }
          await audit(tx, request, created, 'quality_profile.copied', {
            sourceId: current.id,
            name: created.name,
            language: created.language,
          });
          return created;
        });
        return reply.code(201).send(profileDto(copy));
      } catch (err) {
        return uniqueConflict(err);
      }
    },
  );

  app.post(
    '/quality-profiles/:id/set-default',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary: "Make this the organisation's default profile for its language",
        params: idParams,
        response: { 200: profileSchema },
      },
    },
    async (request) => {
      const profile = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      try {
        const updated = await deps.db.transaction(async (tx) => {
          // Concurrent calls queue on these row locks; each then clears the flag the previous
          // one set, so the language always ends with exactly one default (the last call's).
          await lockLanguage(tx, profile.organizationId, profile.language);
          await tx
            .update(qualityProfiles)
            .set({ isDefault: false })
            .where(
              and(
                eq(qualityProfiles.organizationId, profile.organizationId),
                eq(qualityProfiles.language, profile.language),
                eq(qualityProfiles.isDefault, true),
              ),
            );
          const [row] = await tx
            .update(qualityProfiles)
            .set({ isDefault: true })
            .where(eq(qualityProfiles.id, profile.id))
            .returning();
          if (!row) throw notFound('Quality profile');
          await audit(tx, request, row, 'quality_profile.default_set', {
            name: row.name,
            language: row.language,
          });
          return row;
        });
        return profileDto(updated);
      } catch (err) {
        return uniqueConflict(err);
      }
    },
  );

  app.get(
    '/quality-profiles/:id/rules',
    {
      schema: {
        tags: ['profiles'],
        summary:
          'The rules this profile governs, with the effective activation (inheritance resolved)',
        params: idParams,
        querystring: z.strictObject({
          limit: z.coerce.number().int().min(1).max(500).default(50),
          cursor: z.string().max(1_024).optional(),
          active: z.enum(['true', 'false']).optional(),
          q: ruleQuery,
          /** `default`: ruling P4's set plus the rules set in the chain; `all`: all it decides. */
          scope: z.enum(['default', 'all']).default('default'),
        }),
        response: {
          200: z.object({ items: z.array(profileRuleSchema), nextCursor: z.string().nullable() }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { limit, cursor, active, q, scope } = request.query;
      const after = afterRuleKey(cursor);
      const profile = await profileFor(accessOf(deps), principal, request.params.id, 'org.read');
      const rows = await effectiveRules(deps.db, profile, [after, ruleSearch(q)], {
        active: active === undefined ? undefined : active === 'true',
        scope,
        limit: limit + 1,
      });
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return {
        items: items.map((r) => profileRuleDto(profile, r)),
        nextCursor: rows.length > limit && last ? ruleCursorOf(last.rule.key) : null,
      };
    },
  );

  app.put(
    '/quality-profiles/:id/rules/:ruleKey',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary: 'Activate or deactivate a rule in this profile, optionally with a severity',
        params: ruleParams,
        body: z.strictObject({
          active: z.boolean(),
          severityOverride: z.enum(SEVERITIES).nullable().optional(),
        }),
        response: { 200: profileRuleSchema },
      },
    },
    async (request) => {
      const profile = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      requireEditableProfile(profile);
      const key = request.params.ruleKey;
      const parsed = requireGovernable(profile, key);
      const bare = bareRule(parsed, key);
      const active = request.body.active;
      const severityOverride = request.body.severityOverride ?? null;
      const rule = await deps.db.transaction(async (tx) => {
        // Serialises the rule settings of this profile, so the bound below holds; waits for a
        // delete of the profile, and finds it gone after.
        const [locked] = await tx
          .select({ id: qualityProfiles.id })
          .from(qualityProfiles)
          .where(eq(qualityProfiles.id, profile.id))
          .for('no key update');
        if (!locked) {
          throw conflict(
            'CONFLICT',
            'The request refers to something that was changed or deleted concurrently',
          );
        }
        const [own] = await tx
          .select({ ruleId: profileRules.ruleId })
          .from(profileRules)
          .innerJoin(rules, eq(rules.id, profileRules.ruleId))
          .where(and(eq(profileRules.profileId, profile.id), eq(rules.key, key)));
        if (!own) {
          const [set] = await tx
            .select({ n: count() })
            .from(profileRules)
            .where(eq(profileRules.profileId, profile.id));
          if ((set?.n ?? 0) >= MAX_RULES_PER_PROFILE) {
            throw conflict(
              'PROFILE_RULE_LIMIT_REACHED',
              `A profile sets at most ${MAX_RULES_PER_PROFILE} rules itself`,
            );
          }
        }
        // Ruling X5: a rule no report has named yet is created as ingestion's bare path creates
        // it (no lock on an existing row), so an admin can decide a rule before it is first
        // reported, or one an `unknownRules: ignore` profile keeps filtering out. The rule is then
        // held FOR KEY SHARE, so a concurrent cleanup (removeBareRules, SKIP LOCKED) leaves it;
        // one that locked it first and deleted it makes the lookup miss, and it is created again.
        // Whether the organisation had met the rule (ruling X2) is read before its row below
        // makes it visible: a rule only another organisation reported answers exactly like a new
        // one.
        let found: { row: RuleRow; visible: boolean } | undefined;
        for (let attempt = 0; attempt < 3 && !found; attempt++) {
          await tx
            .insert(rules)
            .values({
              key,
              engineId: bare.engineId,
              engineRuleId: parsed.engineRuleId,
              name: bare.name,
              defaultSeverity: bare.defaultSeverity,
              quality: bare.quality,
              kind: bare.kind,
              origin: 'reported',
            })
            .onConflictDoNothing({ target: rules.key });
          [found] = await tx
            .select({
              row: rules,
              visible: sql<boolean>`${ruleVisibleTo(profile.organizationId)}`,
            })
            .from(rules)
            .where(eq(rules.key, key))
            .for('key share', { of: rules });
        }
        if (!found) throw notFound('Rule');
        // One upsert: concurrent PUTs of one rule never collide on the primary key.
        await tx
          .insert(profileRules)
          .values({ profileId: profile.id, ruleId: found.row.id, active, severityOverride })
          .onConflictDoUpdate({
            target: [profileRules.profileId, profileRules.ruleId],
            set: { active, severityOverride },
          });
        await audit(tx, request, profile, 'quality_profile.rule_set', {
          ruleKey: key,
          active,
          severityOverride,
        });
        return found;
      });
      return profileRuleDto(profile, {
        rule: rule.visible ? rule.row : bare,
        rowActive: active,
        severityOverride,
        sourceProfileId: profile.id,
      });
    },
  );

  app.delete(
    '/quality-profiles/:id/rules/:ruleKey',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary: "Remove this profile's own setting for a rule (it inherits again)",
        params: ruleParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const profile = await profileFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.profiles.manage',
      );
      requireEditableProfile(profile);
      requireGovernable(profile, request.params.ruleKey);
      // 204 whether or not there was a row, or a rule: a rule the organisation has not met has no
      // row in its profiles, so nothing tells an unknown key from another organisation's rule.
      await deps.db.transaction(async (tx) => {
        const removed = await tx
          .delete(profileRules)
          .where(
            and(
              eq(profileRules.profileId, profile.id),
              eq(
                profileRules.ruleId,
                tx
                  .select({ id: rules.id })
                  .from(rules)
                  .where(eq(rules.key, request.params.ruleKey)),
              ),
            ),
          )
          .returning({ ruleId: profileRules.ruleId });
        await removeBareRules(
          tx,
          removed.map((r) => r.ruleId),
        );
        if (removed.length > 0) {
          await audit(tx, request, profile, 'quality_profile.rule_reset', {
            ruleKey: request.params.ruleKey,
          });
        }
      });
      return reply.code(204).send();
    },
  );

  app.get(
    '/projects/:id/quality-profiles',
    {
      schema: {
        tags: ['profiles'],
        summary: 'The quality profile each language of the project uses',
        params: idParams,
        response: { 200: z.array(projectProfileSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.read',
      );
      return projectProfileList(deps.db, project);
    },
  );

  app.put(
    '/projects/:id/quality-profiles/:language',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['profiles'],
        summary:
          "Use this profile for one language of the project (null: back to the organisation's default); applies from the next analysis",
        params: z.strictObject({ id: z.uuid(), language: z.enum(PROFILE_LANGUAGES) }),
        body: z.strictObject({ profileId: z.uuid().nullable() }),
        response: { 200: projectProfileSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.settings',
      );
      const { language } = request.params;
      const { profileId } = request.body;
      const own = and(
        eq(projectProfiles.projectId, project.id),
        eq(projectProfiles.language, language),
      );
      // rbac-audit.md §8: `project.profile_assigned` when the project's own choice changed, in the
      // change's transaction (the previous choice read under the row's lock).
      const assign = async (write: (tx: Executor) => Promise<unknown>) =>
        deps.db.transaction(async (tx) => {
          const [before] = await tx
            .select({ profileId: projectProfiles.profileId })
            .from(projectProfiles)
            .where(own)
            .for('update');
          await write(tx);
          const from = before?.profileId ?? null;
          if (from === profileId || !deps.audit.active()) return;
          const refs = await projectRefs(tx, project.id);
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project.profile_assigned',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'project', id: project.id, label: refs.project.key },
              details: { language, from, to: profileId },
            },
          ]);
        });
      if (profileId === null) {
        await assign((tx) => tx.delete(projectProfiles).where(own));
      } else {
        // A profile's organisation and language never change, so this check cannot go stale; a
        // profile deleted in between is a foreign-key violation on the upsert (409 CONFLICT).
        const [profile] = await deps.db
          .select({ id: qualityProfiles.id })
          .from(qualityProfiles)
          .where(
            and(
              eq(qualityProfiles.id, profileId),
              eq(qualityProfiles.organizationId, project.organizationId),
              eq(qualityProfiles.language, language),
            ),
          );
        if (!profile) {
          throw validationFailed([
            {
              path: 'body.profileId',
              message: `No ${language} profile of the project's organisation has this id`,
            },
          ]);
        }
        await assign((tx) =>
          tx
            .insert(projectProfiles)
            .values({ projectId: project.id, language, profileId })
            .onConflictDoUpdate({
              target: [projectProfiles.projectId, projectProfiles.language],
              set: { profileId },
            }),
        );
      }
      const list = await projectProfileList(deps.db, project);
      const entry = list.find((e) => e.language === language);
      if (!entry) throw notFound('Quality profile');
      return entry;
    },
  );
};
