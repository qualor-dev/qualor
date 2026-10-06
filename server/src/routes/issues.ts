import { ISSUE_KINDS, QUALITIES, ruleHelpUri, SEVERITIES, secondaryLocation } from '@qualor/shared';
import { and, asc, eq, gt } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireUser } from '../auth/access';
import { first } from '../db/rows';
import { issueChanges, rules, users } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, forbidden, notFound, ProblemError, validationFailed } from '../http/problem';
import { idParams, iso, isoOrNull, noNul, text, timestamp } from '../http/schemas';
import {
  ISSUE_FACETS,
  ISSUE_SORTS,
  ISSUE_STATUSES,
  issueFacets,
  issueSortPlan,
  listIssues,
  type IssueFacet,
  type IssueFilters,
  type IssueListRow,
} from '../issues/query';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import { overrideSeverity } from '../issues/severity';
import {
  ownCommentMax,
  provenanceLine,
  triageSuggestionFor,
  withProvenance,
} from '../llm/provenance';
import {
  commentRequired,
  transitionIssues,
  USER_STATUSES,
  type UserStatus,
} from '../issues/transitions';
import { branchForUser, issueForUser, type IssueRow } from '../projects/access';
import type { IssueStatus } from '../tracking/plan';

export const issueStatusSchema = z.enum(ISSUE_STATUSES);

export const issueSchema = z.object({
  id: z.uuid(),
  projectId: z.uuid(),
  branchId: z.uuid(),
  rule: z.object({ key: z.string(), name: z.string(), engine: z.string() }),
  severity: z.enum(SEVERITIES),
  severityOverridden: z.boolean(),
  quality: z.enum(QUALITIES),
  kind: z.enum(ISSUE_KINDS),
  status: issueStatusSchema,
  message: z.string(),
  path: z.string().nullable(),
  startLine: z.number().int().nullable(),
  startColumn: z.number().int().nullable(),
  endLine: z.number().int().nullable(),
  endColumn: z.number().int().nullable(),
  inNewCode: z.boolean(),
  duplicateOfIssueId: z.uuid().nullable(),
  firstSeenAt: timestamp,
  resolvedAt: timestamp.nullable(),
  closedAt: timestamp.nullable(),
  createdAt: timestamp,
  updatedAt: timestamp,
});
export type IssueDto = z.infer<typeof issueSchema>;

export const issueDetailSchema = issueSchema.extend({
  rule: z.object({
    key: z.string(),
    name: z.string(),
    engine: z.string(),
    descriptionMd: z.string().nullable(),
    helpUri: z.string().nullable(),
    defaultSeverity: z.enum(SEVERITIES),
    quality: z.enum(QUALITIES),
    kind: z.enum(ISSUE_KINDS),
    tags: z.array(z.string()),
    cwe: z.array(z.number().int()),
  }),
  fingerprint: z.string(),
  snippet: z.unknown(),
  secondaryLocations: z.array(secondaryLocation),
  firstSeenAnalysisId: z.uuid().nullable(),
  lastSeenAnalysisId: z.uuid().nullable(),
  resolvedBy: z.object({ id: z.uuid(), username: z.string() }).nullable(),
});

const changeSchema = z.object({
  id: z.uuid(),
  user: z.object({ id: z.uuid(), username: z.string() }).nullable(),
  analysisId: z.uuid().nullable(),
  field: z.enum(['status', 'severity', 'comment']),
  oldValue: z.string().nullable(),
  newValue: z.string().nullable(),
  comment: z.string().nullable(),
  createdAt: timestamp,
});

/** data-model.md §6: at most 2 000 characters (issue_changes_comment_length), no U+0000. */
const commentField = noNul(z.string().max(2_000)).optional();
const transitionBody = { to: z.enum(USER_STATUSES), comment: commentField };
/** api.md §3: a bulk transition names at most this many issues. */
const BULK_TRANSITION_MAX_IDS = 500;

/** A blank comment is no comment; 422 COMMENT_REQUIRED where §6 requires one. */
function transitionComment(to: UserStatus, raw: string | undefined): string | null {
  const comment = raw?.trim() ? raw.trim() : null;
  if (comment === null && commentRequired(to)) {
    throw new ProblemError(422, 'COMMENT_REQUIRED', `A comment is required to set ${to}`, {
      errors: [{ path: 'body.comment', message: `Required for ${to}` }],
    });
  }
  return comment;
}

const facetValues = z.array(z.object({ value: z.string(), count: z.number().int() }));

/** A repeatable query parameter: `?status=open&status=resolved` or a single `?status=open`. */
function many<T extends z.ZodType>(item: T, max: number) {
  return z.union([item, z.array(item).min(1).max(max)]).optional();
}

function list<T>(value: T | T[] | undefined): T[] | undefined {
  if (value === undefined) return undefined;
  return [...new Set(Array.isArray(value) ? value : [value])];
}

const booleanParam = z.enum(['true', 'false']).optional();

export const issueListQuery = z.strictObject({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  cursor: z.string().max(8_192).optional(),
  branchId: z.uuid(),
  status: many(issueStatusSchema, ISSUE_STATUSES.length),
  severity: many(z.enum(SEVERITIES), SEVERITIES.length),
  quality: many(z.enum(QUALITIES), QUALITIES.length),
  kind: many(z.enum(ISSUE_KINDS), ISSUE_KINDS.length),
  rule: many(text(512), 50),
  engine: many(text(64), 20),
  path: many(text(1_024), 20),
  inNewCode: booleanParam,
  q: noNul(z.string().trim().min(1).max(200)).optional(),
  includeDuplicates: booleanParam,
  sort: z.enum(ISSUE_SORTS).default('severity'),
  facets: z.string().max(200).optional(),
});
type IssueListQuery = z.infer<typeof issueListQuery>;

export function filtersFrom(query: IssueListQuery): IssueFilters {
  return {
    branchId: query.branchId,
    statuses: list(query.status) ?? ['open'],
    severities: list(query.severity),
    qualities: list(query.quality),
    kinds: list(query.kind),
    ruleKeys: list(query.rule),
    engines: list(query.engine),
    pathPrefixes: list(query.path),
    inNewCode: query.inNewCode === undefined ? undefined : query.inNewCode === 'true',
    q: query.q,
    includeDuplicates: query.includeDuplicates === 'true',
  };
}

/** `?facets=severity,rule` → the distinct facet names; anything else is a 422. */
export function facetList(raw: string | undefined): IssueFacet[] {
  if (raw === undefined) return [];
  const names = [...new Set(raw.split(',').map((s) => s.trim()))];
  const unknown = names.filter((n) => !(ISSUE_FACETS as readonly string[]).includes(n));
  if (unknown.length > 0) {
    throw validationFailed([
      { path: 'query.facets', message: `Unknown facet: ${unknown.join(', ')}` },
    ]);
  }
  return names as IssueFacet[];
}

export function issueDto(row: IssueListRow): IssueDto {
  return {
    id: row.id,
    projectId: row.projectId,
    branchId: row.branchId,
    rule: { key: row.ruleKey, name: row.ruleName, engine: row.engineId },
    severity: row.severity as IssueDto['severity'],
    severityOverridden: row.severityOverridden,
    quality: row.quality as IssueDto['quality'],
    kind: row.kind as IssueDto['kind'],
    status: row.status as IssueStatus,
    message: row.message,
    path: row.path,
    startLine: row.startLine,
    startColumn: row.startColumn,
    endLine: row.endLine,
    endColumn: row.endColumn,
    inNewCode: row.inNewCode,
    duplicateOfIssueId: row.duplicateOfIssueId,
    firstSeenAt: iso(row.firstSeenAt),
    resolvedAt: isoOrNull(row.resolvedAt),
    closedAt: isoOrNull(row.closedAt),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

export const issueRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the AI routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  // scm.md §7, ruling G7: each issue a transition or severity override names costs its user one
  // change; checked before anything is read or written.
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  /** The full issue (snippet, secondary locations, rule summary), after the access check. */
  const detail = async (issue: IssueRow): Promise<z.infer<typeof issueDetailSchema>> => {
    const rule = first(await deps.db.select().from(rules).where(eq(rules.id, issue.ruleId)));
    const [resolver] = issue.resolvedBy
      ? await deps.db
          .select({ id: users.id, username: users.username })
          .from(users)
          .where(eq(users.id, issue.resolvedBy))
      : [];
    return {
      ...issueDto({
        ...issue,
        ruleKey: rule.key,
        ruleName: rule.name,
        engineId: rule.engineId,
      }),
      rule: {
        key: rule.key,
        name: rule.name,
        engine: rule.engineId,
        descriptionMd: rule.descriptionMd,
        helpUri: ruleHelpUri(rule.key, rule.helpUri),
        defaultSeverity: rule.defaultSeverity as IssueDto['severity'],
        quality: rule.quality as IssueDto['quality'],
        kind: rule.kind,
        tags: rule.tags,
        cwe: rule.cwe,
      },
      fingerprint: issue.fingerprint,
      snippet: issue.snippet ?? null,
      secondaryLocations: issue.secondaryLocations as z.infer<typeof secondaryLocation>[],
      firstSeenAnalysisId: issue.firstSeenAnalysisId,
      lastSeenAnalysisId: issue.lastSeenAnalysisId,
      resolvedBy: resolver ?? null,
    };
  };

  app.get(
    '/issues',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['issues'],
        summary: 'Issues of a branch: repeatable filters, keyset pages, optional facets',
        querystring: issueListQuery,
        response: {
          200: z.object({
            items: z.array(issueSchema),
            nextCursor: z.string().nullable(),
            facets: z.partialRecord(z.enum(ISSUE_FACETS), facetValues).optional(),
          }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const facets = facetList(request.query.facets);
      // The cursor is checked before any query runs: a bad one is a 422 that costs no facets.
      const plan = issueSortPlan(request.query.sort, request.query.cursor);
      await branchForUser(accessOf(deps), principal, request.query.branchId, 'project.read');
      const filters = filtersFrom(request.query);
      const [page, counts] = await Promise.all([
        listIssues(deps.db, filters, { plan, limit: request.query.limit }),
        facets.length > 0 ? issueFacets(deps.db, filters, facets) : undefined,
      ]);
      return {
        items: page.items.map(issueDto),
        nextCursor: page.nextCursor,
        ...(counts === undefined ? {} : { facets: counts }),
      };
    },
  );

  app.get(
    '/issues/:id',
    {
      schema: {
        tags: ['issues'],
        summary: 'One issue with its snippet, secondary locations and rule summary',
        params: idParams,
        response: { 200: issueDetailSchema },
      },
    },
    async (request) =>
      detail(
        await issueForUser(accessOf(deps), requireUser(request), request.params.id, 'project.read'),
      ),
  );
  app.post(
    '/issues/:id/transition',
    {
      config: {
        openapi: {
          problems: [409, 429, 503],
          problemDescriptions: {
            409: 'The transition is not allowed from the current status (INVALID_TRANSITION)',
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
            422: 'Validation failed (VALIDATION_FAILED; also a suggestionId that is not a succeeded AI triage suggestion of this issue), or a required comment is missing (COMMENT_REQUIRED)',
            503: 'The issue stayed locked by an ingestion (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary:
          'Change the status (open, resolved, wont_fix, false_positive); mirrored onto duplicates',
        params: idParams,
        body: z.strictObject({ ...transitionBody, suggestionId: z.uuid().optional() }),
        response: { 200: issueDetailSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      let comment = transitionComment(request.body.to, request.body.comment);
      if (request.body.suggestionId !== undefined) {
        // llm.md §7, a person accepts (or not) an AI triage suggestion; the model never
        // changes the issue. The issue is looked up as this person first (404 as without it), so
        // a suggestion id never tells anything about an issue they cannot see.
        await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage');
        const suggestion = await triageSuggestionFor(
          deps.db,
          request.params.id,
          request.body.suggestionId,
        );
        if (!suggestion) {
          throw validationFailed([
            {
              path: 'body.suggestionId',
              message: 'Not a succeeded AI triage suggestion of this issue',
            },
          ]);
        }
        const line = provenanceLine(suggestion.row, suggestion.result, principal.user.username);
        const max = ownCommentMax(line);
        if ((comment ?? '').length > max) {
          throw validationFailed([
            { path: 'body.comment', message: `At most ${max} characters with a suggestion` },
          ]);
        }
        comment = withProvenance(comment, line);
      }
      chargeChanges(principal.user.id, 1);
      const result = await transitionIssues(
        accessOf(deps),
        principal,
        [request.params.id],
        request.body.to,
        comment,
        {
          audit: {
            recorder: deps.audit,
            context: actorOf(request),
            bulk: false,
            suggestionId: request.body.suggestionId ?? null,
          },
        },
      );
      const [failure] = result.failed;
      if (failure?.code === 'NOT_FOUND') throw notFound('Issue');
      if (failure?.code === 'FORBIDDEN')
        throw forbidden('FORBIDDEN', 'Your role does not allow this');
      if (failure) {
        throw conflict(
          'INVALID_TRANSITION',
          `An issue cannot go from ${failure.from ?? 'its status'} to ${request.body.to}`,
        );
      }
      return detail(
        await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage'),
      );
    },
  );

  app.post(
    '/issues/bulk-transition',
    {
      config: {
        openapi: {
          problems: [429, 503],
          problemDescriptions: {
            422: 'Validation failed (VALIDATION_FAILED), or a required comment is missing (COMMENT_REQUIRED)',
            429: 'Too many issue changes by this user, one per id (RATE_LIMITED); see Retry-After',
            503: 'An issue stayed locked by an ingestion (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary: 'Change the status of up to 500 issues; each one succeeds or fails on its own',
        body: z.strictObject({
          ids: z.array(z.uuid()).min(1).max(BULK_TRANSITION_MAX_IDS),
          ...transitionBody,
        }),
        response: {
          200: z.object({
            succeeded: z.array(z.uuid()),
            failed: z.array(
              z.object({
                id: z.uuid(),
                code: z.enum(['NOT_FOUND', 'FORBIDDEN', 'INVALID_TRANSITION']),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const comment = transitionComment(request.body.to, request.body.comment);
      // One change per distinct issue: naming an id twice changes it once.
      chargeChanges(principal.user.id, new Set(request.body.ids).size);
      const result = await transitionIssues(
        accessOf(deps),
        principal,
        request.body.ids,
        request.body.to,
        comment,
        {
          audit: {
            recorder: deps.audit,
            context: actorOf(request),
            bulk: true,
            suggestionId: null,
          },
        },
      );
      return {
        succeeded: result.succeeded,
        failed: result.failed.map((f) => ({ id: f.id, code: f.code })),
      };
    },
  );

  app.patch(
    '/issues/:id',
    {
      config: {
        openapi: {
          problems: [429, 503],
          problemDescriptions: {
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary: 'Override the severity (recorded in the changelog)',
        params: idParams,
        body: z.strictObject({ severity: z.enum(SEVERITIES) }),
        response: { 200: issueDetailSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      chargeChanges(principal.user.id, 1);
      await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage');
      const updated = await overrideSeverity(
        deps.db,
        principal.user,
        request.params.id,
        request.body.severity,
        { recorder: deps.audit, context: actorOf(request) },
      );
      if (!updated) throw notFound('Issue');
      return detail(updated);
    },
  );

  app.get(
    '/issues/:id/changelog',
    {
      schema: {
        tags: ['issues'],
        summary: 'Status and severity changes, oldest first',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(changeSchema) },
      },
    },
    async (request) => {
      const issue = await issueForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select({ change: issueChanges, username: users.username })
        .from(issueChanges)
        .leftJoin(users, eq(users.id, issueChanges.userId))
        .where(
          and(eq(issueChanges.issueId, issue.id), after ? gt(issueChanges.id, after) : undefined),
        )
        .orderBy(asc(issueChanges.id))
        .limit(request.query.limit + 1);
      const page = toPage(
        rows.map((r) => ({ ...r, id: r.change.id })),
        request.query.limit,
      );
      return {
        items: page.items.map(({ change, username }) => ({
          id: change.id,
          user:
            change.userId !== null && username !== null ? { id: change.userId, username } : null,
          analysisId: change.analysisId,
          field: change.field,
          oldValue: change.oldValue,
          newValue: change.newValue,
          comment: change.comment,
          createdAt: iso(change.createdAt),
        })),
        nextCursor: page.nextCursor,
      };
    },
  );
};
