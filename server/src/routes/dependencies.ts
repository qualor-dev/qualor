import {
  LICENSE_GROUPS,
  licenseClassifier,
  type LicenseGroupId,
  type LicensePolicy,
  type LicenseVerdict,
} from '@qualor/shared';
import { and, eq, type SQL } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireUser } from '../auth/access';
import { branches, projectVersions } from '../db/schema';
import {
  dependencySummary,
  hasInventory,
  listAllDependencies,
  listDependencies,
  type DependencyFilter,
  type DependencyTarget,
  type DependencyRow,
} from '../dependencies/query';
import { notFound } from '../http/problem';
import { idParams, noNul, text } from '../http/schemas';
import { policyFor } from '../licenses/settings';
import { projectForUser } from '../projects/access';

const GROUP_IDS = LICENSE_GROUPS.map((g) => g.id) as [LicenseGroupId, ...LicenseGroupId[]];
const booleanParam = z.enum(['true', 'false']).optional();
const VERDICTS = ['allowed', 'forbidden', 'unknown'] as const satisfies readonly LicenseVerdict[];

/** One inventory entry. */
const dependencySchema = z.object({
  ecosystem: z.string(),
  /** The lockfile or manifest, repo-relative. */
  path: z.string(),
  line: z.number().int().nullable(),
  name: z.string(),
  version: z.string(),
  /** SPDX ids or expressions as the scanner normalised them; `[]` means unknown. */
  licenses: z.array(z.string()),
  /** `null`: the scanner did not say. */
  direct: z.boolean().nullable(),
  /**
   * The organisation licence policy's verdict (6M §8): present when `verdicts` is true, that is
   * while the enterprise feature license-policy is active and the organisation has a policy.
   */
  verdict: z.enum(VERDICTS).optional(),
});

const summarySchema = z.object({
  total: z.number().int(),
  known: z.number().int(),
  unknown: z.number().int(),
  /** The 20 most frequent licence strings. */
  byLicense: z.array(z.object({ license: z.string(), count: z.number().int() })),
});

const responseSchema = z.object({
  rows: z.array(dependencySchema),
  page: z.number().int(),
  pageSize: z.number().int(),
  /** Entries matching the filters. */
  total: z.number().int(),
  /** The whole inventory of the branch or version, whatever the filters. */
  summary: summarySchema,
  /** `false`: no analysis of the branch has reported a dependency inventory yet. */
  inventory: z.boolean(),
  /**
   * The rows carry the policy's `verdict`, and the `verdict` filter applies: the enterprise
   * feature license-policy is active and the project's organisation has a licence policy.
   */
  verdicts: z.boolean(),
});

const querySchema = z
  .strictObject({
    /** A branch by name; the main branch when neither `branch` nor `mr` is given. */
    branch: text(255).optional(),
    /** A merge request by its number. */
    mr: z.coerce.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    /** A released version of the project (`GET /projects/{id}/versions`); not with `branch` or `mr`. */
    version: z.uuid().optional(),
    license: text(256).optional(),
    group: z.enum(GROUP_IDS).optional(),
    ecosystem: z
      .string()
      .regex(/^[a-z0-9-]{1,32}$/)
      .optional(),
    unknown: booleanParam,
    direct: booleanParam,
    q: noNul(z.string().trim().min(1).max(200)).optional(),
    verdict: z.enum(VERDICTS).optional().meta({
      description:
        "Entries with this verdict of the organisation's licence policy; ignored (every entry matches) while the answer's `verdicts` is false",
    }),
    page: z.coerce.number().int().min(1).max(100_000).default(1),
    pageSize: z.coerce.number().int().min(1).max(500).default(50),
  })
  .refine((q) => q.branch === undefined || q.mr === undefined, {
    message: 'Give branch or mr, not both',
    path: ['mr'],
  })
  .refine((q) => q.version === undefined || (q.branch === undefined && q.mr === undefined), {
    message: 'Give version, or branch or mr, not both',
    path: ['version'],
  });

const EMPTY_SUMMARY = { total: 0, known: 0, unknown: 0, byLicense: [] };

type DependencyQuery = z.infer<typeof querySchema>;

/** The branch the query names: the merge request, the branch, or else the main branch. */
function branchOfQuery(query: DependencyQuery): SQL | undefined {
  if (query.mr !== undefined) {
    return and(eq(branches.kind, 'merge_request'), eq(branches.name, String(query.mr)));
  }
  if (query.branch !== undefined) {
    return and(eq(branches.kind, 'branch'), eq(branches.name, query.branch));
  }
  return eq(branches.isMain, true);
}

/** The inventory filter of the query's filter parameters, each one given. */
function filterOfQuery(query: DependencyQuery): DependencyFilter {
  return {
    ...(query.license !== undefined && { license: query.license }),
    ...(query.group !== undefined && { group: query.group }),
    ...(query.ecosystem !== undefined && { ecosystem: query.ecosystem }),
    ...(query.unknown !== undefined && { unknown: query.unknown === 'true' }),
    ...(query.direct !== undefined && { direct: query.direct === 'true' }),
    ...(query.q !== undefined && { q: query.q }),
  };
}

/**
 * The policy's verdict on a row's licences: the policy prepared once, and each distinct set of
 * licences judged once (an inventory repeats a few licence sets many times).
 */
function verdictOf(policy: LicensePolicy): (row: DependencyRow) => LicenseVerdict {
  const judge = licenseClassifier(policy);
  const seen = new Map<string, LicenseVerdict>();
  return (row) => {
    const key = JSON.stringify(row.licenses);
    let verdict = seen.get(key);
    if (verdict === undefined) {
      verdict = judge(row.licenses).verdict;
      seen.set(key, verdict);
    }
    return verdict;
  };
}

/**
 * The inventory the query names: the version (`notFound('Version')` when it is not the project's),
 * or the branch, merge request or main branch; `null` when that branch does not exist (the caller
 * answers 404 for a named one).
 */
async function targetOf(
  deps: RouteDeps,
  projectId: string,
  query: DependencyQuery,
): Promise<DependencyTarget | null> {
  if (query.version !== undefined) {
    const [version] = await deps.db
      .select({ id: projectVersions.id })
      .from(projectVersions)
      .where(and(eq(projectVersions.id, query.version), eq(projectVersions.projectId, projectId)));
    if (!version) throw notFound('Version');
    return { kind: 'version', versionId: version.id };
  }
  const [branch] = await deps.db
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), branchOfQuery(query)));
  return branch ? { kind: 'branch', branchId: branch.id } : null;
}

export const dependencyRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  app.get(
    '/projects/:id/dependencies',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['dependencies'],
        summary:
          'The dependency inventory of a branch, merge request or released version (the main branch by default), filtered and paged',
        params: idParams,
        querystring: querySchema,
        response: { 200: responseSchema },
      },
    },
    async (request) => {
      const query = request.query;
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );

      const named = query.mr !== undefined || query.branch !== undefined;
      const target = await targetOf(deps, project.id, query);
      const paging = { page: query.page, pageSize: query.pageSize };
      // 6M §8: the verdicts need the feature and a policy of the project's organisation.
      const policy = deps.edition.limits().licenses.policy
        ? await policyFor(deps.db, project.organizationId)
        : null;
      const verdicts = policy !== null;
      if (!target) {
        if (named) throw notFound('Branch');
        // The main branch has no analysis yet.
        return {
          rows: [],
          ...paging,
          total: 0,
          summary: EMPTY_SUMMARY,
          inventory: false,
          verdicts,
        };
      }

      const filter = filterOfQuery(query);
      const judge = policy === null ? null : verdictOf(policy);
      const [list, summary] = await Promise.all([
        judge !== null && query.verdict !== undefined
          ? verdictPage(deps, target, filter, judge, query.verdict, paging)
          : listDependencies(deps.db, target, filter, paging),
        dependencySummary(deps.db, target),
      ]);
      return {
        rows: judge === null ? list.rows : list.rows.map((r) => ({ ...r, verdict: judge(r) })),
        ...paging,
        total: list.total,
        summary,
        inventory: await hasInventory(deps.db, target, summary.total),
        verdicts,
      };
    },
  );
};

/**
 * The policy is not in SQL: the verdict filter judges every entry the other filters keep (at
 * most the 50 000 of a snapshot), in the list's order, and pages after it.
 */
async function verdictPage(
  deps: RouteDeps,
  target: DependencyTarget,
  filter: DependencyFilter,
  judge: (row: DependencyRow) => LicenseVerdict,
  verdict: LicenseVerdict,
  page: { page: number; pageSize: number },
): Promise<{ rows: DependencyRow[]; total: number }> {
  const matching = (await listAllDependencies(deps.db, target, filter)).filter(
    (r) => judge(r) === verdict,
  );
  const start = (page.page - 1) * page.pageSize;
  return { rows: matching.slice(start, start + page.pageSize), total: matching.length };
}
