import { and, eq, isNotNull, isNull } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { projects, scmConnections } from '../db/schema';
import { notFound, ProblemError } from '../http/problem';
import { idParams, noNul } from '../http/schemas';
import { gitlabClientFor } from '../scm/connections';
import { listInstallationRepositories } from '../scm/github/installations';
import { ScmError } from '../scm/provider';

/** Repositories to a page: what both providers list at most. */
const PAGE_SIZE = 100;

const optionSchema = z.object({
  ref: z.string().meta({
    description: 'What a project maps to: the GitLab project id, or the GitHub owner/repo',
  }),
  name: z.string().meta({ description: 'owner/repo (GitHub) or the full path (GitLab)' }),
  defaultBranch: z.string().nullable(),
  language: z.string().nullable().meta({ description: 'GitHub only; null for GitLab' }),
  archived: z.boolean(),
  project: z
    .object({
      id: z.uuid(),
      key: z.string(),
      state: z.enum(['mapped', 'adoptable']).meta({
        description:
          '`mapped`: the project already maps this repository. `adoptable`: an unmapped project has the key the repository would get.',
      }),
    })
    .nullable(),
});

/** What a failed SCM call tells the page: the fixed text of the error, never the provider's words. */
function scmProblem(err: ScmError): ProblemError {
  return new ProblemError(502, 'SCM_UNAVAILABLE', 'The SCM provider could not list repositories', {
    detail: err.message,
  });
}

interface Listed {
  ref: string;
  name: string;
  defaultBranch: string | null;
  language: string | null;
  archived: boolean;
}

export const repositorySetupRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const scmDeps = {
    secretKey: deps.config.secretKey,
    internalHosts: deps.config.scmInternalHosts,
  };

  app.get(
    '/scm-connections/:id/repositories',
    {
      config: { openapi: { problems: [404, 422, 502] } },
      schema: {
        tags: ['scm'],
        summary:
          'One page of the repositories a connection reaches (100 to a page), with the project that maps or could adopt each; for members who may create projects',
        params: idParams,
        querystring: z.strictObject({
          page: z.coerce.number().int().min(1).max(10_000).default(1),
          filter: noNul(z.string().max(255)).optional().meta({
            description:
              'Case-insensitive part of the repository name. GitLab searches on its side; GitHub has no search over an installation’s repositories, so the listed page is filtered here',
          }),
        }),
        response: { 200: z.object({ items: z.array(optionSchema), hasMore: z.boolean() }) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const [row] = await deps.db
        .select()
        .from(scmConnections)
        .where(eq(scmConnections.id, request.params.id));
      if (!row) throw notFound('SCM connection');
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        row.organizationId,
        'org.projects.create',
      );
      const { page } = request.query;
      const filter = request.query.filter?.trim() ?? '';

      let listed: Listed[];
      let hasMore: boolean;
      try {
        if (row.provider === 'github') {
          const found = await listInstallationRepositories(row, scmDeps, undefined, {
            page,
            perPage: PAGE_SIZE,
          });
          // GitHub has no server-side search for an installation's repositories, so the filter
          // narrows the listed page only (acceptable for the first version).
          const needle = filter.toLowerCase();
          listed = found.repositories
            .filter((r) => r.ref.toLowerCase().includes(needle))
            .map((r) => ({
              ref: r.ref,
              name: r.ref,
              defaultBranch: r.defaultBranch,
              language: r.language,
              archived: r.archived,
            }));
          hasMore = found.hasMore;
        } else {
          const made = gitlabClientFor(row, scmDeps);
          if ('problem' in made) {
            throw new ScmError('refused', made.problem, { reason: 'invalid_input' });
          }
          const found = await made.client.listProjects({
            page,
            perPage: PAGE_SIZE,
            ...(filter === '' ? {} : { search: filter }),
          });
          listed = found.projects.map((p) => ({
            ref: p.ref,
            name: p.path,
            defaultBranch: p.defaultBranch,
            language: null,
            archived: p.archived,
          }));
          hasMore = found.hasMore;
        }
      } catch (err) {
        if (err instanceof ScmError) throw scmProblem(err);
        throw err;
      }

      const mappedRows = await deps.db
        .select({ id: projects.id, key: projects.key, ref: projects.scmProjectRef })
        .from(projects)
        .where(
          and(
            eq(projects.organizationId, row.organizationId),
            eq(projects.scmConnectionId, row.id),
            isNotNull(projects.scmProjectRef),
          ),
        );
      const unmappedRows = await deps.db
        .select({ id: projects.id, key: projects.key })
        .from(projects)
        .where(
          and(eq(projects.organizationId, row.organizationId), isNull(projects.scmConnectionId)),
        );
      // GitHub names and GitLab paths compare without case; a GitLab id compares as written.
      const mapped = new Map<string, { id: string; key: string }>();
      for (const p of mappedRows) if (p.ref !== null) mapped.set(p.ref.toLowerCase(), p);
      // Keys are case-sensitive: an unmapped project is adoptable only by the exact name.
      const adoptable = new Map(unmappedRows.map((p) => [p.key, p]));

      const items = listed.map((r) => {
        const found = mapped.get(r.ref.toLowerCase()) ?? mapped.get(r.name.toLowerCase());
        const free = adoptable.get(r.name);
        return {
          ...r,
          project: found
            ? { id: found.id, key: found.key, state: 'mapped' as const }
            : free
              ? { id: free.id, key: free.key, state: 'adoptable' as const }
              : null,
        };
      });
      return { items, hasMore };
    },
  );
};
