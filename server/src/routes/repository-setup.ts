import { and, asc, eq, inArray, isNotNull, isNull, ne } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import { first } from '../db/rows';
import {
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  SETUP_CI_OUTCOMES,
  SETUP_PROJECT_OUTCOMES,
  SETUP_RUN_STATUSES,
} from '../db/schema';
import { notFound, ProblemError, validationFailed } from '../http/problem';
import { idParams, noNul } from '../http/schemas';
import {
  MAX_SETUP_REPOSITORIES,
  REPOSITORY_SETUP_QUEUE,
  SETUP_CI_REASONS,
  SETUP_ERROR_CODES,
  SETUP_TOKEN_AAD,
  type SetupCiReason,
  type SetupErrorCode,
} from '../onboarding/setup-run';
import { enqueue } from '../queue/queue';
import { createCiSetupStatus, type CiSetupReason } from '../scm/ci-setup-status';
import { gitlabClientFor } from '../scm/connections';
import { listInstallationRepositories } from '../scm/github/installations';
import { ScmError } from '../scm/provider';
import { projectRefProblem, scmProjectRef } from './scm-connections';

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

/** The UI polls a run that is not done yet this often (seconds). */
const POLL_SECONDS = 2;

const CI_SETUP_UNAVAILABLE: Record<CiSetupReason, string> = {
  not_allowed: 'The connection does not allow CI setup',
  missing_permissions: 'The GitHub App lacks the Workflows and Secrets (write) permissions',
  no_public_url: 'CI setup needs QUALOR_PUBLIC_URL',
};

const itemSchema = z.object({
  ref: z.string().meta({ description: 'The repository as the run was given it' }),
  name: z.string().meta({
    description: 'owner/repo (GitHub) or the full path (GitLab) once read; the ref until then',
  }),
  project: z.object({ id: z.uuid(), key: z.string() }).nullable(),
  projectOutcome: z.enum(SETUP_PROJECT_OUTCOMES).meta({
    description:
      '`adopted`: an existing project (unmapped with the same key, or already mapped to this repository) is used',
  }),
  ciOutcome: z.enum(SETUP_CI_OUTCOMES).meta({
    description:
      '`merge_request`: opened, or already open (`ciUrl`); `snippet`: CI could not be set up (`ciReason`), copy the snippet; `already`: the repository has a Qualor job or token; `skipped`: the run did not set up CI',
  }),
  ciUrl: z.string().nullable(),
  ciReason: z.enum(SETUP_CI_REASONS).nullable(),
  snippet: z.string().nullable(),
  token: z.string().nullable().meta({
    description:
      "The project's new CI setup token, for the snippet: shown to the run's creator on the first read after the repository is done, never again",
  }),
  error: z.object({ code: z.enum(SETUP_ERROR_CODES), message: z.string() }).nullable(),
});
const runSchema = z.object({
  id: z.uuid(),
  status: z.enum(SETUP_RUN_STATUSES),
  ciSetup: z.boolean(),
  items: z.array(itemSchema),
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
  const key = encryptionKey(deps.config.secretKey);
  const ciSetupOf = createCiSetupStatus({
    deps: scmDeps,
    publicUrl: deps.config.publicUrl,
    warn: (message, context) => app.log.warn(context, message),
  });

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

  app.post(
    '/repository-setups',
    {
      config: { openapi: { problems: [404, 422] } },
      schema: {
        tags: ['scm'],
        summary:
          "Add a connection's repositories as projects in the background (202 with the run's id); for members who may create projects",
        body: z.strictObject({
          organizationId: z.uuid(),
          connectionId: z.uuid(),
          repositories: z
            .array(scmProjectRef)
            .min(1)
            .max(MAX_SETUP_REPOSITORIES)
            .refine((refs) => new Set(refs.map((r) => r.toLowerCase())).size === refs.length, {
              message: 'Each repository once',
            })
            .meta({
              description: `Refs as \`GET /scm-connections/{id}/repositories\` lists them, 1 to ${MAX_SETUP_REPOSITORIES}; one the provider does not know fails in the run`,
            }),
          ciSetup: z.boolean().meta({
            description:
              "Also open a merge request per repository that adds the Qualor job; only where the connection's `ciSetup.available`",
          }),
        }),
        response: { 202: z.object({ id: z.uuid() }) },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const body = request.body;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        body.organizationId,
        'org.projects.create',
      );
      const [connection] = await deps.db
        .select()
        .from(scmConnections)
        .where(
          and(
            eq(scmConnections.id, body.connectionId),
            eq(scmConnections.organizationId, body.organizationId),
          ),
        );
      if (!connection) {
        throw validationFailed([{ path: 'body.connectionId', message: 'Unknown SCM connection' }]);
      }
      const problems = body.repositories.flatMap((ref, i) => {
        const problem = projectRefProblem(connection.provider, ref);
        return problem === null ? [] : [{ path: `body.repositories.${i}`, message: problem }];
      });
      if (problems.length > 0) throw validationFailed(problems);
      if (body.ciSetup) {
        // The page offers the option only where it is available: the server agrees.
        const status = await ciSetupOf(connection);
        if (!status.available) {
          throw validationFailed([
            {
              path: 'body.ciSetup',
              message: CI_SETUP_UNAVAILABLE[status.reason ?? 'not_allowed'],
            },
          ]);
        }
      }
      const id = await deps.db.transaction(async (tx) => {
        const run = first(
          await tx
            .insert(repositorySetupRuns)
            .values({
              organizationId: body.organizationId,
              connectionId: connection.id,
              createdBy: principal.user.id,
              ciSetup: body.ciSetup,
            })
            .returning({ id: repositorySetupRuns.id }),
        );
        await tx.insert(repositorySetupItems).values(
          body.repositories.map((ref, position) => ({
            runId: run.id,
            position,
            repositoryRef: ref,
            repositoryName: ref,
          })),
        );
        // One run at a time per connection: the provider's pacing and limits are per connection.
        await enqueue(tx, {
          queue: REPOSITORY_SETUP_QUEUE,
          payload: { runId: run.id },
          concurrencyKey: connection.id,
        });
        return run.id;
      });
      return reply.code(202).send({ id });
    },
  );

  app.get(
    '/repository-setups/:id',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['scm'],
        summary:
          "A repository-setup run and each repository's outcome (Retry-After: 2 until it is done); its creator sees each new token once",
        params: idParams,
        response: { 200: runSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const [run] = await deps.db
        .select()
        .from(repositorySetupRuns)
        .where(eq(repositorySetupRuns.id, request.params.id));
      if (!run) throw notFound('Repository setup');
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        run.organizationId,
        'org.projects.create',
      );
      const creator = run.createdBy === principal.user.id;
      const { rows, tokens } = await deps.db.transaction(async (tx) => {
        const shownTokens = new Map<number, string>();
        if (creator) {
          // Locked, so two reads at once never both show a token; cleared in this transaction.
          const shown = await tx
            .select({
              position: repositorySetupItems.position,
              tokenEnc: repositorySetupItems.tokenEnc,
            })
            .from(repositorySetupItems)
            .where(
              and(
                eq(repositorySetupItems.runId, run.id),
                isNotNull(repositorySetupItems.tokenEnc),
                ne(repositorySetupItems.ciOutcome, 'pending'),
              ),
            )
            .for('update');
          if (shown.length > 0) {
            for (const item of shown) {
              const token =
                item.tokenEnc === null ? null : decryptSecret(key, item.tokenEnc, SETUP_TOKEN_AAD);
              if (token !== null) shownTokens.set(item.position, token);
            }
            await tx
              .update(repositorySetupItems)
              .set({ tokenEnc: null })
              .where(
                and(
                  eq(repositorySetupItems.runId, run.id),
                  inArray(
                    repositorySetupItems.position,
                    shown.map((item) => item.position),
                  ),
                ),
              );
          }
        }
        const found = await tx
          .select({ item: repositorySetupItems, projectKey: projects.key })
          .from(repositorySetupItems)
          .leftJoin(projects, eq(projects.id, repositorySetupItems.projectId))
          .where(eq(repositorySetupItems.runId, run.id))
          .orderBy(asc(repositorySetupItems.position));
        return { rows: found, tokens: shownTokens };
      });
      if (run.status !== 'done') void reply.header('retry-after', POLL_SECONDS);
      return {
        id: run.id,
        status: run.status,
        ciSetup: run.ciSetup,
        items: rows.map(({ item, projectKey }) => ({
          ref: item.repositoryRef,
          name: item.repositoryName,
          project:
            item.projectId !== null && projectKey !== null
              ? { id: item.projectId, key: projectKey }
              : null,
          projectOutcome: item.projectOutcome,
          ciOutcome: item.ciOutcome,
          ciUrl: item.ciUrl,
          ciReason: item.ciReason as SetupCiReason | null,
          snippet: item.snippet,
          token: tokens.get(item.position) ?? null,
          error:
            item.errorCode === null
              ? null
              : { code: item.errorCode as SetupErrorCode, message: item.errorMessage ?? '' },
        })),
      };
    },
  );
};
