import { and, eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requirePrincipal } from '../auth/access';
import { branches } from '../db/schema';
import { conflict } from '../http/problem';
import { timestamp } from '../http/schemas';
import {
  BASELINE_WARNINGS,
  DEFAULT_NEW_CODE_DEFINITION,
  resolveBaseline,
  type ResolvedBaseline,
} from '../newcode/baseline';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForUpload } from '../projects/access';
import { newCodeDefinitionSchema } from './projects';

export const newCodeBaselineSchema = z.object({
  /** The commit new code is diffed against; null on the main branch's first analysis. */
  revision: z.string().nullable(),
  analysisId: z.uuid().nullable(),
  analysisDate: timestamp.nullable(),
  definition: newCodeDefinitionSchema,
  warnings: z.array(z.enum(BASELINE_WARNINGS)),
});

export const newCodeRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/projects/new-code-baseline',
    {
      config: {
        openapi: {
          problems: [404, 409],
          problemDescriptions: {
            404: 'PROJECT_NOT_FOUND: the project does not exist or the caller cannot see it (a server without this route answers NOT_FOUND)',
            409: "NOT_MAIN_BRANCH: `branch` is not the project's main branch",
          },
        },
      },
      schema: {
        tags: ['projects'],
        summary:
          "The main branch's new-code baseline; the CLI calls this before a main-branch scan",
        querystring: z.strictObject({
          projectKey: z.string().regex(PROJECT_KEY_PATTERN),
          branch: z.string().min(1).max(255),
          version: z.string().min(1).max(100).optional(),
        }),
        response: { 200: newCodeBaselineSchema },
      },
    },
    async (request) => {
      const principal = requirePrincipal(request);
      const { projectKey, branch, version } = request.query;
      // One read-only snapshot: the project, its main branch and its analyses are read consistently.
      const resolved = await deps.db.transaction(
        async (tx): Promise<ResolvedBaseline> => {
          const project = await projectForUpload(accessOf(deps, tx), principal, projectKey);
          if (branch !== project.mainBranchName) {
            throw conflict(
              'NOT_MAIN_BRANCH',
              `Only the main branch (${project.mainBranchName}) has a server-side new-code baseline`,
            );
          }
          const [main] = await tx
            .select({ id: branches.id })
            .from(branches)
            .where(and(eq(branches.projectId, project.id), eq(branches.isMain, true)));
          if (main) return resolveBaseline(tx, project, main.id, version);
          return {
            baseline: null,
            definition: project.newCodeDefinition ?? DEFAULT_NEW_CODE_DEFINITION,
            warnings: [],
          };
        },
        { isolationLevel: 'repeatable read', accessMode: 'read only' },
      );
      return {
        revision: resolved.baseline?.revision ?? null,
        analysisId: resolved.baseline?.id ?? null,
        analysisDate: resolved.baseline?.analysisDate.toISOString() ?? null,
        definition: resolved.definition,
        warnings: resolved.warnings,
      };
    },
  );
};
