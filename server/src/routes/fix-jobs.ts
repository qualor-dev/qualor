import {
  fixClaimAnswerSchema,
  fixClaimBodySchema,
  fixResultBodySchema,
  FIX_RESULT_BODY_LIMIT,
} from '@qualor/shared/fix';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireProjectToken } from '../auth/access';
import { FIX_STATES } from '../db/schema';
import { dependencyFixForUpload } from '../fixes/access';
import { claimFixes } from '../fixes/claim';
import type { FixScmDeps } from '../fixes/repository';
import { acceptFixResult } from '../fixes/result';
import { ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForUpload } from '../projects/access';
import { createScmRuntime } from '../scm/runtime';

/**
 * 0.16 fix MRs §6.5–§6.7, B1: the fix job of a project's CI claims requested fixes and uploads
 * what it made of each, with the project's analysis token only (📤). Neither is audited, as a
 * report upload is not.
 */
export const fixJobRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  // The uploads' reads of the repository share one runtime per app: GitHub installation tokens are
  // cached across uploads. Nothing here writes to the SCM.
  const scm: FixScmDeps = {
    db: deps.db,
    scm: { secretKey: deps.config.secretKey, internalHosts: deps.config.scmInternalHosts },
    runtime: createScmRuntime(),
  };

  app.post(
    '/projects/fixes/claim',
    {
      config: {
        openapi: {
          problems: [404, 409],
          problemDescriptions: {
            404: 'PROJECT_NOT_FOUND: no such project, or the token is of another project',
            409: "NOT_MAIN_BRANCH: `branch` is not the project's main branch",
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          "The fix job's claim: up to `max` requested fixes of the job's families (and open MRs to refresh), oldest first, each `preparing` with a 30-minute lease whose token is shown only here. A project whose fixes cannot run answers no items and `reason`. A project analysis token only",
        querystring: z.strictObject({ projectKey: z.string().regex(PROJECT_KEY_PATTERN) }),
        body: fixClaimBodySchema,
        response: { 200: fixClaimAnswerSchema },
      },
    },
    async (request) => {
      const principal = requireProjectToken(request);
      const project = await projectForUpload(accessOf(deps), principal, request.query.projectKey);
      const answer = await claimFixes(deps.db, project, request.body);
      request.log.info(
        {
          projectId: project.id,
          // Ruling F12: the job's revision is only logged.
          revision: request.body.revision ?? null,
          families: request.body.families,
          fixIds: answer.items.map((item) => item.id),
          reason: answer.reason,
        },
        'fix claim',
      );
      return answer;
    },
  );

  app.put(
    '/fixes/:id/result',
    {
      // R16: 32 MiB of files in base64 and the JSON around them.
      bodyLimit: FIX_RESULT_BODY_LIMIT,
      config: {
        openapi: {
          problems: [404, 409, 413, 422, 503],
          problemDescriptions: {
            404: "NOT_FOUND: no fix of the token's project has this id",
            409: 'FIX_LEASE_LOST: the job no longer holds the fix (the lease expired or was released, or the fix was cancelled or claimed again), nothing changed; SCM_NOT_BOUND: the project is no longer mapped to a repository; FIX_MRS_NOT_ALLOWED: the connection no longer allows fix merge requests (both leave the fix `preparing`)',
            413: `BODY_TOO_LARGE: a body over ${FIX_RESULT_BODY_LIMIT} bytes`,
            422: 'UPLOAD_REFUSED: the files break a rule, the fix is now failed (upload_refused); the title is the rule’s fixed text, `reason` the rule, `detail` the file; VALIDATION_FAILED',
            503: 'SCM_UNAVAILABLE: the repository could not be read now (down, a timeout, a rate limit) to check the upload; FIX_CHECK_BUSY: an upload of this project is being checked, or eight wait already; both leave the fix `preparing` with its lease, try again after Retry-After',
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          "The fix job's result for a claimed fix: its files (checked by path, target, base and content, then committed by a background job), a failure, no fix, or the claim handed back. A repository that refuses the read for good (a permission, a refused request) ends the attempt: 202 with the fix failed (scm_permission, scm_refused). A project analysis token only",
        params: idParams,
        body: fixResultBodySchema,
        response: { 202: z.object({ state: z.enum(FIX_STATES) }) },
      },
    },
    async (request, reply) => {
      const principal = requireProjectToken(request);
      const { fix, project } = await dependencyFixForUpload(
        accessOf(deps),
        principal,
        request.params.id,
      );
      try {
        const result = await acceptFixResult(scm, fix, project, request.body, {
          log: request.log,
        });
        request.log.info({ fixId: fix.id, state: result.state }, 'fix result');
        return await reply.code(202).send(result);
      } catch (err) {
        if (err instanceof ProblemError && err.code === 'UPLOAD_REFUSED') {
          // The rule and the file (bounded and scrubbed), never a file's content.
          request.log.info(
            { fixId: fix.id, rule: err.extensions.reason, path: err.detail ?? null },
            'fix upload refused',
          );
        }
        throw err;
      }
    },
  );
};
