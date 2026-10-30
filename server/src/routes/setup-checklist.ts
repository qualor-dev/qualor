import { and, eq, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { first } from '../db/rows';
import {
  analyses,
  memberships,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  setupChecklistClosures,
  users,
} from '../db/schema';
import { idParams } from '../http/schemas';
import { organizationSettings, readLlmSettings } from '../llm/settings';
import { reviewUnavailableReason } from './review';

const STEP_IDS = ['connect', 'repositories', 'analysis', 'ai_review', 'team'] as const;

const checklistSchema = z.object({
  steps: z.array(
    z.object({
      id: z.enum(STEP_IDS),
      done: z.boolean().meta({ description: 'Read from the server state, never from clicks' }),
      hint: z.enum(['merge_request', 'ask_server_admin']).nullable().meta({
        description:
          '`merge_request`: a CI setup merge request is open and the project has no analysis yet. `ask_server_admin`: no AI provider is set and only an instance admin can set one',
      }),
      blocking: z.boolean().meta({ description: 'Whether the step holds back `allDone`' }),
    }),
  ),
  closed: z.boolean().meta({ description: 'The viewer closed the checklist of this organization' }),
  allDone: z.boolean().meta({ description: 'Every blocking step is done' }),
});
type Checklist = z.infer<typeof checklistSchema>;

/**
 * The first-setup checklist of an organization (onboarding design, "The checklist (UI)"). It
 * is shown to the organization's admins, so both routes need `org.projects.create`: the admin
 * action the steps lead to, held by organization admins only (not by project admins).
 */
export const setupChecklistRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const { db } = deps;

  /** A project (column) with a succeeded analysis. */
  const analysed = (projectId: unknown) =>
    sql`exists (select 1 from ${analyses} where ${analyses.projectId} = ${projectId} and ${analyses.status} = 'succeeded')`;

  async function checklistOf(
    organizationId: string,
    userId: string,
    isInstanceAdmin: boolean,
  ): Promise<Checklist> {
    const [facts, settings] = await Promise.all([
      db
        .select({
          connect: sql<boolean>`exists (select 1 from ${scmConnections} where ${scmConnections.organizationId} = ${organizationId})`,
          repositories: sql<boolean>`exists (select 1 from ${projects} where ${projects.organizationId} = ${organizationId} and ${projects.scmConnectionId} is not null)`,
          analysis: sql<boolean>`exists (select 1 from ${projects} where ${projects.organizationId} = ${organizationId} and ${analysed(projects.id)})`,
          openMergeRequest: sql<boolean>`exists (
            select 1 from ${repositorySetupItems}
            join ${repositorySetupRuns} on ${repositorySetupRuns.id} = ${repositorySetupItems.runId}
            where ${repositorySetupRuns.organizationId} = ${organizationId}
              and ${repositorySetupItems.ciOutcome} = 'merge_request'
              and ${repositorySetupItems.projectId} is not null
              and not ${analysed(repositorySetupItems.projectId)})`,
          team: sql<boolean>`(select count(*) from (
            select 1 from ${memberships}
            join ${users} on ${users.id} = ${memberships.userId}
            where ${memberships.organizationId} = ${organizationId} and ${users.active}
            limit 2) active_members) > 1`,
          closed: sql<boolean>`exists (select 1 from ${setupChecklistClosures} where ${setupChecklistClosures.userId} = ${userId} and ${setupChecklistClosures.organizationId} = ${organizationId})`,
        })
        .from(sql`(select 1) as one`)
        .then((rows) => first(rows)),
      readLlmSettings(db),
    ]);
    const aiOn = organizationSettings(settings, organizationId).review.enabled;
    const askServerAdmin =
      !aiOn &&
      !isInstanceAdmin &&
      reviewUnavailableReason(settings, organizationId) === 'no_provider';
    const steps: Checklist['steps'] = [
      { id: 'connect', done: facts.connect, hint: null, blocking: true },
      { id: 'repositories', done: facts.repositories, hint: null, blocking: true },
      {
        id: 'analysis',
        done: facts.analysis,
        hint: !facts.analysis && facts.openMergeRequest ? 'merge_request' : null,
        blocking: true,
      },
      {
        id: 'ai_review',
        done: aiOn,
        hint: askServerAdmin ? 'ask_server_admin' : null,
        blocking: !askServerAdmin,
      },
      { id: 'team', done: facts.team, hint: null, blocking: true },
    ];
    return {
      steps,
      closed: facts.closed,
      allDone: steps.every((s) => s.done || !s.blocking),
    };
  }

  app.get(
    '/organizations/:id/setup-checklist',
    {
      schema: {
        tags: ['organizations'],
        summary:
          "The organization's first-setup checklist and whether the caller closed it (org.projects.create)",
        params: idParams,
        response: { 200: checklistSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.projects.create',
      );
      return checklistOf(organizationId, principal.user.id, principal.user.isInstanceAdmin);
    },
  );

  app.put(
    '/organizations/:id/setup-checklist',
    {
      schema: {
        tags: ['organizations'],
        summary:
          'Close or reopen the first-setup checklist for the caller in this organization (org.projects.create)',
        params: idParams,
        body: z.object({ closed: z.boolean() }),
        response: { 200: checklistSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.projects.create',
      );
      if (request.body.closed) {
        await db
          .insert(setupChecklistClosures)
          .values({ userId: principal.user.id, organizationId })
          .onConflictDoNothing();
      } else {
        await db
          .delete(setupChecklistClosures)
          .where(
            and(
              eq(setupChecklistClosures.userId, principal.user.id),
              eq(setupChecklistClosures.organizationId, organizationId),
            ),
          );
      }
      return checklistOf(organizationId, principal.user.id, principal.user.isInstanceAdmin);
    },
  );
};
