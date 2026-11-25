import { and, eq, ne, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import { boardsLinkFor } from '../boards/access';
import { enqueueBoardsCreate } from '../boards/jobs';
import {
  boardsLinkDto,
  boardsLinkDtoOf,
  boardsLinkPreconditions,
  boardsLinkRowsOf,
  boardsLinkSchema,
  insertPendingBoardsLinks,
  rearmBoardsLink,
  usableBoardsConnection,
  type BoardsLink,
  type BoardsLinkRow,
  type BoardsLinkWithUrl,
} from '../boards/links';
import type { Executor } from '../db/client';
import { boardsLinks, projects, scmConnections } from '../db/schema';
import { conflict, validationFailed } from '../http/problem';
import { idParams, noContent } from '../http/schemas';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import {
  linkRowsOf,
  REARMABLE_STATES,
  RETRYABLE_STATES,
  rowTarget,
  targetKey,
  type LinkSkip,
  type LinkTarget,
} from '../jira/links';
import { projectForUser } from '../projects/access';
import { compare } from '../vulnerabilities/order';
import {
  issueTargets,
  linkBody,
  pairTargets,
  withoutOtherTracker,
  type Resolved,
} from './jira-links';

const answerFields = {
  /** The link the item made pending, or the one it already has (`ALREADY_LINKED`). */
  link: boardsLinkSchema.nullable(),
  skipped: z.enum(['NOT_FOUND', 'NOT_ELIGIBLE', 'ALREADY_LINKED']).nullable(),
};
const linkItem = z.union([
  z.object({ issueId: z.uuid(), ...answerFields }),
  z.object({ packageName: z.string(), vulnerabilityId: z.string(), ...answerFields }),
]);

/** The 409s of both routes that make a link pending. */
const CONNECTION_PROBLEMS =
  "BOARDS_NOT_CONNECTED: the organisation has no Azure DevOps connection, or the project's is gone; BOARDS_CONNECTION_BROKEN: the connection has a credential problem (its code in `problemCode`), which an organisation admin must fix";

/** A wrong state for Retry: 409, nothing changed. */
function notRetryable(): never {
  throw conflict(
    'BOARDS_LINK_NOT_RETRYABLE',
    'Only a failed or missing Boards link can be retried; request a work item to re-create a dismissed one',
  );
}

/**
 * As Jira's ruling T12b: Retry asks what a request asks of its finding: a code issue still on the
 * main branch and not closed, a pair still linkable. Otherwise 409, nothing changed.
 */
async function requireLinkable(
  db: Executor,
  projectId: string,
  link: BoardsLinkRow,
): Promise<void> {
  const target = rowTarget(link);
  const [resolved] =
    target.kind === 'issue'
      ? await issueTargets(db, projectId, [target.issueId])
      : await pairTargets(db, projectId, [
          { packageName: target.packageName, vulnerabilityId: target.vulnerabilityId },
        ]);
  if (resolved && 'target' in resolved && resolved.target.kind === target.kind) return;
  throw conflict(
    'BOARDS_LINK_NOT_RETRYABLE',
    'The finding of this Boards link is closed or can no longer have a work item',
  );
}

/**
 * Design §7.8: requesting Azure Boards work items for findings, retrying a failed or missing link,
 * and dismissing one (`issue.triage`), as the Jira link routes. Each link made or re-armed costs
 * its user one issue change (ruling G7). A finding with a Jira link row, in any state, gets no work
 * item (plan Ruling 9).
 */
export const boardsLinkRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the issue routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  app.post(
    '/projects/:id/boards/links',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: `${CONNECTION_PROBLEMS}; BOARDS_PROJECT_NOT_MAPPED: the project has no Azure Boards mapping`,
            422: 'Validation failed (VALIDATION_FAILED), also without exactly one of `issueIds` and `vulnerabilities`',
            429: 'Too many issue changes by this user, one per link made or re-armed (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          "Request Azure Boards work items for findings: exactly one of `issueIds` (1-500) or `vulnerabilities` (1-100). Each new finding, or one whose link was dismissed, failed or missing, gets a pending link on the mapping's connection. Items answer in request order: a Trivy issue under its `issueId` with its vulnerability link; NOT_FOUND, NOT_ELIGIBLE, or ALREADY_LINKED with the existing link (with no link when the finding has a Jira link, in any state)",
        params: idParams,
        body: linkBody,
        response: { 202: z.object({ items: z.array(linkItem) }) },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      const { issueIds, vulnerabilities } = request.body;
      if ((issueIds === undefined) === (vulnerabilities === undefined)) {
        throw validationFailed([
          { path: 'body', message: 'Send exactly one of issueIds and vulnerabilities' },
        ]);
      }
      const { connection, mapping } = await boardsLinkPreconditions(deps.db, project);
      // Plan Ruling 9: a finding with a Jira link row, in any state, stays in Jira.
      const resolved = await withoutOtherTracker(
        issueIds !== undefined
          ? await issueTargets(deps.db, project.id, issueIds)
          : await pairTargets(deps.db, project.id, vulnerabilities ?? []),
        (targets) => linkRowsOf(deps.db, project.id, targets),
      );

      // One link per finding: the first item of a finding claims it, the later ones answer with
      // its link.
      const targets = new Map<string, LinkTarget>();
      for (const r of resolved) {
        if ('target' in r && !targets.has(targetKey(r.target))) {
          targets.set(targetKey(r.target), r.target);
        }
      }
      const existing = await boardsLinkRowsOf(deps.db, project.id, [...targets.values()]);
      const fresh: LinkTarget[] = [];
      const rearm: BoardsLinkRow[] = [];
      for (const [key, target] of targets) {
        const row = existing.get(key);
        if (!row) fresh.push(target);
        else if ((REARMABLE_STATES as readonly string[]).includes(row.state)) rearm.push(row);
      }
      // Written in one order whatever the request's order (new rows by finding, re-arms by id), so
      // two overlapping requests wait on each other instead of deadlocking (40P01).
      fresh.sort((a, b) => compare(targetKey(a), targetKey(b)));
      rearm.sort((a, b) => compare(a.id, b.id));
      const charged = fresh.length + rearm.length;
      if (charged > 0) chargeChanges(principal.user.id, charged);

      let outcome: {
        made: Map<string, BoardsLinkRow>;
        lost: Map<string, BoardsLinkWithUrl>;
        baseUrl: string;
      };
      try {
        outcome = await deps.db.transaction(async (tx) => {
          // The Jira request's lock order (project row, then connection row); a removed connection
          // stops here instead of failing the insert.
          await tx
            .select({ id: projects.id })
            .from(projects)
            .where(eq(projects.id, project.id))
            .for('key share');
          const [current] = await tx
            .select({ baseUrl: scmConnections.baseUrl })
            .from(scmConnections)
            .where(eq(scmConnections.id, connection.id))
            .for('key share');
          if (!current) {
            throw conflict(
              'BOARDS_NOT_CONNECTED',
              'The Azure DevOps connection of the project is gone',
            );
          }
          const pending = await insertPendingBoardsLinks(
            tx,
            {
              projectId: project.id,
              connectionId: connection.id,
              azureProjectId: mapping.azureProjectId,
              userId: principal.user.id,
            },
            fresh,
          );
          for (const row of rearm) {
            const rearmed = await rearmBoardsLink(tx, row.id, REARMABLE_STATES, principal.user.id, {
              connectionId: connection.id,
              azureProjectId: mapping.azureProjectId,
            });
            if (rearmed) pending.push(rearmed);
          }
          const made = new Map(pending.map((row) => [targetKey(rowTarget(row)), row]));
          // A finding another request linked or re-armed meanwhile: its row as that one left it.
          const losers = [...fresh, ...rearm.map(rowTarget)].filter((t) => !made.has(targetKey(t)));
          const lost =
            losers.length === 0
              ? new Map<string, BoardsLinkWithUrl>()
              : await boardsLinkRowsOf(tx, project.id, losers);
          if (pending.length > 0) {
            // Every row made or re-armed is on this connection. Queued in this transaction (the
            // worker cannot claim the job before the rows commit), the schedule lock before the
            // audit chain's, as Jira's request takes them.
            await enqueueBoardsCreate(tx, connection.id);
            await recordProjectEvent(deps.audit, tx, request, project, 'boards_link.requested', {
              count: pending.length,
              kind: issueIds !== undefined ? 'issue' : 'vulnerability',
            });
          }
          return { made, lost, baseUrl: current.baseUrl };
        });
      } catch (err) {
        if (charged > 0) chargeChanges.refund(principal.user.id, charged);
        throw err;
      }
      const lostCount = charged - outcome.made.size;
      if (lostCount > 0) chargeChanges.refund(principal.user.id, lostCount);

      const claimed = new Set<string>();
      const answer = (r: Resolved): { link: BoardsLink | null; skipped: LinkSkip | null } => {
        if ('skipped' in r) return { link: null, skipped: r.skipped };
        const key = targetKey(r.target);
        const made = outcome.made.get(key);
        if (made) {
          const link = boardsLinkDto(made, outcome.baseUrl);
          if (claimed.has(key)) return { link, skipped: 'ALREADY_LINKED' };
          claimed.add(key);
          return { link, skipped: null };
        }
        const row = outcome.lost.get(key) ?? existing.get(key);
        return row
          ? { link: boardsLinkDtoOf(row), skipped: 'ALREADY_LINKED' }
          : { link: null, skipped: 'NOT_FOUND' };
      };
      return reply.code(202).send({ items: resolved.map((r) => ({ ...r.item, ...answer(r) })) });
    },
  );

  app.post(
    '/boards-links/:id/retry',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: `${CONNECTION_PROBLEMS}; BOARDS_LINK_NOT_RETRYABLE: the link is neither failed nor missing, or its finding is closed or no longer linkable (a code issue off the main branch, a vulnerability no tracked target or Trivy issue holds)`,
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          "Retry a failed or missing Azure Boards link whose finding may still have one (as for a request): it goes back to pending as a new create (its generation goes up, its old work item id, state and failure are cleared). Only the link's connection is checked, not the mapping: without one, the create step fails the link `not_mapped`",
        params: idParams,
        response: { 202: boardsLinkSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { link, project } = await boardsLinkFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      // As Jira's ruling P15: the connection, not the mapping.
      const connection = await usableBoardsConnection(deps.db, project, link.connectionId);
      if (!(RETRYABLE_STATES as readonly string[]).includes(link.state)) notRetryable();
      await requireLinkable(deps.db, project.id, link);
      chargeChanges(principal.user.id, 1);
      let row: BoardsLinkRow;
      try {
        row = await deps.db.transaction(async (tx) => {
          const rearmed = await rearmBoardsLink(tx, link.id, RETRYABLE_STATES, principal.user.id);
          if (!rearmed) notRetryable();
          // A retry keeps the link's own connection: its create runs there.
          await enqueueBoardsCreate(tx, rearmed.connectionId);
          await recordProjectEvent(deps.audit, tx, request, project, 'boards_link.requested', {
            count: 1,
            kind: rearmed.kind,
          });
          return rearmed;
        });
      } catch (err) {
        chargeChanges.refund(principal.user.id, 1);
        throw err;
      }
      return reply.code(202).send(boardsLinkDto(row, connection.baseUrl));
    },
  );

  app.delete(
    '/boards-links/:id',
    {
      schema: {
        tags: ['boards'],
        summary:
          'Dismiss: the link becomes dismissed and reads as no link; its work item id is kept, the work item stays, and the automatic rule never brings it back. Requesting a work item for the finding again re-arms it. Dismissing a dismissed link changes nothing',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { link, project } = await boardsLinkFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      await deps.db.transaction(async (tx) => {
        const [dismissed] = await tx
          .update(boardsLinks)
          .set({ state: 'dismissed', updatedAt: sql`now()` })
          .where(and(eq(boardsLinks.id, link.id), ne(boardsLinks.state, 'dismissed')))
          .returning({ workItemId: boardsLinks.workItemId });
        if (!dismissed) return;
        await recordProjectEvent(deps.audit, tx, request, project, 'boards_link.dismissed', {
          workItemId: dismissed.workItemId,
        });
      });
      return reply.code(204).send();
    },
  );
};
