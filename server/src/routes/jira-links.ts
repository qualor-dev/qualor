import { and, eq, inArray, ne, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import { boardsLinkRowsOf } from '../boards/links';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { branches, issues, jiraConnections, jiraLinks, projects, rules } from '../db/schema';
import { conflict, validationFailed } from '../http/problem';
import { idParams, noContent, noNul } from '../http/schemas';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import { jiraLinkFor } from '../jira/access';
import { enqueueJiraCreate } from '../jira/jobs';
import {
  insertPendingLinks,
  isPairIssue,
  issueLinkable,
  jiraLinkDto,
  jiraLinkSchema,
  linkPreconditions,
  linkRowsOf,
  MAX_LINK_ISSUE_IDS,
  MAX_LINK_VULNERABILITIES,
  pairKey,
  pairPresence,
  REARMABLE_STATES,
  rearmLink,
  RETRYABLE_STATES,
  rowTarget,
  targetKey,
  usableConnection,
  type JiraLink,
  type JiraLinkRow,
  type LinkSkip,
  type LinkTarget,
} from '../jira/links';
import { JIRA_ISSUE_KEY_PATTERN } from '../patterns';
import { projectForUser } from '../projects/access';
import { vulnerabilitySettings } from '../versions/settings';
import { compare } from '../vulnerabilities/order';

const pairSchema = z.strictObject({
  packageName: noNul(z.string().min(1).max(512)),
  vulnerabilityId: noNul(z.string().min(1).max(128)),
});
export type Pair = z.infer<typeof pairSchema>;

/** A link request's body, Jira's and Azure Boards' alike. */
export const linkBody = z.strictObject({
  issueIds: z.array(z.uuid()).min(1).max(MAX_LINK_ISSUE_IDS).optional().meta({
    description:
      'Issues: a code issue of the main branch, or a Trivy issue of main or a tracked branch (its vulnerability is linked)',
  }),
  vulnerabilities: z
    .array(pairSchema)
    .min(1)
    .max(MAX_LINK_VULNERABILITIES)
    .optional()
    .meta({ description: 'Vulnerabilities of the project, as the Vulnerabilities tab lists them' }),
});

const answerFields = {
  /** The link the item made pending, or the one it already has (`ALREADY_LINKED`). */
  link: jiraLinkSchema.nullable(),
  skipped: z.enum(['NOT_FOUND', 'NOT_ELIGIBLE', 'ALREADY_LINKED']).nullable(),
};
const linkItem = z.union([
  z.object({ issueId: z.uuid(), ...answerFields }),
  z.object({ packageName: z.string(), vulnerabilityId: z.string(), ...answerFields }),
]);

/** The 409s of both routes that make a link pending. */
const CONNECTION_PROBLEMS =
  'JIRA_NOT_CONNECTED: the organisation has no Jira connection; JIRA_CONNECTION_BROKEN: the connection has a credential problem (its code in `problemCode`), which an organisation admin must fix';

/**
 * One item of a request, as it names it, and the finding it asks for, or why there is none
 * (ALREADY_LINKED here: the finding has a link of the other tracker).
 */
export type Resolved = { item: { issueId: string } | Pair } & (
  { target: LinkTarget } | { skipped: LinkSkip }
);

/**
 * spec §6.3: each issue as a finding to link. Another project's issue and an unknown id are
 * NOT_FOUND; an issue R6 does not let be linked is NOT_ELIGIBLE (another branch, a merge request,
 * an untracked branch for a Trivy issue, a closed issue).
 */
export async function issueTargets(
  db: Executor,
  projectId: string,
  issueIds: readonly string[],
): Promise<Resolved[]> {
  const rows = await db
    .select({
      id: issues.id,
      status: issues.status,
      packageName: issues.packageName,
      engineId: rules.engineId,
      engineRuleId: rules.engineRuleId,
      branch: { name: branches.name, isMain: branches.isMain, kind: branches.kind },
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .innerJoin(branches, eq(branches.id, issues.branchId))
    .where(
      and(eq(issues.projectId, projectId), inArray(issues.id, uuidList([...new Set(issueIds)]))),
    );
  const byId = new Map(rows.map((r) => [r.id, r]));
  const settings = await vulnerabilitySettings(db, projectId);
  return issueIds.map((id): Resolved => {
    const item = { issueId: id };
    const row = byId.get(id);
    if (!row) return { item, skipped: 'NOT_FOUND' };
    if (!issueLinkable(row, row.branch, settings)) return { item, skipped: 'NOT_ELIGIBLE' };
    return {
      item,
      target:
        isPairIssue(row) && row.packageName !== null
          ? {
              kind: 'vulnerability',
              packageName: row.packageName,
              vulnerabilityId: row.engineRuleId,
            }
          : { kind: 'issue', issueId: id },
    };
  });
}

/**
 * spec §6.3, ruling T6d: each pair as a vulnerability to link. One present as the sync pass
 * judges presence ({@link pairPresence}) is linkable; one the project holds only elsewhere (an
 * untracked target, a merge request, closed Trivy issues) is NOT_ELIGIBLE; any other is NOT_FOUND.
 */
export async function pairTargets(
  db: Executor,
  projectId: string,
  pairs: readonly Pair[],
): Promise<Resolved[]> {
  const presence = await pairPresence(db, projectId, pairs);
  return pairs.map((p): Resolved => {
    const key = pairKey(p.packageName, p.vulnerabilityId);
    if (presence.linkable.has(key)) return { item: p, target: { kind: 'vulnerability', ...p } };
    return { item: p, skipped: presence.known.has(key) ? 'NOT_ELIGIBLE' : 'NOT_FOUND' };
  });
}

/**
 * Azure DevOps plan Ruling 9: one tracker per finding. Each finding `linkedElsewhere` returns a row
 * of (the other tracker's link rows of the targets, in any state, by `targetKey`) is
 * ALREADY_LINKED with no link of this tracker.
 */
export async function withoutOtherTracker(
  resolved: readonly Resolved[],
  linkedElsewhere: (targets: LinkTarget[]) => Promise<ReadonlyMap<string, unknown>>,
): Promise<Resolved[]> {
  const targets = resolved.flatMap((r) => ('target' in r ? [r.target] : []));
  const other = targets.length === 0 ? new Map<string, unknown>() : await linkedElsewhere(targets);
  return resolved.map((r) =>
    'target' in r && other.has(targetKey(r.target))
      ? { item: r.item, skipped: 'ALREADY_LINKED' }
      : r,
  );
}

/** R9: 409 for a row Retry does not take back to pending. */
function notRetryable(): never {
  throw conflict(
    'JIRA_LINK_NOT_RETRYABLE',
    'Only a failed or missing Jira link can be retried; request a Jira issue to re-create a dismissed one',
  );
}

/**
 * Ruling T12b: Retry asks what a request asks of its finding (R6, R7, T6d): a code issue still on
 * the main branch and not closed, a pair still linkable. Otherwise 409, nothing changed.
 */
async function requireLinkable(db: Executor, projectId: string, link: JiraLinkRow): Promise<void> {
  const target = rowTarget(link);
  const [resolved] =
    target.kind === 'issue'
      ? await issueTargets(db, projectId, [target.issueId])
      : await pairTargets(db, projectId, [
          { packageName: target.packageName, vulnerabilityId: target.vulnerabilityId },
        ]);
  if (resolved && 'target' in resolved && resolved.target.kind === target.kind) return;
  throw conflict(
    'JIRA_LINK_NOT_RETRYABLE',
    'The finding of this Jira link is closed or can no longer have a Jira issue',
  );
}

/**
 * spec §6.4, §6.8: requesting Jira issues for findings, retrying a failed or missing link, and
 * unlinking (`issue.triage`). Each link made or re-armed costs its user one issue change (ruling
 * G7, the limiter `POST /issues/bulk-transition` charges), and the create job does the Jira calls.
 */
export const jiraLinkRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the issue routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  app.post(
    '/projects/:id/jira/links',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: `${CONNECTION_PROBLEMS}; JIRA_PROJECT_NOT_MAPPED: the project has no Jira mapping`,
            422: 'Validation failed (VALIDATION_FAILED), also without exactly one of `issueIds` and `vulnerabilities`',
            429: 'Too many issue changes by this user, one per link made or re-armed (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          'Request Jira issues for findings: exactly one of `issueIds` (1-500) or `vulnerabilities` (1-100). Each new finding, or one whose link was dismissed, failed or missing, gets a pending link that the create job sends to Jira. Items answer in request order: a Trivy issue under its `issueId` with its vulnerability link; NOT_FOUND, NOT_ELIGIBLE, or ALREADY_LINKED with the existing link',
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
      const { connection } = await linkPreconditions(deps.db, project);
      // Azure DevOps plan Ruling 9: a finding with an Azure Boards link row stays in Boards.
      const resolved = await withoutOtherTracker(
        issueIds !== undefined
          ? await issueTargets(deps.db, project.id, issueIds)
          : await pairTargets(deps.db, project.id, vulnerabilities ?? []),
        (targets) => boardsLinkRowsOf(deps.db, project.id, targets),
      );

      // One link per finding (R21): the first item of a finding claims it, the later ones answer
      // with its link.
      const targets = new Map<string, LinkTarget>();
      for (const r of resolved) {
        if ('target' in r && !targets.has(targetKey(r.target))) {
          targets.set(targetKey(r.target), r.target);
        }
      }
      const existing = await linkRowsOf(deps.db, project.id, [...targets.values()]);
      const fresh: LinkTarget[] = [];
      const rearm: JiraLinkRow[] = [];
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
        made: Map<string, JiraLinkRow>;
        lost: Map<string, JiraLinkRow>;
        siteUrl: string;
      };
      try {
        outcome = await deps.db.transaction(async (tx) => {
          // The lock order of the mapping save (project row, then connection row) and of the
          // connection save (connection row, then the links, the job schedule and the audit chain); a
          // removed connection stops here instead of failing the insert.
          await tx
            .select({ id: projects.id })
            .from(projects)
            .where(eq(projects.id, project.id))
            .for('key share');
          const [current] = await tx
            .select({ siteUrl: jiraConnections.siteUrl })
            .from(jiraConnections)
            .where(eq(jiraConnections.id, connection.id))
            .for('key share');
          if (!current) {
            throw conflict('JIRA_NOT_CONNECTED', 'The organisation has no Jira connection');
          }
          const pending = await insertPendingLinks(
            tx,
            { projectId: project.id, connectionId: connection.id, userId: principal.user.id },
            fresh,
          );
          for (const row of rearm) {
            const rearmed = await rearmLink(tx, row.id, REARMABLE_STATES, principal.user.id);
            if (rearmed) pending.push(rearmed);
          }
          const made = new Map(pending.map((row) => [targetKey(rowTarget(row)), row]));
          // A finding another request linked or re-armed meanwhile: its row as that one left it.
          const losers = [...fresh, ...rearm.map(rowTarget)].filter((t) => !made.has(targetKey(t)));
          const lost =
            losers.length === 0
              ? new Map<string, JiraLinkRow>()
              : await linkRowsOf(tx, project.id, losers);
          if (pending.length > 0) {
            await enqueueJiraCreate(tx, project.organizationId);
            await recordProjectEvent(deps.audit, tx, request, project, 'jira_link.requested', {
              count: pending.length,
              kind: issueIds !== undefined ? 'issue' : 'vulnerability',
            });
          }
          return { made, lost, siteUrl: current.siteUrl };
        });
      } catch (err) {
        if (charged > 0) chargeChanges.refund(principal.user.id, charged);
        throw err;
      }
      const lostCount = charged - outcome.made.size;
      if (lostCount > 0) chargeChanges.refund(principal.user.id, lostCount);

      const claimed = new Set<string>();
      const answer = (r: Resolved): { link: JiraLink | null; skipped: LinkSkip | null } => {
        if ('skipped' in r) return { link: null, skipped: r.skipped };
        const key = targetKey(r.target);
        const made = outcome.made.get(key);
        if (made && !claimed.has(key)) {
          claimed.add(key);
          return { link: jiraLinkDto(made, outcome.siteUrl), skipped: null };
        }
        const row = made ?? outcome.lost.get(key) ?? existing.get(key);
        return row
          ? { link: jiraLinkDto(row, outcome.siteUrl), skipped: 'ALREADY_LINKED' }
          : { link: null, skipped: 'NOT_FOUND' };
      };
      return reply.code(202).send({ items: resolved.map((r) => ({ ...r.item, ...answer(r) })) });
    },
  );

  app.post(
    '/jira-links/:id/retry',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: `${CONNECTION_PROBLEMS}; JIRA_LINK_NOT_RETRYABLE: the link is neither failed nor missing (R9), or its finding is closed or no longer linkable (a code issue off the main branch, a vulnerability no tracked target or Trivy issue holds)`,
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          'Retry a failed or missing Jira link whose finding may still have one (as for a request: a code issue of the main branch that is not closed, a vulnerability still linkable): it goes back to pending as a new create (its generation goes up, its old key, status and failure are cleared). The mapping is not checked: without one, the create job fails the link `not_mapped`',
        params: idParams,
        response: { 202: jiraLinkSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { link, project } = await jiraLinkFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      // Ruling P15: the connection, not the mapping.
      const connection = await usableConnection(deps.db, project);
      if (!(RETRYABLE_STATES as readonly string[]).includes(link.state)) notRetryable();
      await requireLinkable(deps.db, project.id, link);
      chargeChanges(principal.user.id, 1);
      let row: JiraLinkRow;
      try {
        row = await deps.db.transaction(async (tx) => {
          const rearmed = await rearmLink(tx, link.id, RETRYABLE_STATES, principal.user.id);
          if (!rearmed) notRetryable();
          await enqueueJiraCreate(tx, project.organizationId);
          await recordProjectEvent(deps.audit, tx, request, project, 'jira_link.requested', {
            count: 1,
            kind: rearmed.kind,
          });
          return rearmed;
        });
      } catch (err) {
        chargeChanges.refund(principal.user.id, 1);
        throw err;
      }
      return reply.code(202).send(jiraLinkDto(row, connection.siteUrl));
    },
  );

  app.delete(
    '/jira-links/:id',
    {
      schema: {
        tags: ['jira'],
        summary:
          'Unlink: the link becomes dismissed and reads as no link; its key is kept, the Jira issue stays, and the automatic rule never brings it back. Requesting a Jira issue for the finding again re-arms it. Unlinking a dismissed link changes nothing',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { link, project } = await jiraLinkFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      await deps.db.transaction(async (tx) => {
        const [dismissed] = await tx
          .update(jiraLinks)
          .set({ state: 'dismissed', updatedAt: sql`now()` })
          .where(and(eq(jiraLinks.id, link.id), ne(jiraLinks.state, 'dismissed')))
          .returning({ key: jiraLinks.jiraKey });
        if (!dismissed) return;
        // A key Jira gave in another form is recorded as none rather than refusing the unlink.
        const key =
          dismissed.key !== null &&
          dismissed.key.length <= 255 &&
          JIRA_ISSUE_KEY_PATTERN.test(dismissed.key)
            ? dismissed.key
            : null;
        await recordProjectEvent(deps.audit, tx, request, project, 'jira_link.dismissed', { key });
      });
      return reply.code(204).send();
    },
  );
};
