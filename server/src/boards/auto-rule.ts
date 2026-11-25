import { and, asc, eq, isNotNull, or } from 'drizzle-orm';
import { projectBoardsSettings, projects, scmConnections } from '../db/schema';
import { AUTO_PER_PASS, qualifyingPairs } from '../jira/auto-rule';
import { pairKey, type LinkTarget } from '../jira/links';
import { compare } from '../vulnerabilities/order';
import { insertPendingBoardsLinks } from './links';
import type { BoardsRunContext } from './run';

/*
 * Azure DevOps design §7.8: Jira's automatic rule (jira/auto-rule.ts, spec §6.6) for Azure Boards.
 * Which pairs qualify is Jira's `qualifyingPairs` itself, asked as Boards: it skips a pair with a
 * Boards link row in any state, or with a Jira one unless that failed before a Jira issue was made
 * (`blocksOtherTracker`); only the mappings and the rows written are Boards'.
 */

/**
 * The connection's mapped projects whose rule is on, as it applies now (an `exploited`-only rule
 * needs `vuln.priority`): the rule switched on longest ago first.
 */
async function ruleProjects(ctx: BoardsRunContext, priority: boolean): Promise<string[]> {
  const s = projectBoardsSettings;
  const rows = await ctx.deps.db
    .select({ projectId: s.projectId })
    .from(s)
    .where(
      and(
        eq(s.connectionId, ctx.connection.id),
        isNotNull(s.autoSince),
        priority
          ? or(isNotNull(s.autoMinSeverity), eq(s.autoExploited, true))
          : isNotNull(s.autoMinSeverity),
      ),
    )
    .orderBy(asc(s.autoSince), asc(s.projectId));
  return rows.map((r) => r.projectId);
}

/**
 * The project's qualifying pairs made pending rows (`origin` auto, no `created_by`, no audit) on
 * the mapping's connection and Azure DevOps project, in one transaction. It takes the links
 * route's lock order (the project row, then the connection row), then the mapping row shared, so
 * the rows are those of the rule as stored. A pair linked meanwhile makes none (`ON CONFLICT DO
 * NOTHING`); the rows are written by pair, so the route and the rule never deadlock. Returns how
 * many it made, or null when the connection is gone or has another address than the run's.
 */
function linkProject(
  ctx: BoardsRunContext,
  projectId: string,
  options: { priority: boolean; limit: number },
): Promise<number | null> {
  return ctx.deps.db.transaction(async (tx) => {
    await tx
      .select({ id: projects.id })
      .from(projects)
      .where(eq(projects.id, projectId))
      .for('key share');
    const [connection] = await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.id, ctx.connection.id),
          eq(scmConnections.baseUrl, ctx.connection.baseUrl),
        ),
      )
      .for('key share');
    if (!connection) return null;
    const [mapping] = await tx
      .select()
      .from(projectBoardsSettings)
      .where(eq(projectBoardsSettings.projectId, projectId))
      .for('share');
    if (!mapping || mapping.connectionId !== connection.id) return 0;
    const exploited = options.priority && mapping.autoExploited;
    const targets: LinkTarget[] = (
      await qualifyingPairs(tx, mapping, { exploited, limit: options.limit, tracker: 'boards' })
    )
      .map((p) => ({ kind: 'vulnerability' as const, ...p }))
      .sort((a, b) =>
        compare(
          pairKey(a.packageName, a.vulnerabilityId),
          pairKey(b.packageName, b.vulnerabilityId),
        ),
      );
    if (targets.length === 0) return 0;
    const made = await insertPendingBoardsLinks(
      tx,
      {
        projectId,
        connectionId: connection.id,
        azureProjectId: mapping.azureProjectId,
        userId: null,
      },
      targets,
    );
    return made.length;
  });
}

/**
 * Design §7.8, the pass's automatic rule: the connection's mapped projects, at most `cap` new
 * links in all (counted across those projects). The cap is per connection, as the pass is: an
 * organisation with several Azure DevOps connections gets `cap` per connection per pass. It calls
 * no Azure DevOps: the pass's create step
 * sends the rows. A stored `exploited` applies only while `vuln.priority` is active. Returns how
 * many links it made.
 */
export async function runBoardsAutoRule(
  ctx: BoardsRunContext,
  cap = AUTO_PER_PASS,
): Promise<number> {
  const { priority } = ctx.deps.limits().vulnerabilities;
  let made = 0;
  for (const projectId of await ruleProjects(ctx, priority)) {
    if (made >= cap) break;
    const n = await linkProject(ctx, projectId, { priority, limit: cap - made });
    if (n === null) break;
    made += n;
  }
  return made;
}
