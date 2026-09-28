import { eq } from 'drizzle-orm';
import { projects, scmConnections } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import { enqueueDecoration } from './queue';

/**
 * scm.md §4.1, github.md §5.1, after `gate` and before `webhooks`: when the project is mapped
 * through a connection of the report's own provider (a GitLab project for a report from GitLab
 * CI, a GitHub repository for one from GitHub Actions), enqueue the decoration of this analysis in
 * the ingestion transaction. Nothing is sent here; a rolled-back analysis decorates nothing. The
 * mapping is read again inside the transaction (the project row was loaded before it began).
 */
export const scmStage: IngestionStage = {
  name: 'scm',
  async run(ctx) {
    const provider = ctx.report.scm.provider;
    if (provider === 'none') return;
    const [mapping] = await ctx.tx
      .select({ ref: projects.scmProjectRef, provider: scmConnections.provider })
      .from(projects)
      .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
      .where(eq(projects.id, ctx.project.id));
    // github.md §5.1: only through a connection of the report's own provider.
    if (!mapping || mapping.ref === null || mapping.provider !== provider) return;
    await enqueueDecoration(ctx.tx, {
      analysisId: ctx.analysisId,
      branchId: ctx.branch.id,
      gitlab: provider === 'gitlab' ? (ctx.report.scm.gitlab ?? null) : null,
      github: provider === 'github' ? (ctx.report.scm.github ?? null) : null,
    });
  },
};
