import { eq } from 'drizzle-orm';
import { projects, scmConnections } from '../src/db/schema';
import type { IngestHarness } from './ingest';

/**
 * Switches fix MRs on for the project, as an organisation admin does, through the API, and allows
 * them on the project's SCM connection when it has one (B2). `body` overrides any field of the
 * settings (`enabled`, `autoCreate`, `maxOpen`).
 */
export async function enableFixes(
  h: IngestHarness,
  projectId: string,
  body: object = {},
): Promise<void> {
  const res = await h.ctx.app.inject({
    method: 'PUT',
    url: `/api/v0/projects/${projectId}/fixes/settings`,
    headers: h.orgAdmin.headers,
    payload: {
      enabled: true,
      autoCreate: { minSeverity: null, exploited: false },
      maxOpen: 5,
      ...body,
    },
  });
  if (res.statusCode !== 200) throw new Error(`fix settings: ${res.body}`);
  const [project] = await h.ctx.db
    .select({ connectionId: projects.scmConnectionId })
    .from(projects)
    .where(eq(projects.id, projectId));
  if (project?.connectionId) {
    await h.ctx.db
      .update(scmConnections)
      .set({ fixMrsAllowed: true })
      .where(eq(scmConnections.id, project.connectionId));
  }
}
