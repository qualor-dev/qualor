import type { FixFamily } from '@qualor/shared/fix';
import { eq } from 'drizzle-orm';
import type { Executor } from '../src/db/client';
import { dependencyFixes, projects, scmConnections } from '../src/db/schema';
import { fixBranchName } from '../src/fixes/rows';
import type { VulnerabilitySeverity } from '../src/vulnerabilities/order';
import type { IngestHarness } from './ingest';
import { seedTargetRow } from './vulnerabilities';

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

/**
 * A vulnerability of an installed package on the project's main branch: its `vulnerability_matches`
 * row and its `target_vulnerabilities` row on the main target (`fixedVersion` is Trivy's comma
 * list, null for none).
 */
export async function seedMainVulnerability(
  db: Executor,
  project: { id: string; mainBranchId: string },
  row: {
    ecosystem: string;
    packageName: string;
    version: string;
    vulnerabilityId: string;
    severity: VulnerabilitySeverity;
    fixedVersion: string | null;
    firstSeenAt?: Date;
  },
): Promise<void> {
  await seedTargetRow(db, {
    projectId: project.id,
    branchId: project.mainBranchId,
    ecosystem: row.ecosystem,
    packageName: row.packageName,
    packageVersion: row.version,
    vulnerabilityId: row.vulnerabilityId,
    severity: row.severity,
    fixedVersion: row.fixedVersion,
    ...(row.firstSeenAt !== undefined && { firstSeenAt: row.firstSeenAt }),
  });
}

/** What the state checks of `dependency_fixes` need of a row in `state` (migration 0033). */
function stateFields(state: string | undefined): Partial<typeof dependencyFixes.$inferInsert> {
  switch (state) {
    case 'preparing':
      return {
        leaseTokenHash: 'f'.repeat(64),
        leaseUntil: new Date(Date.now() + 30 * 60_000),
      };
    case 'committing':
      return { prepared: { baseSha: 'b'.repeat(40), files: [], lockfiles: [], unfixable: [] } };
    case 'open':
      return { mrNumber: 12, mrUrl: 'https://scm.example/mr/12', headSha: 'c'.repeat(40) };
    default:
      return {};
  }
}

/**
 * A `dependency_fixes` row, `requested` and manual unless `row` says otherwise, on the package's
 * first branch name; a state the table's checks constrain gets what they need (a lease, prepared
 * files, an MR and its head) unless given. Returns its id.
 */
export async function seedFix(
  db: Executor,
  row: Partial<typeof dependencyFixes.$inferInsert> & {
    projectId: string;
    family: FixFamily;
    packageName: string;
  },
): Promise<string> {
  const [made] = await db
    .insert(dependencyFixes)
    .values({
      state: 'requested',
      origin: 'manual',
      branch: fixBranchName(row.family, row.packageName, 1),
      ...stateFields(row.state),
      ...row,
    })
    .returning({ id: dependencyFixes.id });
  if (!made) throw new Error('no fix seeded');
  return made.id;
}
