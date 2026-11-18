import { createHash } from 'node:crypto';
import type { FixClaimAnswer, FixClaimItem, FixFamily } from '@qualor/shared/fix';
import { and, eq, like, sql } from 'drizzle-orm';
import type { Db, Executor } from '../src/db/client';
import { dependencyFixes, jobs, projects, scmConnections } from '../src/db/schema';
import { FIX_QUEUE } from '../src/fixes/jobs';
import { fixBranchName } from '../src/fixes/rows';
import { fixHandlers, type FixJobDeps } from '../src/fixes/run';
import { runUntilIdle } from '../src/queue/worker';
import type { VulnerabilitySeverity } from '../src/vulnerabilities/order';
import { bearer } from './app';
import type { IngestHarness } from './ingest';
import { silentLogger } from './scm';
import { seedTargetRow } from './vulnerabilities';

// ─── qf-a: the package the fix job tests fix (Tasks 10 and 11) ──────────────

const NPM = 'https://registry.npmjs.org';

/** An app's `package.json` depending on qf-a at `range`. */
export const qfaPackageJson = (range: string): string =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }\n}\n`;

/** A made-up, stable integrity of qf-a at `version`. */
const qfaIntegrity = (version: string): string =>
  'sha512-' +
  createHash('sha512')
    .update('qf-a-' + version)
    .digest('base64');

/** Its `package-lock.json` with qf-a resolved to `version`. */
export const qfaPackageLock = (version: string): string =>
  `${JSON.stringify(
    {
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
        'node_modules/qf-a': {
          version,
          resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
          integrity: qfaIntegrity(version),
        },
      },
    },
    null,
    2,
  )}\n`;

const b64 = (text: string) => Buffer.from(text).toString('base64');

/** A project as its fix job sees it: its id, key and project token. */
export interface FixJobProject {
  id: string;
  key: string;
  token: string;
}

/** The fix job's claim of the project's js fixes, one at most (Task 9's route); 200 required. */
export async function claimFixes(
  h: IngestHarness,
  project: FixJobProject,
): Promise<FixClaimAnswer> {
  const res = await h.ctx.app.inject({
    method: 'POST',
    url: `/api/v0/projects/fixes/claim?projectKey=${encodeURIComponent(project.key)}`,
    headers: bearer(project.token),
    payload: { families: ['js'], branch: 'main', max: 1 },
  });
  if (res.statusCode !== 200) throw new Error(`claim: ${res.statusCode} ${res.body}`);
  return res.json() as FixClaimAnswer;
}

/** {@link claimFixes}, which must hand out exactly one fix. */
export async function claimFix(h: IngestHarness, project: FixJobProject): Promise<FixClaimItem> {
  const { items } = await claimFixes(h, project);
  if (items.length !== 1) throw new Error(`claim: ${items.length} items, not 1`);
  return items[0]!;
}

/** `PUT /fixes/{id}/result` of a claimed fix, with the claim's generation and lease. */
export function putFixResult(
  h: IngestHarness,
  project: FixJobProject,
  item: FixClaimItem,
  body: object,
) {
  return h.ctx.app.inject({
    method: 'PUT',
    url: `/api/v0/fixes/${item.id}/result`,
    headers: bearer(project.token),
    payload: { generation: item.generation, leaseToken: item.leaseToken, ...body },
  });
}

/** The good upload of qf-a 1.2.5 → 1.2.6 on `baseSha` (main's head); 202 required. */
export async function uploadQfA(
  h: IngestHarness,
  project: FixJobProject,
  item: FixClaimItem,
  baseSha: string | null,
): Promise<void> {
  const res = await putFixResult(h, project, item, {
    baseSha,
    installedVersion: '1.2.5',
    targetVersion: '1.2.6',
    targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
    files: [
      { path: 'package.json', content: b64(qfaPackageJson('^1.2.6')) },
      { path: 'package-lock.json', content: b64(qfaPackageLock('1.2.6')) },
    ],
    lockfiles: [{ path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] }],
    unfixable: [],
  });
  if (res.statusCode !== 202) throw new Error(`upload: ${res.statusCode} ${res.body}`);
}

/** A requested fix of qf-a, claimed and uploaded on `baseSha`: `committing`. Returns its id. */
export async function acceptedQfA(
  h: IngestHarness,
  project: FixJobProject,
  baseSha: string | null,
): Promise<string> {
  await seedFix(h.ctx.db, { projectId: project.id, family: 'js', packageName: 'qf-a' });
  const item = await claimFix(h, project);
  await uploadQfA(h, project, item, baseSha);
  return item.id;
}

/**
 * Drops the queued sync passes (a settings save queues one), so a test runs the organisation's
 * passes itself.
 */
export async function dropQueuedFixPasses(db: Db): Promise<void> {
  await db
    .delete(jobs)
    .where(
      and(
        eq(jobs.queue, FIX_QUEUE),
        eq(jobs.status, 'queued'),
        like(jobs.concurrencyKey, 'fix-sync:%'),
      ),
    );
}

/**
 * Runs the queued commit and close jobs now ({@link dropQueuedFixPasses} first) until the queue
 * is idle; returns how many jobs ran.
 */
export async function runFixJobs(db: Db, deps: FixJobDeps): Promise<number> {
  await dropQueuedFixPasses(db);
  await db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(and(eq(jobs.queue, FIX_QUEUE), eq(jobs.status, 'queued')));
  return runUntilIdle(db, fixHandlers(deps), silentLogger);
}

/**
 * An open fix of qf-a with its MR: accepted ({@link acceptedQfA}) and committed by Task 10's job.
 * Returns its id.
 */
export async function openQfA(
  h: IngestHarness,
  project: FixJobProject,
  baseSha: string | null,
  deps: FixJobDeps,
): Promise<string> {
  const fixId = await acceptedQfA(h, project, baseSha);
  await runFixJobs(h.ctx.db, deps);
  const [row] = await h.ctx.db
    .select({ state: dependencyFixes.state })
    .from(dependencyFixes)
    .where(eq(dependencyFixes.id, fixId));
  if (row?.state !== 'open') throw new Error(`fix ${fixId} is ${row?.state}, not open`);
  return fixId;
}

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
      return {
        prepared: {
          baseSha: 'b'.repeat(40),
          files: [],
          lockfiles: [],
          unfixable: [],
          additions: [],
        },
      };
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
