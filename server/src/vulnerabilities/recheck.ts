import { performance } from 'node:perf_hooks';
import { asc, inArray, sql, type SQL } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import type { Config } from '../config';
import { jsonChunks, textList, uuidList } from '../db/bulk';
import type { Db, Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { projects } from '../db/schema';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { withLocalDatabase, type LocalProblem } from '../vulndb/local';
import { readVulndbSettings } from '../vulndb/settings';
import { readVulndbState, updateVulndbState, type VulndbState } from '../vulndb/state';
import { currentDataset } from '../vulndb/store';
import { enqueueVulnerabilityAlerts } from './alerts/enqueue';
import { purlOf } from './purl';
import { buildSbom, type SbomPackage } from './sbom';
import { projectTargets, type Target } from './targets';
import {
  createTrivyRunner,
  removeStaleWorkDirs,
  type TrivyRunner,
  type VulnerabilityMatch,
} from './trivy';

/** The re-check job's queue, and its concurrency key: one re-check at a time, across replicas. */
export const RECHECK_QUEUE = 'vulnerabilities.recheck';
/** At most this many components in one SBOM, so in one Trivy run. */
export const SBOM_MAX_COMPONENTS = 20_000;
export const TRIVY_TIMEOUT_MS = 15 * 60_000;
export const TRIVY_MAX_OUTPUT_BYTES = 512 * 1024 * 1024;
/** Projects read and written together: bounds the memory of a run and the length of a write. */
const PROJECT_BATCH = 25;
/** Values in one IN-list. */
const LIST_CHUNK = 10_000;

/** What to re-check: every project, or these. */
export type RecheckScope = { all: true } | { projectIds: string[] };

const scopeSchema = z.union([
  z.object({ all: z.literal(true) }),
  z.object({ projectIds: z.array(z.uuid()) }),
]);

/** A job's payload; one that does not parse is a full re-check (never too little). */
export function scopeOf(payload: unknown): RecheckScope {
  const parsed = scopeSchema.safeParse(payload);
  if (!parsed.success || 'all' in parsed.data) return { all: true };
  return { projectIds: [...new Set(parsed.data.projectIds)].sort() };
}

function mergeScopes(a: RecheckScope, b: RecheckScope): RecheckScope {
  if ('all' in a || 'all' in b) return { all: true };
  return { projectIds: [...new Set([...a.projectIds, ...b.projectIds])].sort() };
}

/**
 * Asks for a re-check of the tracked targets: of every project, or of these. A request while a
 * job is queued merges into its payload (the union of the projects; `all` wins). While a job runs,
 * one queued job waits behind it (the concurrency key keeps them serial).
 *
 * Under LOCKS.vulnerabilityRecheck, with the queued job's row locked until the caller's
 * transaction commits: the worker cannot claim the job (SKIP LOCKED) before the rows this request
 * is about are committed, and two requests never both insert one. Call it last in a transaction.
 */
export async function enqueueRecheck(db: Executor, scope: RecheckScope): Promise<void> {
  if ('projectIds' in scope && scope.projectIds.length === 0) return;
  const own = mergeScopes(scope, { projectIds: [] });
  await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityRecheck})`);
    const queued = await tx.execute<{ id: string; payload: unknown }>(sql`
      SELECT id, payload FROM jobs
       WHERE queue = ${RECHECK_QUEUE} AND status = 'queued'
       ORDER BY id
       LIMIT 1
         FOR UPDATE`);
    const job = queued.rows[0];
    if (job === undefined) {
      await enqueue(tx, { queue: RECHECK_QUEUE, concurrencyKey: RECHECK_QUEUE, payload: own });
      return;
    }
    const merged = mergeScopes(scopeOf(job.payload), own);
    if (JSON.stringify(merged) === JSON.stringify(scopeOf(job.payload))) return;
    await tx.execute(sql`
      UPDATE jobs SET payload = ${JSON.stringify(merged)}::jsonb, updated_at = now()
       WHERE id = ${job.id}`);
  });
}

export interface RecheckDeps {
  db: Db;
  config: { vulndb: Pick<Config['vulndb'], 'dir' | 'trivyPath'> };
  /** Tests substitute Trivy. */
  runner?: TrivyRunner;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** The server is stopping (main.ts): Trivy is killed, and the run ends at its next step. */
  shutdown?: AbortSignal;
}

export type RecheckSummary = NonNullable<VulndbState['lastRecheck']>;
type Problem = NonNullable<VulndbState['lastRecheckError']>;

export type RecheckResult =
  /** The instance switch is off: nothing was touched (ruling R6). */
  | { kind: 'off' }
  /** No current dataset: nothing was touched. */
  | { kind: 'no_data' }
  /** Stopped; `lastRecheckError` says why (rulings R12, R19). */
  | { kind: 'failed'; error: Problem }
  /** The server is stopping: nothing recorded, the scope queued again for the next server. */
  | { kind: 'stopped' }
  | { kind: 'done'; summary: RecheckSummary };

interface Package {
  ecosystem: string;
  name: string;
  version: string;
}

/** What one run uses from start to end: one dataset (its digest and its local copy). */
interface Run {
  db: Db;
  runner: TrivyRunner;
  cacheDir: string;
  digest: string;
  /** When the run started: the time {@link ignoreActive} judges expiry dates against. */
  now: Date;
  shutdown: AbortSignal | undefined;
}

/** What a run answers when the server's stop ended it (before a step, or by killing Trivy). */
const STOPPED = 'stopped';
const stopping = (of: { shutdown?: AbortSignal | undefined }): boolean =>
  of.shutdown?.aborted === true;

interface Counts {
  projects: number;
  packages: Set<string>;
  unchecked: Set<string>;
}

function* slices<T>(items: readonly T[], size: number): Generator<T[]> {
  for (let at = 0; at < items.length; at += size) yield items.slice(at, at + size);
}

const targetKey = (t: Target): string =>
  t.kind === 'branch' ? `b:${t.branchId}` : `v:${t.versionId}`;

/** The projects of the scope that still exist. */
async function projectsOf(db: Db, scope: RecheckScope): Promise<string[]> {
  if (!('all' in scope) && scope.projectIds.length === 0) return [];
  const query = db.select({ id: projects.id }).from(projects).orderBy(asc(projects.id));
  const rows = await ('all' in scope ? query : query.where(inArray(projects.id, scope.projectIds)));
  return rows.map((r) => r.id);
}

/** The distinct packages of these targets' inventories. */
async function distinctPackages(db: Db, targets: readonly Target[]): Promise<Package[]> {
  const branchIds = targets.flatMap((t) => (t.kind === 'branch' ? [t.branchId] : []));
  const versionIds = targets.flatMap((t) => (t.kind === 'version' ? [t.versionId] : []));
  const parts: SQL[] = [];
  if (branchIds.length > 0) {
    parts.push(sql`SELECT ecosystem, name, version FROM branch_dependencies
                    WHERE branch_id IN ${uuidList(branchIds)}`);
  }
  if (versionIds.length > 0) {
    parts.push(sql`SELECT ecosystem, name, version FROM version_dependencies
                    WHERE version_id IN ${uuidList(versionIds)}`);
  }
  if (parts.length === 0) return [];
  return (await db.execute<Package & Record<string, unknown>>(sql.join(parts, sql` UNION `))).rows;
}

/** Removes from `byPurl` the purls already matched against `digest`. */
async function dropFresh(db: Db, byPurl: Map<string, SbomPackage>, digest: string): Promise<void> {
  for (const part of slices([...byPurl.keys()], LIST_CHUNK)) {
    const fresh = await db.execute<{ purl: string }>(sql`
      SELECT purl FROM matched_packages
       WHERE dataset_digest = ${digest} AND purl IN ${textList(part)}`);
    for (const { purl } of fresh.rows) byPurl.delete(purl);
  }
}

/** A Trivy date, or null when it is not one. */
function timestampOf(text: string | null): string | null {
  if (text === null) return null;
  const at = Date.parse(text);
  return Number.isNaN(at) ? null : new Date(at).toISOString();
}

/** Replaces the matches of `purls` and marks them matched against `digest`, in one transaction. */
async function storeMatches(
  db: Db,
  purls: readonly string[],
  matches: ReadonlyMap<string, VulnerabilityMatch[]>,
  digest: string,
): Promise<void> {
  const rows: object[] = [];
  for (const purl of purls) {
    // Trivy can report one id twice for a package (one per advisory source): kept once.
    const seen = new Set<string>();
    for (const m of matches.get(purl) ?? []) {
      if (seen.has(m.vulnerabilityId)) continue;
      seen.add(m.vulnerabilityId);
      rows.push({
        purl,
        vulnerability_id: m.vulnerabilityId,
        severity: m.severity,
        title: m.title,
        fixed_version: m.fixedVersion,
        primary_url: m.primaryUrl,
        published_at: timestampOf(m.publishedAt),
      });
    }
  }
  await db.transaction(async (tx) => {
    for (const part of slices(purls, LIST_CHUNK)) {
      await tx.execute(sql`DELETE FROM vulnerability_matches WHERE purl IN ${textList(part)}`);
    }
    for (const chunk of jsonChunks(rows)) {
      await tx.execute(sql`
        INSERT INTO vulnerability_matches (purl, vulnerability_id, severity, title, fixed_version,
          primary_url, published_at)
        SELECT r.purl, r.vulnerability_id, r.severity, r.title, r.fixed_version, r.primary_url,
               r.published_at
          FROM jsonb_to_recordset(${chunk}::jsonb) AS r(purl text, vulnerability_id text,
               severity text, title text, fixed_version text, primary_url text,
               published_at timestamptz)`);
    }
    for (const chunk of jsonChunks(purls)) {
      await tx.execute(sql`
        INSERT INTO matched_packages (purl, dataset_digest, matched_at)
        SELECT p.purl, ${digest}, now() FROM jsonb_array_elements_text(${chunk}::jsonb) AS p(purl)
        ON CONFLICT (purl) DO UPDATE
          SET dataset_digest = excluded.dataset_digest, matched_at = excluded.matched_at`);
    }
  });
}

/**
 * Runs Trivy on `packages` in SBOMs of at most {@link SBOM_MAX_COMPONENTS}, storing each chunk's
 * matches as it comes. A failed run stops there, its chunk untouched (ruling R12); so does a stop.
 */
async function matchPackages(
  run: Run,
  packages: readonly SbomPackage[],
): Promise<Problem | typeof STOPPED | null> {
  for (const chunk of slices(packages, SBOM_MAX_COMPONENTS)) {
    if (stopping(run)) return STOPPED;
    const got = await run.runner.run(buildSbom(chunk), run.cacheDir, run.shutdown);
    if (!got.ok) {
      if (stopping(run)) return STOPPED;
      return {
        code: 'RECHECK_FAILED',
        message: `The vulnerability re-check stopped: Trivy failed (${got.code}): ${got.message}`,
      };
    }
    await storeMatches(
      run.db,
      chunk.map((p) => p.purl),
      got.matches,
      run.digest,
    );
  }
  return null;
}

/** A target's distinct packages (one per purl) and the ignore ids active when the run started. */
interface Inventory {
  projectId: string;
  target: Target;
  /** What the target's check records (see {@link writeChecks}), read before its packages. */
  basis: string;
  packages: Map<string, Package>;
  ignored: Set<string>;
}

const ignoreList = z
  .array(z.object({ id: z.string(), expiresAt: z.string().optional() }))
  .catch([]);

/**
 * Whether a `.trivyignore` entry still applies at `now`. As Trivy applies `exp:` in a scan, the
 * entry ends at 00:00 UTC of its `expiresAt` day: that day itself is no longer ignored (ruling
 * R16). Without `expiresAt` it never ends; an unreadable date ends it.
 */
export function ignoreActive(entry: { expiresAt?: string | undefined }, now: Date): boolean {
  if (entry.expiresAt === undefined) return true;
  const end = Date.parse(`${entry.expiresAt}T00:00:00Z`);
  return !Number.isNaN(end) && now.getTime() < end;
}

/** The ids of a stored `.trivyignore` list that are active at `now`. */
function ignoredIds(value: unknown, now: Date): Set<string> {
  return new Set(
    ignoreList
      .parse(value ?? [])
      .filter((e) => ignoreActive(e, now))
      .map((e) => e.id),
  );
}

/**
 * The basis of each branch and version: a branch's last analysis (empty when it has none), a
 * version's analysis time (UTC, to the millisecond, the same text every run).
 */
async function basesOf(
  db: Db,
  branchIds: readonly string[],
  versionIds: readonly string[],
): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  for (const part of slices(branchIds, LIST_CHUNK)) {
    const got = await db.execute<{ id: string; basis: string }>(sql`
      SELECT id, coalesce(last_analysis_id::text, '') AS basis
        FROM branches WHERE id IN ${uuidList(part)}`);
    for (const row of got.rows) result.set(row.id, row.basis);
  }
  for (const part of slices(versionIds, LIST_CHUNK)) {
    const got = await db.execute<{ id: string; basis: string }>(sql`
      SELECT id, coalesce(to_char(analyzed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), '') AS basis
        FROM project_versions WHERE id IN ${uuidList(part)}`);
    for (const row of got.rows) result.set(row.id, row.basis);
  }
  return result;
}

/**
 * The inventories of `targetsOf`. A branch's ignore ids are those of the analysis its inventory
 * came from (`branch_dependencies.analysis_id`); a version's are its own. Counts every package
 * into `counts`: with a purl, or as unchecked.
 */
async function inventories(
  run: Run,
  targetsOf: ReadonlyMap<string, Target[]>,
  counts: Counts,
): Promise<Inventory[]> {
  const ofBranch = new Map<string, Inventory>();
  const ofVersion = new Map<string, Inventory>();
  for (const [projectId, targets] of targetsOf) {
    for (const target of targets) {
      const inventory = {
        projectId,
        target,
        basis: '',
        packages: new Map(),
        ignored: new Set<string>(),
      };
      if (target.kind === 'branch') ofBranch.set(target.branchId, inventory);
      else ofVersion.set(target.versionId, inventory);
    }
  }
  // Before the packages: an analysis that lands in between leaves an older basis, never a newer one.
  const bases = await basesOf(run.db, [...ofBranch.keys()], [...ofVersion.keys()]);
  for (const [id, inventory] of ofBranch) inventory.basis = bases.get(id) ?? '';
  for (const [id, inventory] of ofVersion) inventory.basis = bases.get(id) ?? '';
  const add = (inventory: Inventory | undefined, p: Package): void => {
    const purl = purlOf(p.ecosystem, p.name, p.version);
    if (purl === null) {
      counts.unchecked.add(`${p.ecosystem}\u0000${p.name}\u0000${p.version}`);
      return;
    }
    counts.packages.add(purl);
    if (inventory !== undefined && !inventory.packages.has(purl)) {
      inventory.packages.set(purl, { ecosystem: p.ecosystem, name: p.name, version: p.version });
    }
  };
  type Row = Package & { owner: string; analysis_id: string | null };
  const branchesOf = new Map<string, Inventory[]>();
  if (ofBranch.size > 0) {
    const got = await run.db.execute<Row & Record<string, unknown>>(sql`
      SELECT DISTINCT branch_id AS owner, analysis_id, ecosystem, name, version
        FROM branch_dependencies
       WHERE branch_id IN ${uuidList([...ofBranch.keys()])}
       ORDER BY owner, ecosystem, name, version`);
    for (const row of got.rows) {
      const inventory = ofBranch.get(row.owner);
      add(inventory, row);
      if (inventory === undefined || row.analysis_id === null) continue;
      const list = branchesOf.get(row.analysis_id) ?? [];
      if (!list.includes(inventory)) list.push(inventory);
      branchesOf.set(row.analysis_id, list);
    }
  }
  if (ofVersion.size > 0) {
    const got = await run.db.execute<Row & Record<string, unknown>>(sql`
      SELECT DISTINCT version_id AS owner, NULL::uuid AS analysis_id, ecosystem, name, version
        FROM version_dependencies
       WHERE version_id IN ${uuidList([...ofVersion.keys()])}
       ORDER BY owner, ecosystem, name, version`);
    for (const row of got.rows) add(ofVersion.get(row.owner), row);
  }
  type Ignores = { id: string; ignores: unknown } & Record<string, unknown>;
  if (branchesOf.size > 0) {
    const got = await run.db.execute<Ignores>(sql`
      SELECT id, dependency_ignores AS ignores FROM analyses
       WHERE id IN ${uuidList([...branchesOf.keys()])}`);
    for (const row of got.rows) {
      const ids = ignoredIds(row.ignores, run.now);
      for (const inventory of branchesOf.get(row.id) ?? []) {
        for (const id of ids) inventory.ignored.add(id);
      }
    }
  }
  if (ofVersion.size > 0) {
    const got = await run.db.execute<Ignores>(sql`
      SELECT id, dependency_ignores AS ignores FROM project_versions
       WHERE id IN ${uuidList([...ofVersion.keys()])}`);
    for (const row of got.rows) {
      const inventory = ofVersion.get(row.id);
      if (inventory !== undefined) inventory.ignored = ignoredIds(row.ignores, run.now);
    }
  }
  return [...ofBranch.values(), ...ofVersion.values()];
}

/** The vulnerability ids stored for each of `purls`. */
async function vulnerabilitiesOf(db: Db, purls: readonly string[]): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();
  for (const part of slices(purls, LIST_CHUNK)) {
    const got = await db.execute<{ purl: string; vulnerability_id: string }>(sql`
      SELECT purl, vulnerability_id FROM vulnerability_matches WHERE purl IN ${textList(part)}`);
    for (const row of got.rows) {
      const list = result.get(row.purl);
      if (list === undefined) result.set(row.purl, [row.vulnerability_id]);
      else list.push(row.vulnerability_id);
    }
  }
  return result;
}

interface Wanted {
  projectId: string;
  target: Target;
  ecosystem: string;
  packageName: string;
  packageVersion: string;
  purl: string;
  vulnerabilityId: string;
  ignored: boolean;
}

const rowKey = (target: string, purl: string, vulnerabilityId: string): string =>
  `${target}\u0000${purl}\u0000${vulnerabilityId}`;

/**
 * Makes the rows of the tracked targets in `targetsOf` what `wanted` says: new rows are inserted
 * (first seen now), kept rows keep their id and first_seen_at and follow `ignored`, and a tracked
 * target's other rows go (vulnerabilities no longer found). Rows of untracked targets (a version
 * not tracked, a branch that no longer matches, every target of a project switched off) are left
 * as they are (ruling R17, spec §6.2 and §8.1): they go only with their target (FK cascade), and a
 * target tracked again is diffed against them, so its first_seen_at survives.
 *
 * One transaction; the projects, then the targets, are held FOR KEY SHARE until it commits, so a
 * deletion waits for it, and a target deleted before it gets no rows.
 */
async function writeTargets(
  db: Db,
  targetsOf: ReadonlyMap<string, Target[]>,
  wanted: ReadonlyMap<string, Wanted>,
  bases: ReadonlyMap<string, string>,
): Promise<void> {
  const projectIds = new Set<string>();
  const branchIds = new Set<string>();
  const versionIds = new Set<string>();
  for (const [projectId, targets] of targetsOf) {
    for (const t of targets) {
      projectIds.add(projectId);
      if (t.kind === 'branch') branchIds.add(t.branchId);
      else versionIds.add(t.versionId);
    }
  }
  if (projectIds.size === 0) return;
  await db.transaction(async (tx) => {
    const ids = async (table: 'projects' | 'branches' | 'project_versions', of: Set<string>) =>
      of.size === 0
        ? new Set<string>()
        : new Set(
            (
              await tx.execute<{ id: string }>(sql`
                SELECT id FROM ${sql.identifier(table)} WHERE id IN ${uuidList([...of])}
                 ORDER BY id FOR KEY SHARE`)
            ).rows.map((r) => r.id),
          );
    await ids('projects', projectIds);
    const liveBranches = await ids('branches', branchIds);
    const liveVersions = await ids('project_versions', versionIds);

    const ofTracked: SQL[] = [];
    if (branchIds.size > 0) ofTracked.push(sql`branch_id IN ${uuidList([...branchIds])}`);
    if (versionIds.size > 0) ofTracked.push(sql`version_id IN ${uuidList([...versionIds])}`);
    const existing = await tx.execute<{
      id: string;
      branch_id: string | null;
      version_id: string | null;
      purl: string;
      vulnerability_id: string;
      ignored: boolean;
    }>(sql`
      SELECT id, branch_id, version_id, purl, vulnerability_id, ignored
        FROM target_vulnerabilities
       WHERE ${sql.join(ofTracked, sql` OR `)}`);
    const seen = new Set<string>();
    const gone: string[] = [];
    const flips: { id: string; ignored: boolean }[] = [];
    for (const row of existing.rows) {
      const target = row.branch_id !== null ? `b:${row.branch_id}` : `v:${row.version_id ?? ''}`;
      const key = rowKey(target, row.purl, row.vulnerability_id);
      const want = wanted.get(key);
      if (want === undefined || seen.has(key)) {
        gone.push(row.id);
        continue;
      }
      seen.add(key);
      if (want.ignored !== row.ignored) flips.push({ id: row.id, ignored: want.ignored });
    }
    const fresh: object[] = [];
    for (const [key, w] of wanted) {
      if (seen.has(key)) continue;
      const live =
        w.target.kind === 'branch'
          ? liveBranches.has(w.target.branchId)
          : liveVersions.has(w.target.versionId);
      if (!live) continue;
      fresh.push({
        id: uuidv7(),
        project_id: w.projectId,
        branch_id: w.target.kind === 'branch' ? w.target.branchId : null,
        version_id: w.target.kind === 'version' ? w.target.versionId : null,
        ecosystem: w.ecosystem,
        package_name: w.packageName,
        package_version: w.packageVersion,
        purl: w.purl,
        vulnerability_id: w.vulnerabilityId,
        ignored: w.ignored,
      });
    }
    for (const part of slices(gone, LIST_CHUNK)) {
      await tx.execute(sql`DELETE FROM target_vulnerabilities WHERE id IN ${uuidList(part)}`);
    }
    for (const chunk of jsonChunks(flips)) {
      await tx.execute(sql`
        UPDATE target_vulnerabilities AS t SET ignored = r.ignored
          FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, ignored boolean)
         WHERE t.id = r.id`);
    }
    for (const chunk of jsonChunks(fresh)) {
      await tx.execute(sql`
        INSERT INTO target_vulnerabilities (id, project_id, branch_id, version_id, ecosystem,
          package_name, package_version, purl, vulnerability_id, ignored, first_seen_at)
        SELECT r.id, r.project_id, r.branch_id, r.version_id, r.ecosystem, r.package_name,
               r.package_version, r.purl, r.vulnerability_id, r.ignored, now()
          FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, project_id uuid, branch_id uuid,
               version_id uuid, ecosystem text, package_name text, package_version text,
               purl text, vulnerability_id text, ignored boolean)
        ON CONFLICT DO NOTHING`);
    }
    // After the inserts: a target's new rows and its baseline share the transaction's now().
    await writeChecks(
      tx,
      [...liveBranches].map((id) => ({ id, basis: bases.get(id) ?? '' })),
      [...liveVersions].map((id) => ({ id, basis: bases.get(id) ?? '' })),
    );
  });
}

/**
 * Records that the targets were checked now, each against the `basis` its inventory was read with
 * (see {@link basesOf}), not the one current now. A changed basis moves `baseline_at`, which is
 * what the rows first seen in this run (`first_seen_at` = now()) count as new from. Every target
 * given is written, rows or none.
 */
async function writeChecks(
  tx: Executor,
  branches: readonly { id: string; basis: string }[],
  versions: readonly { id: string; basis: string }[],
): Promise<void> {
  const moved = sql`
    checked_at = now(),
    basis = EXCLUDED.basis,
    baseline_at = CASE WHEN vulnerability_target_checks.basis IS DISTINCT FROM EXCLUDED.basis
                       THEN now() ELSE vulnerability_target_checks.baseline_at END`;
  for (const chunk of jsonChunks(branches)) {
    await tx.execute(sql`
      INSERT INTO vulnerability_target_checks (project_id, branch_id, basis, baseline_at, checked_at)
      SELECT b.project_id, b.id, r.basis, now(), now()
        FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, basis text)
        JOIN branches b ON b.id = r.id
      ON CONFLICT (branch_id) WHERE branch_id IS NOT NULL DO UPDATE SET ${moved}`);
  }
  for (const chunk of jsonChunks(versions)) {
    await tx.execute(sql`
      INSERT INTO vulnerability_target_checks (project_id, version_id, basis, baseline_at, checked_at)
      SELECT v.project_id, v.id, r.basis, now(), now()
        FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, basis text)
        JOIN project_versions v ON v.id = r.id
      ON CONFLICT (version_id) WHERE version_id IS NOT NULL DO UPDATE SET ${moved}`);
  }
}

/**
 * Steps 3–8 of a re-check, inside the local copy's lock. Two passes over the projects, a batch at a
 * time: the first collects the distinct packages not yet matched against this dataset and matches
 * them in as few Trivy runs as the 20 000 cap allows; the second diffs each batch's tracked
 * targets. Only tracked targets are read, matched and written: an untracked one keeps its rows
 * (R17). A package that entered an inventory between the passes is matched in the second.
 */
async function recheckAll(
  run: Run,
  projectIds: readonly string[],
): Promise<Counts | Problem | typeof STOPPED> {
  const pending = new Map<string, SbomPackage>();
  for (const batch of slices(projectIds, PROJECT_BATCH)) {
    if (stopping(run)) return STOPPED;
    const targets = [...(await projectTargets(run.db, batch)).values()].flat();
    const byPurl = new Map<string, SbomPackage>();
    for (const p of await distinctPackages(run.db, targets)) {
      const purl = purlOf(p.ecosystem, p.name, p.version);
      // R13: the SBOM names a package by its stored name.
      if (purl !== null && !pending.has(purl) && !byPurl.has(purl)) {
        byPurl.set(purl, { purl, name: p.name, version: p.version });
      }
    }
    await dropFresh(run.db, byPurl, run.digest);
    for (const [purl, p] of byPurl) pending.set(purl, p);
  }
  const failed = await matchPackages(run, [...pending.values()]);
  if (failed !== null) return failed;
  pending.clear();

  const counts: Counts = { projects: 0, packages: new Set(), unchecked: new Set() };
  for (const batch of slices(projectIds, PROJECT_BATCH)) {
    if (stopping(run)) return STOPPED;
    const targetsOf = await projectTargets(run.db, batch);
    const batchInventories = await inventories(run, targetsOf, counts);
    const late = new Map<string, SbomPackage>();
    for (const inventory of batchInventories) {
      for (const [purl, p] of inventory.packages) {
        if (!late.has(purl)) late.set(purl, { purl, name: p.name, version: p.version });
      }
    }
    const purls = [...late.keys()];
    await dropFresh(run.db, late, run.digest);
    if (late.size > 0) {
      const lateFailure = await matchPackages(run, [...late.values()]);
      if (lateFailure !== null) return lateFailure;
    }
    const vulnerabilities = await vulnerabilitiesOf(run.db, purls);
    const wanted = new Map<string, Wanted>();
    for (const inventory of batchInventories) {
      const key = targetKey(inventory.target);
      for (const [purl, p] of inventory.packages) {
        for (const vulnerabilityId of vulnerabilities.get(purl) ?? []) {
          wanted.set(rowKey(key, purl, vulnerabilityId), {
            projectId: inventory.projectId,
            target: inventory.target,
            ecosystem: p.ecosystem,
            packageName: p.name,
            packageVersion: p.version,
            purl,
            vulnerabilityId,
            ignored: inventory.ignored.has(vulnerabilityId),
          });
        }
      }
    }
    await writeTargets(
      run.db,
      targetsOf,
      wanted,
      new Map(
        batchInventories.map((i) => [
          i.target.kind === 'branch' ? i.target.branchId : i.target.versionId,
          i.basis,
        ]),
      ),
    );
    for (const targets of targetsOf.values()) if (targets.length > 0) counts.projects += 1;
  }
  return counts;
}

/**
 * The end of a good full re-check: the matches and marks of packages that no tracked inventory
 * has any more (`purls` is the run's set) go. The matches of a package some target still lists
 * stay, as an untracked target keeps its rows (R17); its mark goes, so the package is matched
 * again when a run needs it. Here and not in housekeeping: only a full run knows every inventory.
 */
async function pruneUnused(db: Db, purls: ReadonlySet<string>): Promise<void> {
  const inRun = JSON.stringify([...purls]);
  await db.transaction(async (tx) => {
    await tx.execute(sql`
      DELETE FROM vulnerability_matches m
       WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(${inRun}::jsonb) AS p(purl)
                          WHERE p.purl = m.purl)
         AND NOT EXISTS (SELECT 1 FROM target_vulnerabilities t WHERE t.purl = m.purl)`);
    await tx.execute(sql`
      DELETE FROM matched_packages m
       WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(${inRun}::jsonb) AS p(purl)
                          WHERE p.purl = m.purl)`);
  });
}

/** R19: the re-check's own field; the update job's `lastError` is never touched here. */
const setError = (db: Db, error: Problem) =>
  updateVulndbState(db, (state) => ({ ...state, lastRecheckError: error }));

/**
 * A run the server's stop ended: nothing is recorded, and the scope is queued again, for the next
 * server (main.ts stops this one's worker from claiming it). What the run already stored stays
 * valid: matches carry their dataset's digest, and each written batch is a whole diff.
 */
async function stoppedRun(deps: RecheckDeps, scope: RecheckScope): Promise<RecheckResult> {
  await enqueueRecheck(deps.db, scope);
  deps.logger?.info(
    { component: 'vulnerabilities' },
    'vulnerability re-check stopped: the server is stopping; it is queued again',
  );
  return { kind: STOPPED };
}

/**
 * One re-check of the scope's projects against the current dataset, without a scan:
 *
 * 1. The instance switch off, or no dataset: nothing is touched. The dataset is read once and used
 *    to the end, even when another becomes current meanwhile (its digest tags what it matched).
 * 2. The local copy of that dataset is held for the run, and the Trivy work directories a killed
 *    run left in its directory are removed; DISK (or MISSING, as RECHECK_FAILED)
 *    goes to `lastRecheckError` (ruling R19), as does a failed Trivy run (R12).
 * 3–5. The packages not yet matched against it run through Trivy, 20 000 per SBOM.
 * 6–7. Each tracked target's rows follow its inventory ({@link writeTargets}).
 * 8. Untracked targets (a version not tracked, a branch that no longer matches, every target of a
 *    project switched off) are not re-checked and keep their rows (ruling R17, spec §6.2, §8.1).
 * 9. A good full re-check writes `lastRecheck` and clears `lastRecheckError`; a scoped one leaves
 *    both (rulings R15, R22). The update job's `lastError` is never touched.
 *
 * A stop of the server (`shutdown`) cuts the extraction or kills Trivy, and ends the run before
 * its next batch or chunk ({@link stoppedRun}).
 */
export async function recheckProjects(
  deps: RecheckDeps,
  scope: RecheckScope,
): Promise<RecheckResult> {
  const started = performance.now();
  const now = deps.now ?? (() => new Date());
  if (!(await readVulndbSettings(deps.db)).enabled) return { kind: 'off' };
  const dataset = await currentDataset(deps.db, await readVulndbState(deps.db));
  if (dataset === null) return { kind: 'no_data' };
  if (stopping(deps)) return stoppedRun(deps, scope);
  const projectIds = await projectsOf(deps.db, scope);
  const runner =
    deps.runner ??
    createTrivyRunner({
      command: [deps.config.vulndb.trivyPath],
      workDir: deps.config.vulndb.dir,
      timeoutMs: TRIVY_TIMEOUT_MS,
      maxOutputBytes: TRIVY_MAX_OUTPUT_BYTES,
    });
  let local: { result: Counts | Problem | typeof STOPPED } | { problem: LocalProblem };
  try {
    local = await withLocalDatabase(
      deps.db,
      deps.config.vulndb.dir,
      dataset,
      async (cacheDir) => {
        // Under the lock, so no run of this server uses them: what a killed run left goes.
        await removeStaleWorkDirs(deps.config.vulndb.dir);
        return recheckAll(
          {
            db: deps.db,
            runner,
            cacheDir,
            digest: dataset.digest,
            now: now(),
            shutdown: deps.shutdown,
          },
          projectIds,
        );
      },
      { signal: deps.shutdown },
    );
  } catch (err) {
    // The stop cut the extraction (or whatever it was doing): not this run's failure.
    if (stopping(deps)) return stoppedRun(deps, scope);
    throw err;
  }
  const outcome: Counts | Problem | typeof STOPPED =
    'problem' in local
      ? {
          code: local.problem.code === 'DISK' ? 'DISK' : 'RECHECK_FAILED',
          message: local.problem.message,
        }
      : local.result;
  if (outcome === STOPPED) return stoppedRun(deps, scope);
  if ('code' in outcome) {
    await setError(deps.db, outcome);
    deps.logger?.warn(
      { component: 'vulnerabilities', code: outcome.code, message: outcome.message },
      'vulnerability re-check failed',
    );
    return { kind: 'failed', error: outcome };
  }
  if ('all' in scope) {
    // Housekeeping of the shared tables: a problem here never fails a re-check that is done.
    try {
      await pruneUnused(deps.db, outcome.packages);
    } catch (err) {
      deps.logger?.warn(
        {
          component: 'vulnerabilities',
          errorClass: err instanceof Error ? err.constructor.name : typeof err,
        },
        'vulnerability matches were not pruned',
      );
    }
  }
  const summary: RecheckSummary = {
    at: now().toISOString(),
    projects: outcome.projects,
    packages: outcome.packages.size,
    unchecked: outcome.unchecked.size,
    durationMs: Math.round(performance.now() - started),
  };
  await updateVulndbState(deps.db, (state) => ({
    ...state,
    // R15: the admin line describes the last full re-check, not the last ingestion.
    lastRecheck: 'all' in scope ? summary : state.lastRecheck,
    // R22: one project's good run says nothing about the rest; only a full run clears the error.
    lastRecheckError: 'all' in scope ? null : state.lastRecheckError,
  }));
  deps.logger?.info({ component: 'vulnerabilities', ...summary }, 'vulnerability re-check done');
  // 4b: the alert job looks at what this run wrote. A stopped run never gets here (it is queued again).
  await enqueueVulnerabilityAlerts(deps.db);
  return { kind: 'done', summary };
}

/** The `vulndb` worker's handler for `vulnerabilities.recheck` (main.ts). */
export function recheckHandlers(deps: RecheckDeps): JobHandlers {
  return {
    [RECHECK_QUEUE]: async (job) => {
      await recheckProjects(deps, scopeOf(job.payload));
    },
  };
}
