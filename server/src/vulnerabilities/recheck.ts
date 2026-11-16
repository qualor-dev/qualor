import { performance } from 'node:perf_hooks';
import { asc, inArray, sql, type SQL } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { isOsPackageType, OS_PACKAGE_TYPES } from '@qualor/shared';
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
import { invalidStoredPackage, matchKeyOf, osMatchKey, osSourceOf } from './purl';
import { buildOsSbom, buildSbom, sbomGroupKey, type SbomPackage } from './sbom';
import { projectTargets, type Target } from './targets';
import {
  createTrivyRunner,
  MAX_VENDOR_IDS,
  removeStaleWorkDirs,
  type TrivyRun,
  type TrivyRunner,
  type VulnerabilityMatch,
} from './trivy';

/** The re-check job's queue, and its concurrency key: one re-check at a time, across replicas. */
export const RECHECK_QUEUE = 'vulnerabilities.recheck';
/**
 * At most this many components in one SBOM, so in one Trivy run. Trivy's output grows with the
 * advisories found, not with the components: the densest inventory measured (old versions of
 * popular packages, 60% vulnerable, 5 414 distinct purls) wrote 28 KB per package, so 1 000
 * components write about 28 MB, where 20 000 wrote 570 MB and killed the server's heap.
 */
export const SBOM_MAX_COMPONENTS = 1_000;
export const TRIVY_TIMEOUT_MS = 15 * 60_000;
/**
 * The most output one run may leave for `JSON.parse` (about 3.5 times that in heap: 154 MB of
 * output exhausted the 512 MB heap of a 1 GiB server). Over it, the run answers TOO_LARGE unread.
 */
export const TRIVY_MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
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
    // A merged request runs now: a job on retry backoff (failJob) does not wait it out.
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
    const unchanged = JSON.stringify(merged) === JSON.stringify(scopeOf(job.payload));
    await tx.execute(
      unchanged
        ? sql`UPDATE jobs SET run_at = least(run_at, now()), updated_at = now() WHERE id = ${job.id}`
        : sql`
      UPDATE jobs SET payload = ${JSON.stringify(merged)}::jsonb,
                      run_at = least(run_at, now()), updated_at = now()
       WHERE id = ${job.id}`,
    );
  });
}

/**
 * At boot (main.ts), A14: migration 0028 cleared every package's mark, so that each match gets
 * Trivy's vendor ids. While monitoring is on and a mark is cleared, one full re-check is queued (a
 * second replica's request merges into it), and logged with its reason. A good full re-check
 * marks or prunes every package, so the next boot queues none; after a failed one, the next boot
 * asks again. Answers whether it queued.
 */
export async function queueRematchIfCleared(
  db: Executor,
  logger?: Pick<FastifyBaseLogger, 'info'>,
): Promise<boolean> {
  if (!(await readVulndbSettings(db)).enabled) return false;
  const cleared = await db.execute<{ cleared: boolean }>(sql`
    SELECT EXISTS (SELECT 1 FROM matched_packages WHERE dataset_digest = '') AS cleared`);
  if (cleared.rows[0]?.cleared !== true) return false;
  await enqueueRecheck(db, { all: true });
  logger?.info(
    { component: 'vulnerabilities' },
    'a full vulnerability re-check is queued: the upgrade cleared the packages’ match marks, so every match gets Trivy’s vendor ids',
  );
  return true;
}

export interface RecheckDeps {
  db: Db;
  config: { vulndb: Pick<Config['vulndb'], 'dir' | 'trivyPath'> };
  /** Tests substitute Trivy. */
  runner?: TrivyRunner;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** Tests make chunks small: components per SBOM. */
  chunk?: { components?: number };
  /** Tests only: how long to wait for the local copy's lock (default LOCAL_LOCK_WAIT_MS). */
  lockWaitMs?: number;
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

/** A package of an inventory, with its version's distribution and its source (0.16 SBOMs). */
interface Package {
  ecosystem: string;
  name: string;
  version: string;
  /** The distribution of the version it belongs to; null on a branch or without one. */
  osFamily: string | null;
  osVersion: string | null;
  /** The source package an SBOM named; null on a branch and for libraries. */
  sourceName: string | null;
  sourceVersion: string | null;
  /**
   * The arch and modularity label an SBOM named for an rpm (Task 9b): Trivy matches Red Hat-family
   * advisories by them. Null for every other package, so deb and apk rows stay one per key.
   */
  arch: string | null;
  modularityLabel: string | null;
  /** The organisation of the project holding it (first pass only), for R17 and R19. */
  organizationId?: string | null;
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
  chunk: { components: number };
  /** Trivy runs made so far, splits included. */
  trivyRuns: number;
  /**
   * The {@link sbomGroupKey} of each distribution Trivy cannot scan, found in this run
   * ({@link faultOf}): its packages stay unchecked, and its other chunks are not run.
   */
  failedGroups: Set<string>;
  /** Those distributions as `<family> <version>`, for the summary. */
  unsupported: Set<string>;
  /**
   * The match keys of the single packages Trivy failed on, or answered too much for, in this run:
   * they stay unchecked.
   */
  failedKeys: Set<string>;
  /** The match keys given up because every organisation holding them is past its budget. */
  overBudget: Set<string>;
  /**
   * The organisations holding each package sent to Trivy (rulings R17, R19): one id, or a set once
   * a second organisation holds it. Ids are shared through `organizationIds`.
   */
  owners: Map<string, string | Set<string>>;
  /** One string per organisation id, so that `owners` holds no copies. */
  organizationIds: Map<string, string>;
  /** Single packages Trivy failed on in this run, per organisation holding them. */
  failuresOf: Map<string, number>;
  logger: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
}

/** What a run answers when the server's stop ended it (before a step, or by killing Trivy). */
const STOPPED = 'stopped';
const stopping = (of: { shutdown?: AbortSignal | undefined }): boolean =>
  of.shutdown?.aborted === true;

interface Counts {
  projects: number;
  /** The match keys of the inventories' packages. */
  packages: Set<string>;
  unchecked: Set<string>;
  /** Of `unchecked`, the packages whose stored values keep them from a key ({@link invalidStoredPackage}). */
  invalid: Set<string>;
  /** The keys of OS packages, by {@link sbomGroupKey}: a group Trivy cannot scan is unchecked. */
  osGroups: Map<string, Set<string>>;
}

/** How the steps of a re-check ended: its counts, the problem that stopped it, or a stop. */
type RecheckOutcome = Counts | Problem | typeof STOPPED;

function* slices<T>(items: readonly T[], size: number): Generator<T[]> {
  for (let at = 0; at < items.length; at += size) yield items.slice(at, at + size);
}

const targetKey = (t: Target): string =>
  t.kind === 'branch' ? `b:${t.branchId}` : `v:${t.versionId}`;

/** The projects of the scope that still exist. */
async function projectsOf(db: Db, scope: RecheckScope): Promise<string[]> {
  if (!('all' in scope) && scope.projectIds.length === 0) return [];
  const query = db.select({ id: projects.id }).from(projects).orderBy(asc(projects.id));
  const rows = await ('all' in scope
    ? query
    : query.where(inArray(projects.id, uuidList(scope.projectIds))));
  return rows.map((r) => r.id);
}

/** The OS package types (deb, rpm, apk), as an SQL list. */
const OS_TYPES = sql`(${sql.join(
  OS_PACKAGE_TYPES.map((type) => sql`${type}`),
  sql`, `,
)})`;

/** Of the OS package types, the one whose key holds the arch and the modularity label (Task 9b). */
const RPM = 'rpm';

/**
 * The columns of {@link Package} from `version_dependencies d` joined to its `project_versions v`:
 * the distribution and the source only for OS packages, so a library stays one row per
 * (ecosystem, name, version) across the targets; the arch and the modularity label only for rpm,
 * so a deb or apk package stays one row whatever its arch.
 */
const VERSION_PACKAGE = sql`d.ecosystem, d.name, d.version,
  CASE WHEN d.ecosystem IN ${OS_TYPES} THEN v.os_family END AS "osFamily",
  CASE WHEN d.ecosystem IN ${OS_TYPES} THEN v.os_version END AS "osVersion",
  CASE WHEN d.ecosystem IN ${OS_TYPES} THEN d.source_name END AS "sourceName",
  CASE WHEN d.ecosystem IN ${OS_TYPES} THEN d.source_version END AS "sourceVersion",
  CASE WHEN d.ecosystem = ${RPM} THEN d.arch END AS arch,
  CASE WHEN d.ecosystem = ${RPM} THEN d.modularity_label END AS "modularityLabel"`;
/** The organisation of the package's project (`projects p`). */
const OWNER = sql`p.organization_id::text AS "organizationId"`;
/** A branch has no distribution, no source packages, no arch and no modularity label. */
const BRANCH_PACKAGE = sql`d.ecosystem, d.name, d.version, NULL::text AS "osFamily",
  NULL::text AS "osVersion", NULL::text AS "sourceName", NULL::text AS "sourceVersion",
  NULL::text AS arch, NULL::text AS "modularityLabel"`;

/** The distinct packages of these targets' inventories. */
async function distinctPackages(db: Db, targets: readonly Target[]): Promise<Package[]> {
  const branchIds = targets.flatMap((t) => (t.kind === 'branch' ? [t.branchId] : []));
  const versionIds = targets.flatMap((t) => (t.kind === 'version' ? [t.versionId] : []));
  const parts: SQL[] = [];
  if (branchIds.length > 0) {
    parts.push(sql`SELECT ${BRANCH_PACKAGE}, ${OWNER}
                     FROM branch_dependencies d JOIN branches b ON b.id = d.branch_id
                     JOIN projects p ON p.id = b.project_id
                    WHERE d.branch_id IN ${uuidList(branchIds)}`);
  }
  if (versionIds.length > 0) {
    parts.push(sql`SELECT ${VERSION_PACKAGE}, ${OWNER}
                     FROM version_dependencies d JOIN project_versions v ON v.id = d.version_id
                     JOIN projects p ON p.id = v.project_id
                    WHERE d.version_id IN ${uuidList(versionIds)}`);
  }
  if (parts.length === 0) return [];
  return (await db.execute<Package & Record<string, unknown>>(sql.join(parts, sql` UNION `))).rows;
}

/**
 * What Trivy is given for a package: its match key (for an rpm, with its arch and modularity label,
 * which Trivy reads from the purl) and, for an OS package, its distribution and source package
 * ({@link osSourceOf}, the one the key holds). Null when it is not checked: no match key
 * ({@link matchKeyOf}: values that fail validation, no purl type, an OS package without a known
 * distribution).
 */
function sbomPackageOf(p: Package): SbomPackage | null {
  const purl = matchKeyOf(p);
  if (purl === null) return null;
  if (!isOsPackageType(p.ecosystem)) return { purl, name: p.name, version: p.version };
  if (p.osFamily === null || p.osVersion === null) return null;
  const source = osSourceOf(p);
  return {
    purl,
    name: p.name,
    version: p.version,
    os: {
      type: p.ecosystem,
      family: p.osFamily,
      osVersion: p.osVersion,
      sourceName: source.name,
      sourceVersion: source.version,
    },
  };
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
    // Trivy 0.74 reports an id once per package. Should one come twice, it is kept once: the first
    // report, with the vendor ids of both. `vendor_ids` is always sent: a missing key is NULL.
    const byId = new Map<string, { vendor_ids: string[] }>();
    for (const m of matches.get(purl) ?? []) {
      const kept = byId.get(m.vulnerabilityId);
      if (kept !== undefined) {
        kept.vendor_ids = [...new Set([...kept.vendor_ids, ...m.vendorIds])].slice(
          0,
          MAX_VENDOR_IDS,
        );
        continue;
      }
      const row = {
        purl,
        vulnerability_id: m.vulnerabilityId,
        severity: m.severity,
        title: m.title,
        fixed_version: m.fixedVersion,
        primary_url: m.primaryUrl,
        published_at: timestampOf(m.publishedAt),
        vendor_ids: [...new Set(m.vendorIds)],
      };
      byId.set(m.vulnerabilityId, row);
      rows.push(row);
    }
  }
  await db.transaction(async (tx) => {
    for (const part of slices(purls, LIST_CHUNK)) {
      await tx.execute(sql`DELETE FROM vulnerability_matches WHERE purl IN ${textList(part)}`);
    }
    for (const chunk of jsonChunks(rows)) {
      await tx.execute(sql`
        INSERT INTO vulnerability_matches (purl, vulnerability_id, severity, title, fixed_version,
          primary_url, published_at, vendor_ids)
        SELECT r.purl, r.vulnerability_id, r.severity, r.title, r.fixed_version, r.primary_url,
               r.published_at, r.vendor_ids
          FROM jsonb_to_recordset(${chunk}::jsonb) AS r(purl text, vulnerability_id text,
               severity text, title text, fixed_version text, primary_url text,
               published_at timestamptz, vendor_ids text[])`);
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
 * The chunks of `packages` in the order they run: one {@link sbomGroupKey} group after another
 * (libraries first), each cut into SBOMs of at most `size`. The groups and single packages Trivy
 * failed on in this run are left out. Reversed, so that `pop()` takes them in order.
 */
function chunksOf(
  run: Run,
  packages: readonly SbomPackage[],
  size: number,
): (readonly SbomPackage[])[] {
  const groups = new Map<string, SbomPackage[]>([['', []]]);
  for (const p of packages) {
    const key = sbomGroupKey(p);
    if (run.failedGroups.has(key) || run.failedKeys.has(p.purl) || run.overBudget.has(p.purl)) {
      continue;
    }
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [p]);
    else group.push(p);
  }
  const chunks: (readonly SbomPackage[])[] = [];
  for (const group of groups.values()) {
    for (const chunk of slices(group, size)) chunks.push(chunk);
  }
  return chunks.reverse();
}

/**
 * Single packages Trivy may fail on (or answer too much for), one by one, in one run, before an
 * organisation's other packages found in a failing chunk are given up for the run (unchecked,
 * `givenUp.overBudget`) instead of bisected (ruling R17). Counted per organisation, never for the
 * instance: a package is given up so only when every organisation that holds it is past its
 * budget. This bounds the Trivy runs one tenant's data can cost to about twice this many times
 * log2 of a chunk (each failed step also runs a probe).
 */
export const MAX_FAILED_PER_ORGANISATION = 16;
/** The package of an OS probe SBOM: a name no vulnerability database holds. */
const PROBE = 'qualor-release-probe';
/**
 * Ruling R20: for each package type and family, a release that Trivy 0.74.0 scans with every
 * database, checked with the probe SBOM against the full trivy-db layer of 2026-09-25 and against
 * the test fixture (`redhat 9` and `centos 7` fail on the fixture, so 8 for both). A family not
 * here takes {@link DEFAULT_KNOWN_GOOD}.
 */
const KNOWN_GOOD: Readonly<Record<string, string>> = {
  'deb debian': '12',
  'deb ubuntu': '22.04',
  'deb echo': '1',
  'apk alpine': '3.20',
  'apk wolfi': '20230201',
  'apk chainguard': '20230214',
  'apk minimos': '20241231',
  'rpm redhat': '8',
  'rpm centos': '8',
  'rpm rocky': '9',
  'rpm alma': '9',
  'rpm oracle': '9',
  'rpm amazon': '2023',
  'rpm cbl-mariner': '2.0',
  'rpm azurelinux': '3.0',
  'rpm photon': '5.0',
  'rpm opensuse-leap': '15.5',
  'rpm opensuse-tumbleweed': '20240101',
  'rpm sles': '15.5',
  'rpm slem': '5.5',
  'rpm coreos': '40',
};
const DEFAULT_KNOWN_GOOD = { type: 'deb', family: 'debian', osVersion: '12' } as const;
/** Ruling R19: the library probe, a package every Trivy database scans. */
const LIBRARY_PROBE: SbomPackage = {
  purl: 'pkg:npm/lodash@4.17.20',
  name: 'lodash',
  version: '4.17.20',
};

type OsRelease = Pick<NonNullable<SbomPackage['os']>, 'type' | 'family' | 'osVersion'>;

/** The known-good release of a distribution's family and package type (R20). */
function knownGoodOf(os: OsRelease): OsRelease {
  const key = `${os.type} ${os.family}`;
  const osVersion = Object.hasOwn(KNOWN_GOOD, key) ? KNOWN_GOOD[key] : undefined;
  return osVersion === undefined ? DEFAULT_KNOWN_GOOD : { ...os, osVersion };
}

/**
 * What a failed run was (ruling R21):
 * - `'rejected'`: Trivy ran and exited with a non-zero code, its own answer;
 * - `'heavy'`: Trivy ran but gave no answer for the size of its work: its output over the cap
 *   (TOO_LARGE), over the time limit (TIMEOUT), or killed by a signal the server did not send (the
 *   kernel's OOM killer: Trivy builds its report in memory). Our own kills answer TOO_LARGE,
 *   TIMEOUT or ABORTED, never a signal death;
 * - `'infrastructure'`: Trivy never ran its scan (not installed, a spawn error, EACCES, no work
 *   directory) or wrote no readable output: the server's problem, never a package's.
 */
function failureOf(got: Extract<TrivyRun, { ok: false }>): 'rejected' | 'heavy' | 'infrastructure' {
  if (got.code === 'TOO_LARGE' || got.code === 'TIMEOUT') return 'heavy';
  if (got.code !== 'FAILED' || got.exitCode === undefined) return 'infrastructure';
  return got.exitCode === null ? 'heavy' : 'rejected';
}

const failedRun = (got: Extract<TrivyRun, { ok: false }>): Problem => ({
  code: 'RECHECK_FAILED',
  message: `The vulnerability re-check stopped: Trivy failed (${got.code}): ${got.message}`,
});

/** One made-up package of a release: an SBOM that holds no stored package data. */
function probeSbom(os: OsRelease): string {
  const source = { name: PROBE, version: '0' };
  return buildOsSbom([
    {
      purl: osMatchKey(os.type, os.family, os.osVersion, PROBE, '0', source),
      name: PROBE,
      version: '0',
      os: { ...os, sourceName: PROBE, sourceVersion: '0' },
    },
  ]);
}

type ProbeAnswer =
  | { kind: 'ok' }
  /** Trivy rejected it, or answered too much for it: Trivy, not the data, is at fault. */
  | { kind: 'failed'; message: string }
  /** A stop, or a failure that is not Trivy's answer (no work directory, spawn error, …). */
  | { kind: 'end'; end: Problem | typeof STOPPED };

async function runProbe(run: Run, sbom: string): Promise<ProbeAnswer> {
  run.trivyRuns += 1;
  const answer = await run.runner.run(sbom, run.cacheDir, run.shutdown);
  if (stopping(run)) return { kind: 'end', end: STOPPED };
  if (answer.ok) return { kind: 'ok' };
  if (failureOf(answer) === 'infrastructure') return { kind: 'end', end: failedRun(answer) };
  return { kind: 'failed', message: `Trivy failed (${answer.code}): ${answer.message}` };
}

const broken = (message: string): Problem => ({
  code: 'RECHECK_FAILED',
  message: `The vulnerability re-check stopped: Trivy fails on the server's own probe SBOM, so Trivy or its database is broken: ${message}`,
});

/**
 * Who is at fault for a failed chunk, decided in the step itself and never remembered (rulings
 * R17, R19, R20), by probe SBOMs that hold no stored package:
 * - a library chunk: the {@link LIBRARY_PROBE} passes, so the packages are (`'packages'`); it
 *   fails, so Trivy or its database is broken, and the run fails;
 * - an OS chunk: a probe of its distribution (the tenant's family and version string) passes, so
 *   the packages are. It fails, and a known-good release of the same family and package type
 *   ({@link knownGoodOf}) passes: the distribution string is (`'release'`). Trivy fails on it
 *   whatever the packages: no default content sets for a Red Hat release ("unable to find CPE
 *   indices", RHEL and CentOS 5 and 10+), or a version it cannot parse (it panics on an Amazon
 *   Linux version of spaces); every row of that exact distribution fails alike, whoever stored
 *   it. The known-good release fails too: that family's detector, or Trivy, is broken, and the
 *   run fails (fail-closed).
 * No stored package text reaches a probe, so no organisation's rows can make another's
 * distribution, or the run, fail.
 */
async function faultOf(
  run: Run,
  first: SbomPackage,
): Promise<'packages' | 'release' | Problem | typeof STOPPED> {
  if (first.os === undefined) {
    const probe = await runProbe(run, buildSbom([LIBRARY_PROBE]));
    if (probe.kind === 'end') return probe.end;
    return probe.kind === 'ok' ? 'packages' : broken(probe.message);
  }
  const probe = await runProbe(run, probeSbom(first.os));
  if (probe.kind === 'end') return probe.end;
  if (probe.kind === 'ok') return 'packages';
  const known = await runProbe(run, probeSbom(knownGoodOf(first.os)));
  if (known.kind === 'end') return known.end;
  return known.kind === 'ok' ? 'release' : broken(known.message);
}

/** The organisations holding a package ({@link addOwner}). */
function ownersOf(run: Run, purl: string): readonly string[] {
  const owners = run.owners.get(purl);
  if (owners === undefined) return [];
  return typeof owners === 'string' ? [owners] : [...owners];
}

/** Whether every organisation that holds this package has spent its failure budget. */
function pastBudget(run: Run, purl: string): boolean {
  const owners = ownersOf(run, purl);
  return (
    owners.length > 0 &&
    owners.every((owner) => (run.failuresOf.get(owner) ?? 0) >= MAX_FAILED_PER_ORGANISATION)
  );
}

const halves = (chunk: readonly SbomPackage[]): (readonly SbomPackage[])[] => {
  const half = Math.ceil(chunk.length / 2);
  return [chunk.slice(half), chunk.slice(0, half)];
};

/**
 * A failed chunk, library or OS alike (rulings R16, R17, R19, R20, R21). An infrastructure failure
 * ({@link failureOf}) fails the run. Otherwise, first and before any other Trivy run, the packages
 * whose every organisation is past its budget go unchecked (`overBudget`) and the rest of the
 * chunk runs again. A heavy chunk (too large, timed out, killed) is halved, down to one package.
 * A rejected chunk, or a single heavy package, goes to {@link faultOf}: a distribution Trivy
 * cannot scan is given up whole, and a Trivy that fails its own probe fails the run. Else the
 * packages are at fault: a rejected chunk is halved, down to one package, and a single package
 * Trivy still rejects, answers too much for, times out on or dies on stays unchecked, only that
 * one, and counts against each organisation that holds it. Answers the chunks to run next, or
 * the run's end.
 */
async function chunkFailed(
  run: Run,
  chunk: readonly SbomPackage[],
  first: SbomPackage,
  got: Extract<TrivyRun, { ok: false }>,
): Promise<(readonly SbomPackage[])[] | Problem | typeof STOPPED> {
  const failure = failureOf(got);
  if (failure === 'infrastructure') return failedRun(got);
  const { os } = first;
  const fields = {
    component: 'vulnerabilities',
    packageType: os?.type ?? 'library',
    ...(os !== undefined && { distribution: `${os.family} ${os.osVersion}` }),
  };
  // Budget first: an organisation past it costs no halving and no probe (R17).
  const kept = chunk.filter((p) => !pastBudget(run, p.purl));
  if (kept.length < chunk.length) {
    for (const p of chunk) if (pastBudget(run, p.purl)) run.overBudget.add(p.purl);
    run.logger?.warn(
      { ...fields, packages: chunk.length - kept.length },
      'Trivy failed on packages whose organisations are past their failure budget; they stay unchecked',
    );
    return kept.length > 0 ? [kept] : [];
  }
  if (failure === 'heavy' && chunk.length > 1) return halves(chunk);
  const fault = await faultOf(run, first);
  if (fault === STOPPED || typeof fault === 'object') return fault;
  if (fault === 'release' && os !== undefined) {
    run.failedGroups.add(sbomGroupKey(first));
    run.unsupported.add(`${os.family} ${os.osVersion}`);
    run.logger?.warn(
      { ...fields, message: got.message },
      'Trivy cannot scan this distribution; its OS packages stay unchecked',
    );
    return [];
  }
  if (chunk.length > 1) return halves(chunk);
  run.failedKeys.add(first.purl);
  for (const owner of ownersOf(run, first.purl)) {
    run.failuresOf.set(owner, (run.failuresOf.get(owner) ?? 0) + 1);
  }
  run.logger?.warn(
    { ...fields, purl: first.purl, message: got.message },
    failure === 'heavy'
      ? 'Trivy gives no answer for one package (too large, timed out or killed); it stays unchecked'
      : 'Trivy failed on one package; it stays unchecked',
  );
  return [];
}

/**
 * Runs Trivy on `packages` in SBOMs of at most `run.chunk.components`, one distribution (or the
 * libraries) per SBOM, storing each chunk's matches as it comes. A failed chunk goes to
 * {@link chunkFailed}, which isolates whatever data is at fault; a failure that is not Trivy's
 * answer (no work directory, a spawn error, a signal, a timeout, no output), or a probe that
 * shows Trivy itself broken, stops the run there, its chunk untouched and the later ones never
 * started (R12); so does a stop.
 */
async function matchPackages(
  run: Run,
  packages: readonly SbomPackage[],
): Promise<Problem | typeof STOPPED | null> {
  const todo = chunksOf(run, packages, run.chunk.components);
  for (let chunk = todo.pop(); chunk !== undefined; chunk = todo.pop()) {
    if (stopping(run)) return STOPPED;
    const first = chunk[0];
    if (first === undefined || run.failedGroups.has(sbomGroupKey(first))) continue;
    run.trivyRuns += 1;
    const sbom = first.os === undefined ? buildSbom(chunk) : buildOsSbom(chunk);
    const got = await run.runner.run(sbom, run.cacheDir, run.shutdown);
    if (!got.ok) {
      if (stopping(run)) return STOPPED;
      const next = await chunkFailed(run, chunk, first, got);
      if (!Array.isArray(next)) return next;
      todo.push(...next);
      continue;
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

/** A package of an inventory as its rows store it, and what Trivy is given for it. */
interface InventoryPackage {
  ecosystem: string;
  name: string;
  version: string;
  entry: SbomPackage;
}

/** A target's distinct packages (one per match key) and the ignore ids active when the run started. */
interface Inventory {
  projectId: string;
  target: Target;
  /** What the target's check records (see {@link writeChecks}), read before its packages. */
  basis: string;
  packages: Map<string, InventoryPackage>;
  ignored: Set<string>;
}

const ignoreEntry = z.object({ id: z.string(), expiresAt: z.string().optional() });
const ignoreList = z.array(z.unknown()).catch([]);

/**
 * Whether a `.trivyignore` entry still applies at `now`. As Trivy applies `exp:` in a scan, the
 * entry ends at 00:00 UTC of its `expiresAt` day: that day itself is no longer ignored (ruling
 * R16). Without `expiresAt` it never ends; an unreadable date ends it. Only `YYYY-MM-DD` reads:
 * this depends on `expiresAt: z.iso.date()` in the report schema (dependencyIgnoreSchema in
 * packages/shared), which lets nothing else in; a date-time here would count as unreadable.
 */
export function ignoreActive(entry: { expiresAt?: string | undefined }, now: Date): boolean {
  if (entry.expiresAt === undefined) return true;
  const end = Date.parse(`${entry.expiresAt}T00:00:00Z`);
  return !Number.isNaN(end) && now.getTime() < end;
}

/**
 * The ids of a stored `.trivyignore` list that are active at `now`. An entry that does not read
 * is dropped alone; a stored value that is not a list is empty.
 */
function ignoredIds(value: unknown, now: Date): Set<string> {
  const ids = new Set<string>();
  for (const raw of ignoreList.parse(value ?? [])) {
    const entry = ignoreEntry.safeParse(raw);
    if (entry.success && ignoreActive(entry.data, now)) ids.add(entry.data.id);
  }
  return ids;
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

/** An empty inventory of each target in `targetsOf`, by branch id and by version id. */
function emptyInventories(targetsOf: ReadonlyMap<string, Target[]>): {
  ofBranch: Map<string, Inventory>;
  ofVersion: Map<string, Inventory>;
} {
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
  return { ofBranch, ofVersion };
}

/**
 * Counts a package into `counts` (with a match key, or as unchecked) and adds it to `inventory`.
 */
function addPackage(counts: Counts, inventory: Inventory | undefined, p: Package): void {
  const entry = sbomPackageOf(p);
  if (entry === null) {
    const key = `${p.ecosystem}\u0000${p.name}\u0000${p.version}`;
    counts.unchecked.add(key);
    if (invalidStoredPackage(p)) counts.invalid.add(key);
    return;
  }
  const { purl } = entry;
  counts.packages.add(purl);
  if (entry.os !== undefined) {
    const group = sbomGroupKey(entry);
    const keys = counts.osGroups.get(group);
    if (keys === undefined) counts.osGroups.set(group, new Set([purl]));
    else keys.add(purl);
  }
  if (inventory !== undefined && !inventory.packages.has(purl)) {
    inventory.packages.set(purl, {
      ecosystem: p.ecosystem,
      name: p.name,
      version: p.version,
      entry,
    });
  }
}

/** A dependency row of a branch's or a version's inventory. */
type DependencyRow = Package & { owner: string; analysis_id: string | null };
/** The stored `.trivyignore` list of an analysis or a version. */
type IgnoresRow = { id: string; ignores: unknown } & Record<string, unknown>;

/**
 * Reads the packages of the branches in `ofBranch` into their inventories and `counts`; answers
 * the inventories by the analysis their packages came from.
 */
async function readBranchPackages(
  db: Db,
  ofBranch: ReadonlyMap<string, Inventory>,
  counts: Counts,
): Promise<Map<string, Inventory[]>> {
  const branchesOf = new Map<string, Inventory[]>();
  const got = await db.execute<DependencyRow & Record<string, unknown>>(sql`
    SELECT DISTINCT d.branch_id AS owner, d.analysis_id, ${BRANCH_PACKAGE}
      FROM branch_dependencies d
     WHERE d.branch_id IN ${uuidList([...ofBranch.keys()])}
     ORDER BY owner, ecosystem, name, version`);
  for (const row of got.rows) {
    const inventory = ofBranch.get(row.owner);
    addPackage(counts, inventory, row);
    if (inventory === undefined || row.analysis_id === null) continue;
    const list = branchesOf.get(row.analysis_id) ?? [];
    if (!list.includes(inventory)) list.push(inventory);
    branchesOf.set(row.analysis_id, list);
  }
  return branchesOf;
}

/** Reads the packages of the versions in `ofVersion` into their inventories and `counts`. */
async function readVersionPackages(
  db: Db,
  ofVersion: ReadonlyMap<string, Inventory>,
  counts: Counts,
): Promise<void> {
  const got = await db.execute<DependencyRow & Record<string, unknown>>(sql`
    SELECT DISTINCT d.version_id AS owner, NULL::uuid AS analysis_id, ${VERSION_PACKAGE}
      FROM version_dependencies d JOIN project_versions v ON v.id = d.version_id
     WHERE d.version_id IN ${uuidList([...ofVersion.keys()])}
     ORDER BY owner, ecosystem, name, version`);
  for (const row of got.rows) addPackage(counts, ofVersion.get(row.owner), row);
}

/** Adds the active ignore ids of each analysis in `branchesOf` to its branches' inventories. */
async function addBranchIgnores(
  run: Run,
  branchesOf: ReadonlyMap<string, Inventory[]>,
): Promise<void> {
  const got = await run.db.execute<IgnoresRow>(sql`
    SELECT id, dependency_ignores AS ignores FROM analyses
     WHERE id IN ${uuidList([...branchesOf.keys()])}`);
  for (const row of got.rows) {
    const ids = ignoredIds(row.ignores, run.now);
    for (const inventory of branchesOf.get(row.id) ?? []) {
      for (const id of ids) inventory.ignored.add(id);
    }
  }
}

/** Sets each version's active ignore ids from its own stored list. */
async function setVersionIgnores(
  run: Run,
  ofVersion: ReadonlyMap<string, Inventory>,
): Promise<void> {
  const got = await run.db.execute<IgnoresRow>(sql`
    SELECT id, dependency_ignores AS ignores FROM project_versions
     WHERE id IN ${uuidList([...ofVersion.keys()])}`);
  for (const row of got.rows) {
    const inventory = ofVersion.get(row.id);
    if (inventory !== undefined) inventory.ignored = ignoredIds(row.ignores, run.now);
  }
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
  const { ofBranch, ofVersion } = emptyInventories(targetsOf);
  // Before the packages: an analysis that lands in between leaves an older basis, never a newer one.
  const bases = await basesOf(run.db, [...ofBranch.keys()], [...ofVersion.keys()]);
  for (const [id, inventory] of ofBranch) inventory.basis = bases.get(id) ?? '';
  for (const [id, inventory] of ofVersion) inventory.basis = bases.get(id) ?? '';
  const branchesOf =
    ofBranch.size > 0
      ? await readBranchPackages(run.db, ofBranch, counts)
      : new Map<string, Inventory[]>();
  if (ofVersion.size > 0) await readVersionPackages(run.db, ofVersion, counts);
  if (branchesOf.size > 0) await addBranchIgnores(run, branchesOf);
  if (ofVersion.size > 0) await setVersionIgnores(run, ofVersion);
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
 * Locks the rows of `ids` in `table` FOR KEY SHARE, in id order, until the transaction commits;
 * answers the ids that still exist.
 */
async function lockRows(
  tx: Executor,
  table: 'projects' | 'branches' | 'project_versions',
  ids: Set<string>,
): Promise<Set<string>> {
  if (ids.size === 0) return new Set<string>();
  const got = await tx.execute<{ id: string }>(sql`
    SELECT id FROM ${sql.identifier(table)} WHERE id IN ${uuidList([...ids])}
     ORDER BY id FOR KEY SHARE`);
  return new Set(got.rows.map((r) => r.id));
}

/**
 * The stored rows of the tracked targets against `wanted`: the keys kept (`seen`), the ids of the
 * rows that go (not wanted, or a duplicate), and the kept rows whose `ignored` flips.
 */
async function diffExisting(
  tx: Executor,
  branchIds: ReadonlySet<string>,
  versionIds: ReadonlySet<string>,
  wanted: ReadonlyMap<string, Wanted>,
): Promise<{ seen: Set<string>; gone: string[]; flips: { id: string; ignored: boolean }[] }> {
  const ofTracked: SQL[] = [];
  if (branchIds.size > 0) ofTracked.push(sql`branch_id IN ${uuidList([...branchIds])}`);
  if (versionIds.size > 0) ofTracked.push(sql`version_id IN ${uuidList([...versionIds])}`);
  const tracked = sql.join(ofTracked, sql` OR `);
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
     WHERE ${tracked}`);
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
  return { seen, gone, flips };
}

/** The wanted rows not stored yet (not in `seen`) whose target still exists, ready to insert. */
function freshRows(
  wanted: ReadonlyMap<string, Wanted>,
  seen: ReadonlySet<string>,
  liveBranches: ReadonlySet<string>,
  liveVersions: ReadonlySet<string>,
): object[] {
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
  return fresh;
}

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
 *
 * Every writer of `target_vulnerabilities` must move the target's check row ({@link writeChecks})
 * in the same transaction: the alerts observe pass reads only targets whose check row moved (D18).
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
    await lockRows(tx, 'projects', projectIds);
    const liveBranches = await lockRows(tx, 'branches', branchIds);
    const liveVersions = await lockRows(tx, 'project_versions', versionIds);

    const { seen, gone, flips } = await diffExisting(tx, branchIds, versionIds, wanted);
    const fresh = freshRows(wanted, seen, liveBranches, liveVersions);
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
 * them in as few Trivy runs as the SBOM_MAX_COMPONENTS cap allows; the second diffs each
 * batch's tracked targets, and each batch is written as a whole diff. A failure in the second
 * pass leaves the batches before it written: their rows are final, the rest stay as they were,
 * and the next re-check does the remainder (R12). Only tracked targets are read, matched and
 * written: an untracked one keeps its rows (R17). A package that entered an inventory between
 * the passes is matched in the second.
 */
async function recheckAll(run: Run, projectIds: readonly string[]): Promise<RecheckOutcome> {
  const pending = await pendingPackages(run, projectIds);
  if (pending === STOPPED) return STOPPED;
  const failed = await matchPackages(run, [...pending.values()]);
  if (failed !== null) return failed;
  pending.clear();

  const counts: Counts = {
    projects: 0,
    packages: new Set(),
    unchecked: new Set(),
    invalid: new Set(),
    osGroups: new Map(),
  };
  for (const batch of slices(projectIds, PROJECT_BATCH)) {
    if (stopping(run)) return STOPPED;
    const failure = await recheckBatch(run, batch, counts);
    if (failure !== null) return failure;
  }
  return counts;
}

/** At most this many distributions are named in a summary's `givenUp.unsupported`. */
const MAX_UNSUPPORTED_NAMED = 20;

/**
 * The summary's counts (rulings R16, R17): the packages with a match key, less those this run gave
 * up (the single packages Trivy failed on, those of organisations past their failure budget, and
 * those of a distribution it cannot scan), which count as unchecked; and why, for the operator.
 */
function checkedCounts(
  counts: Counts,
  run: Run | undefined,
): Pick<RecheckSummary, 'packages' | 'unchecked' | 'givenUp'> {
  const failed = new Set<string>();
  let trivyFailed = 0;
  for (const group of run?.failedGroups ?? []) {
    for (const key of counts.osGroups.get(group) ?? []) failed.add(key);
  }
  for (const key of run?.failedKeys ?? []) {
    if (!counts.packages.has(key) || failed.has(key)) continue;
    failed.add(key);
    trivyFailed += 1;
  }
  let overBudget = 0;
  for (const key of run?.overBudget ?? []) {
    if (!counts.packages.has(key) || failed.has(key)) continue;
    failed.add(key);
    overBudget += 1;
  }
  return {
    packages: counts.packages.size - failed.size,
    unchecked: counts.unchecked.size + failed.size,
    givenUp: {
      invalid: counts.invalid.size,
      trivyFailed,
      overBudget,
      unsupported: [...(run?.unsupported ?? [])].sort().slice(0, MAX_UNSUPPORTED_NAMED),
    },
  };
}

/**
 * The first pass of {@link recheckAll}: the distinct packages of the projects' tracked targets
 * that are not matched against this dataset yet, by purl, a batch of projects at a time.
 */
async function pendingPackages(
  run: Run,
  projectIds: readonly string[],
): Promise<Map<string, SbomPackage> | typeof STOPPED> {
  const pending = new Map<string, SbomPackage>();
  for (const batch of slices(projectIds, PROJECT_BATCH)) {
    if (stopping(run)) return STOPPED;
    const targets = [...(await projectTargets(run.db, batch)).values()].flat();
    const { byPurl, holders } = newSbomPackages(await distinctPackages(run.db, targets), pending);
    await dropFresh(run.db, byPurl, run.digest);
    for (const [purl, p] of byPurl) pending.set(purl, p);
    // Only the packages that go to Trivy need their organisations (R17, R19).
    for (const [purl, organizationId] of holders) {
      if (pending.has(purl)) addOwner(run, purl, organizationId);
    }
  }
  return pending;
}

/** Records that `organizationId` holds the package `purl` (rulings R17, R19). */
function addOwner(run: Run, purl: string, organizationId: string): void {
  let id = run.organizationIds.get(organizationId);
  if (id === undefined) {
    id = organizationId;
    run.organizationIds.set(id, id);
  }
  const known = run.owners.get(purl);
  if (known === undefined) run.owners.set(purl, id);
  else if (typeof known !== 'string') known.add(id);
  else if (known !== id) run.owners.set(purl, new Set([known, id]));
}

/**
 * The packages with a match key that `pending` does not hold, once each, as SBOM entries; and
 * each package's organisation, for those of them that go to Trivy.
 */
function newSbomPackages(
  packages: readonly Package[],
  pending: ReadonlyMap<string, SbomPackage>,
): { byPurl: Map<string, SbomPackage>; holders: [string, string][] } {
  const byPurl = new Map<string, SbomPackage>();
  const holders: [string, string][] = [];
  for (const p of packages) {
    // R13: the SBOM names a package by its stored name.
    const entry = sbomPackageOf(p);
    if (entry === null) continue;
    if (typeof p.organizationId === 'string') holders.push([entry.purl, p.organizationId]);
    if (!pending.has(entry.purl) && !byPurl.has(entry.purl)) byPurl.set(entry.purl, entry);
  }
  return { byPurl, holders };
}

/** The distinct packages of the inventories, by match key, as SBOM entries. */
function inventoryPackages(batchInventories: readonly Inventory[]): Map<string, SbomPackage> {
  const late = new Map<string, SbomPackage>();
  for (const inventory of batchInventories) {
    for (const [purl, p] of inventory.packages) {
      if (!late.has(purl)) late.set(purl, p.entry);
    }
  }
  return late;
}

/** Records the organisation of each inventory's project for its packages that go to Trivy. */
function addLateOwners(
  run: Run,
  batchInventories: readonly Inventory[],
  late: ReadonlyMap<string, SbomPackage>,
  organizationOf: ReadonlyMap<string, string>,
): void {
  for (const inventory of batchInventories) {
    const organizationId = organizationOf.get(inventory.projectId);
    if (organizationId === undefined) continue;
    for (const purl of inventory.packages.keys()) {
      if (late.has(purl)) addOwner(run, purl, organizationId);
    }
  }
}

/** The organisation of each project of `projectIds`. */
async function organizationsOf(
  db: Db,
  projectIds: readonly string[],
): Promise<Map<string, string>> {
  if (projectIds.length === 0) return new Map();
  const rows = await db
    .select({ id: projects.id, organizationId: projects.organizationId })
    .from(projects)
    .where(inArray(projects.id, uuidList(projectIds)));
  return new Map(rows.map((r) => [r.id, r.organizationId]));
}

/** The rows the inventories' targets should have: one per package and its stored vulnerability. */
function wantedRows(
  batchInventories: readonly Inventory[],
  vulnerabilities: ReadonlyMap<string, string[]>,
): Map<string, Wanted> {
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
  return wanted;
}

/**
 * The second pass of {@link recheckAll} for one batch of projects: matches the packages that
 * entered an inventory since the first pass, then diffs the batch's tracked targets. Answers the
 * failure or stop of a Trivy run, else null.
 */
async function recheckBatch(
  run: Run,
  batch: readonly string[],
  counts: Counts,
): Promise<Problem | typeof STOPPED | null> {
  const targetsOf = await projectTargets(run.db, batch);
  const batchInventories = await inventories(run, targetsOf, counts);
  const late = inventoryPackages(batchInventories);
  const purls = [...late.keys()];
  await dropFresh(run.db, late, run.digest);
  if (late.size > 0) {
    addLateOwners(run, batchInventories, late, await organizationsOf(run.db, batch));
    const lateFailure = await matchPackages(run, [...late.values()]);
    if (lateFailure !== null) return lateFailure;
  }
  const vulnerabilities = await vulnerabilitiesOf(run.db, purls);
  await writeTargets(
    run.db,
    targetsOf,
    wantedRows(batchInventories, vulnerabilities),
    new Map(
      batchInventories.map((i) => [
        i.target.kind === 'branch' ? i.target.branchId : i.target.versionId,
        i.basis,
      ]),
    ),
  );
  for (const targets of targetsOf.values()) if (targets.length > 0) counts.projects += 1;
  return null;
}

/**
 * The end of a good full re-check: the matches and marks of packages that no tracked inventory
 * has any more (`purls` is the run's set) go. The matches of a package some target still lists
 * stay, as an untracked target keeps its rows (R17); its mark goes, so the package is matched
 * again when a run needs it. Here and not in housekeeping: only a full run knows every inventory.
 *
 * The stale purls are found first and materialized, so the check against `target_vulnerabilities`
 * (no index leads with `purl`) hashes that small set and scans the table once, instead of hashing
 * the whole table (it spilled to disk at 2 M rows).
 */
async function pruneUnused(db: Db, purls: ReadonlySet<string>): Promise<void> {
  const inRun = JSON.stringify([...purls]);
  await db.transaction(async (tx) => {
    await tx.execute(sql`
      WITH stale AS MATERIALIZED (
        SELECT DISTINCT m.purl FROM vulnerability_matches m
         WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(${inRun}::jsonb) AS p(purl)
                            WHERE p.purl = m.purl))
      DELETE FROM vulnerability_matches m USING stale s
       WHERE m.purl = s.purl
         AND NOT EXISTS (SELECT 1 FROM target_vulnerabilities t WHERE t.purl = s.purl)`);
    await tx.execute(sql`
      DELETE FROM matched_packages m
       WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(${inRun}::jsonb) AS p(purl)
                          WHERE p.purl = m.purl)`);
  });
}

/**
 * {@link pruneUnused}, for housekeeping of the shared tables: a problem here never fails a
 * re-check that is done, it is only logged.
 */
async function pruneQuietly(deps: RecheckDeps, purls: ReadonlySet<string>): Promise<void> {
  try {
    await pruneUnused(deps.db, purls);
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

/** What {@link withLocalDatabase} answers around {@link recheckAll}. */
type LocalOutcome = { result: RecheckOutcome } | { problem: LocalProblem };

/**
 * The outcome of a run. A DISK problem of the local copy stays DISK; MISSING and BUSY (another
 * re-check held the copy past the wait) are the re-check's RECHECK_FAILED.
 */
function outcomeOf(local: LocalOutcome): RecheckOutcome {
  if (!('problem' in local)) return local.result;
  return {
    code: local.problem.code === 'DISK' ? 'DISK' : 'RECHECK_FAILED',
    message: local.problem.message,
  };
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
 *    run left in its directory are removed; DISK (or MISSING and BUSY, as RECHECK_FAILED) goes to
 *    `lastRecheckError` (ruling R19), as does a failed Trivy run (R12).
 * 3–5. The packages not yet matched against it run through Trivy, at most SBOM_MAX_COMPONENTS
 *    (1 000) per SBOM.
 * 6–7. Each tracked target's rows follow its inventory ({@link writeTargets}).
 *    Each batch is written as a whole diff, so a failure in the second pass leaves the earlier
 *    batches written (their rows are final) and the rest as they were.
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
  const trivyRun = (cacheDir: string): Run => {
    current = {
      db: deps.db,
      runner,
      cacheDir,
      digest: dataset.digest,
      now: now(),
      shutdown: deps.shutdown,
      chunk: {
        components: deps.chunk?.components ?? SBOM_MAX_COMPONENTS,
      },
      trivyRuns: 0,
      failedGroups: new Set(),
      unsupported: new Set(),
      failedKeys: new Set(),
      overBudget: new Set(),
      owners: new Map(),
      organizationIds: new Map(),
      failuresOf: new Map(),
      logger: deps.logger,
    };
    return current;
  };
  let current: Run | undefined;
  let local: LocalOutcome;
  try {
    local = await withLocalDatabase(
      deps.db,
      deps.config.vulndb.dir,
      dataset,
      async (cacheDir) => {
        // Under the lock, so no run of this server uses them: what a killed run left goes.
        await removeStaleWorkDirs(deps.config.vulndb.dir);
        return recheckAll(trivyRun(cacheDir), projectIds);
      },
      { signal: deps.shutdown, lockWaitMs: deps.lockWaitMs },
    );
  } catch (err) {
    // The stop cut the extraction (or whatever it was doing): not this run's failure.
    if (stopping(deps)) return stoppedRun(deps, scope);
    throw err;
  }
  const outcome = outcomeOf(local);
  if (outcome === STOPPED) return stoppedRun(deps, scope);
  if ('code' in outcome) {
    await setError(deps.db, outcome);
    deps.logger?.warn(
      { component: 'vulnerabilities', code: outcome.code, message: outcome.message },
      'vulnerability re-check failed',
    );
    // The batches written before the failure are final: the alert job looks at them too.
    await enqueueVulnerabilityAlerts(deps.db);
    return { kind: 'failed', error: outcome };
  }
  if ('all' in scope) await pruneQuietly(deps, outcome.packages);
  const summary: RecheckSummary = {
    at: now().toISOString(),
    projects: outcome.projects,
    ...checkedCounts(outcome, current),
    durationMs: Math.round(performance.now() - started),
  };
  await updateVulndbState(deps.db, (state) => ({
    ...state,
    // R15: the admin line describes the last full re-check, not the last ingestion.
    lastRecheck: 'all' in scope ? summary : state.lastRecheck,
    // R22: one project's good run says nothing about the rest; only a full run clears the error.
    lastRecheckError: 'all' in scope ? null : state.lastRecheckError,
  }));
  deps.logger?.info(
    { component: 'vulnerabilities', ...summary, trivyRuns: current?.trivyRuns ?? 0 },
    'vulnerability re-check done',
  );
  // 4b: the alert job looks at what this run wrote, as after a failure. A stopped run never gets
  // here (it is queued again).
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
