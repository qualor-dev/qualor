import { createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import type { Config } from '../../config';
import type { Db, Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import type { MailDeps } from '../../mail/outbox';
import { fetchHttpsFile as realFetchHttpsFile, isOciProblem } from '../oci';
import { priorityUrl, type PriorityDataset, type VulndbSettings } from '../settings';
import { parseEpss, parseKev, PRIORITY_FILE_MAX_BYTES, type PriorityProblem } from './parse';
import { replaceEpss, replaceKev } from './store';
import {
  readPriorityState,
  updatePriorityState,
  updatePriorityStateLocked,
  type PriorityDatasetState,
} from './state';

/** The order of a run: KEV, then EPSS. */
const PRIORITY_DATASETS: readonly PriorityDataset[] = ['kev', 'epss'];

type LastError = NonNullable<PriorityDatasetState['lastError']>;

/** The update job's dependencies (vulndb/update.ts), without the Trivy registry's seams. */
export interface PriorityUpdateDeps extends MailDeps {
  db: Db;
  config: MailDeps['config'] & { vulndb: Pick<Config['vulndb'], 'internalHosts'> };
  /** Tests substitute the file client. */
  fetchHttpsFile?: typeof realFetchHttpsFile;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** The server is stopping: a download is cut, and the check ends without a verdict. */
  shutdown?: AbortSignal;
}

export interface PriorityValidators {
  etag: string | null;
  lastModified: string | null;
  url: string | null;
}

const UPDATE_FAILED: LastError = {
  code: 'UPDATE_FAILED',
  message: 'The update failed. See the server log',
};

const errorClass = (err: unknown): string =>
  err instanceof Error ? err.constructor.name : typeof err;

/** A parsed file, ready to replace its table. */
interface ParsedFile {
  replace: (tx: Executor) => Promise<number>;
  dataDate: Date | null;
  skipped: number;
}

async function parseFile(
  dataset: PriorityDataset,
  body: Buffer,
): Promise<ParsedFile | PriorityProblem> {
  if (dataset === 'kev') {
    const kev = await parseKev(body);
    if ('problem' in kev) return kev;
    return {
      replace: async (tx) => (await replaceKev(tx, kev.entries)).count,
      dataDate: kev.releasedAt,
      skipped: kev.skipped,
    };
  }
  const epss = await parseEpss(body);
  if ('problem' in epss) return epss;
  return {
    replace: async (tx) => (await replaceEpss(tx, epss)).count,
    dataDate: epss.scoreDate,
    skipped: epss.skipped,
  };
}

/**
 * Stores one KEV or EPSS file as downloaded or uploaded (gzip or not). A file that does not parse
 * is the answer, with no state written (the job records it as `lastError`; an upload answers 422).
 * Otherwise one transaction, under LOCKS.vulnerabilityPriority and then LOCKS.vulndbPriorityState
 * (always in that order), compares the sha256 with the stored file's, replaces the table and
 * writes the state, so two stores at once (the job and an upload) leave the table and the state on
 * the same file. The same bytes as the stored file write only the validators and the check times:
 * no row, and `storedAt` stays. Logs what it stored, with the entries it skipped.
 */
export async function storePriorityFile(
  db: Db,
  dataset: PriorityDataset,
  body: Buffer,
  source: 'official' | 'mirror' | 'upload',
  validators: PriorityValidators,
  now: Date,
  logger?: Pick<FastifyBaseLogger, 'info'>,
): Promise<PriorityDatasetState | PriorityProblem> {
  const at = now.toISOString();
  const digest = `sha256:${createHash('sha256').update(body).digest('hex')}`;
  const parsed = await parseFile(dataset, body);
  if ('problem' in parsed) return parsed;
  const { state, count } = await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityPriority})`);
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbPriorityState})`);
    if ((await readPriorityState(tx))[dataset].digest === digest) {
      const confirmed = await updatePriorityStateLocked(tx, dataset, (s) => ({
        ...s,
        ...validators,
        refreshedAt: at,
        lastCheckAt: at,
        lastError: null,
      }));
      return { state: confirmed, count: null };
    }
    const replaced = await parsed.replace(tx);
    const stored = await updatePriorityStateLocked(tx, dataset, () => ({
      source,
      dataDate: parsed.dataDate === null ? null : parsed.dataDate.toISOString(),
      storedAt: at,
      refreshedAt: at,
      lastCheckAt: at,
      sizeBytes: body.length,
      count: replaced,
      digest,
      ...validators,
      lastError: null,
      staleNotifiedDigest: null,
    }));
    return { state: stored, count: replaced };
  });
  if (count !== null) {
    logger?.info(
      {
        component: 'vulndb',
        dataset,
        count,
        sizeBytes: body.length,
        ...(parsed.skipped > 0 ? { skipped: parsed.skipped } : {}),
      },
      'priority data stored',
    );
  }
  return state;
}

/** Where a dataset comes from: the mirror only when the mirror names a URL for it. */
function sourceOf(settings: VulndbSettings, dataset: PriorityDataset): 'official' | 'mirror' {
  const source = settings.source;
  if (source.kind !== 'mirror') return 'official';
  return (dataset === 'kev' ? source.kevUrl : source.epssUrl) === null ? 'official' : 'mirror';
}

/** One dataset's download: null when it is current or now stored, else the problem. */
async function checkDataset(
  deps: PriorityUpdateDeps,
  settings: VulndbSettings,
  dataset: PriorityDataset,
): Promise<LastError | null> {
  const now = deps.now ?? (() => new Date());
  const url = priorityUrl(settings.source, dataset);
  const state = (await readPriorityState(deps.db))[dataset];
  // The validators belong to the URL they came from: another URL starts without them.
  const sameUrl = state.url === url;
  const got = await (deps.fetchHttpsFile ?? realFetchHttpsFile)(url, {
    internalHosts: deps.config.vulndb.internalHosts,
    maxBytes: PRIORITY_FILE_MAX_BYTES,
    etag: sameUrl ? state.etag : null,
    lastModified: sameUrl ? state.lastModified : null,
    ...(deps.shutdown ? { signal: deps.shutdown } : {}),
  });
  if (isOciProblem(got)) return { code: got.code, message: got.message };
  if (got.kind === 'not_modified') {
    const at = now().toISOString();
    await updatePriorityState(deps.db, dataset, (s) => ({
      ...s,
      refreshedAt: at,
      lastCheckAt: at,
      lastError: null,
    }));
    return null;
  }
  const stored = await storePriorityFile(
    deps.db,
    dataset,
    got.body,
    sourceOf(settings, dataset),
    { etag: got.etag, lastModified: got.lastModified, url },
    now(),
    deps.logger,
  );
  return 'problem' in stored ? stored.problem : null;
}

/**
 * The `vuln.priority` part of a `vulndb.update` run: KEV, then EPSS, each from its URL (the
 * mirror's, else the official one) with a conditional request. Each dataset has its own state: a
 * problem becomes its `lastError` and its rows stay, and the other dataset still runs. A stop of
 * the server cuts the download and records nothing; the datasets left are not checked.
 */
export async function checkPriorityDatasets(
  deps: PriorityUpdateDeps,
  settings: VulndbSettings,
): Promise<void> {
  const now = deps.now ?? (() => new Date());
  const stopping = (): boolean => deps.shutdown?.aborted === true;
  for (const dataset of PRIORITY_DATASETS) {
    if (stopping()) return;
    let error: LastError | null;
    try {
      error = await checkDataset(deps, settings, dataset);
    } catch (err) {
      // Neither the source's answer nor a parse problem: log its class, show a fixed text.
      deps.logger?.warn(
        { component: 'vulndb', dataset, errorClass: errorClass(err) },
        'priority data update failed',
      );
      error = UPDATE_FAILED;
    }
    if (error === null) continue;
    // The stop cut the download: what it ran into says nothing about the source.
    if (stopping()) return;
    const checkedAt = now().toISOString();
    await updatePriorityState(deps.db, dataset, (s) => ({
      ...s,
      lastCheckAt: checkedAt,
      lastError: error,
    }));
  }
}
