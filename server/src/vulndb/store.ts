import { createHash } from 'node:crypto';
import { and, asc, desc, eq, inArray, lt, ne, sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { vulndbChunks, vulndbDatasets, type VulndbDatasetRow } from '../db/schema';
import { OutboundStreamError } from '../http/outbound';
import { readVulndbState, updateVulndbStateLocked, type VulndbState } from './state';
import { readTarGz, TarError } from '@qualor/shared/tar';

/** A `vulndb_datasets` row. */
export type DatasetRow = VulndbDatasetRow;

/** A dataset is stored in rows of this many bytes (the last one may be shorter). */
export const CHUNK_BYTES = 8 * 1024 * 1024;
/** An `incomplete` dataset older than this is a store that died: pruneDatasets removes it. */
export const INCOMPLETE_MAX_AGE_MS = 60 * 60 * 1000;
/** The digest an `incomplete` dataset carries until its bytes are all in. */
const PENDING_DIGEST = `sha256:${'0'.repeat(64)}`;

/** The dataset the state names as current, or null. */
export async function currentDataset(
  db: Executor,
  state: Pick<VulndbState, 'currentDatasetId'>,
): Promise<DatasetRow | null> {
  if (state.currentDatasetId === null) return null;
  const [row] = await db
    .select()
    .from(vulndbDatasets)
    .where(eq(vulndbDatasets.id, state.currentDatasetId));
  return row ?? null;
}

export interface StoreDatasetInput {
  kind: 'trivy';
  source: DatasetRow['source'];
  /** The archive (`db.tar.gz`) as it arrives: a download or an upload. */
  chunks: AsyncIterable<Buffer>;
  /** The layer digest the manifest named (`sha256:<hex>`); none for an upload. */
  expectedDigest?: string;
  /** More bytes than this stop the store with TOO_LARGE. */
  maxBytes: number;
}

/** Ruling R3: the upload route answers TOO_LARGE with 413 and every other code with 422. */
export type StoreProblemCode =
  'TOO_LARGE' | 'DIGEST_MISMATCH' | 'INVALID_DATABASE' | 'STREAM_FAILED';

export interface StoreProblem {
  code: StoreProblemCode;
  /** A short text for an administrator. */
  message: string;
}

export type StoreResult = { dataset: DatasetRow } | { problem: StoreProblem };

const problemOf = (code: StoreProblemCode, message: string): { problem: StoreProblem } => ({
  problem: { code, message },
});

/** What a source that throws is: its own short text for a download, else a fixed one. */
function streamProblem(err: unknown): { problem: StoreProblem } {
  if (err instanceof OutboundStreamError) {
    return problemOf(err.cause === 'too_large' ? 'TOO_LARGE' : 'STREAM_FAILED', err.reason);
  }
  return problemOf('STREAM_FAILED', 'The data stopped before its end');
}

/** One chunk, and the dataset's count of them, in one short transaction. */
async function writeChunk(db: Db, datasetId: string, seq: number, data: Buffer): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.insert(vulndbChunks).values({ datasetId, seq, data });
    await tx
      .update(vulndbDatasets)
      .set({ chunkCount: seq + 1 })
      .where(eq(vulndbDatasets.id, datasetId));
  });
}

/**
 * Writes `chunks` as {@link CHUNK_BYTES} rows of a new `incomplete` dataset, hashing as it goes.
 * Answers the digest and size, or the problem (the caller deletes the dataset).
 */
async function writeChunks(
  db: Db,
  datasetId: string,
  input: StoreDatasetInput,
): Promise<{ digest: string; size: number } | { problem: StoreProblem }> {
  const hash = createHash('sha256');
  const iterator = input.chunks[Symbol.asyncIterator]();
  let parts: Buffer[] = [];
  let pending = 0;
  let size = 0;
  let seq = 0;
  let finished = false;
  try {
    for (;;) {
      let step: IteratorResult<Buffer>;
      try {
        step = await iterator.next();
      } catch (err) {
        finished = true;
        return streamProblem(err);
      }
      if (step.done) {
        finished = true;
        break;
      }
      const piece = step.value;
      size += piece.length;
      if (size > input.maxBytes) {
        return problemOf('TOO_LARGE', `The file is larger than ${input.maxBytes} bytes`);
      }
      hash.update(piece);
      parts.push(piece);
      pending += piece.length;
      if (pending < CHUNK_BYTES) continue;
      const all = Buffer.concat(parts);
      let at = 0;
      for (; all.length - at >= CHUNK_BYTES; at += CHUNK_BYTES) {
        await writeChunk(db, datasetId, seq++, all.subarray(at, at + CHUNK_BYTES));
      }
      parts = at < all.length ? [all.subarray(at)] : [];
      pending = all.length - at;
    }
    if (pending > 0) await writeChunk(db, datasetId, seq++, Buffer.concat(parts));
  } finally {
    // Stopped before the end (too large, or a write failed): the source is told to stop.
    if (!finished) await iterator.return?.().catch(() => undefined);
  }
  if (size === 0) return problemOf('INVALID_DATABASE', 'The file is empty');
  return { digest: `sha256:${hash.digest('hex')}`, size };
}

/** Trivy's `metadata.json`: the build time, or what is wrong with it. */
function builtAtOf(text: string): Date | string {
  let metadata: unknown;
  try {
    metadata = JSON.parse(text);
  } catch {
    return 'metadata.json is not valid JSON';
  }
  if (typeof metadata !== 'object' || metadata === null)
    return 'metadata.json is not a JSON object';
  const { Version: version, UpdatedAt: updatedAt } = metadata as Record<string, unknown>;
  if (version !== 2) {
    return `metadata.json says Version ${JSON.stringify(version ?? null)}; Qualor reads Version 2`;
  }
  const builtAt = typeof updatedAt === 'string' ? new Date(updatedAt) : null;
  if (builtAt === null || Number.isNaN(builtAt.getTime())) {
    return 'metadata.json has no valid UpdatedAt';
  }
  return builtAt;
}

/**
 * Reads the stored archive back: `metadata.json` must say Version 2 with a valid `UpdatedAt`,
 * and `trivy.db` must be there and not empty. Answers the build time, or what is wrong.
 */
async function validate(db: Db, datasetId: string): Promise<Date | string> {
  let metadata: string | null = null;
  let dbBytes = 0;
  try {
    await readTarGz(
      readDatasetChunks(db, datasetId),
      (name) => (name === 'metadata.json' ? 'keep' : name === 'trivy.db' ? 'stream' : 'skip'),
      (entry) => {
        // trivy.db is not read here: the reader passes over it (decompressed, never kept).
        if (entry.want === 'stream') dbBytes = entry.size;
        else metadata = entry.data.toString('utf8');
      },
    );
  } catch (err) {
    if (err instanceof TarError) return err.message;
    throw err;
  }
  if (metadata === null) return 'The archive has no metadata.json';
  const builtAt = builtAtOf(metadata);
  if (typeof builtAt === 'string') return builtAt;
  if (dbBytes === 0) return 'The archive has no trivy.db (or an empty one)';
  return builtAt;
}

/**
 * Stores a Trivy database archive as a new dataset:
 * - the bytes go into {@link CHUNK_BYTES} rows, each in its own short transaction, while the
 *   dataset is `incomplete`, and are hashed on the way;
 * - the digest must equal `expectedDigest` when one is given;
 * - the stored archive is read back: `metadata.json` (Version 2, a valid `UpdatedAt`) and a
 *   `trivy.db` must be in it;
 * - only then is the dataset `ready`, with its digest, size and `built_at`.
 * On any problem the dataset is deleted, and the problem is the answer. A database error throws
 * (the dataset is deleted when that is still possible; else pruneDatasets removes it later).
 * Making the dataset current is the caller's.
 */
export async function storeDataset(db: Db, input: StoreDatasetInput): Promise<StoreResult> {
  const [created] = await db
    .insert(vulndbDatasets)
    .values({
      kind: input.kind,
      digest: PENDING_DIGEST,
      sizeBytes: 0,
      source: input.source,
      status: 'incomplete',
    })
    .returning({ id: vulndbDatasets.id });
  if (created === undefined) throw new Error('the dataset row was not created');
  const datasetId = created.id;
  let kept = false;
  try {
    const written = await writeChunks(db, datasetId, input);
    if ('problem' in written) return written;
    if (input.expectedDigest !== undefined && written.digest !== input.expectedDigest) {
      return problemOf(
        'DIGEST_MISMATCH',
        `The data's digest ${written.digest} is not the expected ${input.expectedDigest}`,
      );
    }
    const builtAt = await validate(db, datasetId);
    if (typeof builtAt === 'string') return problemOf('INVALID_DATABASE', builtAt);
    const [dataset] = await db
      .update(vulndbDatasets)
      .set({ status: 'ready', digest: written.digest, sizeBytes: written.size, builtAt })
      .where(eq(vulndbDatasets.id, datasetId))
      .returning();
    if (dataset === undefined) throw new Error(`vulnerability dataset ${datasetId} vanished`);
    kept = true;
    return { dataset };
  } finally {
    if (!kept) {
      await db
        .delete(vulndbDatasets)
        .where(eq(vulndbDatasets.id, datasetId))
        .catch(() => undefined);
    }
  }
}

/**
 * Names a `ready` dataset current and clears the state's `lastError`, under LOCKS.vulndbState.
 * False (the state untouched) when the row is gone or not `ready`: a prune or a delete got there
 * first, which a caller answers as a problem, never a crash.
 */
export async function makeDatasetCurrent(db: Db, datasetId: string): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbState})`);
    const [row] = await tx
      .select({ id: vulndbDatasets.id })
      .from(vulndbDatasets)
      .where(and(eq(vulndbDatasets.id, datasetId), eq(vulndbDatasets.status, 'ready')));
    if (row === undefined) return false;
    await updateVulndbStateLocked(tx, (state) => ({
      ...state,
      currentDatasetId: datasetId,
      lastError: null,
    }));
    return true;
  });
}

/**
 * A dataset's bytes, chunk by chunk in order, one row in memory at a time. Throws when the
 * dataset or one of its chunks is missing.
 */
export async function* readDatasetChunks(
  db: Executor,
  id: string,
): AsyncGenerator<Buffer, void, undefined> {
  const [dataset] = await db
    .select({ chunkCount: vulndbDatasets.chunkCount })
    .from(vulndbDatasets)
    .where(eq(vulndbDatasets.id, id));
  if (dataset === undefined) throw new Error(`vulnerability dataset ${id} not found`);
  for (let seq = 0; seq < dataset.chunkCount; seq++) {
    const [chunk] = await db
      .select({ data: vulndbChunks.data })
      .from(vulndbChunks)
      .where(and(eq(vulndbChunks.datasetId, id), eq(vulndbChunks.seq, seq)));
    if (chunk === undefined)
      throw new Error(`chunk ${seq} of vulnerability dataset ${id} not found`);
    yield chunk.data;
  }
}

/**
 * Keeps `keep` `ready` datasets and deletes the others, and the `incomplete` ones older than
 * {@link INCOMPLETE_MAX_AGE_MS} (a store that died). The current dataset is always one of those
 * kept, even when it is old, plus the newest other ready one (so there is something to go back
 * to); with no current dataset, the `keep` newest stay. The state cannot change meanwhile
 * (LOCKS.vulndbState). Answers how many were deleted.
 */
export async function pruneDatasets(db: Db, keep = 2): Promise<number> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbState})`);
    const { currentDatasetId } = await readVulndbState(tx);
    const ready = await tx
      .select({ id: vulndbDatasets.id })
      .from(vulndbDatasets)
      .where(eq(vulndbDatasets.status, 'ready'))
      .orderBy(desc(vulndbDatasets.createdAt), asc(vulndbDatasets.id));
    const hasCurrent = ready.some((row) => row.id === currentDatasetId);
    const others = ready.filter((row) => row.id !== currentDatasetId);
    const doomed = (hasCurrent ? others.slice(Math.max(1, keep - 1)) : ready.slice(keep)).map(
      (row) => row.id,
    );
    const abandoned = await tx
      .select({ id: vulndbDatasets.id })
      .from(vulndbDatasets)
      .where(
        and(
          eq(vulndbDatasets.status, 'incomplete'),
          lt(vulndbDatasets.createdAt, new Date(Date.now() - INCOMPLETE_MAX_AGE_MS)),
        ),
      );
    doomed.push(...abandoned.map((row) => row.id));
    if (doomed.length === 0) return 0;
    const deleted = await tx
      .delete(vulndbDatasets)
      .where(
        and(
          inArray(vulndbDatasets.id, doomed),
          currentDatasetId === null ? undefined : ne(vulndbDatasets.id, currentDatasetId),
        ),
      )
      .returning({ id: vulndbDatasets.id });
    return deleted.length;
  });
}
