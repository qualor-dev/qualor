import { asc, gt, sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import { LOCKS } from '../db/locks';
import { auditEvents } from '../db/schema';
import { sendWebhook, type Resolver, type SendOutcome } from '../webhooks/send';
import { signatureHeaders } from '../webhooks/sign';
import { webhookSettings, webhookUrlProblem } from '../webhooks/url';
import { exportRecordOf, type AuditEventRecord } from './chain';
import {
  AUDIT_STREAM_KEY,
  AUDIT_STREAM_SECRET_AAD,
  readAuditSettings,
  readStreamState,
  writeSetting,
  type AuditSettings,
  type StreamState,
} from './settings';

export const STREAM_BATCH_EVENTS = 500;
export const STREAM_BATCH_BYTES = 1_048_576;
export const STREAM_BATCHES_PER_RUN = 20;
/** The whole exchange of one batch; `sendWebhook` adds 3 s to connect (ruling X7). */
const TIMEOUT_MS = 10_000;
const MAX_ERROR_LENGTH = 2_048;
const NO_SECRET = 'The stream secret no longer decrypts: set a new secret';

export interface StreamDeps {
  db: Db;
  secretKey: string;
  version: string;
  /**
   * Whether `audit-log` and `audit-log.stream` are both active (rbac-audit.md §14.4); nothing is
   * sent while they are not, and nothing of the stream is written.
   */
  active: () => boolean;
  now?: () => Date;
  /** Tests substitute DNS; the default is the system resolver. */
  resolve?: Resolver;
  /** Warnings only, never the URL, body, secret or signature (rbac-audit.md §14.2). */
  log?: { warn: (message: string) => void };
}

/** 1, 2, 4 … minutes, at most 60 (rbac-audit.md §14.2). */
export function streamBackoffMinutes(failures: number): number {
  return Math.min(2 ** Math.max(0, failures - 1), 60);
}

type Stream = NonNullable<AuditSettings['stream']>;

/**
 * One signed POST through {@link sendWebhook} (pinned address, every resolved address public
 * unless internal hosts are allowed, no redirect, no proxy), with the URL re-checked against the
 * `webhooks` row first, exactly as a webhook delivery is (api.md §3).
 */
async function post(
  deps: StreamDeps,
  url: string,
  secret: string,
  body: string,
  delivery: string,
  now: Date,
): Promise<SendOutcome> {
  const outcome = await send(deps, url, secret, body, delivery, now);
  return {
    ...outcome,
    excerpt: outcome.excerpt === null ? null : withoutUrl(outcome.excerpt, url),
  };
}

/**
 * The text without the stream URL, its path or its query (a receiver may echo them, and a query
 * can carry a credential): what is stored in `lastError` or returned by the test is never more
 * than the origin, as for audit events.
 */
export function withoutUrl(text: string, url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return text;
  }
  const parts = [url, parsed.href, parsed.pathname + parsed.search, parsed.search.slice(1)]
    .filter((part) => part.length > 1)
    .sort((a, b) => b.length - a.length);
  let out = text;
  for (const part of parts) out = out.split(part).join('[stream URL]');
  return out;
}

async function send(
  deps: StreamDeps,
  url: string,
  secret: string,
  body: string,
  delivery: string,
  now: Date,
): Promise<SendOutcome> {
  const settings = await webhookSettings(deps.db);
  const problem = webhookUrlProblem(url, settings);
  if (problem)
    return { ok: false, status: null, excerpt: `The stream URL is not allowed: ${problem}` };
  return sendWebhook(
    {
      url,
      body,
      headers: {
        'content-type': 'application/json',
        'user-agent': `Qualor-Webhook/${deps.version}`,
        'x-qualor-event': 'audit.events',
        'x-qualor-delivery': delivery,
        ...signatureHeaders(secret, body, Math.floor(now.getTime() / 1000)),
      },
    },
    {
      allowInternalHosts: settings.allowInternalHosts,
      timeoutMs: TIMEOUT_MS,
      ...(deps.resolve ? { resolve: deps.resolve } : {}),
    },
  );
}

/** `lastError`: the status and the excerpt of api.md §3 (never the URL, a header or the body). */
function errorOf(result: SendOutcome): string {
  const text =
    result.status === null
      ? (result.excerpt ?? 'The request failed')
      : `HTTP ${result.status}${result.excerpt ? `: ${result.excerpt}` : ''}`;
  return text.slice(0, MAX_ERROR_LENGTH);
}

function failed(state: StreamState, message: string, now: Date): StreamState {
  const failures = state.consecutiveFailures + 1;
  return {
    ...state,
    lastError: message.slice(0, MAX_ERROR_LENGTH),
    failingSince: state.failingSince ?? now.toISOString(),
    consecutiveFailures: failures,
    nextAttemptAt: new Date(now.getTime() + streamBackoffMinutes(failures) * 60_000).toISOString(),
  };
}

/** The events after the cursor, in seq order: at most 500, and at most 1 MiB of JSON (one at least). */
async function nextBatch(tx: Executor, cursorSeq: string): Promise<AuditEventRecord[]> {
  const rows = await tx
    .select()
    .from(auditEvents)
    .where(gt(auditEvents.seq, Number(cursorSeq)))
    .orderBy(asc(auditEvents.seq))
    .limit(STREAM_BATCH_EVENTS);
  const events: AuditEventRecord[] = [];
  let bytes = 0;
  for (const row of rows) {
    const record = exportRecordOf(row);
    const size = Buffer.byteLength(JSON.stringify(record), 'utf8');
    if (events.length > 0 && bytes + size > STREAM_BATCH_BYTES) break;
    events.push(record);
    bytes += size;
  }
  return events;
}

type BatchOutcome = 'busy' | 'off' | 'waiting' | 'empty' | 'sent' | 'failed';

/**
 * One batch, in one transaction that holds `pg_try_advisory_xact_lock(LOCKS.auditStream)`: one
 * batch at a time across replicas, and a settings change waits for it (settings.ts). The request
 * runs while the lock is held (at most 10 s, as the webhook sender does, ruling X7), so a second
 * replica skips instead of sending the same batch at the same time.
 */
async function oneBatch(
  deps: StreamDeps,
  now: () => Date,
  onSent: (events: number) => void,
): Promise<BatchOutcome> {
  return deps.db.transaction(async (tx): Promise<BatchOutcome> => {
    const result = await tx.execute<{ locked: boolean }>(
      sql`SELECT pg_try_advisory_xact_lock(${LOCKS.auditStream}) AS locked`,
    );
    if (result.rows[0]?.locked !== true) return 'busy';
    // Read under the lock: a settings change that restarted the stream is seen here.
    const stream: Stream | null = (await readAuditSettings(tx)).stream;
    if (!stream?.active) return 'off';
    // Fails closed: a missing or malformed state row sends nothing (never a restart at seq 0,
    // which would resend the whole history); the settings view shows why.
    const read = await readStreamState(tx);
    if (!read.ok) return 'failed';
    let state = read.state;
    if (state.nextAttemptAt && Date.parse(state.nextAttemptAt) > now().getTime()) return 'waiting';

    const secret = decryptSecret(
      encryptionKey(deps.secretKey),
      stream.secretEnc,
      AUDIT_STREAM_SECRET_AAD,
    );
    if (secret === null) {
      await writeSetting(tx, AUDIT_STREAM_KEY, failed(state, NO_SECRET, now()));
      return 'failed';
    }

    // §14.2 step 3: events that aged out while the receiver failed are counted, not waited for.
    const [oldest] = await tx
      .select({ seq: auditEvents.seq })
      .from(auditEvents)
      .orderBy(asc(auditEvents.seq))
      .limit(1);
    const cursor = Number(state.cursorSeq);
    if (oldest && oldest.seq > cursor + 1) {
      const missed = oldest.seq - cursor - 1;
      state = { ...state, skipped: state.skipped + missed, cursorSeq: String(oldest.seq - 1) };
      deps.log?.warn(
        `The audit stream skipped ${missed} events that retention removed before they were sent`,
      );
    }

    const events = await nextBatch(tx, state.cursorSeq);
    const first = events[0];
    const last = events.at(-1);
    if (!first || !last) {
      await writeSetting(tx, AUDIT_STREAM_KEY, state);
      return 'empty';
    }
    const body = JSON.stringify({ stream: 'qualor-audit', test: false, events });
    const sent = await post(
      deps,
      stream.url,
      secret,
      body,
      `audit-${first.seq}-${last.seq}`,
      now(),
    );
    if (!sent.ok) {
      await writeSetting(tx, AUDIT_STREAM_KEY, failed(state, errorOf(sent), now()));
      return 'failed';
    }
    await writeSetting(tx, AUDIT_STREAM_KEY, {
      ...state,
      cursorSeq: last.seq,
      lastSuccessAt: now().toISOString(),
      lastError: null,
      failingSince: null,
      consecutiveFailures: 0,
      nextAttemptAt: null,
    });
    onSent(events.length);
    return 'sent';
  });
}

/**
 * rbac-audit.md §14.2: one run of `ee.audit.stream`. While `audit-log` and `audit-log.stream` are
 * active (§14.4) and a stream is configured and active: at-least-once, in seq order, from the
 * cursor, at most {@link STREAM_BATCHES_PER_RUN} batches; a failure keeps the cursor and backs off.
 */
export async function streamAuditEvents(
  deps: StreamDeps,
  signal: AbortSignal,
): Promise<{ sent: number; failed: boolean }> {
  const now = deps.now ?? (() => new Date());
  let sent = 0;
  for (let batch = 0; batch < STREAM_BATCHES_PER_RUN && !signal.aborted; batch += 1) {
    if (!deps.active()) break;
    const outcome = await oneBatch(deps, now, (n) => {
      sent += n;
    });
    if (outcome === 'failed') return { sent, failed: true };
    if (outcome !== 'sent') break;
  }
  return { sent, failed: false };
}

/**
 * `POST /ee/audit/settings/stream/test`: one signed batch with no events (`"test": true`). It does
 * not move the cursor or the failure fields. Nothing is sent while `audit-log` or
 * `audit-log.stream` is inactive (rbac-audit.md §14.4).
 */
export async function testAuditStream(
  deps: StreamDeps,
): Promise<{ ok: boolean; status: number | null; excerpt: string | null }> {
  const now = deps.now ?? (() => new Date());
  if (!deps.active()) return { ok: false, status: null, excerpt: 'SIEM streaming is not licensed' };
  const settings = await readAuditSettings(deps.db);
  if (!settings.stream) return { ok: false, status: null, excerpt: 'No stream is configured' };
  const secret = decryptSecret(
    encryptionKey(deps.secretKey),
    settings.stream.secretEnc,
    AUDIT_STREAM_SECRET_AAD,
  );
  if (secret === null) return { ok: false, status: null, excerpt: NO_SECRET };
  const body = JSON.stringify({ stream: 'qualor-audit', test: true, events: [] });
  return post(deps, settings.stream.url, secret, body, 'audit-test', now());
}
