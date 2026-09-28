import { count, desc, eq, gt, sql } from 'drizzle-orm';
import { z } from 'zod';
import { randomBase62 } from '../auth/tokens';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { auditEvents, instanceSettings, type EncryptedValue } from '../db/schema';
import { notFound, ProblemError, validationFailed, type FieldError } from '../http/problem';
import { instanceSetting } from '../settings';
import { webhookSettings, webhookUrlProblem } from '../webhooks/url';
import type { AuditActorContext, AuditRecorder } from './recorder';

/** rbac-audit.md §11.1: `{ retentionDays, stream }`. */
export const AUDIT_SETTINGS_KEY = 'audit';
/** rbac-audit.md §11.2: the anchor of the last retention run. */
export const AUDIT_CHAIN_KEY = 'audit-chain';
/** rbac-audit.md §14.3: where the SIEM stream stands. */
export const AUDIT_STREAM_KEY = 'audit-stream';
export const DEFAULT_AUDIT_RETENTION_DAYS = 365;
export const MIN_AUDIT_RETENTION_DAYS = 30;
export const MAX_AUDIT_RETENTION_DAYS = 36_500;
/** The AAD of the stream secret's envelope (data-model.md §2). */
export const AUDIT_STREAM_SECRET_AAD = 'instance_settings.audit.stream.secret';

const envelope = z.object({ v: z.literal(1), iv: z.string(), ct: z.string(), tag: z.string() });
export const auditSettingsSchema = z.object({
  retentionDays: z.number().int().min(MIN_AUDIT_RETENTION_DAYS).max(MAX_AUDIT_RETENTION_DAYS),
  stream: z
    .object({ url: z.string().max(2048), active: z.boolean(), secretEnc: envelope })
    .nullable(),
});
export interface AuditSettings {
  retentionDays: number;
  stream: { url: string; active: boolean; secretEnc: EncryptedValue } | null;
}

export const DEFAULT_AUDIT_SETTINGS: AuditSettings = {
  retentionDays: DEFAULT_AUDIT_RETENTION_DAYS,
  stream: null,
};

export function readAuditSettings(db: Executor): Promise<AuditSettings> {
  return instanceSetting(db, AUDIT_SETTINGS_KEY, auditSettingsSchema, DEFAULT_AUDIT_SETTINGS);
}

/** The anchor of rbac-audit.md §11.2: the last pruned event's seq and hash. */
export interface AuditAnchor {
  throughSeq: string;
  throughHash: string;
}

/** A seq as a decimal string, at most Number.MAX_SAFE_INTEGER (it must round-trip a number). */
export const auditSeqString = z
  .string()
  .regex(/^(0|[1-9]\d{0,15})$/)
  .refine((seq) => Number(seq) <= Number.MAX_SAFE_INTEGER, 'seq exceeds MAX_SAFE_INTEGER');
export const auditHashString = z.string().regex(/^[0-9a-f]{64}$/);
/** The anchor fields of the `audit-chain` row and of an `audit.pruned` event (§11.2). */
export const auditAnchorSchema = z.object({
  throughSeq: auditSeqString,
  throughHash: auditHashString,
});

export const MALFORMED_ANCHOR = 'The audit chain anchor is malformed';

/**
 * rbac-audit.md §10.2, api.md §2.1: the `audit-chain` row exists but is malformed, so the chain
 * can neither report its anchor nor continue. A problem, so every route (core or plugin) answers
 * 409 AUDIT_CHAIN_ANCHOR_MALFORMED through the central error handler, never a 500. An
 * administrator must repair the row; no retry helps.
 */
export class AuditAnchorMalformedError extends ProblemError {
  constructor() {
    super(409, 'AUDIT_CHAIN_ANCHOR_MALFORMED', MALFORMED_ANCHOR, {
      detail:
        'The instance setting audit-chain exists but is malformed, so the audit chain cannot continue. Restore it from a backup, or from the throughSeq and throughHash of the newest audit.pruned event in an export or the SIEM copy.',
    });
    this.name = 'AuditAnchorMalformedError';
  }
}

/**
 * The `audit-chain` row's anchor, or null when there is no row. Fails closed: a row that exists
 * but does not parse throws, so the chain never silently restarts at the genesis and reuses seqs.
 */
export async function readChainAnchor(db: Executor): Promise<AuditAnchor | null> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, AUDIT_CHAIN_KEY));
  if (!row) return null;
  const parsed = auditAnchorSchema.safeParse(row.value);
  if (!parsed.success) throw new AuditAnchorMalformedError();
  return { throughSeq: parsed.data.throughSeq, throughHash: parsed.data.throughHash };
}

export async function writeSetting(tx: Executor, key: string, value: unknown): Promise<void> {
  await tx.execute(sql`
    INSERT INTO instance_settings (key, value) VALUES (${key}, ${JSON.stringify(value)}::jsonb)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`);
}

const isoOrNull = z.iso.datetime().nullable();

/** rbac-audit.md §14.2: the `audit-stream` row, where the SIEM stream stands. */
export const streamStateSchema = z.object({
  cursorSeq: auditSeqString,
  lastSuccessAt: isoOrNull,
  lastError: z.string().max(2048).nullable(),
  failingSince: isoOrNull,
  consecutiveFailures: z.number().int().min(0),
  nextAttemptAt: isoOrNull,
  skipped: z.number().int().min(0),
});
export interface StreamState {
  cursorSeq: string;
  lastSuccessAt: string | null;
  lastError: string | null;
  failingSince: string | null;
  consecutiveFailures: number;
  nextAttemptAt: string | null;
  skipped: number;
}

export function initialStreamState(cursorSeq: string): StreamState {
  return {
    cursorSeq,
    lastSuccessAt: null,
    lastError: null,
    failingSince: null,
    consecutiveFailures: 0,
    nextAttemptAt: null,
    skipped: 0,
  };
}

export const MALFORMED_STREAM_STATE =
  'The audit-stream state row is malformed; reset the stream (save its settings again)';
export const MISSING_STREAM_STATE =
  'The audit-stream state row is missing; reset the stream (save its settings again)';

/**
 * The `audit-stream` row. Fails closed: a row that is missing or does not parse is `ok: false`
 * with the reason, never a stream at seq 0, which would resend the whole history. Saving the
 * stream settings again restarts it at the head (updateAuditSettings).
 */
export async function readStreamState(
  db: Executor,
): Promise<{ ok: true; state: StreamState } | { ok: false; error: string }> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, AUDIT_STREAM_KEY));
  if (!row) return { ok: false, error: MISSING_STREAM_STATE };
  const parsed = streamStateSchema.safeParse(row.value);
  return parsed.success
    ? { ok: true, state: parsed.data }
    : { ok: false, error: MALFORMED_STREAM_STATE };
}

/** rbac-audit.md §14.3. */
export interface AuditStreamStatus {
  /** Null while the state row is missing or malformed (then `lastError` says so). */
  cursorSeq: string | null;
  /** Events after the cursor. */
  pending: number;
  lastSuccessAt: string | null;
  lastError: string | null;
  failingSince: string | null;
  nextAttemptAt: string | null;
  skipped: number;
}

/** `GET /ee/audit/settings`: never the secret, only whether one is set. */
export interface AuditSettingsView {
  retentionDays: number;
  stream: { url: string; active: boolean; secretSet: boolean; status: AuditStreamStatus } | null;
}

/** `PUT /ee/audit/settings`: `stream: null` removes the stream, an absent `stream` keeps it. */
export interface AuditSettingsInput {
  retentionDays?: number;
  stream?: { url: string; active?: boolean; secret?: string } | null;
}

export async function auditSettingsView(db: Executor): Promise<AuditSettingsView> {
  const settings = await readAuditSettings(db);
  if (!settings.stream) return { retentionDays: settings.retentionDays, stream: null };
  const read = await readStreamState(db);
  if (!read.ok) {
    return {
      retentionDays: settings.retentionDays,
      stream: {
        url: settings.stream.url,
        active: settings.stream.active,
        secretSet: true,
        status: {
          cursorSeq: null,
          pending: 0,
          lastSuccessAt: null,
          lastError: read.error,
          failingSince: null,
          nextAttemptAt: null,
          skipped: 0,
        },
      },
    };
  }
  const state = read.state;
  const [pending] = await db
    .select({ n: count() })
    .from(auditEvents)
    .where(gt(auditEvents.seq, Number(state.cursorSeq)));
  return {
    retentionDays: settings.retentionDays,
    stream: {
      url: settings.stream.url,
      active: settings.stream.active,
      secretSet: true,
      status: {
        cursorSeq: state.cursorSeq,
        pending: Number(pending?.n ?? 0),
        lastSuccessAt: state.lastSuccessAt,
        lastError: state.lastError,
        failingSince: state.failingSince,
        nextAttemptAt: state.nextAttemptAt,
        skipped: state.skipped,
      },
    },
  };
}

export interface AuditSettingsDeps {
  secretKey: string;
  recorder: AuditRecorder;
}

/** A generated stream secret: `whsec_` and 32 base62 characters, as for webhooks. */
function generateStreamSecret(): string {
  return `whsec_${randomBase62(32)}`;
}

const MIN_SECRET_LENGTH = 16;
const MAX_SECRET_LENGTH = 256;
const AUDIT_SETTINGS_TARGET = { type: 'audit_settings' as const, id: AUDIT_SETTINGS_KEY };

function validateInput(input: AuditSettingsInput): void {
  const errors: FieldError[] = [];
  const days = input.retentionDays;
  if (
    days !== undefined &&
    (!Number.isInteger(days) || days < MIN_AUDIT_RETENTION_DAYS || days > MAX_AUDIT_RETENTION_DAYS)
  ) {
    errors.push({
      path: 'body.retentionDays',
      message: `Use a whole number of days from ${MIN_AUDIT_RETENTION_DAYS} to ${MAX_AUDIT_RETENTION_DAYS}`,
    });
  }
  const secret = input.stream?.secret;
  if (
    secret !== undefined &&
    (typeof secret !== 'string' ||
      secret.length < MIN_SECRET_LENGTH ||
      secret.length > MAX_SECRET_LENGTH ||
      secret.includes(String.fromCharCode(0)))
  ) {
    errors.push({
      path: 'body.stream.secret',
      message: `Use ${MIN_SECRET_LENGTH} to ${MAX_SECRET_LENGTH} characters`,
    });
  }
  if (errors.length > 0) throw validationFailed(errors);
}

/**
 * The seq the stream's cursor starts at: the chain's head (or, with every event pruned, the
 * anchor's seq), read under the chain lock so no event can slip in between it and the caller's
 * own `audit.settings_updated`, which is then the receiver's first event (rbac-audit.md §14.2).
 * The lock is held to the end of the caller's transaction.
 */
async function chainHeadSeq(tx: Executor): Promise<string> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditChain})`);
  const [head] = await tx
    .select({ seq: auditEvents.seq })
    .from(auditEvents)
    .orderBy(desc(auditEvents.seq))
    .limit(1);
  if (head) return String(head.seq);
  return (await readChainAnchor(tx))?.throughSeq ?? '0';
}

/**
 * `PUT /ee/audit/settings` (rbac-audit.md §13, §14.1): validates (422 on `body.retentionDays`,
 * `body.stream.url` with the webhooks' URL rules, `body.stream.secret`), writes the `audit` row,
 * restarts the stream at the head when it is new or its URL changed, and records
 * `audit.settings_updated` (the URL as its origin only), all in one transaction. Returns
 * a generated secret once; null when the caller gave one or none was needed.
 */
export async function updateAuditSettings(
  db: Db,
  deps: AuditSettingsDeps,
  context: AuditActorContext,
  input: AuditSettingsInput,
): Promise<{ view: AuditSettingsView; secret: string | null }> {
  validateInput(input);
  let url: string | undefined;
  if (input.stream) {
    const problem = webhookUrlProblem(input.stream.url, await webhookSettings(db));
    if (problem) throw validationFailed([{ path: 'body.stream.url', message: problem }]);
    url = new URL(input.stream.url).href;
  }
  const key = encryptionKey(deps.secretKey);
  let generated: string | null = null;
  await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditSettings})`);
    const current = await readAuditSettings(tx);
    const changed: string[] = [];
    const retentionDays = input.retentionDays ?? current.retentionDays;
    if (retentionDays !== current.retentionDays) changed.push('retentionDays');
    let stream = current.stream;
    if (input.stream === null) {
      if (current.stream) changed.push('stream');
      stream = null;
    } else if (input.stream && url !== undefined) {
      const before = current.stream;
      let secretEnc = before?.secretEnc;
      if (input.stream.secret !== undefined) {
        secretEnc = encryptSecret(key, input.stream.secret, AUDIT_STREAM_SECRET_AAD);
        changed.push('stream.secret');
      } else if (!secretEnc) {
        generated = generateStreamSecret();
        secretEnc = encryptSecret(key, generated, AUDIT_STREAM_SECRET_AAD);
      }
      const active = input.stream.active ?? before?.active ?? true;
      if (!before) changed.push('stream');
      else {
        if (before.url !== url) changed.push('stream.url');
        if (before.active !== active) changed.push('stream.active');
      }
      stream = { url, active, secretEnc };
    }
    await writeSetting(tx, AUDIT_SETTINGS_KEY, { retentionDays, stream });
    // A new stream, a new URL, or a state row that is missing or malformed (the reset of
    // readStreamState's error): start at the head.
    const restart =
      stream !== null &&
      (current.stream?.url !== stream.url ||
        (input.stream !== undefined && !(await readStreamState(tx)).ok));
    if (restart) {
      // Waits for a running stream batch (it holds this lock for at most one request), so the
      // run cannot write its old cursor over the restart.
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditStream})`);
      await writeSetting(tx, AUDIT_STREAM_KEY, initialStreamState(await chainHeadSeq(tx)));
    } else if (!stream && current.stream) {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditStream})`);
      await tx.delete(instanceSettings).where(eq(instanceSettings.key, AUDIT_STREAM_KEY));
    }
    await deps.recorder.record(tx, context, [
      {
        action: 'audit.settings_updated',
        target: AUDIT_SETTINGS_TARGET,
        details: {
          changed,
          retentionDays,
          streamOrigin: stream ? new URL(stream.url).origin : null,
          streamActive: stream?.active ?? false,
        },
      },
    ]);
  });
  return { view: await auditSettingsView(db), secret: generated };
}

/**
 * `POST /ee/audit/settings/stream/regenerate-secret`: a new generated secret, returned once;
 * 404 when no stream is configured.
 */
export async function regenerateStreamSecret(
  db: Db,
  deps: AuditSettingsDeps,
  context: AuditActorContext,
): Promise<string> {
  const secret = generateStreamSecret();
  const secretEnc = encryptSecret(encryptionKey(deps.secretKey), secret, AUDIT_STREAM_SECRET_AAD);
  await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditSettings})`);
    const current = await readAuditSettings(tx);
    if (!current.stream) throw notFound('Audit stream');
    await writeSetting(tx, AUDIT_SETTINGS_KEY, {
      ...current,
      stream: { ...current.stream, secretEnc },
    });
    await deps.recorder.record(tx, context, [
      { action: 'audit.stream_secret_regenerated', target: AUDIT_SETTINGS_TARGET, details: {} },
    ]);
  });
  return secret;
}
