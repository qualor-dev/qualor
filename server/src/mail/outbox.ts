import { and, asc, eq, isNotNull, sql } from 'drizzle-orm';
import type { Config } from '../config';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { mailMessages, users } from '../db/schema';
import { enqueue } from '../queue/queue';
import { isEmailAddress } from './address';
import type { MailPayload, RenderedMail } from './payload';
import { mailConfigured } from './settings';
import { clipChars, oneLine } from './text';
import type { SendOptions } from './transport';

/** Deliveries run on their own queue and worker (main.ts), so a slow SMTP server never delays analyses. */
export const MAIL_QUEUE = 'mail';
/**
 * One delivery attempt is one job; the handler enqueues the next attempt itself. A job's own
 * retries are only for database failures around an attempt.
 */
export const MAIL_JOB_MAX_ATTEMPTS = 3;
export const MAX_SUBJECT_LENGTH = 300;

/** Template ids (`mail_messages.kind`, CHECKed `^[a-z0-9.-]{1,64}$`). E2 and E3 add theirs here. */
export const MAIL_KINDS = [
  'test',
  'license.expiry',
  'webhook.failed',
  // 0.15: the vulnerability database is stale.
  'vulndb.stale',
  // mail E2: account emails.
  'account.password-reset',
  'account.invitation',
  'account.password-changed',
  // mail E3: project notifications.
  'notify.gate-failed',
  'notify.gate-recovered',
  'notify.analysis-failed',
  // 0.15: vulnerability alerts.
  'notify.vulnerabilities-digest',
  'notify.vulnerabilities-exploited',
] as const;
export type MailKind = (typeof MAIL_KINDS)[number];

/** M5: each payload decrypts only as the payload of its own row. */
export function mailPayloadAad(messageId: string): string {
  return `mail_messages.payload:${messageId}`;
}

export interface MailDeps {
  /** QUALOR_SMTP_* (Config.smtp), QUALOR_PUBLIC_URL, and the key payloads are encrypted under. */
  config: Pick<Config, 'smtp' | 'publicUrl' | 'secretKey'>;
  /** Tests only: the test CA and short timeouts (transport.ts). */
  send?: SendOptions;
}

export function mailDeps(config: Pick<Config, 'smtp' | 'publicUrl' | 'secretKey'>): MailDeps {
  return { config };
}

export interface MailRecipient {
  userId: string;
  address: string;
  username: string;
  displayName: string | null;
}

export interface QueueMailInput {
  kind: MailKind;
  to: { address: string; userId?: string | null };
  /** Called only when the message is stored (not when skipped or a duplicate). */
  render: () => RenderedMail;
  /** Skip when a message with this key went to the same address within the window. */
  dedupe?: { key: string; withinHours: number };
}

export type QueueMailResult =
  { status: 'queued'; id: string } | { status: 'skipped' } | { status: 'duplicate' };

/**
 * E1 spec: stores one message for one recipient and enqueues its first attempt, in the caller's
 * transaction (a rollback sends nothing). Nothing is stored while email is not configured, and
 * nothing for a `to` that is not exactly one plain address (no list, no `Name <address>`, no line
 * break). Dedupe is read, not locked: the callers that dedupe (webhook alerts under their
 * webhook's delivery lock, the daily licence check under LOCKS.licenseAlerts) are serialised
 * already.
 */
export async function queueMail(
  tx: Executor,
  deps: MailDeps,
  input: QueueMailInput,
): Promise<QueueMailResult> {
  if (!(await mailConfigured(tx, deps.config))) return { status: 'skipped' };
  const address = input.to.address;
  if (!isEmailAddress(address)) return { status: 'skipped' };
  if (input.dedupe) {
    const found = await tx.execute(sql`
      SELECT 1 FROM mail_messages
       WHERE dedupe_key = ${clipChars(input.dedupe.key, 200)} AND lower(to_address) = lower(${address})
         AND created_at > now() - make_interval(hours => ${input.dedupe.withinHours})
       LIMIT 1`);
    if (found.rows.length > 0) return { status: 'duplicate' };
  }
  const mail = input.render();
  const id = uuidv7();
  const payload: MailPayload = {
    html: mail.html,
    text: mail.text,
    ...(mail.headers ? { headers: mail.headers } : {}),
  };
  await tx.insert(mailMessages).values({
    id,
    kind: input.kind,
    userId: input.to.userId ?? null,
    toAddress: address,
    subject: clipChars(oneLine(mail.subject), MAX_SUBJECT_LENGTH),
    status: 'pending',
    payloadEnc: encryptSecret(
      encryptionKey(deps.config.secretKey),
      JSON.stringify(payload),
      mailPayloadAad(id),
    ),
    dedupeKey: input.dedupe ? clipChars(input.dedupe.key, 200) : null,
    nextAttemptAt: sql`now()`,
  });
  await enqueue(tx, {
    queue: MAIL_QUEUE,
    payload: { messageId: id, attempts: 0 },
    maxAttempts: MAIL_JOB_MAX_ATTEMPTS,
  });
  return { status: 'queued', id };
}

/** M8: every active instance administrator with an email address, ordered by email. */
export async function instanceAdminRecipients(db: Executor): Promise<MailRecipient[]> {
  const rows = await db
    .select({
      userId: users.id,
      address: users.email,
      username: users.username,
      displayName: users.displayName,
    })
    .from(users)
    .where(and(eq(users.isInstanceAdmin, true), eq(users.active, true), isNotNull(users.email)))
    .orderBy(asc(users.email));
  return rows.map((r) => ({ ...r, address: r.address ?? '' }));
}

/** One {@link queueMail} per instance administrator, rendered for each, with the same dedupe key. */
export async function queueMailToAdmins(
  tx: Executor,
  deps: MailDeps,
  input: {
    kind: MailKind;
    render: (to: MailRecipient) => RenderedMail;
    dedupe?: { key: string; withinHours: number };
  },
): Promise<QueueMailResult[]> {
  const results: QueueMailResult[] = [];
  for (const admin of await instanceAdminRecipients(tx)) {
    results.push(
      await queueMail(tx, deps, {
        kind: input.kind,
        to: { address: admin.address, userId: admin.userId },
        render: () => input.render(admin),
        ...(input.dedupe ? { dedupe: input.dedupe } : {}),
      }),
    );
  }
  return results;
}
