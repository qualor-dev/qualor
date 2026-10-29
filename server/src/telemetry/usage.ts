import { sql, type SQL } from 'drizzle-orm';
import type { Db } from '../db/client';
import { readLicensePolicies } from '../licenses/settings';
import type { StoredLlmSettings } from '../llm/settings';
import { MAIL_KINDS } from '../mail/outbox';
import { readMailSettings } from '../mail/settings';

/** The mail templates the report names; any other kind counts as `other`. */
export type MailKindToken = (typeof MAIL_KINDS)[number] | 'other';

/**
 * telemetry.md schema 3 (0.13): which features are used, in counts and flags only. Every window is
 * the last 30 days on the database's clock. Names, hosts, addresses and time zones never leave.
 * The receiver's validation copies this field list.
 */
export interface UsageBlocks {
  /** Automatic fix suggestions made (the people's are `assistant30d`), and those posted. */
  autoFix30d: { made: number; posted: number };
  integrations: {
    /** MCP clients with a live grant used, and the people behind them. */
    mcp: { clients30d: number; users30d: number };
    /** Active Slack and Teams subscriptions, and those with a digest in the last 4 ISO weeks. */
    chat: { slack: number; teams: number; withDigest: number };
    /** Mails sent, in total and by template (every kind present, 0 when none). */
    email: { sent30d: number; byKind: Record<MailKindToken, number> };
  };
  reports30d: { complianceReady: number; complianceFailed: number; sonarImport: number };
  /** The organisations with a dependency licence policy. */
  licensePolicyOrgs: number;
  /** Analyses of merge requests, by the SCM provider the report named. */
  mergeRequests30d: { gitlab: number; github: number };
  /** Analyses by the CI system whose context they carried; `other` carried neither. */
  ci: { gitlab: number; github: number; other: number };
  /** The booleans of `features`. */
  flags: { autoFix: boolean; mcp: boolean; chat: boolean; email: boolean; licensePolicy: boolean };
}

const MAIL_TOKENS: readonly string[] = MAIL_KINDS;

/** The one row of an aggregate query, each of its counts a number. */
async function row<K extends string>(db: Db, query: SQL): Promise<Record<K, number>> {
  const r = (await db.execute<Record<K, string | number>>(query)).rows[0];
  const out = {} as Record<K, number>;
  for (const [key, value] of Object.entries(r ?? {})) out[key as K] = Number(value ?? 0);
  return out;
}

/**
 * Schema 3's numbers. It throws when any query fails, and the report is then of the schema below.
 * The settings are those the report already read.
 */
export async function collectUsage(db: Db, settings: StoredLlmSettings): Promise<UsageBlocks> {
  const [autoFix, mcp, chat, mailRows, reports, scm, organizations, policies, mail, grants] =
    await Promise.all([
      row<'made' | 'posted'>(
        db,
        sql`
          SELECT count(*) FILTER (WHERE status = 'succeeded') AS made,
                 count(*) FILTER (WHERE post ->> 'status' = 'posted') AS posted
            FROM llm_requests
           WHERE feature = 'fix' AND user_id IS NULL
             AND created_at > now() - interval '30 days'`,
      ),
      row<'clients' | 'users'>(
        db,
        sql`
          SELECT count(DISTINCT client_row_id) AS clients, count(DISTINCT user_id) AS users
            FROM oauth_grants
           WHERE revoked_at IS NULL AND last_used_at > now() - interval '30 days'`,
      ),
      row<'slack' | 'teams' | 'digest'>(
        db,
        sql`
          SELECT count(*) FILTER (WHERE kind = 'slack') AS slack,
                 count(*) FILTER (WHERE kind = 'teams') AS teams,
                 count(*) FILTER (
                   WHERE digest_last_week >= to_char(now() - interval '28 days', 'IYYY-"W"IW')
                 ) AS digest
            FROM webhook_subscriptions
           WHERE active AND kind IN ('slack', 'teams')`,
      ),
      db.execute<{ kind: string; n: string | number }>(sql`
        SELECT kind, count(*) AS n FROM mail_messages
         WHERE status = 'sent' AND sent_at > now() - interval '30 days'
         GROUP BY kind`),
      row<'ready' | 'failed' | 'sonar'>(
        db,
        sql`
          SELECT (SELECT count(*) FROM compliance_reports
                   WHERE status = 'ready' AND created_at > now() - interval '30 days') AS ready,
                 (SELECT count(*) FROM compliance_reports
                   WHERE status = 'failed' AND created_at > now() - interval '30 days') AS failed,
                 (SELECT count(*) FROM audit_events
                   WHERE action = 'issue.statuses_imported' AND outcome = 'success'
                     AND created_at > now() - interval '30 days') AS sonar`,
      ),
      row<'gitlab_mr' | 'github_mr' | 'gitlab' | 'github' | 'other'>(
        db,
        sql`
          SELECT count(*) FILTER (
                   WHERE scm_context ->> 'provider' = 'gitlab'
                     AND scm_context ->> 'mergeRequestId' IS NOT NULL
                 ) AS gitlab_mr,
                 count(*) FILTER (
                   WHERE scm_context ->> 'provider' = 'github'
                     AND scm_context ->> 'mergeRequestId' IS NOT NULL
                 ) AS github_mr,
                 count(*) FILTER (WHERE scm_context -> 'gitlab' IS NOT NULL
                   AND scm_context -> 'gitlab' <> 'null'::jsonb) AS gitlab,
                 count(*) FILTER (
                   WHERE coalesce(scm_context -> 'gitlab', 'null'::jsonb) = 'null'::jsonb
                     AND coalesce(scm_context -> 'github', 'null'::jsonb) <> 'null'::jsonb
                 ) AS github,
                 count(*) FILTER (
                   WHERE coalesce(scm_context -> 'gitlab', 'null'::jsonb) = 'null'::jsonb
                     AND coalesce(scm_context -> 'github', 'null'::jsonb) = 'null'::jsonb
                 ) AS other
            FROM analyses
           WHERE queued_at > now() - interval '30 days'`,
      ),
      db.execute<{ id: string }>(sql`SELECT id FROM organizations`),
      readLicensePolicies(db),
      readMailSettings(db),
      row<'n'>(db, sql`SELECT count(*) AS n FROM oauth_grants WHERE revoked_at IS NULL`),
    ]);

  const byKind = Object.fromEntries([...MAIL_KINDS, 'other'].map((kind) => [kind, 0])) as Record<
    MailKindToken,
    number
  >;
  let sent = 0;
  for (const m of mailRows.rows) {
    const token = (MAIL_TOKENS.includes(m.kind) ? m.kind : 'other') as MailKindToken;
    byKind[token] += Number(m.n);
    sent += Number(m.n);
  }
  const existing = new Set(organizations.rows.map((o) => o.id));
  const licensePolicyOrgs = Object.keys(policies.organizations).filter((id) =>
    existing.has(id),
  ).length;
  const autoFixOn =
    settings.provider !== null &&
    Object.entries(settings.organizations).some(
      ([id, o]) => existing.has(id) && o.enabled && o.autoFix.enabled,
    );

  return {
    autoFix30d: { made: autoFix.made, posted: autoFix.posted },
    integrations: {
      mcp: { clients30d: mcp.clients, users30d: mcp.users },
      chat: { slack: chat.slack, teams: chat.teams, withDigest: chat.digest },
      email: { sent30d: sent, byKind },
    },
    reports30d: {
      complianceReady: reports.ready,
      complianceFailed: reports.failed,
      sonarImport: reports.sonar,
    },
    licensePolicyOrgs,
    mergeRequests30d: { gitlab: scm.gitlab_mr, github: scm.github_mr },
    ci: { gitlab: scm.gitlab, github: scm.github, other: scm.other },
    flags: {
      autoFix: autoFixOn,
      mcp: grants.n > 0,
      chat: chat.slack + chat.teams > 0,
      email: mail.server !== null || sent > 0,
      licensePolicy: licensePolicyOrgs > 0,
    },
  };
}
