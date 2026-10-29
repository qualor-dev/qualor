import { existsSync } from 'node:fs';
import { BUILTIN_ENGINES } from '@qualor/shared';
import { sql, type SQL } from 'drizzle-orm';
import type { Db } from '../db/client';
import { VERSION } from '../index';
import type { Edition } from '../license/edition';
import { readLlmSettings, type StoredLlmSettings } from '../llm/settings';
import {
  collectAiReviewUsage,
  collectAssistantUsage,
  type AiReviewUsage,
  type AssistantUsage,
} from './ai-review';
import { collectUsage, type UsageBlocks } from './usage';

/** telemetry.md: one list item, a short lowercase token; anything else is dropped. */
export const LIST_ITEM = /^[a-z0-9][a-z0-9+#._-]{0,39}$/;
const MAX_LIST = 50;
const OS = ['linux', 'darwin', 'win32', 'freebsd', 'openbsd'] as const;
const ARCH = ['x64', 'arm64', 'arm', 'ia32', 'ppc64', 's390x', 'riscv64'] as const;

/**
 * telemetry.md: the daily report of schema 1, which a server before 0.12.0 sends, and which a newer
 * one sends on a day it cannot count its AI use.
 */
export interface TelemetryPayloadV1 {
  schema: 1;
  installationId: string;
  version: string;
  edition: 'community' | 'enterprise';
  platform: { os: string; arch: string; node: string; runtime: 'docker' | 'kubernetes' | 'node' };
  database: 'embedded' | 'external';
  counts: {
    organizations: number;
    users: number;
    projects: number;
    branches: number;
    analyses30d: number;
    qualityGates: number;
    qualityProfiles: number;
    webhooks: number;
  };
  languages: string[];
  engines: string[];
  scm: string[];
  features: { sso: boolean; scim: boolean; aiAssistant: boolean };
}

/**
 * telemetry.md: the daily report of schema 2 (0.12.0, R39). It adds `features.aiReview`,
 * `aiReview` and `assistant30d` to schema 1 and changes nothing else; the receiver takes both.
 */
export interface TelemetryPayloadV2 extends Omit<TelemetryPayloadV1, 'schema' | 'features'> {
  schema: 2;
  features: TelemetryPayloadV1['features'] & { aiReview: boolean };
  aiReview: AiReviewUsage;
  assistant30d: AssistantUsage;
}

/**
 * telemetry.md: the daily report of schema 3 (0.13). It adds the feature flags and the blocks of
 * {@link UsageBlocks} to schema 2 and changes nothing else; the receiver takes 1, 2 and 3.
 */
export interface TelemetryPayloadV3 extends Omit<TelemetryPayloadV2, 'schema' | 'features'> {
  schema: 3;
  features: TelemetryPayloadV2['features'] & UsageBlocks['flags'];
  autoFix30d: UsageBlocks['autoFix30d'];
  integrations: UsageBlocks['integrations'];
  reports30d: UsageBlocks['reports30d'];
  licensePolicyOrgs: number;
  mergeRequests30d: UsageBlocks['mergeRequests30d'];
  ci: UsageBlocks['ci'];
}

export type TelemetryPayload = TelemetryPayloadV1 | TelemetryPayloadV2 | TelemetryPayloadV3;

export interface CollectDeps {
  db: Db;
  edition: Pick<Edition, 'edition'>;
  installationId: string;
  database: 'embedded' | 'external';
  env?: Record<string, string | undefined>;
  dockerEnvExists?: boolean;
  logger?: { debug: (obj: object, msg: string) => void } | undefined;
}

/** What the server logs, at debug, when it sends schema 1 because it could not count its AI use. */
export const AI_USE_NOT_COUNTED = 'telemetry sends schema 1: AI use not counted';

/** What the server logs, at debug, when it sends schema 2 because it could not count its usage. */
export const USAGE_NOT_COUNTED = 'telemetry sends schema 2: feature use not counted';

/** Lowercased, deduplicated, sorted, at most 50; a value that is not a short token is dropped. */
export function cleanList(values: Iterable<string | null | undefined>): string[] {
  const out = new Set<string>();
  for (const v of values) {
    if (typeof v !== 'string') continue;
    const s = v.trim().toLowerCase();
    if (LIST_ITEM.test(s)) out.add(s);
  }
  return [...out].sort().slice(0, MAX_LIST);
}

/** The official image sets QUALOR_UI_DIR=/app/ui; Fargate and containerd have no /.dockerenv. */
export function detectRuntime(
  env: Record<string, string | undefined>,
  dockerEnvExists: boolean,
): 'docker' | 'kubernetes' | 'node' {
  if (env.KUBERNETES_SERVICE_HOST) return 'kubernetes';
  if (dockerEnvExists || env.QUALOR_UI_DIR === '/app/ui') return 'docker';
  return 'node';
}

const BUILTIN: readonly string[] = BUILTIN_ENGINES;

/**
 * External SARIF engine ids are user-chosen (qualor.yml `sarif[].engine`), and a hand-made report
 * can claim any id as builtin, so only the built-in ids go out; everything else is `external`.
 */
export function engineTokens(ids: Iterable<string | null>): string[] {
  const out: string[] = [];
  for (const id of ids) {
    if (typeof id !== 'string') continue;
    out.push(BUILTIN.includes(id) ? id : 'external');
  }
  return cleanList(out);
}

const oneOf = (value: string, known: readonly string[]): string =>
  known.includes(value) ? value : 'other';

/**
 * Schema 2's numbers, or null when either collector fails. The day's report is then schema 1, which
 * the receiver takes, and never zeros, which would read as no reviews. The settings are those the
 * report reads: a failure to read them is the report's own, and is not caught here.
 */
async function countAiUse(
  deps: CollectDeps,
  settings: Promise<StoredLlmSettings>,
): Promise<{ aiReview: AiReviewUsage; assistant30d: AssistantUsage } | null> {
  const read = await settings;
  try {
    const [aiReview, assistant30d] = await Promise.all([
      collectAiReviewUsage(deps.db, read),
      collectAssistantUsage(deps.db),
    ]);
    return { aiReview, assistant30d };
  } catch (err) {
    deps.logger?.debug(
      {
        component: 'telemetry',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
      },
      AI_USE_NOT_COUNTED,
    );
    return null;
  }
}

/** Schema 3's blocks, or null when a query fails: the report is then of schema 2, never zeros. */
async function countUsage(
  deps: CollectDeps,
  settings: Promise<StoredLlmSettings>,
): Promise<UsageBlocks | null> {
  const read = await settings;
  try {
    return await collectUsage(deps.db, read);
  } catch (err) {
    deps.logger?.debug(
      {
        component: 'telemetry',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
      },
      USAGE_NOT_COUNTED,
    );
    return null;
  }
}

export async function collectTelemetry(deps: CollectDeps): Promise<TelemetryPayload> {
  const { db } = deps;
  const count = async (query: SQL): Promise<number> =>
    Number((await db.execute<{ n: string | number }>(query)).rows[0]?.n ?? 0);
  const values = async (query: SQL): Promise<(string | null)[]> =>
    (await db.execute<{ v: string | null }>(query)).rows.map((r) => r.v);
  const recent = sql`queued_at > now() - interval '30 days'`;
  // The settings are read once: AI review's numbers are of the same settings as the features.
  const settings = readLlmSettings(db);

  const [
    organizations,
    users,
    projects,
    branches,
    analyses30d,
    qualityGates,
    qualityProfiles,
    webhooks,
    ssoConnections,
    scimTokens,
    languages,
    engines,
    scm,
    llm,
    aiUse,
    usage,
  ] = await Promise.all([
    count(sql`SELECT count(*) AS n FROM organizations`),
    count(sql`SELECT count(*) AS n FROM users`),
    count(sql`SELECT count(*) AS n FROM projects`),
    count(sql`SELECT count(*) AS n FROM branches`),
    count(sql`SELECT count(*) AS n FROM analyses WHERE ${recent}`),
    count(sql`SELECT count(*) AS n FROM quality_gates`),
    count(sql`SELECT count(*) AS n FROM quality_profiles`),
    count(sql`SELECT count(*) AS n FROM webhook_subscriptions`),
    count(sql`SELECT count(*) AS n FROM sso_connections WHERE enabled`),
    count(sql`
      SELECT count(*) AS n FROM scim_tokens
       WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`),
    values(sql`SELECT DISTINCT language AS v FROM branch_files`),
    values(sql`
      SELECT DISTINCT e ->> 'id' AS v
        FROM analyses a CROSS JOIN LATERAL jsonb_array_elements(a.engines) e
       WHERE a.queued_at > now() - interval '30 days' AND e ->> 'status' = 'ok'`),
    values(sql`SELECT DISTINCT provider AS v FROM scm_connections`),
    settings,
    countAiUse(deps, settings),
    countUsage(deps, settings),
  ]);

  const report: TelemetryPayloadV1 = {
    schema: 1,
    installationId: deps.installationId,
    version: VERSION,
    edition: deps.edition.edition(),
    platform: {
      os: oneOf(process.platform, OS),
      arch: oneOf(process.arch, ARCH),
      node: process.versions.node,
      runtime: detectRuntime(
        deps.env ?? process.env,
        deps.dockerEnvExists ?? existsSync('/.dockerenv'),
      ),
    },
    database: deps.database,
    counts: {
      organizations,
      users,
      projects,
      branches,
      analyses30d,
      qualityGates,
      qualityProfiles,
      webhooks,
    },
    languages: cleanList(languages),
    engines: engineTokens(engines),
    scm: cleanList(scm),
    features: {
      sso: ssoConnections > 0,
      scim: scimTokens > 0,
      aiAssistant: llm.provider !== null && Object.values(llm.organizations).some((o) => o.enabled),
    },
  };
  if (aiUse === null) return report;
  const v2: TelemetryPayloadV2 = {
    ...report,
    schema: 2,
    features: { ...report.features, aiReview: aiUse.aiReview.organizations > 0 },
    aiReview: aiUse.aiReview,
    assistant30d: aiUse.assistant30d,
  };
  if (usage === null) return v2;
  const { flags, ...blocks } = usage;
  return { ...v2, schema: 3, features: { ...v2.features, ...flags }, ...blocks };
}
