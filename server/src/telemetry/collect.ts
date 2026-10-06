import { existsSync } from 'node:fs';
import { BUILTIN_ENGINES } from '@qualor/shared';
import { sql, type SQL } from 'drizzle-orm';
import type { Db } from '../db/client';
import { VERSION } from '../index';
import type { Edition } from '../license/edition';
import { readLlmSettings } from '../llm/settings';

/** telemetry.md: one list item, a short lowercase token; anything else is dropped. */
export const LIST_ITEM = /^[a-z0-9][a-z0-9+#._-]{0,39}$/;
const MAX_LIST = 50;
const OS = ['linux', 'darwin', 'win32', 'freebsd', 'openbsd'] as const;
const ARCH = ['x64', 'arm64', 'arm', 'ia32', 'ppc64', 's390x', 'riscv64'] as const;

export interface TelemetryPayload {
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

export interface CollectDeps {
  db: Db;
  edition: Pick<Edition, 'edition'>;
  installationId: string;
  database: 'embedded' | 'external';
  env?: Record<string, string | undefined>;
  dockerEnvExists?: boolean;
}

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

export async function collectTelemetry(deps: CollectDeps): Promise<TelemetryPayload> {
  const { db } = deps;
  const count = async (query: SQL): Promise<number> =>
    Number((await db.execute<{ n: string | number }>(query)).rows[0]?.n ?? 0);
  const values = async (query: SQL): Promise<(string | null)[]> =>
    (await db.execute<{ v: string | null }>(query)).rows.map((r) => r.v);
  const recent = sql`queued_at > now() - interval '30 days'`;

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
    readLlmSettings(db),
  ]);

  return {
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
}
