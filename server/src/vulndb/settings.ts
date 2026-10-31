import { eq, sql } from 'drizzle-orm';
import { z } from 'zod';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { instanceSettings, type EncryptedValue } from '../db/schema';

export const VULNDB_SETTINGS_KEY = 'vulndb';
/** The stored mirror password's envelope decrypts only under this AAD. */
export const VULNDB_PASSWORD_AAD = 'instance_settings.vulndb.mirror.password';
export const OFFICIAL_REPOSITORY = 'ghcr.io/aquasecurity/trivy-db:2';
export const OFFICIAL_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const OFFICIAL_EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
/** The two datasets of the paid `vuln.priority` feature. */
export type PriorityDataset = 'kev' | 'epss';
export const VULNDB_INTERVAL_HOURS = [1, 3, 6, 12, 24] as const;
export type VulndbIntervalHours = (typeof VULNDB_INTERVAL_HOURS)[number];

/** A registry host (with an optional port), a path, and a tag or a sha256 digest. */
export const VULNDB_REPOSITORY_PATTERN =
  /^[a-z0-9.-]+(:[0-9]+)?(\/[a-z0-9._-]+)+(:[A-Za-z0-9._-]{1,128}|@sha256:[0-9a-f]{64})$/;

const encrypted = z.object({ v: z.literal(1), iv: z.string(), ct: z.string(), tag: z.string() });

const sourceSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('official') }),
  z.object({
    kind: z.literal('mirror'),
    repository: z.string().max(512).regex(VULNDB_REPOSITORY_PATTERN),
    username: z.string().max(256).nullable().catch(null),
    passwordEnc: encrypted.nullable().catch(null),
    kevUrl: z.string().max(2048).nullable().catch(null),
    epssUrl: z.string().max(2048).nullable().catch(null),
  }),
  z.object({ kind: z.literal('upload') }),
]);

export type VulndbSource =
  | { kind: 'official' }
  | {
      kind: 'mirror';
      repository: string;
      username: string | null;
      passwordEnc: EncryptedValue | null;
      kevUrl: string | null;
      epssUrl: string | null;
    }
  | { kind: 'upload' };

export const VULNDB_SCANNER_POLICIES = ['daily', 'every'] as const;
export type VulndbScannerPolicy = (typeof VULNDB_SCANNER_POLICIES)[number];

/** Whether scanners take the database from this server, and how often they refresh it. */
export interface VulndbScannerSettings {
  enabled: boolean;
  policy: VulndbScannerPolicy;
}

export interface VulndbSettings {
  enabled: boolean;
  source: VulndbSource;
  intervalHours: VulndbIntervalHours;
  scanners: VulndbScannerSettings;
}

export const DEFAULT_VULNDB_SETTINGS: VulndbSettings = Object.freeze({
  enabled: true,
  source: Object.freeze({ kind: 'official' }) as VulndbSource,
  intervalHours: 6,
  scanners: Object.freeze({ enabled: true, policy: 'daily' }) as VulndbScannerSettings,
}) as VulndbSettings;

/** Part by part, so one damaged key never turns into the defaults of the others. */
const onRead = z.object({
  enabled: z.boolean().catch(DEFAULT_VULNDB_SETTINGS.enabled),
  source: sourceSchema.catch({ kind: 'official' }),
  intervalHours: z
    .union([z.literal(1), z.literal(3), z.literal(6), z.literal(12), z.literal(24)])
    .catch(6),
  scanners: z
    .object({
      enabled: z.boolean().catch(true),
      policy: z.enum(VULNDB_SCANNER_POLICIES).catch('daily'),
    })
    .catch({ enabled: true, policy: 'daily' }),
});

export async function readVulndbSettings(db: Executor): Promise<VulndbSettings> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, VULNDB_SETTINGS_KEY));
  const value =
    typeof row?.value === 'object' && row.value !== null && !Array.isArray(row.value)
      ? row.value
      : {};
  return onRead.parse(value) as VulndbSettings;
}

/** `password`: a string sets it, null removes it, absent keeps it; `username`, `kevUrl` and `epssUrl` likewise. */
export type VulndbSourceInput =
  | { kind: 'official' }
  | {
      kind: 'mirror';
      repository: string;
      username?: string | null;
      password?: string | null;
      kevUrl?: string | null;
      epssUrl?: string | null;
    }
  | { kind: 'upload' };

export interface VulndbSettingsPatch {
  enabled?: boolean;
  intervalHours?: VulndbIntervalHours;
  source?: VulndbSourceInput;
  scanners?: { enabled?: boolean; policy?: VulndbScannerPolicy };
}

/** The host[:port] of a repository: the part before the first slash, lowercased. */
function registryHost(repository: string): string {
  return repository.split('/')[0]?.toLowerCase() ?? '';
}

function nextSource(
  input: VulndbSourceInput,
  current: VulndbSource,
  secretKey: string,
): VulndbSource {
  if (input.kind !== 'mirror') return { kind: input.kind };
  // Credentials carry over only from an existing mirror; a new mirror starts without any.
  const before = current.kind === 'mirror' ? current : null;
  // The stored password never follows the repository to another registry host.
  const sameHost =
    before !== null && registryHost(before.repository) === registryHost(input.repository);
  const passwordEnc =
    input.password === undefined
      ? sameHost
        ? (before?.passwordEnc ?? null)
        : null
      : input.password === null
        ? null
        : encryptSecret(encryptionKey(secretKey), input.password, VULNDB_PASSWORD_AAD);
  return {
    kind: 'mirror',
    repository: input.repository,
    username: input.username === undefined ? (before?.username ?? null) : input.username,
    passwordEnc,
    kevUrl: input.kevUrl === undefined ? (before?.kevUrl ?? null) : input.kevUrl,
    epssUrl: input.epssUrl === undefined ? (before?.epssUrl ?? null) : input.epssUrl,
  };
}

/** Where a priority dataset comes from: the mirror's URL when set, else the official one. */
export function priorityUrl(source: VulndbSource, dataset: PriorityDataset): string {
  if (source.kind === 'mirror') {
    const url = dataset === 'kev' ? source.kevUrl : source.epssUrl;
    if (url !== null) return url;
  }
  return dataset === 'kev' ? OFFICIAL_KEV_URL : OFFICIAL_EPSS_URL;
}

/** Applies `patch` under LOCKS.vulndbSettings; returns the row before and after, for the audit. */
export async function writeVulndbSettings(
  tx: Executor,
  patch: VulndbSettingsPatch,
  secretKey: string,
): Promise<{ before: VulndbSettings; after: VulndbSettings }> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbSettings})`);
  const before = await readVulndbSettings(tx);
  const after: VulndbSettings = {
    enabled: patch.enabled ?? before.enabled,
    intervalHours: patch.intervalHours ?? before.intervalHours,
    source:
      patch.source === undefined
        ? before.source
        : nextSource(patch.source, before.source, secretKey),
    scanners: {
      enabled: patch.scanners?.enabled ?? before.scanners.enabled,
      policy: patch.scanners?.policy ?? before.scanners.policy,
    },
  };
  await tx
    .insert(instanceSettings)
    .values({ key: VULNDB_SETTINGS_KEY, value: after })
    .onConflictDoUpdate({
      target: instanceSettings.key,
      set: { value: after, updatedAt: sql`now()` },
    });
  return { before, after };
}
