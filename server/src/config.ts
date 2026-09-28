import { isIP } from 'node:net';
import { isAbsolute, resolve } from 'node:path';
import { z } from 'zod';
import { LOG_LEVELS, type LogLevel } from './http/logger';
import { USERNAME_PATTERN } from './patterns';
import { parseInternalHosts } from './scm/url';

const MiB = 1024 * 1024;

/** proxy-addr's named ranges, which Fastify's trustProxy also accepts. */
const PROXY_PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);

function isAddressOrCidr(entry: string): boolean {
  if (PROXY_PRESETS.has(entry)) return true;
  const [address = '', prefix, ...rest] = entry.split('/');
  const family = isIP(address);
  if (family === 0 || rest.length > 0) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (family === 4 ? 32 : 128);
}

/**
 * Which reverse proxies may set X-Forwarded-For/-Proto/-Host: off (unset or empty), a hop count
 * (the N closest proxies), or a comma-separated list of IPs, CIDRs and presets. `true` (trust
 * every hop) is deliberately not accepted: it lets any client choose its own address, which would
 * defeat the per-IP login throttle.
 */
const trustProxySchema = z
  .string()
  .optional()
  .transform((raw, ctx): false | number | string[] => {
    const value = raw?.trim() ?? '';
    if (value === '') return false;
    if (/^\d+$/.test(value)) {
      const hops = Number(value);
      if (hops >= 1 && hops <= 100) return hops;
      ctx.addIssue({ code: 'custom', message: 'a hop count must be between 1 and 100' });
      return z.NEVER;
    }
    const entries = value.split(',').map((e) => e.trim());
    if (entries.every(isAddressOrCidr)) return entries;
    ctx.addIssue({
      code: 'custom',
      message: 'must be a hop count (integer >= 1) or a comma-separated list of IPs/CIDRs',
    });
    return z.NEVER;
  });
/**
 * scm.md §2.3: where users open Qualor, for links in GitLab comments and commit statuses. An
 * `http(s)` URL without credentials, query or fragment, kept without a trailing slash; unset or
 * empty means no links.
 */
const publicUrlSchema = z
  .string()
  .optional()
  .transform((raw, ctx): string | null => {
    const value = raw?.trim() ?? '';
    if (value === '') return null;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be an http or https URL' });
      return z.NEVER;
    }
    if (
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username !== '' ||
      url.password !== '' ||
      url.search !== '' ||
      url.hash !== '' ||
      value.includes('?') ||
      value.includes('#')
    ) {
      ctx.addIssue({
        code: 'custom',
        message: 'must be an http or https URL without credentials, query or fragment',
      });
      return z.NEVER;
    }
    return url.href.replace(/\/+$/, '');
  });

/** scm.md §2.1: SCM hosts the operator allows on an internal network. */
const internalHostsSchema = z
  .string()
  .optional()
  .transform((raw, ctx): ReadonlySet<string> => {
    try {
      return parseInternalHosts(raw);
    } catch (err) {
      ctx.addIssue({ code: 'custom', message: (err as Error).message });
      return z.NEVER;
    }
  });
const bytes = (fallback: number) => z.coerce.number().int().min(1024).default(fallback);

// Zod's default messages name the constraint, never the input value, so errors are safe to print.
/** An unset or blank variable is no value. */
const blankAsUnset = (v: unknown): unknown =>
  typeof v === 'string' && v.trim() === '' ? undefined : v;

/** An absolute directory (embedded-postgres.md §3). */
const absoluteDir = (fallback: string) =>
  z.preprocess(
    blankAsUnset,
    z
      .string()
      .refine((v) => isAbsolute(v.trim()), 'must be an absolute path')
      .default(fallback),
  );

/** Trimmed text; unset, empty or blank is null. */
const optionalText = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? null : v.trim()));

/** api.md §4.1: absolute paths of plugin modules (.js or .mjs), comma-separated, at most 8. */
const pluginPathsSchema = z
  .string()
  .optional()
  .transform((v, ctx) => {
    const paths = (v ?? '')
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p !== '');
    if (paths.length > 8) ctx.addIssue({ code: 'custom', message: 'at most 8 plugin paths' });
    for (const p of paths) {
      if (!isAbsolute(p) || !/\.m?js$/.test(p)) {
        ctx.addIssue({
          code: 'custom',
          message: `"${p}" is not an absolute path to a .js or .mjs file`,
        });
      }
    }
    return paths.map((p) => resolve(p));
  });

const envSchema = z
  .object({
    // embedded-postgres.md §2: unset or empty starts the PostgreSQL the image carries.
    DATABASE_URL: z.preprocess(
      blankAsUnset,
      z
        .string()
        .regex(/^postgres(ql)?:\/\//, 'must be a postgres:// URL')
        .optional(),
    ),
    QUALOR_DATA_DIR: absoluteDir('/var/lib/qualor'),
    QUALOR_POSTGRES_DIR: absoluteDir('/opt/postgresql'),
    QUALOR_SECRET_KEY: z.string().min(32, 'must be at least 32 characters'),
    HOST: z.string().min(1).default('0.0.0.0'),
    PORT: z.coerce.number().int().min(0).max(65_535).default(8080),
    QUALOR_LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
    QUALOR_TRUST_PROXY: trustProxySchema,
    QUALOR_BOOTSTRAP_ADMIN_USERNAME: z.string().regex(USERNAME_PATTERN).default('admin'),
    QUALOR_BOOTSTRAP_ADMIN_PASSWORD: z
      .string()
      .min(12, 'must be at least 12 characters')
      .max(256)
      .optional(),
    QUALOR_SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(2_160).default(168),
    QUALOR_UPLOAD_MAX_COMPRESSED_BYTES: bytes(50 * MiB),
    // Ruling S13 #3: hard-capped at 500 MiB regardless of what an operator sets — decoding a report
    // this size already means holding several times that in memory at once (compressed buffer,
    // inflated buffer, UTF-8 string, parsed JSON, the validated zod copy) on a single worker slot;
    // see the memory guidance of deploy/README.md that goes with this ceiling.
    QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES: z.coerce
      .number()
      .int()
      .min(1024)
      .max(500 * MiB)
      .default(500 * MiB),
    // Ruling S13 #3: defaults to 1 — see the memory note above; each concurrent slot can hold
    // several GB while decoding a report near the decompressed-bytes ceiling, and decoding runs
    // synchronously on the event loop (moving it to a worker thread is deferred).
    QUALOR_WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(1),
    // S11: bounds how long Fastify lets a request run (protects against a client that never
    // finishes sending) and how many report uploads are read/decompressed concurrently (each holds
    // up to maxCompressedBytes in memory). Minimum 1000: 0 would disable the timeout entirely,
    // which defeats the point (fix round 2).
    QUALOR_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(3_600_000).default(300_000),
    QUALOR_MAX_CONCURRENT_UPLOADS: z.coerce.number().int().min(1).max(1_000).default(4),
    // Plan 1F ruling Y2: the built web UI to serve from this origin; unset or empty = API only.
    QUALOR_UI_DIR: z.string().optional(),
    QUALOR_PUBLIC_URL: publicUrlSchema,
    QUALOR_SCM_INTERNAL_HOSTS: internalHostsSchema,
    QUALOR_LLM_INTERNAL_HOSTS: internalHostsSchema,
    // sso-scim.md §14: its own list, as QUALOR_SCM_INTERNAL_HOSTS and QUALOR_LLM_INTERNAL_HOSTS are.
    QUALOR_SSO_INTERNAL_HOSTS: internalHostsSchema,
    // sso-scim.md §10.4: the emergency switch; anything but true/false/empty stops the boot.
    QUALOR_FORCE_PASSWORD_SIGN_IN: z
      .enum(['true', 'false', ''], {
        message: 'QUALOR_FORCE_PASSWORD_SIGN_IN must be true or false',
      })
      .optional()
      .transform((v) => v === 'true'),
    // enterprise.md §6: the licence key itself, or a file holding it (read once at boot).
    QUALOR_LICENSE: optionalText,
    QUALOR_LICENSE_FILE: optionalText,
    QUALOR_PLUGIN_PATHS: pluginPathsSchema,
  })
  .superRefine((e, ctx) => {
    // Names both variables, never the key text (enterprise.md §6).
    if (e.QUALOR_LICENSE !== null && e.QUALOR_LICENSE_FILE !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['QUALOR_LICENSE'],
        message: 'set QUALOR_LICENSE or QUALOR_LICENSE_FILE, not both',
      });
    }
  });

export interface UploadLimits {
  maxCompressedBytes: number;
  maxDecompressedBytes: number;
}

/** Embedded mode's directories (embedded-postgres.md §3). */
export interface EmbeddedPostgresDirs {
  /** QUALOR_DATA_DIR: the volume with postgres/ (the cluster) and run/ (the socket). */
  dataDir: string;
  /** QUALOR_POSTGRES_DIR: the installation (bin/, VERSION) and its template cluster. */
  postgresDir: string;
}

export interface Config {
  /** DATABASE_URL: an external database, or null for the embedded one (embedded-postgres.md §2). */
  databaseUrl: string | null;
  embedded: EmbeddedPostgresDirs;
  secretKey: string;
  host: string;
  port: number;
  logLevel: LogLevel;
  /** Passed to Fastify's `trustProxy`: off, a hop count, or trusted proxy addresses/CIDRs. */
  trustProxy: false | number | string[];
  bootstrapAdmin: { username: string; password: string | undefined };
  sessionTtlHours: number;
  upload: UploadLimits;
  workerConcurrency: number;
  requestTimeoutMs: number;
  maxConcurrentUploads: number;
  /** Absolute path of the built web UI (QUALOR_UI_DIR), or null when the server is API-only. */
  uiDir: string | null;
  /** QUALOR_PUBLIC_URL without a trailing slash, or null (no links in GitLab comments). */
  publicUrl: string | null;
  /** QUALOR_SCM_INTERNAL_HOSTS, normalised (scm/url.ts). */
  scmInternalHosts: ReadonlySet<string>;
  /** QUALOR_LLM_INTERNAL_HOSTS, normalised (llm.md §4). */
  llmInternalHosts: ReadonlySet<string>;
  /** QUALOR_SSO_INTERNAL_HOSTS, normalised (sso-scim.md §14). */
  ssoInternalHosts: ReadonlySet<string>;
  /** QUALOR_FORCE_PASSWORD_SIGN_IN=true: re-enables password sign-in for everyone (sso-scim.md §10.4). */
  forcePasswordSignIn: boolean;
  /** enterprise.md §6: the key text (QUALOR_LICENSE) or a file holding it (QUALOR_LICENSE_FILE). */
  license: { text: string | null; file: string | null };
  /** QUALOR_PLUGIN_PATHS: read only when the boot licence is active or in grace (enterprise.md §12). */
  pluginPaths: string[];
}

export class ConfigError extends Error {
  readonly problems: string[];

  constructor(problems: string[]) {
    super(`invalid configuration:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

export function loadConfig(env: Record<string, string | undefined>): Config {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`));
  }
  const e = parsed.data;
  return {
    databaseUrl: e.DATABASE_URL ?? null,
    embedded: {
      dataDir: resolve(e.QUALOR_DATA_DIR.trim()),
      postgresDir: resolve(e.QUALOR_POSTGRES_DIR.trim()),
    },
    secretKey: e.QUALOR_SECRET_KEY,
    host: e.HOST,
    port: e.PORT,
    logLevel: e.QUALOR_LOG_LEVEL,
    trustProxy: e.QUALOR_TRUST_PROXY,
    bootstrapAdmin: {
      username: e.QUALOR_BOOTSTRAP_ADMIN_USERNAME,
      password: e.QUALOR_BOOTSTRAP_ADMIN_PASSWORD,
    },
    sessionTtlHours: e.QUALOR_SESSION_TTL_HOURS,
    upload: {
      maxCompressedBytes: e.QUALOR_UPLOAD_MAX_COMPRESSED_BYTES,
      maxDecompressedBytes: e.QUALOR_UPLOAD_MAX_DECOMPRESSED_BYTES,
    },
    workerConcurrency: e.QUALOR_WORKER_CONCURRENCY,
    requestTimeoutMs: e.QUALOR_REQUEST_TIMEOUT_MS,
    maxConcurrentUploads: e.QUALOR_MAX_CONCURRENT_UPLOADS,
    uiDir: e.QUALOR_UI_DIR?.trim() ? resolve(e.QUALOR_UI_DIR.trim()) : null,
    publicUrl: e.QUALOR_PUBLIC_URL,
    scmInternalHosts: e.QUALOR_SCM_INTERNAL_HOSTS,
    llmInternalHosts: e.QUALOR_LLM_INTERNAL_HOSTS,
    ssoInternalHosts: e.QUALOR_SSO_INTERNAL_HOSTS,
    forcePasswordSignIn: e.QUALOR_FORCE_PASSWORD_SIGN_IN,
    license: {
      text: e.QUALOR_LICENSE,
      file: e.QUALOR_LICENSE_FILE === null ? null : resolve(e.QUALOR_LICENSE_FILE),
    },
    pluginPaths: e.QUALOR_PLUGIN_PATHS,
  };
}
