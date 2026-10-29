import { isIP } from 'node:net';
import { isAbsolute, resolve } from 'node:path';
import { z } from 'zod';
import { LOG_LEVELS, type LogLevel } from './http/logger';
import { isEmailAddress, isHostName, isOneLine, parseMailbox } from './mail/address';
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

/** telemetry.md: where the daily report goes. Not in the guide: for tests and staging. */
export const DEFAULT_TELEMETRY_URL = 'https://qualor.dev/api/telemetry';

/** telemetry.md "Update check": the tag list read daily. Not in the guide: for tests only. */
export const DEFAULT_UPDATE_CHECK_URL =
  'https://hub.docker.com/v2/namespaces/qualor/repositories/server/tags?page_size=100&ordering=last_updated';

/** An http(s) URL; unset or blank means `fallback`. */
const httpUrlSchema = (fallback: string) =>
  z
    .string()
    .optional()
    .transform((raw, ctx): string => {
      const value = raw?.trim() ?? '';
      if (value === '') return fallback;
      let url: URL | undefined;
      try {
        url = new URL(value);
      } catch {
        url = undefined;
      }
      if (url === undefined || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
        ctx.addIssue({ code: 'custom', message: 'must be an http or https URL' });
        return z.NEVER;
      }
      return url.href;
    });

/** E1 spec: how a message reaches the SMTP server. */
export const SMTP_SECURITIES = ['starttls', 'tls', 'none'] as const;
export type SmtpSecurity = (typeof SMTP_SECURITIES)[number];

/** The SMTP server of QUALOR_SMTP_URL with QUALOR_SMTP_FROM and QUALOR_SMTP_REPLY_TO (email.md). */
export interface SmtpConfig {
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string | null;
  password: string | null;
  fromName: string;
  fromAddress: string;
  replyTo: string | null;
}

export type SmtpUrlParts = Pick<SmtpConfig, 'host' | 'port' | 'security' | 'username' | 'password'>;

const SMTP_URL_FORM =
  'must be smtp://[user[:password]@]host[:port] or smtps://…, optionally with ?security=none';

/**
 * E1 spec: `smtp://` (STARTTLS required, port 587), `smtps://` (implicit TLS, 465), `?security=none`
 * on smtp:// for a relay without TLS; user and password URL-decoded. Every message names the rule,
 * never the value: the URL holds a password.
 */
export function parseSmtpUrl(
  raw: string,
): { ok: true; server: SmtpUrlParts } | { ok: false; message: string } {
  const fail = (message: string) => ({ ok: false as const, message });
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fail(SMTP_URL_FORM);
  }
  const scheme = url.protocol;
  if (scheme !== 'smtp:' && scheme !== 'smtps:') return fail(SMTP_URL_FORM);
  if ((url.pathname !== '' && url.pathname !== '/') || url.hash !== '' || raw.includes('#')) {
    return fail(SMTP_URL_FORM);
  }
  const security = smtpSecurityOf(url);
  if (security === null) return fail('the only query it takes is ?security=none, on smtp://');
  let host = url.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!isHostName(host)) return fail('must name a host');
  const port = smtpPortOf(url);
  if (!Number.isInteger(port) || port < 1 || port > 65_535)
    return fail('the port must be 1 to 65535');
  const credentials = smtpCredentialsOf(url);
  if (typeof credentials === 'string') return fail(credentials);
  return { ok: true, server: { host, port, security, ...credentials } };
}

/**
 * The security of an smtp:// or smtps:// URL: TLS for smtps://, STARTTLS for smtp://, none for
 * smtp://…?security=none; null for any other query.
 */
function smtpSecurityOf(url: URL): SmtpSecurity | null {
  const smtps = url.protocol === 'smtps:';
  if (url.search === '') return smtps ? 'tls' : 'starttls';
  const params = [...url.searchParams.entries()];
  const only = params.length === 1 ? params[0] : undefined;
  if (smtps || only?.[0] !== 'security' || only[1] !== 'none') return null;
  return 'none';
}

/** The port of an smtp:// or smtps:// URL: its own, else 465 for smtps:// and 587 for smtp://. */
function smtpPortOf(url: URL): number {
  if (url.port !== '') return Number(url.port);
  return url.protocol === 'smtps:' ? 465 : 587;
}

/** The URL's user name and password, URL-decoded, or the rule they break. */
function smtpCredentialsOf(url: URL): Pick<SmtpUrlParts, 'username' | 'password'> | string {
  let username: string | null;
  let password: string | null;
  try {
    username = url.username === '' ? null : decodeURIComponent(url.username);
    password = url.password === '' ? null : decodeURIComponent(url.password);
  } catch {
    return 'the user name and password must be URL-encoded';
  }
  if (password !== null && username === null) return 'a password needs a user name';
  if ((username !== null && !isOneLine(username)) || (password !== null && !isOneLine(password))) {
    return 'the user name and password must not contain line breaks';
  }
  return { username, password };
}

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
    // 6I-2 (ruling P4, spec §5): the AI review snapshot a scanner uploads next to its report has
    // limits of its own, which the review-context route tells the scanner. As for the report, the
    // inflated size is capped at 500 MiB whatever is set; it is never less than 1 MiB.
    QUALOR_REVIEW_SNAPSHOT_MAX_COMPRESSED_BYTES: bytes(50 * MiB),
    QUALOR_REVIEW_SNAPSHOT_MAX_DECOMPRESSED_BYTES: z.coerce
      .number()
      .int()
      .min(MiB)
      .max(500 * MiB)
      .default(500 * MiB),
    // Ruling S13 #3: defaults to 1 — see the memory note above; each concurrent slot can hold
    // several GB while decoding a report near the decompressed-bytes ceiling, and decoding runs
    // synchronously on the event loop (moving it to a worker thread is deferred).
    QUALOR_WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(1),
    // 6I-3 R21: AI reviews run on a worker of their own, this many at once. Each holds a masking
    // worker thread (up to 512 MiB) and waits on the provider, so the bound is small.
    QUALOR_REVIEW_WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(8).default(2),
    // 0.13: an AI review's time in all, in minutes, for a model slower than the default allows
    // (REVIEW_TIME_BUDGET_MS, review/job.ts); unset, that default.
    QUALOR_AI_REVIEW_MAX_MINUTES: z.coerce.number().int().min(5).max(240).optional(),
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
    // 6G R7: chat webhook hosts besides Slack's and Teams' (tests and fake receivers only).
    QUALOR_CHAT_TEST_HOSTS: internalHostsSchema,
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
    // The read-only guest account behind the sign-in page's "Explore the demo" (auth/demo.ts).
    QUALOR_DEMO_USER: optionalText.refine((v) => v === null || USERNAME_PATTERN.test(v), {
      message: 'must be a username',
    }),
    // telemetry.md: anonymous usage statistics, on unless switched off; a typo stops the boot.
    QUALOR_TELEMETRY: z
      .preprocess(
        (v) => (typeof v === 'string' ? v.trim().toLowerCase() : v),
        z
          .enum(['true', 'false', '1', '0', 'on', 'off', 'yes', 'no', ''], {
            message: 'QUALOR_TELEMETRY must be true or false',
          })
          .optional(),
      )
      .transform((v) => !(v === 'false' || v === '0' || v === 'off' || v === 'no')),
    QUALOR_TELEMETRY_URL: httpUrlSchema(DEFAULT_TELEMETRY_URL),
    QUALOR_UPDATE_CHECK_URL: httpUrlSchema(DEFAULT_UPDATE_CHECK_URL),
    // E1 spec (email.md): the SMTP server; overrides the one saved in Settings → Email.
    QUALOR_SMTP_URL: z
      .string()
      .optional()
      .transform((raw, ctx): SmtpUrlParts | null => {
        const value = raw?.trim() ?? '';
        if (value === '') return null;
        const parsed = parseSmtpUrl(value);
        if (parsed.ok) return parsed.server;
        ctx.addIssue({ code: 'custom', message: parsed.message });
        return z.NEVER;
      }),
    QUALOR_SMTP_FROM: z
      .string()
      .optional()
      .transform((raw, ctx): { name: string; address: string } | null => {
        const value = raw?.trim() ?? '';
        if (value === '') return null;
        const mailbox = parseMailbox(value);
        if (mailbox) return mailbox;
        ctx.addIssue({ code: 'custom', message: 'must be an address or Name <address>' });
        return z.NEVER;
      }),
    QUALOR_SMTP_REPLY_TO: optionalText.refine((v) => v === null || isEmailAddress(v), {
      message: 'must be an email address',
    }),
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
    if (e.QUALOR_DEMO_USER !== null && e.QUALOR_DEMO_USER === e.QUALOR_BOOTSTRAP_ADMIN_USERNAME) {
      ctx.addIssue({
        code: 'custom',
        path: ['QUALOR_DEMO_USER'],
        message: 'must not be the bootstrap administrator',
      });
    }
    if (e.QUALOR_SMTP_URL !== null && e.QUALOR_SMTP_FROM === null) {
      ctx.addIssue({
        code: 'custom',
        path: ['QUALOR_SMTP_FROM'],
        message: 'required when QUALOR_SMTP_URL is set',
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
  /** 6I-2: the AI review snapshot's limits, QUALOR_REVIEW_SNAPSHOT_MAX_* (as sent, and inflated). */
  reviewSnapshot: UploadLimits;
  workerConcurrency: number;
  /** 6I-3 R21: QUALOR_REVIEW_WORKER_CONCURRENCY, the AI reviews the review worker runs at once. */
  reviewWorkerConcurrency: number;
  /** QUALOR_AI_REVIEW_MAX_MINUTES: an AI review's time in all, 5 to 240; null: the default (45). */
  aiReviewMaxMinutes: number | null;
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
  /** QUALOR_CHAT_TEST_HOSTS, normalised: extra hosts a Slack or Teams webhook may use (6G R7). */
  chatTestHosts: ReadonlySet<string>;
  /** QUALOR_FORCE_PASSWORD_SIGN_IN=true: re-enables password sign-in for everyone (sso-scim.md §10.4). */
  forcePasswordSignIn: boolean;
  /** enterprise.md §6: the key text (QUALOR_LICENSE) or a file holding it (QUALOR_LICENSE_FILE). */
  license: { text: string | null; file: string | null };
  /** QUALOR_PLUGIN_PATHS: read only when the boot licence is active or in grace (enterprise.md §12). */
  pluginPaths: string[];
  /** QUALOR_DEMO_USER: the username anyone may sign in as, read-only, without a password; or null. */
  demoUser: string | null;
  /** telemetry.md: QUALOR_TELEMETRY (default on) and QUALOR_TELEMETRY_URL. */
  telemetry: { enabled: boolean; url: string };
  /** E1 spec: QUALOR_SMTP_URL with its sender, or null (Settings → Email decides). */
  smtp: SmtpConfig | null;
  /** telemetry.md "Update check": QUALOR_UPDATE_CHECK_URL; runs only while telemetry is enabled. */
  updateCheck: { url: string };
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
    reviewSnapshot: {
      maxCompressedBytes: e.QUALOR_REVIEW_SNAPSHOT_MAX_COMPRESSED_BYTES,
      maxDecompressedBytes: e.QUALOR_REVIEW_SNAPSHOT_MAX_DECOMPRESSED_BYTES,
    },
    workerConcurrency: e.QUALOR_WORKER_CONCURRENCY,
    reviewWorkerConcurrency: e.QUALOR_REVIEW_WORKER_CONCURRENCY,
    aiReviewMaxMinutes: e.QUALOR_AI_REVIEW_MAX_MINUTES ?? null,
    requestTimeoutMs: e.QUALOR_REQUEST_TIMEOUT_MS,
    maxConcurrentUploads: e.QUALOR_MAX_CONCURRENT_UPLOADS,
    uiDir: e.QUALOR_UI_DIR?.trim() ? resolve(e.QUALOR_UI_DIR.trim()) : null,
    publicUrl: e.QUALOR_PUBLIC_URL,
    scmInternalHosts: e.QUALOR_SCM_INTERNAL_HOSTS,
    llmInternalHosts: e.QUALOR_LLM_INTERNAL_HOSTS,
    ssoInternalHosts: e.QUALOR_SSO_INTERNAL_HOSTS,
    chatTestHosts: e.QUALOR_CHAT_TEST_HOSTS,
    forcePasswordSignIn: e.QUALOR_FORCE_PASSWORD_SIGN_IN,
    license: {
      text: e.QUALOR_LICENSE,
      file: e.QUALOR_LICENSE_FILE === null ? null : resolve(e.QUALOR_LICENSE_FILE),
    },
    pluginPaths: e.QUALOR_PLUGIN_PATHS,
    demoUser: e.QUALOR_DEMO_USER,
    telemetry: { enabled: e.QUALOR_TELEMETRY, url: e.QUALOR_TELEMETRY_URL },
    smtp:
      e.QUALOR_SMTP_URL === null || e.QUALOR_SMTP_FROM === null
        ? null
        : {
            ...e.QUALOR_SMTP_URL,
            fromName: e.QUALOR_SMTP_FROM.name,
            fromAddress: e.QUALOR_SMTP_FROM.address,
            replyTo: e.QUALOR_SMTP_REPLY_TO,
          },
    updateCheck: { url: e.QUALOR_UPDATE_CHECK_URL },
  };
}
