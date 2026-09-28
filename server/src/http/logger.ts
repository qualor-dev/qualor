import {
  pino,
  stdSerializers,
  type DestinationStream,
  type Logger,
  type LoggerOptions,
} from 'pino';
import { pgErrorCode } from '../db/errors';

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** api.md §4. pino wildcards match exactly one level, so each key is listed bare and under `*`. */
const SENSITIVE_KEYS = [
  'authorization',
  'cookie',
  'password',
  'currentPassword',
  'newPassword',
  'token',
  'secret',
  // The LLM provider's key (llm.md §3.2): never logged, even by mistake.
  'apiKey',
  // sso-scim.md §7.8: the new secret shapes SSO and SCIM add.
  'clientSecret',
  'spKey',
  'SAMLResponse',
  'code_verifier',
  'id_token',
  'access_token',
  'refresh_token',
];
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-qualor-csrf"]',
  'res.headers["set-cookie"]',
  ...SENSITIVE_KEYS,
  ...SENSITIVE_KEYS.map((key) => `*.${key}`),
  // The licence key text (enterprise.md §6): `key` alone is too common a name to redact everywhere.
  'license.key',
  '*.license.key',
];

/**
 * Task 6 review, controller ruling S7: pino's default `err` serializer includes every own
 * enumerable property of the error, plus its message and stack. drizzle-orm's DrizzleQueryError
 * puts the failed query and its bind params in both `message`/`stack` (`Failed query: ...\nparams:
 * ...`) and again as `query`/`params` own properties — REDACT_PATHS can't reach inside a free-form
 * SQL string, so a dropped connection while writing a password hash (`PUT /auth/me/password`)
 * would otherwise put that hash straight into the logs. Any error carrying a `query` or `params`
 * property is treated the same way, whatever its exact class: keep only its constructor name, the
 * Postgres SQLSTATE if the `cause` chain has one, and a fixed, safe message. Every other error
 * keeps pino's standard serialization.
 */
function errSerializer(value: unknown): unknown {
  if (value instanceof Error && ('query' in value || 'params' in value)) {
    const code = pgErrorCode(value);
    return {
      type: value.constructor.name,
      message: 'database query failed',
      ...(code ? { code } : {}),
    };
  }
  return stdSerializers.err(value as Error);
}

/** sso-scim.md §7.8: `code` and `state` ride in the query string of the SSO callbacks. */
export const SSO_PATH_PREFIX = '/api/v0/ee/sso/';

interface SerializableRequest {
  method?: string;
  url?: string;
  host?: string;
  ip?: string;
  headers?: Record<string, unknown>;
  socket?: { remotePort?: number };
}

/**
 * Fastify logs `{ req: request }` with the real `Request` instance (fastify/lib/log-controller.js),
 * whose default serializer emits `method`, `url`, `version`, `host`, `remoteAddress` (from `req.ip`)
 * and `remotePort` (fastify/lib/logger-pino.js, checked against the installed 5.12.5). This keeps the
 * same fields, so no existing log consumer changes, and additionally drops the query string of a URL
 * under `SSO_PATH_PREFIX` (it holds `code` and `state`, sso-scim.md §7.8).
 */
function reqSerializer(req: SerializableRequest): Record<string, unknown> {
  const url = typeof req.url === 'string' ? req.url : undefined;
  const cut = url?.startsWith(SSO_PATH_PREFIX) ? url.split('?', 1)[0] : url;
  return {
    method: req.method,
    url: cut,
    version: req.headers?.['accept-version'],
    host: req.host,
    remoteAddress: req.ip,
    remotePort: req.socket?.remotePort,
  };
}

export function loggerOptions(level: LogLevel): LoggerOptions {
  return {
    level,
    redact: { paths: REDACT_PATHS, censor: '[redacted]' },
    serializers: { err: errSerializer, req: reqSerializer },
  };
}

export function createLogger(level: LogLevel, destination?: DestinationStream): Logger {
  return destination ? pino(loggerOptions(level), destination) : pino(loggerOptions(level));
}
