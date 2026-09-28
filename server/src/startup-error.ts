import { pgErrorCode } from './db/errors';

const SYSTEM_ERROR_CODE = /^E[A-Z0-9_]+$/;

interface SystemErrorInfo {
  code: string;
  syscall: string | undefined;
}

/**
 * Walks `cause` links (mirrors db/errors.ts's `pgField`) looking for a Node system error code such
 * as `EADDRINUSE` or `ECONNREFUSED` (task 6 review, controller ruling S7 part 2) — useful when the
 * server fails to bind its port or reach the database before any query ever runs, so there is no
 * Postgres SQLSTATE to report. `syscall` (e.g. `listen`, `connect`), when present on the same
 * error object, is carried along too.
 */
function systemErrorInfo(err: unknown): SystemErrorInfo | undefined {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const record = current as Record<string, unknown>;
    const code = record.code;
    if (typeof code === 'string' && SYSTEM_ERROR_CODE.test(code)) {
      const syscall = record.syscall;
      return { code, syscall: typeof syscall === 'string' ? syscall : undefined };
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * Controller ruling S6 (task 6, from the task 5 review): drizzle-orm wraps every driver failure
 * in `DrizzleQueryError`, whose `message` (and therefore `.stack`) embeds the failed query and
 * its bind params verbatim — during bootstrap those params can include the admin's argon2 hash.
 * On a fatal startup error we must never print `message` or `stack`; only the error's class name
 * (via `constructor.name`, since DrizzleQueryError does not override the inherited `name`
 * property), when the cause chain carries a Postgres SQLSTATE, that code, and otherwise, when it
 * carries a Node system error code (e.g. the port is already in use), that code and its syscall.
 */
export function formatStartupError(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const name = err.constructor.name;
  const pgCode = pgErrorCode(err);
  if (pgCode) return `${name} (${pgCode})`;
  const system = systemErrorInfo(err);
  if (!system) return name;
  return system.syscall
    ? `${name} (${system.code}, ${system.syscall})`
    : `${name} (${system.code})`;
}

/**
 * Plan 1G: the start-up failure of the first database use (the migrations), which in a container
 * is nearly always the deployment's (PostgreSQL not up yet, a wrong host or password). Says which
 * setting to check, with `formatStartupError`'s safe summary; never the URL, which holds the
 * password.
 */
export function databaseStartupError(err: unknown, embedded = false): string {
  if (embedded) {
    // embedded-postgres.md §5: the server started this database itself; no URL to check.
    return `cannot use the embedded PostgreSQL: ${formatStartupError(err)}`;
  }
  return (
    `cannot use the database DATABASE_URL names: ${formatStartupError(err)}; ` +
    'check that PostgreSQL is running and reachable, and the URL and password'
  );
}
