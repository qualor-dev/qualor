export const PG_UNIQUE_VIOLATION = '23505';
export const PG_CHECK_VIOLATION = '23514';
export const PG_FOREIGN_KEY_VIOLATION = '23503';
/** PostgreSQL 18 reports a violated `ON DELETE/UPDATE RESTRICT` action as restrict_violation. */
export const PG_RESTRICT_VIOLATION = '23001';

/** A foreign key refused the change: 23503, or 23001 for a RESTRICT action on PostgreSQL 18+. */
export function isForeignKeyViolation(code: string | undefined): boolean {
  return code === PG_FOREIGN_KEY_VIOLATION || code === PG_RESTRICT_VIOLATION;
}

/** Walks `cause` links: drizzle wraps driver errors in DrizzleQueryError. */
function pgField(err: unknown, field: 'code' | 'constraint'): string | undefined {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const value = (current as Record<string, unknown>)[field];
    if (typeof value === 'string' && (field !== 'code' || /^[0-9A-Z]{5}$/.test(value)))
      return value;
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

export function pgErrorCode(err: unknown): string | undefined {
  return pgField(err, 'code');
}

export function pgConstraint(err: unknown): string | undefined {
  return pgField(err, 'constraint');
}
