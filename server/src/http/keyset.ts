import type { z } from 'zod';
import { validationFailed } from './problem';

/**
 * Opaque cursors for keyset pagination over more than the id (api.md §1): the sort key values of
 * the last row returned, as base64url JSON. `pagination.ts` covers the common id-only case.
 */
export function encodeKeyset(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/** `undefined` without a cursor; a 422 on `query.cursor` when it does not match `schema`. */
export function decodeKeyset<T>(cursor: string | undefined, schema: z.ZodType<T>): T | undefined {
  if (cursor === undefined) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    raw = undefined;
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw validationFailed([{ path: 'query.cursor', message: 'Invalid cursor' }]);
  }
  return parsed.data;
}
