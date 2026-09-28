import { z } from 'zod';
import { validationFailed } from './problem';

/** Spread into a route's querystring schema: ?limit (default 50, max 500) & ?cursor. */
export const pageQuery = {
  limit: z.coerce.number().int().min(1).max(500).default(50),
  cursor: z.string().max(200).optional(),
};

const cursorPayload = z.strictObject({ id: z.uuid() });

export function encodeCursor(id: string): string {
  return Buffer.from(JSON.stringify({ id }), 'utf8').toString('base64url');
}

export function decodeCursor(cursor: string | undefined): string | undefined {
  if (cursor === undefined) return undefined;
  try {
    return cursorPayload.parse(JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))).id;
  } catch {
    throw validationFailed([{ path: 'query.cursor', message: 'Invalid cursor' }]);
  }
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

/** `rows` must be fetched with `limit + 1`, in keyset (id) order. */
export function toPage<T extends { id: string }>(rows: readonly T[], limit: number): Page<T> {
  const items = rows.slice(0, limit);
  const last = items.at(-1);
  return { items, nextCursor: rows.length > limit && last ? encodeCursor(last.id) : null };
}

export function pageSchema<T extends z.ZodType>(item: T) {
  return z.object({ items: z.array(item), nextCursor: z.string().nullable() });
}
