import { describe, expect, it } from 'vitest';
import { decodeCursor, encodeCursor, toPage } from './pagination';
import { ProblemError } from './problem';

const ID = '0190a0b0-0000-7000-8000-000000000001';

describe('keyset pagination', () => {
  it('round-trips an opaque cursor', () => {
    expect(decodeCursor(encodeCursor(ID))).toBe(ID);
    expect(decodeCursor(undefined)).toBeUndefined();
  });

  it('rejects tampered cursors with 422 on query.cursor', () => {
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    for (const bad of ['garbage', b64({ id: 'nope' }), b64({ id: ID, extra: 1 }), b64([ID])]) {
      try {
        decodeCursor(bad);
        expect.unreachable(bad);
      } catch (err) {
        expect(err).toBeInstanceOf(ProblemError);
        expect((err as ProblemError).errors).toEqual([
          { path: 'query.cursor', message: 'Invalid cursor' },
        ]);
      }
    }
  });

  it('returns a next cursor only when there is another page', () => {
    const rows = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    expect(toPage(rows, 2)).toEqual({ items: rows.slice(0, 2), nextCursor: encodeCursor('b') });
    expect(toPage(rows.slice(0, 2), 2)).toEqual({ items: rows.slice(0, 2), nextCursor: null });
  });
});
