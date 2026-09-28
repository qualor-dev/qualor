import { describe, expect, it } from 'vitest';
import { jsonChunks } from './bulk';

describe('jsonChunks', () => {
  it('returns no chunk for no rows', () => {
    expect([...jsonChunks([])]).toEqual([]);
  });

  it('is a generator: nothing is built until iterated', () => {
    const iterator = jsonChunks([{ a: 1 }]);
    expect(iterator.next).toBeTypeOf('function');
    expect([...iterator]).toEqual(['[{"a":1}]']);
  });

  it('splits by row count and keeps every row once, in order', () => {
    const rows = Array.from({ length: 7 }, (_, i) => ({ i }));
    const chunks = [...jsonChunks(rows, { maxRows: 3 })];
    expect(chunks).toHaveLength(3);
    expect(chunks.flatMap((c) => JSON.parse(c) as unknown[])).toEqual(rows);
  });

  it('splits by size, and gives an oversized row its own chunk', () => {
    const big = { s: 'x'.repeat(100) };
    const chunks = [...jsonChunks([{ a: 1 }, big, { b: 2 }], { maxBytes: 50 })];
    expect(chunks.map((c) => JSON.parse(c) as unknown[])).toEqual([[{ a: 1 }], [big], [{ b: 2 }]]);
  });

  it('drops U+0000 from every string, which Postgres text and jsonb reject', () => {
    const [chunk] = jsonChunks([{ message: 'a\u0000b', nested: { lines: ['c\u0000'] } }]);
    expect(JSON.parse(chunk!)).toEqual([{ message: 'ab', nested: { lines: ['c'] } }]);
    // A literal backslash-u sequence in the text is data, not a NUL, and survives.
    const [literal] = jsonChunks([{ s: '\\u0000' }]);
    expect(JSON.parse(literal!)).toEqual([{ s: '\\u0000' }]);
  });
});
