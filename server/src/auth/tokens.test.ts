import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateToken, hashesEqual, hashToken, parseToken, randomBase62 } from './tokens';

describe('API tokens (data-model.md §4.1)', () => {
  it('formats personal and project tokens as prefix + 32 base62 characters', () => {
    expect(generateToken('personal').token).toMatch(/^qlr_pat_[0-9A-Za-z]{32}$/);
    expect(generateToken('project').token).toMatch(/^qlr_prj_[0-9A-Za-z]{32}$/);
  });

  it('shows the first 12 characters and stores only a SHA-256 of the whole token', () => {
    const g = generateToken('personal');
    expect(g.prefix).toBe(g.token.slice(0, 12));
    expect(g.secretHash).toEqual(createHash('sha256').update(g.token).digest());
    expect(g.secretHash).toHaveLength(32);
  });

  it('draws base62 characters without modulo bias', () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 2_000; i++) {
      for (const c of randomBase62(32)) counts.set(c, (counts.get(c) ?? 0) + 1);
    }
    expect(counts.size).toBe(62);
    const mean = (2_000 * 32) / 62;
    for (const n of counts.values()) {
      expect(n).toBeGreaterThan(mean * 0.75);
      expect(n).toBeLessThan(mean * 1.25);
    }
  });

  it('generates distinct tokens', () => {
    expect(new Set(Array.from({ length: 1_000 }, () => generateToken('personal').token)).size).toBe(
      1_000,
    );
  });

  it('parses only well-formed tokens', () => {
    const g = generateToken('project');
    expect(parseToken(g.token)).toEqual({ kind: 'project', prefix: g.prefix });
    for (const bad of [
      '',
      'qlr_pat_',
      `qlr_pat_${'a'.repeat(31)}`,
      `qlr_pat_${'a'.repeat(33)}`,
      `qlr_xxx_${'a'.repeat(32)}`,
      `qlr_pat_${'a'.repeat(31)}-`,
      ` ${g.token}`,
    ]) {
      expect(parseToken(bad), bad).toBeNull();
    }
  });

  it('compares hashes in constant time and rejects length mismatches', () => {
    const a = hashToken('x');
    expect(hashesEqual(a, hashToken('x'))).toBe(true);
    expect(hashesEqual(a, hashToken('y'))).toBe(false);
    expect(hashesEqual(a, a.subarray(0, 16))).toBe(false);
  });
});
