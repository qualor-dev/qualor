import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export type TokenKind = 'personal' | 'project';

const KIND_PREFIX: Record<TokenKind, string> = { personal: 'qlr_pat_', project: 'qlr_prj_' };
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const TOKEN_PATTERN = /^qlr_(pat|prj)_[0-9A-Za-z]{32}$/;
export const TOKEN_SECRET_LENGTH = 32;
export const TOKEN_PREFIX_LENGTH = 12;

/** Rejection sampling: bytes ≥ 248 (= 4 × 62) are discarded so every character is equally likely. */
export function randomBase62(length: number): string {
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte >= 248) continue;
      out += ALPHABET.charAt(byte % 62);
      if (out.length === length) break;
    }
  }
  return out;
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export interface GeneratedToken {
  token: string;
  prefix: string;
  secretHash: Buffer;
}

export function generateToken(kind: TokenKind): GeneratedToken {
  const token = KIND_PREFIX[kind] + randomBase62(TOKEN_SECRET_LENGTH);
  return { token, prefix: token.slice(0, TOKEN_PREFIX_LENGTH), secretHash: hashToken(token) };
}

export function parseToken(token: string): { kind: TokenKind; prefix: string } | null {
  const match = TOKEN_PATTERN.exec(token);
  if (!match) return null;
  return {
    kind: match[1] === 'pat' ? 'personal' : 'project',
    prefix: token.slice(0, TOKEN_PREFIX_LENGTH),
  };
}

export function hashesEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
