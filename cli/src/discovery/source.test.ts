import { createHash } from 'node:crypto';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { splitSourceLines } from '@qualor/shared';
import { MAX_ANALYZED_BYTES } from './discover';
import { readSource, readSourceLines } from './source';

const tmp = useTempDirs();

describe('readSource', () => {
  it('hashes the raw bytes and counts CRLF+BOM lines like LF lines', () => {
    const root = tmp();
    const bytes = Buffer.from('﻿a\r\nb\r\nc\r\n', 'utf8');
    writeTree(root, { 'crlf.ts': bytes, 'lf.ts': 'a\nb\nc' });
    const crlf = readSource(path.join(root, 'crlf.ts'));
    expect(crlf.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(crlf.lines).toBe(3);
    expect(crlf.encoding).toBe('utf-8');
    expect(crlf.text!.startsWith('﻿')).toBe(false);
    expect(readSource(path.join(root, 'lf.ts')).lines).toBe(3);
    expect(readSourceLines(path.join(root, 'crlf.ts'))).toEqual(['a', 'b', 'c']);
  });

  it('decodes invalid UTF-8 as Latin-1 without losing lines', () => {
    const root = tmp();
    writeTree(root, { 'latin.java': new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x0a, 0x78, 0x0a]) });
    const s = readSource(path.join(root, 'latin.java'));
    expect(s.encoding).toBe('latin1');
    expect(s.text).toBe('café\nx\n');
    expect(s.lines).toBe(2);
  });

  it('streams a file over 1 MiB: hashes and counts lines without decoding it into memory', () => {
    const root = tmp();
    const line = `export const value = ${'1'.repeat(80)};\r\n`;
    const bytes = Buffer.concat([
      Buffer.from('﻿', 'utf8'),
      Buffer.from(line.repeat(Math.ceil((1.5 * 1024 * 1024) / line.length)), 'utf8'),
      Buffer.from('tail without newline', 'utf8'),
    ]);
    expect(bytes.length).toBeGreaterThan(MAX_ANALYZED_BYTES);
    writeTree(root, { 'big.ts': bytes });
    const s = readSource(path.join(root, 'big.ts'));
    expect(s.text).toBeNull();
    expect(s.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(s.lines).toBe(splitSourceLines(bytes.toString('utf8')).length);
    expect(s.encoding).toBe('utf-8');
  });

  it('streams with the same line rules as splitSourceLines (BOM, CRLF, trailing newline, Latin-1)', () => {
    const root = tmp();
    const cases: Record<string, Uint8Array> = {
      'empty.ts': new Uint8Array(),
      'bom-only.ts': Buffer.from('﻿', 'utf8'),
      'newline.ts': Buffer.from('\n', 'utf8'),
      'crlf.ts': Buffer.from('﻿a\r\nb\r\n\r\n', 'utf8'),
      'no-eol.ts': Buffer.from('a\nb', 'utf8'),
      'blank.ts': Buffer.from('a\n\n\n', 'utf8'),
      'lone-cr.ts': Buffer.from('a\rb\r', 'utf8'),
      'split-utf8.ts': Buffer.from('é€\né€', 'utf8'),
      'latin.ts': new Uint8Array([0x63, 0x61, 0x66, 0xe9, 0x0a, 0x78]),
    };
    writeTree(root, cases);
    for (const [name, bytes] of Object.entries(cases)) {
      const full = readSource(path.join(root, name));
      // Forces the streaming path with a tiny chunk size, so chunk boundaries fall everywhere.
      const streamed = readSource(path.join(root, name), { maxInMemoryBytes: -1, chunkBytes: 1 });
      expect(streamed.text, name).toBeNull();
      expect(full.text, name).not.toBeNull();
      expect(streamed.sha256, name).toBe(createHash('sha256').update(bytes).digest('hex'));
      expect(streamed.sha256, name).toBe(full.sha256);
      expect(streamed.lines, name).toBe(full.lines);
      expect(streamed.encoding, name).toBe(full.encoding);
    }
  });

  it('returns null lines for an unreadable file', () => {
    expect(readSourceLines(path.join(tmp(), 'missing.ts'))).toBeNull();
  });
});
