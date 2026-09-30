import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { analyzeFiles, duplicationFilter } from './analyze-files';

const tmp = useTempDirs();

function scope(root: string, p: string, extra: Partial<ScopeFile> = {}): ScopeFile {
  return {
    path: p,
    absPath: path.join(root, ...p.split('/')),
    language: 'typescript',
    grammar: 'typescript',
    kind: 'main',
    size: 10,
    ...extra,
  };
}

describe('analyzeFiles', () => {
  it('measures parseable files and hashes every file', async () => {
    const root = tmp();
    writeTree(root, { 'a.ts': 'export function f() {\n  return 1;\n}\n', 'README.md': '# x\n' });
    const warnings = new Warnings();
    const out = analyzeFiles(
      [scope(root, 'a.ts'), scope(root, 'README.md', { language: 'other', grammar: null })],
      { parsers: await testParsers(), warnings, log: silentLogger },
    );
    expect(out[0]).toMatchObject({ lines: 3, metrics: { functions: 1, ncloc: 3 } });
    expect(out[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(out[1]).toMatchObject({ lines: 1 });
    expect(out[1]?.metrics).toBeUndefined();
    expect(warnings.list()).toEqual([]);
  });

  it('skips metrics for files over 1 MiB, warns about Latin-1 and syntax errors', async () => {
    const root = tmp();
    writeTree(root, {
      'big.min.ts': 'x',
      'latin.ts': new Uint8Array([
        0x2f, 0x2f, 0xe9, 0x0a, 0x6c, 0x65, 0x74, 0x20, 0x61, 0x3b, 0x0a,
      ]),
      'broken.ts': 'function (\n',
    });
    const warnings = new Warnings();
    const out = analyzeFiles(
      [
        scope(root, 'big.min.ts', { size: 2 * 1024 * 1024 }),
        scope(root, 'latin.ts'),
        scope(root, 'broken.ts'),
      ],
      { parsers: await testParsers(), warnings, log: silentLogger },
    );
    expect(out[0]?.metrics).toBeUndefined();
    expect(out[1]?.metrics).toMatchObject({ ncloc: 1, commentLines: 1 });
    expect(out[2]?.metrics).toBeDefined();
    expect(warnings.list().map((w) => w.code)).toEqual([
      'FILE_TOO_LARGE',
      'FILE_NOT_UTF8',
      'PARSE_ERRORS',
    ]);
  });

  it('streams a real file over 1 MiB (even one that grew after discovery) and still reports its lines', async () => {
    const root = tmp();
    const content = 'let a = 1;\n'.repeat(120_000);
    writeTree(root, { 'grew.ts': content });
    const warnings = new Warnings();
    const out = analyzeFiles([scope(root, 'grew.ts', { size: 10 })], {
      parsers: await testParsers(),
      warnings,
      log: silentLogger,
    });
    expect(out[0]).toMatchObject({ lines: 120_000 });
    expect(out[0]?.metrics).toBeUndefined();
    expect(warnings.list().map((w) => w.code)).toEqual(['FILE_TOO_LARGE']);
  });

  it('skips metrics when parsing exceeds the time budget', async () => {
    const root = tmp();
    writeTree(root, { 'data.ts': `export const a = [${'1,'.repeat(200_000)}];\n` });
    const warnings = new Warnings();
    const out = analyzeFiles([scope(root, 'data.ts')], {
      parsers: await testParsers(),
      warnings,
      log: silentLogger,
      parseTimeoutMs: 0,
    });
    expect(out[0]?.metrics).toBeUndefined();
    expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'PARSE_TIMEOUT' }));
  });

  it('leaves out a file that disappeared after discovery', async () => {
    const root = tmp();
    const warnings = new Warnings();
    const out = analyzeFiles([scope(root, 'gone.ts')], {
      parsers: await testParsers(),
      warnings,
      log: silentLogger,
    });
    expect(out).toEqual([]);
    expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'FILE_UNREADABLE' }));
  });

  it('collects duplication units only for eligible files', async () => {
    const root = tmp();
    writeTree(root, { 'a.ts': 'export const a = 1;\n', 'a.test.ts': 'export const b = 2;\n' });
    const config = parseConfig({ version: 1, duplication: { exclude: ['gen/**'] } });
    const filter = duplicationFilter(config);
    const out = analyzeFiles([scope(root, 'a.ts'), scope(root, 'a.test.ts', { kind: 'test' })], {
      parsers: await testParsers(),
      warnings: new Warnings(),
      log: silentLogger,
      collectUnits: filter,
    });
    expect(out[0]?.units).toHaveLength(1);
    expect(out[1]?.units).toBeUndefined();
    expect(filter(scope(root, 'gen/x.ts'))).toBe(false);
    expect(
      duplicationFilter(parseConfig({ version: 1, duplication: { enabled: false } }))(
        scope(root, 'a.ts'),
      ),
    ).toBe(false);
  });

  it('measures a one-line Kotlin class body without a PARSE_ERRORS warning (phase 8E)', async () => {
    const root = tmp();
    writeTree(root, { 'A.kt': 'class A { fun f() {} }\n', 'B.kt': 'fun broken( {\n' });
    const warnings = new Warnings();
    const kt = { language: 'kotlin', grammar: 'kotlin' } as const;
    const out = analyzeFiles([scope(root, 'A.kt', kt)], {
      parsers: await testParsers(),
      warnings,
      log: silentLogger,
    });
    expect(out[0]?.metrics).toMatchObject({ functions: 1, classes: 1 });
    expect(warnings.list()).toEqual([]);
    analyzeFiles([scope(root, 'B.kt', kt)], {
      parsers: await testParsers(),
      warnings,
      log: silentLogger,
    });
    expect(warnings.list().map((w) => w.code)).toEqual(['PARSE_ERRORS']);
  });
});
