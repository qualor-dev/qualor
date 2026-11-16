import { gzipSync } from 'node:zlib';
import type { SbomEntry } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { ProblemError } from '../http/problem';
import {
  readSbomText,
  SBOM_BODY_MAX_BYTES,
  SBOM_TEXT_MAX_BYTES,
  sbomLabel,
  toVersionEntries,
} from './upload';

const MiB = 1024 * 1024;

async function* chunks(...parts: Buffer[]): AsyncIterable<Buffer> {
  for (const part of parts) yield part;
}

/** The problem a call throws, as `[status, code]`, with its detail. */
async function refused(
  run: () => unknown,
): Promise<{ status: number; code: string; detail?: string }> {
  try {
    await run();
  } catch (err) {
    if (err instanceof ProblemError)
      return { status: err.status, code: err.code, detail: err.detail };
    throw err;
  }
  throw new Error('not refused');
}

describe('readSbomText', () => {
  it('has the caps of the KEV and EPSS files: 32 MiB as sent, 64 MiB inflated', () => {
    expect([SBOM_BODY_MAX_BYTES, SBOM_TEXT_MAX_BYTES]).toEqual([32 * MiB, 64 * MiB]);
  });

  it('reads a plain body in chunks, up to its cap', async () => {
    const body = chunks(Buffer.from('{"a":'), Buffer.from('1}'));
    expect(await readSbomText(body, { gzip: false, maxBodyBytes: 7 })).toBe('{"a":1}');
  });

  it('refuses a body one byte over its cap with 413 SBOM_TOO_LARGE', async () => {
    const body = chunks(Buffer.alloc(5, 0x20), Buffer.alloc(6, 0x20));
    expect(
      await refused(() => readSbomText(body, { gzip: false, maxBodyBytes: 10 })),
    ).toMatchObject({ status: 413, code: 'SBOM_TOO_LARGE' });
  });

  it('refuses a plain body over the text cap', async () => {
    const body = chunks(Buffer.alloc(101, 0x20));
    expect(
      await refused(() =>
        readSbomText(body, { gzip: false, maxBodyBytes: 1_000, maxTextBytes: 100 }),
      ),
    ).toMatchObject({ status: 413, code: 'SBOM_TOO_LARGE' });
  });

  it('inflates gzip up to the text cap, and refuses one byte more', async () => {
    const exactly = gzipSync(Buffer.alloc(100, 0x61));
    expect(await readSbomText(chunks(exactly), { gzip: true, maxTextBytes: 100 })).toBe(
      'a'.repeat(100),
    );
    const over = gzipSync(Buffer.alloc(101, 0x61));
    expect(
      await refused(() => readSbomText(chunks(over), { gzip: true, maxTextBytes: 100 })),
    ).toMatchObject({ status: 413, code: 'SBOM_TOO_LARGE' });
  });

  it('refuses a gzip bomb (65 MiB of spaces) at the real caps without inflating it all', async () => {
    const bomb = gzipSync(Buffer.alloc(65 * MiB, 0x20));
    expect(bomb.length).toBeLessThan(SBOM_BODY_MAX_BYTES);
    const problem = await refused(() => readSbomText(chunks(bomb), { gzip: true }));
    expect(problem).toMatchObject({ status: 413, code: 'SBOM_TOO_LARGE' });
    expect(problem.detail).toContain(String(SBOM_TEXT_MAX_BYTES));
  });

  it('refuses plain bytes sent as gzip, and an empty gzip body, with 422 SBOM_INVALID', async () => {
    for (const body of [Buffer.from('{"bomFormat":"CycloneDX"}'), Buffer.alloc(0)]) {
      expect(await refused(() => readSbomText(chunks(body), { gzip: true }))).toMatchObject({
        status: 422,
        code: 'SBOM_INVALID',
      });
    }
  });

  it('refuses text that is not UTF-8, and says when a plain body is gzip', async () => {
    const latin1 = Buffer.from([0x7b, 0x22, 0xe9, 0x22, 0x7d]);
    expect(await refused(() => readSbomText(chunks(latin1), { gzip: false }))).toMatchObject({
      status: 422,
      code: 'SBOM_INVALID',
    });
    const zipped = await refused(() =>
      readSbomText(chunks(gzipSync(Buffer.from('{}'))), { gzip: false }),
    );
    expect(zipped).toMatchObject({ status: 422, code: 'SBOM_INVALID' });
    expect(zipped.detail).toContain('Content-Encoding: gzip');
  });

  it('strips a leading byte order mark, plain or gzipped', async () => {
    const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{}')]);
    expect(await readSbomText(chunks(withBom), { gzip: false })).toBe('{}');
    expect(await readSbomText(chunks(gzipSync(withBom)), { gzip: true })).toBe('{}');
  });

  it('answers 499 CLIENT_ABORTED when the client goes away mid-body', async () => {
    async function* aborted(): AsyncIterable<Buffer> {
      yield Buffer.from('{');
      throw Object.assign(new Error('aborted'), { code: 'ECONNRESET' });
    }
    expect(await refused(() => readSbomText(aborted(), { gzip: false }))).toMatchObject({
      status: 499,
      code: 'CLIENT_ABORTED',
    });
  });
});

describe('sbomLabel (ruling R4)', () => {
  const invalid = { status: 422, code: 'VERSION_LABEL_INVALID' };

  it('takes the trimmed query, else the subject version', () => {
    expect(sbomLabel(' 2.0.0 ', '1.4.0')).toBe('2.0.0');
    expect(sbomLabel(undefined, '1.4.0')).toBe('1.4.0');
    expect(sbomLabel('x'.repeat(100), null)).toBe('x'.repeat(100));
  });

  it('refuses a blank query, even with a subject version', async () => {
    expect(await refused(() => sbomLabel('  ', '1.0'))).toMatchObject(invalid);
    expect(await refused(() => sbomLabel('', '1.0'))).toMatchObject(invalid);
  });

  it('refuses no label at all, and one over 100 characters', async () => {
    expect(await refused(() => sbomLabel(undefined, null))).toMatchObject(invalid);
    expect(await refused(() => sbomLabel(undefined, '  '))).toMatchObject(invalid);
    expect(await refused(() => sbomLabel('x'.repeat(101), null))).toMatchObject(invalid);
    expect(await refused(() => sbomLabel(undefined, 'x'.repeat(101)))).toMatchObject(invalid);
  });
});

describe('toVersionEntries', () => {
  const entry = (over: Partial<SbomEntry>): SbomEntry => ({
    ecosystem: 'npm',
    name: 'minimist',
    version: '1.2.5',
    path: 'package-lock.json',
    licenses: ['MIT'],
    direct: null,
    source: null,
    ...over,
  });

  it('leaves an unknown direct out, and names the source package', () => {
    expect(
      toVersionEntries([
        entry({}),
        entry({ name: 'a', direct: true }),
        entry({ name: 'b', direct: false }),
        entry({
          ecosystem: 'deb',
          name: 'libssl3',
          version: '3.0.15-1~deb12u1',
          path: '',
          source: { name: 'openssl', version: '3.0.15-1~deb12u1' },
        }),
      ]),
    ).toEqual([
      {
        ecosystem: 'npm',
        name: 'minimist',
        version: '1.2.5',
        path: 'package-lock.json',
        licenses: ['MIT'],
      },
      {
        ecosystem: 'npm',
        name: 'a',
        version: '1.2.5',
        path: 'package-lock.json',
        licenses: ['MIT'],
        direct: true,
      },
      {
        ecosystem: 'npm',
        name: 'b',
        version: '1.2.5',
        path: 'package-lock.json',
        licenses: ['MIT'],
        direct: false,
      },
      {
        ecosystem: 'deb',
        name: 'libssl3',
        version: '3.0.15-1~deb12u1',
        path: '',
        licenses: ['MIT'],
        sourceName: 'openssl',
        sourceVersion: '3.0.15-1~deb12u1',
      },
    ]);
  });
});
