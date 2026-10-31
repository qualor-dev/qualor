import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import {
  EPSS_MAX_LINES,
  KEV_DATA_MAX_BYTES,
  KEV_MAX_ENTRIES,
  parseEpss,
  parseKev,
  PRIORITY_DATA_MAX_BYTES,
  PRIORITY_FILE_MAX_BYTES,
} from './parse';

function entry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    cveID: 'CVE-2024-0001',
    vendorProject: 'V',
    product: 'P',
    vulnerabilityName: 'N',
    dateAdded: '2026-02-03',
    shortDescription: 'd',
    requiredAction: 'a',
    dueDate: '2026-03-03',
    knownRansomwareCampaignUse: 'Unknown',
    ...over,
  };
}

function catalog(entries: unknown[], over: Record<string, unknown> = {}): Buffer {
  return Buffer.from(
    JSON.stringify({
      title: 'CISA KEV',
      catalogVersion: '2026.10.30',
      dateReleased: '2026-10-30T14:22:10.123Z',
      count: entries.length,
      vulnerabilities: entries,
      ...over,
    }),
  );
}

describe('constants', () => {
  it('has the production limits', () => {
    expect(PRIORITY_DATA_MAX_BYTES).toBe(64 * 1024 * 1024);
    expect(PRIORITY_FILE_MAX_BYTES).toBe(32 * 1024 * 1024);
    expect(KEV_DATA_MAX_BYTES).toBe(8 * 1024 * 1024);
    expect(KEV_MAX_ENTRIES).toBe(100_000);
    expect(EPSS_MAX_LINES).toBe(1_000_000);
  });
});

describe('parseKev', () => {
  const two = catalog([
    entry(),
    entry({ cveID: 'CVE-2024-0002', knownRansomwareCampaignUse: 'Known' }),
  ]);

  it('parses a valid catalog', async () => {
    const got = await parseKev(two);
    expect(got).toEqual({
      catalogVersion: '2026.10.30',
      releasedAt: new Date('2026-10-30T14:22:10.123Z'),
      entries: [
        { vulnerabilityId: 'CVE-2024-0001', dateAdded: '2026-02-03', ransomware: false },
        { vulnerabilityId: 'CVE-2024-0002', dateAdded: '2026-02-03', ransomware: true },
      ],
      skipped: 0,
    });
  });

  it('parses the same catalog gzipped', async () => {
    expect(await parseKev(gzipSync(two))).toEqual(await parseKev(two));
  });

  it('skips a bad id or date and counts it', async () => {
    const got = await parseKev(
      catalog([
        entry(),
        entry({ cveID: 'GHSA-xxxx' }),
        entry({ cveID: 'CVE-2024-0003', dateAdded: '2026-13-01' }),
        entry({ cveID: 'CVE-2024-0004', dateAdded: '2026-02-30' }),
      ]),
    );
    expect(got).toMatchObject({ skipped: 3 });
    expect('entries' in got && got.entries).toHaveLength(1);
  });

  it('keeps the first entry of a duplicate id', async () => {
    const got = await parseKev(
      catalog([entry({ dateAdded: '2026-01-01' }), entry({ dateAdded: '2026-02-02' })]),
    );
    expect('entries' in got && got.entries).toEqual([
      { vulnerabilityId: 'CVE-2024-0001', dateAdded: '2026-01-01', ransomware: false },
    ]);
  });

  it.each([
    ['empty object', Buffer.from('{}')],
    ['vulnerabilities not an array', Buffer.from('{"vulnerabilities":"x"}')],
    ['bad dateReleased', catalog([entry()], { dateReleased: 'yesterday' })],
    ['impossible dateReleased', catalog([entry()], { dateReleased: '2026-02-30T00:00:00Z' })],
    ['every entry invalid', catalog([entry({ cveID: 'x' }), 5, null])],
    ['invalid JSON', Buffer.from('{nope')],
    ['array', Buffer.from('[]')],
    ['empty', Buffer.alloc(0)],
    ['bad gzip', Buffer.from([0x1f, 0x8b, 1, 2, 3])],
  ])('gives INVALID_DATA for %s', async (_name, body) => {
    expect(await parseKev(body)).toMatchObject({ problem: { code: 'INVALID_DATA' } });
  });

  it('gives TOO_LARGE past the byte limit and the row limit', async () => {
    expect(await parseKev(gzipSync(two), { maxDataBytes: 50 })).toMatchObject({
      problem: { code: 'TOO_LARGE' },
    });
    expect(await parseKev(two, { maxEntries: 1 })).toMatchObject({
      problem: { code: 'TOO_LARGE' },
    });
    expect(await parseKev(two, { maxEntries: 2 })).toMatchObject({ skipped: 0 });
  });

  it('gives TOO_LARGE past 100 000 entries by default', async () => {
    const many = catalog(Array.from({ length: KEV_MAX_ENTRIES + 1 }, () => ({})));
    expect(await parseKev(many)).toMatchObject({
      problem: { code: 'TOO_LARGE', message: 'The KEV catalog has more than 100000 entries.' },
    });
  });

  it.each([
    ['Z', '2025-03-14T10:00:00Z'],
    ['+00:00', '2025-03-14T10:00:00+00:00'],
    ['+0000', '2025-03-14T10:00:00+0000'],
    ['+0530', '2025-03-14T15:30:00+0530'],
    ['-0200', '2025-03-14T08:00:00-0200'],
  ])('reads a release date with the offset %s', async (_name, dateReleased) => {
    expect(await parseKev(catalog([entry()], { dateReleased }))).toMatchObject({
      releasedAt: new Date('2025-03-14T10:00:00Z'),
    });
  });
});

describe('parseEpss', () => {
  const text =
    '#model_version:v2025.03.14,score_date:2026-10-31T12:55:00Z\n' +
    'cve,epss,percentile\nCVE-2024-0001,0.95,0.999\n';
  const expected = {
    scoreDate: new Date('2026-10-31T12:55:00Z'),
    modelVersion: 'v2025.03.14',
    ids: ['CVE-2024-0001'],
    scores: [0.95],
    percentiles: [0.999],
    skipped: 0,
  };

  it('parses a file', async () => {
    expect(await parseEpss(Buffer.from(text))).toEqual(expected);
  });

  it('parses gzip and CRLF the same', async () => {
    expect(await parseEpss(gzipSync(Buffer.from(text)))).toEqual(expected);
    expect(await parseEpss(Buffer.from(text.replaceAll('\n', '\r\n')))).toEqual(expected);
  });

  it('parses a file without the comment line', async () => {
    const body = text.split('\n').slice(1).join('\n');
    expect(await parseEpss(Buffer.from(body))).toEqual({
      ...expected,
      scoreDate: null,
      modelVersion: null,
    });
  });

  it('skips and counts bad rows, and blank lines', async () => {
    const got = await parseEpss(
      Buffer.from(
        `${text}\nCVE-2024-0002,1.5,0.1\nCVE-2024-0003,abc,0.1\nfoo,0.1,0.1\nCVE-2024-0004,0.1\n\nCVE-2024-0005,-0.1,0.2\nCVE-2024-0006,0.1,0.2,9\n`,
      ),
    );
    expect(got).toMatchObject({ ids: ['CVE-2024-0001'], skipped: 6 });
  });

  it('keeps the first of a duplicate id', async () => {
    const got = await parseEpss(Buffer.from(`${text}CVE-2024-0001,0.5,0.5\n`));
    expect(got).toMatchObject({ ids: ['CVE-2024-0001'], scores: [0.95], skipped: 1 });
  });

  it.each([
    ['wrong header', Buffer.from('cve,score\nCVE-2024-0001,0.1\n')],
    ['no valid row', Buffer.from('cve,epss,percentile\nfoo,2,3\n')],
    ['empty', Buffer.alloc(0)],
    ['bad gzip', Buffer.from([0x1f, 0x8b, 1, 2, 3])],
  ])('gives INVALID_DATA for %s', async (_name, body) => {
    expect(await parseEpss(body)).toMatchObject({ problem: { code: 'INVALID_DATA' } });
  });

  it('gives TOO_LARGE past the byte limit and the row limit', async () => {
    const big = gzipSync(Buffer.from(text + 'CVE-2024-0002,0.1,0.1\n'.repeat(1)));
    expect(await parseEpss(big, { maxDataBytes: 40 })).toMatchObject({
      problem: { code: 'TOO_LARGE' },
    });
    // Five lines: the comment, the header and three rows.
    const rows = `${text}CVE-2024-0002,0.1,0.1\nCVE-2024-0003,0.1,0.1\n`;
    expect(await parseEpss(Buffer.from(rows), { maxLines: 4 })).toMatchObject({
      problem: { code: 'TOO_LARGE', message: 'The EPSS file has more than 4 lines.' },
    });
    expect(await parseEpss(Buffer.from(rows), { maxLines: 5 })).toMatchObject({
      ids: expect.any(Array),
    });
  });

  it('counts blank and comment lines against the line limit', async () => {
    const body = Buffer.from(`\n\n#a\n#b\n${text}`);
    expect(await parseEpss(body, { maxLines: 6 })).toMatchObject({
      problem: { code: 'TOO_LARGE' },
    });
    expect(await parseEpss(body, { maxLines: 7 })).toMatchObject({ ids: ['CVE-2024-0001'] });
  });

  it.each([
    ['+0000', '2025-03-14T00:00:00+0000', '2025-03-14T00:00:00Z'],
    ['+00:00', '2025-03-14T00:00:00+00:00', '2025-03-14T00:00:00Z'],
    ['-0130', '2025-03-14T00:00:00-0130', '2025-03-14T01:30:00Z'],
  ])('reads a score date with the offset %s', async (_name, value, utc) => {
    const body = Buffer.from(
      `#model_version:v1,score_date:${value}\ncve,epss,percentile\nCVE-2024-0001,0.95,0.999\n`,
    );
    expect(await parseEpss(body)).toMatchObject({ scoreDate: new Date(utc) });
  });

  it.each([['+000'], ['+00:0'], ['+00000'], ['+2500'], ['+0060']])(
    'gives no score date for the offset %s',
    async (offset) => {
      const body = Buffer.from(
        `#score_date:2025-03-14T00:00:00${offset}\ncve,epss,percentile\nCVE-2024-0001,0.95,0.999\n`,
      );
      expect(await parseEpss(body)).toMatchObject({ scoreDate: null });
    },
  );
});

describe('hostile input', () => {
  const head = '#model_version:v1,score_date:2026-10-31T12:55:00Z\n';
  const row = 'CVE-2024-0001,0.95,0.999\n';

  it('accepts a BOM on KEV and on EPSS', async () => {
    const kev = await parseKev(Buffer.concat([Buffer.from('\ufeff'), catalog([entry()])]));
    expect(kev).toMatchObject({ skipped: 0, entries: [{ vulnerabilityId: 'CVE-2024-0001' }] });
    const epss = await parseEpss(Buffer.from(`\ufeff${head}cve,epss,percentile\n${row}`));
    expect(epss).toMatchObject({ ids: ['CVE-2024-0001'], modelVersion: 'v1' });
    const bare = await parseEpss(Buffer.from(`\ufeffcve,epss,percentile\n${row}`));
    expect(bare).toMatchObject({ ids: ['CVE-2024-0001'], scoreDate: null });
  });

  it('accepts a spaced header and spaced cells', async () => {
    const got = await parseEpss(
      Buffer.from(`${head}CVE, EPSS , Percentile\n CVE-2024-0001 , 0.95 , 0.999 \n`),
    );
    expect(got).toMatchObject({ ids: ['CVE-2024-0001'], scores: [0.95], skipped: 0 });
  });

  it('refuses other column sets', async () => {
    const got = await parseEpss(Buffer.from(`cve,percentile,epss\n${row}`));
    expect(got).toMatchObject({ problem: { code: 'INVALID_DATA' } });
  });

  it('skips NaN, Infinity and 1e999 cells', async () => {
    const got = await parseEpss(
      Buffer.from(
        `cve,epss,percentile\n${row}CVE-2024-0002,NaN,0.1\nCVE-2024-0003,Infinity,0.1\n` +
          'CVE-2024-0004,1e999,0.1\nCVE-2024-0005,0.1,-Infinity\n',
      ),
    );
    expect(got).toMatchObject({ ids: ['CVE-2024-0001'], skipped: 4 });
  });

  it('skips a non-zero score or percentile below 1e-37, which PostgreSQL real refuses', async () => {
    const got = await parseEpss(
      Buffer.from(
        `cve,epss,percentile\n${row}CVE-2024-0002,1e-50,0.1\nCVE-2024-0003,0.1,1e-38\n` +
          `CVE-2024-0004,0,0\nCVE-2024-0005,1e-37,0.5\nCVE-2024-0006,9.9e-38,0.5\n`,
      ),
    );
    expect(got).toMatchObject({
      ids: ['CVE-2024-0001', 'CVE-2024-0004', 'CVE-2024-0005'],
      scores: [0.95, 0, 1e-37],
      percentiles: [0.999, 0, 0.5],
      skipped: 3,
    });
  });

  it('skips a 100 000-digit cell', async () => {
    const got = await parseEpss(
      Buffer.from(`cve,epss,percentile\n${row}CVE-2024-0002,${'9'.repeat(100_000)}x,0.1\n`),
    );
    expect(got).toMatchObject({ ids: ['CVE-2024-0001'], skipped: 1 });
  });

  it('gives INVALID_DATA for a truncated gzip', async () => {
    const whole = gzipSync(Buffer.from(`cve,epss,percentile\n${row}`.repeat(50)));
    const half = whole.subarray(0, Math.floor(whole.length / 2));
    expect(await parseEpss(half)).toMatchObject({ problem: { code: 'INVALID_DATA' } });
    expect(await parseKev(half)).toMatchObject({ problem: { code: 'INVALID_DATA' } });
  });

  it('gives TOO_LARGE for a gzipped newline bomb', async () => {
    const bomb = gzipSync(Buffer.alloc(2 * 1024 * 1024, 0x0a));
    expect(await parseEpss(bomb, { maxLines: 1000 })).toMatchObject({
      problem: { code: 'TOO_LARGE', message: 'The EPSS file has more than 1000 lines.' },
    });
  });

  it('gives TOO_LARGE for a gzipped KEV of empty entries past the inflated cap', async () => {
    const top = '"catalogVersion":"x","dateReleased":"2026-10-30T00:00:00Z"';
    const bomb = gzipSync(Buffer.from(`{${top},"vulnerabilities":[${'{},'.repeat(400_000)}{}]}`));
    expect(await parseKev(bomb, { maxDataBytes: 512 * 1024 })).toMatchObject({
      problem: {
        code: 'TOO_LARGE',
        message: 'The file is larger than 524288 bytes when inflated.',
      },
    });
  });

  it('gives TOO_LARGE for a plain KEV past 8 MiB', async () => {
    const body = Buffer.alloc(KEV_DATA_MAX_BYTES + 1, 0x20);
    expect(await parseKev(body)).toMatchObject({
      problem: { code: 'TOO_LARGE', message: 'The file is larger than 8388608 bytes.' },
    });
  });

  it('skips a row of 2 million commas, and refuses such a header', async () => {
    const commas = ','.repeat(2_000_000);
    const rowBomb = gzipSync(Buffer.from(`cve,epss,percentile\n${row}${commas}\n`));
    expect(await parseEpss(rowBomb)).toMatchObject({ ids: ['CVE-2024-0001'], skipped: 1 });
    const headerBomb = gzipSync(Buffer.from(`cve,epss,percentile${commas}\n${row}`));
    expect(await parseEpss(headerBomb)).toMatchObject({ problem: { code: 'INVALID_DATA' } });
    const commentBomb = gzipSync(Buffer.from(`#${commas}\ncve,epss,percentile\n${row}`));
    expect(await parseEpss(commentBomb)).toMatchObject({ ids: ['CVE-2024-0001'] });
  });

  it('gives TOO_LARGE for a gzip bomb', async () => {
    const bomb = gzipSync(Buffer.alloc(10 * 1024 * 1024));
    const limits = { maxDataBytes: 1024 * 1024 };
    expect(await parseEpss(bomb, limits)).toMatchObject({ problem: { code: 'TOO_LARGE' } });
    expect(await parseKev(bomb, limits)).toMatchObject({ problem: { code: 'TOO_LARGE' } });
  });
});
