import { truncateSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { MAX_GO_COVER_BYTES, parseGoCover } from './gocover';
import { detectFormat } from './import';
import type { CoverageRecord } from './model';

const tmp = useTempDirs();

function profile(text: string): string {
  const file = path.join(tmp(), 'coverage.out');
  writeFileSync(file, text);
  return file;
}

const lines = (r: CoverageRecord | undefined) => [...(r?.lines ?? [])].sort((a, b) => a[0] - b[0]);

describe('parseGoCover (config.md §6, plan 9C)', () => {
  it('makes each line of a block with statements executable; the last line only past column 1', async () => {
    const parsed = await parseGoCover(
      profile(
        'mode: set\n' +
          'example.com/m/a.go:3.2,5.1 2 1\n' + // lines 3, 4 (line 5 holds only the closing brace)
          'example.com/m/a.go:6.2,6.12 1 0\n' + // line 6, never run
          'example.com/m/a.go:7.10,9.3 1 1\n' + // lines 7, 8, 9
          'example.com/m/a.go:10.2,11.1 0 1\n', // no statement: nothing
      ),
    );
    expect([...parsed.files.keys()]).toEqual(['example.com/m/a.go']);
    expect(lines(parsed.files.get('example.com/m/a.go'))).toEqual([
      [3, 1],
      [4, 1],
      [6, 0],
      [7, 1],
      [8, 1],
      [9, 1],
    ]);
    expect(parsed.sourceDirs).toEqual([]);
  });

  it('takes the most hits of the blocks on a line, across repeated blocks and mode lines', async () => {
    const parsed = await parseGoCover(
      profile('mode: count\nx/a.go:1.1,1.20 1 0\nx/a.go:1.21,1.40 1 3\nmode: count\nx/a.go:1.1,1.20 1 2\n'),
    );
    expect(lines(parsed.files.get('x/a.go'))).toEqual([[1, 3]]);
  });

  it('reads atomic mode, CRLF line ends and the _/absolute paths of a GOPATH-less run', async () => {
    const parsed = await parseGoCover(profile('mode: atomic\r\n_/home/u/p/a.go:2.1,2.5 1 4\r\n'));
    expect(lines(parsed.files.get('/home/u/p/a.go'))).toEqual([[2, 4]]);
  });

  it('refuses what is not a Go coverage profile', async () => {
    await expect(parseGoCover(profile(''))).rejects.toThrow(/empty/);
    await expect(parseGoCover(profile('SF:a.go\n'))).rejects.toThrow(/mode line/);
    await expect(parseGoCover(profile('mode: set\na.go:1.1,x 1 1\n'))).rejects.toThrow(/unexpected line/);
  });

  it('is detected by its first line', () => {
    expect(detectFormat(profile('mode: atomic\nx/a.go:1.1,1.2 1 1\n'))).toBe('gocover');
    expect(detectFormat(profile('﻿mode: set\n'))).toBe('gocover');
    expect(detectFormat(profile('model: set\n'))).toBeNull();
  });
});

describe('parseGoCover on an untrusted profile', () => {
  it('drops entries whose path climbs out with `..` segments', async () => {
    const parsed = await parseGoCover(
      profile('mode: set\n../../etc/a.go:1.1,2.1 1 1\nx/../../a.go:1.1,2.1 1 1\nx/ok.go:1.1,2.1 1 1\n'),
    );
    expect([...parsed.files.keys()]).toEqual(['x/ok.go']);
  });

  it('refuses a profile larger than the limit without reading it', async () => {
    const file = profile('mode: set\n');
    truncateSync(file, MAX_GO_COVER_BYTES + 1); // sparse: nothing is written
    await expect(parseGoCover(file)).rejects.toThrow(/too large/);
  });

  it('bounds the lines a single block can claim', async () => {
    const parsed = await parseGoCover(
      profile('mode: set\nx/a.go:1.1,999999999999.1 1 1\nx/a.go:5.1,5.9 1 1\nx/a.go:99999999999999999999.1,99999999999999999999.2 1 1\n'),
    );
    expect(lines(parsed.files.get('x/a.go'))).toEqual([[5, 1]]);
  });

  it('does not count repeated blocks of a merged profile against the cap', async () => {
    // Scaled-down caps keep it fast under --coverage: 2000 copies of a 500-line block are 1M line
    // visits (under the visit cap) and 500 distinct lines (under the 1000-line cap the 1M would pass).
    const block = 'x/a.go:1.1,500.2 1 1\n';
    const parsed = await parseGoCover(profile('mode: set\n' + block.repeat(2000)), {
      distinctLines: 1000,
      lineVisits: 2_000_000,
    });
    expect(parsed.truncated).toBeUndefined();
    expect(parsed.files.get('x/a.go')?.lines.size).toBe(500);
  });

  it('keeps what it read and flags the report when the distinct lines pass the cap', async () => {
    let text = 'mode: set\n';
    for (let i = 0; i < 10; i++) text += `x/a${i}.go:1.1,100.2 1 1\n`;
    const parsed = await parseGoCover(profile(text), { distinctLines: 250, lineVisits: 1_000_000 });
    expect(parsed.truncated).toBe(true);
    expect([...parsed.files.keys()]).toEqual(['x/a0.go', 'x/a1.go', 'x/a2.go']);
  });

  it('flags the report when the repeated work passes the visit cap', async () => {
    const parsed = await parseGoCover(profile('mode: set\n' + 'x/a.go:1.1,100.2 1 1\n'.repeat(50)), {
      distinctLines: 1000,
      lineVisits: 1000,
    });
    expect(parsed.truncated).toBe(true);
    expect(parsed.files.get('x/a.go')?.lines.size).toBe(100);
  });

  it('skips a block that ends before it starts and reports a missing file cleanly', async () => {
    const parsed = await parseGoCover(profile('mode: set\nx/a.go:9.1,3.5 1 1\nx/a.go:4.1,4.5 1 1\n'));
    expect(lines(parsed.files.get('x/a.go'))).toEqual([[4, 1]]);
    await expect(parseGoCover(path.join(tmp(), 'nope.out'))).rejects.toThrow('cannot read the Go coverage profile');
  });
});
