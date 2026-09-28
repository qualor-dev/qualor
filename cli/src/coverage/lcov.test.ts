import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseLcov } from './lcov';

const tmp = useTempDirs();

describe('parseLcov', () => {
  it('reads DA and BRDA records of the ts-basic fixture', async () => {
    const parsed = await parseLcov(path.join(FIXTURES_DIR, 'ts-basic', 'coverage', 'lcov.info'));
    const math = parsed.files.get('src/math.ts');
    expect(math?.lines.size).toBe(13);
    expect([...(math?.lines ?? [])].filter(([, h]) => h === 0).map(([l]) => l)).toEqual([6, 12]);
    expect([...(math?.branches ?? [])]).toEqual([
      [3, { total: 2, covered: 2 }],
      [5, { total: 2, covered: 1 }],
      [19, { total: 4, covered: 3 }],
    ]);
    expect(parsed.sourceDirs).toEqual([]);
  });

  it('tolerates CRLF, "-" branches, malformed lines and a missing end_of_record', async () => {
    const root = tmp();
    writeTree(root, {
      'lcov.info':
        'TN:\r\nSF:a.ts\r\nDA:1,1\r\nDA:x,1\r\nBRDA:2,0,0,-\r\nBRDA:2,0,1,3\r\nend_of_record\r\nSF:b.ts\r\nDA:4,0\r\n',
    });
    const parsed = await parseLcov(path.join(root, 'lcov.info'));
    expect([...(parsed.files.get('a.ts')?.lines ?? [])]).toEqual([[1, 1]]);
    expect(parsed.files.get('a.ts')?.branches.get(2)).toEqual({ total: 2, covered: 1 });
    expect([...(parsed.files.get('b.ts')?.lines ?? [])]).toEqual([[4, 0]]);
  });
});
