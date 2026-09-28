import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseJacoco } from './jacoco';

const tmp = useTempDirs();

describe('parseJacoco', () => {
  it('reads the java-basic fixture report with package-qualified paths', async () => {
    const parsed = await parseJacoco(path.join(FIXTURES_DIR, 'java-basic', 'reports', 'jacoco.xml'));
    const record = parsed.files.get('com/acme/Calculator.java');
    expect(record?.lines.size).toBe(9);
    expect([...(record?.lines ?? [])].filter(([, h]) => h === 0).map(([l]) => l)).toEqual([9, 11, 23]);
    expect([...(record?.branches ?? [])]).toEqual([
      [15, { total: 2, covered: 1 }],
      [20, { total: 2, covered: 1 }],
    ]);
  });

  it('handles groups (multi-module reports) and the default package', async () => {
    const root = tmp();
    writeTree(root, {
      'j.xml':
        '<report name="r"><group name="m"><package name="a/b"><sourcefile name="X.java"><line nr="1" mi="0" ci="2" mb="0" cb="0"/><line nr="2" mi="0" ci="0" mb="0" cb="0"/></sourcefile></package></group><package name=""><sourcefile name="Y.java"><line nr="5" mi="3" ci="0" mb="2" cb="0"/></sourcefile></package></report>',
    });
    const parsed = await parseJacoco(path.join(root, 'j.xml'));
    expect([...(parsed.files.get('a/b/X.java')?.lines ?? [])]).toEqual([[1, 2]]);
    expect([...(parsed.files.get('Y.java')?.lines ?? [])]).toEqual([[5, 0]]);
    expect(parsed.files.get('Y.java')?.branches.get(5)).toEqual({ total: 2, covered: 0 });
  });
});
