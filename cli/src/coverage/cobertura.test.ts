import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseCobertura } from './cobertura';

const tmp = useTempDirs();

describe('parseCobertura', () => {
  it('reads the mixed-secrets fixture report', async () => {
    const parsed = await parseCobertura(path.join(FIXTURES_DIR, 'mixed-secrets', 'coverage', 'cobertura.xml'));
    expect(parsed.sourceDirs).toEqual(['.']);
    expect([...(parsed.files.get('src/config.ts')?.lines ?? [])]).toEqual([
      [1, 1],
      [2, 1],
      [4, 0],
    ]);
    expect([...(parsed.files.get('src/run.ts')?.lines ?? [])]).toEqual([[2, 1]]);
  });

  it('reads condition coverage and ignores method-level duplicates of class lines', async () => {
    const root = tmp();
    writeTree(root, {
      'c.xml': `<?xml version="1.0"?>
<coverage><sources><source>/build/agent/src</source></sources><packages><package name="p"><classes>
  <class name="A" filename="a/A.java">
    <methods><method name="m"><lines><line number="3" hits="99"/></lines></method></methods>
    <lines>
      <line number="3" hits="2" branch="true" condition-coverage="50% (1/2)"/>
      <line number="4" hits="0"/>
    </lines>
  </class>
  <class name="A$Inner" filename="a/A.java"><lines><line number="4" hits="1"/></lines></class>
</classes></package></packages></coverage>`,
    });
    const parsed = await parseCobertura(path.join(root, 'c.xml'));
    expect(parsed.sourceDirs).toEqual(['/build/agent/src']);
    const record = parsed.files.get('a/A.java');
    expect([...(record?.lines ?? [])]).toEqual([
      [3, 2],
      [4, 1],
    ]);
    expect(record?.branches.get(3)).toEqual({ total: 2, covered: 1 });
  });

  it('reads branch="True" as coverlet writes it (plan 2D, fixtures/csharp-basic)', async () => {
    const parsed = await parseCobertura(path.join(FIXTURES_DIR, 'csharp-basic', 'coverage', 'coverage.cobertura.xml'));
    const record = parsed.files.get('src/Acme.Store/Pricing.cs');
    expect(record?.branches.get(14)).toEqual({ total: 4, covered: 2 });
    expect(record?.branches.size).toBe(1);
  });
});
