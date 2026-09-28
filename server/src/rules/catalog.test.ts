import { describe, expect, it } from 'vitest';
import { engine, file, finding, reportWith } from '../../test/reports';
import { ruleRowsFromReport } from './catalog';

describe('ruleRowsFromReport', () => {
  it('sorts both withMetadata and bare rows by key, so two concurrent ingestions that upsert an overlapping set of rules lock them in the same order and never deadlock (Postgres 40P01)', () => {
    const report = reportWith({
      engines: [engine('eslint', [{ id: 'zzz' }, { id: 'aaa' }, { id: 'mmm' }])],
      files: [file('src/a.ts')],
      findings: [
        finding({ engineId: 'my-tool', ruleId: 'zzz-bare', line: 1 }),
        finding({ engineId: 'my-tool', ruleId: 'aaa-bare', line: 2 }),
        finding({ engineId: 'my-tool', ruleId: 'mmm-bare', line: 3 }),
      ],
    });
    const { withMetadata, bare } = ruleRowsFromReport(report);
    expect(withMetadata.map((r) => r.key)).toEqual(['eslint:aaa', 'eslint:mmm', 'eslint:zzz']);
    expect(bare.map((r) => r.key)).toEqual([
      'my-tool:aaa-bare',
      'my-tool:mmm-bare',
      'my-tool:zzz-bare',
    ]);
  });
});
