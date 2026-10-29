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

  it("takes a rule's scope from its metadata, the first entry's; none from a rule without one or a bare rule (0.13)", () => {
    const report = reportWith({
      engines: [
        engine('sonarjs', [
          { id: 'S2004', scope: 'main' },
          { id: 'S2699', scope: 'test' },
          { id: 'S1' },
          // The first entry wins, its missing scope included.
          { id: 'S1', scope: 'main' },
        ]),
      ],
      files: [file('src/a.ts')],
      findings: [finding({ engineId: 'sonarjs', ruleId: 'S9999', line: 1 })],
    });
    const { withMetadata, bare } = ruleRowsFromReport(report);
    expect(withMetadata.map((r) => [r.key, r.scope])).toEqual([
      ['sonarjs:S1', null],
      ['sonarjs:S2004', 'main'],
      ['sonarjs:S2699', 'test'],
    ]);
    expect(bare.map((r) => [r.key, r.scope])).toEqual([['sonarjs:S9999', null]]);
  });

  it("never takes a server engine's rules from a report, defined or only referenced (6M §6)", () => {
    const report = reportWith({
      engines: [
        engine('eslint', [{ id: 'no-console' }]),
        engine('license', [
          { id: 'forbidden', quality: 'security', kind: 'hotspot', defaultSeverity: 'blocker' },
        ]),
      ],
      files: [file('src/a.ts')],
      findings: [
        finding({ line: 1 }),
        finding({ engineId: 'license', ruleId: 'forbidden', line: 2 }),
        finding({ engineId: 'license', ruleId: 'made-up', line: 3 }),
      ],
    });
    const { withMetadata, bare } = ruleRowsFromReport(report);
    expect(withMetadata.map((r) => r.key)).toEqual(['eslint:no-console']);
    expect(bare).toEqual([]);
  });

  it("never takes the AI review's rules from a report either, defined or only referenced (6I-3)", () => {
    const report = reportWith({
      engines: [
        engine('eslint', [{ id: 'no-console' }]),
        engine('ai', [
          { id: 'logic', quality: 'security', kind: 'hotspot', defaultSeverity: 'blocker' },
        ]),
      ],
      files: [file('src/a.ts')],
      findings: [
        finding({ line: 1 }),
        finding({ engineId: 'ai', ruleId: 'logic', line: 2 }),
        finding({ engineId: 'ai', ruleId: 'made-up', line: 3 }),
      ],
    });
    const { withMetadata, bare } = ruleRowsFromReport(report);
    expect(withMetadata.map((r) => r.key)).toEqual(['eslint:no-console']);
    expect(bare).toEqual([]);
  });
});
