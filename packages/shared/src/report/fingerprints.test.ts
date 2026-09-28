import { describe, expect, it } from 'vitest';
import { computeFingerprints } from '../hash';
import { reportFingerprints } from './fingerprints';
import type { ReportFinding } from './schema';

const finding: ReportFinding = {
  engineId: 'eslint',
  ruleId: 'no-console',
  message: 'Unexpected console statement.',
  location: { path: 'src/a.ts', startLine: 3, startColumn: 5 },
  lineHash: 'd'.repeat(32),
  contextHash: 'e'.repeat(32),
};

describe('reportFingerprints (data-model.md §5.1)', () => {
  it('is computeFingerprints over the rule key, path, hashes and position', () => {
    const findings: ReportFinding[] = [
      finding,
      { ...finding, location: null },
      { ...finding, location: { path: 'src/a.ts', startLine: 1 } },
    ];
    expect(reportFingerprints(findings)).toEqual(
      computeFingerprints([
        {
          ruleKey: 'eslint:no-console',
          path: 'src/a.ts',
          lineHash: finding.lineHash,
          contextHash: finding.contextHash,
          startLine: 3,
          startColumn: 5,
        },
        {
          ruleKey: 'eslint:no-console',
          path: null,
          lineHash: finding.lineHash,
          contextHash: finding.contextHash,
          startLine: 0,
          startColumn: 0,
        },
        {
          ruleKey: 'eslint:no-console',
          path: 'src/a.ts',
          lineHash: finding.lineHash,
          contextHash: finding.contextHash,
          startLine: 1,
          startColumn: 0,
        },
      ]),
    );
  });

  it('ignores the message and anything else a rescan may change', () => {
    expect(reportFingerprints([{ ...finding, message: 'other', severity: 'high' }])).toEqual(
      reportFingerprints([finding]),
    );
  });
});
