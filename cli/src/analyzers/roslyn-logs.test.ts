import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { silentLogger } from '../log';
import { useTempDirs } from '../../test/tmp';
import { mergeRoslynLogs, readRoslynLogs } from './roslyn-logs';

const tmp = useTempDirs();

const result = (ruleId: string, ruleIndex: number, line: number, extra: object = {}) => ({
  ruleId,
  ruleIndex,
  level: 'warning',
  message: { text: `${ruleId} message` },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: 'file:///r/src/A.cs' },
        region: { startLine: line, startColumn: 5, endLine: line, endColumn: 9 },
      },
    },
  ],
  ...extra,
});

const log = (version: string, rules: string[], results: object[]) => ({
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'Microsoft (R) Visual C# Compiler',
          version: `${version}-1.26423.113 (e34a38d2)`,
          semanticVersion: version,
          rules: rules.map((id) => ({
            id,
            properties: { category: id.startsWith('CA5') ? 'Security' : 'Design' },
          })),
        },
      },
      columnKind: 'utf16CodeUnits',
      results,
    },
  ],
});

describe('mergeRoslynLogs (rulings D4–D6)', () => {
  it('keeps one of identical results across logs (a multi-targeting project, Review Focus 1)', () => {
    const net8 = log(
      '5.9.0',
      ['CA1062', 'CA5351'],
      [result('CA5351', 1, 9), result('CA1062', 0, 7)],
    );
    const net10 = log(
      '5.9.0',
      ['CA5351', 'CA1062'],
      [result('CA5351', 0, 9), result('CA1062', 1, 7)],
    );
    const merged = mergeRoslynLogs([net8, net10]);
    const run = (
      merged.sarif as {
        runs: {
          results: { ruleId: string; ruleIndex?: number }[];
          tool: { driver: { rules: { id: string }[] } };
        }[];
      }
    ).runs[0]!;
    expect(run.results.map((r) => r.ruleId)).toEqual(['CA5351', 'CA1062']);
    expect(run.results.every((r) => r.ruleIndex === undefined)).toBe(true);
    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(['CA1062', 'CA5351']);
    expect(merged).toMatchObject({ version: '5.9.0', results: 2, duplicates: 2 });
  });

  it('keeps results that differ in line, column or message', () => {
    const a = log(
      '4.11.0',
      ['CA1822'],
      [
        result('CA1822', 0, 11),
        result('CA1822', 0, 13),
        result('CA1822', 0, 11, { message: { text: 'other' } }),
      ],
    );
    expect(mergeRoslynLogs([a]).results).toBe(3);
  });

  it('keeps a file-less result and a suppressed one (the normaliser drops suppressed results)', () => {
    const a = log(
      '5.9.0',
      ['CA1014', 'CA1822'],
      [
        { ruleId: 'CA1014', level: 'warning', message: { text: 'mark assembly' } },
        result('CA1822', 1, 26, { suppressions: [{ kind: 'inSource' }] }),
      ],
    );
    const run = (mergeRoslynLogs([a]).sarif as { runs: { results: object[] }[] }).runs[0]!;
    expect(run.results).toHaveLength(2);
  });

  it('takes the version from the first log with one, and copes with none', () => {
    expect(mergeRoslynLogs([]).version).toBeNull();
    expect(mergeRoslynLogs([]).sarif).toMatchObject({ version: '2.1.0', runs: [{ results: [] }] });
  });
});

describe('readRoslynLogs', () => {
  it('reads SARIF 2.1.0 logs and counts the unreadable ones', () => {
    const dir = tmp();
    const good = path.join(dir, 'A.sarif');
    writeFileSync(good, JSON.stringify(log('5.9.0', [], [])));
    const notJson = path.join(dir, 'B.sarif');
    writeFileSync(notJson, '{');
    const notSarif = path.join(dir, 'C.sarif');
    writeFileSync(notSarif, '{"version":"1.0"}');
    const { logs, unreadable } = readRoslynLogs(
      [good, notJson, notSarif, path.join(dir, 'gone.sarif')],
      silentLogger,
    );
    expect(logs).toHaveLength(1);
    expect(unreadable).toBe(3);
  });
});
