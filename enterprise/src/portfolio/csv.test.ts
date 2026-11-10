// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type { PortfolioProjectRow } from '@qualor/server/plugin-contract';
import { describe, expect, it } from 'vitest';
import { portfolioCsv } from './csv';
import { sampleRow, sampleRows } from './test-overview';

async function* from(rows: PortfolioProjectRow[]): AsyncGenerator<PortfolioProjectRow> {
  for (const row of rows) yield row;
}

async function lines(rows: PortfolioProjectRow[]): Promise<string[]> {
  const out: string[] = [];
  for await (const line of portfolioCsv(from(rows))) out.push(line);
  return out;
}

const HEADER =
  'organization_key,organization,project_key,project,last_analysis_at,abandoned,gate,security_rating,reliability_rating,' +
  'ncloc,coverage,duplication,issues,blocker,high,medium,low,info,new_issues,secrets,' +
  'vulnerable_dependencies,vulnerable_releases,exploited_vulnerabilities\r\n';

describe('portfolioCsv (4E-2 §3)', () => {
  it('starts with a BOM and the header of spec §3', async () => {
    const [head] = await lines([]);
    expect(head).toBe(String.fromCharCode(0xfeff) + HEADER);
  });

  it('writes one line per project, ratings as letters and nulls as empty cells', async () => {
    const out = await lines(sampleRows());
    expect(out).toHaveLength(4);
    expect(out[1]).toBe(
      'platform,Platform team,proj-000,Project 0,2026-10-10T12:00:00.000Z,false,failed,C,A,4000,80.5,2.25,21,1,2,3,10,5,2,1,3,2,1\r\n',
    );
    expect(out[2]).toBe(
      'mobile,Mobile apps,proj-001,Project 1,2026-10-10T12:00:00.000Z,false,passed,A,B,4001,80.5,2.25,3,0,0,1,2,0,2,0,0,0,0\r\n',
    );
    expect(out[3]).toBe('platform,Platform team,proj-002,Project 2,,true,,,,,,,,,,,,,,0,0,,\r\n');
  });

  it('neutralises formulas and quotes with the shared helper', async () => {
    const out = await lines([
      sampleRow(0, {
        project: { id: 'x', key: 'x', name: '=cmd' },
        organization: { key: 'o', name: 'Team "A", Ops' },
      }),
    ]);
    expect(out[1]!.startsWith(`o,"Team ""A"", Ops",x,'=cmd,`)).toBe(true);
  });

  it('streams: a large source is read only as far as the lines taken', async () => {
    let produced = 0;
    async function* many(): AsyncGenerator<PortfolioProjectRow> {
      for (let i = 0; i < 1_000_000; i++) {
        produced += 1;
        yield sampleRow(i);
      }
    }
    const csv = portfolioCsv(many());
    await csv.next();
    await csv.next();
    await csv.next();
    expect(produced).toBeLessThanOrEqual(2);
    await csv.return(undefined);
  });
});
