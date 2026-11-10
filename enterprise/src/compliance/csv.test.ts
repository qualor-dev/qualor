// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { describe, expect, it } from 'vitest';
import { csvCell } from '../csv';
import { csvRows } from './csv';
import { parseCanonical } from './assemble';
import { dependencyReport, sampleReport, sampleReportV1 } from './test-report';

describe('csvRows (4E-1 §2.5)', () => {
  it('starts with a BOM and the header, one column per standard', () => {
    const [head] = csvRows(sampleReport());
    expect(
      head!.startsWith(
        '﻿section,project,path,line,rule,rule_name,engine,severity,kind,cwe,status,in_new_code,first_seen_at,s,triage_by,triage_at,triage_comment,triage_reason,vulnerability_id,fixed_versions,kev_date_added,epss_score,epss_percentile\r\n',
      ),
    ).toBe(true);
  });
  it('writes open findings, then triage rows', () => {
    const lines = [...csvRows(sampleReport())];
    expect(lines[1]).toBe(
      'code,alpha,a.ts,1,semgrep:sqli,SQLi,semgrep,high,issue,89,open,true,2026-01-01T00:00:00.000Z,A;B,,,,,,,,,\r\n',
    );
    expect(lines.at(-1)).toMatch(
      /^code,alpha,c\.ts,3,semgrep:sqli,,,high,,89,false_positive,,,A;B,Ann,2026-05-01T00:00:00\.000Z,"not reachable, see ""ADR-7""",,,,,,\r\n$/,
    );
  });
  it('writes the vulnerability facts and the triage reason, empty when null', () => {
    const lines = [...csvRows(dependencyReport())];
    const d1 = lines.find((l) => l.includes(',d1,') || l.includes('CVE-2026-0001'))!;
    expect(d1.endsWith(',,,,CVE-2026-0001,3.10.2;4.17.21,2026-03-05,0.42,0.973\r\n')).toBe(true);
    const d2 = lines.find((l) => l.includes('CVE-2026-0002'))!;
    expect(d2.endsWith(',,,,CVE-2026-0002,,,,\r\n')).toBe(true);
    const t2 = lines.find((l) => l.includes('false_positive') && l.includes('CVE-2026-0004'))!;
    expect(t2.endsWith(',vulnerable_code_not_in_execute_path,CVE-2026-0004,1.2.6,,,\r\n')).toBe(
      true,
    );
  });
  it('writes a stored version 1 report with the new columns empty', () => {
    const v1 = parseCanonical(Buffer.from(JSON.stringify(sampleReportV1())));
    const lines = [...csvRows(v1)];
    expect(lines).toHaveLength(4);
    expect(lines[1]).toBe(
      'code,alpha,a.ts,1,semgrep:sqli,SQLi,semgrep,high,issue,89,open,true,2026-01-01T00:00:00.000Z,A;B,,,,,,,,,\r\n',
    );
  });
  it('quotes and neutralises formulas (Review Focus 3)', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('+1')).toBe(`'+1`);
    expect(csvCell('-1')).toBe(`'-1`);
    expect(csvCell('@a')).toBe(`'@a`);
    expect(csvCell('\tx')).toBe(`'\tx`);
    expect(csvCell('a\nb')).toBe('"a\nb"');
    expect(csvCell(null)).toBe('');
    expect(csvCell('x'.repeat(10_000))).toHaveLength(10_000);
    expect(csvCell('路径/文件.ts')).toBe('路径/文件.ts');
  });
});
