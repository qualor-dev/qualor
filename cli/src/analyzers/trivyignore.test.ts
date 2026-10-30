import { REPORT_BOUNDS } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { parseTrivyIgnore } from './trivyignore';

describe('parseTrivyIgnore', () => {
  it('skips blank lines and comments, takes the first token as the id', () => {
    const text = '# comment\n\nCVE-2026-1 some note\n  GHSA-abcd-1234  \n';
    expect(parseTrivyIgnore(text)).toEqual({
      entries: [{ id: 'CVE-2026-1' }, { id: 'GHSA-abcd-1234' }],
      truncated: false,
    });
  });

  it('reads exp: anywhere on the line and drops an invalid date', () => {
    const text =
      'CVE-1 exp:2026-12-31\nCVE-2 note exp:2027-01-15\nCVE-3 exp:2026-13-45\nCVE-4 exp:soon\n';
    expect(parseTrivyIgnore(text).entries).toEqual([
      { id: 'CVE-1', expiresAt: '2026-12-31' },
      { id: 'CVE-2', expiresAt: '2027-01-15' },
      { id: 'CVE-3' },
      { id: 'CVE-4' },
    ]);
  });

  it('handles CRLF', () => {
    expect(parseTrivyIgnore('CVE-1 exp:2026-12-31\r\nCVE-2\r\n').entries).toEqual([
      { id: 'CVE-1', expiresAt: '2026-12-31' },
      { id: 'CVE-2' },
    ]);
  });

  it('keeps a duplicate id once, with the latest valid expiry', () => {
    const text =
      'CVE-1 exp:2026-06-01\nCVE-1 exp:2026-12-31\nCVE-1 exp:2026-03-01\nCVE-1 exp:bad\n';
    expect(parseTrivyIgnore(text).entries).toEqual([{ id: 'CVE-1', expiresAt: '2026-12-31' }]);
  });

  it('skips ids longer than the rule id bound', () => {
    const long = 'x'.repeat(REPORT_BOUNDS.ruleIdChars + 1);
    expect(parseTrivyIgnore(`${long}\nCVE-1\n`).entries).toEqual([{ id: 'CVE-1' }]);
  });

  it('cuts at the entry bound and says so', () => {
    const n = REPORT_BOUNDS.dependencyIgnores;
    const text = Array.from({ length: n + 5 }, (_, i) => `CVE-${i}`).join('\n');
    const r = parseTrivyIgnore(text);
    expect(r.entries).toHaveLength(n);
    expect(r.truncated).toBe(true);
    expect(parseTrivyIgnore('CVE-1').truncated).toBe(false);
  });
});
