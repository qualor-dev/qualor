import { describe, expect, it } from 'vitest';
import {
  QUALOR_KIND_PROPERTY,
  QUALOR_SEVERITY_PROPERTY,
  qualorManifestSchema,
  qualorRuleId,
  qualorRuleMeta,
} from './qualor';

const entry = (over: Record<string, unknown> = {}) => ({
  id: 'java/sql-injection',
  path: 'rules/java/sql/sql-injection.yml',
  sha256: 'a'.repeat(64),
  languages: ['java'],
  kind: 'issue',
  severity: 'high',
  cwe: ['CWE-89'],
  title: 'A synthetic rule',
  ...over,
});
const manifest = (over: Record<string, unknown> = {}) => ({
  version: '2026.10.0',
  opengrep: '1.30.0',
  rules: [entry()],
  ...over,
});

describe('qualor rule ids (plan 6B-1)', () => {
  it('maps the OpenGrep id <lang>.<name> to the Qualor id <lang>/<name>', () => {
    expect(qualorRuleId('java.sql-injection')).toBe('java/sql-injection');
    expect(qualorRuleId('js.open-redirect')).toBe('js/open-redirect');
    expect(qualorRuleId('go.ssrf')).toBe('go/ssrf');
  });

  it('answers null for anything else', () => {
    for (const id of [
      'ruby.sql-injection',
      'java/sql-injection',
      'java.',
      'java.Sql',
      'java.a.b',
      '',
      '__proto__',
    ]) {
      expect(qualorRuleId(id), id).toBeNull();
    }
  });
});

describe('qualorManifestSchema (plan 6B-1)', () => {
  it('accepts a pack manifest, and keeps every field a newer pack adds', () => {
    const parsed = qualorManifestSchema.parse(
      manifest({ released: '2026-10-03', rules: [entry({ frameworks: ['jdbc'] })] }),
    );
    expect(parsed).toMatchObject({
      version: '2026.10.0',
      opengrep: '1.30.0',
      released: '2026-10-03',
    });
    expect(parsed.rules[0]).toEqual(entry({ frameworks: ['jdbc'] }));
  });

  it('refuses what the CLI could not trust', () => {
    const bad = [
      manifest({ version: '2026.01.0' }),
      manifest({ version: '2026.13.0' }),
      // Over-long parts: a patch has at most 6 digits, the year exactly 4.
      manifest({ version: '2026.10.1234567' }),
      manifest({ version: '20260.10.0' }),
      manifest({ opengrep: 'latest' }),
      manifest({ rules: [] }),
      manifest({ rules: [entry({ id: 'java.sql-injection' })] }),
      manifest({ rules: [entry({ path: 'rules/java/sql/other.yml' })] }),
      manifest({ rules: [entry({ path: 'rules/python/sql/sql-injection.yml' })] }),
      manifest({ rules: [entry({ path: '../rules/java/sql/sql-injection.yml' })] }),
      manifest({ rules: [entry({ sha256: 'A'.repeat(64) })] }),
      manifest({ rules: [entry({ kind: 'bug' })] }),
      manifest({ rules: [entry({ severity: 'critical' })] }),
      manifest({ rules: [entry({ cwe: ['89'] })] }),
      manifest({ rules: [entry({ title: '' })] }),
      manifest({ rules: [entry(), entry()] }),
    ];
    for (const m of bad) {
      expect(qualorManifestSchema.safeParse(m).success, JSON.stringify(m)).toBe(false);
    }
  });
});

describe('qualorRuleMeta (report-format.md §7.1, plan 6B-1)', () => {
  it('reads the kind and severity the CLI copied from the manifest', () => {
    expect(
      qualorRuleMeta({ [QUALOR_KIND_PROPERTY]: 'hotspot', [QUALOR_SEVERITY_PROPERTY]: 'low' }),
    ).toEqual({ kind: 'hotspot', severity: 'low' });
  });

  it('falls back to issue/medium for missing or invalid values, and never throws', () => {
    for (const p of [
      undefined,
      {},
      { qualorKind: 'bug', qualorSeverity: 'critical' },
      { qualorKind: 1 },
      { kind: 'hotspot' },
    ]) {
      expect(qualorRuleMeta(p), JSON.stringify(p)).toEqual({ kind: 'issue', severity: 'medium' });
    }
  });
});
