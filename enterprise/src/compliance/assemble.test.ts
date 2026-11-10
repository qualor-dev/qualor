// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ComplianceSource } from '@qualor/server/plugin-contract';
import { assembleReport, categoriesOf, parseCanonical } from './assemble';
import type { StandardData } from './standard';
import { sampleReportV1 } from './test-report';

const STD: StandardData = {
  id: 's',
  family: 'owasp-top10',
  version: '1',
  title: 'S',
  source: 'src',
  licence: 'L',
  sourceSha256: '0'.repeat(64),
  categories: [
    { id: 'A', title: 'Injection', cwe: [89, 78] },
    { id: 'B', title: 'Secrets', cwe: [798, 89] },
    { id: 'H', title: 'High', cwe: [], severities: ['blocker', 'high'] },
  ],
};

const source = (over: Partial<ComplianceSource> = {}): ComplianceSource => ({
  generatedAt: '2026-10-12T10:00:00.000Z',
  createdBy: 'Ann',
  scope: {
    kind: 'project',
    organization: { id: 'o', key: 'acme', name: 'Acme' },
    project: { id: 'p', key: 'alpha', name: 'Alpha' },
    branch: { id: 'b', name: 'main' },
    version: null,
  },
  projects: [
    {
      id: 'p',
      key: 'alpha',
      name: 'Alpha',
      branch: { id: 'b', name: 'main' },
      analysis: null,
      gate: null,
      trend: [],
    },
  ],
  groups: [
    {
      status: 'open',
      section: 'code',
      rule: 'semgrep:sqli',
      severity: 'high',
      kind: 'issue',
      inNewCode: true,
      cwe: [89],
      count: 2,
      oldestFirstSeenAt: '2026-01-01T00:00:00.000Z',
    },
    {
      status: 'open',
      section: 'secret',
      rule: 'gitleaks:aws',
      severity: 'blocker',
      kind: 'issue',
      inNewCode: false,
      cwe: [798],
      count: 1,
      oldestFirstSeenAt: '2026-02-01T00:00:00.000Z',
    },
    {
      status: 'open',
      section: 'code',
      rule: 'x:hot',
      severity: 'low',
      kind: 'hotspot',
      inNewCode: false,
      cwe: [],
      count: 3,
      oldestFirstSeenAt: '2026-03-01T00:00:00.000Z',
    },
    {
      status: 'false_positive',
      section: 'code',
      rule: 'semgrep:sqli',
      severity: 'high',
      kind: 'issue',
      inNewCode: false,
      cwe: [89],
      count: 1,
      oldestFirstSeenAt: '2026-01-01T00:00:00.000Z',
    },
  ],
  findings: [
    {
      id: 'f1',
      project: 'alpha',
      path: 'a.ts',
      line: 1,
      rule: 'semgrep:sqli',
      ruleName: 'SQLi',
      engine: 'semgrep',
      severity: 'high',
      kind: 'issue',
      cwe: [89],
      message: 'm',
      inNewCode: true,
      firstSeenAt: '2026-01-01T00:00:00.000Z',
      section: 'code',
      vulnerability: null,
    },
    {
      id: 'f2',
      project: 'alpha',
      path: 'b.ts',
      line: 2,
      rule: 'semgrep:sqli',
      ruleName: 'SQLi',
      engine: 'semgrep',
      severity: 'high',
      kind: 'issue',
      cwe: [89],
      message: 'm',
      inNewCode: true,
      firstSeenAt: '2026-01-02T00:00:00.000Z',
      section: 'code',
      vulnerability: null,
    },
    {
      id: 'f3',
      project: 'alpha',
      path: 'package-lock.json',
      line: null,
      rule: 'trivy:CVE-2026-0001',
      ruleName: 'lodash',
      engine: 'trivy',
      severity: 'high',
      kind: 'issue',
      cwe: [],
      message: 'm',
      inNewCode: false,
      firstSeenAt: '2026-01-03T00:00:00.000Z',
      section: 'dependency',
      vulnerability: {
        epss: { percentile: 0.97, score: 0.4 },
        kev: { dateAdded: '2026-03-05' },
        fixedVersions: ['4.17.21'],
        packageName: 'lodash',
        id: 'CVE-2026-0001',
      },
    },
  ],
  triage: [
    {
      id: 't1',
      project: 'alpha',
      path: 'c.ts',
      line: 3,
      rule: 'semgrep:sqli',
      severity: 'low',
      cwe: [798],
      status: 'false_positive',
      section: 'code',
      by: 'Bob',
      at: '2026-02-02T00:00:00.000Z',
      comment: 'ok',
      reason: 'component_not_present',
      vulnerability: null,
    },
  ],
  datasets: {
    vulnerabilityDatabase: { builtAt: '2026-10-11T06:00:00.000Z', digest: 'sha256:db' },
    kev: { refreshedAt: '2026-10-12T05:00:00.000Z', digest: 'sha256:kev' },
    epss: {
      dataDate: '2026-10-11',
      refreshedAt: '2026-10-12T05:30:00.000Z',
      digest: 'sha256:epss',
    },
  },
  ...over,
});

describe('assembleReport (4E-1 §2.2, §2.3)', () => {
  it('maps a finding to every matching category, severities included', () => {
    expect(categoriesOf(STD, [89], 'high')).toEqual(['A', 'B', 'H']);
    expect(categoriesOf(STD, [], 'low')).toEqual([]);
  });

  it('counts categories from the groups: multi-category, not mapped, rules, oldest', () => {
    const { summary } = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.8.0',
      source: source(),
      standards: [STD],
    });
    const s = summary.standards[0]!;
    expect(s.categories.find((c) => c.id === 'A')).toMatchObject({
      open: 2,
      inNewCode: 2,
      rules: 1,
      oldestFirstSeenAt: '2026-01-01T00:00:00.000Z',
    });
    expect(s.categories.find((c) => c.id === 'B')!.open).toBe(3); // sqli 2 + secret 1
    expect(s.categories.find((c) => c.id === 'H')!.open).toBe(3); // high 2 + blocker 1
    expect(s.notMapped).toMatchObject({ open: 3, rules: 1 });
    expect(s.distinctTotal).toBe(6);
    expect(summary.findings).toEqual({
      total: 6,
      bySeverity: { blocker: 1, high: 2, medium: 0, low: 3, info: 0 },
      inNewCode: 2,
    });
    expect(summary.secrets.open).toBe(1);
    expect(summary.triage).toEqual({ falsePositive: 1, wontFix: 0 });
    expect(summary.truncated).toBe(false);
  });

  it('truncates the detail lists, keeps exact counts, and flags it', () => {
    const { json, summary } = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.8.0',
      source: source(),
      standards: [STD],
      limit: 1,
    });
    expect(json.findings).toHaveLength(1);
    expect(summary.truncated).toBe(true);
    expect(summary.findings.total).toBe(6);
  });

  it('writes canonical bytes: stable, schema key order, sha256 of the bytes', () => {
    const a = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.8.0',
      source: source(),
      standards: [STD],
    });
    const b = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.8.0',
      source: source(),
      standards: [STD],
    });
    expect(a.canonical.equals(b.canonical)).toBe(true);
    expect(a.sha256).toBe(createHash('sha256').update(a.canonical).digest('hex'));
    expect(Object.keys(JSON.parse(a.canonical.toString('utf8')))).toEqual([
      'schemaVersion',
      'id',
      'generatedAt',
      'generatedBy',
      'server',
      'scope',
      'standards',
      'datasets',
      'projects',
      'summary',
      'findings',
      'triage',
    ]);
    expect(a.canonical.toString('utf8')).not.toMatch(/\n/);
    expect(parseCanonical(a.canonical)).toEqual(a.json);
    expect(a.json.findings[0]!.categories).toEqual({ s: ['A', 'B', 'H'] });
    // R2: triage entries carry computed categories, in spec key order
    expect(a.json.triage[0]!.categories).toEqual({ s: ['B'] });
    expect(Object.keys(a.json.triage[0]!)).toEqual([
      'id',
      'project',
      'path',
      'line',
      'rule',
      'severity',
      'cwe',
      'categories',
      'status',
      'section',
      'by',
      'at',
      'comment',
      'reason',
      'vulnerability',
    ]);
  });

  it('writes schema 2 with the vulnerability facts, reasons and dataset dates', () => {
    const { json } = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.15.0',
      source: source(),
      standards: [STD],
    });
    expect(json.schemaVersion).toBe(2);
    expect(json.datasets).toEqual(source().datasets);
    expect(json.findings[2]!.vulnerability).toEqual({
      id: 'CVE-2026-0001',
      packageName: 'lodash',
      fixedVersions: ['4.17.21'],
      kev: { dateAdded: '2026-03-05' },
      epss: { score: 0.4, percentile: 0.97 },
    });
    expect(Object.keys(json.findings[2]!.vulnerability!)).toEqual([
      'id',
      'packageName',
      'fixedVersions',
      'kev',
      'epss',
    ]);
    expect(json.triage[0]!.reason).toBe('component_not_present');
  });

  it('keeps a dataset without a build time as null', () => {
    const { json } = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.15.0',
      source: source({
        datasets: {
          vulnerabilityDatabase: { builtAt: null, digest: 'sha256:db' },
          kev: null,
          epss: null,
        },
      }),
      standards: [STD],
    });
    expect(json.datasets.vulnerabilityDatabase).toEqual({ builtAt: null, digest: 'sha256:db' });
  });

  it('writes the version after the branch, and null for a branch report', () => {
    const version = { id: 'v', label: '2.0.0' };
    const make = (scope: Partial<ComplianceSource['scope']>) =>
      assembleReport({
        id: 'r',
        generatedBy: 'Ann',
        serverVersion: '0.15.0',
        source: source({ scope: { ...source().scope, ...scope } }),
        standards: [STD],
      }).json.scope;
    const forVersion = make({ branch: null, version });
    expect(Object.keys(forVersion)).toEqual([
      'kind',
      'organization',
      'project',
      'branch',
      'version',
    ]);
    expect(forVersion).toMatchObject({ branch: null, version });
    expect(make({}).version).toBeNull();
  });

  it('reads schema 1 and 2 and refuses any other', () => {
    const a = assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.15.0',
      source: source(),
      standards: [STD],
    });
    expect(parseCanonical(a.canonical).schemaVersion).toBe(2);
    const v1 = parseCanonical(Buffer.from(JSON.stringify(sampleReportV1())));
    expect(v1.schemaVersion).toBe(1);
    expect(v1.datasets).toEqual({ vulnerabilityDatabase: null, kev: null, epss: null });
    expect(v1.scope.version).toBeNull();
    expect(v1.findings.every((f) => f.vulnerability === null)).toBe(true);
    expect(v1.triage.every((t) => t.reason === null && t.vulnerability === null)).toBe(true);
    expect(() => parseCanonical(Buffer.from('{"schemaVersion":3}'))).toThrow(
      'unsupported report schema version',
    );
  });

  const richProjects = (reversed: boolean): ComplianceSource['projects'] => {
    const analysis = {
      id: 'an1',
      date: '2026-10-11T00:00:00.000Z',
      revision: 'abc',
      versionLabel: '1.0',
    };
    const cond = { metric: 'security_issues', op: 'gt' as const, threshold: 0, actual: 2 };
    const trend = {
      analysisId: 'an1',
      date: '2026-10-11T00:00:00.000Z',
      security_issues: 2,
      security_rating: 3,
    };
    const rev = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).reverse()) as T;
    const make = <T extends object>(o: T): T => (reversed ? rev(o) : o);
    return [
      {
        id: 'p',
        key: 'alpha',
        name: 'Alpha',
        branch: { id: 'b', name: 'main' },
        analysis: make(analysis),
        gate: make({ status: 'failed' as const, failedConditions: [make(cond)] }),
        trend: [make(trend)],
      },
    ];
  };
  const build = (reversed: boolean) =>
    assembleReport({
      id: 'r',
      generatedBy: 'Ann',
      serverVersion: '0.8.0',
      source: source({
        projects: richProjects(reversed),
        scope: { ...source().scope, version: { label: '1.0', id: 'v' } },
      }),
      standards: [STD],
    });

  it('is independent of the key order of the input (analysis, gate, trend)', () => {
    expect(build(true).canonical.equals(build(false).canonical)).toBe(true);
  });

  it('writes every nested object in the key order of spec 2.3', () => {
    const shape = (v: unknown): unknown => {
      if (Array.isArray(v)) return v.length > 0 ? [shape(v[0])] : [];
      if (v !== null && typeof v === 'object')
        return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shape(x)]));
      return null;
    };
    const sev = { blocker: null, high: null, medium: null, low: null, info: null };
    const expected = {
      schemaVersion: null,
      id: null,
      generatedAt: null,
      generatedBy: null,
      server: { version: null },
      scope: {
        kind: null,
        organization: { id: null, name: null },
        project: { id: null, key: null, name: null },
        branch: { id: null, name: null },
        version: { id: null, label: null },
      },
      standards: [
        { id: null, version: null, title: null, source: null, licence: null, sourceSha256: null },
      ],
      datasets: {
        vulnerabilityDatabase: { builtAt: null, digest: null },
        kev: { refreshedAt: null, digest: null },
        epss: { dataDate: null, refreshedAt: null, digest: null },
      },
      projects: [
        {
          id: null,
          key: null,
          name: null,
          branch: null,
          analysis: { id: null, date: null, revision: null, versionLabel: null },
          gate: {
            status: null,
            failedConditions: [{ metric: null, op: null, threshold: null, actual: null }],
          },
          trend: [{ analysisId: null, date: null, security_issues: null, security_rating: null }],
        },
      ],
      summary: {
        findings: { total: null, bySeverity: sev, inNewCode: null },
        standards: [
          {
            id: null,
            categories: [
              {
                id: null,
                title: null,
                open: null,
                bySeverity: sev,
                inNewCode: null,
                rules: null,
                oldestFirstSeenAt: null,
              },
            ],
            notMapped: { open: null, bySeverity: sev, inNewCode: null, rules: null },
            distinctTotal: null,
          },
        ],
        secrets: { open: null },
        dependencies: { open: null, bySeverity: sev },
        triage: { falsePositive: null, wontFix: null },
        truncated: null,
      },
      findings: [
        {
          id: null,
          project: null,
          path: null,
          line: null,
          rule: null,
          ruleName: null,
          engine: null,
          severity: null,
          kind: null,
          cwe: [null],
          message: null,
          categories: { s: [null] },
          inNewCode: null,
          firstSeenAt: null,
          section: null,
          vulnerability: null,
        },
      ],
      triage: [
        {
          id: null,
          project: null,
          path: null,
          line: null,
          rule: null,
          severity: null,
          cwe: [null],
          categories: { s: [null] },
          status: null,
          section: null,
          by: null,
          at: null,
          comment: null,
          reason: null,
          vulnerability: null,
        },
      ],
    };
    const parsed: unknown = JSON.parse(build(true).canonical.toString('utf8'));
    expect(JSON.stringify(shape(parsed))).toBe(JSON.stringify(expected));
  });
});
