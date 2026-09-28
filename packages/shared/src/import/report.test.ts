import { describe, expect, it } from 'vitest';
import { importReportSchema } from './report';

const minimal = {
  format: 'qualor-import-report',
  version: 1,
  source: {
    kind: 'sonarqube',
    edition: 'server',
    origin: 'https://sonar.example.com',
    organization: null,
    version: '10.7.0.96327',
  },
  dryRun: true,
  startedAt: '2026-09-25T10:00:00.000Z',
  finishedAt: '2026-09-25T10:01:00.000Z',
  organization: { id: '0192f7a0-0000-7000-8000-000000000001', key: 'default' },
  profiles: [],
  gates: [],
  projects: [],
  warnings: [{ code: 'SONARQUBE_ISSUE_WINDOW', message: '12 issues were not read' }],
  aborted: null,
};

const condition = (over: Record<string, unknown> = {}) => ({
  metric: 'open_issues',
  op: 'GT',
  error: '5',
  outcome: 'unmapped',
  qualor: null,
  approximate: false,
  reason: 'duplicate_metric',
  qualorMetric: 'issues',
  ...over,
});
const withCondition = (c: Record<string, unknown>) => ({
  ...minimal,
  gates: [
    {
      name: 'Mixed',
      outcome: 'would_create',
      reason: null,
      qualorGateId: null,
      defaultChange: null,
      conditions: [c],
    },
  ],
});

describe('importReportSchema (import-sonarqube.md §12.2)', () => {
  it('accepts a minimal report', () => {
    expect(importReportSchema.safeParse(minimal).success).toBe(true);
  });

  it('takes a report marked aborted with its reason, and requires the mark (ruling S13)', () => {
    const aborted = { ...minimal, aborted: { reason: 'SonarQube refused the token (401)' } };
    expect(importReportSchema.safeParse(aborted).success).toBe(true);
    expect(importReportSchema.safeParse({ ...minimal, aborted: { reason: '' } }).success).toBe(
      false,
    );
    const unmarked = Object.fromEntries(Object.entries(minimal).filter(([k]) => k !== 'aborted'));
    expect(importReportSchema.safeParse(unmarked).success).toBe(false);
  });

  it('refuses unknown fields and unknown warning codes', () => {
    expect(importReportSchema.safeParse({ ...minimal, token: 'x' }).success).toBe(false);
    expect(
      importReportSchema.safeParse({ ...minimal, warnings: [{ code: 'NOPE', message: 'm' }] })
        .success,
    ).toBe(false);
  });

  it('names why a condition is unmapped, and the Qualor metric a collision lost on', () => {
    for (const reason of ['metric', 'operator', 'threshold', 'threshold_out_of_range']) {
      expect(
        importReportSchema.safeParse(withCondition(condition({ reason, qualorMetric: null })))
          .success,
      ).toBe(true);
      // Only a collision names a Qualor metric.
      expect(importReportSchema.safeParse(withCondition(condition({ reason }))).success).toBe(
        false,
      );
    }
    for (const reason of ['duplicate_metric', 'operator_conflict']) {
      expect(importReportSchema.safeParse(withCondition(condition({ reason }))).success).toBe(true);
      expect(
        importReportSchema.safeParse(withCondition(condition({ reason, qualorMetric: null })))
          .success,
      ).toBe(false);
    }
    expect(
      importReportSchema.safeParse(withCondition(condition({ reason: 'other' }))).success,
    ).toBe(false);
  });

  it('takes a condition as mapped or unmapped, never a mix of both (a discriminated union)', () => {
    const mapped = {
      metric: 'open_issues',
      op: 'GT',
      error: '5',
      outcome: 'mapped',
      qualor: { metric: 'issues', operator: 'gt', threshold: 5 },
      approximate: true,
      reason: null,
    };
    const ok = (c: Record<string, unknown>) =>
      importReportSchema.safeParse(withCondition(c)).success;
    expect(ok(mapped)).toBe(true);
    expect(ok({ ...mapped, reason: 'metric' })).toBe(false);
    expect(ok({ ...mapped, qualor: null })).toBe(false);
    expect(ok({ ...mapped, qualorMetric: null })).toBe(false);
    expect(ok(condition({ qualor: { metric: 'issues', operator: 'gt', threshold: 5 } }))).toBe(
      false,
    );
    expect(ok(condition({ reason: null }))).toBe(false);
    expect(ok(condition({ approximate: true }))).toBe(false);
  });

  it('keeps only the origin and path of the SonarQube URL', () => {
    const at = (origin: string) =>
      importReportSchema.safeParse({ ...minimal, source: { ...minimal.source, origin } }).success;
    expect(at('https://sonar.example.com')).toBe(true);
    expect(at('http://127.0.0.1:9000/sonarqube')).toBe(true);
    for (const bad of [
      'https://user:pass@sonar.example.com',
      'https://token@sonar.example.com',
      'https://sonar.example.com/?token=x',
      'https://sonar.example.com/#frag',
      'https://sonar.example.com/?',
      'ftp://sonar.example.com',
      'not a url',
      `https://sonar.example.com/${'x'.repeat(2048)}`,
    ]) {
      expect(at(bad), bad).toBe(false);
    }
  });

  it('bounds its strings and lists, and an item line starts at 1', () => {
    const project = (issues: Record<string, unknown>) => ({
      ...minimal,
      projects: [
        {
          key: 'acme:shop',
          outcome: 'found',
          reason: null,
          qualorProjectId: null,
          profiles: [],
          gate: null,
          issues: {
            outcome: 'done',
            read: 1,
            applied: 0,
            wouldApply: 0,
            alreadySet: 0,
            conflict: 0,
            unmatched: 1,
            ambiguous: 0,
            competitorsUnknown: 0,
            notSent: 0,
            changed: 0,
            failed: 0,
            unmappedRule: 0,
            pathInvalid: 0,
            invalid: 0,
            notRead: 0,
            hotspotsNotImported: 0,
            unmappedRules: [],
            items: [
              {
                sonarKey: 'AYi-1',
                rule: 'typescript:S1440',
                path: 'src/a.ts',
                line: 1,
                outcome: 'unmatched',
                qualorIssueId: null,
                ...issues,
              },
            ],
          },
        },
      ],
    });
    const ok = (r: unknown) => importReportSchema.safeParse(r).success;
    expect(ok(project({}))).toBe(true);
    expect(ok(project({ line: null }))).toBe(true);
    expect(ok(project({ line: 0 }))).toBe(false);
    expect(ok(project({ line: 10_000_001 }))).toBe(false);
    expect(ok(project({ path: 'a'.repeat(1025) }))).toBe(false);
    expect(ok(project({ rule: 'x'.repeat(1025) }))).toBe(false);
    expect(ok(project({ sonarKey: 'k'.repeat(101) }))).toBe(false);
    const profile = {
      sonarKey: 'p1',
      name: 'Team TS',
      sonarLanguage: 'ts',
      language: 'typescript',
      outcome: 'skipped',
      reason: null,
      qualorProfileId: null,
      defaultChange: null,
      rules: {
        active: 0,
        mapped: 0,
        deactivated: 0,
        severityOverrides: 0,
        pendingReview: [],
        statusOnly: [],
        unmapped: [],
        unmappedCount: 0,
        parametersNotImported: [],
      },
    };
    expect(ok({ ...minimal, profiles: [profile] })).toBe(true);
    expect(ok({ ...minimal, profiles: [{ ...profile, name: 'n'.repeat(1001) }] })).toBe(false);
    expect(
      ok({
        ...minimal,
        profiles: [
          {
            ...profile,
            rules: { ...profile.rules, pendingReview: Array.from({ length: 10_001 }, () => 'k:r') },
          },
        ],
      }),
    ).toBe(false);
    expect(
      ok({
        ...minimal,
        warnings: Array.from({ length: 100_001 }, () => ({
          code: 'SONARQUBE_ISSUE_WINDOW',
          message: 'm',
        })),
      }),
    ).toBe(false);
  });
});
