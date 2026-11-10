// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
// Test-only fixture: never imported from plugin.ts's graph, so never bundled.
import type {
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
  PortfolioTrendPoint,
} from '@qualor/server/plugin-contract';

const GENERATED_AT = '2026-10-13T09:30:00.000Z';

function aggregate(overrides: Partial<PortfolioAggregate> = {}): PortfolioAggregate {
  return {
    projects: 3,
    analysed: 2,
    abandoned: 1,
    gate: { passed: 1, failed: 1, error: 0, none: 1 },
    passedShare: 0.5,
    securityRating: { A: 1, B: 0, C: 1, D: 0, E: 0 },
    reliabilityRating: { A: 2, B: 0, C: 0, D: 0, E: 0 },
    ncloc: 12_345,
    coverage: 71.25,
    duplication: 3.5,
    issues: 42,
    bySeverity: { blocker: 2, high: 5, medium: 10, low: 20, info: 5 },
    securityIssues: 7,
    reliabilityIssues: 9,
    maintainabilityIssues: 26,
    newIssues: 4,
    ...overrides,
  };
}

/** A project row; `i` varies the key so rows stay distinct. */
export function sampleRow(
  i = 0,
  overrides: Partial<PortfolioProjectRow> = {},
): PortfolioProjectRow {
  const key = `proj-${String(i).padStart(3, '0')}`;
  return {
    organization: { key: 'platform', name: 'Platform team' },
    project: {
      id: `00000000-0000-7000-8000-${String(i).padStart(12, '0')}`,
      key,
      name: `Project ${i}`,
    },
    lastAnalysisAt: '2026-10-10T12:00:00.000Z',
    abandoned: false,
    gate: 'failed',
    securityRating: 'C',
    reliabilityRating: 'A',
    ncloc: 4_000 + i,
    coverage: 80.5,
    duplication: 2.25,
    issues: 21,
    bySeverity: { blocker: 1, high: 2, medium: 3, low: 10, info: 5 },
    newIssues: 2,
    secrets: 1,
    vulnerableDependencies: 3,
    vulnerableReleases: 2,
    exploited: 1,
    ...overrides,
  };
}

const passing = (): PortfolioProjectRow =>
  sampleRow(1, {
    organization: { key: 'mobile', name: 'Mobile apps' },
    gate: 'passed',
    securityRating: 'A',
    reliabilityRating: 'B',
    bySeverity: { blocker: 0, high: 0, medium: 1, low: 2, info: 0 },
    issues: 3,
    secrets: 0,
    vulnerableDependencies: 0,
    vulnerableReleases: 0,
    exploited: 0,
  });

const neverAnalysed = (): PortfolioProjectRow =>
  sampleRow(2, {
    lastAnalysisAt: null,
    abandoned: true,
    gate: null,
    securityRating: null,
    reliabilityRating: null,
    ncloc: null,
    coverage: null,
    duplication: null,
    issues: null,
    bySeverity: null,
    newIssues: null,
    secrets: 0,
    vulnerableDependencies: 0,
    vulnerableReleases: null,
    exploited: null,
  });

/** Three fresh rows: a failing project, a passing one in another organisation, a never-analysed. */
export function sampleRows(): PortfolioProjectRow[] {
  return [sampleRow(0), passing(), neverAnalysed()];
}

/** Twelve weekly points from 2026-07-27; the first three have no analysed project (null shares). */
function trend(): PortfolioTrendPoint[] {
  return Array.from({ length: 12 }, (_, i) => {
    const start = new Date(Date.UTC(2026, 6, 27 + 7 * i));
    const end = i === 11 ? new Date(GENERATED_AT) : new Date(start.getTime() + 7 * 86_400_000);
    const empty = i < 3;
    return {
      start: start.toISOString(),
      end: end.toISOString(),
      ...aggregate(
        empty
          ? {
              analysed: 0,
              passedShare: null,
              coverage: null,
              duplication: null,
              ncloc: 0,
              issues: 0,
              gate: { passed: 0, failed: 0, error: 0, none: 3 },
            }
          : { ncloc: 10_000 + 250 * i, issues: 60 - 2 * i, coverage: 60 + i, passedShare: i / 12 },
      ),
      analyses: empty ? 0 : i,
      triage: empty ? 0 : 1,
    };
  });
}

/**
 * A fresh overview. The all scope (the default) has two organisations; the organisation scope
 * has none (`organizations: null`).
 */
export function sampleOverview(kind: 'all' | 'organization' = 'all'): PortfolioOverview {
  return {
    generatedAt: GENERATED_AT,
    scope:
      kind === 'all'
        ? { kind: 'all', organization: null }
        : {
            kind: 'organization',
            organization: {
              id: '00000000-0000-7000-8000-00000000000a',
              key: 'platform',
              name: 'Platform team',
            },
          },
    granularity: 'week',
    totals: {
      ...aggregate(),
      secrets: 1,
      vulnerableDependencies: 3,
      vulnerableReleases: 2,
      exploited: 1,
    },
    organizations:
      kind === 'all'
        ? [
            {
              id: '00000000-0000-7000-8000-00000000000b',
              key: 'mobile',
              name: 'Mobile apps',
              ...aggregate({ projects: 1, analysed: 1, abandoned: 0, ncloc: 4_001 }),
            },
            {
              id: '00000000-0000-7000-8000-00000000000a',
              key: 'platform',
              name: 'Platform team',
              ...aggregate({ projects: 2, analysed: 1, ncloc: 8_344 }),
            },
          ]
        : null,
    trend: trend(),
    attention: {
      exploited: [sampleRow(0)],
      failingGates: [sampleRow(0)],
      worstSecurity: [sampleRow(0)],
      mostSevere: [sampleRow(0)],
      abandoned: [neverAnalysed()],
    },
  };
}
