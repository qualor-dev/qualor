import { randomBytes } from 'node:crypto';
import { and, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { grantProject, rbacContext } from '../../test/rbac';
import { createDatabase } from '../db/client';
import { seedTargetRow } from '../../test/vulnerabilities';
import {
  analyses,
  branches,
  issueChanges,
  measures,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  vulnerabilityKev,
} from '../db/schema';
import type {
  PluginPortfolio,
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
  QualorPlugin,
} from '../plugins/contract';
import { createPortfolioService, readSnapshot } from './service';

/** A Wednesday: the last week bucket starts Monday 2026-10-12, the last month 2026-10-01. */
const NOW = new Date('2026-10-14T12:00:00.000Z');
const LICENSED = new Date('2027-01-01T00:00:00Z');

/** A uuid v7 at exactly `iso` (uuidv7() never goes back in time, so it cannot seed the past). */
function idAt(iso: string): string {
  const hex = Date.parse(iso).toString(16).padStart(12, '0');
  const r = randomBytes(10).toString('hex');
  const variant = ((Number.parseInt(r[3]!, 16) & 3) | 8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8)}-7${r.slice(0, 3)}-${variant}${r.slice(4, 7)}-${r.slice(8, 20)}`;
}

/** The service on the fixed clock; the plugin's context holds the one on the transaction's. */
let fixed: PluginPortfolio;

type Query = {
  scope?: string;
  organizationId?: string;
  granularity?: string;
  sort?: string;
  cursor?: string;
  limit?: string;
};
const inputOf = (q: Query) =>
  (q.scope === 'organization'
    ? { scope: 'organization', organizationId: q.organizationId }
    : { scope: 'all' }) as never;

const FIXTURE: QualorPlugin = {
  name: 'portfolio-fixture',
  apiVersion: 1,
  features: ['portfolio'],
  register(ctx) {
    ctx.routes('portfolio', async (app) => {
      app.get('/t/portfolio', async (req) => {
        const q = req.query as Query;
        return ctx.portfolio.overview(req, inputOf(q), {
          granularity: (q.granularity ?? 'week') as never,
        });
      });
      app.get('/t/portfolio/fixed', async (req) => {
        const q = req.query as Query;
        return fixed.overview(req, inputOf(q), {
          granularity: (q.granularity ?? 'week') as never,
        });
      });
      app.get('/t/portfolio/projects', async (req) => {
        const q = req.query as Query;
        return fixed.projects(req, inputOf(q), {
          sort: (q.sort ?? 'key') as never,
          ...(q.cursor === undefined ? {} : { cursor: q.cursor }),
          limit: Number(q.limit ?? '50'),
        });
      });
      app.get('/t/portfolio/export', async (req) => {
        const rows: PortfolioProjectRow[] = [];
        for await (const row of fixed.exportRows(req, inputOf(req.query as Query))) rows.push(row);
        return rows;
      });
    });
  },
};

const EMPTY: PortfolioAggregate = {
  projects: 0,
  analysed: 0,
  abandoned: 0,
  gate: { passed: 0, failed: 0, error: 0, none: 0 },
  passedShare: null,
  securityRating: { A: 0, B: 0, C: 0, D: 0, E: 0 },
  reliabilityRating: { A: 0, B: 0, C: 0, D: 0, E: 0 },
  ncloc: 0,
  coverage: null,
  duplication: null,
  issues: 0,
  bySeverity: { blocker: 0, high: 0, medium: 0, low: 0, info: 0 },
  securityIssues: 0,
  reliabilityIssues: 0,
  maintainabilityIssues: 0,
  newIssues: 0,
};

const WEEK_STARTS = [
  '2026-07-27',
  '2026-08-03',
  '2026-08-10',
  '2026-08-17',
  '2026-08-24',
  '2026-08-31',
  '2026-09-07',
  '2026-09-14',
  '2026-09-21',
  '2026-09-28',
  '2026-10-05',
  '2026-10-12',
].map((d) => `${d}T00:00:00.000Z`);

describe('ctx.portfolio overview (4E-2 §1, §2)', () => {
  let ctx: TestContext;
  let root: Session;
  let member: Session;
  let grantOnly: Session;
  let outsider: Session;
  let east: string;
  let north: string;
  const ids: Record<string, string> = {};

  const overview = async (
    session: Session,
    query: Query,
    path = '/fixed',
  ): Promise<{ status: number; body: PortfolioOverview & { code?: string } }> => {
    const qs = new URLSearchParams(query as Record<string, string>).toString();
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/ee/t/portfolio${path}?${qs}`,
      headers: session.headers,
    });
    return { status: res.statusCode, body: res.json() };
  };

  /** Measures of an analysis: overall keys, and `new_issues` stored as (`issues`, `new`). */
  const measure = async (analysisId: string, values: Record<string, number>) => {
    await ctx.db
      .insert(measures)
      .values(
        Object.entries(values).map(([key, value]) =>
          key === 'new_issues'
            ? { analysisId, metricKey: 'issues', scope: 'new' as const, value }
            : { analysisId, metricKey: key, scope: 'overall' as const, value },
        ),
      );
  };

  const analysis = async (
    projectId: string,
    branchId: string,
    at: string,
    status: 'succeeded' | 'failed' | 'queued',
    gateStatus: 'passed' | 'failed' | 'error' | 'none' | null = null,
  ): Promise<string> => {
    const id = idAt(at);
    await ctx.db.insert(analyses).values({
      id,
      projectId,
      branchId,
      status,
      revision: 'a'.repeat(40),
      baselineStatus: 'ok',
      scannerVersion: '1.0.0',
      analysisDate: new Date(at),
      gateStatus,
    });
    return id;
  };

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => LICENSED, features: ['portfolio'], plugin: FIXTURE });
    fixed = createPortfolioService({ db: ctx.db, isFeatureActive: () => true, now: () => NOW });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    const newOrg = async (key: string) => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: root.headers,
        payload: { key, name: `${key} team` },
      });
      expect(res.statusCode).toBe(201);
      return (res.json() as { id: string }).id;
    };
    // Created out of key order, so the all scope's sort by key shows.
    north = await newOrg('north');
    east = await newOrg('east');
    for (const [key, org] of [
      ['alpha', east],
      ['beta', east],
      ['gamma', east],
      ['delta', east],
      ['omega', north],
      // Upper case sorts before lower case in code-unit order (R5).
      ['Zulu', north],
    ] as const) {
      ids[key] = (await createProject(ctx, root, { organizationId: org, key })).id;
    }
    // Every project exists from the start of the year, except Zulu: created in week 6 (R4).
    await ctx.db.update(projects).set({ createdAt: new Date('2026-01-01T00:00:00Z') });
    await ctx.db
      .update(projects)
      .set({ createdAt: new Date('2026-09-01T00:00:00Z') })
      .where(eq(projects.id, ids.Zulu!));
    const main = async (key: string) => mainBranchId(ctx.db, ids[key]!);

    // alpha: a1 at exactly Monday 2026-09-28 00:00:00.000Z (gate failed), a2 on 2026-10-13.
    const alphaMain = await main('alpha');
    const a1 = await analysis(
      ids.alpha!,
      alphaMain,
      '2026-09-28T00:00:00.000Z',
      'succeeded',
      'failed',
    );
    await measure(a1, {
      ncloc: 1000,
      coverage: 50,
      duplicated_lines_density: 10,
      security_rating: 3,
      reliability_rating: 2,
      issues: 20,
      blocker_issues: 1,
      high_issues: 2,
      medium_issues: 3,
      low_issues: 4,
      info_issues: 10,
      security_issues: 5,
      reliability_issues: 6,
      maintainability_issues: 9,
      new_issues: 4,
    });
    const a2 = await analysis(
      ids.alpha!,
      alphaMain,
      '2026-10-13T09:00:00.000Z',
      'succeeded',
      'passed',
    );
    await measure(a2, {
      ncloc: 1200,
      coverage: 80,
      duplicated_lines_density: 5,
      security_rating: 1,
      reliability_rating: 2,
      issues: 10,
      blocker_issues: 0,
      high_issues: 1,
      medium_issues: 2,
      low_issues: 3,
      info_issues: 4,
      security_issues: 1,
      reliability_issues: 2,
      maintainability_issues: 7,
      new_issues: 2,
    });
    // Neither a failed nor a queued analysis sets the state.
    const failed = await analysis(ids.alpha!, alphaMain, '2026-10-14T10:00:00.000Z', 'failed');
    await measure(failed, { ncloc: 999_999, security_rating: 5 });
    await analysis(ids.alpha!, alphaMain, '2026-10-14T11:00:00.000Z', 'queued');
    // A branch that is not main: counts as activity, never as state.
    const [feature] = await ctx.db
      .insert(branches)
      .values({ projectId: ids.alpha!, kind: 'branch', name: 'feature' })
      .returning({ id: branches.id });
    const side = await analysis(
      ids.alpha!,
      feature!.id,
      '2026-10-14T11:30:00.000Z',
      'succeeded',
      'failed',
    );
    await measure(side, { ncloc: 777_777, security_rating: 5, blocker_issues: 50 });

    // beta: abandoned, last analysed 40 days before NOW; no coverage, no new_issues.
    const betaMain = await main('beta');
    const b1 = await analysis(
      ids.beta!,
      betaMain,
      '2026-09-04T12:00:00.000Z',
      'succeeded',
      'failed',
    );
    await measure(b1, {
      ncloc: 3000,
      duplicated_lines_density: 20,
      security_rating: 5,
      reliability_rating: 1,
      issues: 7,
      blocker_issues: 2,
      high_issues: 3,
      medium_issues: 1,
      low_issues: 1,
      info_issues: 0,
      security_issues: 4,
      reliability_issues: 2,
      maintainability_issues: 1,
    });
    // gamma is never analysed. delta is analysed, with no measures.
    await analysis(
      ids.delta!,
      await main('delta'),
      '2026-10-10T00:00:00.000Z',
      'succeeded',
      'error',
    );
    // omega (north): failing, with no blocker or high finding.
    const o1 = await analysis(
      ids.omega!,
      await main('omega'),
      '2026-10-01T00:00:00.000Z',
      'succeeded',
      'failed',
    );
    await measure(o1, {
      ncloc: 500,
      coverage: 90,
      duplicated_lines_density: 0,
      security_rating: 2,
      reliability_rating: 1,
      issues: 3,
      blocker_issues: 0,
      high_issues: 0,
      medium_issues: 1,
      low_issues: 1,
      info_issues: 1,
      security_issues: 0,
      reliability_issues: 1,
      maintainability_issues: 2,
      new_issues: 1,
    });
    // Zulu (north, created 2026-09-01): passing, rated A, one high finding.
    const z1 = await analysis(
      ids.Zulu!,
      await main('Zulu'),
      '2026-10-02T00:00:00.000Z',
      'succeeded',
      'passed',
    );
    await measure(z1, {
      ncloc: 100,
      coverage: 60,
      duplicated_lines_density: 0,
      security_rating: 1,
      reliability_rating: 1,
      issues: 1,
      blocker_issues: 0,
      high_issues: 1,
      medium_issues: 0,
      low_issues: 0,
      info_issues: 0,
      security_issues: 0,
      reliability_issues: 0,
      maintainability_issues: 1,
      new_issues: 0,
    });

    // Current-only counts: open, not duplicate, main branch.
    const secret = await seedRule(ctx.db, { key: 'gitleaks:aws-key', quality: 'security' });
    const dependency = await seedRule(ctx.db, { key: 'trivy:CVE-2026-1', quality: 'security' });
    const code = await seedRule(ctx.db, { key: 'eslint:no-eval', quality: 'security' });
    const onAlpha = { projectId: ids.alpha!, branchId: alphaMain };
    const s1 = await seedIssue(ctx.db, { ...onAlpha, ruleId: secret });
    await seedIssue(ctx.db, { ...onAlpha, ruleId: secret });
    await seedIssue(ctx.db, { ...onAlpha, ruleId: secret, status: 'resolved' });
    await seedIssue(ctx.db, { ...onAlpha, ruleId: secret, duplicateOfIssueId: s1 });
    for (let i = 0; i < 3; i++) await seedIssue(ctx.db, { ...onAlpha, ruleId: dependency });
    await seedIssue(ctx.db, { projectId: ids.alpha!, branchId: feature!.id, ruleId: dependency });
    await seedIssue(ctx.db, { ...onAlpha, ruleId: code });
    await seedIssue(ctx.db, {
      projectId: ids.omega!,
      branchId: await main('omega'),
      ruleId: secret,
    });

    // Triage: a false positive on alpha (week of 08-31, September), a won't fix on beta (week of
    // 10-05, October); a resolution and a comment do not count.
    const alphaIssue = await seedIssue(ctx.db, {
      ...onAlpha,
      ruleId: code,
      status: 'false_positive',
    });
    const betaIssue = await seedIssue(ctx.db, {
      projectId: ids.beta!,
      branchId: betaMain,
      ruleId: code,
      status: 'wont_fix',
    });
    await ctx.db.insert(issueChanges).values([
      {
        issueId: alphaIssue,
        field: 'status',
        oldValue: 'open',
        newValue: 'false_positive',
        createdAt: new Date('2026-09-02T08:00:00Z'),
      },
      {
        issueId: betaIssue,
        field: 'status',
        oldValue: 'open',
        newValue: 'wont_fix',
        createdAt: new Date('2026-10-06T08:00:00Z'),
      },
      {
        issueId: alphaIssue,
        field: 'status',
        oldValue: 'open',
        newValue: 'resolved',
        createdAt: new Date('2026-10-06T09:00:00Z'),
      },
      {
        issueId: alphaIssue,
        field: 'comment',
        comment: 'false_positive',
        createdAt: new Date('2026-10-06T10:00:00Z'),
      },
    ]);

    const session = async (username: string) => {
      const user = await createUser(ctx, { username });
      return { user, session: await login(ctx, user.username, user.password) };
    };
    const m = await session('east-member');
    await addMember(ctx, east, m.user.id, 'member');
    member = m.session;
    const g = await session('alpha-viewer');
    await grantProject(ctx, ids.alpha!, g.user.id, 'viewer');
    grantOnly = g.session;
    outsider = (await session('outsider')).session;
  });
  afterAll(async () => ctx.close());

  const eastAggregate = {
    projects: 4,
    analysed: 3,
    abandoned: 2,
    gate: { passed: 1, failed: 1, error: 1, none: 0 },
    securityRating: { A: 1, B: 0, C: 0, D: 0, E: 1 },
    reliabilityRating: { A: 1, B: 1, C: 0, D: 0, E: 0 },
    ncloc: 4200,
    coverage: 80,
    issues: 17,
    bySeverity: { blocker: 2, high: 4, medium: 3, low: 4, info: 4 },
    securityIssues: 5,
    reliabilityIssues: 4,
    maintainabilityIssues: 8,
    newIssues: 2,
  };
  const eastTotals = { ...eastAggregate, secrets: 2, vulnerableDependencies: 3 };

  it('totals the organisation scope for a member, by hand from the seed', async () => {
    const { status, body } = await overview(member, {
      scope: 'organization',
      organizationId: east,
    });
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.generatedAt).toBe(NOW.toISOString());
    expect(body.scope).toEqual({
      kind: 'organization',
      organization: { id: east, key: 'east', name: 'east team' },
    });
    expect(body.granularity).toBe('week');
    expect(body.organizations).toBeNull();
    expect(body.totals).toMatchObject(eastTotals);
    expect(body.totals.passedShare).toBeCloseTo(1 / 3, 10);
    // (5 × 1200 + 20 × 3000) / 4200: both have ncloc and duplication.
    expect(body.totals.duplication).toBeCloseTo(66_000 / 4200, 10);
    const keys = (list: { project: { key: string } }[]) => list.map((r) => r.project.key);
    expect(keys(body.attention.failingGates)).toEqual(['beta']);
    // R3: alpha is rated A, so it needs no security attention; it has one high finding.
    expect(keys(body.attention.worstSecurity)).toEqual(['beta']);
    expect(keys(body.attention.mostSevere)).toEqual(['beta', 'alpha']);
    expect(keys(body.attention.abandoned)).toEqual(['gamma', 'beta']);
    const alpha = body.attention.mostSevere[1]!;
    expect(alpha).toEqual({
      organization: { key: 'east', name: 'east team' },
      project: { id: ids.alpha, key: 'alpha', name: 'alpha' },
      lastAnalysisAt: '2026-10-13T09:00:00.000Z',
      abandoned: false,
      gate: 'passed',
      securityRating: 'A',
      reliabilityRating: 'B',
      ncloc: 1200,
      coverage: 80,
      duplication: 5,
      issues: 10,
      bySeverity: { blocker: 0, high: 1, medium: 2, low: 3, info: 4 },
      newIssues: 2,
      secrets: 2,
      vulnerableDependencies: 3,
      vulnerableReleases: 0,
      exploited: 0,
    });
    expect(body.attention.abandoned[1]).toMatchObject({
      lastAnalysisAt: '2026-09-04T12:00:00.000Z',
      abandoned: true,
      securityRating: 'E',
      coverage: null,
      newIssues: null,
    });
  });

  it('shows a grant-only user its granted project only (Review Focus 2)', async () => {
    const { status, body } = await overview(grantOnly, {
      scope: 'organization',
      organizationId: east,
    });
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.totals).toMatchObject({
      projects: 1,
      analysed: 1,
      abandoned: 0,
      gate: { passed: 1, failed: 0, error: 0, none: 0 },
      passedShare: 1,
      securityRating: { A: 1, B: 0, C: 0, D: 0, E: 0 },
      ncloc: 1200,
      coverage: 80,
      duplication: 5,
      issues: 10,
      secrets: 2,
      vulnerableDependencies: 3,
    });
    expect(body.trend.map((p) => p.projects)).toEqual(Array(12).fill(1));
    expect(body.trend.map((p) => p.analyses)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);
    expect(body.trend.map((p) => p.triage)).toEqual([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for (const list of Object.values(body.attention)) {
      expect(list).not.toBeNull();
      expect(list!.every((r) => r.project.key === 'alpha')).toBe(true);
    }
    expect(body.attention.worstSecurity).toHaveLength(0);
    expect(body.attention.mostSevere).toHaveLength(1);
    expect(body.attention.abandoned).toEqual([]);

    const all = await overview(grantOnly, { scope: 'all' });
    expect(all.status).toBe(200);
    expect(all.body.scope).toEqual({ kind: 'all', organization: null });
    expect(all.body.organizations?.map((o) => [o.key, o.name, o.projects])).toEqual([
      ['east', 'east team', 1],
    ]);
    expect(all.body.totals.projects).toBe(1);
  });

  it('hides an organisation from an outsider, and gives it empty totals (Review Focus 1)', async () => {
    const org = await overview(outsider, { scope: 'organization', organizationId: east });
    expect(org.status).toBe(404);
    const missing = await overview(outsider, {
      scope: 'organization',
      organizationId: 'not-a-uuid',
    });
    expect(missing.status).toBe(404);
    const { status, body } = await overview(outsider, { scope: 'all' });
    expect(status).toBe(200);
    expect(body.totals).toEqual({
      ...EMPTY,
      secrets: 0,
      vulnerableDependencies: 0,
      vulnerableReleases: null,
      exploited: null,
    });
    expect(body.organizations).toEqual([]);
    expect(body.trend).toHaveLength(12);
    for (const point of body.trend) {
      expect(point).toEqual({
        ...EMPTY,
        start: point.start,
        end: point.end,
        analyses: 0,
        triage: 0,
      });
    }
    expect(body.attention).toEqual({
      exploited: [],
      failingGates: [],
      worstSecurity: [],
      mostSevere: [],
      abandoned: [],
    });
  });

  it('shows an instance admin every organisation with a project, sorted by key', async () => {
    const { status, body } = await overview(root, { scope: 'all' });
    expect(status).toBe(200);
    expect(body.organizations?.map((o) => [o.id, o.key, o.name])).toEqual([
      [east, 'east', 'east team'],
      [north, 'north', 'north team'],
    ]);
    const [eastRow, northRow] = body.organizations!;
    expect(eastRow).toMatchObject(eastAggregate);
    expect(northRow).toMatchObject({
      projects: 2,
      analysed: 2,
      gate: { passed: 1, failed: 1, error: 0, none: 0 },
      passedShare: 0.5,
      duplication: 0,
    });
    // (90 × 500 + 60 × 100) / 600.
    expect(northRow!.coverage).toBeCloseTo(51_000 / 600, 10);
    expect(body.totals).toMatchObject({
      projects: 6,
      analysed: 5,
      ncloc: 4800,
      secrets: 3,
      vulnerableDependencies: 3,
    });
    // (80 × 1200 + 90 × 500 + 60 × 100) / 1800: beta has no coverage.
    expect(body.totals.coverage).toBeCloseTo(147_000 / 1800, 10);
    const keys = (list: { project: { key: string } }[]) => list.map((r) => r.project.key);
    expect(keys(body.attention.failingGates)).toEqual(['beta', 'omega']);
    // R3: alpha and Zulu are rated A; omega has no blocker or high finding.
    expect(keys(body.attention.worstSecurity)).toEqual(['beta', 'omega']);
    // Zulu and alpha tie at one high finding: by key in code-unit order, upper case first (R5).
    expect(keys(body.attention.mostSevere)).toEqual(['beta', 'Zulu', 'alpha']);
    // R4: Zulu, created in week 6, is absent from the points before it.
    expect(body.trend.map((p) => p.projects)).toEqual([5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6]);
    expect(body.trend[4]).toMatchObject({ projects: 5, analysed: 0, abandoned: 5 });
    expect(body.trend[5]).toMatchObject({ projects: 6, analysed: 1, abandoned: 5 });
  });

  it('reads the state at each bucket end from main-branch successes before it (Review Focus 3)', async () => {
    const { body } = await overview(member, { scope: 'organization', organizationId: east });
    expect(body.trend.map((p) => p.start)).toEqual(WEEK_STARTS);
    expect(body.trend.map((p) => p.end)).toEqual([...WEEK_STARTS.slice(1), NOW.toISOString()]);
    const at = (start: string) => body.trend.find((p) => p.start.startsWith(start))!;
    // The bucket ending Monday 09-28 00:00 does not see a1 uploaded at exactly that instant.
    expect(at('2026-09-21')).toMatchObject({
      projects: 4,
      analysed: 1,
      abandoned: 3,
      gate: { passed: 0, failed: 1, error: 0, none: 0 },
      ncloc: 3000,
    });
    // The next one does; beta's last analysis is now more than 30 days before the bucket end.
    expect(at('2026-09-28')).toMatchObject({
      analysed: 2,
      abandoned: 3,
      gate: { passed: 0, failed: 2, error: 0, none: 0 },
      securityRating: { A: 0, B: 0, C: 1, D: 0, E: 1 },
      ncloc: 4000,
    });
    // a2 (10-13) does not change the bucket ending 10-12; delta (10-10) joins it.
    expect(at('2026-10-05')).toMatchObject({
      analysed: 3,
      gate: { passed: 0, failed: 2, error: 1, none: 0 },
      ncloc: 4000,
    });
    // The current bucket is the state now; the failed, queued and non-main ones set nothing.
    expect(at('2026-10-12')).toMatchObject(eastAggregate);
    expect(body.trend.slice(0, 5).map((p) => p.analysed)).toEqual([0, 0, 0, 0, 0]);
    expect(body.trend.slice(0, 5).map((p) => p.abandoned)).toEqual([4, 4, 4, 4, 4]);
    expect(at('2026-08-31')).toMatchObject({ analysed: 1, abandoned: 3 });
    // a1 counts in the week it opens; the non-main success counts, the failed and queued do not.
    expect(body.trend.map((p) => p.analyses)).toEqual([0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2]);
    expect(body.trend.map((p) => p.triage)).toEqual([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0]);
  });

  it('buckets by calendar month', async () => {
    const { body } = await overview(member, {
      scope: 'organization',
      organizationId: east,
      granularity: 'month',
    });
    expect(body.granularity).toBe('month');
    expect(body.trend.map((p) => p.start)).toEqual([
      '2025-11-01T00:00:00.000Z',
      '2025-12-01T00:00:00.000Z',
      '2026-01-01T00:00:00.000Z',
      '2026-02-01T00:00:00.000Z',
      '2026-03-01T00:00:00.000Z',
      '2026-04-01T00:00:00.000Z',
      '2026-05-01T00:00:00.000Z',
      '2026-06-01T00:00:00.000Z',
      '2026-07-01T00:00:00.000Z',
      '2026-08-01T00:00:00.000Z',
      '2026-09-01T00:00:00.000Z',
      '2026-10-01T00:00:00.000Z',
    ]);
    expect(body.trend.at(-1)!.end).toBe(NOW.toISOString());
    expect(body.trend.map((p) => p.triage)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
    expect(body.trend.map((p) => p.analyses)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3]);
    // The end of September: beta and a1; beta is not yet 30 days old.
    expect(body.trend[10]).toMatchObject({ analysed: 2, abandoned: 2 });
  });

  it('gives a never-analysed project and one without measures nulls, never NaN', async () => {
    const { body } = await overview(root, { scope: 'organization', organizationId: east });
    const gamma = body.attention.abandoned.find((r) => r.project.key === 'gamma');
    expect(gamma).toMatchObject({
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
    });
    // delta (analysed, no measures) is counted as analysed with gate error, and nowhere else.
    expect(body.totals.analysed).toBe(3);
    expect(body.totals.gate.error).toBe(1);
    expect(body.attention.worstSecurity.map((r) => r.project.key)).not.toContain('delta');
    expect(body.attention.mostSevere.map((r) => r.project.key)).not.toContain('delta');

    // JSON turns NaN into null, so read the service's own answer: as an instance admin, and as a
    // user who sees nothing.
    const numbers: number[] = [];
    const walk = (v: unknown): void => {
      if (typeof v === 'number') numbers.push(v);
      else if (v !== null && typeof v === 'object') Object.values(v).forEach(walk);
    };
    for (const user of [
      { id: ctx.adminId, isInstanceAdmin: true },
      { id: '00000000-0000-7000-8000-000000000000', isInstanceAdmin: false },
    ]) {
      const request = { principal: { kind: 'session', user } } as unknown as FastifyRequest;
      walk(await fixed.overview(request, { scope: 'all' }, { granularity: 'week' }));
    }
    expect(numbers.length).toBeGreaterThan(100);
    expect(numbers.filter((n) => !Number.isFinite(n))).toEqual([]);
  });

  it('serves the plugin context on the transaction clock', async () => {
    const { status, body } = await overview(
      member,
      { scope: 'organization', organizationId: east },
      '',
    );
    expect(status, JSON.stringify(body)).toBe(200);
    expect(Math.abs(Date.parse(body.generatedAt) - Date.now())).toBeLessThan(60_000);
    expect(body.trend).toHaveLength(12);
    expect(body.totals).toMatchObject({ projects: 4, analysed: 3, secrets: 2 });
  });

  it('answers 503 PORTFOLIO_TIMEOUT past the statement budget', async () => {
    // One connection, so the check below runs on the connection the budget was set on.
    const pinned = createDatabase(ctx.database.url, { max: 1 });
    try {
      await expect(
        readSnapshot(pinned.db, 1, async (tx) => tx.execute(sql`SELECT pg_sleep(0.2)`)),
      ).rejects.toMatchObject({
        status: 503,
        code: 'PORTFOLIO_TIMEOUT',
        message: 'The portfolio took too long to compute',
      });
      // The budget is local to the transaction: the connection is back on the default.
      const [row] = (
        await pinned.db.execute<{ t: string }>(
          sql`SELECT current_setting('statement_timeout') AS t`,
        )
      ).rows;
      expect(row?.t).toBe('0');
    } finally {
      await pinned.close();
    }
  });

  it('answers 403 FEATURE_NOT_LICENSED while the feature is inactive', async () => {
    const off = createPortfolioService({ db: ctx.db, isFeatureActive: () => false });
    await expect(
      off.overview({} as FastifyRequest, { scope: 'all' }, { granularity: 'week' }),
    ).rejects.toMatchObject({
      status: 403,
      code: 'FEATURE_NOT_LICENSED',
      message: 'The enterprise feature "portfolio" is not licensed',
    });
  });

  // ─── projects: sorted pages and the cursor (4E-2 §2) ─────────────────────────────────────────

  type Page = { items: PortfolioProjectRow[]; nextCursor: string | null };
  const read = async <T>(
    session: Session,
    path: string,
    query: Query,
  ): Promise<{ status: number; body: T & { code?: string; errors?: unknown } }> => {
    const qs = new URLSearchParams(
      Object.entries(query).filter((e): e is [string, string] => e[1] !== undefined),
    ).toString();
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/ee/t/portfolio/${path}?${qs}`,
      headers: session.headers,
    });
    return { status: res.statusCode, body: res.json() };
  };
  const page = (session: Session, query: Query) => read<Page>(session, 'projects', query);
  const keysOf = (rows: PortfolioProjectRow[]) => rows.map((r) => r.project.key);
  /** Projects that tie on the sort value, in the tie-break order: by project id. */
  const tie = (...keys: string[]) => [...keys].sort((a, b) => (ids[a]! < ids[b]! ? -1 : 1));

  /** Every row of a sort, read `limit` at a time through the cursor. */
  const pageThrough = async (session: Session, query: Query, limit: number) => {
    const seen: PortfolioProjectRow[] = [];
    const sizes: number[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < 20; i++) {
      const { status, body } = await page(session, { ...query, limit: String(limit), cursor });
      expect(status, JSON.stringify(body)).toBe(200);
      seen.push(...body.items);
      sizes.push(body.items.length);
      if (body.nextCursor === null) return { seen, sizes };
      cursor = body.nextCursor;
    }
    throw new Error('the cursor never ended');
  };

  /** The sorts over the seed, computed after the seed (tie() reads the ids). */
  const sorted = (): [string, string[]][] => [
    // R5: organisation key, then project key, in byte order (upper case first).
    ['key', ['alpha', 'beta', 'delta', 'gamma', 'Zulu', 'omega']],
    // failed, error, none, passed, then never analysed; within one, the worst security rating
    // first (R11): beta (E) before omega (B).
    ['gate', ['beta', 'omega', 'delta', ...tie('alpha', 'Zulu'), 'gamma']],
    // E first; delta (no measures) and gamma (never analysed) last.
    ['security', ['beta', 'omega', ...tie('alpha', 'Zulu'), ...tie('delta', 'gamma')]],
    ['reliability', ['alpha', ...tie('beta', 'omega', 'Zulu'), ...tie('delta', 'gamma')]],
    ['issues', ['alpha', 'beta', 'omega', 'Zulu', ...tie('delta', 'gamma')]],
    ['ncloc', ['beta', 'alpha', 'omega', 'Zulu', ...tie('delta', 'gamma')]],
    // The lowest first (R12); beta has no coverage: with the unmeasured, last.
    ['coverage', ['Zulu', 'alpha', 'omega', ...tie('beta', 'delta', 'gamma')]],
    // Oldest first, and never analysed before everything (the most stale).
    ['lastAnalysis', ['gamma', 'beta', 'omega', 'Zulu', 'delta', 'alpha']],
  ];

  it('sorts the projects by each sort, nulls in their place', async () => {
    for (const [sort, expected] of sorted()) {
      const { status, body } = await page(root, { scope: 'all', sort, limit: '100' });
      expect(status, JSON.stringify(body)).toBe(200);
      expect(keysOf(body.items), sort).toEqual(expected);
      expect(body.nextCursor).toBeNull();
    }
  });

  it('pages through every sort with the cursor, every row exactly once', async () => {
    for (const [sort, expected] of sorted()) {
      for (const limit of [1, 2, 4]) {
        const { seen, sizes } = await pageThrough(root, { scope: 'all', sort }, limit);
        expect(keysOf(seen), `${sort}, limit ${limit}`).toEqual(expected);
        // A full last page has no next cursor: no empty page at the end.
        expect(sizes.at(-1)).toBeGreaterThan(0);
        expect(sizes.slice(0, -1).every((n) => n === limit)).toBe(true);
      }
    }
  });

  it('pages through the gate sort by its security tie-break either way round the ids (R11)', async () => {
    /** Sets the security rating of a project's one main-branch analysis (beta's or omega's). */
    const setSecurity = (key: string, value: number) =>
      ctx.db
        .update(measures)
        .set({ value })
        .where(
          and(
            eq(measures.metricKey, 'security_rating'),
            inArray(
              measures.analysisId,
              ctx.db
                .select({ id: analyses.id })
                .from(analyses)
                .where(eq(analyses.projectId, ids[key]!)),
            ),
          ),
        );
    // beta and omega both fail their gate. One of the two orders runs against their id order,
    // so a cursor without the rating would skip or repeat a row in it.
    try {
      for (const [beta, omega, first] of [
        [5, 2, ['beta', 'omega']],
        [2, 5, ['omega', 'beta']],
      ] as const) {
        await setSecurity('beta', beta);
        await setSecurity('omega', omega);
        for (const limit of [1, 2, 4]) {
          const { seen } = await pageThrough(root, { scope: 'all', sort: 'gate' }, limit);
          expect(keysOf(seen), `beta ${beta}, omega ${omega}, limit ${limit}`).toEqual([
            ...first,
            'delta',
            ...tie('alpha', 'Zulu'),
            'gamma',
          ]);
        }
      }
    } finally {
      await setSecurity('beta', 5);
      await setSecurity('omega', 2);
    }
  });

  it('serves the same rows as the overview, and only what the user can read', async () => {
    const all = await page(root, { scope: 'all', sort: 'key', limit: '100' });
    const { body } = await overview(root, { scope: 'all' });
    const alpha = all.body.items.find((r) => r.project.key === 'alpha');
    expect(alpha).toEqual(body.attention.mostSevere.find((r) => r.project.key === 'alpha'));
    const gamma = all.body.items.find((r) => r.project.key === 'gamma');
    expect(gamma).toEqual(body.attention.abandoned.find((r) => r.project.key === 'gamma'));

    const inEast = await page(member, { scope: 'organization', organizationId: east, sort: 'key' });
    expect(keysOf(inEast.body.items)).toEqual(['alpha', 'beta', 'delta', 'gamma']);
    const memberAll = await page(member, { scope: 'all', sort: 'ncloc' });
    expect(keysOf(memberAll.body.items)).toEqual(['beta', 'alpha', ...tie('delta', 'gamma')]);
    const granted = await page(grantOnly, { scope: 'all', sort: 'gate' });
    expect(keysOf(granted.body.items)).toEqual(['alpha']);
    expect((await page(outsider, { scope: 'all' })).body).toEqual({ items: [], nextCursor: null });
    expect((await page(outsider, { scope: 'organization', organizationId: east })).status).toBe(
      404,
    );
  });

  it('answers 422 for a bad cursor, sort or limit', async () => {
    const encode = (v: unknown) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
    const keyCursor = (await page(root, { scope: 'all', sort: 'key', limit: '1' })).body
      .nextCursor!;
    const dateCursor = (await page(root, { scope: 'all', sort: 'lastAnalysis', limit: '2' })).body
      .nextCursor!;
    for (const [sort, cursor] of [
      ['key', 'not-a-cursor'],
      ['key', encode({ v: ['east', 'alpha'] })],
      ['key', encode({ v: ['east', 'alpha'], id: 'not-a-uuid' })],
      ['key', encode({ v: ['east', 'alpha'], id: ids.alpha, extra: 1 })],
      // A cursor of one sort is no cursor of another.
      ['ncloc', keyCursor],
      ['key', dateCursor],
      ['gate', encode({ v: 4, id: ids.alpha })],
      ['gate', encode({ v: [4, 1], id: ids.alpha })],
      ['gate', encode({ v: [0, 6], id: ids.alpha })],
      ['security', encode({ v: 0, id: ids.alpha })],
      ['lastAnalysis', encode({ v: '2026-10-13', id: ids.alpha })],
    ] as const) {
      const { status, body } = await page(root, { scope: 'all', sort, cursor });
      expect(status, `${sort} ${cursor}`).toBe(422);
      expect(body.errors).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
    }
    for (const [query, path] of [
      [{ sort: 'name' }, 'query.sort'],
      [{ limit: '0' }, 'query.limit'],
      [{ limit: '101' }, 'query.limit'],
      [{ limit: '2.5' }, 'query.limit'],
    ] as const) {
      const { status, body } = await page(root, { scope: 'all', ...query });
      expect(status, JSON.stringify(query)).toBe(422);
      expect(body.errors).toEqual([expect.objectContaining({ path })]);
    }
    // A null sort value is a cursor value like any other.
    const ncloc = await page(root, { scope: 'all', sort: 'ncloc', limit: '5' });
    const tail = await page(root, { scope: 'all', sort: 'ncloc', cursor: ncloc.body.nextCursor! });
    expect(tail.status).toBe(200);
    expect(tail.body.items).toHaveLength(1);
  });

  // ─── exportRows (4E-2 §2) ────────────────────────────────────────────────────────────────────

  it('exports every visible row by key, and only those (grant-only user)', async () => {
    const all = await read<PortfolioProjectRow[]>(root, 'export', { scope: 'all' });
    expect(all.status).toBe(200);
    expect(keysOf(all.body)).toEqual(['alpha', 'beta', 'delta', 'gamma', 'Zulu', 'omega']);
    const paged = await page(root, { scope: 'all', sort: 'key', limit: '100' });
    expect(all.body).toEqual(paged.body.items);

    const granted = await read<PortfolioProjectRow[]>(grantOnly, 'export', { scope: 'all' });
    expect(keysOf(granted.body)).toEqual(['alpha']);
    const inEast = await read<PortfolioProjectRow[]>(grantOnly, 'export', {
      scope: 'organization',
      organizationId: east,
    });
    expect(keysOf(inEast.body)).toEqual(['alpha']);
    const inNorth = await read<PortfolioProjectRow[]>(grantOnly, 'export', {
      scope: 'organization',
      organizationId: north,
    });
    expect(inNorth.status).toBe(404);
    const none = await read<PortfolioProjectRow[]>(outsider, 'export', { scope: 'all' });
    expect(none.body).toEqual([]);
  });

  it('gates projects and exportRows on the feature', async () => {
    const off = createPortfolioService({ db: ctx.db, isFeatureActive: () => false });
    const problem = {
      status: 403,
      code: 'FEATURE_NOT_LICENSED',
      message: 'The enterprise feature "portfolio" is not licensed',
    };
    await expect(
      off.projects({} as FastifyRequest, { scope: 'all' }, { sort: 'key', limit: 50 }),
    ).rejects.toMatchObject(problem);
    const rows = off.exportRows({} as FastifyRequest, { scope: 'all' });
    await expect(rows[Symbol.asyncIterator]().next()).rejects.toMatchObject(problem);
  });

  // ─── vulnerable releases and exploited vulnerabilities (plan 5, V1–V3) ───────────────────────

  describe('vulnerability numbers', () => {
    /** Same service, without `vuln.priority`. */
    let plain: PluginPortfolio;
    const rootRequest = () =>
      ({
        principal: { kind: 'session', user: { id: ctx.adminId, isInstanceAdmin: true } },
      }) as unknown as FastifyRequest;
    const version = async (key: string, label: string, minute: number) =>
      (
        await ctx.db
          .insert(projectVersions)
          .values({
            projectId: ids[key]!,
            label,
            source: 'tag',
            tag: label,
            analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, minute)),
          })
          .returning({ id: projectVersions.id })
      )[0]!.id;
    const seedRows = async (
      key: string,
      target: { branchId: string } | { versionId: string },
      vulnerabilityIds: string[],
    ) => {
      for (const vulnerabilityId of vulnerabilityIds) {
        await seedTargetRow(ctx.db, {
          projectId: ids[key]!,
          ...target,
          packageName: `pkg-${vulnerabilityId}`,
          vulnerabilityId,
        });
      }
    };
    const rowsByKey = async (sort = 'key') =>
      new Map(
        (await page(root, { scope: 'all', sort, limit: '100' })).body.items.map((r) => [
          r.project.key,
          r,
        ]),
      );

    beforeAll(async () => {
      plain = createPortfolioService({
        db: ctx.db,
        isFeatureActive: (feature) => feature === 'portfolio',
        now: () => NOW,
      });
      await ctx.db
        .insert(vulnerabilityKev)
        .values(
          ['1001', '1002', '1003', '1004', '1005', '1006'].map((k) => ({
            vulnerabilityId: `CVE-2024-${k}`,
            dateAdded: '2024-03-05',
          })),
        )
        .onConflictDoNothing();
      // alpha: two tracked versions with rows; K4 is on main and on a version, K5 on the other.
      await seedRows('alpha', { branchId: await mainBranchId(ctx.db, ids.alpha!) }, [
        'CVE-2024-1004',
      ]);
      await seedRows('alpha', { versionId: await version('alpha', 'v1', 1) }, ['CVE-2024-1004']);
      await seedRows('alpha', { versionId: await version('alpha', 'v2', 2) }, ['CVE-2024-1005']);
      await version('alpha', 'v3', 3);
      // beta and gamma: three exploited ids on main, no version.
      for (const key of ['beta', 'gamma']) {
        await seedRows(key, { branchId: await mainBranchId(ctx.db, ids[key]!) }, [
          'CVE-2024-1001',
          'CVE-2024-1002',
          'CVE-2024-1003',
        ]);
      }
      // beta also has one version with a row that is not in KEV.
      await seedRows('beta', { versionId: await version('beta', 'v1', 1) }, ['CVE-2024-2001']);
      await seedRows('Zulu', { branchId: await mainBranchId(ctx.db, ids.Zulu!) }, [
        'CVE-2024-1006',
      ]);
      await seedRows('Zulu', { versionId: await version('Zulu', 'v1', 1) }, ['CVE-2024-2002']);
      // omega is not monitored.
      await ctx.db.insert(projectVulnerabilitySettings).values({
        projectId: ids.omega!,
        enabled: false,
      });
    });

    it('carries the numbers on the rows and the totals', async () => {
      const rows = await rowsByKey();
      const numbers = (key: string) => {
        const r = rows.get(key)!;
        return [r.vulnerableReleases, r.exploited];
      };
      expect(numbers('alpha')).toEqual([2, 2]);
      expect(numbers('beta')).toEqual([1, 3]);
      expect(numbers('gamma')).toEqual([0, 3]);
      expect(numbers('delta')).toEqual([0, 0]);
      expect(numbers('Zulu')).toEqual([1, 1]);
      expect(numbers('omega')).toEqual([null, null]);
      const { body } = await overview(root, { scope: 'all' });
      expect(body.totals).toMatchObject({ vulnerableReleases: 4, exploited: 9 });
    });

    it('lists the exploited projects most first, then by key', async () => {
      const { body } = await overview(root, { scope: 'all' });
      expect(body.attention.exploited?.map((r) => [r.project.key, r.exploited])).toEqual([
        ['beta', 3],
        ['gamma', 3],
        ['alpha', 2],
        ['Zulu', 1],
      ]);
    });

    it('hides the exploited numbers without vuln.priority', async () => {
      const result = await plain.overview(rootRequest(), { scope: 'all' }, { granularity: 'week' });
      expect(result.attention.exploited).toBeNull();
      expect(result.totals).toMatchObject({ vulnerableReleases: 4, exploited: null });
      const { items } = await plain.projects(
        rootRequest(),
        { scope: 'all' },
        { sort: 'key', limit: 100 },
      );
      expect(items.map((r) => r.exploited)).toEqual(Array(6).fill(null));
      expect(items.find((r) => r.project.key === 'alpha')?.vulnerableReleases).toBe(2);
      const rows: PortfolioProjectRow[] = [];
      for await (const row of plain.exportRows(rootRequest(), { scope: 'all' })) rows.push(row);
      expect(rows.every((r) => r.exploited === null)).toBe(true);
    });

    it('sorts by vulnerable releases and exploited, a missing value last', async () => {
      for (const [sort, expected] of [
        [
          'vulnerableReleases',
          ['alpha', ...tie('beta', 'Zulu'), ...tie('gamma', 'delta'), 'omega'],
        ],
        ['exploited', [...tie('beta', 'gamma'), 'alpha', 'Zulu', 'delta', 'omega']],
      ] as const) {
        const { status, body } = await page(root, { scope: 'all', sort, limit: '100' });
        expect(status, JSON.stringify(body)).toBe(200);
        expect(keysOf(body.items), sort).toEqual(expected);
        for (const limit of [1, 2, 4]) {
          const { seen } = await pageThrough(root, { scope: 'all', sort }, limit);
          expect(keysOf(seen), `${sort}, limit ${limit}`).toEqual(expected);
        }
      }
    });

    it('caps the exploited list at 10', async () => {
      for (let i = 0; i < 11; i++) {
        const key = `many${String(i).padStart(2, '0')}`;
        ids[key] = (await createProject(ctx, root, { organizationId: north, key })).id;
        await seedRows(key, { branchId: await mainBranchId(ctx.db, ids[key]!) }, ['CVE-2024-1001']);
      }
      const { body } = await overview(root, { scope: 'all' });
      const list = body.attention.exploited!;
      expect(list).toHaveLength(10);
      expect(list.map((r) => r.project.key).slice(0, 4)).toEqual([
        'beta',
        'gamma',
        'alpha',
        'Zulu',
      ]);
    });
  });
});
