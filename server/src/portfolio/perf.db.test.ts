import { performance } from 'node:perf_hooks';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session, type TestContext } from '../../test/app';
import { budgetMs } from '../../test/perf';
import { rbacContext } from '../../test/rbac';
import type { PortfolioOverview, PortfolioProjectRow, QualorPlugin } from '../plugins/contract';
import { STATE_METRICS } from './query';

/** 4E-2 §6: 2 000 projects × 12 trend points finish inside the 20 s statement budget. */
const PROJECTS = 2_000;
const ORGANIZATIONS = 20;
/** 13 succeeded main-branch analyses per project, one a week over the last 12 weeks. */
const ANALYSES = 13;
/** Tracked versions per project, each with this many vulnerability rows (plan 5, V7). */
const VERSIONS = 5;
const VULNERABILITIES_PER_VERSION = 20;
const KEV_IDS = 3;
const BUDGET_MS = 20_000;
/** Above this the run is reported as a concern (with the slowest query's plan). */
const CONCERN_MS = 10_000;
const LICENSED = new Date('2027-01-01T00:00:00Z');
/** Measures a real analysis also stores, which the portfolio's reads must skip. */
const OTHER_METRICS = [
  'lines',
  'files',
  'functions',
  'classes',
  'complexity',
  'cognitive_complexity',
  'comment_lines',
  'duplicated_lines',
  'lines_to_cover',
  'uncovered_lines',
];

const FIXTURE: QualorPlugin = {
  name: 'portfolio-perf-fixture',
  apiVersion: 1,
  features: ['portfolio', 'vuln.priority'],
  register(ctx) {
    ctx.routes('portfolio', async (app) => {
      app.get('/t/perf/overview', async (req) => {
        const { granularity } = req.query as { granularity: 'week' | 'month' };
        return ctx.portfolio.overview(req, { scope: 'all' }, { granularity });
      });
      app.get('/t/perf/projects', async (req) =>
        ctx.portfolio.projects(req, { scope: 'all' }, { sort: 'gate', limit: 50 }),
      );
    });
  },
};

/** A uuid v7 at the timestamp `t` (an SQL expression), random below the millisecond. */
const v7 = (t: string) =>
  sql.raw(`(lpad(to_hex(floor(extract(epoch FROM ${t}) * 1000)::bigint), 12, '0') || '7'
    || substr(md5(random()::text), 1, 3) || '8' || substr(md5(random()::text), 1, 15))::uuid`);

describe('ctx.portfolio performance: 2 000 projects × 13 analyses (seeded)', () => {
  let ctx: TestContext;
  let viewer: Session;
  const timings: Record<string, number> = {};

  const timed = async <T>(name: string, url: string): Promise<T> => {
    const start = performance.now();
    const res = await ctx.app.inject({ method: 'GET', url, headers: viewer.headers });
    timings[name] = Math.round(performance.now() - start);
    expect(res.statusCode, res.body.slice(0, 500)).toBe(200);
    return res.json() as T;
  };

  beforeAll(async () => {
    ctx = await rbacContext({
      now: () => LICENSED,
      features: ['portfolio', 'vuln.priority'],
      plugin: FIXTURE,
    });
    const start = performance.now();
    await ctx.db.execute(sql`
      INSERT INTO organizations (id, key, name)
      SELECT gen_random_uuid(), 'perf-' || lpad(o::text, 2, '0'), 'Perf team ' || o
        FROM generate_series(1, ${ORGANIZATIONS}) AS o`);
    await ctx.db.execute(sql`
      INSERT INTO projects (id, organization_id, key, name, created_at)
      SELECT gen_random_uuid(), o.id, 'perf-' || lpad(p::text, 4, '0'), 'Perf project ' || p,
             now() - interval '1 year'
        FROM generate_series(1, ${PROJECTS}) AS p
        JOIN organizations o
          ON o.key = 'perf-' || lpad((1 + p % ${ORGANIZATIONS})::text, 2, '0')`);
    await ctx.db.execute(sql`
      INSERT INTO branches (id, project_id, kind, name, is_main)
      SELECT gen_random_uuid(), id, 'branch', 'main', true FROM projects WHERE key LIKE 'perf-%'`);
    // One a week back from an hour ago, each project at its own minute; gates in rotation.
    await ctx.db.execute(sql`
      INSERT INTO analyses (id, project_id, branch_id, status, revision, baseline_status,
                            scanner_version, analysis_date, gate_status)
      SELECT ${v7('x.t')}, b.project_id, b.id, 'succeeded', repeat('a', 40), 'ok', '1.0.0', x.t,
             (ARRAY['passed', 'failed', 'error', 'none'])[1 + (k + abs(hashtext(b.id::text))) % 4]
        FROM branches b
        JOIN projects p ON p.id = b.project_id AND p.key LIKE 'perf-%'
       CROSS JOIN generate_series(0, ${ANALYSES - 1}) AS k
       CROSS JOIN LATERAL (
         SELECT now() - make_interval(days => 7 * k, hours => 1,
                                      mins => abs(hashtext(b.id::text)) % 600) AS t) x`);
    await ctx.db.execute(sql`
      INSERT INTO measures (analysis_id, metric_key, scope, value)
      SELECT a.id, m.key, 'overall',
             CASE WHEN m.key LIKE '%_rating' THEN 1 + abs(hashtext(a.id::text || m.key)) % 5
                  WHEN m.key IN ('coverage', 'duplicated_lines_density')
                    THEN (abs(hashtext(a.id::text || m.key)) % 1001) / 10.0
                  ELSE abs(hashtext(a.id::text || m.key)) % 50000 END
        FROM analyses a
        JOIN projects p ON p.id = a.project_id AND p.key LIKE 'perf-%'
       CROSS JOIN unnest(${sql.param([...STATE_METRICS, ...OTHER_METRICS])}::text[]) AS m(key)
      UNION ALL
      SELECT a.id, 'issues', 'new', abs(hashtext(a.id::text)) % 100
        FROM analyses a
        JOIN projects p ON p.id = a.project_id AND p.key LIKE 'perf-%'`);
    // Vulnerability monitoring: every version tracked, VULNERABILITIES_PER_VERSION rows on each,
    // the first KEV_IDS of the ids in the KEV catalog.
    await ctx.db.execute(sql`
      INSERT INTO project_vulnerability_settings (project_id, version_rule)
      SELECT id, 'all' FROM projects WHERE key LIKE 'perf-%'`);
    await ctx.db.execute(sql`
      INSERT INTO project_versions (id, project_id, label, source, tag, analyzed_at)
      SELECT gen_random_uuid(), p.id, 'v' || k, 'tag', 'v' || k, now() - make_interval(days => k)
        FROM projects p
       CROSS JOIN generate_series(1, ${VERSIONS}) AS k
       WHERE p.key LIKE 'perf-%'`);
    await ctx.db.execute(sql`
      INSERT INTO vulnerability_matches (purl, vulnerability_id, severity)
      SELECT 'pkg:npm/perf-' || j || '@1.0.0', 'CVE-2024-' || (1000 + j), 'high'
        FROM generate_series(1, ${VULNERABILITIES_PER_VERSION}) AS j`);
    await ctx.db.execute(sql`
      INSERT INTO vulnerability_kev (vulnerability_id, date_added)
      SELECT 'CVE-2024-' || (1000 + j), '2024-03-05' FROM generate_series(1, ${KEV_IDS}) AS j`);
    await ctx.db.execute(sql`
      INSERT INTO target_vulnerabilities (id, project_id, version_id, ecosystem, package_name,
                                          package_version, purl, vulnerability_id)
      SELECT gen_random_uuid(), v.project_id, v.id, 'npm', 'perf-' || j, '1.0.0', 'pkg:npm/perf-' || j || '@1.0.0',
             'CVE-2024-' || (1000 + j)
        FROM project_versions v
        JOIN projects p ON p.id = v.project_id AND p.key LIKE 'perf-%'
       CROSS JOIN generate_series(1, ${VULNERABILITIES_PER_VERSION}) AS j`);
    // A real database has statistics; the planner should not plan on an empty table's guesses.
    await ctx.db.execute(sql`
      ANALYZE organizations, projects, branches, analyses, measures, project_versions,
              target_vulnerabilities, vulnerability_matches`);
    timings.seed = Math.round(performance.now() - start);

    const counts = await ctx.db.execute<{ projects: number; analyses: number; measures: number }>(
      sql`SELECT (SELECT count(*) FROM projects WHERE key LIKE 'perf-%')::int AS projects,
                 (SELECT count(*) FROM analyses)::int AS analyses,
                 (SELECT count(*) FROM measures)::int AS measures`,
    );
    expect(counts.rows[0]).toEqual({
      projects: PROJECTS,
      analyses: PROJECTS * ANALYSES,
      measures: PROJECTS * ANALYSES * (STATE_METRICS.length + OTHER_METRICS.length + 1),
    });

    // A member of every organisation: the visibility filter of a user, not an instance admin's.
    const user = await createUser(ctx, { username: 'perf-viewer' });
    const orgs = await ctx.db.execute<{ id: string }>(
      sql`SELECT id FROM organizations WHERE key LIKE 'perf-%'`,
    );
    for (const { id } of orgs.rows) await addMember(ctx, id, user.id, 'member');
    viewer = await login(ctx, user.username, user.password);
  }, 600_000);
  afterAll(async () => {
    // Printed so a slow run shows how close it came to the budget.
    console.info('portfolio timings (ms), 2 000 projects × 13 analyses:', timings);
    await ctx?.close();
  });

  it.each(['week', 'month'] as const)(
    'computes the %s overview within the budget',
    async (granularity) => {
      const body = await timed<PortfolioOverview>(
        granularity,
        `/api/v0/ee/t/perf/overview?granularity=${granularity}`,
      );
      expect(body.totals.projects).toBe(PROJECTS);
      expect(body.totals.analysed).toBe(PROJECTS);
      expect(body.organizations).toHaveLength(ORGANIZATIONS);
      expect(body.trend).toHaveLength(12);
      // Every version is vulnerable, and each project has KEV_IDS distinct exploited ids.
      expect(body.totals.vulnerableReleases).toBe(PROJECTS * VERSIONS);
      expect(body.totals.exploited).toBe(PROJECTS * KEV_IDS);
      if (granularity === 'week') {
        // The oldest analysis is 12 weeks old: every point has a state for every project.
        expect(body.trend.every((p) => p.analysed === PROJECTS)).toBe(true);
      }
      expect(body.trend.reduce((n, p) => n + p.analyses, 0)).toBeGreaterThan(0);
      if (timings[granularity]! > CONCERN_MS) {
        console.warn(`portfolio ${granularity} overview took ${timings[granularity]} ms`);
      }
      expect(timings[granularity]).toBeLessThan(budgetMs(BUDGET_MS));
    },
    120_000,
  );

  it('serves the first projects page within the budget', async () => {
    const body = await timed<{ items: PortfolioProjectRow[] }>(
      'projects',
      '/api/v0/ee/t/perf/projects',
    );
    expect(body.items).toHaveLength(50);
    expect(body.items.every((r) => r.gate === 'failed')).toBe(true);
    expect(timings.projects).toBeLessThan(budgetMs(BUDGET_MS));
  }, 120_000);
});
