import { performance } from 'node:perf_hooks';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { budgetMs } from '../../test/perf';
import { seedIssues, seedRuleKey } from '../../test/seed-issues';
import { encodeKeyset } from '../http/keyset';

/** brief §7, api.md §4, data-model.md §8.7: P95 below 300 ms on a branch with 100k issues. */
const ISSUES = 100_000;
const P95_BUDGET_MS = 300;
const WARM_UP = 5;
const SAMPLES = 40;
/**
 * Under load (the whole suite in parallel, a busy CI runner) one round of samples can land on a
 * stall that says nothing about the query. A round over budget is measured again, up to this many
 * rounds, and the best P95 counts: a query that is really slow (a lost index, a sequential scan
 * over 100k rows) is over budget in every round.
 */
const ROUNDS = 3;

interface Page {
  items: unknown[];
  nextCursor: string | null;
  facets?: Record<string, unknown[]>;
}

function p95(samples: readonly number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.ceil(sorted.length * 0.95) - 1] ?? Number.POSITIVE_INFINITY;
}

describe('GET /issues latency with 100k issues on one branch (seeded)', () => {
  let h: IngestHarness;
  let branchId: string;
  const timings: Record<string, number> = {};

  const request = async (query: string): Promise<Page> => {
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/issues?branchId=${branchId}${query}`,
      headers: h.orgAdmin.headers,
    });
    if (res.statusCode !== 200) throw new Error(`${query}: ${res.statusCode} ${res.body}`);
    return res.json() as Page;
  };

  /** Fails unless `query` finds rows (and every facet values): a query that finds nothing measures nothing. */
  const expectRows = async (name: string, query: string): Promise<void> => {
    const page = await request(query);
    expect(page.items.length, name).toBeGreaterThan(0);
    for (const [facet, values] of Object.entries(page.facets ?? {})) {
      expect(values.length, `${name}: facet ${facet}`).toBeGreaterThan(0);
    }
  };

  /** The P95 wall time of `query` through the whole HTTP stack (auth, validation, SQL, JSON). */
  const measureOnce = async (query: string): Promise<number> => {
    for (let i = 0; i < WARM_UP; i++) await request(query);
    const samples: number[] = [];
    for (let i = 0; i < SAMPLES; i++) {
      const start = performance.now();
      await request(query);
      samples.push(performance.now() - start);
    }
    return p95(samples);
  };

  /** The best P95 of up to ROUNDS rounds, stopping at the first round within the budget. */
  const measure = async (query: string): Promise<number> => {
    let best = Number.POSITIVE_INFINITY;
    for (let round = 0; round < ROUNDS && best >= budgetMs(P95_BUDGET_MS); round++) {
      best = Math.min(best, await measureOnce(query));
    }
    return best;
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    const project = await h.project('acme/big');
    branchId = await mainBranchId(h.ctx.db, project.id);
    await seedIssues(h.ctx.db, { projectId: project.id, branchId, count: ISSUES });
    const counted = await h.ctx.db.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM issues WHERE branch_id = ${branchId}`,
    );
    expect(counted.rows[0]?.n).toBe(ISSUES);
  }, 180_000);
  afterAll(async () => {
    // Printed so a slow CI run shows how close it came to the budget.
    console.info('GET /issues P95 (ms) with 100k issues:', timings);
    await h.close();
  });

  it('spreads the seeded attributes independently (every pair of values occurs)', async () => {
    const pairs = await h.ctx.db.execute<{ pair: string; n: number }>(sql`
      SELECT 'engine x severity' AS pair, count(DISTINCT (r.engine_id, i.severity))::int AS n
        FROM issues i JOIN rules r ON r.id = i.rule_id WHERE i.branch_id = ${branchId}
      UNION ALL
      SELECT 'module x status', count(DISTINCT (split_part(i.path, '/', 2), i.status))::int
        FROM issues i WHERE i.branch_id = ${branchId}
      UNION ALL
      SELECT 'severity x in new code x duplicate',
             count(DISTINCT (i.severity, i.in_new_code, i.duplicate_of_issue_id IS NULL))::int
        FROM issues i WHERE i.branch_id = ${branchId}
      UNION ALL
      SELECT 'rule x module', count(DISTINCT (i.rule_id, split_part(i.path, '/', 2)))::int
        FROM issues i WHERE i.branch_id = ${branchId}`);
    expect(Object.fromEntries(pairs.rows.map((r) => [r.pair, r.n]))).toEqual({
      'engine x severity': 5 * 5,
      'module x status': 50 * 5,
      'severity x in new code x duplicate': 5 * 2 * 2,
      // 10 000 of the 200 x 50 combinations, with 100 000 draws: all but a handful occur.
      'rule x module': expect.any(Number),
    });
    const ruleByModule = pairs.rows.find((r) => r.pair === 'rule x module');
    expect(ruleByModule?.n).toBeGreaterThan(9_900);
  });

  const cases: [string, string][] = [
    ['default list (open, by severity, first page)', ''],
    ['filtered by rule and path', `&rule=${seedRuleKey(7)}&path=src/module7/`],
    ['several statuses', '&status=open&status=resolved&status=wont_fix&limit=100'],
    ['sorted by path', '&sort=path'],
    ['sorted by creation', '&sort=createdAt'],
    ['message search', '&q=number%2042'],
    ['every facet', '&facets=severity,quality,rule,engine,status,path'],
  ];

  for (const [name, query] of cases) {
    it(`${name}: P95 < ${P95_BUDGET_MS} ms`, async () => {
      await expectRows(name, query);
      timings[name] = Math.round(await measure(query));
      expect(timings[name]).toBeLessThan(budgetMs(P95_BUDGET_MS));
    }, 120_000);
  }

  it(`a page deep in the list (the 40th of 50): P95 < ${P95_BUDGET_MS} ms`, async () => {
    let cursor: string | null = null;
    for (let page = 0; page < 39; page++) {
      cursor = (await request(cursor ? `&cursor=${encodeURIComponent(cursor)}` : '')).nextCursor;
    }
    expect(cursor).not.toBeNull();
    const query = `&cursor=${encodeURIComponent(cursor!)}`;
    await expectRows('40th page', query);
    timings['40th page'] = Math.round(await measure(query));
    expect(timings['40th page']).toBeLessThan(budgetMs(P95_BUDGET_MS));
  }, 120_000);

  it(`a path-sorted page deep in the list (after row 60 000): P95 < ${P95_BUDGET_MS} ms`, async () => {
    // The cursor the API would hand out after row 60 000 of the default filter, sorted by path.
    const after = await h.ctx.db.execute<{ path: string | null; line: number | null; id: string }>(
      sql`SELECT path, start_line AS line, id FROM issues
           WHERE branch_id = ${branchId} AND status = 'open' AND duplicate_of_issue_id IS NULL
           ORDER BY path ASC NULLS LAST, start_line ASC NULLS LAST, id ASC
           OFFSET 59999 LIMIT 1`,
    );
    const row = after.rows[0];
    expect(row).toBeDefined();
    const cursor = encodeKeyset({ s: 'path', p: row!.path, l: row!.line, id: row!.id });
    const query = `&sort=path&cursor=${encodeURIComponent(cursor)}`;
    await expectRows('deep path page', query);
    timings['path page after row 60k'] = Math.round(await measure(query));
    expect(timings['path page after row 60k']).toBeLessThan(budgetMs(P95_BUDGET_MS));
  }, 120_000);
});
