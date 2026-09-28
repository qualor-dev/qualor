import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { issues } from '../db/schema';
import { issueSortPlan, listIssues, type IssueFilters } from './query';

describe('path-sorted issue pages read one snapshot (E1 wave)', () => {
  let h: IngestHarness;
  let filters: IssueFilters;
  let moving: string;
  let cursor: string;

  beforeAll(async () => {
    h = await createIngestHarness();
    const project = await h.project('acme/snapshot');
    const branchId = await mainBranchId(h.ctx.db, project.id);
    const ruleId = await seedRule(h.ctx.db, { key: 'eslint:no-snapshot' });
    const base = { projectId: project.id, branchId, ruleId };
    await seedIssue(h.ctx.db, { ...base, path: 'src/b.ts', startLine: 1 });
    moving = await seedIssue(h.ctx.db, { ...base, path: 'src/b.ts', startLine: 5 });
    filters = { branchId, statuses: ['open'], includeDuplicates: false };
    const firstPage = await listIssues(h.ctx.db, filters, {
      plan: issueSortPlan('path', undefined),
      limit: 1,
    });
    cursor = firstPage.nextCursor!;
  });
  afterAll(async () => {
    await h.close();
  });

  it('never returns an issue twice when it moves between segments during the page', async () => {
    // The page after `src/b.ts:1` reads `src/b.ts` lines after 1, then paths after `src/b.ts`.
    // Between those reads, the issue on line 5 moves to `src/c.ts`: read without one snapshot,
    // the second segment would return it again.
    const plan = issueSortPlan('path', cursor);
    expect(plan.segments.length).toBeGreaterThan(1);
    let moved = false;
    const page = await listIssues(h.ctx.db, filters, {
      plan,
      limit: 10,
      afterSegment: async () => {
        if (moved) return;
        moved = true;
        await h.ctx.db.update(issues).set({ path: 'src/c.ts' }).where(eq(issues.id, moving));
      },
    });
    expect(moved).toBe(true);
    expect(page.items.map((i) => i.id)).toEqual([moving]);
    expect(page.items[0]!.path).toBe('src/b.ts');
  });
});
