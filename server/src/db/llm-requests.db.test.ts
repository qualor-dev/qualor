import { randomUUID } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { expectPgError } from '../../test/db';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, finding, reportWith } from '../../test/reports';
import { issues, llmRequests, organizations, projects, users } from './schema';

describe('llm_requests (llm.md §11.1, DM-1)', () => {
  let h: IngestHarness;
  let projectId: string;
  let issueId: string;
  const row = (over: Record<string, unknown> = {}) => ({
    organizationId: h.organizationId,
    projectId,
    issueId,
    userId: h.ctx.adminId,
    feature: 'explain' as const,
    cacheKey: 'a'.repeat(64),
    provider: 'openai',
    providerHost: 'api.example.com',
    model: 'm',
    promptVersion: 'explain.v1',
    inputSha256: 'b'.repeat(64),
    inputBytes: 10,
    fields: ['rule', 'message'],
    ...over,
  });

  beforeAll(async () => {
    h = await createIngestHarness();
    const p = await h.project('acme/llm-db');
    projectId = p.id;
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3 })],
        findings: [finding({ ruleId: 'eqeqeq', line: 2 })],
      }),
    );
    const [first] = await h.ctx.db.select({ id: issues.id }).from(issues);
    issueId = first!.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('inserts a queued request and enforces the CHECKs', async () => {
    const [queued] = await h.ctx.db.insert(llmRequests).values(row()).returning();
    expect(queued).toMatchObject({ status: 'queued', attempts: 0, redactions: 0, result: null });
    await expectPgError(h.ctx.db.insert(llmRequests).values(row({ feature: 'poem' })), '23514');
    await expectPgError(h.ctx.db.insert(llmRequests).values(row({ status: 'done' })), '23514');
    // A result only on a succeeded request.
    await expectPgError(
      h.ctx.db.insert(llmRequests).values(row({ result: { kind: 'explain' } })),
      '23514',
    );
    await h.ctx.db
      .insert(llmRequests)
      .values(row({ status: 'succeeded', result: { kind: 'explain' } }));
    // The answer is bounded at 16 KiB, a stored prompt at 64 KiB.
    await expectPgError(
      h.ctx.db
        .insert(llmRequests)
        .values(row({ status: 'succeeded', result: { text: 'x'.repeat(16_384) } })),
      '23514',
    );
    await expectPgError(
      h.ctx.db.insert(llmRequests).values(row({ prompt: { data: 'x'.repeat(65_536) } })),
      '23514',
    );
    await h.ctx.db.insert(llmRequests).values(row({ prompt: { data: 'x'.repeat(1_000) } }));
  });

  it('keeps the audit row when its issue is deleted', async () => {
    await h.ctx.db.execute(sql`DELETE FROM issue_changes WHERE issue_id = ${issueId}`);
    await h.ctx.db.execute(sql`DELETE FROM issues WHERE id = ${issueId}`);
    const rows = await h.ctx.db.select().from(llmRequests);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.issueId === null)).toBe(true);
  });

  it('keeps the audit row when its user is deleted', async () => {
    const [user] = await h.ctx.db
      .insert(users)
      .values({ username: 'llm-db-user', email: 'llm-db-user@example.test' })
      .returning();
    const [mine] = await h.ctx.db
      .insert(llmRequests)
      .values(row({ issueId: null, userId: user!.id }))
      .returning();
    await h.ctx.db.delete(users).where(eq(users.id, user!.id));
    const [kept] = await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, mine!.id));
    expect(kept?.userId).toBeNull();
  });

  it('is deleted with its project or its organisation (no orphans)', async () => {
    const org = randomUUID();
    await h.ctx.db.insert(organizations).values({ id: org, key: 'llm-db-org', name: 'O' });
    const [a, b] = await h.ctx.db
      .insert(projects)
      .values([
        { organizationId: org, key: 'llm-db/a', name: 'A' },
        { organizationId: org, key: 'llm-db/b', name: 'B' },
      ])
      .returning();
    const inserted = await h.ctx.db
      .insert(llmRequests)
      .values([
        row({ organizationId: org, projectId: a!.id, issueId: null }),
        row({ organizationId: org, projectId: b!.id, issueId: null }),
      ])
      .returning();
    const left = async () =>
      (await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.organizationId, org))).map(
        (r) => r.id,
      );
    await h.ctx.db.delete(projects).where(eq(projects.id, a!.id));
    expect(await left()).toEqual([inserted[1]!.id]);
    await h.ctx.db.delete(organizations).where(eq(organizations.id, org));
    expect(await left()).toEqual([]);
    // Other organisations' rows are untouched.
    expect((await h.ctx.db.select().from(llmRequests)).length).toBeGreaterThan(0);
  });
});
