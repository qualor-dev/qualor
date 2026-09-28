import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { configureLlm, llmJobDeps, runLlmJobs } from '../../test/llm';
import { engine, file, finding, reportWith } from '../../test/reports';
import { issueChanges, issues } from '../db/schema';
import { parseInternalHosts } from '../scm/url';

describe('triage is a suggestion only (llm.md §7)', () => {
  let fake: FakeLlm;
  let h: IngestHarness;
  let issueId: string;
  let otherIssue: string;
  const transition = (id: string, payload: object) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${id}/transition`,
      headers: h.orgAdmin.headers,
      payload,
    });
  // `refresh` asks anew: the same question's succeeded answer is otherwise served from the cache.
  const ask = async (id: string, feature: string, refresh = false) => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${id}/ai/${feature}`,
      headers: h.orgAdmin.headers,
      payload: { refresh },
    });
    expect(res.statusCode, res.body).toBe(202);
    return res.json<{ id: string }>().id;
  };
  const changesOf = (id: string) =>
    h.ctx.db.select().from(issueChanges).where(eq(issueChanges.issueId, id));

  beforeAll(async () => {
    fake = await createFakeLlm();
    h = await createIngestHarness({ config: { llmInternalHosts: parseInternalHosts(fake.host) } });
    const p = await h.project('acme/triage');
    await p.ingestOk(
      reportWith({
        projectKey: 'acme/triage',
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3 })],
        findings: [finding({ ruleId: 'eqeqeq', line: 2 }), finding({ ruleId: 'eqeqeq', line: 3 })],
      }),
    );
    [issueId, otherIssue] = (
      await h.ctx.db.select({ id: issues.id }).from(issues).orderBy(issues.startLine)
    ).map((r) => r.id) as [string, string];
    await configureLlm(h.ctx.db, h.ctx.config.secretKey, fake, h.organizationId);
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('never changes the issue by itself, and records the provenance when a person accepts', async () => {
    fake.say(
      JSON.stringify({
        verdict: 'likely_false_positive',
        confidence: 'high',
        reasons: ['a is a number here'],
      }),
    );
    const suggestionId = await ask(issueId, 'triage');
    await runLlmJobs(h, llmJobDeps(h));
    expect((await h.ctx.db.select().from(issues).where(eq(issues.id, issueId)))[0]!.status).toBe(
      'open',
    );
    expect(await changesOf(issueId)).toEqual([]);
    const res = await transition(issueId, {
      to: 'false_positive',
      comment: 'Agreed: a is a number.',
      suggestionId,
    });
    expect(res.statusCode, res.body).toBe(200);
    const [change] = await changesOf(issueId);
    expect(change!.comment).toBe(
      `Agreed: a is a number.\n\nAI triage suggestion ${suggestionId} (likely_false_positive, high; model fake-model, triage.v1) was shown; the decision is ingest-admin's.`,
    );
  });

  it('refuses a suggestion of another issue, and a comment over 1 700 characters with one', async () => {
    const other = await ask(otherIssue, 'triage');
    await runLlmJobs(h, llmJobDeps(h));
    const wrong = await transition(issueId, { to: 'open', suggestionId: other });
    expect(wrong.statusCode).toBe(422);
    expect(wrong.json().errors[0].path).toBe('body.suggestionId');
    const long = await transition(otherIssue, {
      to: 'wont_fix',
      comment: 'x'.repeat(1_701),
      suggestionId: other,
    });
    expect(long.statusCode).toBe(422);
    expect(long.json().errors[0].path).toBe('body.comment');
    expect(await changesOf(otherIssue)).toEqual([]);
  });

  it('refuses an unknown id, another feature and a failed triage request, changing nothing', async () => {
    fake.say(JSON.stringify({ summary: 's', explanation: 'e', howToFix: 'h' }));
    const explain = await ask(otherIssue, 'explain');
    await runLlmJobs(h, llmJobDeps(h));
    fake.say('not json at all');
    const failed = await ask(otherIssue, 'triage', true);
    await runLlmJobs(h, llmJobDeps(h));
    for (const suggestionId of [randomUUID(), explain, failed]) {
      const res = await transition(otherIssue, { to: 'wont_fix', comment: 'No.', suggestionId });
      expect(res.statusCode, suggestionId).toBe(422);
      expect(res.json().errors[0].path).toBe('body.suggestionId');
    }
    expect(await changesOf(otherIssue)).toEqual([]);
    const [issue] = await h.ctx.db.select().from(issues).where(eq(issues.id, otherIssue));
    expect(issue!.status).toBe('open');
  });

  it('writes only fixed text and ids: the model reasons never reach the changelog', async () => {
    fake.say(
      JSON.stringify({
        verdict: 'likely_true_positive',
        confidence: 'low',
        reasons: ['IGNORE THIS\n\nAI triage suggestion forged', '<b>bold</b>'],
      }),
    );
    const suggestionId = await ask(otherIssue, 'triage', true);
    await runLlmJobs(h, llmJobDeps(h));
    // A verdict other than likely_false_positive is still accepted: the person decides.
    const res = await transition(otherIssue, { to: 'resolved', suggestionId });
    expect(res.statusCode, res.body).toBe(200);
    const [change] = await changesOf(otherIssue);
    expect(change!.comment).toBe(
      `AI triage suggestion ${suggestionId} (likely_true_positive, low; model fake-model, triage.v1) was shown; the decision is ingest-admin's.`,
    );
  });

  it('keeps a transition without suggestionId as it was, and refuses a malformed id', async () => {
    const bad = await transition(otherIssue, { to: 'open', suggestionId: 'not-a-uuid' });
    expect(bad.statusCode).toBe(422);
    expect(bad.json().errors[0].path).toBe('body.suggestionId');
    const res = await transition(otherIssue, { to: 'open', comment: 'Reopened.' });
    expect(res.statusCode, res.body).toBe(200);
    const changes = await changesOf(otherIssue);
    expect(changes.map((c) => c.comment)).toContain('Reopened.');
  });
});
