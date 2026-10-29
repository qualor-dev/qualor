import { randomUUID } from 'node:crypto';
import { eq, sql, type SQL } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { configuredProvider } from '../../test/llm';
import { switchReviewOn } from '../../test/review';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { first } from '../db/rows';
import {
  analyses,
  llmRequests,
  organizations,
  projects,
  reviewFindings,
  reviewReplies,
  reviewRuns,
  scmConnections,
  type LlmRequestFeature,
  type ReviewRunStatus,
} from '../db/schema';
import {
  DEFAULT_LLM_SETTINGS,
  readLlmSettings,
  writeLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import { SCM_TOKEN_AAD } from '../scm/connections';
import { collectAiReviewUsage, collectAssistantUsage } from './ai-review';
import { collectTelemetry, type TelemetryPayloadV3 } from './collect';
import { installationId } from './installation-id';

/** Every name, host and model of this test: none of them may reach the report (Review Focus 2). */
const NAMED = /secret-host|secret-standard|secret-strong|secret-team|secret-project|llm\./;
const NOW = sql`now()`;
const OLD = sql`now() - interval '31 days'`;
const SHA = 'a'.repeat(40);
/** Columns of a row to insert, a time as SQL on the database's clock. */
type Columns<T> = { [K in keyof T]?: T[K] | SQL };

describe('telemetry schema 2: AI review and the assistant (telemetry.md, R39)', () => {
  let fake: FakeLlm;
  let h: IngestHarness;
  let p: IngestProject;
  let branchId: string;
  let ruleId: string;
  let note = 0;
  const nextNoteId = () => {
    note += 1;
    return note;
  };

  /** The report, which is schema 3 whenever the server could count its use. */
  const collect = async (): Promise<TelemetryPayloadV3> => {
    const payload = await collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: await installationId(h.ctx.db),
      database: 'external',
      env: {},
      dockerEnvExists: false,
    });
    if (payload.schema !== 3) throw new Error(`a report of schema ${payload.schema}`);
    return payload;
  };
  /** An OpenAI provider on the Responses API, with a strong model of its own and no fast one. */
  const provider = (): StoredProvider => ({
    ...configuredProvider(h.ctx.config.secretKey, fake),
    kind: 'openai',
    api: 'responses',
    baseUrl: 'https://llm.secret-host.test/v1',
    model: 'secret-standard',
    strongModel: 'secret-strong',
    fastModel: null,
  });
  const reasonOf = (status: ReviewRunStatus): 'draft' | 'internal' | null => {
    if (status === 'skipped') return 'draft';
    return status === 'failed' ? 'internal' : null;
  };
  const run = async (status: ReviewRunStatus, finishedAt: SQL | null) => {
    const analysisId = first(
      await h.ctx.db.insert(analyses).values({ projectId: p.id }).returning(),
    ).id;
    await h.ctx.db.insert(reviewRuns).values({
      projectId: p.id,
      branchId,
      analysisId,
      status,
      reason: reasonOf(status),
      deadlineAt: new Date(),
      startedAt: status === 'waiting' ? null : NOW,
      finishedAt,
    });
  };
  const finding = async (over: Columns<typeof reviewFindings.$inferInsert>) =>
    h.ctx.db.insert(reviewFindings).values({
      issueId: await seedIssue(h.ctx.db, { projectId: p.id, branchId, ruleId }),
      category: 'logic',
      body: 'secret-project: the loop never ends when the list is empty.',
      reviewedHeadSha: SHA,
      ...over,
    });
  const reply = (over: Columns<typeof reviewReplies.$inferInsert>) =>
    h.ctx.db.insert(reviewReplies).values({
      projectId: p.id,
      branchId,
      provider: 'gitlab',
      noteId: nextNoteId(),
      kind: 'reply',
      author: 'secret-team-member',
      status: 'done',
      finishedAt: NOW,
      ...over,
    });
  /** A request a person made; an automatic one (4E-3) has no user. */
  const request = (
    feature: LlmRequestFeature,
    createdAt: SQL = NOW,
    userId: string | null = h.ctx.adminId,
  ) =>
    h.ctx.db.insert(llmRequests).values({
      organizationId: h.organizationId,
      userId,
      projectId: p.id,
      feature,
      cacheKey: 'c'.repeat(64),
      provider: 'openai',
      providerHost: 'llm.secret-host.test',
      model: 'secret-standard',
      promptVersion: 'test-1',
      status: 'succeeded',
      inputSha256: 'd'.repeat(64),
      inputBytes: 10,
      fields: ['message'],
      createdAt,
    });

  beforeAll(async () => {
    fake = await createFakeLlm();
    h = await createIngestHarness();
    await h.ctx.db
      .update(organizations)
      .set({ key: 'secret-team', name: 'secret-team' })
      .where(eq(organizations.id, h.organizationId));
    p = await h.project('secret-project');
    branchId = await mainBranchId(h.ctx.db, p.id);
    ruleId = await seedRule(h.ctx.db, { key: 'ai:logic' });
    // reviewActive needs the project mapped to an SCM connection.
    const connection = first(
      await h.ctx.db
        .insert(scmConnections)
        .values({
          organizationId: h.organizationId,
          provider: 'gitlab',
          baseUrl: 'https://scm.secret-host.test',
          tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'x', SCM_TOKEN_AAD),
        })
        .returning(),
    );
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connection.id, scmProjectRef: 'secret-team/secret-project' })
      .where(eq(projects.id, p.id));

    for (const status of ['done', 'skipped', 'failed', 'superseded'] as const) {
      await run(status, NOW);
    }
    await run('done', OLD);
    await run('running', null);

    await finding({ anchorLine: 3, suggestion: { startLine: 3, endLine: 3, lines: ['x'] } });
    await finding({ anchorLine: 5 });
    await finding({});
    await finding({
      anchorLine: 7,
      suggestion: { startLine: 7, endLine: 7, lines: ['y'] },
      createdAt: OLD,
    });

    await reply({ outcome: 'answered', verdict: 'keep', answer: 'secret-project is fine here.' });
    await reply({ outcome: 'wont_fix', verdict: 'wont_fix', answer: 'Marked as won’t fix.' });
    await reply({ status: 'failed', reason: 'internal' });
    await reply({ kind: 'command', command: 'review', outcome: 'review_requested' });
    await reply({ kind: 'command', command: 'stop', outcome: 'not_available' });
    await reply({
      outcome: 'false_positive',
      verdict: 'false_positive',
      createdAt: OLD,
      finishedAt: OLD,
    });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() =>
    switchReviewOn(h.ctx.db, {
      secretKey: h.ctx.config.secretKey,
      fake,
      organizationId: h.organizationId,
      userId: h.ctx.adminId,
      over: { provider: provider() },
    }),
  );

  it('counts AI review use as numbers and flags, and names nothing (Review Focus 2)', async () => {
    const usage = await collectAiReviewUsage(h.ctx.db, await readLlmSettings(h.ctx.db));
    expect(usage).toEqual({
      organizations: 1,
      projects: 1,
      provider: 'openai_responses',
      tiers: { strong: true, fast: false },
      reviews30d: { done: 1, skipped: 1, failed: 1, superseded: 1 },
      findings30d: 3,
      inline30d: 2,
      suggestions30d: 1,
      replies30d: { answered: 2, statusChanges: 1 },
      commands30d: { review: 1, fix: 0, stop: 1 },
    });
    const payload = await collect();
    expect(payload.features.aiReview).toBe(true);
    expect(payload.aiReview).toEqual(usage);
    expect(JSON.stringify(payload)).not.toMatch(NAMED);
  });

  it('does not count an organisation that the settings outlive', async () => {
    const settings = await readLlmSettings(h.ctx.db);
    const own = settings.organizations[h.organizationId]!;
    await writeLlmSettings(h.ctx.db, {
      ...settings,
      organizations: { ...settings.organizations, [randomUUID()]: own },
    });
    const usage = await collectAiReviewUsage(h.ctx.db, await readLlmSettings(h.ctx.db));
    expect(usage.organizations).toBe(1);
    expect(usage.projects).toBe(1);
  });

  it('reports none and zeros without a provider', async () => {
    await writeLlmSettings(h.ctx.db, DEFAULT_LLM_SETTINGS);
    const usage = await collectAiReviewUsage(h.ctx.db, await readLlmSettings(h.ctx.db));
    expect(usage).toMatchObject({
      provider: 'none',
      organizations: 0,
      projects: 0,
      tiers: { strong: false, fast: false },
    });
    const payload = await collect();
    expect(payload.features).toMatchObject({ aiAssistant: false, aiReview: false });
    expect(payload.aiReview.provider).toBe('none');
  });

  it('names the kind of a provider whose address does not parse, and counts none of its organisations', async () => {
    const settings = await readLlmSettings(h.ctx.db);
    const usage = await collectAiReviewUsage(h.ctx.db, {
      ...settings,
      provider: { ...provider(), baseUrl: 'not an address' },
    });
    // organizationReviewInactive says `no_provider`: nothing could be sent to it.
    expect(usage).toMatchObject({
      provider: 'openai_responses',
      organizations: 0,
      projects: 0,
      tiers: { strong: true, fast: false },
    });
  });

  it('counts the assistant requests people made in 30 days by feature', async () => {
    await request('explain');
    await request('explain');
    await request('triage');
    await request('fix');
    await request('fix', NOW, null); // an automatic fix suggestion, which no person made
    await request('explain', OLD);
    for (let i = 0; i < 3; i += 1) await request('review');
    await request('review-reply');
    expect(await collectAssistantUsage(h.ctx.db)).toEqual({ explain: 2, triage: 1, fix: 1 });
    const payload = await collect();
    expect(payload.assistant30d).toEqual({ explain: 2, triage: 1, fix: 1 });
    expect(JSON.stringify(payload)).not.toMatch(NAMED);
  });

  it('counts a status change whose reply then failed or was skipped, never as answered', async () => {
    const usage = async () =>
      (await collectAiReviewUsage(h.ctx.db, await readLlmSettings(h.ctx.db))).replies30d;
    const before = await usage();
    // The model decided and the status changed; posting the answer then failed, or its thread went.
    await reply({
      status: 'failed',
      reason: 'internal',
      outcome: 'false_positive',
      verdict: 'false_positive',
    });
    await reply({
      status: 'skipped',
      reason: 'thread_gone',
      outcome: 'wont_fix',
      verdict: 'wont_fix',
    });
    expect(await usage()).toEqual({
      answered: before.answered,
      statusChanges: before.statusChanges + 2,
    });
  });
});
