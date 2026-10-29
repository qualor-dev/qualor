import { gzipSync } from 'node:zlib';
import { encodeSnapshotLine, type SnapshotLine } from '@qualor/shared';
import { and, asc, eq, inArray, or, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab, type FakeMergeRequest } from '../../test/fake-gitlab';
import {
  anthropicToolUse,
  createFakeLlm,
  openAiToolCalls,
  type FakeLlm,
  type LlmResponder,
} from '../../test/fake-llm';
import { mappedGitHubProject, pullRequestReport } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { configuredProvider } from '../../test/llm';
import {
  REVIEW_CALL_USAGE,
  reviewResponder,
  reviewRoleOf,
  storeTestSnapshot,
  switchReviewOn,
  type ReviewScript,
} from '../../test/review';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  runDecorations,
  silentLogger,
} from '../../test/scm';
import { first } from '../db/rows';
import {
  analyses,
  branches,
  issues,
  jobs,
  llmRequests,
  reviewFindings,
  reviewRuns,
  reviewSnapshots,
  rules,
} from '../db/schema';
import { createLlmRuntime } from '../llm/job';
import { readLlmSettings, type StoredPricing, type StoredProvider } from '../llm/settings';
import { runUntilIdle, startWorker } from '../queue/worker';
import { markerOf } from '../scm/markdown';
import { enqueueLatestDecoration, lockBranchQueue, SCM_QUEUE } from '../scm/queue';
import { parseInternalHosts } from '../scm/url';
import { REVIEW_LEASE_MS, reviewHandlers, type ReviewJobDeps } from './job';
import { reviewTokensLeft } from './job-context';
import type { Running } from './job-start';
import { mergeRequestStateHandlers, REVIEW_MR_STATE_QUEUE } from './lifecycle';
import { REVIEW_OUTPUT_TOKENS } from './pipeline';
import { AI_REVIEW_QUEUE, reconcileStuckReviewRuns, requestReviewRun } from './runs';
import type { ReviewBudgets } from './settings';
import { storeSnapshotUpload, unpackSnapshot } from './snapshot-store';
import { reviewUsageToday } from './usage';

const MiB = 1024 * 1024;
const LIMITS = { maxCompressedBytes: 50 * MiB, maxDecompressedBytes: 500 * MiB };
const GITLAB_PROJECT = 710;
const GITHUB_REPOSITORY = 9_710;
/** The head and base of `storeTestSnapshot`'s header. */
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const PRICING = {
  inputUsdPerMTok: 3,
  outputUsdPerMTok: 15,
  cachedInputUsdPerMTok: null,
  strong: null,
  fast: null,
};
/** The three models of a tiered provider: the standard one is the fake's `fake-model`. */
const TIERS = { strongModel: 'strong-model', fastModel: 'fast-model' };
/** A dear strong model, and a cheap fast one beside the standard model of PRICING. */
const TIER_PRICING = {
  ...PRICING,
  strong: { inputUsdPerMTok: 15, outputUsdPerMTok: 75, cachedInputUsdPerMTok: null },
  fast: { inputUsdPerMTok: 1, outputUsdPerMTok: 5, cachedInputUsdPerMTok: null },
};
/** What each call of `reviewResponder` costs at a model's prices: its 1 000 tokens in and 100 out. */
const callCost = (prices: { inputUsdPerMTok: number; outputUsdPerMTok: number }): number =>
  REVIEW_CALL_USAGE.input * prices.inputUsdPerMTok +
  REVIEW_CALL_USAGE.output * prices.outputUsdPerMTok;
const revision = (n: number) => String(n % 10).repeat(40);

/** The patch of a file the merge request adds, of these lines. */
const addedPatch = (lines: readonly string[]): string => {
  const rows = lines.map((line) => `+${line}`);
  return `@@ -0,0 +1,${lines.length} @@\n${rows.join('\n')}\n`;
};

const CART_LINES = [
  'export function total(items: number[]): number {',
  '  let sum = 0;',
  '  for (let i = 0; i < items.length - 1; i += 1) sum += items[i];',
  '  return sum;',
  '}',
];
const CART = `${CART_LINES.join('\n')}\n`;
/** A merge request that adds one small file: a trivial change, which one reviewer and the judge read. */
const CHANGE: SnapshotLine[] = [
  {
    type: 'change',
    path: 'src/cart.ts',
    oldPath: null,
    status: 'added',
    patch: addedPatch(CART_LINES),
    since: null,
  },
  { type: 'file', path: 'src/cart.ts', text: CART },
];
const FINDING = {
  category: 'logic',
  severity: 'major',
  confidence: 'high',
  path: 'src/cart.ts',
  line: 3,
  endLine: 3,
  title: 'The loop skips the last item',
  body: 'The loop stops one item early, so the last item is never added to the sum.',
};
/**
 * A merge request that adds a few lines on a path that looks security-sensitive: a trivial review,
 * which a security reviewer joins at any size.
 */
const LOGIN_LINES = [
  'export function isGuest(name: string): boolean {',
  "  return name === '';",
  '}',
];
const LOGIN: SnapshotLine[] = [
  {
    type: 'change',
    path: 'src/auth/login.ts',
    oldPath: null,
    status: 'added',
    patch: addedPatch(LOGIN_LINES),
    since: null,
  },
  { type: 'file', path: 'src/auth/login.ts', text: `${LOGIN_LINES.join('\n')}\n` },
];
/** A merge request that adds a file of 320 lines: a full review, with every specialist. */
const BIG_LINES = Array.from({ length: 320 }, (_, i) => `export const value${i + 1} = ${i + 1};`);
const BIG: SnapshotLine[] = [
  {
    type: 'change',
    path: 'src/big.ts',
    oldPath: null,
    status: 'added',
    patch: addedPatch(BIG_LINES),
    since: null,
  },
  { type: 'file', path: 'src/big.ts', text: `${BIG_LINES.join('\n')}\n` },
];
/** The judge keeps a serious security finding of it, which the verification then checks. */
const BIG_FINDING = {
  category: 'security',
  severity: 'major',
  confidence: 'high',
  path: 'src/big.ts',
  line: 3,
  endLine: 3,
  title: 'A secret is built into the code',
  body: 'The constant is a fixed value that should come from the configuration.',
};
const BIG_FOUND: ReviewScript = {
  judge: JSON.stringify({
    findings: [{ ...BIG_FINDING, sources: [] }],
    dropped: [],
    prior: [],
    summary: { verdict: 'One security problem.', walkthrough: ['Adds constants.'] },
  }),
};
const FOUND: ReviewScript = {
  quality: JSON.stringify({ findings: [FINDING] }),
  judge: JSON.stringify({
    findings: [{ ...FINDING, sources: ['s1'] }],
    dropped: [],
    prior: [],
    summary: { verdict: 'One logic problem in the cart total.', walkthrough: ['Adds a total.'] },
  }),
};

/**
 * A reviewer's answer, `text`, that waits to be let go: `reached` is settled when the call arrives
 * at the provider, and `release` lets it answer.
 */
const held = (text: string) => {
  let arrived!: () => void;
  let free!: () => void;
  const reached = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  const freed = new Promise<void>((resolve) => {
    free = resolve;
  });
  return {
    reached,
    release: free,
    answer: async () => {
      arrived();
      await freed;
      return text;
    },
  };
};

describe('the ai-review job (6I-3, R15)', () => {
  let llm: FakeLlm;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let h: IngestHarness;
  let p: IngestProject;
  /** Mapped to a repository of the fake GitHub. */
  let gh: IngestProject;
  let iid = 0;
  /** Every line the job logged. */
  const logged: unknown[][] = [];
  const logger = {
    info: (...args: unknown[]) => void logged.push(['info', ...args]),
    warn: (...args: unknown[]) => void logged.push(['warn', ...args]),
    error: (...args: unknown[]) => void logged.push(['error', ...args]),
  };

  const reviewOn = (
    o: {
      budgets?: Partial<ReviewBudgets>;
      pricing?: StoredPricing;
      /** The strong and the fast model of the provider; without them it has the standard model alone. */
      tiers?: Pick<StoredProvider, 'strongModel' | 'fastModel'>;
      /** The model's context window, in tokens; without it the provider has none set. */
      window?: number;
    } = {},
  ) =>
    switchReviewOn(h.ctx.db, {
      secretKey: h.ctx.config.secretKey,
      fake: llm,
      organizationId: h.organizationId,
      userId: h.ctx.adminId,
      ...(o.budgets === undefined ? {} : { budgets: o.budgets }),
      over: {
        pricing: o.pricing ?? null,
        ...(o.tiers === undefined && o.window === undefined
          ? {}
          : {
              provider: {
                ...configuredProvider(h.ctx.config.secretKey, llm),
                ...o.tiers,
                contextWindowTokens: o.window ?? null,
              },
            }),
      },
    });
  /** The organisation switches AI review off; everything else stays as it is. */
  const reviewOff = () =>
    h.ctx.db.execute(
      sql`UPDATE instance_settings
             SET value = jsonb_set(value, ${`{organizations,${h.organizationId},review,enabled}`}::text[], 'false')
           WHERE key = 'llm'`,
    );
  /** A merge request of its own on the fake GitLab: open, and no draft, unless `over` says so. */
  const mergeRequest = (over: Partial<FakeMergeRequest> = {}): number => {
    iid += 1;
    gitlab.addMergeRequest(GITLAB_PROJECT, {
      iid,
      title: 'Add the cart total',
      state: 'opened',
      sourceBranch: `feature/${iid}`,
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [],
      ...over,
    });
    return iid;
  };
  /** The merge request's analysis, ingested: its run waits for a snapshot. */
  const analysisOf = (mr: number, n = 1) =>
    p.ingestOk(
      mergeRequestReport(mr, revision(n), {
        projectKey: p.key,
        gitlab: { projectId: String(GITLAB_PROJECT) },
        analysisDate: `2026-10-0${n}T10:00:00Z`,
      }),
    );
  const snapshotOf = (analysisId: string, mr: number, lines: SnapshotLine[] = CHANGE) =>
    storeTestSnapshot(h.ctx.db, analysisId, lines, {
      mergeRequest: { id: String(mr), title: 'Add the cart total', description: null },
    });
  const runOf = async (analysisId: string) =>
    first(await h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.analysisId, analysisId)));
  const jobDeps = (over: Partial<ReviewJobDeps> = {}): ReviewJobDeps => ({
    db: h.ctx.db,
    config: h.ctx.config,
    logger,
    llmCircuit: createLlmRuntime().circuit,
    scm: decorationDeps(h).scm,
    scmRuntime: decorationDeps(h).runtime,
    shutdown: new AbortController().signal,
    ...over,
  });
  /** Runs the `ai-review` jobs that are due, as its worker does. */
  const runReviews = (over: Partial<ReviewJobDeps> = {}) =>
    runUntilIdle(h.ctx.db, reviewHandlers(jobDeps(over)), silentLogger);
  /** The run's queued job is due now (as if its deadline had come). */
  const dueNow = (runId: string) =>
    h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${runId}`));
  /** The decorations queued for the analysis. */
  const decorationsOf = (analysisId: string) =>
    h.ctx.db
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, SCM_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'analysisId' = ${analysisId}`,
        ),
      );
  /** Forgets the decorations ingestion queued, so that only the job's are left to see. */
  const forgetDecorations = () => h.ctx.db.delete(jobs).where(eq(jobs.queue, SCM_QUEUE));
  const reviewCalls = () => llm.requests.filter((request) => reviewRoleOf(request) !== null);
  /** A responder that answers as `script` does after 5.5 s: past the least the assistant waits. */
  const slow =
    (script: ReviewScript): LlmResponder =>
    async (request) => ({ ...(await reviewResponder(script)(request)), delayMs: 5_500 });
  /** The rows of the review's provider calls, oldest first. */
  const reviewRows = () =>
    h.ctx.db
      .select()
      .from(llmRequests)
      .where(eq(llmRequests.feature, 'review'))
      .orderBy(asc(llmRequests.createdAt), asc(llmRequests.id));
  /**
   * Reviews a new merge request of `lines`, with `script` answering each of `calls` conversations
   * the review makes. Gives the run, the role and the model of every call the provider received,
   * and the rows the calls wrote, all in the order of the calls.
   */
  const reviewWith = async (lines: SnapshotLine[], script: ReviewScript, calls: number) => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr, lines);
    const before = { calls: reviewCalls().length, rows: (await reviewRows()).length };
    llm.enqueue(...Array.from({ length: calls }, () => reviewResponder(script)));
    expect(await runReviews()).toBe(1);
    return {
      run: await runOf(analysisId),
      sent: reviewCalls()
        .slice(before.calls)
        .map((request) => [reviewRoleOf(request), (request.json as { model: string }).model]),
      rows: (await reviewRows()).slice(before.rows),
    };
  };
  const aiIssuesOf = async (branchId: string) =>
    h.ctx.db
      .select({ issue: issues, finding: reviewFindings, ruleKey: rules.key })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .leftJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
      .where(and(eq(issues.branchId, branchId), eq(rules.engineId, 'ai')));
  const snapshotsOfBranch = async (branchId: string) =>
    h.ctx.db
      .select({ id: reviewSnapshots.id })
      .from(reviewSnapshots)
      .where(
        or(
          eq(reviewSnapshots.branchId, branchId),
          inArray(
            reviewSnapshots.analysisId,
            h.ctx.db
              .select({ id: analyses.id })
              .from(analyses)
              .where(eq(analyses.branchId, branchId)),
          ),
        ),
      );

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(gitlab.url).host},${new URL(github.url).host}`,
        ),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
    gitlab.addProject({ id: GITLAB_PROJECT, path: 'acme/review' });
    p = await mappedProject(h, gitlab, 'review/p', GITLAB_PROJECT);
    github.addRepository({
      id: GITHUB_REPOSITORY,
      owner: 'acme',
      name: 'reviewed',
      installationId: 710,
    });
    gh = await mappedGitHubProject(h, github, 'review/gh', 'acme/reviewed');
  });
  afterAll(async () => {
    await h.close();
    await gitlab.close();
    await github.close();
    await llm.close();
  });
  beforeEach(async () => {
    await reviewOn();
    logged.length = 0;
  });

  it('a full run with reviewResponder stores issues, writes usage on the run and queues decoration', async () => {
    await reviewOn({ pricing: PRICING });
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    const snapshotId = await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
    expect(await runReviews()).toBe(1);

    // One reviewer for a trivial change, then the judge.
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality', 'judge']);
    const run = await runOf(analysisId);
    const { input, output } = REVIEW_CALL_USAGE;
    expect(run).toMatchObject({
      status: 'done',
      phase: null,
      reason: null,
      snapshotId,
      headSha: HEAD,
      sinceSha: null,
      snapshotPartial: false,
      tier: 'trivial',
      reviewers: ['quality'],
      providerHost: llm.host,
      model: 'fake-model',
      modelCalls: 2,
      toolCalls: 0,
      inputTokens: 2 * input,
      outputTokens: 2 * output,
      costMicroUsd: 2 * (input * PRICING.inputUsdPerMTok + output * PRICING.outputUsdPerMTok),
      findingsNew: 1,
      findingsOpen: 1,
      findingsFixed: 0,
      summary: {
        verdict: 'One logic problem in the cart total.',
        walkthrough: ['Adds a total.'],
        notes: [],
      },
      startedAt: expect.any(Date),
      finishedAt: expect.any(Date),
    });
    expect(run.diffDigest).toMatch(/^[0-9a-f]{64}$/);
    const stored = await aiIssuesOf(run.branchId);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({
      ruleKey: 'ai:logic',
      issue: { path: 'src/cart.ts', startLine: 3, severity: 'medium', status: 'open' },
      finding: { runId: run.id, anchorLine: 3, reviewedHeadSha: HEAD },
    });
    // Every call is a row of its own feature.
    const rows = await h.ctx.db
      .select({ feature: llmRequests.feature, projectId: llmRequests.projectId })
      .from(llmRequests)
      .where(eq(llmRequests.feature, 'review'));
    expect(rows.filter((row) => row.projectId === p.id).length).toBeGreaterThanOrEqual(2);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    // Nothing of the repository or of the model's words is logged.
    const log = JSON.stringify(logged);
    expect(log).toContain(run.id);
    for (const text of [CART_LINES[2]!, FINDING.title, FINDING.body]) {
      expect(log).not.toContain(text);
    }
  });

  it('stores the same findings and rows from streamed answers as from answers that are not streamed', async () => {
    // The same review twice: through the fake, which streams its answers, and through a fake that
    // will not stream, so that each call is asked once more without it.
    const PER_RUN = new Set([
      'id',
      'projectId',
      'branchId',
      'analysisId',
      'snapshotId',
      'providerHost',
      'deadlineAt',
      'createdAt',
      'updatedAt',
      'startedAt',
      'finishedAt',
    ]);
    const unstreaming = await createFakeLlm({ refuseStream: true });
    try {
      const config = {
        ...h.ctx.config,
        llmInternalHosts: parseInternalHosts(`${llm.host},${unstreaming.host}`),
      };
      const review = async (fake: FakeLlm) => {
        await switchReviewOn(h.ctx.db, {
          secretKey: h.ctx.config.secretKey,
          fake,
          organizationId: h.organizationId,
          userId: h.ctx.adminId,
          over: { pricing: PRICING },
        });
        const mr = mergeRequest();
        const analysisId = await analysisOf(mr);
        await snapshotOf(analysisId, mr);
        const before = { requests: fake.requests.length, rows: (await reviewRows()).length };
        fake.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
        expect(await runReviews({ config })).toBe(1);
        // The run, but for what is the merge request's own, where the fake listened, and when.
        const ran = await runOf(analysisId);
        const run = Object.fromEntries(
          Object.entries(ran).filter(([field]) => !PER_RUN.has(field)),
        );
        const found = (await aiIssuesOf(ran.branchId)).map(({ issue, finding, ruleKey }) => ({
          ruleKey,
          issue: {
            path: issue.path,
            startLine: issue.startLine,
            endLine: issue.endLine,
            message: issue.message,
            severity: issue.severity,
            status: issue.status,
            confidence: issue.confidence,
          },
          finding: finding && {
            category: finding.category,
            body: finding.body,
            assumption: finding.assumption,
            verification: finding.verification,
            suggestion: finding.suggestion,
            anchorLine: finding.anchorLine,
            reviewedHeadSha: finding.reviewedHeadSha,
          },
        }));
        const rows = (await reviewRows()).slice(before.rows).map((row) => ({
          feature: row.feature,
          provider: row.provider,
          model: row.model,
          promptVersion: row.promptVersion,
          status: row.status,
          errorCode: row.errorCode,
          attempts: row.attempts,
          redactions: row.redactions,
          inputTokens: row.inputTokens,
          outputTokens: row.outputTokens,
          costMicroUsd: row.costMicroUsd,
        }));
        const streamed = fake.requests
          .slice(before.requests)
          .map((request) => (request.json as { stream?: unknown }).stream === true);
        return { run, found, rows, streamed };
      };
      const streamed = await review(llm);
      const unstreamed = await review(unstreaming);
      expect(streamed.streamed).toEqual([true, true]);
      // The first call was refused its stream and asked again without it; the second, of the same
      // model, asked for none.
      expect(unstreamed.streamed).toEqual([true, false, false]);
      expect(streamed.run).toMatchObject({ status: 'done', modelCalls: 2, findingsNew: 1 });
      expect(streamed.found).toHaveLength(1);
      expect(streamed.rows).toHaveLength(2);
      expect(streamed.run).toEqual(unstreamed.run);
      expect(streamed.found).toEqual(unstreamed.found);
      expect(streamed.rows).toEqual(unstreamed.rows);
    } finally {
      await unstreaming.close();
    }
  });

  it("a review conversation's calls carry the markers, the fake reports reads from the second call on, and the run's cost prices them at the cached price (R49)", async () => {
    const caching = await createFakeLlm({ promptCache: true });
    try {
      const config = {
        ...h.ctx.config,
        llmInternalHosts: parseInternalHosts(`${llm.host},${caching.host}`),
      };
      // Fictional prices: 3 for input, 0.4 for cached input, 15 for output.
      const prices = { inputUsdPerMTok: 3, outputUsdPerMTok: 15, cachedInputUsdPerMTok: 0.4 };
      await switchReviewOn(h.ctx.db, {
        secretKey: h.ctx.config.secretKey,
        fake: caching,
        organizationId: h.organizationId,
        userId: h.ctx.adminId,
        over: {
          pricing: { ...prices, strong: null, fast: null },
          provider: configuredProvider(h.ctx.config.secretKey, caching, 'anthropic'),
        },
      });
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      // The quality reviewer reads the file before it answers: a conversation of two calls.
      const { input, output } = REVIEW_CALL_USAGE;
      const readsFirst: LlmResponder = async (request) =>
        reviewRoleOf(request) === 'quality'
          ? {
              status: 200,
              body: anthropicToolUse(
                [{ id: 'toolu_1', name: 'read_file', input: { path: 'src/cart.ts' } }],
                { usage: { input_tokens: input, output_tokens: output } },
              ),
            }
          : await reviewResponder(FOUND)(request);
      caching.enqueue(readsFirst, reviewResponder(FOUND), reviewResponder(FOUND));
      const before = logged.length;
      expect(await runReviews({ config })).toBe(1);

      const calls = caching.requests.filter((request) => reviewRoleOf(request) !== null);
      expect(calls.map(reviewRoleOf)).toEqual(['quality', 'quality', 'judge']);
      for (const call of calls) {
        expect(call.body.match(/"cache_control"/g)).toHaveLength(2);
        expect((call.json as { system: unknown }).system).toEqual([
          expect.objectContaining({ type: 'text', cache_control: { type: 'ephemeral' } }),
        ]);
      }
      // What each call said of the cache, in its log line: counts only.
      const counts = logged
        .slice(before)
        .filter((line) => line[2] === 'AI review call finished')
        .map((line) => line[1] as Record<string, number>);
      expect(counts).toHaveLength(3);
      const [opening, reread, judged] = counts;
      // The first call writes its prefix; the second reads it, and writes what it adds.
      expect(opening).toMatchObject({ cacheReadTokens: 0 });
      expect(opening!.cacheWriteTokens).toBeGreaterThan(0);
      expect(reread!.cacheReadTokens).toBe(opening!.cacheWriteTokens);
      expect(reread!.cacheWriteTokens).toBeGreaterThan(0);
      // The judge has a system prompt of its own: nothing of the reviewer's is read.
      expect(judged).toMatchObject({ cacheReadTokens: 0 });
      // Every prompt token is the call's input, and each is priced by what the cache did with it.
      const costOfCall = (c: Record<string, number>) =>
        Math.round(
          (c.inputTokens! - c.cacheReadTokens! - c.cacheWriteTokens!) * prices.inputUsdPerMTok +
            c.cacheWriteTokens! * prices.inputUsdPerMTok * 1.25 +
            c.cacheReadTokens! * prices.cachedInputUsdPerMTok +
            c.outputTokens! * prices.outputUsdPerMTok,
        );
      for (const c of counts) {
        expect(c.inputTokens).toBe(input + c.cacheReadTokens! + c.cacheWriteTokens!);
      }
      const rows = (await reviewRows()).filter((row) => row.projectId === p.id).slice(-3);
      expect(rows.map((row) => row.inputTokens)).toEqual(counts.map((c) => c.inputTokens));
      expect(rows.map((row) => row.costMicroUsd)).toEqual(counts.map(costOfCall));
      // The reads cost the cached price: less than the same tokens at the input price.
      expect(costOfCall(reread!)).toBeLessThan(
        reread!.inputTokens! * prices.inputUsdPerMTok + reread!.outputTokens! * 15,
      );
      const run = await runOf(analysisId);
      expect(run).toMatchObject({
        status: 'done',
        modelCalls: 3,
        toolCalls: 1,
        inputTokens: counts.reduce((sum, c) => sum + c.inputTokens!, 0),
        costMicroUsd: counts.reduce((sum, c) => sum + costOfCall(c), 0),
      });
    } finally {
      await caching.close();
    }
  });

  it('a review call waits past the assistant’s timeout', async () => {
    await reviewOn();
    // The assistant gives up after 5 s (the least it can be set to); the reviewer's call takes the
    // model 5.5 s.
    await h.ctx.db.execute(
      sql`UPDATE instance_settings
             SET value = jsonb_set(value, '{provider,timeoutSeconds}', '5')
           WHERE key = 'llm'`,
    );
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    llm.enqueue(slow(FOUND), reviewResponder(FOUND));
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({
      status: 'done',
      reason: null,
      modelCalls: 2,
      findingsNew: 1,
    });
  });

  it('a rejected snapshot ends the run as snapshot_rejected', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    const body = gzipSync(
      [
        {
          type: 'header',
          v: 1,
          headSha: HEAD,
          baseSha: BASE,
          sinceSha: null,
          targetBranch: 'main',
          mergeRequest: { id: String(mr), title: null, description: null },
          partial: false,
          generator: 'qualor-cli/test',
        },
        { type: 'file', path: '../escape.ts', text: 'x\n' },
        { type: 'end', files: 1, changes: 0, omitted: 0 },
      ]
        .map((line) => encodeSnapshotLine(line as SnapshotLine))
        .join(''),
    );
    const snapshotId = await storeSnapshotUpload(h.ctx.db, {
      analysisId,
      projectId: p.id,
      body,
      compressedBytes: body.length,
    });
    expect(await unpackSnapshot(h.ctx.db, snapshotId, LIMITS)).toBe('rejected');
    await forgetDecorations();
    // Woken by the rejection: it does not wait for its deadline.
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({
      status: 'skipped',
      reason: 'snapshot_rejected',
      detail: 'SNAPSHOT_INVALID',
      startedAt: null,
      finishedAt: expect.any(Date),
    });
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  });

  it('the deadline ends it as no_snapshot and a late snapshot restarts it', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    const waiting = await runOf(analysisId);
    await forgetDecorations();
    // Before its deadline a run without a snapshot waits on: its job comes back at the deadline.
    await dueNow(waiting.id);
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({ status: 'waiting', finishedAt: null });
    const [again] = await h.ctx.db
      .select({ runAt: jobs.runAt })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AI_REVIEW_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'runId' = ${waiting.id}`,
        ),
      );
    expect(again?.runAt).toEqual(waiting.deadlineAt);
    expect(await decorationsOf(analysisId)).toEqual([]);

    // At the deadline, still no snapshot.
    await dueNow(waiting.id);
    const late = new Date(waiting.deadlineAt.getTime() + 1_000);
    expect(await runReviews({ now: () => late })).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({
      status: 'skipped',
      reason: 'no_snapshot',
      finishedAt: expect.any(Date),
    });
    expect(await decorationsOf(analysisId)).toHaveLength(1);

    // The snapshot comes after all: the run waits again, with a new deadline, and is due at once.
    await forgetDecorations();
    await snapshotOf(analysisId, mr);
    const restarted = await runOf(analysisId);
    expect(restarted).toMatchObject({ status: 'waiting', reason: null, finishedAt: null });
    expect(restarted.deadlineAt.getTime()).toBeGreaterThanOrEqual(waiting.deadlineAt.getTime());
    llm.enqueue(reviewResponder(), reviewResponder());
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({ status: 'done', findingsNew: 0 });
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  });

  it('a merged merge request deletes the snapshots and ends the run as closed', async () => {
    for (const state of ['merged', 'closed'] as const) {
      const mr = mergeRequest({ state });
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      await forgetDecorations();
      const calls = reviewCalls().length;
      expect(await runReviews()).toBe(1);
      const run = await runOf(analysisId);
      expect([state, run.status, run.reason]).toEqual([state, 'skipped', 'closed']);
      expect(run.startedAt).toEqual(expect.any(Date));
      expect(await snapshotsOfBranch(run.branchId)).toEqual([]);
      expect(reviewCalls()).toHaveLength(calls);
      expect(await decorationsOf(analysisId)).toHaveLength(1);
    }
  });

  it('a draft is skipped', async () => {
    const mr = mergeRequest({ draft: true });
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({ status: 'skipped', reason: 'draft', headSha: HEAD });
    expect(reviewCalls()).toHaveLength(calls);
    // The snapshot stays: the merge request is still open.
    expect(await snapshotsOfBranch(run.branchId)).toHaveLength(1);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  });

  it('a draft is reviewed when a person asked for the run, and the next push is skipped as a draft again', async () => {
    const mr = mergeRequest({ draft: true });
    const first = await analysisOf(mr, 1);
    await snapshotOf(first, mr);
    expect(await runReviews()).toBe(1);
    const skipped = await runOf(first);
    expect(skipped).toMatchObject({ status: 'skipped', reason: 'draft', requestedBy: null });

    // `qualor review`: the same run waits again, asked for by a person.
    await h.ctx.db.transaction(async (tx) => {
      await lockBranchQueue(tx, skipped.branchId);
      await requestReviewRun(
        tx,
        { analysisId: first, projectId: p.id, branchId: skipped.branchId, requestedBy: 'octocat' },
        silentLogger,
      );
    });
    const calls = reviewCalls().length;
    llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
    expect(await runReviews()).toBe(1);
    expect(await runOf(first)).toMatchObject({
      status: 'done',
      reason: null,
      requestedBy: 'octocat',
      headSha: HEAD,
      findingsNew: 1,
    });
    expect(reviewCalls()).toHaveLength(calls + 2);

    // The next push is no request of anyone's: its run is skipped as a draft again.
    const second = await analysisOf(mr, 2);
    await snapshotOf(second, mr);
    expect(await runReviews()).toBe(1);
    expect(await runOf(second)).toMatchObject({
      status: 'skipped',
      reason: 'draft',
      requestedBy: null,
    });
    expect(reviewCalls()).toHaveLength(calls + 2);
  });

  it('a requested run is skipped as closed when its merge request is merged, draft or not', async () => {
    const mr = mergeRequest({ state: 'merged', draft: true });
    const analysisId = await analysisOf(mr, 1);
    await snapshotOf(analysisId, mr);
    await h.ctx.db
      .update(reviewRuns)
      .set({ requestedBy: 'octocat' })
      .where(eq(reviewRuns.analysisId, analysisId));
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({
      status: 'skipped',
      reason: 'closed',
      requestedBy: 'octocat',
    });
    expect(reviewCalls()).toHaveLength(calls);
  });

  it('a merge request the provider cannot be asked about is reviewed all the same', async () => {
    // No such merge request on the fake: GitLab answers 404, and the review goes on.
    const analysisId = await analysisOf(9_000);
    await snapshotOf(analysisId, 9_000);
    llm.enqueue(reviewResponder(), reviewResponder());
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({ status: 'done' });
  });

  it('an unchanged diff is skipped', async () => {
    const mr = mergeRequest();
    const first1 = await analysisOf(mr, 1);
    await snapshotOf(first1, mr);
    llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
    expect(await runReviews()).toBe(1);
    const done = await runOf(first1);
    expect(done.status).toBe('done');
    // A push that changes nothing the review reads (an amend, a rebase onto the same tree).
    const second = await analysisOf(mr, 2);
    await snapshotOf(second, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const skipped = await runOf(second);
    expect(skipped).toMatchObject({ status: 'skipped', reason: 'unchanged' });
    expect(skipped.diffDigest).toBe(done.diffDigest);
    expect(reviewCalls()).toHaveLength(calls);
    expect(await decorationsOf(second)).toHaveLength(1);
    // The first review's finding is left as it is.
    expect(await aiIssuesOf(done.branchId)).toHaveLength(1);
  });

  it('a spent budget is skipped', async () => {
    // The organisation's tokens of the day are used up.
    const used = await reviewUsageToday(h.ctx.db, h.organizationId);
    await reviewOn({ budgets: { tokensPerDay: used.tokens } });
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const spent = await runOf(analysisId);
    expect(spent).toMatchObject({ status: 'skipped', reason: 'budget_spent', detail: null });
    expect(spent.diffDigest).toMatch(/^[0-9a-f]{64}$/);
    // What is left of the day is too little for this change, which Tokens per review would hold:
    // the day's budget is what stops it, not the size of the change.
    await reviewOn({ budgets: { tokensPerDay: used.tokens + 1_000 } });
    const nearly = mergeRequest();
    const late = await analysisOf(nearly);
    await snapshotOf(late, nearly);
    expect(await runReviews()).toBe(1);
    expect(await runOf(late)).toMatchObject({
      status: 'skipped',
      reason: 'budget_spent',
      detail: null,
    });
    expect(reviewCalls()).toHaveLength(calls);
  });

  it('a review writes its spend after each conversation', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    // The quality reviewer answers; the judge, the second conversation, is held.
    const judge = held(FOUND.judge as string);
    llm.enqueue(
      reviewResponder({ quality: FOUND.quality }),
      reviewResponder({ judge: judge.answer }),
    );
    let job: Promise<number> | undefined;
    try {
      job = runReviews();
      await judge.reached;
      const during = await runOf(analysisId);
      expect(during.status).toBe('running');
      expect(during.inputTokens).toBe(REVIEW_CALL_USAGE.input);
      expect(during.outputTokens).toBe(REVIEW_CALL_USAGE.output);
      expect(during.modelCalls).toBe(1);
    } finally {
      judge.release();
      await Promise.allSettled([job]);
    }
    // The end writes the totals of both conversations.
    expect(await runOf(analysisId)).toMatchObject({
      status: 'done',
      inputTokens: 2 * REVIEW_CALL_USAGE.input,
      outputTokens: 2 * REVIEW_CALL_USAGE.output,
      modelCalls: 2,
    });
  });

  it('a review that starts while another of the organisation runs gets what the day has left less that one’s reservation', async () => {
    // Nothing else of the organisation is running.
    await h.ctx.db
      .update(reviewRuns)
      .set({ status: 'superseded', finishedAt: new Date() })
      .where(eq(reviewRuns.status, 'running'));
    const used = await reviewUsageToday(h.ctx.db, h.organizationId);
    // The day has 400 000 left; run A is running with 100 000 written, so 200 000 of its 300 000
    // are reserved.
    await reviewOn({ budgets: { tokensPerDay: used.tokens + 100_000 + 400_000 } });
    await h.ctx.db.insert(llmRequests).values({
      organizationId: h.organizationId,
      projectId: p.id,
      feature: 'review',
      cacheKey: 'c'.repeat(64),
      provider: 'openai',
      providerHost: 'api.example.com',
      model: 'm',
      promptVersion: 'review-1',
      status: 'succeeded',
      inputSha256: 'd'.repeat(64),
      inputBytes: 10,
      fields: ['review'],
      inputTokens: 100_000,
      outputTokens: 0,
    });
    const startedRun = async () => {
      const analysisId = await analysisOf(mergeRequest());
      const run = await runOf(analysisId);
      await h.ctx.db
        .update(reviewRuns)
        .set({ status: 'running', phase: 'specialists', startedAt: new Date() })
        .where(eq(reviewRuns.id, run.id));
      return runOf(analysisId);
    };
    try {
      const runA = await startedRun();
      await h.ctx.db
        .update(reviewRuns)
        .set({ inputTokens: 80_000, outputTokens: 20_000 })
        .where(eq(reviewRuns.id, runA.id));
      const runB = await startedRun();
      const settings = await readLlmSettings(h.ctx.db);
      const left = (run: typeof runB) =>
        reviewTokensLeft(h.ctx.db, {
          run,
          settings,
          organizationId: h.organizationId,
        } as unknown as Running);
      expect(await left(runB)).toBe(200_000);
      // A, beside nothing that runs, has all the day left (up to Tokens per review).
      await h.ctx.db
        .update(reviewRuns)
        .set({ status: 'superseded', phase: null, finishedAt: new Date() })
        .where(eq(reviewRuns.id, runB.id));
      expect(await left(runA)).toBe(300_000);
    } finally {
      // Nothing is left running to reserve for the tests after this one, even when one fails.
      await h.ctx.db
        .update(reviewRuns)
        .set({ status: 'superseded', phase: null, finishedAt: new Date() })
        .where(eq(reviewRuns.status, 'running'));
    }
  });

  it('a merge request too large for Tokens per review is skipped as too large, and the summary says so', async () => {
    // The day has tokens left, but a review of 1 000 has no room for the first message of a
    // reviewer, even of this small change: it is not started.
    await reviewOn({ budgets: { maxTokensPerReview: 1_000 } });
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({ status: 'skipped', reason: 'budget_spent', detail: 'too_large' });
    expect(run.diffDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(reviewCalls()).toHaveLength(calls);
    // The summary names the budget to raise, not the day's.
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    await runDecorations(h, decorationDeps(h));
    const summary =
      gitlab
        .discussions(GITLAB_PROJECT, mr)
        .flatMap((d) => d.notes)
        .find((n) => markerOf(n.body)?.kind === 'summary')?.body ?? '';
    expect(summary).toContain(
      'AI review did not run because this merge request is too large for the Tokens per review budget; raise it in Settings → AI.',
    );
    expect(summary).not.toContain('token budget for today');
  });

  it('a review of a 150-file merge request runs, notes lists_shortened, and its first message has at most 200 changes with 3 ranges each', async () => {
    // 150 files of five ranges each, at the default 300 000 tokens per review: the lists of today
    // leave a reviewer no room (it was skipped as too large), shorter ones do.
    await reviewOn();
    const lines: SnapshotLine[] = [];
    for (let n = 0; n < 150; n += 1) {
      const path = `server/src/module${String(n).padStart(3, '0')}/handlers/some-file.ts`;
      const text = Array.from({ length: 60 }, (_, i) => `export const v${n}_${i + 1} = ${i + 1};`);
      const hunk = (at: number, k: number) =>
        [
          `@@ -${at - 1 - k},2 +${at - 1},3 @@`,
          ` ${text[at - 2]}`,
          `+${text[at - 1]}`,
          ` ${text[at]}`,
        ].join('\n');
      const patch = `${[3, 13, 23, 33, 43].map(hunk).join('\n')}\n`;
      lines.push(
        { type: 'change', path, oldPath: null, status: 'modified', patch, since: null },
        { type: 'file', path, text: `${text.join('\n')}\n` },
      );
    }
    const before = reviewCalls().length;
    const { run } = await reviewWith(lines, {}, 5);
    expect(run).toMatchObject({ status: 'done', tier: 'full', modelCalls: 5 });
    expect(run.summary).toMatchObject({ notes: ['lists_shortened'] });
    const first = reviewCalls()[before]!;
    const messages = (first.json as { messages: { role: string; content: string }[] }).messages;
    const user = messages.find((message) => message.role === 'user')!.content;
    const data = JSON.parse(user.split('\n')[2]!) as {
      changes: { lines: number[][]; unlistedLines?: number }[];
      unlistedChanges: number;
    };
    // Rung 1 exactly: 200 changes fit, so all 150 are listed, with 3 of their 5 ranges.
    expect(data.changes).toHaveLength(150);
    expect(data.unlistedChanges).toBe(0);
    for (const change of data.changes) {
      expect(change.lines).toHaveLength(3);
      expect(change.lines.length + (change.unlistedLines ?? 0)).toBe(5);
    }
  });

  it('a model with a 32 000-token window: no call passes it', async () => {
    // A local model's window (Review Focus 4).
    const window = 32_000;
    await reviewOn({ window });
    // A file of about 13 000 tokens beside the change, as the window guesses them. The quality
    // reviewer reads it three times in one turn, which no call of its may send in this window; the
    // judge reads 200 of its lines, which fit the call that wraps up and leave no room for another
    // turn as large.
    const large = Array.from(
      { length: 400 },
      (_, i) => `export const large${i} = '${'1'.repeat(64)}';`,
    );
    const lines: SnapshotLine[] = [
      ...CHANGE,
      { type: 'file', path: 'src/large.ts', text: `${large.join('\n')}\n` },
    ];
    const reads = (count: number, to?: number) =>
      Array.from({ length: count }, (_, i) => ({
        id: `read-${i}`,
        name: 'read_file',
        arguments: { path: 'src/large.ts', ...(to === undefined ? {} : { from: 1, to }) },
      }));
    const answers = reviewResponder(FOUND);
    const readsFirst: LlmResponder = (request) => {
      const role = reviewRoleOf(request);
      const { messages } = request.json as { messages: { role: string }[] };
      if (messages.some((message) => message.role === 'tool') || role === null) {
        return answers(request);
      }
      return {
        status: 200,
        body: openAiToolCalls(role === 'quality' ? reads(3) : reads(1, 200), {
          usage: {
            prompt_tokens: REVIEW_CALL_USAGE.input,
            completion_tokens: REVIEW_CALL_USAGE.output,
          },
        }),
      };
    };
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr, lines);
    const before = { calls: reviewCalls().length, rows: (await reviewRows()).length };
    llm.enqueue(...Array.from({ length: 4 }, () => readsFirst));
    expect(await runReviews()).toBe(1);

    const sent = reviewCalls().slice(before.calls);
    const rows = (await reviewRows()).slice(before.rows);
    expect(sent.map(reviewRoleOf)).toEqual(['quality', 'quality', 'judge', 'judge']);
    expect(rows).toHaveLength(sent.length);
    // Each call's input as the server records it, guessed at three bytes a token, as the window is
    // guarded: under the window less the role's answer.
    for (const [i, row] of rows.entries()) {
      const role = reviewRoleOf(sent[i]!)!;
      expect(Math.ceil(row.inputBytes / 3), `call ${i + 1}, ${role}`).toBeLessThan(
        window - REVIEW_OUTPUT_TOKENS[role],
      );
    }
    // The reviewer's reads were kept back; the judge's read was sent, and its wrap-up came after it.
    expect(sent[1]!.body).not.toContain('export const large1 ');
    expect(sent[1]!.body).toContain('context window is full');
    expect(sent[3]!.body).toContain('export const large1 ');
    const run = await runOf(analysisId);
    expect(run).toMatchObject({ status: 'done', findingsNew: 1, toolCalls: 4 });
    expect(run.summary).toMatchObject({ notes: ['context_window_reached'] });
  });

  it('a merge request that cannot fit a small window is skipped budget_spent: window_too_small, and the summary says the window is the cause, not Tokens per review', async () => {
    // A window of 24 000 tokens, under the least that a change of one line needs (about 26 600):
    // the judge's answer and its prompt leave no room in its third for this small change, though
    // Tokens per review holds it many times over.
    await reviewOn({ window: 24_000 });
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'skipped',
      reason: 'budget_spent',
      detail: 'window_too_small',
    });
    expect(run.diffDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(reviewCalls()).toHaveLength(calls);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    await runDecorations(h, decorationDeps(h));
    const summary =
      gitlab
        .discussions(GITLAB_PROJECT, mr)
        .flatMap((d) => d.notes)
        .find((n) => markerOf(n.body)?.kind === 'summary')?.body ?? '';
    expect(summary).toContain(
      'AI review did not run because this merge request is too large for the model’s context window; raise Context window in the AI provider settings if the model takes more.',
    );
    expect(summary).not.toContain('Tokens per review');
    expect(summary).not.toContain('token budget for today');

    // Too large for Tokens per review as well, whatever the window: that is what it says then.
    await reviewOn({ window: 24_000, budgets: { maxTokensPerReview: 1_000 } });
    const both = mergeRequest();
    const late = await analysisOf(both);
    await snapshotOf(late, both);
    expect(await runReviews()).toBe(1);
    expect(await runOf(late)).toMatchObject({
      status: 'skipped',
      reason: 'budget_spent',
      detail: 'too_large',
    });
    expect(reviewCalls()).toHaveLength(calls);
  });

  describe("the review's time (REVIEW_TIME_BUDGET_MS)", () => {
    const MINUTE = 60_000;
    /** The summary note of the analysis' merge request, once its decoration ran. */
    const summaryOf = async (mr: number): Promise<string> => {
      await runDecorations(h, decorationDeps(h));
      return (
        gitlab
          .discussions(GITLAB_PROJECT, mr)
          .flatMap((d) => d.notes)
          .find((n) => markerOf(n.body)?.kind === 'summary')?.body ?? ''
      );
    };

    it('a review whose specialists used 60 % of its 45 minutes is done without the rest of them, and the summary notes the time limit', async () => {
      // A trivial change on a sensitive path: the security reviewer, then the quality reviewer.
      let at = Date.now();
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr, LOGIN);
      await forgetDecorations();
      const calls = reviewCalls().length;
      llm.enqueue(
        reviewResponder({
          security: () => {
            at += 27 * MINUTE;
            return JSON.stringify({ findings: [] });
          },
        }),
        reviewResponder(),
      );
      expect(await runReviews({ now: () => new Date(at) })).toBe(1);
      expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['security', 'judge']);
      const run = await runOf(analysisId);
      expect(run).toMatchObject({ status: 'done', reason: null, detail: null, modelCalls: 2 });
      expect(run.summary).toMatchObject({ notes: ['time_limit_reached'] });
      expect(await summaryOf(mr)).toContain(
        'The review reached its time limit, so it may have missed problems.',
      );
    });

    it('a review whose judge cannot answer within its 45 minutes fails: provider_error, time_limit, and the next push reviews again', async () => {
      let at = Date.now();
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      await forgetDecorations();
      const calls = reviewCalls().length;
      llm.enqueue(
        reviewResponder({
          quality: () => {
            at += 45 * MINUTE;
            return JSON.stringify({ findings: [FINDING] });
          },
        }),
      );
      expect(await runReviews({ now: () => new Date(at) })).toBe(1);
      // The judge is not asked once the time is up.
      expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
      const run = await runOf(analysisId);
      expect(run).toMatchObject({
        status: 'failed',
        reason: 'provider_error',
        detail: 'time_limit',
        findingsNew: 0,
        modelCalls: 1,
      });
      expect(logged).toContainEqual([
        'info',
        expect.objectContaining({ runId: run.id, status: 'failed', detail: 'time_limit' }),
        'AI review run ended',
      ]);
      const summary = await summaryOf(mr);
      expect(summary).toContain(
        'AI review failed because it ran out of time. The next push reviews again.',
      );
      expect(summary).not.toContain('returned an error');
    });

    it('QUALOR_AI_REVIEW_MAX_MINUTES sets the time instead: 90 minutes leave the same review in time', async () => {
      let at = Date.now();
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      llm.enqueue(
        reviewResponder({
          ...FOUND,
          quality: () => {
            at += 45 * MINUTE;
            return FOUND.quality as string;
          },
        }),
        reviewResponder(FOUND),
      );
      const config = { ...h.ctx.config, aiReviewMaxMinutes: 90 };
      expect(await runReviews({ config, now: () => new Date(at) })).toBe(1);
      const run = await runOf(analysisId);
      expect(run).toMatchObject({ status: 'done', findingsNew: 1 });
      expect(run.summary).toMatchObject({ notes: [] });
    });
  });

  it('a run superseded between two model calls stores nothing', async () => {
    const mr = mergeRequest();
    const older = await analysisOf(mr, 1);
    await snapshotOf(older, mr);
    let newer: string | undefined;
    // The quality reviewer answers once a newer push of the merge request has been ingested.
    llm.enqueue(
      reviewResponder({
        quality: async () => {
          newer = await analysisOf(mr, 2);
          return JSON.stringify({ findings: [FINDING] });
        },
      }),
    );
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    expect(newer).toBeDefined();
    const run = await runOf(older);
    expect(run).toMatchObject({ status: 'superseded', modelCalls: 1, findingsNew: 0 });
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
    // Only the newer analysis is decorated (its ingestion queued that); the job queued nothing.
    expect(await decorationsOf(older)).toEqual([]);
    expect(await decorationsOf(newer!)).toHaveLength(1);
    expect((await runOf(newer!)).status).toBe('waiting');
  });

  it('a job whose run was started again before its context was built writes no digest into it', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const { id: runId, branchId } = await runOf(analysisId);
    await forgetDecorations();
    // While the job reads the merge request's state, its lease is lost, the sweep ends its run, and
    // a person asks for the review again: the run waits for the job that comes next.
    gitlab.inject('GET', /\/merge_requests\/\d+$/, {
      status: 200,
      passThrough: true,
      before: async () => {
        await h.ctx.db
          .update(jobs)
          .set({ status: 'dead', lastError: 'lease expired' })
          .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${runId}`));
        await reconcileStuckReviewRuns(h.ctx.db, silentLogger);
        await h.ctx.db.transaction(async (tx) => {
          await lockBranchQueue(tx, branchId);
          await requestReviewRun(
            tx,
            { analysisId, projectId: p.id, branchId, requestedBy: 'octocat' },
            silentLogger,
          );
        });
        await h.ctx.db
          .update(jobs)
          .set({ runAt: sql`now() + interval '1 hour'` })
          .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), eq(jobs.status, 'queued')));
      },
    });
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    expect(reviewCalls().slice(calls)).toEqual([]);
    expect(await runOf(analysisId)).toMatchObject({
      status: 'waiting',
      startedAt: null,
      diffDigest: null,
    });
  });

  it('a job that lost its lease writes nothing into its run once another job has it again', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const { id: runId, branchId } = await runOf(analysisId);
    await forgetDecorations();
    const calls = reviewCalls().length;
    const first = held(
      JSON.stringify({ findings: [{ ...FINDING, title: 'Found by the first job' }] }),
    );
    const second = held(
      JSON.stringify({
        findings: [{ ...FINDING, line: 4, endLine: 4, title: 'Found by the second' }],
      }),
    );
    llm.enqueue(
      reviewResponder({ quality: first.answer }),
      reviewResponder({ quality: second.answer }),
    );
    let firstJob: Promise<number> | undefined;
    let secondJob: Promise<number> | undefined;
    try {
      // The first job's reviewer is in flight when its lease is lost: the job is gone for the queue,
      // the sweep ends its run, and a person asks for the review again.
      firstJob = runReviews();
      await first.reached;
      await h.ctx.db
        .update(jobs)
        .set({ status: 'dead', lastError: 'lease expired' })
        .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${runId}`));
      await reconcileStuckReviewRuns(h.ctx.db, silentLogger);
      expect(await runOf(analysisId)).toMatchObject({ status: 'failed', reason: 'internal' });
      await h.ctx.db.transaction(async (tx) => {
        await lockBranchQueue(tx, branchId);
        await requestReviewRun(
          tx,
          { analysisId, projectId: p.id, branchId, requestedBy: 'octocat' },
          silentLogger,
        );
      });
      // Another job starts the run again, and its reviewer is in flight too.
      secondJob = runReviews();
      await second.reached;
      const restarted = await runOf(analysisId);
      expect(restarted).toMatchObject({ status: 'running', phase: 'specialists', modelCalls: 0 });
      await forgetDecorations();

      // The first job's reviewer answers. It finds the run no longer its own: it asks the provider
      // nothing more, and writes no phase, no end, no spend and no store into the run.
      first.release();
      expect(await firstJob).toBe(1);
      expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality', 'quality']);
      expect(await runOf(analysisId)).toEqual(restarted);
      expect(await decorationsOf(analysisId)).toEqual([]);
      expect(await aiIssuesOf(branchId)).toEqual([]);

      // The second job reviews to the end, and its findings alone are stored.
      llm.enqueue(
        reviewResponder({
          judge: JSON.stringify({
            findings: [
              { ...FINDING, line: 4, endLine: 4, title: 'Found by the second', sources: ['s1'] },
            ],
            dropped: [],
            prior: [],
            summary: { verdict: 'One problem.', walkthrough: ['Adds a total.'] },
          }),
        }),
      );
      second.release();
      expect(await secondJob).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({
        status: 'done',
        requestedBy: 'octocat',
        modelCalls: 2,
        findingsNew: 1,
      });
      const stored = await aiIssuesOf(branchId);
      expect(stored).toHaveLength(1);
      expect(stored[0]).toMatchObject({ issue: { startLine: 4 }, finding: { runId } });
    } finally {
      first.release();
      second.release();
      await Promise.allSettled([firstJob, secondJob]);
    }
  });

  it('review switched off during the run stops it as inactive and stores nothing', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    // The judge answers once the organisation has switched review off: after the last call.
    llm.enqueue(
      reviewResponder(FOUND),
      reviewResponder({
        ...FOUND,
        judge: async () => {
          await reviewOff();
          return FOUND.judge as string;
        },
      }),
    );
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'skipped',
      reason: 'inactive',
      detail: 'review_disabled',
      modelCalls: 2,
      findingsNew: 0,
    });
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
    // Its end is decorated: the summary says the review did not run to the end.
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  });

  /**
   * The merge request is merged, and the hourly check of its snapshot, come due, deletes the copy
   * (what a decoration or another review would do on seeing the merge as well).
   */
  const mergeAndCheck = async (mr: number, branchId: string) => {
    gitlab.updateMergeRequest(GITLAB_PROJECT, mr, { state: 'merged' });
    await h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(
        and(
          eq(jobs.queue, REVIEW_MR_STATE_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'branchId' = ${branchId}`,
        ),
      );
    await runUntilIdle(h.ctx.db, mergeRequestStateHandlers(decorationDeps(h)), silentLogger);
    expect(await snapshotsOfBranch(branchId)).toEqual([]);
  };
  /** A run that stopped for its deleted snapshot stored nothing, and says so. */
  const expectStoppedForSnapshot = async (
    analysisId: string,
    modelCalls: number,
  ): Promise<void> => {
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'skipped',
      reason: 'closed',
      detail: 'snapshot_deleted',
      snapshotId: null,
      modelCalls,
      findingsNew: 0,
      finishedAt: expect.any(Date),
    });
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
    expect(
      await h.ctx.db
        .select({ issueId: reviewFindings.issueId })
        .from(reviewFindings)
        .where(eq(reviewFindings.runId, run.id)),
    ).toEqual([]);
    // Its end is decorated like any other, so that the summary leaves "in progress".
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  };

  it('a merge request merged during its review stops the run and stores nothing', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const { branchId } = await runOf(analysisId);
    await forgetDecorations();
    const calls = reviewCalls().length;
    // The quality reviewer answers once the copy it reads has been deleted.
    llm.enqueue(
      reviewResponder({
        quality: async () => {
          await mergeAndCheck(mr, branchId);
          return JSON.stringify({ findings: [FINDING] });
        },
      }),
    );
    expect(await runReviews()).toBe(1);
    // It stopped before the judge was asked, and stored nothing of what the reviewer said.
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
    await expectStoppedForSnapshot(analysisId, 1);
  });

  it('a merge request merged while the judge answers is found before anything is stored', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const { branchId } = await runOf(analysisId);
    await forgetDecorations();
    // The last call answers after the merge: the check that comes after it, before the store.
    llm.enqueue(
      reviewResponder(FOUND),
      reviewResponder({
        ...FOUND,
        judge: async () => {
          await mergeAndCheck(mr, branchId);
          return FOUND.judge as string;
        },
      }),
    );
    expect(await runReviews()).toBe(1);
    await expectStoppedForSnapshot(analysisId, 2);
  });

  it('a snapshot deleted after the last stop check is found by the store, which stores nothing', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    // The copy goes as the run turns to storing: after its last stop check, while its outcome is
    // prepared, before the store's transaction (the merge request merged in that second).
    await h.ctx.db.execute(sql`
      CREATE FUNCTION review_test_delete_when_storing() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.phase = 'storing' AND OLD.phase IS DISTINCT FROM 'storing' THEN
          DELETE FROM review_snapshots WHERE id = NEW.snapshot_id;
        END IF;
        RETURN NEW;
      END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER review_test_delete_when_storing AFTER UPDATE OF phase ON review_runs
         FOR EACH ROW EXECUTE FUNCTION review_test_delete_when_storing()`);
    try {
      llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
      expect(await runReviews()).toBe(1);
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER review_test_delete_when_storing ON review_runs`);
      await h.ctx.db.execute(sql`DROP FUNCTION review_test_delete_when_storing()`);
    }
    await expectStoppedForSnapshot(analysisId, 2);
  });

  it('a newer push while a run stores ends it superseded, with no decoration', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const { branchId } = await runOf(analysisId);
    // The newer push's analysis, as ingestion leaves it: a succeeded one on the same branch.
    const [newer] = await h.ctx.db
      .insert(analyses)
      .values({
        projectId: p.id,
        branchId,
        status: 'succeeded',
        revision: revision(2),
        baselineRevision: BASE,
        baselineStatus: 'ok',
        analysisDate: new Date('2026-10-02T10:00:00Z'),
        scannerVersion: '0.0.0',
        finishedAt: new Date(),
      })
      .returning({ id: analyses.id });
    await forgetDecorations();
    // The push is ingested as the run turns to storing: after its last stop check, before its store.
    // A run that stores is let finish (it is not superseded), so ingestion makes the newer analysis
    // the branch's newest and deletes the snapshots of the older ones, as the run's store finds out.
    await h.ctx.db.execute(sql`
      CREATE FUNCTION review_test_push_when_storing() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.phase = 'storing' AND OLD.phase IS DISTINCT FROM 'storing' THEN
          UPDATE branches
             SET last_analysis_id = (SELECT id FROM analyses
                                      WHERE branch_id = NEW.branch_id AND id <> NEW.analysis_id)
           WHERE id = NEW.branch_id;
          DELETE FROM review_snapshots WHERE id = NEW.snapshot_id;
        END IF;
        RETURN NEW;
      END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER review_test_push_when_storing AFTER UPDATE OF phase ON review_runs
         FOR EACH ROW EXECUTE FUNCTION review_test_push_when_storing()`);
    try {
      llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
      expect(await runReviews()).toBe(1);
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER review_test_push_when_storing ON review_runs`);
      await h.ctx.db.execute(sql`DROP FUNCTION review_test_push_when_storing()`);
    }
    const [branch] = await h.ctx.db
      .select({ newest: branches.lastAnalysisId })
      .from(branches)
      .where(eq(branches.id, branchId));
    expect(branch?.newest).toBe(newer!.id);
    expect(await snapshotsOfBranch(branchId)).toEqual([]);
    // Superseded, with what it spent, and nothing stored of what it read.
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'superseded',
      reason: null,
      detail: null,
      phase: null,
      snapshotId: null,
      modelCalls: 2,
      findingsNew: 0,
      finishedAt: expect.any(Date),
    });
    expect(await aiIssuesOf(branchId)).toEqual([]);
    // As every superseded run it is not decorated: the newer analysis has the decoration of its own.
    expect(await decorationsOf(analysisId)).toEqual([]);
    expect(logged).toContainEqual([
      'info',
      { runId: run.id, status: 'superseded', reason: null },
      'AI review run ended',
    ]);
    const [job] = await h.ctx.db
      .select({ status: jobs.status })
      .from(jobs)
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
    expect(job).toEqual({ status: 'succeeded' });
  });

  it('a waiting run whose analysis is no longer the newest is superseded', async () => {
    const mr = mergeRequest();
    const older = await analysisOf(mr, 1);
    const run = await runOf(older);
    // A newer push while review is off: no newer run supersedes this one.
    await reviewOff();
    const newer = await analysisOf(mr, 2);
    await reviewOn();
    await forgetDecorations();
    await dueNow(run.id);
    expect(await runReviews()).toBe(1);
    expect(await runOf(older)).toMatchObject({
      status: 'superseded',
      finishedAt: expect.any(Date),
    });
    expect(await decorationsOf(older)).toEqual([]);
    expect(
      await h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.analysisId, newer)),
    ).toEqual([]);
  });

  it('a run that ends after a newer push queues no decoration over the newer one', async () => {
    const mr = mergeRequest();
    const older = await analysisOf(mr, 1);
    const newer = await analysisOf(mr, 2);
    const { branchId } = await runOf(newer);
    const queued = await decorationsOf(newer);
    expect(queued).toHaveLength(1);
    expect(
      await enqueueLatestDecoration(h.ctx.db, { analysisId: older, branchId, gitlab: null }),
    ).toBe(false);
    expect(await decorationsOf(newer)).toEqual(queued);
    expect(await decorationsOf(older)).toEqual([]);
    expect(
      await enqueueLatestDecoration(h.ctx.db, { analysisId: newer, branchId, gitlab: null }),
    ).toBe(true);
    const again = await decorationsOf(newer);
    expect(again).toHaveLength(1);
    expect(again).not.toEqual(queued);
  });

  it('a crash ends the run as failed internal and still queues decoration', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    const snapshotId = await snapshotOf(analysisId, mr);
    // A stored snapshot the reader cannot read: a fault of the server, not of the scanner.
    await h.ctx.db
      .update(reviewSnapshots)
      .set({ instructions: sql`'{"not": "a list"}'::jsonb` })
      .where(eq(reviewSnapshots.id, snapshotId));
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'failed',
      reason: 'internal',
      phase: null,
      finishedAt: expect.any(Date),
    });
    expect(reviewCalls()).toHaveLength(calls);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    const failures = logged.filter(([level]) => level === 'error');
    expect(failures).toEqual([
      [
        'error',
        expect.objectContaining({ runId: run.id, errorClass: 'TypeError' }),
        expect.any(String),
      ],
    ]);
    // The job completed: it is never tried again into more spend.
    const [job] = await h.ctx.db
      .select({ status: jobs.status })
      .from(jobs)
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
    expect(job).toEqual({ status: 'succeeded' });

    // A run its job finds running already was left so by a job that died: it ends failed too,
    // and what that job wrote of its spend stays (this job spent nothing).
    const other = mergeRequest();
    const crashed = await analysisOf(other);
    const stuck = await runOf(crashed);
    const spent = {
      providerHost: llm.host,
      model: 'fake-model',
      modelCalls: 3,
      toolCalls: 1,
      inputTokens: 3_000,
      outputTokens: 300,
      costMicroUsd: 13_500,
    };
    await h.ctx.db
      .update(reviewRuns)
      .set({ status: 'running', startedAt: new Date(), headSha: HEAD, ...spent })
      .where(eq(reviewRuns.id, stuck.id));
    await dueNow(stuck.id);
    await forgetDecorations();
    expect(await runReviews()).toBe(1);
    expect(await runOf(crashed)).toMatchObject({
      status: 'failed',
      reason: 'internal',
      ...spent,
    });
    expect(await decorationsOf(crashed)).toHaveLength(1);
  });

  it('a failure before the run starts leaves it as it was for the second try: an end and its decoration are one step', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const run = await runOf(analysisId);
    await forgetDecorations();
    // Review is off when the job decides: it ends the run, and the decoration it queues with that
    // end fails once, as a database can.
    await reviewOff();
    await h.ctx.db.execute(sql`CREATE SEQUENCE review_test_fail_once`);
    await h.ctx.db.execute(sql`
      CREATE FUNCTION review_test_fail_once() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.queue = 'scm' AND nextval('review_test_fail_once') = 1 THEN
          RAISE EXCEPTION 'a transient failure' USING ERRCODE = '40001';
        END IF;
        RETURN NEW;
      END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER review_test_fail_once BEFORE INSERT ON jobs
         FOR EACH ROW EXECUTE FUNCTION review_test_fail_once()`);
    try {
      expect(await runReviews()).toBe(1);
      // Nothing of that step is kept: the run waits, undecorated, and its job is tried again.
      expect(await runOf(analysisId)).toMatchObject({ status: 'waiting', finishedAt: null });
      expect(await decorationsOf(analysisId)).toEqual([]);
      const [job] = await h.ctx.db
        .select({ status: jobs.status, attempts: jobs.attempts })
        .from(jobs)
        .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
      expect(job).toEqual({ status: 'queued', attempts: 1 });
      expect(logged).toContainEqual([
        'warn',
        { runId: run.id, errorClass: expect.any(String), code: '40001' },
        'AI review run not decided; its job is tried again',
      ]);
      expect(logged.filter(([level]) => level === 'error')).toEqual([]);
      // The second try decides it: ended, and decorated in the same step.
      await dueNow(run.id);
      expect(await runReviews()).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({
        status: 'skipped',
        reason: 'inactive',
        detail: 'review_disabled',
      });
      expect(await decorationsOf(analysisId)).toHaveLength(1);
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER review_test_fail_once ON jobs`);
      await h.ctx.db.execute(sql`DROP FUNCTION review_test_fail_once()`);
      await h.ctx.db.execute(sql`DROP SEQUENCE review_test_fail_once`);
    }
  });

  it('an error before the run starts that comes again on its last try ends the run failed', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    const run = await runOf(analysisId);
    await forgetDecorations();
    // The run cannot start, on either try: its snapshot is gone under the start (23503) each time.
    await h.ctx.db.execute(sql`
      CREATE FUNCTION review_test_never_starts() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF OLD.status = 'waiting' AND NEW.status = 'running' THEN
          RAISE EXCEPTION 'the snapshot is gone' USING ERRCODE = '23503';
        END IF;
        RETURN NEW;
      END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER review_test_never_starts BEFORE UPDATE ON review_runs
         FOR EACH ROW EXECUTE FUNCTION review_test_never_starts()`);
    const notDecided = 'AI review run not decided; its job is tried again';
    const jobOfRun = async () =>
      first(
        await h.ctx.db
          .select({ status: jobs.status, attempts: jobs.attempts })
          .from(jobs)
          .where(
            and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`),
          ),
      );
    try {
      // The first try is tried again: such a race is over by the second, as a rule.
      expect(await runReviews()).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({ status: 'waiting', finishedAt: null });
      expect(await jobOfRun()).toEqual({ status: 'queued', attempts: 1 });
      expect(logged).toContainEqual([
        'warn',
        { runId: run.id, errorClass: expect.any(String), code: '23503' },
        notDecided,
      ]);
      // The last try fails as the first did: the run ends failed, with its decoration, rather than
      // be left to the sweep (which would say it had no snapshot), and the job completes.
      logged.length = 0;
      await dueNow(run.id);
      expect(await runReviews()).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({
        status: 'failed',
        reason: 'internal',
        startedAt: null,
        finishedAt: expect.any(Date),
      });
      expect(await decorationsOf(analysisId)).toHaveLength(1);
      expect(await jobOfRun()).toEqual({ status: 'succeeded', attempts: 2 });
      expect(logged.filter((line) => line[2] === notDecided)).toEqual([]);
      expect(logged).toContainEqual([
        'error',
        { runId: run.id, errorClass: expect.any(String), code: '23503' },
        'AI review run failed',
      ]);
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER review_test_never_starts ON review_runs`);
      await h.ctx.db.execute(sql`DROP FUNCTION review_test_never_starts()`);
    }
  });

  it('a provider changed during the run stops it before its next call', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    // The quality reviewer answers once the instance has moved to another model, with a consent
    // that names it: review is still on, but not with the provider the run started with (R10).
    llm.enqueue(
      reviewResponder({
        quality: async () => {
          await switchReviewOn(h.ctx.db, {
            secretKey: h.ctx.config.secretKey,
            fake: llm,
            organizationId: h.organizationId,
            userId: h.ctx.adminId,
            over: {
              pricing: null,
              provider: {
                ...configuredProvider(h.ctx.config.secretKey, llm),
                model: 'other-model',
              },
            },
          });
          return JSON.stringify({ findings: [FINDING] });
        },
      }),
    );
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'skipped',
      reason: 'inactive',
      detail: 'provider_changed',
      modelCalls: 1,
      model: 'fake-model',
      findingsNew: 0,
    });
    // The judge was never asked, of either model.
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
  });

  it.each([
    ['strong', { strongModel: 'other-strong-model' }],
    ['fast', { fastModel: 'other-fast-model' }],
  ])('a changed %s model during the run stops it before its next call', async (_tier, tier) => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    // The instance moves a tier to another model, with a consent that names the new set of models:
    // review is still on, but not with the provider the run started with.
    llm.enqueue(
      reviewResponder({
        quality: async () => {
          await switchReviewOn(h.ctx.db, {
            secretKey: h.ctx.config.secretKey,
            fake: llm,
            organizationId: h.organizationId,
            userId: h.ctx.adminId,
            over: {
              pricing: null,
              provider: { ...configuredProvider(h.ctx.config.secretKey, llm), ...tier },
            },
          });
          return JSON.stringify({ findings: [FINDING] });
        },
      }),
    );
    const calls = reviewCalls().length;
    expect(await runReviews()).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'skipped',
      reason: 'inactive',
      detail: 'provider_changed',
      modelCalls: 1,
      model: 'fake-model',
      findingsNew: 0,
    });
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
  });

  describe('model tiers', () => {
    const SPECIALISTS = ['security', 'quality', 'tests', 'performance'];

    it('the judge and the verification run on the strong model', async () => {
      await reviewOn({ pricing: TIER_PRICING, tiers: TIERS });
      const { run, sent } = await reviewWith(BIG, BIG_FOUND, 6);

      expect(run).toMatchObject({ status: 'done', tier: 'full', modelCalls: 6 });
      expect(sent).toEqual([
        ...SPECIALISTS.map((role) => [role, 'fake-model']),
        ['judge', 'strong-model'],
        ['verify', 'strong-model'],
      ]);
    });

    it("a trivial review's quality reviewer runs on the fast model", async () => {
      await reviewOn({ pricing: TIER_PRICING, tiers: TIERS });
      const { run, sent } = await reviewWith(CHANGE, FOUND, 2);

      expect(run).toMatchObject({ status: 'done', tier: 'trivial', modelCalls: 2 });
      expect(sent).toEqual([
        ['quality', 'fast-model'],
        ['judge', 'strong-model'],
      ]);
    });

    it("every llm_requests row names the model it called, and its cost uses that model's prices", async () => {
      await reviewOn({ pricing: TIER_PRICING, tiers: TIERS });
      const strong = callCost(TIER_PRICING.strong);
      const standard = callCost(TIER_PRICING);
      const fast = callCost(TIER_PRICING.fast);
      // Three prices, three costs: the model of each call is the one its row and its cost follow.
      expect(new Set([strong, standard, fast]).size).toBe(3);

      const full = await reviewWith(BIG, BIG_FOUND, 6);
      expect(full.rows.map((row) => row.model)).toEqual(full.sent.map(([, model]) => model));
      expect(full.rows.map((row) => row.costMicroUsd)).toEqual([
        standard,
        standard,
        standard,
        standard,
        strong,
        strong,
      ]);
      // The run's cost is the sum of its calls', each at its own model's prices, and it names the
      // standard model, as it always did.
      expect(full.run).toMatchObject({
        model: 'fake-model',
        modelCalls: 6,
        costMicroUsd: 4 * standard + 2 * strong,
      });

      const trivial = await reviewWith(CHANGE, FOUND, 2);
      expect(trivial.rows.map((row) => row.model)).toEqual(['fast-model', 'strong-model']);
      expect(trivial.rows.map((row) => row.costMicroUsd)).toEqual([fast, strong]);
      expect(trivial.run).toMatchObject({ model: 'fake-model', costMicroUsd: fast + strong });
    });

    it("the day's cost budget converts at the dearest price in use", async () => {
      // $2 are left of the review's cost budget today, whatever the other tests spent.
      const used = await reviewUsageToday(h.ctx.db, h.organizationId);
      const budgets = { costPerDayUsd: (used.costMicroUsd + 2_000_000) / 1_000_000 };

      // The strong model's output costs $300 for a million tokens: $2 buy 6 666 tokens, which is
      // too few for the smallest review, though the standard model's $15 would buy 133 333.
      await reviewOn({
        budgets,
        pricing: {
          ...TIER_PRICING,
          strong: { inputUsdPerMTok: 60, outputUsdPerMTok: 300, cachedInputUsdPerMTok: null },
        },
        tiers: TIERS,
      });
      const calls = reviewCalls().length;
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      expect(await runReviews()).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({
        status: 'skipped',
        reason: 'budget_spent',
        detail: null,
      });
      expect(reviewCalls()).toHaveLength(calls);

      // The same budget with the standard model's prices alone is enough for the same change.
      await reviewOn({ budgets, pricing: PRICING });
      const { run } = await reviewWith(CHANGE, FOUND, 2);
      expect(run).toMatchObject({ status: 'done', modelCalls: 2 });
    });

    it('with no tier models every call uses the standard model, as before', async () => {
      await reviewOn({ pricing: PRICING });
      const standard = callCost(PRICING);

      const full = await reviewWith(BIG, BIG_FOUND, 6);
      expect(full.sent).toEqual([...SPECIALISTS, 'judge', 'verify'].map((r) => [r, 'fake-model']));
      expect(full.rows.map((row) => row.model)).toEqual(Array(6).fill('fake-model'));
      expect(full.rows.map((row) => row.costMicroUsd)).toEqual(Array(6).fill(standard));
      expect(full.run).toMatchObject({ model: 'fake-model', costMicroUsd: 6 * standard });

      const trivial = await reviewWith(CHANGE, FOUND, 2);
      expect(trivial.sent).toEqual([
        ['quality', 'fake-model'],
        ['judge', 'fake-model'],
      ]);
      expect(trivial.run).toMatchObject({ model: 'fake-model', costMicroUsd: 2 * standard });
    });

    it('a trivial review of a sensitive path runs quality on the fast model and security on the standard one', async () => {
      await reviewOn({ pricing: TIER_PRICING, tiers: TIERS });
      const { run, sent, rows } = await reviewWith(LOGIN, {}, 3);

      expect(run).toMatchObject({
        status: 'done',
        tier: 'trivial',
        reviewers: ['security', 'quality'],
        modelCalls: 3,
      });
      expect(sent).toEqual([
        ['security', 'fake-model'],
        ['quality', 'fast-model'],
        ['judge', 'strong-model'],
      ]);
      expect(rows.map((row) => [row.model, row.costMicroUsd])).toEqual([
        ['fake-model', callCost(TIER_PRICING)],
        ['fast-model', callCost(TIER_PRICING.fast)],
        ['strong-model', callCost(TIER_PRICING.strong)],
      ]);
    });

    it('a call of the strong model waits past the assistant’s timeout too', async () => {
      await reviewOn({ pricing: TIER_PRICING, tiers: TIERS });
      // The assistant gives up after 5 s (the least it can be set to); the judge's call, on the
      // strong model, takes 5.5 s.
      await h.ctx.db.execute(
        sql`UPDATE instance_settings
               SET value = jsonb_set(value, '{provider,timeoutSeconds}', '5')
             WHERE key = 'llm'`,
      );
      const mr = mergeRequest();
      const analysisId = await analysisOf(mr);
      await snapshotOf(analysisId, mr);
      const calls = reviewCalls().length;
      llm.enqueue(reviewResponder(FOUND), slow(FOUND));

      expect(await runReviews()).toBe(1);
      expect(await runOf(analysisId)).toMatchObject({
        status: 'done',
        reason: null,
        modelCalls: 2,
        findingsNew: 1,
      });
      expect(
        reviewCalls()
          .slice(calls)
          .map((request) => [reviewRoleOf(request), (request.json as { model: string }).model]),
      ).toEqual([
        ['quality', 'fast-model'],
        ['judge', 'strong-model'],
      ]);
    });

    it('a model of its own with no prices gives its call a null cost and adds nothing to the run’s cost', async () => {
      // The settings API refuses this state, but a row can hold it: the strong model has no prices,
      // and its call is not costed at the standard model's, which are another model's.
      await reviewOn({ pricing: { ...TIER_PRICING, strong: null }, tiers: TIERS });
      const fast = callCost(TIER_PRICING.fast);

      const { run, rows } = await reviewWith(CHANGE, FOUND, 2);

      expect(rows.map((row) => [row.model, row.costMicroUsd])).toEqual([
        ['fast-model', fast],
        ['strong-model', null],
      ]);
      expect(run).toMatchObject({ status: 'done', modelCalls: 2, costMicroUsd: fast });
    });

    it('tier models set to the standard model change nothing either', async () => {
      await reviewOn({
        pricing: PRICING,
        tiers: { strongModel: 'fake-model', fastModel: 'fake-model' },
      });
      const { run, sent, rows } = await reviewWith(CHANGE, FOUND, 2);

      expect(sent).toEqual([
        ['quality', 'fake-model'],
        ['judge', 'fake-model'],
      ]);
      expect(rows.map((row) => row.model)).toEqual(['fake-model', 'fake-model']);
      expect(run).toMatchObject({ status: 'done', costMicroUsd: 2 * callCost(PRICING) });
    });
  });

  it('a server stop ends a running review at once', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    const rows = async () =>
      (await h.ctx.db.select({ id: llmRequests.id }).from(llmRequests)).length;
    const rowsBefore = await rows();
    // The quality reviewer's call is in flight when the server stops: the provider holds it.
    let asked!: () => void;
    const inFlight = new Promise<void>((resolve) => {
      asked = resolve;
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    llm.enqueue(async (request) => {
      asked();
      await held;
      return reviewResponder(FOUND)(request);
    });
    const circuit = createLlmRuntime().circuit;
    const shutdown = new AbortController();
    const worker = startWorker({
      db: h.ctx.db,
      handlers: reviewHandlers(jobDeps({ llmCircuit: circuit, shutdown: shutdown.signal })),
      concurrency: 1,
      leaseMs: REVIEW_LEASE_MS,
      pollIntervalMs: 20,
      logger: silentLogger,
    });
    try {
      await inFlight;
      // As main.ts stops: the signal first, then the wait for the worker.
      const stopping = Date.now();
      shutdown.abort();
      await worker.stop();
      // Well within a stop's grace period, and before the provider's own timeout of 5 s.
      expect(Date.now() - stopping).toBeLessThan(4_000);
    } finally {
      release();
    }
    const run = await runOf(analysisId);
    expect(run).toMatchObject({
      status: 'failed',
      reason: 'internal',
      phase: null,
      finishedAt: expect.any(Date),
      findingsNew: 0,
      modelCalls: 0,
      inputTokens: 0,
    });
    expect(await aiIssuesOf(run.branchId)).toEqual([]);
    // Its end is decorated: the summary is final at once, not "in progress" until the sweep.
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    const [job] = await h.ctx.db
      .select({ status: jobs.status })
      .from(jobs)
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
    expect(job).toEqual({ status: 'succeeded' });
    // The call in flight was cut, and the provider was not asked again.
    const quality = reviewCalls().slice(calls);
    expect(quality.map(reviewRoleOf)).toEqual(['quality']);
    await vi.waitFor(() => expect(llm.abandoned).toContain(quality[0]));
    // A call given up is no failure of the provider's: its circuit counts nothing, and no row is
    // left that the day's budget would charge as a call that timed out.
    expect(circuit.inspect(llm.openAiBaseUrl)).toMatchObject({ state: 'closed', failures: 0 });
    expect(await rows()).toBe(rowsBefore);
  });

  it('a stop during a retry wait ends the run at once', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    const rowsBefore = (await reviewRows()).length;
    // The provider limits the quality reviewer's call and asks to wait two minutes: the review
    // waits for a minute, the longest wait it makes, before it asks again.
    llm.enqueue({
      status: 429,
      headers: { 'retry-after': '120' },
      body: { error: { message: 'slow down' } },
    });
    const shutdown = new AbortController();
    const worker = startWorker({
      db: h.ctx.db,
      handlers: reviewHandlers(jobDeps({ shutdown: shutdown.signal })),
      concurrency: 1,
      leaseMs: REVIEW_LEASE_MS,
      pollIntervalMs: 20,
      logger: silentLogger,
    });
    try {
      // The limited call has been answered and recorded: the review is waiting to ask again.
      await vi.waitFor(async () => expect(await reviewRows()).toHaveLength(rowsBefore + 1), {
        timeout: 20_000,
        interval: 25,
      });
      // As main.ts stops: the signal first, then the wait for the worker.
      const stopping = Date.now();
      shutdown.abort();
      await worker.stop();
      // Within a second: the wait is cut, not sat out.
      expect(Date.now() - stopping).toBeLessThan(1_000);
    } finally {
      shutdown.abort();
      await worker.stop();
    }
    expect(await runOf(analysisId)).toMatchObject({
      status: 'failed',
      reason: 'internal',
      phase: null,
      modelCalls: 1,
      findingsNew: 0,
      finishedAt: expect.any(Date),
    });
    // The provider was not asked again, and the end is decorated at once, as for any stop.
    expect(reviewCalls().slice(calls).map(reviewRoleOf)).toEqual(['quality']);
    expect(await decorationsOf(analysisId)).toHaveLength(1);
    expect(await aiIssuesOf((await runOf(analysisId)).branchId)).toEqual([]);
  });

  it('a server that is stopping starts no review: the run waits, and its job comes again', async () => {
    const mr = mergeRequest();
    const analysisId = await analysisOf(mr);
    await snapshotOf(analysisId, mr);
    await forgetDecorations();
    const calls = reviewCalls().length;
    expect(await runReviews({ shutdown: AbortSignal.abort() })).toBe(1);
    const run = await runOf(analysisId);
    expect(run).toMatchObject({ status: 'waiting', startedAt: null, finishedAt: null });
    expect(reviewCalls()).toHaveLength(calls);
    expect(await decorationsOf(analysisId)).toEqual([]);
    // Its job is queued again, a few seconds on, for the server that is up then.
    const queued = await h.ctx.db
      .select({ due: sql<boolean>`${jobs.runAt} > now()` })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AI_REVIEW_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'runId' = ${run.id}`,
        ),
      );
    expect(queued).toEqual([{ due: true }]);
    await dueNow(run.id);
    llm.enqueue(reviewResponder(FOUND), reviewResponder(FOUND));
    expect(await runReviews()).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({ status: 'done', findingsNew: 1 });
  });

  it('a GitHub pull request is decorated with its Actions context, and one without it is not', async () => {
    const pull = (number: number) =>
      github.addPull(GITHUB_REPOSITORY, {
        number,
        title: 'Add the cart total',
        headSha: HEAD,
        baseSha: BASE,
        files: [],
        state: 'open',
        draft: true,
      });
    const githubContext = { repositoryId: String(GITHUB_REPOSITORY), checkout: 'head' as const };
    pull(1);
    const analysisId = await gh.ingestOk(
      pullRequestReport(1, revision(1), {
        projectKey: gh.key,
        analysisDate: '2026-10-01T10:00:00Z',
        github: githubContext,
      }),
    );
    await snapshotOf(analysisId, 1);
    await forgetDecorations();
    expect(await runReviews()).toBe(1);
    // A draft on GitHub, as the provider says now: skipped, and the summary says so.
    expect(await runOf(analysisId)).toMatchObject({ status: 'skipped', reason: 'draft' });
    const queued = await h.ctx.db
      .select({ payload: jobs.payload })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, SCM_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'analysisId' = ${analysisId}`,
        ),
      );
    expect(queued).toEqual([
      { payload: { analysisId, attempt: 0, gitlab: null, github: githubContext } },
    ]);

    // An analysis an older CLI sent, without the Actions context: which revision it checked out
    // is unknown, so it is not decorated (fail closed), and that is said once.
    pull(2);
    const older = pullRequestReport(2, revision(2), {
      projectKey: gh.key,
      analysisDate: '2026-10-02T10:00:00Z',
    });
    const scm = { ...older.scm };
    delete scm.github;
    const withoutContext = await gh.ingestOk({ ...older, scm });
    await snapshotOf(withoutContext, 2);
    await forgetDecorations();
    logged.length = 0;
    expect(await runReviews()).toBe(1);
    const run = await runOf(withoutContext);
    expect(run).toMatchObject({ status: 'skipped', reason: 'draft' });
    expect(await decorationsOf(withoutContext)).toEqual([]);
    expect(logged).toContainEqual([
      'warn',
      { runId: run.id, analysisId: withoutContext },
      'AI review ended but not decorated: the analysis has no stored GitHub Actions context',
    ]);
  });

  it('a run of an analysis from another provider than its project connection is not decorated, and says so', async () => {
    // A GitHub Actions report uploaded to the project mapped to GitLab (github.md §5.1).
    const analysisId = await p.ingestOk(
      pullRequestReport(9_100, revision(1), {
        projectKey: p.key,
        analysisDate: '2026-10-01T10:00:00Z',
      }),
    );
    const run = await runOf(analysisId);
    await forgetDecorations();
    await dueNow(run.id);
    const late = new Date(run.deadlineAt.getTime() + 1_000);
    expect(await runReviews({ now: () => late })).toBe(1);
    expect(await runOf(analysisId)).toMatchObject({ status: 'skipped', reason: 'no_snapshot' });
    expect(await decorationsOf(analysisId)).toEqual([]);
    expect(logged).toContainEqual([
      'warn',
      { runId: run.id, analysisId, provider: 'github', connection: 'gitlab' },
      "AI review ended but not decorated: the analysis is not of the provider of its project's SCM connection",
    ]);
  });
});
