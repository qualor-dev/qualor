import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { AzureClient } from '../client.js';
import { redact } from '../record.js';
import { QualorApi } from './qualor-api.js';
import {
  hookRights,
  qualorAnswerText,
  qualorConnectionRecord,
  recordedResult,
} from './identity.js';
import { CONNECTION_DATA_VERSION } from './01-identity.js';
import { authorizeDefinitions, EXAMPLES } from './18-ci.js';
import {
  BENCH_ORG,
  benchProject,
  benchScmUrl,
  benchUploadYaml,
  buildAt,
  check,
  DECORATION_WAIT_MS,
  DOCKER_PATH,
  FINDING_LINE,
  listThreads,
  markerKind,
  needEnv,
  ownThreads,
  qualorIdentityId,
  qualorIdentityName,
  rec,
  threadStatusName,
  type Check,
  type Thr,
} from './19-decoration.js';
import {
  addIdentity,
  answerOf,
  BUILD_POLICY,
  ConnectionDataSchema,
  createBranchAt,
  createDefinition,
  createPolicy,
  createPr,
  defaultQueueId,
  excerpt,
  ok,
  prWithMerge,
  pushFiles,
  refHead,
  remove,
  repoInfo,
  result,
  shape,
  threadsPath,
  waitBuild,
  waitFor,
  type ProbeContext,
  type ProbeItem,
  type ProbeResult,
  type Repo,
} from './common.js';

const SUBSCRIPTIONS = '/_apis/hooks/subscriptions';
const LIST_SUBSCRIPTIONS = `${SUBSCRIPTIONS}?publisherId=tfs&consumerId=webHooks&consumerActionId=httpRequest`;
const HOOK_EVENTS = ['git.pullrequest.updated', 'ms.vss-code.git-pullrequest-comment-event'];
/** The path every webhook address of the bench Qualor ends in (server/src/scm/azure/url.ts). */
const WEBHOOK_PATH = '/api/v0/azure-devops/webhooks/';
/** The hook path's budget for one answer (the brief: within 3 minutes). */
const REPLY_WAIT_MS = 3 * 60_000;
/**
 * A `qualor review` may run the review before it answers: 5 minutes, or
 * `AZURE_PROBE_COMMAND_WAIT_MINUTES` (1 to 30). Without service hooks (a weaker identity) only
 * Qualor's poll answers, every 15 minutes (server/src/scm/azure/poll.ts), so a rights check waits 17.
 */
export function commandWaitMs(raw: string | undefined): number {
  const minutes = raw === undefined || raw === '' ? 5 : Number(raw);
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 30) {
    throw new Error('AZURE_PROBE_COMMAND_WAIT_MINUTES must be a whole number from 1 to 30');
  }
  return minutes * 60_000;
}
const COMMAND_WAIT_MS = commandWaitMs(process.env['AZURE_PROBE_COMMAND_WAIT_MINUTES']);
/** Qualor's AI review runs after the upload: the wait for its threads after the summary. */
const AI_WAIT_MS = 8 * 60_000;
const REPLY_TEXT = 'Qualor probe item 21: why is this an issue, and how do I fix it?';
const COMMAND_TEXT = 'qualor review';

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';

/** Whether the first line of `content` is Qualor's reply marker (server/src/scm/markdown.ts `replyMarker`). */
export function isReplyNote(content: string | undefined): boolean {
  const first = (content ?? '').split(/\r?\n/, 1)[0] ?? '';
  return new RegExp(`^<!-- qualor:reply ${UUID} -->$`).test(first);
}

/**
 * Qualor's answer when it refuses a `qualor review` (server/src/review/commands.ts NOT_A_MEMBER: the
 * author's Contribute could not be shown, also when Qualor's own credential cannot read the identities
 * or the ACL): the text, else undefined.
 */
export function commandRefusal(content: string | undefined): string | undefined {
  const refused = 'Only project members can ask for an AI review.';
  return (content ?? '').includes(refused) ? refused : undefined;
}

/** An issue thread's first note is the AI review's when its header line (the second) opens with `**AI review**`. */
export function isAiNote(content: string | undefined): boolean {
  if (markerKind(content) !== 'issue') return false;
  return ((content ?? '').split(/\r?\n/)[1] ?? '').startsWith('**AI review**');
}

/**
 * The file's text (test data for the model to find: nothing here is run): an empty function (the
 * analyzer's finding, line 2) and an inverted permission check on line 6 (the model's). The model's
 * defect is one no analyzer reports: the AI review leaves out what analyzers already cover, and
 * `eval(input)` was left out on the 2026-11-24 run for that reason.
 */
export function reviewSource(stamp: string): string {
  return [
    `// Qualor probe item 21 (${stamp})`,
    'export function emptyHandler() {',
    '}',
    '',
    '/** Only administrators may delete accounts. */',
    'export const canDeleteAccount = (user) => !user.isAdmin;',
    '',
  ].join('\n');
}

/** The AI review's section of a summary comment (from its heading), cut to `max` characters; '' when there is none. */
export function aiSection(summary: string | undefined, max = 300): string {
  const at = (summary ?? '').indexOf('#### AI review');
  return at < 0 ? '' : (summary ?? '').slice(at, at + max);
}

/** Whether a summary's AI review section still says it is in progress. */
export function aiInProgress(summary: string | undefined): boolean {
  return aiSection(summary, 2000).includes('in progress');
}

type Subscription = {
  id: string;
  status: string;
  eventType: string;
  projectId: string;
  url: string;
  /** The entry as Azure DevOps answered it (what the recording keeps). */
  raw: unknown;
};

const SubscriptionList = z.object({
  value: z.array(
    z
      .object({
        id: z.string(),
        status: z.string(),
        eventType: z.string(),
        publisherInputs: z.object({ projectId: z.string().nullish() }).loose().nullish(),
        consumerInputs: z.object({ url: z.string().nullish() }).loose().nullish(),
      })
      .loose(),
  ),
});

/** Qualor's subscriptions of one Azure project (by the webhook path and the project id). */
export function ownSubscriptions(json: unknown, projectId: string): Subscription[] {
  const parsed = SubscriptionList.safeParse(json);
  if (!parsed.success) return [];
  return parsed.data.value
    .map((s) => ({
      id: s.id,
      status: s.status,
      eventType: s.eventType,
      projectId: s.publisherInputs?.projectId ?? '',
      url: s.consumerInputs?.url ?? '',
      raw: s,
    }))
    .filter(
      (s) => s.url.includes(WEBHOOK_PATH) && s.projectId.toLowerCase() === projectId.toLowerCase(),
    );
}

const NotificationList = z.object({
  value: z.array(
    z
      .object({
        status: z.string().optional(),
        result: z.string().optional(),
        createdDate: z.string().optional(),
      })
      .loose(),
  ),
});

/**
 * A subscription's notification history, read loosely (no recording shows it yet): how many were
 * delivered (`status` completed, `result` succeeded) and how many of those were created at or after `sinceMs`.
 */
export function deliveries(json: unknown, sinceMs: number) {
  const parsed = NotificationList.safeParse(json);
  if (!parsed.success) return { total: 0, succeeded: 0, since: 0, readable: false };
  const succeeded = parsed.data.value.filter(
    (n) => n.status === 'completed' && n.result === 'succeeded',
  );
  const since = succeeded.filter((n) => {
    const at = Date.parse(n.createdDate ?? '');
    return Number.isFinite(at) && at >= sinceMs;
  });
  return {
    total: parsed.data.value.length,
    succeeded: succeeded.length,
    since: since.length,
    readable: true,
  };
}

/**
 * What is recorded of a subscription's notification history: each notification's id, status,
 * result and date, nothing else. Its `details` can hold the request Azure DevOps sent, Basic
 * header and all, so they never reach a recording; an answer of another shape records no entry.
 */
export function notificationsRecording(json: unknown): {
  count?: number;
  value: Record<string, unknown>[];
} {
  const parsed = NotificationList.safeParse(json);
  if (!parsed.success) return { value: [] };
  const value = parsed.data.value.map((n) => {
    const kept: Record<string, unknown> = {};
    for (const field of ['id', 'status', 'result', 'createdDate'] as const) {
      const v = (n as Record<string, unknown>)[field];
      if (typeof v === 'string' || typeof v === 'number') kept[field] = v;
    }
    return kept;
  });
  const count = (json as { count?: unknown }).count;
  return typeof count === 'number' ? { count, value } : { value };
}

/** What `PUT /system/llm` takes to store the settings as they are now, without the provider (and so its key). */
export function withoutProvider(current: unknown): Record<string, unknown> {
  const c = (current ?? {}) as Record<string, unknown>;
  const organizations = Object.fromEntries(
    Object.entries((c['organizations'] ?? {}) as Record<string, Record<string, unknown>>).map(
      ([id, org]) => {
        const { reviewStatus: _status, ...rest } = org;
        void _status;
        return [id, rest];
      },
    ),
  );
  return {
    provider: null,
    organizations,
    excludePaths: c['excludePaths'] ?? [],
    budgets: c['budgets'],
    pricing: c['pricing'] ?? null,
    storePrompts: c['storePrompts'] ?? false,
    promptRetentionDays: c['promptRetentionDays'] ?? 7,
  };
}

// ---------------------------------------------------------------------------------------------
// The bench Qualor's API (admin session): qualor-api.ts, re-exported for the items that import it from here

export { QualorApi };

/** Removes the provider (and so the stored key) from the bench Qualor's settings; throws when it is still there. */
export async function removeProvider(api: QualorApi): Promise<void> {
  const current = (await api.call('GET', '/api/v0/system/llm')).json;
  if ((current as { provider?: unknown } | null)?.provider === null) return;
  await api.call('PUT', '/api/v0/system/llm', withoutProvider(current));
  const after = (await api.call('GET', '/api/v0/system/llm')).json as { provider?: unknown } | null;
  if (after?.provider !== null) throw new Error('the LLM provider is still configured');
}

// ---------------------------------------------------------------------------------------------
// Azure DevOps calls

async function whoAmI(ctx: ProbeContext, client: AzureClient = ctx.user) {
  const res = ok(
    await client.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: CONNECTION_DATA_VERSION,
    }),
    'connectionData (PAT user)',
  );
  return shape(ConnectionDataSchema, res.json, 'connectionData (PAT user)').authenticatedUser;
}

async function azureSubscriptions(ctx: ProbeContext, repo: Repo) {
  const res = ok(await ctx.bot.request('GET', LIST_SUBSCRIPTIONS), 'service hook subscriptions');
  return { res, own: ownSubscriptions(res.json, repo.project.id) };
}

const CommentThread = z
  .object({
    id: z.number(),
    comments: z.array(
      z
        .object({
          id: z.number(),
          parentCommentId: z.number().optional(),
          content: z.string().optional(),
          isDeleted: z.boolean().optional(),
          author: z.object({ id: z.string() }).loose(),
        })
        .loose(),
    ),
  })
  .loose();

/**
 * Posts a reply (`parentCommentId` set) or opens a thread (not) as the PAT user (`client`: another
 * commenter, when Qualor's identity is the PAT user's).
 */
async function postAsUser(
  ctx: ProbeContext,
  repo: Repo,
  prId: number,
  content: string,
  reply?: { threadId: number; parentCommentId: number },
  client: AzureClient = ctx.user,
) {
  const res = ok(
    reply
      ? await client.request('POST', threadsPath(ctx, repo, prId, `/${reply.threadId}/comments`), {
          parentCommentId: reply.parentCommentId,
          content,
          commentType: 1,
        })
      : await client.request('POST', threadsPath(ctx, repo, prId), {
          comments: [{ parentCommentId: 0, content, commentType: 1 }],
          status: 1,
        }),
    reply ? 'reply (PAT user)' : 'new thread (PAT user)',
  );
  return res;
}

/** Waits for a comment of Qualor's with the reply marker in thread `threadId`, after comment `afterCommentId`. */
async function waitForAnswer(
  ctx: ProbeContext,
  repo: Repo,
  prId: number,
  spId: string,
  wanted: { threadId: number; afterCommentId: number },
  timeoutMs: number,
) {
  return waitFor(
    async () => {
      const got = await listThreads(ctx, repo, prId);
      const t = got.threads.find((x) => x.id === wanted.threadId);
      const answer = t?.comments.find(
        (c) =>
          c.isDeleted !== true &&
          c.author.id === spId &&
          isReplyNote(c.content) &&
          c.id > wanted.afterCommentId,
      );
      return t && answer ? { thread: t, answer, res: got.res } : undefined;
    },
    { timeoutMs, intervalMs: 5000 },
  );
}

// ---------------------------------------------------------------------------------------------

/** What the item's phases share: the pull request's repository, the checks and notes so far, the actors. */
interface ReviewFlow {
  ctx: ProbeContext;
  checks: Check[];
  notes: string[];
  repo: Repo;
  /** Qualor's identity id. */
  spId: string;
  api: QualorApi;
  /** The bench Qualor's organisation and connection of the target. */
  orgId: string;
  connectionId: string;
  /** Who comments and replies, and that identity's own record. */
  commenter: AzureClient;
  me: Awaited<ReturnType<typeof whoAmI>>;
}

/** The bench Qualor's address, project key and token for the item's scan definition. */
interface ReviewBench {
  qualorUrl: string;
  projectKey: string;
  qualorToken: string;
}

type SubscriptionsSeen = Awaited<ReturnType<typeof azureSubscriptions>>;

/** The verdict: as before for the bot; a weaker identity's steps and refusals are recorded. */
function endReview(flow: ReviewFlow, prId: number): Promise<ProbeResult> {
  const { ctx, checks, notes, api, orgId, connectionId, repo } = flow;
  return ctx.qualorAs
    ? weakerEnd(ctx, checks, notes, prId, { api, orgId, connectionId, repo })
    : finish(ctx, checks, notes, prId);
}

/** The identity that writes the reply and the command when Qualor's own identity is the commenting user's. */
function otherIdentity(ctx: ProbeContext): { client: AzureClient; label: string } | undefined {
  if (ctx.target === 'server') return { client: ctx.bot, label: 'qualor-bot' };
  if (ctx.entra) return { client: ctx.entra('secret'), label: 'the bench service principal' };
  return undefined;
}

/**
 * Qualor never answers its own comments. Under a weaker identity the user who comments can be
 * Qualor's identity itself: probe-user on Server under contributor, and on Services under
 * minimal-pat the PAT owner, the account of the user PAT on the bench. Another identity then
 * writes the reply and the command: qualor-bot on Server, the bench service principal on Services.
 * `writer` is that other identity, set only when it takes over.
 */
async function pickCommenter(ctx: ProbeContext, spId: string) {
  const userMe = await whoAmI(ctx, ctx.user);
  const other = otherIdentity(ctx);
  const asOther =
    ctx.qualorAs !== undefined &&
    other !== undefined &&
    userMe.id.toLowerCase() === spId.toLowerCase();
  const commenter = asOther && other ? other.client : ctx.user;
  const me = asOther ? await whoAmI(ctx, commenter) : userMe;
  addIdentity(ctx.redaction, me);
  return { commenter, me, writer: asOther ? other : undefined };
}

/** The bench Qualor's organisation and its Azure DevOps connection of the target. */
async function findOrgAndConnection(
  api: QualorApi,
  scmUrl: string,
): Promise<{ orgId: string; connectionId: string }> {
  const org = (
    await api.items('/api/v0/organizations', z.object({ id: z.string(), key: z.string() }).loose())
  ).find((o) => o.key === BENCH_ORG);
  if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
  const connection = (
    await api.items(
      `/api/v0/scm-connections?organizationId=${org.id}`,
      z.object({ id: z.string(), provider: z.string(), baseUrl: z.string() }).loose(),
    )
  ).find((c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === scmUrl);
  if (!connection)
    throw new Error('the bench Qualor has no Azure DevOps connection (run seed-qualor.mjs)');
  return { orgId: org.id, connectionId: connection.id };
}

/** Qualor's subscribe route; a weaker identity may be refused: the answer is noted, the run goes on. */
async function subscribeHooks(flow: ReviewFlow): Promise<void> {
  const { ctx, api, repo, notes, connectionId } = flow;
  // Qualor's own subscriptions go at clean-up, found by their address at that time (also when the call failed part-way).
  ctx.cleanup.add('delete the service hook subscriptions of the bench Qualor', async () => {
    const { own } = await azureSubscriptions(ctx, repo);
    for (const s of own) await remove(ctx.bot, `${SUBSCRIPTIONS}/${s.id}`, `subscription ${s.id}`);
  });
  // A password the probe knows, so the redaction table lists it before anything is recorded.
  const secret = shape(
    z.object({ password: z.string().min(8) }).loose(),
    (await api.call('POST', `/api/v0/scm-connections/${connectionId}/azure-hooks/secret`)).json,
    'azure-hooks/secret',
  );
  ctx.redaction.secrets.push(
    secret.password,
    Buffer.from(`:${secret.password}`).toString('base64'),
    Buffer.from(`qualor:${secret.password}`).toString('base64'),
  );
  const hooksPath = `/api/v0/scm-connections/${connectionId}/azure-hooks`;
  const hooksAnswer = ctx.qualorAs
    ? await api.send('POST', hooksPath)
    : await api.call('POST', hooksPath);
  if (ctx.qualorAs) {
    const said =
      hooksAnswer.status < 300
        ? `HTTP ${hooksAnswer.status}`
        : qualorAnswerText(hooksAnswer.status, hooksAnswer.json);
    notes.push(`subscribe route (POST …/azure-hooks): ${said}`);
  }
  if (hooksAnswer.status < 300) {
    const subscribed = shape(
      z.object({
        projects: z.array(
          z.object({ projectId: z.string(), comment: z.string(), updated: z.string() }).loose(),
        ),
      }),
      hooksAnswer.json,
      'azure-hooks',
    );
    const projects = subscribed.projects.map((p) => `comment ${p.comment}, updated ${p.updated}`);
    notes.push(`subscribe route: ${projects.join('; ') || 'no projects'}`);
  }
}

const bothEnabled = (own: SubscriptionsSeen['own']): boolean =>
  own.length === 2 && own.every((s) => s.status === 'enabled');

/** Waits for the two enabled subscriptions, records Qualor's own entries and judges them. */
async function checkSubscriptions(flow: ReviewFlow): Promise<SubscriptionsSeen> {
  const { ctx, repo, checks } = flow;
  const enabled = await waitFor(
    async () => {
      const got = await azureSubscriptions(ctx, repo);
      return bothEnabled(got.own) ? got : undefined;
    },
    { timeoutMs: 60_000, intervalMs: 5000 },
  );
  const seen = enabled ?? (await azureSubscriptions(ctx, repo));
  // Only Qualor's own entries: the organisation's other hooks are none of the recording's business.
  await rec(ctx, 'subscriptions', {
    ...answerOf(seen.res),
    body: { count: seen.own.length, value: seen.own.map((x) => x.raw) },
  });
  const listed = seen.own.map((s) => `${s.eventType} ${s.status}`).join(', ');
  checks.push(
    check(
      'two Qualor subscriptions in the Azure project, both enabled, one per event',
      bothEnabled(seen.own) && HOOK_EVENTS.every((e) => seen.own.some((s) => s.eventType === e)),
      `${seen.own.length} subscription(s): ${listed}`,
    ),
  );
  return seen;
}

/** A pull request with an analyzer finding and a defect for the model, behind a build policy. */
async function openReviewPr(
  flow: ReviewFlow,
  bench: ReviewBench,
  base: string,
): Promise<{ defId: number; prId: number; file: string; fileLines: number }> {
  const { ctx, repo, notes } = flow;
  const mainYaml = benchUploadYaml(
    readFileSync(fileURLToPath(new URL('qualor-docker.yml', EXAMPLES)), 'utf8'),
  );
  const queueId = await defaultQueueId(ctx);
  const def = await createDefinition(ctx, {
    name: `Qualor probe item 21 review ${ctx.stamp}`,
    path: '\\',
    type: 'build',
    queue: { id: queueId },
    process: { type: 2, yamlFilename: DOCKER_PATH },
    repository: {
      id: repo.id,
      name: repo.name,
      type: 'TfsGit',
      defaultBranch: 'refs/heads/main',
    },
    variables: {
      QUALOR_URL: { value: bench.qualorUrl, allowOverride: false },
      QUALOR_PROJECT_KEY: { value: bench.projectKey, allowOverride: false },
      QUALOR_TOKEN: { value: bench.qualorToken, isSecret: true, allowOverride: false },
    },
  });
  notes.push(await authorizeDefinitions(ctx, queueId, [def.id]));
  const target = await createBranchAt(ctx, `probe/21-${ctx.stamp}-target`, base);
  const file = `/probe/item-21-${ctx.stamp}.js`;
  const source = reviewSource(ctx.stamp);
  const fileLines = source.split('\n').length - 1;
  const pushed = await pushFiles(
    ctx,
    `probe/21-${ctx.stamp}`,
    [
      { path: `/${DOCKER_PATH}`, content: mainYaml },
      { path: file, content: source },
    ],
    { base },
  );
  await createPolicy(ctx, {
    isEnabled: true,
    isBlocking: true,
    type: { id: BUILD_POLICY },
    settings: {
      buildDefinitionId: def.id,
      queueOnSourceUpdateOnly: false,
      manualQueueOnly: false,
      displayName: `Qualor probe item 21 build ${ctx.stamp}`,
      validDuration: 0,
      scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
    },
  });
  const created = await createPr(ctx, pushed.refName, { targetRefName: target });
  const prId = created.pr.pullRequestId;
  await prWithMerge(ctx, prId);
  ctx.log(
    `pull request ${prId}: build, decoration, the AI review (up to ${AI_WAIT_MS / 60000} min more)`,
  );
  return { defId: def.id, prId, file, fileLines };
}

/** The build, then the decoration; undefined when the build or the summary never came (the run ends). */
async function awaitDecoration(flow: ReviewFlow, defId: number, prId: number) {
  const { ctx, repo, checks, notes, spId } = flow;
  const build = await buildAt(ctx, defId, []);
  if (!build) {
    checks.push(check('a build queued by the pull request', false, 'none within 3 minutes'));
    return undefined;
  }
  const done = await waitBuild(ctx, build.id, { timeoutMs: 30 * 60_000 });
  await rec(ctx, 'build', answerOf(done.res));
  // The gate fails on the finding: the scan exits with the verdict, so a failed build is expected.
  notes.push(`build ${build.id}: ${done.build.status} ${done.build.result ?? '?'}`);

  // The decoration: the summary comes after the analyzer threads.
  const decorated = await waitFor(
    async () => {
      const got = await listThreads(ctx, repo, prId);
      return ownThreads(got.threads, spId, 'summary').length > 0 ? got : undefined;
    },
    { timeoutMs: DECORATION_WAIT_MS, intervalMs: 10_000 },
  );
  if (!decorated) {
    checks.push(
      check('Qualor decorated the pull request (a summary thread)', false, 'none within the wait'),
    );
    return undefined;
  }
  // The AI review runs after the upload: its threads follow the summary, which says when it is done.
  const afterAi = await waitFor(
    async () => {
      const got = await listThreads(ctx, repo, prId);
      const summary = ownThreads(got.threads, spId, 'summary')[0]?.comments[0]?.content;
      const hasAi = ownThreads(got.threads, spId, 'issue').some((t) =>
        isAiNote(t.comments[0]?.content),
      );
      return hasAi || !aiInProgress(summary) ? got : undefined;
    },
    { timeoutMs: AI_WAIT_MS, intervalMs: 10_000 },
  );
  const decoratedNow = afterAi ?? (await listThreads(ctx, repo, prId));
  await rec(ctx, 'threads-decorated', answerOf(decoratedNow.res));
  return decoratedNow;
}

/** The analyzer thread's check: active, with the issue marker, on the empty function of the file. */
function checkAnalyzerThread(flow: ReviewFlow, analyzer: Thr[], file: string): Thr | undefined {
  const a = analyzer.find((t) => t.threadContext?.rightFileStart?.line === FINDING_LINE);
  let got = `${analyzer.length} analyzer thread(s), none on line ${FINDING_LINE}`;
  if (a) {
    const where = a.threadContext?.filePath === file ? 'the file' : 'another file';
    got = `${threadStatusName(a.status)} ${where} line ${a.threadContext?.rightFileStart?.line ?? '?'}`;
  }
  flow.checks.push(
    check(
      'the analyzer thread: active, with the issue marker, on the empty function (an added line) of the file',
      a !== undefined &&
        threadStatusName(a.status) === 'active' &&
        a.threadContext?.filePath === file,
      got,
    ),
  );
  return a;
}

/** The AI threads' check and note, or the note that the model reported none. */
function checkAiThreads(
  flow: ReviewFlow,
  ai: Thr[],
  file: string,
  fileLines: number,
  summaryText: string | undefined,
): void {
  const { ctx, checks, notes } = flow;
  const first = ai[0];
  if (!first) {
    notes.push(
      `the model reported no AI thread within the wait (the defect is the inverted admin check on line 6); the summary says: ${excerpt(aiSection(summaryText, 400), ctx.redaction, 400) || 'no AI review section'}`,
    );
    return;
  }
  const line = first.threadContext?.rightFileStart?.line;
  checks.push(
    check(
      'an AI thread with the issue marker, anchored on an added line of the file',
      first.threadContext?.filePath === file &&
        line !== undefined &&
        line >= 1 &&
        line <= fileLines,
      `${ai.length} AI thread(s); first at ${first.threadContext?.filePath === file ? 'the file' : (first.threadContext?.filePath ?? 'no file')} line ${line ?? '?'}, ${threadStatusName(first.status)}`,
    ),
  );
  const unanchored = ai.filter((x) => !x.threadContext?.filePath).length;
  notes.push(
    `AI threads: ${ai.length}, lines ${ai.map((x) => x.threadContext?.rightFileStart?.line ?? 'none').join(', ')}; ${unanchored} without a file anchor (Azure refused the anchor and Qualor fell back, or none was asked for)`,
  );
}

/** The decoration's checks: the analyzer thread, the AI threads. Returns the analyzer thread. */
function checkDecoration(
  flow: ReviewFlow,
  decoratedNow: Awaited<ReturnType<typeof listThreads>>,
  file: string,
  fileLines: number,
): Thr | undefined {
  const { spId } = flow;
  const issues = ownThreads(decoratedNow.threads, spId, 'issue');
  const analyzer = issues.filter((t) => !isAiNote(t.comments[0]?.content));
  const ai = issues.filter((t) => isAiNote(t.comments[0]?.content));
  const summaryText = ownThreads(decoratedNow.threads, spId, 'summary')[0]?.comments[0]?.content;
  const a = checkAnalyzerThread(flow, analyzer, file);
  checkAiThreads(flow, ai, file, fileLines, summaryText);
  return a;
}

/** Whether the answer rode the hook: the comment-event subscription's history shows a delivery after the reply. */
async function noteDeliveries(
  flow: ReviewFlow,
  commentSub: SubscriptionsSeen['own'][number],
  postedAt: number,
): Promise<void> {
  const { ctx, notes } = flow;
  const history = await ctx.bot.request(
    'GET',
    `${SUBSCRIPTIONS}/${commentSub.id}/notifications?maxResults=20`,
  );
  // Never the notifications' details: they can hold the delivery's Basic header.
  await rec(ctx, 'reply-notifications', {
    ...answerOf(history),
    body: notificationsRecording(history.json),
  });
  const d = deliveries(history.json, postedAt - 5000);
  if (!d.readable) {
    notes.push(`comment-event subscription history: HTTP ${history.status}, shape not read`);
    return;
  }
  const rode =
    d.since > 0
      ? ' (the answer rode the hook path)'
      : ' (none after the reply: the hook path is not shown; the poll may have answered)';
  notes.push(
    `comment-event subscription history (HTTP ${history.status}): ${d.total} notification(s), ${d.succeeded} succeeded, ${d.since} succeeded since the reply${rode}`,
  );
}

/** A reply in the analyzer thread, answered (the delivery is looked up after the answer). */
async function replyStep(
  flow: ReviewFlow,
  prId: number,
  a: Thr,
  seen: SubscriptionsSeen,
): Promise<void> {
  const { ctx, repo, checks, notes, spId, commenter, me } = flow;
  const root = a.comments[0];
  if (!root) throw new Error('the analyzer thread has no comment');
  const postedAt = Date.now();
  const replyRes = await postAsUser(
    ctx,
    repo,
    prId,
    REPLY_TEXT,
    { threadId: a.id, parentCommentId: root.id },
    commenter,
  );
  await rec(ctx, 'reply-post', answerOf(replyRes));
  const reply = shape(
    z.object({ id: z.number(), author: z.object({ id: z.string() }).loose().optional() }).loose(),
    replyRes.json,
    'reply',
  );
  let authorIs = 'is absent for';
  if (reply.author) {
    authorIs = reply.author.id.toLowerCase() === me.id.toLowerCase() ? 'equals' : 'differs from';
  }
  notes.push(`the reply's comment author id ${authorIs} the PAT user's identity id`);
  const answered = await waitForAnswer(
    ctx,
    repo,
    prId,
    spId,
    { threadId: a.id, afterCommentId: reply.id },
    REPLY_WAIT_MS,
  );
  const seconds = Math.round((Date.now() - postedAt) / 1000);
  if (answered) await rec(ctx, 'reply-thread', answerOf(answered.res));
  const qualorName = qualorIdentityName(ctx.target, ctx.qualorAs?.identity);
  checks.push(
    check(
      `Qualor's answer to the reply: a comment of ${qualorName} with the reply marker, within 3 minutes`,
      answered !== undefined,
      answered ? `answered in ${seconds} s` : `no answer within ${REPLY_WAIT_MS / 60000} minutes`,
    ),
  );
  if (!answered) return;
  const sameAuthor = answered.answer.author.id.toLowerCase() === spId.toLowerCase();
  notes.push(
    `answer author id ${sameAuthor ? 'equals' : 'differs from'} ${qualorName}'s identity id`,
  );
  notes.push(`reply to answer: ${seconds} s`);
  // Noted, not asserted: no recording shows this call's shape yet.
  const commentSub = seen.own.find((x) => x.eventType === HOOK_EVENTS[1]);
  if (commentSub) await noteDeliveries(flow, commentSub, postedAt);
}

/** A command, a new thread `qualor review` by the PAT user. */
async function commandStep(flow: ReviewFlow, prId: number): Promise<void> {
  const { ctx, repo, checks, spId, commenter } = flow;
  const commandRes = await postAsUser(ctx, repo, prId, COMMAND_TEXT, undefined, commenter);
  await rec(ctx, 'command-post', answerOf(commandRes));
  const command = shape(CommentThread, commandRes.json, 'new thread');
  const commandAt = Date.now();
  const commandAnswer = await waitForAnswer(
    ctx,
    repo,
    prId,
    spId,
    { threadId: command.id, afterCommentId: command.comments[0]?.id ?? 0 },
    COMMAND_WAIT_MS,
  );
  if (commandAnswer) await rec(ctx, 'command-threads', answerOf(commandAnswer.res));
  // Qualor answers a command it refuses as well: that answer is no review.
  const refusal = commandAnswer ? commandRefusal(commandAnswer.answer.content) : undefined;
  let got = `no answer within ${COMMAND_WAIT_MS / 60000} minutes`;
  if (commandAnswer) {
    const refused = refusal ? `; Qualor refused: "${refusal}"` : '';
    got = `answered in ${Math.round((Date.now() - commandAt) / 1000)} s${refused}`;
  }
  checks.push(
    check(
      'an answer to `qualor review` with the reply marker, in the thread of the command itself, not a refusal',
      commandAnswer !== undefined && refusal === undefined,
      got,
    ),
  );
}

export const item: ProbeItem = {
  id: 21,
  title:
    'Qualor subscribes its service hooks, adds AI threads, answers a reply and a `qualor review` command on Azure DevOps',
  async run(ctx) {
    // The bench Qualor's project and connection of the target (Server: its own).
    const project = benchProject(ctx.target, 'main');
    const bench: ReviewBench = {
      qualorUrl: needEnv('AZURE_PROBE_QUALOR_URL'),
      qualorToken: needEnv(project.tokenEnv),
      projectKey: project.key,
    };
    const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
    const scmUrl = benchScmUrl(ctx.target);
    const checks: Check[] = [];
    const notes: string[] = [];

    // The model key the seed stored must not outlive the run, whatever happens next.
    const api = new QualorApi(bench.qualorUrl);
    await api.login(adminPassword);
    ctx.cleanup.add('remove the LLM provider from the bench Qualor', () => removeProvider(api));
    const llm = (await api.call('GET', '/api/v0/system/llm')).json as {
      provider?: { apiKeySet?: boolean } | null;
    } | null;
    if (!llm?.provider || llm.provider.apiKeySet !== true) {
      return result(
        ctx,
        'no',
        'the bench Qualor has no LLM provider with a key: run the seed with --ai (scripts/seed-qualor.mjs --ai; AZURE_PROBE_LLM_KIND, AZURE_PROBE_LLM_KEY, AZURE_PROBE_LLM_MODEL)',
      );
    }

    const spId = await qualorIdentityId(ctx);
    const { commenter, me, writer } = await pickCommenter(ctx, spId);
    const repo = await repoInfo(ctx);
    const base = await refHead(ctx, repo.defaultBranch);
    if (!base) throw new Error('no head on the default branch');

    // ---- Step 1: Qualor's subscribe route; two enabled subscriptions on Azure.
    const { orgId, connectionId } = await findOrgAndConnection(api, scmUrl);
    const flow: ReviewFlow = {
      ctx,
      checks,
      notes,
      repo,
      spId,
      api,
      orgId,
      connectionId,
      commenter,
      me,
    };
    await subscribeHooks(flow);
    if (writer) {
      notes.push(
        `Qualor's identity is the commenting user's own: ${writer.label} writes the reply and the command (Qualor never answers its own comments)`,
      );
    }
    const seen = await checkSubscriptions(flow);

    // ---- Step 2: a pull request with an analyzer finding and a defect for the model.
    const opened = await openReviewPr(flow, bench, base);
    const { prId } = opened;

    // ---- Step 3: the decoration, with the analyzer and AI threads.
    const decoratedNow = await awaitDecoration(flow, opened.defId, prId);
    if (!decoratedNow) return endReview(flow, prId);
    const a = checkDecoration(flow, decoratedNow, opened.file, opened.fileLines);

    // ---- Step 4: a reply in the analyzer thread, answered.
    if (a) await replyStep(flow, prId, a, seen);

    // ---- Step 5: a command, a new thread `qualor review` by the PAT user.
    await commandStep(flow, prId);
    return endReview(flow, prId);
  },
};

/** A weaker identity's verdict: the steps, its own subscribe calls, and Qualor's record of the connection. */
async function weakerEnd(
  ctx: ProbeContext,
  checks: Check[],
  notes: string[],
  prId: number,
  bench: { api: QualorApi; orgId: string; connectionId: string; repo: Repo },
): Promise<ProbeResult> {
  const record = [
    ...(await hookRights(ctx, bench.repo.project.id, bench.repo.id)),
    ...(await qualorConnectionRecord(bench.api, bench.orgId, bench.connectionId, bench.repo.id)),
  ];
  return recordedResult(
    ctx,
    `pull request ${prId} into a probe target branch`,
    checks,
    notes.map((n) => String(redact(n, ctx.redaction))),
    record,
  );
}

function finish(ctx: ProbeContext, checks: Check[], notes: string[], prId: number) {
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass = checks.length >= 4 && checks.every((c) => c.pass);
  const detail = [
    `pull request ${prId} into a probe target branch`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${String(redact(n, ctx.redaction))}`),
  ].join('\n\n');
  return Promise.resolve(result(ctx, pass ? 'yes' : 'no', detail));
}
