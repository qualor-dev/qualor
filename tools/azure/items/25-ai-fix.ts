import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { authorizeDefinitions, EXAMPLES } from './18-ci.js';
import {
  BENCH_ORG,
  benchProject,
  benchUploadYaml,
  buildAt,
  check,
  DECORATION_WAIT_MS,
  DOCKER_PATH,
  FINDING_LINE,
  listThreads,
  needEnv,
  qualorIdentityId,
  rec,
  type Check,
  type Thr,
} from './19-decoration.js';
import { QualorApi, removeProvider } from './21-review.js';
import {
  answerOf,
  BUILD_POLICY,
  createBranchAt,
  createDefinition,
  createPolicy,
  createPr,
  defaultQueueId,
  pushFiles,
  prWithMerge,
  refHead,
  repoInfo,
  result,
  shape,
  waitBuild,
  waitFor,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const BUILD_WAIT_MS = 15 * 60_000;
/** The model's answer to the fix request. */
const AI_WAIT_MS = 8 * 60_000;
/** The post job (it waits for a free SCM slot of the organisation, as a decoration does). */
const POST_WAIT_MS = 10 * 60_000;
/** The analyzer rule the file triggers on line 2: an empty function. */
const RULE = 'S1186';

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** The file of the pull request: one empty function on line 2 (sonarjs S1186), as item 21's. */
export function fixSource(stamp: string): string {
  return [`// Qualor probe item 25 (${stamp})`, 'export function emptyHandler() {', '}', ''].join(
    '\n',
  );
}

/** Qualor's ai-fix marker (server/src/llm/render.ts `aiFixMarker`). */
export const aiFixMarker = (issueId: string, requestId: string): string =>
  `<!-- qualor:ai-fix ${issueId} ${requestId} -->`;

/** The whole-line range a suggestion over `startLine..endLine` of `source` selects. */
export function expectedRange(
  source: string,
  startLine: number,
  endLine: number,
): { start: { line: number; offset: number }; end: { line: number; offset: number } } {
  const lines = source.split('\n');
  return {
    start: { line: startLine, offset: 1 },
    end: { line: endLine, offset: (lines[endLine - 1] ?? '').length + 1 },
  };
}

type IssueRow = { id: string; rule: { key: string }; startLine: number | null; status?: string };

/** The analyzer's finding on `line`: the S1186 one first, else any issue there. */
export function pickFinding<T extends IssueRow>(issues: readonly T[], line: number): T | undefined {
  const there = issues.filter((i) => i.startLine === line);
  return there.find((i) => i.rule.key.includes(RULE)) ?? there[0];
}

const firstLine = (text: string | undefined): string => (text ?? '').split(/\r?\n/, 1)[0] ?? '';
const sameId = (a: string | undefined, b: string): boolean =>
  (a ?? '').toLowerCase() === b.toLowerCase();

/** The threads whose first comment is the service principal's and starts with `marker`. */
export function markedThreads(threads: readonly Thr[], spId: string, marker: string): Thr[] {
  return threads.filter((t) => {
    const first = t.comments[0];
    return (
      first !== undefined &&
      first.isDeleted !== true &&
      sameId(first.author.id, spId) &&
      firstLine(first.content) === marker
    );
  });
}

/** The thread id a post's URL names (`…/pullrequest/7?discussionId=12`); undefined without one. */
export function discussionIdOf(url: string | null | undefined): number | undefined {
  const m = /[?&]discussionId=(\d+)(?:[&#]|$)/.exec(url ?? '');
  return m ? Number(m[1]) : undefined;
}

/**
 * The shape of the posted fix (never the model's words): one thread of the service principal with
 * the ai-fix marker on its first line, on the file over the stored fix's whole lines, a
 * suggestion fence, and a post URL naming that thread.
 */
export function judgeAiFixThread(
  threads: readonly Thr[],
  want: {
    spId: string;
    issueId: string;
    requestId: string;
    filePath: string;
    source: string;
    startLine: number;
    endLine: number;
    postUrl: string | null;
  },
): Check[] {
  const found = markedThreads(threads, want.spId, aiFixMarker(want.issueId, want.requestId));
  const t = found[0];
  const range = expectedRange(want.source, want.startLine, want.endLine);
  const anchor = t?.threadContext;
  const start = anchor?.rightFileStart;
  const end = anchor?.rightFileEnd;
  const at = (a: { line: number; offset: number } | null | undefined) =>
    a ? `${a.line}:${a.offset}` : '?';
  const content = t?.comments[0]?.content ?? '';
  const discussion = discussionIdOf(want.postUrl);
  const anchorFile =
    anchor?.filePath === want.filePath ? 'the file' : (anchor?.filePath ?? 'no file');
  const anchorGot = t ? `${anchorFile} ${at(start)}-${at(end)}` : 'no thread';
  let fenceGot = 'no thread';
  if (t) fenceGot = content.includes('```suggestion') ? 'present' : 'absent';
  return [
    check(
      'one thread by the service principal whose first line is the ai-fix marker',
      found.length === 1,
      `${found.length} such thread(s)`,
    ),
    check(
      `anchored on the file from ${at(range.start)} to ${at(range.end)} (the stored fix's lines ${want.startLine}..${want.endLine}, the end line's length + 1)`,
      anchor?.filePath === want.filePath &&
        start?.line === range.start.line &&
        start.offset === range.start.offset &&
        end?.line === range.end.line &&
        end.offset === range.end.offset,
      anchorGot,
    ),
    check(
      'the thread carries a ```suggestion fence',
      /^```suggestion\s*$/m.test(content.replace(/\r\n/g, '\n')),
      fenceGot,
    ),
    check(
      "the post's url names the thread (discussionId=)",
      discussion !== undefined && discussion === t?.id,
      discussion === undefined
        ? 'no discussionId in the url'
        : `discussionId=${discussion}, thread ${t?.id ?? 'none'}`,
    ),
  ];
}

// ---------------------------------------------------------------------------------------------
// The bench Qualor

const AiRequest = z
  .object({
    id: z.string(),
    status: z.string(),
    error: z.object({ code: z.string(), detail: z.string().nullable() }).nullable(),
    result: z
      .object({
        kind: z.string(),
        status: z.string().optional(),
        startLine: z.number().optional(),
        endLine: z.number().optional(),
      })
      .loose()
      .nullable(),
    post: z
      .object({ status: z.string(), reason: z.string().nullable(), url: z.string().nullable() })
      .loose()
      .nullable(),
  })
  .loose();
type AiRequestDto = z.infer<typeof AiRequest>;

const IssueItem = z
  .object({
    id: z.string(),
    rule: z.object({ key: z.string() }).loose(),
    path: z.string().nullable(),
    startLine: z.number().nullable(),
    status: z.string(),
  })
  .loose();

const codeOf = (json: unknown): string => {
  const p = (json ?? {}) as { code?: unknown; detail?: unknown };
  const detail = typeof p.detail === 'string' ? ` (${p.detail})` : '';
  return `${typeof p.code === 'string' ? p.code : 'no code'}${detail}`;
};

async function aiRequest(api: QualorApi, id: string): Promise<AiRequestDto> {
  return shape(AiRequest, (await api.call('GET', `/api/v0/ai-requests/${id}`)).json, 'ai request');
}

// ---------------------------------------------------------------------------------------------

type Repo = Awaited<ReturnType<typeof repoInfo>>;
type Issue = NonNullable<ReturnType<typeof pickFinding<z.infer<typeof IssueItem>>>>;

/** The bench Qualor, logged in, with the project of the target. */
interface Bench {
  api: QualorApi;
  qualorUrl: string;
  qualorToken: string;
  projectKey: string;
  project: { id: string; key: string };
}

/** The bench Qualor; a string is the reason the AI fix feature is off there (the item says no). */
async function openBench(ctx: ProbeContext): Promise<Bench | string> {
  // The bench Qualor's project of the target (Server: its own, mapped to the Server's `probe`).
  const bench = benchProject(ctx.target, 'main');
  const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL');
  const qualorToken = needEnv(bench.tokenEnv);
  const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
  const projectKey = bench.key;

  // The model key the seed stored must not outlive the run, whatever happens next.
  const api = new QualorApi(qualorUrl);
  await api.login(adminPassword);
  ctx.cleanup.add('remove the LLM provider from the bench Qualor', () => removeProvider(api));
  const org = (
    await api.items('/api/v0/organizations', z.object({ id: z.string(), key: z.string() }).loose())
  ).find((o) => o.key === BENCH_ORG);
  if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
  const ai = shape(
    z.object({ enabled: z.boolean(), features: z.object({ fix: z.boolean() }).loose() }).loose(),
    (await api.call('GET', `/api/v0/organizations/${org.id}/ai`)).json,
    'organisation AI',
  );
  if (!ai.enabled || !ai.features.fix) {
    return `the AI fix feature is not on for organisation bench (enabled ${ai.enabled}, fix ${ai.features.fix}): run the seed with --ai (scripts/seed-qualor.mjs --ai; AZURE_PROBE_LLM_KIND, AZURE_PROBE_LLM_KEY, AZURE_PROBE_LLM_MODEL)`;
  }
  const project = (
    await api.items(
      `/api/v0/projects?organizationId=${org.id}`,
      z.object({ id: z.string(), key: z.string() }).loose(),
    )
  ).find((p) => p.key === projectKey);
  if (!project)
    throw new Error(`the bench Qualor has no project ${projectKey} (run seed-qualor.mjs)`);
  return { api, qualorUrl, qualorToken, projectKey, project };
}

/** A pull request with the analyzer finding, built and analysed by the bench Qualor. */
async function openPullRequest(ctx: ProbeContext, bench: Bench, notes: string[]) {
  const spId = await qualorIdentityId(ctx);
  const repo: Repo = await repoInfo(ctx);
  const base = await refHead(ctx, repo.defaultBranch);
  if (!base) throw new Error('no head on the default branch');

  const queueId = await defaultQueueId(ctx);
  const def = await createDefinition(ctx, {
    name: `Qualor probe item 25 ai fix ${ctx.stamp}`,
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
  const target = await createBranchAt(ctx, `probe/25-${ctx.stamp}-target`, base);
  const relative = `probe/item-25-${ctx.stamp}.js`;
  const file = `/${relative}`;
  const source = fixSource(ctx.stamp);
  const pushed = await pushFiles(
    ctx,
    `probe/25-${ctx.stamp}`,
    [
      {
        path: `/${DOCKER_PATH}`,
        content: benchUploadYaml(
          readFileSync(fileURLToPath(new URL('qualor-docker.yml', EXAMPLES)), 'utf8'),
        ),
      },
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
      displayName: `Qualor probe item 25 build ${ctx.stamp}`,
      validDuration: 0,
      scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
    },
  });
  const created = await createPr(ctx, pushed.refName, { targetRefName: target });
  const prId = created.pr.pullRequestId;
  await prWithMerge(ctx, prId);
  ctx.log(
    `pull request ${prId}: build and analysis, the model's fix (up to ${AI_WAIT_MS / 60000} min), the post`,
  );
  return { spId, repo, prId, defId: def.id, relative, file, source };
}

/** The bench Qualor's finding on the pull request's file; undefined (a failed check) without one. */
async function findIssue(
  ctx: ProbeContext,
  bench: Bench,
  opened: Awaited<ReturnType<typeof openPullRequest>>,
  checks: Check[],
  notes: string[],
): Promise<Issue | undefined> {
  const { api, project } = bench;
  const { prId, defId, relative } = opened;
  const build = await buildAt(ctx, defId, []);
  if (!build) {
    checks.push(check('a build queued by the pull request', false, 'none within 3 minutes'));
    return undefined;
  }
  const built = await waitBuild(ctx, build.id, { timeoutMs: BUILD_WAIT_MS });
  await rec(ctx, 'build', answerOf(built.res));
  // The gate fails on the finding: the scan exits with the verdict, so a failed build is expected.
  notes.push(`build ${build.id}: ${built.build.status} ${built.build.result ?? '?'}`);

  const branch = await waitFor(
    async () =>
      (
        await api.all(
          `/api/v0/projects/${project.id}/branches?kind=merge_request`,
          z
            .object({ id: z.string(), name: z.string(), lastAnalysisId: z.string().nullable() })
            .loose(),
        )
      ).find((b) => b.name === String(prId) && b.lastAnalysisId !== null),
    { timeoutMs: DECORATION_WAIT_MS, intervalMs: 10_000 },
  );
  if (!branch) {
    checks.push(
      check(
        'Qualor analysed the pull request',
        false,
        `not within ${DECORATION_WAIT_MS / 60000} minutes`,
      ),
    );
    return undefined;
  }
  const issues = shape(
    z.object({ items: z.array(IssueItem) }).loose(),
    (
      await api.call(
        'GET',
        `/api/v0/issues?branchId=${branch.id}&path=${encodeURIComponent(relative)}&limit=100`,
      )
    ).json,
    'issues',
  ).items;
  const issue = pickFinding(issues, FINDING_LINE);
  checks.push(
    check(
      `the analyzer's finding on line ${FINDING_LINE} of the file`,
      issue !== undefined,
      issue
        ? issue.rule.key
        : `${issues.length} issue(s) on the file, none on line ${FINDING_LINE}`,
    ),
  );
  return issue;
}

/** What the failed fix request says: the status, then the error's code and detail. */
function describeFailedFix(answered: AiRequestDto): string {
  if (!answered.error) return answered.status;
  const detail = answered.error.detail ? ` (${answered.error.detail})` : '';
  return `${answered.status}: ${answered.error.code}${detail}`;
}

/** The model's fix of the finding; undefined (a failed check) when the request or the model fails. */
async function askForFix(api: QualorApi, issue: Issue, checks: Check[], notes: string[]) {
  const asked = await api.send('POST', `/api/v0/issues/${issue.id}/ai/fix`, {});
  if (asked.status !== 200 && asked.status !== 202) {
    checks.push(
      check(
        'the fix request is taken (200 or 202)',
        false,
        `HTTP ${asked.status} ${codeOf(asked.json)}`,
      ),
    );
    return undefined;
  }
  const requestId = shape(AiRequest, asked.json, 'ai request').id;
  const answered = await waitFor(
    async () => {
      const r = await aiRequest(api, requestId);
      return r.status === 'succeeded' || r.status === 'failed' ? r : undefined;
    },
    { timeoutMs: AI_WAIT_MS, intervalMs: 5000 },
  );
  const fix = answered?.result;
  if (answered?.status !== 'succeeded' || fix?.kind !== 'fix') {
    checks.push(
      check(
        "the model's fix",
        false,
        answered ? describeFailedFix(answered) : `no answer within ${AI_WAIT_MS / 60000} minutes`,
      ),
    );
    return undefined;
  }
  if (fix.status !== 'fixed' || fix.startLine === undefined || fix.endLine === undefined) {
    // The model may find nothing to fix: the item cannot judge a post then.
    checks.push(
      check(
        "the model's fix",
        false,
        `the model answered that there is no fix (${fix.status ?? '?'})`,
      ),
    );
    notes.push('the model answered not_applicable: run the item again, or try another model');
    return undefined;
  }
  checks.push(check("the model's fix", true, `lines ${fix.startLine}..${fix.endLine}`));
  return { requestId, startLine: fix.startLine, endLine: fix.endLine };
}

/** What the post job says: its status, then the reason when there is one. */
function describePost(post: NonNullable<AiRequestDto['post']>): string {
  return post.reason ? `${post.status} (${post.reason})` : post.status;
}

/** The post of the fix; undefined (a failed check) when it is not queued or not posted. */
async function postFix(api: QualorApi, requestId: string, checks: Check[]) {
  const posting = await api.send('POST', `/api/v0/ai-requests/${requestId}/post`, {});
  if (posting.status !== 202) {
    checks.push(
      check('the post is queued (202)', false, `HTTP ${posting.status} ${codeOf(posting.json)}`),
    );
    return undefined;
  }
  const posted = await waitFor(
    async () => {
      const r = await aiRequest(api, requestId);
      return r.post && r.post.status !== 'queued' ? r : undefined;
    },
    { timeoutMs: POST_WAIT_MS, intervalMs: 5000 },
  );
  const post = posted?.post;
  checks.push(
    check(
      'the post is posted',
      post?.status === 'posted',
      post ? describePost(post) : `still queued after ${POST_WAIT_MS / 60000} minutes`,
    ),
  );
  return post?.status === 'posted' ? post : undefined;
}

export const item: ProbeItem = {
  id: 25,
  title: 'an AI fix suggestion posted on an Azure DevOps pull request',
  async run(ctx) {
    const checks: Check[] = [];
    const notes: string[] = [];
    const bench = await openBench(ctx);
    if (typeof bench === 'string') return result(ctx, 'no', bench);
    const opened = await openPullRequest(ctx, bench, notes);
    const { prId } = opened;

    const issue = await findIssue(ctx, bench, opened, checks, notes);
    if (!issue) return finish(ctx, checks, notes, prId);

    // ---- 1. The model's fix.
    const fix = await askForFix(bench.api, issue, checks, notes);
    if (!fix) return finish(ctx, checks, notes, prId);

    // ---- 2. The post.
    const post = await postFix(bench.api, fix.requestId, checks);
    if (!post) return finish(ctx, checks, notes, prId);

    // ---- 3. The thread on Azure DevOps.
    const listed = await listThreads(ctx, opened.repo, prId);
    await rec(ctx, 'threads-posted', answerOf(listed.res));
    checks.push(
      ...judgeAiFixThread(listed.threads, {
        spId: opened.spId,
        issueId: issue.id,
        requestId: fix.requestId,
        filePath: opened.file,
        source: opened.source,
        startLine: fix.startLine,
        endLine: fix.endLine,
        postUrl: post.url,
      }),
    );
    return finish(ctx, checks, notes, prId);
  },
};

/** The checks of the full flow: the finding, the model's fix, posted, then four on the thread. */
const ALL_CHECKS = 7;

function finish(ctx: ProbeContext, checks: Check[], notes: string[], prId: number) {
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass = checks.length >= ALL_CHECKS && checks.every((c) => c.pass);
  const detail = [
    `pull request ${prId} into a probe target branch`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${n}`),
  ].join('\n\n');
  return Promise.resolve(result(ctx, pass ? 'yes' : 'no', detail));
}
