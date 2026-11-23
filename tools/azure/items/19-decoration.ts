import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { redact } from '../record.js';
import {
  BUILD_POLICY,
  addIdentity,
  answerOf,
  BuildSchema,
  buildLogs,
  ConnectionDataSchema,
  createBranchAt,
  createDefinition,
  createPolicy,
  createPr,
  defaultQueueId,
  evaluations,
  gitPath,
  ok,
  prWithMerge,
  pushFiles,
  refHead,
  repoInfo,
  result,
  shape,
  threadsPath,
  waitBuild,
  waitFor,
  type Pr,
  type ProbeContext,
  type ProbeItem,
  type Repo,
} from './common.js';
import {
  authorizeDefinitions,
  BENCH_IMAGE_TAG,
  BENCH_SWAPS,
  checkForm,
  DRY_RUN,
  EXAMPLES,
  example,
  extensionInstalled,
  swapped,
  type Form,
  type Run,
} from './18-ci.js';

/** Azure DevOps's Status check policy type (item 7). */
const STATUS_POLICY = 'cbdc66da-9728-4af8-aada-9a5a32e4a226';
const DOCKER_PATH = '.azure-pipelines/qualor-docker.yml';
const DOTNET_PATHS: Record<Form, string> = {
  docker: '.azure-pipelines/qualor-dotnet-docker.yml',
  task: '.azure-pipelines/qualor-dotnet-task.yml',
};
const FIXTURE = new URL('../../../fixtures/csharp-basic/', import.meta.url);
/** The finding's file: one empty function on line 2 (sonarjs S1186, as the js-sonar fixture). */
const FINDING_LINE = 2;
const FINDING_TEXT = 'export function emptyHandler() {';
/** The commit that removes it: the same file with a body. */
const FIXED_TEXT = 'export function emptyHandler() {\n  return 0;\n}\n';
const DECORATION_WAIT_MS = 10 * 60_000;

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** The pipeline of the main flow: the docker example on the bench pool, image and upload (no dry run). */
export function benchUploadYaml(exampleText: string): string {
  return swapped(
    'qualor-docker.yml',
    exampleText,
    [
      ...BENCH_SWAPS,
      [
        /^( {2}QUALOR_SCANNER_IMAGE: )qualor\/scanner:\S+$/m,
        (_m, key) => `${key}qualor/scanner:${BENCH_IMAGE_TAG}`,
      ],
    ],
    null,
  );
}

const DOTNET_IMAGE: [RegExp, (m: string, ...g: string[]) => string] = [
  /^( {2}QUALOR_SCANNER_IMAGE: )qualor\/scanner-dotnet:\S+$/m,
  (_m, key) => `${key}qualor/scanner-dotnet:${BENCH_IMAGE_TAG}`,
];

/** integrations/azure-devops/qualor-dotnet-docker.yml as the bench runs it: the bench image, a dry run at `end`. */
export function benchDotnetDockerYaml(exampleText: string): string {
  return swapped('qualor-dotnet-docker.yml', exampleText, [
    ...BENCH_SWAPS,
    DOTNET_IMAGE,
    [/\$\(QUALOR_SCANNER_IMAGE\) dotnet end$/m, (m) => `${m} ${DRY_RUN}`],
  ]);
}

/** integrations/azure-devops/qualor-dotnet.yml (the task with `dotnet: true`) as the bench runs it. */
export function benchDotnetTaskYaml(exampleText: string): string {
  return swapped('qualor-dotnet.yml', exampleText, [
    ...BENCH_SWAPS,
    [
      /^( {2}- task: Qualor@0\n {4}displayName: Qualor scan\n {4}inputs:\n) {6}imageTag: .+\n/m,
      (_m, head) => `${head}      imageTag: ${BENCH_IMAGE_TAG}\n      arguments: ${DRY_RUN}\n`,
    ],
  ]);
}

const THREAD_STATUS: Record<number, string> = {
  1: 'active',
  2: 'fixed',
  3: 'wontFix',
  4: 'closed',
  5: 'byDesign',
  6: 'pending',
};

/** A thread's status as its name (Azure DevOps answers a name, or a number on older versions). */
export function threadStatusName(status: string | number | undefined): string {
  if (typeof status === 'number') return THREAD_STATUS[status] ?? String(status);
  return status ?? 'none';
}

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';

/** What the first line of a comment marks (Qualor's markers, server/src/scm/markdown.ts). */
export function markerKind(content: string | undefined): 'summary' | 'issue' | 'fixed' | null {
  const first = (content ?? '').split(/\r?\n/, 1)[0] ?? '';
  if (new RegExp(`^<!-- qualor:summary ${UUID} -->$`).test(first)) return 'summary';
  if (new RegExp(`^<!-- qualor:issue ${UUID} -->$`).test(first)) return 'issue';
  if (new RegExp(`^<!-- qualor:fixed ${UUID} [0-9a-f]{40,64} -->$`).test(first)) return 'fixed';
  return null;
}

/** Strings no recording may hold, whatever the table says. */
export function forbiddenIn(text: string, organisation: string | undefined): string[] {
  const hits: string[] = [];
  for (const word of ['X-Amz-', 'Bearer ', 'Basic ']) if (text.includes(word)) hits.push(word);
  if (
    organisation &&
    organisation.length >= 3 &&
    text.toLowerCase().includes(organisation.toLowerCase())
  ) {
    hits.push('the organisation name');
  }
  return hits;
}

// ---------------------------------------------------------------------------------------------
// Shapes

const Comment = z
  .object({
    id: z.number(),
    content: z.string().optional(),
    isDeleted: z.boolean().optional(),
    author: z.object({ id: z.string() }).loose(),
  })
  .loose();
const Anchor = z.object({ line: z.number(), offset: z.number() }).loose();
const Thread = z
  .object({
    id: z.number(),
    status: z.union([z.string(), z.number()]).optional(),
    isDeleted: z.boolean().optional(),
    threadContext: z
      .object({
        filePath: z.string().nullish(),
        rightFileStart: Anchor.nullish(),
        rightFileEnd: Anchor.nullish(),
      })
      .loose()
      .nullish(),
    pullRequestThreadContext: z.unknown().optional(),
    comments: z.array(Comment),
  })
  .loose();
type Thr = z.infer<typeof Thread>;
const Iterations = z.object({
  value: z.array(
    z.object({ id: z.number(), sourceRefCommit: z.object({ commitId: z.string() }) }).loose(),
  ),
});
const Statuses = z.object({
  value: z.array(
    z
      .object({
        id: z.number(),
        state: z.string(),
        description: z.string().nullish(),
        targetUrl: z.string().nullish(),
        context: z.object({ name: z.string(), genre: z.string().nullish() }).loose(),
      })
      .loose(),
  ),
});

// ---------------------------------------------------------------------------------------------
// Calls

/** Records `value` after a last look for what no recording may hold; throws before anything is written. */
async function rec(ctx: ProbeContext, call: string, value: unknown): Promise<void> {
  const org = (() => {
    try {
      return new URL(process.env['AZURE_PROBE_SERVICES_URL'] ?? '').pathname
        .split('/')
        .find(Boolean);
    } catch {
      return undefined;
    }
  })();
  const text = JSON.stringify(redact(value, ctx.redaction));
  const hits = forbiddenIn(text, org);
  if (hits.length > 0)
    throw new Error(`recording ${call} would hold ${hits.join(', ')}; not written`);
  await ctx.record(call, value);
}

/** Qualor's comments are the service principal's: its names join the redaction table, and its id is returned. */
async function servicePrincipalId(ctx: ProbeContext): Promise<string> {
  if (!ctx.entra)
    throw new Error('no Entra client on this target: the bench Qualor acts as a service principal');
  const res = ok(
    await ctx.entra('secret').request('GET', '/_apis/connectionData', undefined, {
      apiVersion: '7.0-preview',
    }),
    'connectionData of the service principal',
  );
  const data = shape(ConnectionDataSchema, res.json, 'connectionData (service principal)');
  addIdentity(ctx.redaction, data.authenticatedUser);
  return data.authenticatedUser.id;
}

async function listThreads(ctx: ProbeContext, repo: Repo, prId: number) {
  const res = ok(await ctx.bot.request('GET', threadsPath(ctx, repo, prId)), 'threads');
  const list = shape(z.object({ value: z.array(Thread) }), res.json, 'threads').value;
  return { res, threads: list.filter((t) => t.isDeleted !== true) };
}

/** The threads whose first comment is the service principal's and carries `kind`'s marker. */
function ownThreads(threads: Thr[], spId: string, kind: 'summary' | 'issue') {
  return threads.filter((t) => {
    const first = t.comments[0];
    return first !== undefined && first.author.id === spId && markerKind(first.content) === kind;
  });
}

/** Pushes one commit that edits `file` on `branch` (the helper in common.ts only adds files). */
async function pushEdit(
  ctx: ProbeContext,
  branch: string,
  file: string,
  content: string,
): Promise<string> {
  const repo = await repoInfo(ctx);
  const refName = `refs/heads/${branch}`;
  const head = await refHead(ctx, refName);
  if (!head) throw new Error(`no head on ${refName}`);
  const res = ok(
    await ctx.bot.request('POST', gitPath(ctx, repo, '/pushes'), {
      refUpdates: [{ name: refName, oldObjectId: head }],
      commits: [
        {
          comment: `Qualor probe item ${ctx.item}: remove the finding`,
          parents: [head],
          changes: [
            {
              changeType: 'edit',
              item: { path: file },
              newContent: { content, contentType: 'rawtext' },
            },
          ],
        },
      ],
    }),
    'push the fix',
  );
  const push = shape(
    z.object({ commits: z.array(z.object({ commitId: z.string() })).min(1) }),
    res.json,
    'push',
  );
  return push.commits[push.commits.length - 1]?.commitId ?? '';
}

/** The newest build of a definition that is not `except`. */
async function newBuild(ctx: ProbeContext, definitionId: number, except: number | undefined) {
  return waitFor(
    async () => {
      const res = ok(
        await ctx.bot.request(
          'GET',
          `/${ctx.project}/_apis/build/builds?definitions=${definitionId}`,
        ),
        'builds',
      );
      const list = shape(z.object({ value: z.array(BuildSchema) }), res.json, 'builds').value;
      return list.find((b) => b.id !== except);
    },
    { timeoutMs: 180_000, intervalMs: 5000 },
  );
}

async function iterationOf(ctx: ProbeContext, repo: Repo, prId: number, commit: string) {
  const res = ok(
    await ctx.bot.request('GET', gitPath(ctx, repo, `/pullRequests/${prId}/iterations`)),
    'iterations',
  );
  const list = shape(Iterations, res.json, 'iterations').value;
  const found = list
    .filter((i) => i.sourceRefCommit.commitId.toLowerCase() === commit.toLowerCase())
    .sort((a, b) => b.id - a.id)[0];
  return { res, iteration: found, newest: Math.max(0, ...list.map((i) => i.id)) };
}

/** The statuses of an iteration, by name and genre. */
async function iterationStatuses(ctx: ProbeContext, repo: Repo, prId: number, iterationId: number) {
  const res = ok(
    await ctx.bot.request(
      'GET',
      gitPath(ctx, repo, `/pullRequests/${prId}/iterations/${iterationId}/statuses`),
    ),
    'iteration statuses',
  );
  return { res, list: shape(Statuses, res.json, 'iteration statuses').value };
}

type Check = { what: string; pass: boolean; got: string };
const check = (what: string, pass: boolean, got: string): Check => ({ what, pass, got });

/** The state of Qualor's newest status of that name on the iteration (highest id). */
function newestStatus(list: z.infer<typeof Statuses>['value'], name: string) {
  return list
    .filter((s) => s.context.name === name && s.context.genre === 'qualor')
    .sort((a, b) => b.id - a.id)[0];
}

/** Waits for Qualor's status on the analysed iteration (a new one, `after`, the id of an older status). */
async function waitStatus(
  ctx: ProbeContext,
  repo: Repo,
  prId: number,
  commit: string,
  name: string,
  wantState: string,
) {
  return waitFor(
    async () => {
      const { iteration } = await iterationOf(ctx, repo, prId, commit);
      if (!iteration) return undefined;
      const got = await iterationStatuses(ctx, repo, prId, iteration.id);
      const status = newestStatus(got.list, name);
      return status && status.state === wantState ? { iteration, status, ...got } : undefined;
    },
    { timeoutMs: DECORATION_WAIT_MS, intervalMs: 10_000 },
  );
}

async function policyVerdict(ctx: ProbeContext, pr: Pr, policyId: number, want: string) {
  return waitFor(
    async () => {
      const { list, res } = await evaluations(ctx, pr);
      const ev = list.value.find((e) => e.configuration.id === policyId);
      return ev && ev.status === want ? { status: ev.status, res } : undefined;
    },
    { timeoutMs: 3 * 60_000, intervalMs: 5000 },
  );
}

/** The observations the controller's rulings ask for: reported, never asserted. */
async function observe(
  ctx: ProbeContext,
  repo: Repo,
  prId: number,
  iterationId: number,
  commit: string,
  file: string,
  thread: Thr | undefined,
): Promise<string[]> {
  const notes: string[] = [];
  const noProject = `/_apis/git/repositories/${repo.id}`;
  const probes: [string, string][] = [
    ['threads without the project segment', `${noProject}/pullRequests/${prId}/threads`],
    [
      'iteration statuses without the project segment',
      `${noProject}/pullRequests/${prId}/iterations/${iterationId}/statuses`,
    ],
  ];
  for (const [what, p] of probes) {
    const res = await ctx.bot.request('GET', p);
    notes.push(`${what}: HTTP ${res.status}`);
  }
  const items = await ctx.bot.request(
    'GET',
    `${noProject}/items?path=${encodeURIComponent(file)}&versionDescriptor.version=${commit}&versionDescriptor.versionType=commit&includeContent=true&$format=json`,
  );
  const content = (items.json as { content?: unknown } | null)?.content;
  notes.push(
    `items with $format=json and includeContent: HTTP ${items.status}, content ${typeof content === 'string' ? `present (${content.length} characters)` : 'absent'}`,
  );
  const changes = await ctx.bot.request(
    'GET',
    `${noProject}/pullRequests/${prId}/iterations/${iterationId}/changes?$top=100&$skip=0`,
  );
  const body = (changes.json ?? {}) as {
    changeEntries?: unknown[];
    nextSkip?: unknown;
    nextTop?: unknown;
  };
  notes.push(
    `iteration changes page: HTTP ${changes.status}, ${body.changeEntries?.length ?? '?'} entries, nextSkip ${JSON.stringify(body.nextSkip ?? null)}, nextTop ${JSON.stringify(body.nextTop ?? null)}`,
  );
  notes.push(
    `thread placement: Qualor sent no pullRequestThreadContext; the stored thread has ${thread?.pullRequestThreadContext ? 'one (Azure filled it in)' : 'none'}`,
  );
  return notes;
}

/** The files of fixtures/csharp-basic, as repository files (not its expected.json). */
function fixtureFiles(): { path: string; content: string }[] {
  const root = fileURLToPath(FIXTURE);
  const out: { path: string; content: string }[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (name !== 'expected.json') {
        out.push({
          path: `/${path.relative(root, full).split(path.sep).join('/')}`,
          content: readFileSync(full, 'utf8'),
        });
      }
    }
  };
  walk(root);
  return out;
}

function needEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`${key} is not set (scripts/seed-qualor.mjs writes it into bench.env)`);
  return v;
}

export const item: ProbeItem = {
  id: 19,
  title: 'Qualor decorates a pull request on Azure DevOps Services: status, summary and a thread',
  async run(ctx) {
    if (ctx.target !== 'services') {
      return result(
        ctx,
        'no',
        'item 19 runs on the Services target only (the bench Qualor is mapped to it)',
      );
    }
    const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL');
    const qualorToken = needEnv('AZURE_PROBE_QUALOR_TOKEN');
    const projectKey = process.env['AZURE_PROBE_QUALOR_PROJECT_KEY'] ?? 'bench';
    const statusName = `qualor/${projectKey}`;
    const spId = await servicePrincipalId(ctx);
    const repo = await repoInfo(ctx);
    const base = await refHead(ctx, repo.defaultBranch);
    if (!base) throw new Error('no head on the default branch');
    const ext = await extensionInstalled(ctx);
    const queueId = await defaultQueueId(ctx);
    const checks: Check[] = [];
    const notes: string[] = [];

    // ---- Definitions: the main flow (uploads to the bench Qualor) and the .NET forms (dry runs).
    const mainYaml = benchUploadYaml(
      readFileSync(fileURLToPath(new URL('qualor-docker.yml', EXAMPLES)), 'utf8'),
    );
    const defMain = await createDefinition(ctx, {
      name: `Qualor probe item 19 decoration ${ctx.stamp}`,
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
        QUALOR_URL: { value: qualorUrl, allowOverride: false },
        QUALOR_PROJECT_KEY: { value: projectKey, allowOverride: false },
        QUALOR_TOKEN: { value: qualorToken, isSecret: true, allowOverride: false },
      },
    });
    const dummy = ['qlr', 'bench', randomBytes(12).toString('hex')].join('_');
    const dotnetForms: Form[] = ext.installed ? ['docker', 'task'] : ['docker'];
    const dotnetRuns: Run[] = [];
    for (const form of dotnetForms) {
      const def = await createDefinition(ctx, {
        name: `Qualor probe item 19 dotnet ${form} ${ctx.stamp}`,
        path: '\\',
        type: 'build',
        queue: { id: queueId },
        process: { type: 2, yamlFilename: DOTNET_PATHS[form] },
        repository: {
          id: repo.id,
          name: repo.name,
          type: 'TfsGit',
          defaultBranch: 'refs/heads/main',
        },
        variables: {
          QUALOR_URL: { value: 'https://qualor.invalid', allowOverride: false },
          QUALOR_TOKEN: { value: dummy, isSecret: true, allowOverride: false },
        },
      });
      dotnetRuns.push({
        form,
        label: `dotnet-${form}`,
        scanStep: form === 'docker' ? 'Qualor end' : 'Qualor scan',
        definitionId: def.id,
        policyId: 0,
      });
    }
    const authorized = await authorizeDefinitions(ctx, queueId, [
      defMain.id,
      ...dotnetRuns.map((r) => r.definitionId),
    ]);
    notes.push(authorized);

    // ---- Main flow: a pull request with one finding.
    const target = await createBranchAt(ctx, `probe/19-${ctx.stamp}-target`, base);
    const findingFile = `/probe/item-19-${ctx.stamp}.js`;
    const findingContent = `// Qualor probe item 19 (${ctx.stamp})\n${FINDING_TEXT}\n}\n`;
    const branch = `probe/19-${ctx.stamp}`;
    const pushed = await pushFiles(
      ctx,
      branch,
      [
        { path: `/${DOCKER_PATH}`, content: mainYaml },
        { path: findingFile, content: findingContent },
      ],
      { base },
    );
    const buildPolicy = await createPolicy(ctx, {
      isEnabled: true,
      isBlocking: true,
      type: { id: BUILD_POLICY },
      settings: {
        buildDefinitionId: defMain.id,
        queueOnSourceUpdateOnly: false,
        manualQueueOnly: false,
        displayName: `Qualor probe item 19 build ${ctx.stamp}`,
        validDuration: 0,
        scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
      },
    });
    const statusPolicy = await createPolicy(ctx, {
      isEnabled: true,
      isBlocking: true,
      type: { id: STATUS_POLICY },
      settings: {
        statusName,
        statusGenre: 'qualor',
        invalidateOnSourceUpdate: true,
        policyApplicability: null,
        defaultDisplayName: `Qualor probe item 19 ${ctx.stamp}`,
        scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
      },
    });
    const created = await createPr(ctx, pushed.refName, { targetRefName: target });
    const prId = created.pr.pullRequestId;
    const { pr: pr1 } = await prWithMerge(ctx, prId);
    const head1 = (pr1.lastMergeSourceCommit?.commitId ?? pushed.commitId).toLowerCase();
    ctx.log(
      `pull request ${prId}: build, then Qualor's decoration (up to ${DECORATION_WAIT_MS / 60000} min)`,
    );

    const build1 = await newBuild(ctx, defMain.id, undefined);
    if (!build1) {
      checks.push(check('first build queued', false, 'none within 3 minutes'));
      return finish(ctx, checks, notes, prId, dotnetRuns, ext.why, repo, base);
    }
    const done1 = await waitBuild(ctx, build1.id, { timeoutMs: 30 * 60_000 });
    await rec(ctx, 'build-first', answerOf(done1.res));
    // The gate fails on the finding: the scan exits with the verdict, so a failed build is expected here.
    notes.push(
      `first build ${build1.id}: ${done1.build.status} ${done1.build.result ?? '?'} (the failed gate is the scan's exit code)`,
    );
    if (done1.build.status !== 'completed') {
      checks.push(check('first build completed', false, done1.build.status));
      return finish(ctx, checks, notes, prId, dotnetRuns, ext.why, repo, base);
    }
    const logs1 = await buildLogs(ctx, build1.id);
    notes.push(`first build logs: ${logs1.size} log(s)`);

    const st1 = await waitStatus(ctx, repo, prId, head1, statusName, 'failed');
    checks.push(
      check(
        `iteration status ${statusName} failed on the analysed iteration`,
        st1 !== undefined,
        st1
          ? `iteration ${st1.iteration.id}, ${st1.status.description ?? ''}`.slice(0, 160)
          : 'no such status within the wait',
      ),
    );
    if (st1) {
      await rec(ctx, 'iteration-statuses-first', answerOf(st1.res));
      notes.push(`status target ${st1.status.targetUrl ? 'set' : 'absent'}`);
    }
    const verdict1 = await policyVerdict(ctx, pr1, statusPolicy.id, 'rejected');
    checks.push(
      check(
        'Status check policy rejected',
        verdict1 !== undefined,
        verdict1?.status ?? 'not rejected within 3 minutes',
      ),
    );
    if (verdict1) await rec(ctx, 'evaluations-first', answerOf(verdict1.res));

    // Threads: Qualor writes the inline threads before the summary, so a summary means the job ended.
    const t1 = await waitFor(
      async () => {
        const got = await listThreads(ctx, repo, prId);
        return ownThreads(got.threads, spId, 'summary').length > 0 ? got : undefined;
      },
      { timeoutMs: DECORATION_WAIT_MS, intervalMs: 10_000 },
    );
    const summaries1 = t1 ? ownThreads(t1.threads, spId, 'summary') : [];
    const issues1 = t1 ? ownThreads(t1.threads, spId, 'issue') : [];
    const summary1 = summaries1[0];
    checks.push(
      check(
        'one closed summary thread with the marker, on the pull request as a whole',
        summaries1.length === 1 &&
          threadStatusName(summary1?.status) === 'closed' &&
          !summary1?.threadContext?.filePath,
        `${summaries1.length} summary thread(s), status ${threadStatusName(summary1?.status)}`,
      ),
    );
    const issue1 = issues1[0];
    const lineLength = FINDING_TEXT.length;
    const start = issue1?.threadContext?.rightFileStart;
    const end = issue1?.threadContext?.rightFileEnd;
    checks.push(
      check(
        'one active thread with the issue marker on the added line, anchored on the whole line',
        issues1.length === 1 &&
          threadStatusName(issue1?.status) === 'active' &&
          issue1?.threadContext?.filePath === findingFile &&
          start?.line === FINDING_LINE &&
          start.offset === 1 &&
          end?.line === FINDING_LINE &&
          end.offset === lineLength + 1,
        `${issues1.length} issue thread(s); ${issue1 ? `${threadStatusName(issue1.status)} ${issue1.threadContext?.filePath ?? 'no file'} ${start?.line ?? '?'}:${start?.offset ?? '?'}-${end?.line ?? '?'}:${end?.offset ?? '?'} (expected ${findingFile} ${FINDING_LINE}:1-${FINDING_LINE}:${lineLength + 1})` : 'none'}`,
      ),
    );
    if (t1) await rec(ctx, 'threads-first', answerOf(t1.res));
    if (st1) {
      notes.push(...(await observe(ctx, repo, prId, st1.iteration.id, head1, findingFile, issue1)));
    } else {
      notes.push('observations skipped: no analysed iteration');
    }
    if (!issue1 || !summary1)
      return finish(ctx, checks, notes, prId, dotnetRuns, ext.why, repo, base);

    // ---- The fix: a commit that removes the finding.
    const fixCommit = (
      await pushEdit(
        ctx,
        branch,
        findingFile,
        `// Qualor probe item 19 (${ctx.stamp})\n${FIXED_TEXT}`,
      )
    ).toLowerCase();
    const build2 = await newBuild(ctx, defMain.id, build1.id);
    if (!build2) {
      checks.push(check('second build queued by the push', false, 'none within 3 minutes'));
      return finish(ctx, checks, notes, prId, dotnetRuns, ext.why, repo, base);
    }
    const done2 = await waitBuild(ctx, build2.id, { timeoutMs: 30 * 60_000 });
    await rec(ctx, 'build-fixed', answerOf(done2.res));
    checks.push(
      check(
        'second build succeeded (the gate passes, the scan uploads)',
        done2.build.result === 'succeeded',
        `${done2.build.status} ${done2.build.result ?? '?'}`,
      ),
    );
    const { pr: pr2 } = await prWithMerge(ctx, prId);
    const head2 = (pr2.lastMergeSourceCommit?.commitId ?? fixCommit).toLowerCase();
    const st2 = await waitStatus(ctx, repo, prId, head2, statusName, 'succeeded');
    checks.push(
      check(
        `iteration status ${statusName} succeeded on the new iteration`,
        st2 !== undefined && st2.iteration.id !== st1?.iteration.id,
        st2 ? `iteration ${st2.iteration.id}` : 'no such status within the wait',
      ),
    );
    if (st2) await rec(ctx, 'iteration-statuses-fixed', answerOf(st2.res));
    const verdict2 = await policyVerdict(ctx, pr2, statusPolicy.id, 'approved');
    checks.push(
      check(
        'Status check policy approved',
        verdict2 !== undefined,
        verdict2?.status ?? 'not approved within 3 minutes',
      ),
    );
    if (verdict2) await rec(ctx, 'evaluations-fixed', answerOf(verdict2.res));
    notes.push(`build policy ${buildPolicy.id} and status policy ${statusPolicy.id} evaluated`);

    const t2 = await waitFor(
      async () => {
        const got = await listThreads(ctx, repo, prId);
        const own = ownThreads(got.threads, spId, 'issue')[0];
        return own && threadStatusName(own.status) === 'fixed' ? got : undefined;
      },
      { timeoutMs: DECORATION_WAIT_MS, intervalMs: 10_000 },
    );
    const got2 = t2 ?? (await listThreads(ctx, repo, prId));
    const issue2 = ownThreads(got2.threads, spId, 'issue').find((t) => t.id === issue1.id);
    const lastOfIssue = issue2?.comments.filter((c) => c.isDeleted !== true).at(-1);
    const fixedLine = (lastOfIssue?.content ?? '').split(/\r?\n/, 1)[0] ?? '';
    checks.push(
      check(
        "the issue thread is fixed, and its last comment is Qualor's fixed comment",
        issue2 !== undefined &&
          threadStatusName(issue2.status) === 'fixed' &&
          lastOfIssue?.author.id === spId &&
          markerKind(lastOfIssue.content) === 'fixed' &&
          fixedLine.includes(head2) &&
          (lastOfIssue.content ?? '').includes(`Fixed in \`${head2.slice(0, 7)}\``),
        `${issue2 ? threadStatusName(issue2.status) : 'thread missing'}; last comment ${markerKind(lastOfIssue?.content) ?? 'not a Qualor marker'}`,
      ),
    );
    const summaries2 = ownThreads(got2.threads, spId, 'summary');
    const summary2 = summaries2[0];
    checks.push(
      check(
        'the summary is edited in place: same thread, same comment, new text',
        summaries2.length === 1 &&
          summary2?.id === summary1.id &&
          summary2.comments[0]?.id === summary1.comments[0]?.id &&
          summary2.comments[0]?.content !== summary1.comments[0]?.content,
        `${summaries2.length} summary thread(s); same thread ${summary2?.id === summary1.id}; text changed ${summary2?.comments[0]?.content !== summary1.comments[0]?.content}`,
      ),
    );
    await rec(ctx, 'threads-fixed', answerOf(got2.res));
    return finish(ctx, checks, notes, prId, dotnetRuns, ext.why, repo, base);
  },
};

/**
 * The .NET forms (dry runs on fixtures/csharp-basic) when the main flow got that far, then the verdict.
 * The main flow's own failures do not stop the .NET forms; they stop only when nothing was decorated.
 */
async function finish(
  ctx: ProbeContext,
  checks: Check[],
  notes: string[],
  prId: number,
  runs: Run[],
  extensionWhy: string,
  repo: Repo,
  base: string,
) {
  const outcomes: { pass: boolean; text: string }[] = [];
  if (runs.length > 0) {
    const target = await createBranchAt(ctx, `probe/19-${ctx.stamp}-dotnet-target`, base);
    const files = [
      ...runs.map((r) => ({
        path: `/${DOTNET_PATHS[r.form]}`,
        content:
          r.form === 'docker'
            ? benchDotnetDockerYaml(example('qualor-dotnet-docker.yml'))
            : benchDotnetTaskYaml(example('qualor-dotnet.yml')),
      })),
      ...fixtureFiles(),
    ];
    const { refName } = await pushFiles(ctx, `probe/19-${ctx.stamp}-dotnet`, files, { base });
    for (const run of runs) {
      const policy = await createPolicy(ctx, {
        isEnabled: true,
        isBlocking: true,
        type: { id: BUILD_POLICY },
        settings: {
          buildDefinitionId: run.definitionId,
          queueOnSourceUpdateOnly: false,
          manualQueueOnly: false,
          displayName: `Qualor probe item 19 ${run.label ?? run.form}`,
          validDuration: 0,
          scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
        },
      });
      run.policyId = policy.id;
    }
    const created = await createPr(ctx, refName, { targetRefName: target });
    const { pr } = await prWithMerge(ctx, created.pr.pullRequestId);
    for (const run of runs) {
      outcomes.push(await checkForm(ctx, run, { pr, target, source: refName, repo }));
    }
  }
  const skipped = runs.length === 1 ? [`dotnet task form skipped: ${extensionWhy}`] : [];
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass =
    checks.every((c) => c.pass) &&
    checks.length >= 9 &&
    outcomes.every((o) => o.pass) &&
    outcomes.length === runs.length;
  const detail = [
    `pull request ${prId} into a probe target branch; image qualor/scanner:${BENCH_IMAGE_TAG}`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${n}`),
    ...outcomes.map((o) => o.text),
    ...skipped,
  ].join('\n\n');
  return result(ctx, pass ? 'yes' : 'no', detail);
}
