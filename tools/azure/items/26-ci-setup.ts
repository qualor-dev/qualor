import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import {
  BUILD_POLICY,
  InterruptedError,
  answerOf,
  authorizeQueue,
  buildLogs,
  createBranchAt,
  createPolicy,
  createPr,
  createdNumber,
  deleteBranch,
  evaluations,
  getBuild,
  messageOf,
  prWithMerge,
  refHead,
  repoInfo,
  result,
  shape,
  trackDefinition,
  waitBuild,
  waitFor,
  type ProbeContext,
  type ProbeItem,
  type TargetName,
} from './common.js';

const YAML_PATH = '.azure-pipelines/qualor.yml';
const HOSTED_QUEUE = 'Azure Pipelines';
/** Azure DevOps Server has no hosted pool: the run goes to the bench's own pool `Default`. */
const SERVER_QUEUE = 'Default';
const ZEROS = '0'.repeat(40);
/** A hosted run (Server: a run on `Default`) must start within this long without any authorisation. */
const START_MS = 5 * 60_000;
const API = { apiVersion: '7.0-preview.1' };

/**
 * The setup's pipeline file: the hosted pool (Server: the pool `Default`), a non-ASCII line so the
 * bytes can be compared.
 */
export function setupYaml(target: TargetName = 'services'): string {
  return [
    'trigger: none',
    'pool:',
    target === 'server' ? `  name: ${SERVER_QUEUE}` : '  vmImage: ubuntu-latest',
    'steps:',
    '- script: |',
    '    echo "Qualor probe item 26: Grüße ✓"',
    '  displayName: Qualor probe item 26',
    '',
  ].join('\n');
}

const QueuesSchema = z.object({
  value: z.array(
    z.object({
      id: z.number(),
      name: z.string(),
      pool: z.object({ id: z.number(), name: z.string() }).loose().optional(),
    }),
  ),
});
type Queue = z.infer<typeof QueuesSchema>['value'][number];

/** The queue called exactly `name` (the list may hold others whose names start alike). */
export function queueNamed(queues: Queue[], name: string): Queue | undefined {
  return queues.find((q) => q.name === name);
}

/** One line per queue: id, name and pool name. */
export function queueLines(queues: Queue[]): string[] {
  return queues.map((q) => `${q.id} ${q.name} (pool ${q.pool?.name ?? 'none'})`);
}

const ItemsSchema = z.object({
  value: z.array(z.object({ path: z.string(), isFolder: z.boolean().optional() }).loose()),
});

/** The entries of a folder listing as `path` plus `/` for a folder. */
export function rootEntries(json: unknown): string[] {
  const parsed = ItemsSchema.safeParse(json);
  if (!parsed.success) return [];
  return parsed.data.value.map((e) => (e.isFolder ? `${e.path}/` : e.path));
}

const DefinitionListSchema = z.object({
  value: z.array(
    z
      .object({
        id: z.number(),
        process: z.object({ yamlFilename: z.string().optional() }).loose().optional(),
      })
      .loose(),
  ),
});

/** The `process.yamlFilename` of definition `id` in a definitions list; undefined when not listed. */
export function listedYamlFilename(json: unknown, id: number): string | undefined {
  const parsed = DefinitionListSchema.safeParse(json);
  if (!parsed.success) return undefined;
  return parsed.data.value.find((d) => d.id === id)?.process?.yamlFilename;
}

/** The ids of a policy configurations list. */
export function listedPolicyIds(json: unknown): number[] {
  const parsed = z.object({ value: z.array(z.object({ id: z.number() }).loose()) }).safeParse(json);
  return parsed.success ? parsed.data.value.map((p) => p.id) : [];
}

type Variables = Record<string, { value?: string | null; isSecret?: boolean }>;

/**
 * The definition as it is PUT back to rotate the token and add the address: the GET body with the
 * new secret value and `QUALOR_URL` (the secret reads back with a null value; sending none keeps it).
 */
export function rotationBody(
  got: Record<string, unknown>,
  token: string,
  url: string,
): Record<string, unknown> {
  const variables = (got['variables'] ?? {}) as Variables;
  return {
    ...got,
    variables: {
      ...variables,
      QUALOR_TOKEN: { value: token, isSecret: true, allowOverride: false },
      QUALOR_URL: { value: url, allowOverride: false },
    },
  };
}

/** How a variable reads back: secret with no value, a value, or absent. */
export function variableReadback(variables: Variables | undefined, key: string): string {
  const v = variables?.[key];
  if (!v) return 'absent';
  const secret = v.isSecret === true ? 'isSecret true' : 'isSecret false';
  return `${v.value === null || v.value === undefined ? 'null value' : 'has a value'}, ${secret}`;
}

/** What Azure answered, without anything secret: status, typeKey and message. */
export function describeAnswer(status: number, json: unknown): string {
  const type =
    json && typeof json === 'object' ? (json as Record<string, unknown>)['typeKey'] : undefined;
  const typeKey = typeof type === 'string' ? ` ${type}` : '';
  return `HTTP ${status}${typeKey}: ${messageOf(json)}`;
}

const PushSchema = z.object({ commits: z.array(z.object({ commitId: z.string() })).min(1) });

type Repo = Awaited<ReturnType<typeof repoInfo>>;
type UsedQueue = NonNullable<ReturnType<typeof queueNamed>>;

/** What every step shares: the repository's URL roots and the facts so far. */
interface Env {
  ctx: ProbeContext;
  facts: string[];
  repo: Repo;
  root: string;
  gitRoot: string;
}

/** A step's answer was not as asserted: the item ends there with the facts so far. */
class Stopped extends Error {
  constructor(
    readonly letter: string,
    why: string,
  ) {
    super(why);
  }
}

/** The queue the steps use: the hosted one, or the Server's Default queue. */
interface QueueUse {
  hosted: UsedQueue;
  kind: string;
  onServer: boolean;
}

/** a: the project's agent queues, by the project's GUID. */
async function stepQueues(env: Env): Promise<QueueUse> {
  const { ctx, facts, root } = env;
  const qres = await ctx.bot.request('GET', `${root}/distributedtask/queues`, undefined, API);
  await ctx.record('queues', answerOf(qres));
  if (qres.status !== 200) {
    throw new Stopped('26a', `queues by project GUID: ${describeAnswer(qres.status, qres.json)}`);
  }
  const queues = shape(QueuesSchema, qres.json, 'agent queues').value;
  // Server: the Default queue takes the hosted queue's place in every step below.
  const onServer = ctx.target === 'server';
  const kind = onServer ? SERVER_QUEUE : 'hosted';
  const wanted = onServer ? SERVER_QUEUE : HOSTED_QUEUE;
  const hosted = queueNamed(queues, wanted);
  const dflt = queueNamed(queues, 'Default');
  facts.push(
    `26a queues by project GUID: HTTP 200, ${queues.length} queues: ${queueLines(queues).join('; ')}`,
  );
  if (!hosted) throw new Stopped('26a', `no queue named ${wanted}`);
  const defaultQueue = dflt ? `id ${dflt.id}` : 'none';
  facts.push(
    `26a ${kind} queue "${hosted.name}" id ${hosted.id}, pool ${hosted.pool?.name ?? 'none'}; Default queue: ${defaultQueue}`,
  );
  return { hosted, kind, onServer };
}

/** b: is the hosted (Server: Default) queue open to all pipelines? True: the setup must authorise. */
async function stepQueuePermissions(env: Env, use: QueueUse): Promise<boolean> {
  const { ctx, facts, root } = env;
  const { hosted, kind, onServer } = use;
  const pres = await ctx.bot.request(
    'GET',
    `${root}/pipelines/pipelinePermissions/queue/${hosted.id}`,
    undefined,
    API,
  );
  await ctx.record(`${onServer ? 'default' : 'hosted'}-queue-permissions`, answerOf(pres));
  const perms = pres.json as {
    allPipelines?: { authorized?: boolean } | null;
    pipelines?: unknown[];
  };
  const allPipelines = perms?.allPipelines ? String(perms.allPipelines.authorized) : 'absent';
  facts.push(
    `26b ${kind} queue permissions: ${describeAnswer(pres.status, pres.status === 200 ? {} : pres.json)}; allPipelines ${allPipelines}; ${perms?.pipelines?.length ?? 0} listed pipelines`,
  );
  // Server's Default queue is not open to all pipelines: the setup authorises its pipeline on it.
  return onServer && perms?.allPipelines?.authorized !== true;
}

/** c: a new branch with one base64 file, from the default branch's head. */
async function stepPush(env: Env) {
  const { ctx, facts, repo, gitRoot } = env;
  const base = await refHead(ctx, repo.defaultBranch);
  if (!base) throw new Stopped('26c', 'no head on the default branch');
  const branch = `probe/26-${ctx.stamp}`;
  const refName = `refs/heads/${branch}`;
  const bytes = Buffer.from(setupYaml(ctx.target), 'utf8');
  ctx.cleanup.add(`delete branch ${branch}`, () => deleteBranch(ctx, refName));
  const push = await ctx.bot.request('POST', `${gitRoot}/pushes`, {
    refUpdates: [{ name: refName, oldObjectId: ZEROS }],
    commits: [
      {
        comment: 'Qualor probe item 26',
        parents: [base],
        changes: [
          {
            changeType: 'add',
            item: { path: `/${YAML_PATH}` },
            newContent: { content: bytes.toString('base64'), contentType: 'base64encoded' },
          },
        ],
      },
    ],
  });
  await ctx.record('push', answerOf(push));
  if (push.status >= 300) {
    throw new Stopped('26c', `base64 add push: ${describeAnswer(push.status, push.json)}`);
  }
  const commit = shape(PushSchema, push.json, 'push').commits[0]?.commitId ?? '';
  const yamlPathQuery = encodeURIComponent(`/${YAML_PATH}`);
  const raw = await ctx.bot.request(
    'GET',
    `${gitRoot}/items?path=${yamlPathQuery}&versionDescriptor.version=${commit}` +
      '&versionDescriptor.versionType=commit&$format=octetStream',
  );
  const back = typeof raw.json === 'string' ? Buffer.from(raw.json, 'utf8') : Buffer.alloc(0);
  const exact = raw.status === 200 && back.equals(bytes);
  facts.push(
    `26c push of a new branch with one base64 add: HTTP ${push.status}; file read back at the commit: HTTP ${raw.status}, byte-exact ${String(exact)} (${back.length} of ${bytes.length} bytes)`,
  );
  if (!exact) throw new Stopped('26c', 'the file is not byte-exact');
  return { base, refName, commit };
}

/** d: the root listing at that commit. */
async function stepRootListing(env: Env, commit: string): Promise<void> {
  const { ctx, facts, gitRoot } = env;
  const list = await ctx.bot.request(
    'GET',
    `${gitRoot}/items?scopePath=/&recursionLevel=OneLevel&versionDescriptor.version=${commit}&versionDescriptor.versionType=commit`,
  );
  await ctx.record('root-items', answerOf(list));
  facts.push(
    `26d root listing at the commit: HTTP ${list.status}; entries ${rootEntries(list.json).join(', ') || 'none'}`,
  );
}

/** e, first half: a definition on the hosted (Server: Default) queue, authorised when it must be. */
async function stepDefinition(env: Env, use: QueueUse, refName: string, authorise: boolean) {
  const { ctx, facts, repo, root } = env;
  const { hosted, kind } = use;
  const token = `probe-${randomBytes(16).toString('hex')}`;
  ctx.redaction.secrets.push(token);
  const defsPath = `${root}/build/definitions`;
  const created = await ctx.bot.request('POST', defsPath, {
    name: `Qualor probe item 26 ${ctx.stamp}`,
    path: '\\',
    type: 'build',
    queue: { id: hosted.id },
    process: { type: 2, yamlFilename: YAML_PATH },
    repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch: refName },
    variables: {
      QUALOR_TOKEN: { value: token, isSecret: true, allowOverride: false },
      QUALOR_PROJECT_KEY: { value: 'probe/project', allowOverride: false },
    },
  });
  if (created.status < 300) trackDefinition(ctx, createdNumber(created, 'id', 'definition'));
  await ctx.record('definition-create', answerOf(created));
  if (created.status >= 300) {
    throw new Stopped(
      '26e',
      `definition on the ${kind} queue: ${describeAnswer(created.status, created.json)}`,
    );
  }
  const defId = createdNumber(created, 'id', 'definition');
  if (authorise) {
    // As the setup does (settleQueue): PATCH pipelinePermissions for this pipeline alone;
    // clean-up takes it back and checks the queue's permissions read as before.
    const auth = await authorizeQueue(ctx, hosted.id, defId);
    await ctx.record('queue-authorize', answerOf(auth));
    facts.push(
      `26e the ${kind} queue is not open to all pipelines: the definition authorised on it (PATCH pipelinePermissions, as the setup does): ${describeAnswer(auth.status, auth.status < 300 ? {} : auth.json)}`,
    );
    if (auth.status >= 300) throw new Stopped('26e', 'the authorisation on the queue was refused');
  }
  return { defId, defsPath, createdStatus: created.status };
}

/** e, second half: a run on the branch must start (without authorisation unless one was made). */
async function stepRun(
  env: Env,
  use: QueueUse,
  defId: number,
  refName: string,
  authorise: boolean,
) {
  const { ctx, root } = env;
  const { kind } = use;
  const qb = await ctx.bot.request('POST', `${root}/build/builds`, {
    definition: { id: defId },
    sourceBranch: refName,
  });
  await ctx.record('run-queue', answerOf(qb));
  if (qb.status >= 300) {
    const props = JSON.stringify(
      (qb.json as { customProperties?: unknown } | null)?.customProperties ?? null,
    ).slice(0, 600);
    throw new Stopped(
      '26e',
      `queue a run: ${describeAnswer(qb.status, qb.json)}; customProperties ${props}`,
    );
  }
  const queuedId = createdNumber(qb, 'id', 'queued build');
  const startedAt = Date.now();
  const started = await waitFor(
    async () => {
      const got = await getBuild(ctx, queuedId);
      return got.build.status !== 'notStarted' ? got : undefined;
    },
    { timeoutMs: START_MS, intervalMs: 10_000 },
  );
  if (!started) {
    env.facts.push(
      `26e ${kind} run still notStarted after 5 minutes: ${authorise ? 'no agent took it' : 'needs authorisation'}`,
    );
    throw new Stopped(
      '26e',
      `the ${kind} run did not start within 5 minutes ${authorise ? 'after the authorisation' : 'without authorisation'}`,
    );
  }
  const seconds = Math.round((Date.now() - startedAt) / 1000);
  const done = await waitBuild(ctx, queuedId, { timeoutMs: 6 * 60_000 });
  if (done.build.status === 'completed') await buildLogs(ctx, queuedId);
  await ctx.record('run', answerOf(done.res));
  return { seconds, startedStatus: started.build.status, done };
}

/** f: find definitions of the repository. */
async function stepSearch(env: Env, defsPath: string, defId: number): Promise<void> {
  const { ctx, facts, repo } = env;
  const found = await ctx.bot.request(
    'GET',
    `${defsPath}?repositoryId=${repo.id}&repositoryType=TfsGit&includeAllProperties=true`,
  );
  await ctx.record('definitions-search', answerOf(found));
  const yamlName = listedYamlFilename(found.json, defId);
  const listed =
    yamlName === undefined ? 'is NOT listed' : `is listed with process.yamlFilename ${yamlName}`;
  facts.push(
    `26f definitions search by repositoryId: HTTP ${found.status}; the created one ${listed}`,
  );
  if (found.status !== 200 || yamlName !== YAML_PATH) {
    throw new Stopped('26f', 'the created definition is not listed with its yamlFilename');
  }
}

/** g: GET then PUT with a new token and QUALOR_URL; the next GET still shows the secret. */
async function stepRotate(env: Env, defsPath: string, defId: number) {
  const { ctx, facts } = env;
  const got = await ctx.bot.request('GET', `${defsPath}/${defId}`);
  if (got.status !== 200)
    throw new Stopped('26g', `get definition: ${describeAnswer(got.status, got.json)}`);
  const newToken = `probe-${randomBytes(16).toString('hex')}`;
  ctx.redaction.secrets.push(newToken);
  const put = await ctx.bot.request(
    'PUT',
    `${defsPath}/${defId}`,
    rotationBody(got.json as Record<string, unknown>, newToken, 'https://qualor.example.com'),
  );
  await ctx.record('definition-put', answerOf(put));
  const after = await ctx.bot.request('GET', `${defsPath}/${defId}`);
  await ctx.record('definition-get-after', answerOf(after));
  const vars = (after.json as { variables?: Variables } | null)?.variables;
  const putNote = put.status >= 300 ? ` ${messageOf(put.json)}` : '';
  facts.push(
    `26g PUT with a new QUALOR_TOKEN and QUALOR_URL: HTTP ${put.status}${putNote}; next GET: QUALOR_TOKEN ${variableReadback(vars, 'QUALOR_TOKEN')}, QUALOR_URL ${variableReadback(vars, 'QUALOR_URL')}, QUALOR_PROJECT_KEY ${variableReadback(vars, 'QUALOR_PROJECT_KEY')}`,
  );
  return { put, vars };
}

/** h: a non-blocking build policy on a probe target branch; a PR into it gets an evaluation. */
async function stepPolicy(env: Env, defId: number, base: string, refName: string) {
  const { ctx, facts, repo, root } = env;
  const target = await createBranchAt(ctx, `probe/26-target-${ctx.stamp}`, base);
  const policy = await createPolicy(ctx, {
    isEnabled: true,
    isBlocking: false,
    type: { id: BUILD_POLICY },
    settings: {
      buildDefinitionId: defId,
      queueOnSourceUpdateOnly: false,
      manualQueueOnly: false,
      displayName: 'Qualor probe item 26',
      validDuration: 0,
      scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
    },
  });
  await ctx.record('policy-create', answerOf(policy.res));
  const polIsBlocking = (policy.res.json as { isBlocking?: boolean } | null)?.isBlocking;
  const pr = await createPr(ctx, refName, { targetRefName: target });
  const { pr: merged } = await prWithMerge(ctx, pr.pr.pullRequestId);
  const evs = await waitFor(
    async () => {
      const e = await evaluations(ctx, merged);
      return e.list.value.some((v) => v.configuration.id === policy.id) ? e : undefined;
    },
    { timeoutMs: 120_000, intervalMs: 5000 },
  );
  if (!evs) {
    facts.push(
      `26h policy ${policy.id} created (isBlocking ${String(polIsBlocking)}); no evaluation for the PR within 2 minutes`,
    );
    throw new Stopped('26h', 'the pull request has no evaluation for the policy');
  }
  await ctx.record('evaluations', answerOf(evs.res));
  const ev = evs.list.value.find((v) => v.configuration.id === policy.id);
  const evBlocking = (ev?.configuration as { isBlocking?: boolean } | undefined)?.isBlocking;
  const prBuilds = await ctx.bot.request('GET', `${root}/build/builds?definitions=${defId}`);
  const builds =
    (prBuilds.json as { value?: { reason?: string; sourceBranch?: string }[] } | null)?.value ?? [];
  const viaPolicy = builds.filter((b) => b.reason === 'pullRequest').length;
  facts.push(
    `26h policy create with isBlocking false: HTTP ${policy.res.status}, echoes isBlocking ${String(polIsBlocking)}; the PR into the probe target has an evaluation (status ${ev?.status}) whose configuration.isBlocking is ${String(evBlocking)}; pull request builds queued for the definition: ${viaPolicy}`,
  );
  if (evBlocking !== false) throw new Stopped('26h', 'the evaluation is not non-blocking');
  return { policy, target };
}

/** i: find the policy by repository, branch and type; true when the policy is listed. */
async function stepPolicySearch(env: Env, policyId: number, target: string) {
  const { ctx, facts, repo, root } = env;
  const pols = await ctx.bot.request(
    'GET',
    `${root}/policy/configurations?repositoryId=${repo.id}&refName=${encodeURIComponent(target)}&policyType=${BUILD_POLICY}`,
  );
  await ctx.record('policies-search', answerOf(pols));
  const ids = listedPolicyIds(pols.json);
  const listed = ids.includes(policyId);
  facts.push(
    `26i policies search by repositoryId, refName and policyType: HTTP ${pols.status}; the policy ${listed ? 'is listed' : 'is NOT listed'} (${ids.length} found)`,
  );
  return pols.status === 200 && listed;
}

export const item: ProbeItem = {
  id: 26,
  title: "the CI setup's queue, push, pipeline, definition search and policy calls",
  async run(ctx: ProbeContext) {
    const facts: string[] = [];
    const repo = await repoInfo(ctx);
    const root = `/${repo.project.id}/_apis`;
    const env: Env = { ctx, facts, repo, root, gitRoot: `${root}/git/repositories/${repo.id}` };
    try {
      const use = await stepQueues(env);
      const authorise = await stepQueuePermissions(env, use);
      const { base, refName, commit } = await stepPush(env);
      await stepRootListing(env, commit);
      const { defId, defsPath, createdStatus } = await stepDefinition(env, use, refName, authorise);
      const run = await stepRun(env, use, defId, refName, authorise);
      const { kind, hosted } = use;
      const finalResult = run.done.build.result ? ` ${run.done.build.result}` : '';
      facts.push(
        `26e definition on ${kind} queue ${hosted.id}: HTTP ${createdStatus}; run started within ~${run.seconds} s ${authorise ? 'after that authorisation' : 'without any authorisation'} (status ${run.startedStatus}); final ${run.done.build.status}${finalResult}`,
      );
      await stepSearch(env, defsPath, defId);
      const { put, vars } = await stepRotate(env, defsPath, defId);
      const { policy, target } = await stepPolicy(env, defId, base, refName);
      const listed = await stepPolicySearch(env, policy.id, target);
      const complete = listed && put.status < 300 && vars?.['QUALOR_TOKEN']?.isSecret === true;
      return result(ctx, complete ? 'yes' : 'partly', facts.join('\n\n'));
    } catch (err) {
      if (err instanceof InterruptedError) throw err;
      if (err instanceof Stopped) {
        facts.push(`${err.letter} NOT AS ASSERTED: ${err.message}`);
        return result(ctx, 'no', facts.join('\n\n'));
      }
      facts.push(`ERROR: ${(err as Error).message}`);
      return result(ctx, 'no', facts.join('\n\n'));
    }
  },
};
