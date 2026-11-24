import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import {
  BUILD_POLICY,
  InterruptedError,
  answerOf,
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
} from './common.js';

const YAML_PATH = '.azure-pipelines/qualor.yml';
const HOSTED_QUEUE = 'Azure Pipelines';
const ZEROS = '0'.repeat(40);
/** A hosted run must start within this long without any authorisation. */
const START_MS = 5 * 60_000;
const API = { apiVersion: '7.0-preview.1' };

/** The setup's pipeline file: the hosted pool, a non-ASCII line so the bytes can be compared. */
export function setupYaml(): string {
  return [
    'trigger: none',
    'pool:',
    '  vmImage: ubuntu-latest',
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
  return `HTTP ${status}${typeof type === 'string' ? ` ${type}` : ''}: ${messageOf(json)}`;
}

const PushSchema = z.object({ commits: z.array(z.object({ commitId: z.string() })).min(1) });

export const item: ProbeItem = {
  id: 26,
  title: "the CI setup's queue, push, pipeline, definition search and policy calls",
  async run(ctx: ProbeContext) {
    const facts: string[] = [];
    const repo = await repoInfo(ctx);
    const pid = repo.project.id;
    const root = `/${pid}/_apis`;
    const gitRoot = `${root}/git/repositories/${repo.id}`;
    const enc = encodeURIComponent;
    const stop = (letter: string, why: string) => {
      facts.push(`${letter} NOT AS ASSERTED: ${why}`);
      return result(ctx, 'no', facts.join('\n\n'));
    };
    try {
      // a: the project's agent queues, by the project's GUID.
      const qres = await ctx.bot.request('GET', `${root}/distributedtask/queues`, undefined, API);
      await ctx.record('queues', answerOf(qres));
      if (qres.status !== 200) {
        return stop('26a', `queues by project GUID: ${describeAnswer(qres.status, qres.json)}`);
      }
      const queues = shape(QueuesSchema, qres.json, 'agent queues').value;
      const hosted = queueNamed(queues, HOSTED_QUEUE);
      const dflt = queueNamed(queues, 'Default');
      facts.push(
        `26a queues by project GUID: HTTP 200, ${queues.length} queues: ${queueLines(queues).join('; ')}`,
      );
      if (!hosted) return stop('26a', `no queue named ${HOSTED_QUEUE}`);
      facts.push(
        `26a hosted queue "${hosted.name}" id ${hosted.id}, pool ${hosted.pool?.name ?? 'none'}; Default queue: ${dflt ? `id ${dflt.id}` : 'none'}`,
      );

      // b: is the hosted queue open to all pipelines?
      const pres = await ctx.bot.request(
        'GET',
        `${root}/pipelines/pipelinePermissions/queue/${hosted.id}`,
        undefined,
        API,
      );
      await ctx.record('hosted-queue-permissions', answerOf(pres));
      const perms = pres.json as {
        allPipelines?: { authorized?: boolean } | null;
        pipelines?: unknown[];
      };
      facts.push(
        `26b hosted queue permissions: ${describeAnswer(pres.status, pres.status === 200 ? {} : pres.json)}; allPipelines ${
          perms?.allPipelines ? String(perms.allPipelines.authorized) : 'absent'
        }; ${perms?.pipelines?.length ?? 0} listed pipelines`,
      );

      // c: a new branch with one base64 file, from the default branch's head.
      const base = await refHead(ctx, repo.defaultBranch);
      if (!base) return stop('26c', 'no head on the default branch');
      const branch = `probe/26-${ctx.stamp}`;
      const refName = `refs/heads/${branch}`;
      const bytes = Buffer.from(setupYaml(), 'utf8');
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
        return stop('26c', `base64 add push: ${describeAnswer(push.status, push.json)}`);
      }
      const commit = shape(PushSchema, push.json, 'push').commits[0]?.commitId ?? '';
      const raw = await ctx.bot.request(
        'GET',
        `${gitRoot}/items?path=${enc(`/${YAML_PATH}`)}&versionDescriptor.version=${commit}` +
          '&versionDescriptor.versionType=commit&$format=octetStream',
      );
      const back = typeof raw.json === 'string' ? Buffer.from(raw.json, 'utf8') : Buffer.alloc(0);
      const exact = raw.status === 200 && back.equals(bytes);
      facts.push(
        `26c push of a new branch with one base64 add: HTTP ${push.status}; file read back at the commit: HTTP ${raw.status}, byte-exact ${String(exact)} (${back.length} of ${bytes.length} bytes)`,
      );
      if (!exact) return stop('26c', 'the file is not byte-exact');

      // d: the root listing at that commit.
      const list = await ctx.bot.request(
        'GET',
        `${gitRoot}/items?scopePath=/&recursionLevel=OneLevel&versionDescriptor.version=${commit}&versionDescriptor.versionType=commit`,
      );
      await ctx.record('root-items', answerOf(list));
      facts.push(
        `26d root listing at the commit: HTTP ${list.status}; entries ${rootEntries(list.json).join(', ') || 'none'}`,
      );

      // e: a definition on the hosted queue; a run on the branch must start without authorisation.
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
        return stop(
          '26e',
          `definition on the hosted queue: ${describeAnswer(created.status, created.json)}`,
        );
      }
      const defId = createdNumber(created, 'id', 'definition');
      const qb = await ctx.bot.request('POST', `${root}/build/builds`, {
        definition: { id: defId },
        sourceBranch: refName,
      });
      await ctx.record('run-queue', answerOf(qb));
      if (qb.status >= 300) {
        return stop(
          '26e',
          `queue a run: ${describeAnswer(qb.status, qb.json)}; customProperties ${JSON.stringify(
            (qb.json as { customProperties?: unknown } | null)?.customProperties ?? null,
          ).slice(0, 600)}`,
        );
      }
      const queued = { id: createdNumber(qb, 'id', 'queued build'), res: qb };
      const startedAt = Date.now();
      const started = await waitFor(
        async () => {
          const got = await getBuild(ctx, queued.id);
          return got.build.status !== 'notStarted' ? got : undefined;
        },
        { timeoutMs: START_MS, intervalMs: 10_000 },
      );
      if (!started) {
        facts.push('26e hosted run still notStarted after 5 minutes: needs authorisation');
        return stop('26e', 'the hosted run did not start within 5 minutes without authorisation');
      }
      const seconds = Math.round((Date.now() - startedAt) / 1000);
      const done = await waitBuild(ctx, queued.id, { timeoutMs: 6 * 60_000 });
      if (done.build.status === 'completed') await buildLogs(ctx, queued.id);
      await ctx.record('run', answerOf(done.res));
      facts.push(
        `26e definition on hosted queue ${hosted.id}: HTTP ${created.status}; run started within ~${seconds} s without any authorisation (status ${started.build.status}); final ${done.build.status}${done.build.result ? ` ${done.build.result}` : ''}`,
      );

      // f: find definitions of the repository.
      const found = await ctx.bot.request(
        'GET',
        `${defsPath}?repositoryId=${repo.id}&repositoryType=TfsGit&includeAllProperties=true`,
      );
      await ctx.record('definitions-search', answerOf(found));
      const yamlName = listedYamlFilename(found.json, defId);
      facts.push(
        `26f definitions search by repositoryId: HTTP ${found.status}; the created one ${yamlName === undefined ? 'is NOT listed' : `is listed with process.yamlFilename ${yamlName}`}`,
      );
      if (found.status !== 200 || yamlName !== YAML_PATH) {
        return stop('26f', 'the created definition is not listed with its yamlFilename');
      }

      // g: GET then PUT with a new token and QUALOR_URL; the next GET still shows the secret.
      const got = await ctx.bot.request('GET', `${defsPath}/${defId}`);
      if (got.status !== 200)
        return stop('26g', `get definition: ${describeAnswer(got.status, got.json)}`);
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
      facts.push(
        `26g PUT with a new QUALOR_TOKEN and QUALOR_URL: HTTP ${put.status}${put.status >= 300 ? ` ${messageOf(put.json)}` : ''}; next GET: QUALOR_TOKEN ${variableReadback(vars, 'QUALOR_TOKEN')}, QUALOR_URL ${variableReadback(vars, 'QUALOR_URL')}, QUALOR_PROJECT_KEY ${variableReadback(vars, 'QUALOR_PROJECT_KEY')}`,
      );

      // h: a non-blocking build policy on a probe target branch; a PR into it gets an evaluation.
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
        return stop('26h', 'the pull request has no evaluation for the policy');
      }
      await ctx.record('evaluations', answerOf(evs.res));
      const ev = evs.list.value.find((v) => v.configuration.id === policy.id);
      const evBlocking = (ev?.configuration as { isBlocking?: boolean } | undefined)?.isBlocking;
      const prBuilds = await ctx.bot.request('GET', `${root}/build/builds?definitions=${defId}`);
      const builds =
        (prBuilds.json as { value?: { reason?: string; sourceBranch?: string }[] } | null)?.value ??
        [];
      const viaPolicy = builds.filter((b) => b.reason === 'pullRequest').length;
      facts.push(
        `26h policy create with isBlocking false: HTTP ${policy.res.status}, echoes isBlocking ${String(polIsBlocking)}; the PR into the probe target has an evaluation (status ${ev?.status}) whose configuration.isBlocking is ${String(evBlocking)}; pull request builds queued for the definition: ${viaPolicy}`,
      );
      if (evBlocking !== false) return stop('26h', 'the evaluation is not non-blocking');

      // i: find the policy by repository, branch and type.
      const pols = await ctx.bot.request(
        'GET',
        `${root}/policy/configurations?repositoryId=${repo.id}&refName=${enc(target)}&policyType=${BUILD_POLICY}`,
      );
      await ctx.record('policies-search', answerOf(pols));
      const ids = listedPolicyIds(pols.json);
      facts.push(
        `26i policies search by repositoryId, refName and policyType: HTTP ${pols.status}; the policy ${ids.includes(policy.id) ? 'is listed' : 'is NOT listed'} (${ids.length} found)`,
      );
      const complete =
        pols.status === 200 &&
        ids.includes(policy.id) &&
        put.status < 300 &&
        vars?.['QUALOR_TOKEN']?.isSecret === true;
      return result(ctx, complete ? 'yes' : 'partly', facts.join('\n\n'));
    } catch (err) {
      if (err instanceof InterruptedError) throw err;
      facts.push(`ERROR: ${(err as Error).message}`);
      return result(ctx, 'no', facts.join('\n\n'));
    }
  },
};
