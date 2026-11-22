import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import {
  answerOf,
  authorizeQueue,
  buildLogs,
  createdNumber,
  keptLogLines,
  defaultQueueId,
  messageOf,
  ok,
  pipelineYaml,
  printedValues,
  pushFiles,
  queueBuild,
  queuePermissions,
  repoInfo,
  result,
  shape,
  trackDefinition,
  waitBuild,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const YAML_PATH = '.azure-pipelines/qualor.yml';
const HOSTED_PATH = '.azure-pipelines/qualor-hosted.yml';

/**
 * The step that says whether the secret reached it. The macro is split in the comparison so that
 * Azure DevOps does not expand it there: an undefined variable leaves `$(QUALOR_TOKEN)` as text.
 */
export const TOKEN_STEP = [
  '- checkout: self',
  '  fetchDepth: 1',
  '- script: |',
  `    if [ -z "$QUALOR_TOKEN" ] || [ "$QUALOR_TOKEN" = '$''(QUALOR_TOKEN)' ]; then echo "QUALOR_TOKEN=missing"; else echo "QUALOR_TOKEN=set"; fi`,
  '    echo "QUALOR_TOKEN_LENGTH=${#QUALOR_TOKEN}"',
  '  displayName: Qualor probe item 8',
  '  env:',
  '    QUALOR_TOKEN: $(QUALOR_TOKEN)',
].join('\n');

const DefinitionSchema = z.object({
  id: z.number(),
  revision: z.number(),
  variables: z.record(
    z.string(),
    z.object({ value: z.string().nullish(), isSecret: z.boolean().optional() }),
  ),
});

/** Runs a build to the end; says whether the secret reached the step, and if the pool waited. */
async function runOnce(
  ctx: ProbeContext,
  defId: number,
  /** The self-hosted queue to check the pipeline's authorization on; none for a hosted run. */
  queueId: number | undefined,
  sourceBranch: string,
  n: number,
  minutes = 10,
): Promise<{ token: string; length: string; result: string; waited: string }> {
  const queued = await queueBuild(ctx, defId, sourceBranch);
  await ctx.record(`queue-${n}`, answerOf(queued.res));
  let waited =
    queueId === undefined ? 'pool not checked' : 'started without waiting for an authorization';
  const onWaiting = async (q: number) => {
    const perms = await queuePermissions(ctx, q);
    await ctx.record(`queue-permissions-waiting-${n}`, answerOf(perms.res));
    if (perms.open || perms.authorized(defId)) {
      waited = 'not started after 90 s although the queue is authorized (agent busy or offline?)';
      return;
    }
    const auth = await authorizeQueue(ctx, q, defId);
    await ctx.record(`queue-authorize-${n}`, answerOf(auth));
    waited =
      `waited for pool authorization (queue ${q} not open to all pipelines); ` +
      `PATCH pipelinePermissions answered HTTP ${auth.status}`;
  };
  const done = await waitBuild(ctx, queued.id, {
    timeoutMs: minutes * 60_000,
    stuckMs: 90_000,
    ...(queueId === undefined ? {} : { onWaiting: () => onWaiting(queueId) }),
  });
  if (done.build.status !== 'completed') {
    await ctx.record(`build-${n}`, answerOf(done.res));
    return { token: 'unknown', length: '?', result: `not completed in ${minutes} min`, waited };
  }
  // The logs first: reading them adds the agent's name to the redaction table.
  const logs = await buildLogs(ctx, queued.id);
  await ctx.record(`build-${n}`, answerOf(done.res));
  let token = 'not printed';
  let length = '?';
  for (const [logId, lines] of logs) {
    const values = printedValues(lines, ['QUALOR_TOKEN', 'QUALOR_TOKEN_LENGTH']);
    if (values['QUALOR_TOKEN'] && token === 'not printed') {
      token = values['QUALOR_TOKEN'];
      length = values['QUALOR_TOKEN_LENGTH'] ?? '?';
      // Only the printed lines: the rest of a step log names the agent and its machine.
      const kept = keptLogLines(lines, ['QUALOR_TOKEN', 'QUALOR_TOKEN_LENGTH']);
      await ctx.record(`build-${n}-log`, { logId, lines: kept });
    }
  }
  return { token, length, result: done.build.result ?? 'none', waited };
}

export const item: ProbeItem = {
  id: 8,
  title: 'a Build definition on a probe-branch YAML runs, and its secret survives GET and PUT',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const branch = `probe/8-${ctx.stamp}`;
    const files = [{ path: `/${YAML_PATH}`, content: pipelineYaml(TOKEN_STEP) }];
    if (ctx.target === 'services') {
      files.push({
        path: `/${HOSTED_PATH}`,
        content: TOKEN_STEP.replace(
          /^/,
          'trigger: none\npool:\n  vmImage: ubuntu-latest\nsteps:\n',
        ),
      });
    }
    const { refName } = await pushFiles(ctx, branch, files);
    const queueId = await defaultQueueId(ctx);
    const before = await queuePermissions(ctx, queueId);
    await ctx.record('queue-permissions-before', answerOf(before.res));

    const secret = `probe-${randomBytes(16).toString('hex')}`;
    ctx.redaction.secrets.push(secret);
    const definition = (yamlFilename: string, defaultBranch: string, name: string) => ({
      name,
      path: '\\',
      type: 'build',
      queue: { id: queueId },
      process: { type: 2, yamlFilename },
      repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch },
      variables: { QUALOR_TOKEN: { value: secret, isSecret: true, allowOverride: false } },
    });
    const defsPath = `/${ctx.project}/_apis/build/definitions`;
    const name = `Qualor probe item 8 ${ctx.stamp}`;

    // The repository's default branch does not have the file; the probe branch does.
    // A created definition (it holds the secret) is tracked for clean-up before anything else.
    const post = async (body: Record<string, unknown>) => {
      const res = await ctx.bot.request('POST', defsPath, body);
      if (res.status < 300) trackDefinition(ctx, createdNumber(res, 'id', 'create definition'));
      return res;
    };
    let createdOn = repo.defaultBranch;
    let created = await post(definition(YAML_PATH, repo.defaultBranch, name));
    await ctx.record('definition-create-default-branch', answerOf(created));
    const onDefault =
      created.status < 300
        ? `accepted (HTTP ${created.status})`
        : `refused: HTTP ${created.status} ${messageOf(created.json)}`;
    if (created.status >= 300) {
      createdOn = refName;
      created = await post(definition(YAML_PATH, refName, name));
      await ctx.record('definition-create-probe-branch', answerOf(created));
      ok(created, 'create build definition on the probe branch');
    }
    const def = shape(DefinitionSchema, created.json, 'build definition');

    const first = await runOnce(ctx, def.id, queueId, refName, 1);

    // GET, then PUT the same definition back: does the secret survive?
    const got = ok(await ctx.bot.request('GET', `${defsPath}/${def.id}`), 'get definition');
    await ctx.record('definition-get', answerOf(got));
    const read = shape(DefinitionSchema, got.json, 'definition');
    const readSecret = read.variables['QUALOR_TOKEN'];
    const put = await ctx.bot.request('PUT', `${defsPath}/${def.id}`, got.json);
    await ctx.record('definition-put', answerOf(put));
    ok(put, 'put definition');
    const second = await runOnce(ctx, def.id, queueId, refName, 2);

    let hosted = 'not tried on server (no hosted pool)';
    if (ctx.target === 'services') {
      const h = await post(definition(HOSTED_PATH, refName, `${name} hosted`));
      await ctx.record('definition-create-hosted', answerOf(h));
      if (h.status < 300) {
        const hostedDef = shape(DefinitionSchema, h.json, 'hosted definition');
        const hostedRun = await runOnce(ctx, hostedDef.id, undefined, refName, 3, 3);
        hosted = `result ${hostedRun.result}, token ${hostedRun.token}; ${hostedRun.waited}`;
      } else {
        hosted = `definition refused: HTTP ${h.status} ${messageOf(h.json)}`;
      }
    }

    const detail = [
      `definition with yamlFilename ${YAML_PATH} and defaultBranch ${repo.defaultBranch} (file absent there): ${onDefault}; created on ${createdOn}`,
      `queue ${queueId} (Default) before the run: ${before.open ? 'open to all pipelines' : 'not open to all pipelines'}`,
      `run 1 on the probe branch: result ${first.result}, QUALOR_TOKEN ${first.token} (length ${first.length}); ${first.waited}`,
      `GET definition: the secret reads back as ${readSecret ? (readSecret.value ? 'a value' : 'null') : 'absent'}, isSecret ${String(readSecret?.isSecret)}; PUT of the same body: HTTP ${put.status}`,
      `run 2 after GET+PUT: result ${second.result}, QUALOR_TOKEN ${second.token} (length ${second.length}); ${second.waited}`,
      `hosted pool (vmImage ubuntu-latest): ${hosted}`,
    ].join('\n\n');
    let answer: 'yes' | 'partly' | 'no' = 'no';
    if (first.token === 'set' && second.token === 'set') answer = 'yes';
    else if (first.token === 'set') answer = 'partly';
    return result(ctx, answer, detail);
  },
};
