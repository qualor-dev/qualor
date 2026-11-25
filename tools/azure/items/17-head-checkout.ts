import { z } from 'zod';
import {
  BUILD_POLICY,
  answerOf,
  authorizeQueue,
  BuildSchema,
  buildLogs,
  keptLogLines,
  createBranchAt,
  createDefinition,
  createPolicy,
  createPr,
  defaultQueueId,
  evaluations,
  ok,
  pipelineYaml,
  printedValues,
  prWithMerge,
  probeSource,
  pushFiles,
  queuePermissions,
  refHead,
  repoInfo,
  result,
  shape,
  waitBuild,
  waitFor,
  type Pr,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const YAML_PATH = '.azure-pipelines/qualor.yml';
const NAMES = [
  'BUILD_SOURCEVERSION',
  'BUILD_SOURCEBRANCH',
  'BUILD_REASON',
  'SYSTEM_PULLREQUEST_SOURCECOMMITID',
  'SYSTEM_PULLREQUEST_PULLREQUESTID',
  'HEAD2',
  'CHECKED_OUT',
];

/** Prints the variables and HEAD, then checks out the merge commit's second parent. */
export const HEAD_STEPS = [
  '- checkout: self',
  '  fetchDepth: 0',
  '- script: |',
  '    echo "BUILD_SOURCEVERSION=$BUILD_SOURCEVERSION"',
  '    echo "BUILD_SOURCEBRANCH=$BUILD_SOURCEBRANCH"',
  '    echo "BUILD_REASON=$BUILD_REASON"',
  '    echo "SYSTEM_PULLREQUEST_SOURCECOMMITID=${SYSTEM_PULLREQUEST_SOURCECOMMITID:-unset}"',
  '    echo "SYSTEM_PULLREQUEST_PULLREQUESTID=${SYSTEM_PULLREQUEST_PULLREQUESTID:-unset}"',
  '    echo "--- git cat-file -p HEAD"',
  '    git cat-file -p HEAD',
  '    echo "--- end"',
  '    SECOND=`git rev-parse HEAD^2`',
  '    echo "HEAD2=$SECOND"',
  '    git checkout --detach "$SECOND"',
  '    echo "CHECKED_OUT=`git rev-parse HEAD`"',
  '  displayName: Qualor probe item 17',
].join('\n');

/** The `parent` lines of the `git cat-file -p HEAD` the step printed. */
export function parentsOf(lines: string[]): string[] {
  const text = lines.map((l) => l.replace(/^\d{4}-\d{2}-\d{2}T\S+\s/, ''));
  const start = text.indexOf('--- git cat-file -p HEAD');
  const end = text.indexOf('--- end', start + 1);
  if (start < 0 || end < 0) return [];
  return text
    .slice(start + 1, end)
    .map((l) => /^parent ([0-9a-f]{40,64})$/.exec(l.trim())?.[1])
    .filter((p): p is string => p !== undefined);
}

/** The build the policy queued for the pull request (or one queued by a requeue). */
async function policyBuild(ctx: ProbeContext, definitionId: number) {
  return waitFor(
    async () => {
      const res = ok(
        await ctx.bot.request(
          'GET',
          `/${ctx.project}/_apis/build/builds?definitions=${definitionId}`,
        ),
        'builds',
      );
      return shape(z.object({ value: z.array(BuildSchema) }), res.json, 'builds').value[0];
    },
    { timeoutMs: 120_000, intervalMs: 5000 },
  );
}

/** Requeues the policy's evaluation once; undefined when the policy has no evaluation yet. */
async function requeuePolicy(
  ctx: ProbeContext,
  pr: Pr,
  policyId: number,
  definitionId: number,
): Promise<{ queued: Awaited<ReturnType<typeof policyBuild>> } | undefined> {
  const { list } = await evaluations(ctx, pr);
  const ev = list.value.find((e) => e.configuration.id === policyId);
  if (!ev) return undefined;
  await ctx.bot.request(
    'PATCH',
    `/${ctx.project}/_apis/policy/evaluations/${ev.evaluationId}`,
    undefined,
    {
      apiVersion: '7.0-preview.1',
    },
  );
  return { queued: await policyBuild(ctx, definitionId) };
}

/** The printed values and the parents of the first log that printed BUILD_SOURCEVERSION. */
async function readPrinted(
  ctx: ProbeContext,
  logs: Map<number, string[]>,
): Promise<{ values: Record<string, string>; parents: string[] }> {
  let values: Record<string, string> = {};
  let parents: string[] = [];
  for (const [logId, lines] of logs) {
    const found = printedValues(lines, NAMES);
    if (found['BUILD_SOURCEVERSION'] && values['BUILD_SOURCEVERSION'] === undefined) {
      values = found;
      parents = parentsOf(lines);
      // Only the printed lines and the cat-file block: the rest names the agent's machine.
      const kept = keptLogLines(lines, NAMES, ['--- git cat-file -p HEAD', '--- end']);
      await ctx.record('build-log', { logId, lines: kept });
    }
  }
  return { values, parents };
}

interface HeadDetail {
  buildId: number;
  how: string;
  authorized: string;
  build: { result?: string | null; reason?: string | null; sourceBranch?: string | null };
  values: Record<string, string>;
  parents: string[];
  head: string | undefined;
  merge: string | undefined;
  secondIsHead: boolean;
  checkedOut: boolean;
}

function sourceCommitText(sourceCommit: string | undefined, head: string | undefined): string {
  if (sourceCommit === undefined || sourceCommit === 'unset') return 'not set on this target';
  if (sourceCommit === head) return 'set, = the PR head';
  return `set, = ${sourceCommit} (head ${head ?? '?'})`;
}

function headDetail(d: HeadDetail): string {
  const { values, parents, head, merge } = d;
  const version = values['BUILD_SOURCEVERSION'];
  const versionText =
    version === merge
      ? 'is the merge commit (lastMergeCommit)'
      : `= ${version ?? 'not printed'} (lastMergeCommit ${merge ?? '?'})`;
  const secondText = d.secondIsHead
    ? 'is the PR head (lastMergeSourceCommit)'
    : `is not the head (${parents[1] ?? 'none'} vs ${head ?? '?'})`;
  const checkedText = d.checkedOut
    ? 'checked out the PR head'
    : `CHECKED_OUT ${values['CHECKED_OUT'] ?? 'not printed'}`;
  return [
    `build ${d.buildId}: ${d.how}; result ${d.build.result ?? 'none'}, reason ${d.build.reason ?? '?'}, sourceBranch ${d.build.sourceBranch ?? '?'}; ${d.authorized}`,
    `BUILD_SOURCEVERSION ${versionText}`,
    `SYSTEM_PULLREQUEST_SOURCECOMMITID: ${sourceCommitText(values['SYSTEM_PULLREQUEST_SOURCECOMMITID'], head)}`,
    `git cat-file -p HEAD: ${parents.length} parent(s); second parent ${secondText}`,
    `git checkout --detach HEAD^2 with fetchDepth 0: ${checkedText}`,
  ].join('\n\n');
}

export const item: ProbeItem = {
  id: 17,
  title: "a pull request build checks out the PR head as the merge commit's second parent",
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const base = await refHead(ctx, repo.defaultBranch);
    if (!base) throw new Error('no head on the default branch');
    const targetRef = await createBranchAt(ctx, `probe/17-${ctx.stamp}-target`, base);
    const { refName } = await pushFiles(
      ctx,
      `probe/17-${ctx.stamp}`,
      [{ path: `/${YAML_PATH}`, content: pipelineYaml(HEAD_STEPS) }, probeSource(ctx)],
      { base },
    );

    const queueId = await defaultQueueId(ctx);
    const def = await createDefinition(ctx, {
      name: `Qualor probe item 17 ${ctx.stamp}`,
      path: '\\',
      type: 'build',
      queue: { id: queueId },
      process: { type: 2, yamlFilename: YAML_PATH },
      repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch: refName },
    });
    await ctx.record('definition-create', answerOf(def.res));
    const perms = await queuePermissions(ctx, queueId);
    let authorized = 'queue open or pipeline already authorized';
    if (!perms.open && !perms.authorized(def.id)) {
      const auth = await authorizeQueue(ctx, queueId, def.id);
      authorized = `pipeline authorized on queue ${queueId} first (HTTP ${auth.status})`;
    }

    const policy = await createPolicy(ctx, {
      isEnabled: true,
      isBlocking: true,
      type: { id: BUILD_POLICY },
      settings: {
        buildDefinitionId: def.id,
        queueOnSourceUpdateOnly: false,
        manualQueueOnly: false,
        displayName: 'Qualor probe item 17',
        validDuration: 0,
        scope: [{ repositoryId: repo.id, refName: targetRef, matchKind: 'exact' }],
      },
    });
    await ctx.record('policy-create', answerOf(policy.res));
    ctx.log(`Build validation policy ${policy.id} on ${targetRef} only`);

    const created = await createPr(ctx, refName, { targetRefName: targetRef });
    const { pr } = await prWithMerge(ctx, created.pr.pullRequestId);
    let queued = await policyBuild(ctx, def.id);
    let how = 'queued by the Build validation policy';
    if (!queued) {
      const requeued = await requeuePolicy(ctx, pr, policy.id, def.id);
      if (requeued) {
        queued = requeued.queued;
        how = 'queued by a requeue of the policy evaluation';
      }
    }
    if (!queued)
      return result(ctx, 'no', `no build was queued for the pull request (${authorized})`);
    const done = await waitBuild(ctx, queued.id, { timeoutMs: 10 * 60_000 });
    // An unfinished build may have no logs to read yet; it is not recorded (its agent's name is
    // not known to the redaction table before the logs are read).
    if (done.build.status !== 'completed') {
      return result(
        ctx,
        'no',
        `the build did not complete within 10 minutes (${how}; ${authorized})`,
      );
    }
    // The logs first: reading them adds the agent's name to the redaction table.
    const logs = await buildLogs(ctx, queued.id);
    await ctx.record('build', answerOf(done.res));
    const evals = await evaluations(ctx, pr);
    await ctx.record('evaluations', answerOf(evals.res));

    const { values, parents } = await readPrinted(ctx, logs);
    const head = pr.lastMergeSourceCommit?.commitId;
    const merge = pr.lastMergeCommit?.commitId;
    const secondIsHead = parents.length === 2 && parents[1] === head;
    const checkedOut = values['CHECKED_OUT'] === head;
    const detail = headDetail({
      buildId: queued.id,
      how,
      authorized,
      build: done.build,
      values,
      parents,
      head,
      merge,
      secondIsHead,
      checkedOut,
    });
    return result(ctx, secondIsHead && checkedOut ? 'yes' : 'no', detail);
  },
};
