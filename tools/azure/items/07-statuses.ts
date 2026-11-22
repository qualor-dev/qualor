import { z } from 'zod';
import {
  answerOf,
  createBranchAt,
  createPolicy,
  createPr,
  evaluations,
  gitPath,
  messageOf,
  ok,
  prWithMerge,
  probeSource,
  pushFiles,
  refHead,
  repoInfo,
  result,
  shape,
  waitFor,
  type Pr,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** The Status check policy type (SDK source; checked against `policy/types` below). */
const STATUS_POLICY = 'cbdc66da-9728-4af8-aada-9a5a32e4a226';
const CONTEXT = { name: 'probe-7', genre: 'qualor' };

async function policyStatus(ctx: ProbeContext, pr: Pr, policyId: number) {
  const { list, res } = await evaluations(ctx, pr);
  return { status: list.value.find((e) => e.configuration.id === policyId)?.status, res };
}

/** The policy's evaluation once it differs from `previous` (or after 20 s), recorded as `call`. */
async function settle(
  ctx: ProbeContext,
  pr: Pr,
  policyId: number,
  previous: string | undefined,
  call: string,
): Promise<string> {
  let last = await policyStatus(ctx, pr, policyId);
  await waitFor(
    async () => {
      last = await policyStatus(ctx, pr, policyId);
      return last.status !== undefined && last.status !== previous ? true : undefined;
    },
    { timeoutMs: 20_000, intervalMs: 2000 },
  );
  await ctx.record(call, answerOf(last.res));
  return last.status ?? 'no evaluation';
}

export const item: ProbeItem = {
  id: 7,
  title: 'a PR status without iterationId satisfies a "reset on new changes" Status check policy',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const types = ok(
      await ctx.bot.request('GET', `/${ctx.project}/_apis/policy/types`),
      'policy types',
    );
    await ctx.record('policy-types', answerOf(types));
    const typeList = shape(
      z.object({ value: z.array(z.object({ id: z.string(), displayName: z.string() })) }),
      types.json,
      'policy types',
    );
    const statusType = typeList.value.find((t) => t.id === STATUS_POLICY);
    if (!statusType) throw new Error(`policy type ${STATUS_POLICY} (Status) is not on this target`);

    const base = await refHead(ctx, repo.defaultBranch);
    if (!base) throw new Error('no head on the default branch');
    const targetRef = await createBranchAt(ctx, `probe/7-${ctx.stamp}-target`, base);
    const policy = await createPolicy(ctx, {
      isEnabled: true,
      isBlocking: true,
      type: { id: STATUS_POLICY },
      settings: {
        statusName: CONTEXT.name,
        statusGenre: CONTEXT.genre,
        invalidateOnSourceUpdate: true,
        policyApplicability: null,
        defaultDisplayName: 'Qualor probe item 7',
        scope: [{ repositoryId: repo.id, refName: targetRef, matchKind: 'exact' }],
      },
    });
    await ctx.record('policy-create', answerOf(policy.res));
    ctx.log(`Status check policy ${policy.id} on ${targetRef} only`);

    const { refName } = await pushFiles(ctx, `probe/7-${ctx.stamp}`, [probeSource(ctx)], { base });
    const created = await createPr(ctx, refName, { targetRefName: targetRef });
    const { pr } = await prWithMerge(ctx, created.pr.pullRequestId);
    const source = pr.lastMergeSourceCommit?.commitId;
    if (!source) throw new Error('the pull request has no lastMergeSourceCommit');

    const initial = await settle(ctx, pr, policy.id, undefined, 'evaluations-initial');

    // 1. A commit status on the source commit, same context.
    const commitStatus = await ctx.bot.request(
      'POST',
      gitPath(ctx, repo, `/commits/${source}/statuses`),
      { state: 'succeeded', description: 'Qualor probe item 7 (commit status)', context: CONTEXT },
    );
    await ctx.record('commit-status', answerOf(commitStatus));
    const afterCommit = await settle(
      ctx,
      pr,
      policy.id,
      initial,
      'evaluations-after-commit-status',
    );

    // 2. A pull request status without iterationId.
    const prPath = gitPath(ctx, repo, `/pullRequests/${pr.pullRequestId}/statuses`);
    const noIteration = await ctx.bot.request('POST', prPath, {
      state: 'succeeded',
      description: 'Qualor probe item 7 (no iterationId)',
      context: CONTEXT,
    });
    await ctx.record('pr-status-no-iteration', answerOf(noIteration));
    const accepted = noIteration.status >= 200 && noIteration.status < 300;
    const afterPr = await settle(ctx, pr, policy.id, afterCommit, 'evaluations-after-pr-status');

    // 3. The control: a status on the latest iteration.
    const iterations = shape(
      z.object({ value: z.array(z.object({ id: z.number() })).min(1) }),
      ok(
        await ctx.bot.request(
          'GET',
          gitPath(ctx, repo, `/pullRequests/${pr.pullRequestId}/iterations`),
        ),
        'iterations',
      ).json,
      'iterations',
    );
    const iterationId = Math.max(...iterations.value.map((i) => i.id));
    const withIteration = await ctx.bot.request('POST', prPath, {
      state: 'succeeded',
      description: 'Qualor probe item 7 (iteration)',
      context: CONTEXT,
      iterationId,
    });
    await ctx.record('pr-status-iteration', answerOf(withIteration));
    const afterIteration = await settle(
      ctx,
      pr,
      policy.id,
      afterPr,
      'evaluations-after-iteration-status',
    );

    const commitSatisfies = afterCommit === 'approved';
    const prSatisfies = accepted && !commitSatisfies && afterPr === 'approved';
    const detail = [
      `policy evaluation before any status: ${initial}`,
      `commit status on the source commit: HTTP ${commitStatus.status}; evaluation ${afterCommit} (${commitSatisfies ? 'satisfies the policy' : 'does not satisfy it'})`,
      `PR status without iterationId: ${accepted ? `accepted (HTTP ${noIteration.status})` : `refused: HTTP ${noIteration.status} ${messageOf(noIteration.json)}`}; evaluation ${afterPr}` +
        (commitSatisfies
          ? ' (already approved by the commit status: its own effect is unknown)'
          : ''),
      `PR status on iteration ${iterationId} (control): HTTP ${withIteration.status}; evaluation ${afterIteration}`,
      'evaluations: GET _apis/policy/evaluations, api-version 7.0-preview.1',
    ].join('\n\n');
    let answer: 'yes' | 'partly' | 'no' = 'no';
    if (prSatisfies) answer = 'yes';
    else if (accepted) answer = 'partly';
    return result(ctx, answer, detail);
  },
};
