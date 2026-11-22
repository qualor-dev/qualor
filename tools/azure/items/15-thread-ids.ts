import {
  answerOf,
  createPr,
  ok,
  probeSource,
  pushFiles,
  repoInfo,
  result,
  shape,
  ThreadListSchema,
  ThreadSchema,
  threadsPath,
  type Answer,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/**
 * How thread ids are numbered, from threads created in the order A1, B1, A2 on pull requests A
 * and B and every thread id each pull request lists (system threads included): an id on both
 * pull requests means one counter per pull request; disjoint ids with A1 < B1 < A2 mean one
 * counter across pull requests. Anything else is undecided.
 */
export function threadIdScope(
  a1: number,
  b1: number,
  a2: number,
  idsA: readonly number[],
  idsB: readonly number[],
): Answer | undefined {
  const onA = new Set([...idsA, a1, a2]);
  if ([...idsB, b1].some((id) => onA.has(id))) return 'per-pull-request';
  if (a1 < b1 && b1 < a2) return 'per-collection';
  return undefined;
}

async function thread(ctx: ProbeContext, prId: number, label: string, call?: string) {
  const repo = await repoInfo(ctx);
  const res = ok(
    await ctx.bot.request('POST', threadsPath(ctx, repo, prId), {
      comments: [{ parentCommentId: 0, content: `Qualor probe item 15: ${label}`, commentType: 1 }],
      status: 1,
    }),
    `thread ${label}`,
  );
  if (call) await ctx.record(call, answerOf(res));
  return shape(ThreadSchema, res.json, `thread ${label}`).id;
}

export const item: ProbeItem = {
  id: 15,
  title: 'thread ids: one counter across pull requests, or one per pull request',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const a = await pushFiles(ctx, `probe/15-${ctx.stamp}-a`, [probeSource(ctx)]);
    const b = await pushFiles(ctx, `probe/15-${ctx.stamp}-b`, [
      { ...probeSource(ctx), path: `/probe/item-15-${ctx.stamp}-b.ts` },
    ]);
    const prA = (await createPr(ctx, a.refName, { title: `Qualor probe item 15 A (${ctx.stamp})` }))
      .pr;
    const prB = (await createPr(ctx, b.refName, { title: `Qualor probe item 15 B (${ctx.stamp})` }))
      .pr;
    const a1 = await thread(ctx, prA.pullRequestId, 'A1', 'thread-a1');
    const b1 = await thread(ctx, prB.pullRequestId, 'B1', 'thread-b1');
    const a2 = await thread(ctx, prA.pullRequestId, 'A2');
    const listB = ok(
      await ctx.bot.request('GET', threadsPath(ctx, repo, prB.pullRequestId)),
      'threads of B',
    );
    await ctx.record('threads-b', answerOf(listB));
    const idsB = shape(ThreadListSchema, listB.json, 'threads of B').value.map((t) => t.id);
    const listA = ok(
      await ctx.bot.request('GET', threadsPath(ctx, repo, prA.pullRequestId)),
      'threads of A',
    );
    const idsA = shape(ThreadListSchema, listA.json, 'threads of A').value.map((t) => t.id);
    const answer = threadIdScope(a1, b1, a2, idsA, idsB);
    const detail =
      `threads created in order: A1 = ${a1} (PR ${prA.pullRequestId}), B1 = ${b1} (PR ${prB.pullRequestId}), A2 = ${a2}; ` +
      `all thread ids (system threads included) on A: ${idsA.join(', ')}; on B: ${idsB.join(', ')}` +
      (answer ? '' : '; the order fits neither numbering');
    return result(ctx, answer ?? 'no', detail);
  },
};
