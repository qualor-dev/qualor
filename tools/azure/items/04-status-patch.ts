import {
  answerOf,
  createPr,
  ok,
  probeSource,
  pushFiles,
  repoInfo,
  result,
  shape,
  ThreadSchema,
  threadsPath,
  type ProbeContext,
  type ProbeItem,
  type Thread,
} from './common.js';

/** Everything of a thread a status change must leave alone. */
export function threadSansStatus(t: Thread): unknown {
  return {
    comments: t.comments.map((c) => ({
      id: c.id,
      parentCommentId: c.parentCommentId,
      content: c.content,
      commentType: c.commentType,
      isDeleted: c.isDeleted,
      author: c.author.id,
    })),
    properties: t.properties ?? null,
    threadContext: t.threadContext ?? null,
    pullRequestThreadContext: t.pullRequestThreadContext ?? null,
    isDeleted: t.isDeleted ?? false,
  };
}

async function patchStatus(
  ctx: ProbeContext,
  path: string,
  status: number,
  call: string,
): Promise<{ http: number; thread: Thread }> {
  const res = await ctx.bot.request('PATCH', path, { status });
  await ctx.record(call, answerOf(res));
  ok(res, `PATCH {status: ${status}}`);
  const got = ok(await ctx.bot.request('GET', path), 'get thread');
  return { http: res.status, thread: shape(ThreadSchema, got.json, 'thread') };
}

export const item: ProbeItem = {
  id: 4,
  title: 'a status-only thread PATCH resolves and reopens, and changes nothing else',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const file = probeSource(ctx);
    const { refName } = await pushFiles(ctx, `probe/4-${ctx.stamp}`, [file]);
    const { pr } = await createPr(ctx, refName);
    const created = ok(
      await ctx.bot.request('POST', threadsPath(ctx, repo, pr.pullRequestId), {
        comments: [{ parentCommentId: 0, content: 'Qualor probe item 4', commentType: 1 }],
        status: 1,
        properties: { 'Qualor.Marker': 'issue 4' },
      }),
      'create thread',
    );
    const before = shape(ThreadSchema, created.json, 'created thread');
    const path = threadsPath(ctx, repo, pr.pullRequestId, `/${before.id}`);

    const fixed = await patchStatus(ctx, path, 2, 'patch-status-fixed');
    const active = await patchStatus(ctx, path, 1, 'patch-status-active');
    const same = (t: Thread) =>
      JSON.stringify(threadSansStatus(t)) === JSON.stringify(threadSansStatus(before));
    const resolvedOk = fixed.thread.status === 'fixed' || fixed.thread.status === 2;
    const reopenedOk = active.thread.status === 'active' || active.thread.status === 1;
    const detail = [
      `{status: 2}: HTTP ${fixed.http}, read back status ${String(fixed.thread.status)}; ${same(fixed.thread) ? 'nothing else changed' : 'other fields changed'}`,
      `{status: 1}: HTTP ${active.http}, read back status ${String(active.thread.status)}; ${same(active.thread) ? 'nothing else changed' : 'other fields changed'}`,
      `compared: comments (id, parent, content, type, deleted, author), properties, threadContext, pullRequestThreadContext, isDeleted`,
    ].join('\n\n');
    const allSame = same(fixed.thread) && same(active.thread);
    const answer = resolvedOk && reopenedOk ? (allSame ? 'yes' : 'partly') : 'no';
    return result(ctx, answer, detail);
  },
};
