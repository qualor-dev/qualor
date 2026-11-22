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
  type ProbeItem,
} from './common.js';

/** The property threads made in the web UI carry; whether API threads need it is part of the check. */
export const SUPPORTS_MARKDOWN = 'Microsoft.TeamFoundation.Discussion.SupportsMarkdown';

const BODY = [
  '<!-- qualor:summary probe -->',
  '**Qualor probe item 2**: the line above is an HTML comment. If it shows, markers are visible.',
  '',
  '- a list item with `code`',
  '- a [link](https://qualor.dev)',
].join('\n');

export const item: ProbeItem = {
  id: 2,
  title: 'an HTML comment marker in a PR comment is hidden (visual check)',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    // Left open for a visual check; `--cleanup-manual` abandons it and deletes the branch.
    const { refName } = await pushFiles(ctx, `probe/2-${ctx.stamp}`, [probeSource(ctx)], {
      keep: true,
    });
    const { pr, webUrl } = await createPr(ctx, refName, { keep: true });
    const path = threadsPath(ctx, repo, pr.pullRequestId);
    const plain = ok(
      await ctx.bot.request('POST', path, {
        comments: [{ parentCommentId: 0, content: BODY, commentType: 1 }],
        status: 1,
      }),
      'thread without properties',
    );
    await ctx.record('thread-plain', answerOf(plain));
    shape(ThreadSchema, plain.json, 'thread');
    const marked = ok(
      await ctx.bot.request('POST', path, {
        comments: [
          {
            parentCommentId: 0,
            content: `${BODY}\n\n(thread with ${SUPPORTS_MARKDOWN}=1)`,
            commentType: 1,
          },
        ],
        status: 1,
        properties: { [SUPPORTS_MARKDOWN]: 1 },
      }),
      'thread with SupportsMarkdown',
    );
    await ctx.record('thread-supports-markdown', answerOf(marked));
    shape(ThreadSchema, marked.json, 'thread');
    return result(
      ctx,
      'manual',
      `pull request ${pr.pullRequestId}, left open: check whether the first line (an HTML comment) is hidden in both threads, ` +
        `and whether Markdown renders in the thread without ${SUPPORTS_MARKDOWN} as in the one with it`,
      [webUrl],
    );
  },
};
