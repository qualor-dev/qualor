import { SUPPORTS_MARKDOWN } from './02-markers.js';
import {
  answerOf,
  changeTracking,
  createPr,
  lineThread,
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

const suggestion = (note: string, line: string) =>
  [
    `**Qualor probe item 5**: a suggestion posted over REST (${note}). Is there an Apply button?`,
    '',
    '```suggestion',
    line,
    '```',
  ].join('\n');

export const item: ProbeItem = {
  id: 5,
  title: 'a REST-posted ```suggestion block gets the Apply button (visual check)',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const file = probeSource(ctx);
    // Left open for a visual check; `--cleanup-manual` abandons it and deletes the branch.
    const { refName } = await pushFiles(ctx, `probe/5-${ctx.stamp}`, [file], { keep: true });
    const { pr, webUrl } = await createPr(ctx, refName, { keep: true });
    const tracking = await changeTracking(ctx, pr.pullRequestId, file.path);
    const path = threadsPath(ctx, repo, pr.pullRequestId);

    const withProperty = ok(
      await ctx.bot.request('POST', path, {
        ...lineThread(
          file.path,
          4,
          suggestion(
            `${SUPPORTS_MARKDOWN}=1`,
            '  const unused = doubled; // suggested by the probe',
          ),
          tracking,
        ),
        properties: { [SUPPORTS_MARKDOWN]: 1 },
      }),
      'suggestion thread with SupportsMarkdown',
    );
    await ctx.record('thread-suggestion-supports-markdown', answerOf(withProperty));
    shape(ThreadSchema, withProperty.json, 'thread');
    const without = ok(
      await ctx.bot.request(
        'POST',
        path,
        lineThread(
          file.path,
          3,
          suggestion('no properties', '  const doubled = input + input; // suggested by the probe'),
          tracking,
        ),
      ),
      'suggestion thread without properties',
    );
    await ctx.record('thread-suggestion-plain', answerOf(without));
    shape(ThreadSchema, without.json, 'thread');
    return result(
      ctx,
      'manual',
      `pull request ${pr.pullRequestId}, left open: line 4 (thread with ${SUPPORTS_MARKDOWN}=1) and line 3 (no properties) ` +
        `of ${file.path} each carry a suggestion; check for the Apply button on each`,
      [webUrl],
    );
  },
};
