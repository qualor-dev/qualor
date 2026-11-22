import { z } from 'zod';
import {
  answerOf,
  changeTracking,
  createPr,
  lineThread,
  messageOf,
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

const Placed = z.object({
  threadContext: z.object({
    filePath: z.string(),
    rightFileStart: z.object({ line: z.number(), offset: z.number() }).nullish(),
  }),
});

export const item: ProbeItem = {
  id: 6,
  title: 'a right-side line thread without pullRequestThreadContext is placed (not refused)',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const file = probeSource(ctx);
    const { refName } = await pushFiles(ctx, `probe/6-${ctx.stamp}`, [file]);
    const { pr } = await createPr(ctx, refName);
    const path = threadsPath(ctx, repo, pr.pullRequestId);

    const bare = await ctx.bot.request(
      'POST',
      path,
      lineThread(file.path, 3, 'Qualor probe item 6: no pullRequestThreadContext'),
    );
    await ctx.record('thread-without-context', answerOf(bare));
    let bareText: string;
    let placed = false;
    if (bare.status >= 200 && bare.status < 300) {
      const t = shape(ThreadSchema, bare.json, 'thread without context');
      const got = ok(await ctx.bot.request('GET', `${path}/${t.id}`), 'get thread');
      await ctx.record('thread-without-context-get', answerOf(got));
      const read = shape(ThreadSchema, got.json, 'thread');
      const ctxRead = Placed.safeParse(read);
      placed = ctxRead.success && ctxRead.data.threadContext.rightFileStart?.line === 3;
      bareText =
        `accepted (HTTP ${bare.status}); read back ${placed ? 'on line 3 of the file' : 'without its line'}; ` +
        `pullRequestThreadContext ${read.pullRequestThreadContext ? 'filled in by the server' : 'absent'}`;
    } else {
      bareText = `refused: HTTP ${bare.status} ${messageOf(bare.json)}`;
    }

    // The control: the same thread with the iteration's change tracking id.
    const tracking = await changeTracking(ctx, pr.pullRequestId, file.path);
    await ctx.record('iteration-changes', answerOf(tracking.changes));
    const full = await ctx.bot.request(
      'POST',
      path,
      lineThread(file.path, 5, 'Qualor probe item 6: with pullRequestThreadContext', tracking),
    );
    await ctx.record('thread-with-context', answerOf(full));
    ok(full, 'thread with pullRequestThreadContext (control)');
    shape(ThreadSchema, full.json, 'thread with context');

    const detail = [
      `without pullRequestThreadContext: ${bareText}`,
      `control with changeTrackingId ${tracking.changeTrackingId}, iteration ${tracking.iterationId}: accepted (HTTP ${full.status})`,
    ].join('\n\n');
    return result(ctx, placed ? 'yes' : 'no', detail);
  },
};
