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
  type ProbeItem,
} from './common.js';

const MARKER = 'Qualor.Marker';
const RESOLVED_BY = 'Qualor.ResolvedBy';

/** The `$value` of a property as Azure DevOps answers it (`{"$type": …, "$value": …}`), or the raw value. */
export function propertyValue(properties: Record<string, unknown> | null | undefined, key: string) {
  const v = properties?.[key];
  if (v && typeof v === 'object' && '$value' in v) return (v as { $value: unknown }).$value;
  return v;
}

export const item: ProbeItem = {
  id: 3,
  title: 'custom thread properties are written on create and update and read back on list',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const { refName } = await pushFiles(ctx, `probe/3-${ctx.stamp}`, [probeSource(ctx)]);
    const { pr } = await createPr(ctx, refName);
    const id = pr.pullRequestId;

    const created = ok(
      await ctx.bot.request('POST', threadsPath(ctx, repo, id), {
        comments: [{ parentCommentId: 0, content: 'Qualor probe item 3', commentType: 1 }],
        status: 1,
        properties: { [MARKER]: 'issue 1', [RESOLVED_BY]: 'qualor' },
      }),
      'create thread with properties',
    );
    await ctx.record('thread-create', answerOf(created));
    const thread = shape(ThreadSchema, created.json, 'created thread');

    const listThread = async (call: string) => {
      const res = ok(await ctx.bot.request('GET', threadsPath(ctx, repo, id)), 'list threads');
      await ctx.record(call, answerOf(res));
      const found = shape(ThreadListSchema, res.json, 'thread list').value.find(
        (t) => t.id === thread.id,
      );
      if (!found) throw new Error(`thread ${thread.id} missing from the list`);
      return found;
    };

    const listed = await listThread('thread-list');
    const marker = propertyValue(listed.properties, MARKER);
    const resolvedBy = propertyValue(listed.properties, RESOLVED_BY);
    const roundTrip = marker === 'issue 1' && resolvedBy === 'qualor';

    // Remove one property by PATCHing it to null; keep the other.
    const patched = await ctx.bot.request('PATCH', threadsPath(ctx, repo, id, `/${thread.id}`), {
      properties: { [RESOLVED_BY]: null },
    });
    await ctx.record('thread-patch-null', answerOf(patched));
    const after = patched.status < 300 ? await listThread('thread-list-after-patch') : listed;
    const removed = after.properties?.[RESOLVED_BY] === undefined;
    const kept = propertyValue(after.properties, MARKER) === 'issue 1';
    const removedValue = propertyValue(after.properties, RESOLVED_BY);

    // Update on an existing thread: a new key written by PATCH.
    const added = await ctx.bot.request('PATCH', threadsPath(ctx, repo, id, `/${thread.id}`), {
      properties: { [RESOLVED_BY]: 'qualor-again' },
    });
    await ctx.record('thread-patch-add', answerOf(added));
    const final = added.status < 300 ? await listThread('thread-list-after-add') : after;
    const updated = propertyValue(final.properties, RESOLVED_BY) === 'qualor-again';

    const createdText = roundTrip
      ? 'both properties read back'
      : `read back ${MARKER}=${JSON.stringify(marker)}, ${RESOLVED_BY}=${JSON.stringify(resolvedBy)}`;
    const removedText = removed
      ? 'the property is gone'
      : `the property is still there (${JSON.stringify(removedValue)})`;
    const detail = [
      `create: ${createdText} (values come back as {$type, $value})`,
      `PATCH {${RESOLVED_BY}: null}: HTTP ${patched.status}; ${removedText}; ${MARKER} ${kept ? 'kept' : 'lost'}`,
      `PATCH {${RESOLVED_BY}: "qualor-again"}: HTTP ${added.status}; ${updated ? 'read back' : 'not read back'}`,
    ].join('\n\n');
    let answer: Answer = 'no';
    if (roundTrip) answer = removed && kept && updated ? 'yes' : 'partly';
    return result(ctx, answer, detail);
  },
};
