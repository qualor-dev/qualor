import { z } from 'zod';
import {
  answerOf,
  createdString,
  createPr,
  messageOf,
  ok,
  probeSource,
  pushFiles,
  recorderGet,
  recorderList,
  remove,
  repoInfo,
  result,
  shape,
  ThreadSchema,
  threadIdFromHref,
  threadsPath,
  waitFor,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const SUBSCRIPTIONS = '/_apis/hooks/subscriptions';
const CREATED = 'Qualor probe item 9: a comment';
const EDITED = 'Qualor probe item 9: a comment, edited';
const REPLY = 'Qualor probe item 9: a reply';

const CommentEvent = z.object({
  eventType: z.string(),
  message: z.object({ text: z.string() }).loose(),
  resource: z.object({
    comment: z.object({
      id: z.number(),
      parentCommentId: z.number().optional(),
      content: z.string(),
      author: z.object({ id: z.string() }).loose(),
      _links: z.object({ threads: z.object({ href: z.string() }) }).loose(),
    }),
    pullRequest: z.object({ pullRequestId: z.number() }).loose(),
  }),
});

const PrEvent = z.object({
  eventType: z.string(),
  message: z.object({ text: z.string() }).loose(),
  resource: z.object({ pullRequestId: z.number(), status: z.string() }).loose(),
});

/**
 * The resource version to subscribe with: `preferred` where the event type offers it, else its
 * newest released version (Server offers only 1.0 for `git.pullrequest.updated`, and a 2.0
 * subscription is accepted there but delivers events with an empty `resource`). Undefined when the
 * event type lists none: the subscription then omits it and gets the latest released version.
 */
export function pickResourceVersion(
  supported: string[] | undefined,
  preferred = '2.0',
): string | undefined {
  if (!supported || supported.length === 0) return undefined;
  if (supported.includes(preferred)) return preferred;
  const released = supported.filter((v) => !v.includes('preview'));
  const pool = released.length > 0 ? released : supported;
  return [...pool].sort((a, b) => Number.parseFloat(b) - Number.parseFloat(a))[0];
}

const EventTypesSchema = z.object({
  value: z.array(
    z.object({ id: z.string(), supportedResourceVersions: z.array(z.string()).nullish() }).loose(),
  ),
});

/** One delivery the recorder holds: the event body and whether the expected basic auth came with it. */
type Hook = { file: string; body: unknown; auth: string; basicOk: boolean };

export type CommentKind = 'created' | 'edited' | 'reply';

/**
 * Which of the item's three comment actions a comment event reports, or undefined when it is about
 * another pull request, thread or comment (the subscription covers the whole repository).
 */
export function commentKind(
  event: z.infer<typeof CommentEvent>,
  expect: { prId: number; threadId: number; commentId: number },
): CommentKind | undefined {
  const c = event.resource.comment;
  if (event.resource.pullRequest.pullRequestId !== expect.prId) return undefined;
  if (threadIdFromHref(c._links.threads.href) !== expect.threadId) return undefined;
  if (c.id === expect.commentId && c.content === CREATED) return 'created';
  if (c.id === expect.commentId && c.content === EDITED) return 'edited';
  if (c.parentCommentId === expect.commentId && c.content === REPLY) return 'reply';
  return undefined;
}

/** A web hook subscription to the recorder; tracked for clean-up as soon as it exists. */
async function subscribe(
  ctx: ProbeContext,
  eventType: string,
  hookName: string,
  publisherInputs: Record<string, string>,
  opts: { url?: string; call: string; resourceVersion: string | undefined },
): Promise<{ id?: string; status: number; text: string }> {
  const res = await ctx.bot.request('POST', SUBSCRIPTIONS, {
    publisherId: 'tfs',
    eventType,
    ...(opts.resourceVersion ? { resourceVersion: opts.resourceVersion } : {}),
    consumerId: 'webHooks',
    consumerActionId: 'httpRequest',
    publisherInputs,
    consumerInputs: {
      url: opts.url ?? `${ctx.hookBase.replace(/\/+$/, '')}/hooks/${hookName}`,
      basicAuthUsername: 'qualor',
      basicAuthPassword: ctx.recorderSecret,
      resourceDetailsToSend: 'all',
      messagesToSend: 'all',
      detailedMessagesToSend: 'all',
    },
  });
  let id: string | undefined;
  if (res.status < 300) {
    // Before the recording (its leak check can throw): an orphan would keep forwarding comments.
    const created = createdString(res, 'id', 'create subscription');
    id = created;
    ctx.cleanup.add(`delete subscription ${created}`, () =>
      remove(ctx.bot, `${SUBSCRIPTIONS}/${created}`, 'subscription'),
    );
  }
  await ctx.record(opts.call, answerOf(res));
  if (!id)
    return { status: res.status, text: `refused: HTTP ${res.status} ${messageOf(res.json)}` };
  const sub = shape(z.object({ id: z.string(), status: z.string() }), res.json, 'subscription');
  return { id, status: res.status, text: `created (status ${sub.status})` };
}

/** The recordings the recorder holds for `hookName`, oldest first. */
async function delivered(ctx: ProbeContext, hookName: string): Promise<Hook[]> {
  const files = (await recorderList(ctx)).filter((f) => f.endsWith(`-${hookName}.json`));
  const out: Hook[] = [];
  for (const file of files) {
    const rec = await recorderGet(ctx, file);
    let body: unknown = rec.body;
    try {
      body = JSON.parse(rec.body);
    } catch {
      // keep the text
    }
    const basicOk =
      rec.authorization.scheme?.toLowerCase() === 'basic' && rec.authorization.passwordMatches;
    out.push({
      file,
      body,
      basicOk,
      auth: `${rec.authorization.scheme ?? 'none'}, password ${rec.authorization.passwordMatches ? 'matches' : 'does not match'}`,
    });
  }
  return out;
}

/** What a delivery keeps in a recording: the event and how it was authenticated, no headers. */
const recorded = (h: Hook) => ({ authorization: h.auth, body: h.body });

/** Why nothing arrived, from the subscription's notification history. */
async function history(ctx: ProbeContext, subId: string, call: string): Promise<string> {
  const res = await ctx.bot.request('GET', `${SUBSCRIPTIONS}/${subId}/notifications?maxResults=5`);
  await ctx.record(call, answerOf(res));
  const parsed = z
    .object({
      value: z.array(
        z.object({ status: z.string().optional(), result: z.string().optional() }).loose(),
      ),
    })
    .safeParse(res.json);
  if (!parsed.success) return `history HTTP ${res.status}`;
  return parsed.data.value.map((n) => `${n.status ?? '?'}/${n.result ?? '?'}`).join(', ') || 'none';
}

type Classified = {
  comments: Map<CommentKind, { hook: Hook; event: z.infer<typeof CommentEvent> }>;
  updates: { hook: Hook; event: z.infer<typeof PrEvent> }[];
  ignored: number;
  badAuth: number;
};

/** Sorts the deliveries: counted only with the expected basic auth, and only about this PR. */
function classify(
  comments: Hook[],
  updates: Hook[],
  expect: { prId: number; threadId: number; commentId: number },
): Classified {
  const out: Classified = { comments: new Map(), updates: [], ignored: 0, badAuth: 0 };
  for (const hook of comments) {
    const ev = CommentEvent.safeParse(hook.body);
    const kind = ev.success ? commentKind(ev.data, expect) : undefined;
    if (!ev.success || !kind) {
      out.ignored++;
    } else if (!hook.basicOk) {
      out.badAuth++;
    } else if (!out.comments.has(kind)) {
      out.comments.set(kind, { hook, event: ev.data });
    }
  }
  for (const hook of updates) {
    const ev = PrEvent.safeParse(hook.body);
    if (!ev.success || ev.data.resource.pullRequestId !== expect.prId) out.ignored++;
    else if (!hook.basicOk) out.badAuth++;
    else out.updates.push({ hook, event: ev.data });
  }
  return out;
}

export const item: ProbeItem = {
  id: 9,
  title: 'service hooks deliver comment create, edit and reply and PR updates with basic auth',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    // The recorder answers the operator first: otherwise nothing below can be read back.
    await recorderList(ctx);

    // Each event type's resource versions on this target decide the subscriptions' version.
    const typesRes = ok(
      await ctx.bot.request('GET', '/_apis/hooks/publishers/tfs/eventTypes'),
      'service hook event types',
    );
    const types = shape(EventTypesSchema, typesRes.json, 'event types').value;
    await ctx.record('event-types', {
      status: typesRes.status,
      pullRequestEvents: types
        .filter((t) => /pullrequest/i.test(t.id))
        .map((t) => ({ id: t.id, supportedResourceVersions: t.supportedResourceVersions ?? null })),
    });
    const versionOf = (id: string) =>
      pickResourceVersion(types.find((t) => t.id === id)?.supportedResourceVersions ?? undefined);
    const COMMENT_EVENT = 'ms.vss-code.git-pullrequest-comment-event';
    const UPDATED_EVENT = 'git.pullrequest.updated';
    const commentVersion = versionOf(COMMENT_EVENT);
    const updatedVersion = versionOf(UPDATED_EVENT);

    const commentHook = `${ctx.target}-9-${ctx.stamp}-comment`;
    const updatedHook = `${ctx.target}-9-${ctx.stamp}-updated`;
    const inputs = { projectId: repo.project.id, repository: repo.id };
    const comment = await subscribe(ctx, COMMENT_EVENT, commentHook, inputs, {
      call: 'subscription-comment',
      resourceVersion: commentVersion,
    });
    const updated = await subscribe(ctx, UPDATED_EVENT, updatedHook, inputs, {
      call: 'subscription-updated',
      resourceVersion: updatedVersion,
    });
    if (!comment.id || !updated.id) {
      return result(ctx, 'no', `comment: ${comment.text}\n\nupdated: ${updated.text}`);
    }

    // Basic auth over plain HTTP: refused, or accepted (then deleted at once).
    const httpName = `${ctx.target}-9-${ctx.stamp}-http`;
    const httpUrl = `${ctx.hookBase.replace(/^https:/, 'http:').replace(/\/+$/, '')}/hooks/${httpName}`;
    const http = await subscribe(ctx, COMMENT_EVENT, httpName, inputs, {
      url: httpUrl,
      call: 'subscription-http-basic-auth',
      resourceVersion: commentVersion,
    });
    if (http.id) await remove(ctx.bot, `${SUBSCRIPTIONS}/${http.id}`, 'http subscription');

    const file = probeSource(ctx);
    const branch = `probe/9-${ctx.stamp}`;
    const { refName } = await pushFiles(ctx, branch, [file]);
    const { pr } = await createPr(ctx, refName);
    const threads = threadsPath(ctx, repo, pr.pullRequestId);

    // The second user comments, edits, replies.
    const created = ok(
      await ctx.user.request('POST', threads, {
        comments: [{ parentCommentId: 0, content: CREATED, commentType: 1 }],
        status: 1,
      }),
      'comment as the second user',
    );
    const thread = shape(ThreadSchema, created.json, 'thread');
    const firstComment = thread.comments[0];
    if (!firstComment) throw new Error('the created thread has no comment');
    const expect = { prId: pr.pullRequestId, threadId: thread.id, commentId: firstComment.id };

    const first = await waitFor(
      async () => ((await delivered(ctx, commentHook)).length > 0 ? true : undefined),
      { timeoutMs: 90_000, intervalMs: 5000 },
    );
    if (!first) {
      const why = await history(ctx, comment.id, 'history-comment');
      return result(
        ctx,
        'no',
        `no comment event reached the recorder within 90 s (the target may not reach the public recorder URL); notification history: ${why}`,
      );
    }
    ok(
      await ctx.user.request('PATCH', `${threads}/${thread.id}/comments/${firstComment.id}`, {
        content: EDITED,
      }),
      'edit the comment',
    );
    ok(
      await ctx.user.request('POST', `${threads}/${thread.id}/comments`, {
        parentCommentId: firstComment.id,
        content: REPLY,
        commentType: 1,
      }),
      'reply',
    );
    // A push to the source branch updates the pull request.
    await pushFiles(ctx, branch, [
      { path: `/probe/item-9-${ctx.stamp}-second.ts`, content: 'export const second = 2;\n' },
    ]);

    const read = async () =>
      classify(await delivered(ctx, commentHook), await delivered(ctx, updatedHook), expect);
    const sorted =
      (await waitFor(
        async () => {
          const got = await read();
          return got.comments.size === 3 && got.updates.length > 0 ? got : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 5000 },
      )) ?? (await read());

    const lines: string[] = [];
    for (const kind of ['created', 'edited', 'reply'] as const) {
      const got = sorted.comments.get(kind);
      if (!got) {
        lines.push(
          `comment ${kind}: no delivery about this pull request with the expected basic auth`,
        );
        continue;
      }
      await ctx.record(`event-comment-${kind}`, recorded(got.hook));
      const c = got.event.resource.comment;
      lines.push(
        `comment ${kind}: ${got.event.eventType}, auth ${got.hook.auth}, comment ${c.id} ` +
          `(parent ${c.parentCommentId ?? 'absent'}), thread ${thread.id} from _links.threads.href; ` +
          `message.text: "${got.event.message.text}"`,
      );
    }
    for (const [i, u] of sorted.updates.slice(0, 2).entries()) {
      await ctx.record(
        i === 0 ? 'event-pr-updated' : `event-pr-updated-${i + 1}`,
        recorded(u.hook),
      );
      lines.push(
        `pr updated ${i + 1}: ${u.event.eventType}, auth ${u.hook.auth}, status ${u.event.resource.status}; message.text: "${u.event.message.text}"`,
      );
    }
    if (sorted.updates.length === 0) {
      lines.push('pr updated: no delivery about this pull request with the expected basic auth');
    }
    lines.push(
      `subscriptions: comment ${comment.text}, updated ${updated.text}; basic auth over http: ${http.text}`,
      `resource versions (from publishers/tfs/eventTypes): comment event ${commentVersion ?? 'none listed (omitted)'}, ` +
        `PR updated ${updatedVersion ?? 'none listed (omitted)'}`,
      `deliveries ignored (other pull requests, threads or comments, or unexpected shapes): ${sorted.ignored}; ` +
        `without the expected basic auth: ${sorted.badAuth}`,
    );
    const found = sorted.comments.size + (sorted.updates.length > 0 ? 1 : 0);
    const answer = found === 4 ? 'yes' : found > 0 ? 'partly' : 'no';
    return result(ctx, answer, lines.join('\n\n'));
  },
};
