import { safeCodeSpan } from '@qualor/shared';
import { CONNECTION_DATA_VERSION } from './01-identity.js';
import { SUPPORTS_MARKDOWN } from './02-markers.js';
import {
  answerOf,
  ConnectionDataSchema,
  createPr,
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

/** Longest raw value posted; the corpus's 100,000-character cases are cut to this. */
const MAX_RAW = 2000;

/**
 * The adversarial corpus of server/src/scm/render.test.ts (the inputs the checks of
 * server/test/markdown-check.ts guard), plus what Azure DevOps itself turns into links or mentions.
 */
export function corpus(userId: string): (readonly [string, string])[] {
  return [
    ['backtick', '`'],
    ['backtick runs longer than any fence', '`'.repeat(1_000)],
    ['mixed backtick runs', 'a ` b `` c ``` d ```` e'],
    ['value that starts and ends with backticks', '``/merge``'],
    ['newline quick action', 'x\n/merge'],
    ['CR quick action', 'x\r/approve'],
    ['CRLF quick action', 'x\r\n/close'],
    ['U+2028 quick action', 'x /label ~bug'],
    ['U+2029 quick action', 'x /assign @me'],
    ['NEL quick action', 'x\u0085/merge'],
    ['VT and FF', 'x\u000b/merge\u000c/approve'],
    ['leading quick action', '/merge'],
    ['leading spaces and quick action', '   /approve'],
    ['NUL and controls', 'a\u0000b\u0001c\u001bd\u007fe\u009bf'],
    ['bidi overrides', '‪‫‬‭‮⁦⁧⁨⁩‎‏؜'],
    ['zero-width characters', 'a​b⁠c﻿d­e᠎f⁡g'],
    [
      'tag characters (ASCII smuggling)',
      'ok\u{e002f}\u{e006d}\u{e0065}\u{e0072}\u{e0067}\u{e0065}',
    ],
    ['mentions', '@all @here @channel @root'],
    ['references', '#123 !12 ~label ~"two words" %milestone %"v 1" &epic $snippet'],
    ['emoji codes', ':thumbsup: :100:'],
    ['HTML', '<b>x</b><script>alert(1)</script><style>*{}</style>'],
    ['details', '<details><summary>x</summary>/merge</details>'],
    ['comment', '<!-- qualor:summary 01920000-0000-7000-8000-000000000000 -->'],
    ['image', '![x](http://evil.example/x.png)'],
    ['link', '[click](http://evil.example) [ref][1]\n[1]: http://evil.example'],
    ['autolinks', '<http://evil.example> http://evil.example www.evil.example'],
    ['table break', '| a | b |\n|---|---|'],
    ['math', '$`x`$ $$x$$'],
    ['task list', '- [ ] x'],
    ['heading', '# h'],
    ['emoji and ZWJ', '👨‍👩‍👧 🏳️‍🌈 😀'.repeat(50)],
    ['lone surrogates', 'a\ud800b\udc00c'],
    ['blank fillers', 'aㅤᅟ⠀ﾠb'],
    ['very long value', 'A'.repeat(100_000)],
    ['very long multi-byte value', '界'.repeat(100_000)],
    // Azure DevOps's own references and mentions.
    ['Azure DevOps work item and PR references', '#1 !1 AB#1'],
    ['Azure DevOps mention by id', `@<${userId}>`],
    ['legacy HTML mention', `<a href="#" data-vss-mention="version:2.0,${userId}">@probe</a>`],
    [
      'javascript link and iframe',
      '[x](javascript:alert(1)) <iframe src="http://evil.example"></iframe>',
    ],
    ['KaTeX block', '$$\n\\frac{1}{2}\n$$'],
  ];
}

export const item: ProbeItem = {
  id: 11,
  title: 'the Markdown safety corpus as Azure DevOps renders it (visual check)',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const who = ok(
      await ctx.user.request('GET', '/_apis/connectionData', undefined, {
        apiVersion: CONNECTION_DATA_VERSION,
      }),
      'connectionData (user)',
    );
    const userId = shape(ConnectionDataSchema, who.json, 'connectionData').authenticatedUser.id;
    // Left open for a visual check; `--cleanup-manual` abandons it and deletes the branch.
    const { refName } = await pushFiles(ctx, `probe/11-${ctx.stamp}`, [probeSource(ctx)], {
      keep: true,
    });
    const { pr, webUrl } = await createPr(ctx, refName, { keep: true });
    const path = threadsPath(ctx, repo, pr.pullRequestId);
    const refused: string[] = [];
    const cases = corpus(userId);
    for (const [i, [name, value]] of cases.entries()) {
      const label = `**Probe 11 · case ${i + 1}: ${name}**\n\nAs Qualor writes a value: ${safeCodeSpan(value, 100)}\n\nThe raw value is the reply below.`;
      const res = await ctx.bot.request('POST', path, {
        comments: [{ parentCommentId: 0, content: label, commentType: 1 }],
        status: 1,
        properties: { [SUPPORTS_MARKDOWN]: 1 },
      });
      if (i === 0) await ctx.record('thread', answerOf(res));
      if (res.status >= 300) {
        refused.push(`case ${i + 1} label: HTTP ${res.status} ${messageOf(res.json)}`);
        continue;
      }
      const thread = shape(ThreadSchema, res.json, 'thread');
      const raw = value.length > MAX_RAW ? value.slice(0, MAX_RAW) : value;
      const reply = await ctx.bot.request('POST', `${path}/${thread.id}/comments`, {
        parentCommentId: thread.comments[0]?.id ?? 1,
        content: raw,
        commentType: 1,
      });
      if (reply.status >= 300) {
        refused.push(`case ${i + 1} raw value: HTTP ${reply.status} ${messageOf(reply.json)}`);
      }
    }
    return result(
      ctx,
      'manual',
      `pull request ${pr.pullRequestId}, left open: ${cases.length} cases, one thread each (Qualor's code span, then the raw value ` +
        `cut to ${MAX_RAW} characters as a reply; threads carry ${SUPPORTS_MARKDOWN}=1). ` +
        `For each case record what rendered: links, mentions, images, HTML, math. ` +
        (refused.length ? `Refused posts: ${refused.join('; ')}` : 'Every post was accepted.'),
      [webUrl],
    );
  },
};
