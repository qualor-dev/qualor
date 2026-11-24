import { readRaw } from './22-fix-writes.js';
import {
  answerOf,
  changeTracking,
  createPr,
  getPr,
  gitPath,
  ok,
  pushFiles,
  refHead,
  repoInfo,
  result,
  shape,
  threadsPath,
  ThreadListSchema,
  ThreadSchema,
  type ProbeContext,
  type ProbeItem,
  type ProbeResult,
} from './common.js';

export const SIX_LINES = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'];

export type ThreadId = 'A' | 'B' | 'C';
export type SuggestionPlan = {
  id: ThreadId;
  start: number;
  end: number;
  replacement: string[];
};

/** A: lines 2-3 by two lines; B: lines 4-5 by three; C: line 6 by nothing (a deletion). */
export const SUGGESTIONS: SuggestionPlan[] = [
  { id: 'A', start: 2, end: 3, replacement: ['bravo-charlie-1', 'bravo-charlie-2'] },
  { id: 'B', start: 4, end: 5, replacement: ['delta-echo-1', 'delta-echo-2', 'delta-echo-3'] },
  { id: 'C', start: 6, end: 6, replacement: [] },
];

/** The comment of a suggestion thread; no lines at all is the empty fence of a deletion. */
export function suggestionBody(lines: string[]): string {
  return ['```suggestion', ...lines, '```'].join('\n');
}

/** The file text once the suggestions `applied` are applied to the original lines. */
export function expectedText(applied: ThreadId[]): string {
  const out: string[] = [];
  for (let n = 1; n <= SIX_LINES.length; n++) {
    const plan = SUGGESTIONS.find((s) => applied.includes(s.id) && s.start <= n && n <= s.end);
    if (!plan) out.push(SIX_LINES[n - 1] ?? '');
    else if (n === plan.start) out.push(...plan.replacement);
  }
  return `${out.join('\n')}\n`;
}

export type Judgement = {
  thread: ThreadId;
  verdict: 'as-expected' | 'not-applied' | 'unexpected';
  /** Whether the text holds an empty line (the original has none): a deletion that left one. */
  blankLine: boolean;
};

const hasRun = (lines: string[], run: string[]): boolean =>
  run.length === 0 || lines.some((_, i) => run.every((line, k) => lines[i + k] === line));

/** Per thread: is its suggestion applied as expected, not applied at all, or something else. */
export function judgeApply(text: string): Judgement[] {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines.at(-1) === '') lines.pop();
  const blankLine = lines.some((l) => l.trim() === '');
  return SUGGESTIONS.map((plan) => {
    const original = SIX_LINES.slice(plan.start - 1, plan.end);
    const originalGone = original.every((l) => !lines.includes(l));
    const originalKept = hasRun(lines, original);
    let verdict: Judgement['verdict'] = 'unexpected';
    if (originalKept && plan.replacement.every((l) => !lines.includes(l))) verdict = 'not-applied';
    else if (originalGone && hasRun(lines, plan.replacement)) {
      // A deletion has no replacement to find: it counts only when no blank line is left.
      verdict = plan.replacement.length === 0 && blankLine ? 'unexpected' : 'as-expected';
    }
    return {
      thread: plan.id,
      verdict,
      blankLine: plan.replacement.length === 0 ? blankLine : false,
    };
  });
}

/** A thread over whole lines `start`-`end` of `lines` (right side). */
function rangeThread(
  filePath: string,
  plan: SuggestionPlan,
  tracking: { iterationId: number; changeTrackingId: number },
): Record<string, unknown> {
  const lastLine = SIX_LINES[plan.end - 1] ?? '';
  return {
    comments: [
      {
        parentCommentId: 0,
        content: `**Qualor probe item 23, thread ${plan.id}**: Apply change should ${
          plan.replacement.length === 0
            ? 'delete line 6'
            : `replace lines ${plan.start}-${plan.end}`
        }.\n\n${suggestionBody(plan.replacement)}`,
        commentType: 1,
      },
    ],
    status: 1,
    threadContext: {
      filePath,
      rightFileStart: { line: plan.start, offset: 1 },
      rightFileEnd: { line: plan.end, offset: lastLine.length + 1 },
    },
    pullRequestThreadContext: {
      changeTrackingId: tracking.changeTrackingId,
      iterationContext: {
        firstComparingIteration: tracking.iterationId,
        secondComparingIteration: tracking.iterationId,
      },
    },
  };
}

export const item: ProbeItem = {
  id: 23,
  title: 'multi-line and deleting ```suggestion blocks: what Apply change produces (manual)',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const file = { path: `/probe/item-23-${ctx.stamp}.txt`, content: expectedText([]) };
    // Left open for the Apply clicks; `--cleanup-manual` abandons it and deletes the branch.
    const { refName } = await pushFiles(ctx, `probe/23-${ctx.stamp}`, [file], { keep: true });
    const { pr, webUrl } = await createPr(ctx, refName, { keep: true });
    const tracking = await changeTracking(ctx, pr.pullRequestId, file.path);
    const path = threadsPath(ctx, repo, pr.pullRequestId);
    const lines: string[] = [];
    for (const plan of SUGGESTIONS) {
      const res = ok(
        await ctx.bot.request('POST', path, rangeThread(file.path, plan, tracking)),
        `suggestion thread ${plan.id}`,
      );
      await ctx.record(`thread-${plan.id.toLowerCase()}`, answerOf(res));
      const thread = shape(ThreadSchema, res.json, 'thread');
      lines.push(
        `thread ${thread.id} (${plan.id}): lines ${plan.start}-${plan.end} of ${file.path}, Apply should give ${
          plan.replacement.length === 0
            ? 'no line (deletion, no blank line left)'
            : JSON.stringify(plan.replacement)
        }`,
      );
    }
    return result(
      ctx,
      'manual',
      `pull request ${pr.pullRequestId}, left open; click Apply change on each thread (${refName}).\n${lines.join('\n')}\n` +
        `then: pnpm azure:probe --target services --auth secret --items 23 --verify-apply ${pr.pullRequestId}`,
      [webUrl],
    );
  },
};

/** `--verify-apply <prId>`: reads the file at the branch head and judges each thread. */
export async function verifyApply(ctx: ProbeContext, prId: number): Promise<ProbeResult> {
  const repo = await repoInfo(ctx);
  const { pr } = await getPr(ctx, prId);
  const head = await refHead(ctx, pr.sourceRefName);
  if (!head) throw new Error(`${pr.sourceRefName} has no head`);
  const threadsRes = ok(await ctx.bot.request('GET', threadsPath(ctx, repo, prId)), 'threads');
  const threads = shape(ThreadListSchema, threadsRes.json, 'threads').value;
  const filePath = threads
    .map((t) => (t.threadContext as { filePath?: string } | undefined)?.filePath)
    .find((p): p is string => typeof p === 'string');
  if (!filePath) throw new Error(`pull request ${prId} has no file thread`);
  const raw = await readRaw(ctx, repo, filePath, head);
  ok(raw.res, 'read the file at the branch head');
  const text = raw.bytes.toString('utf8');
  const commits = ok(
    await ctx.bot.request(
      'GET',
      gitPath(
        ctx,
        repo,
        `/commits?searchCriteria.itemVersion.version=${encodeURIComponent(pr.sourceRefName.replace(/^refs\/heads\//, ''))}&$top=10`,
      ),
    ),
    'commits',
  );
  await ctx.record('verify-commits', answerOf(commits));
  await ctx.record('verify-threads', answerOf(threadsRes));
  await ctx.record('verify-file', { status: raw.res.status, size: raw.bytes.length, text });
  const verdicts = judgeApply(text);
  const all = text === expectedText(['A', 'B', 'C']);
  const detail = [
    `file ${filePath} at ${head.slice(0, 8)}: ${raw.bytes.length} bytes, equals the text with all three applied: ${all}`,
    ...verdicts.map(
      (v) =>
        `thread ${v.thread}: ${v.verdict}${v.thread === 'C' ? `, blank line remains: ${v.blankLine}` : ''}`,
    ),
    `text: ${JSON.stringify(text)}`,
  ].join('\n');
  const answer = verdicts.every((v) => v.verdict === 'as-expected') ? 'yes' : 'partly';
  return result(ctx, answer, detail);
}
