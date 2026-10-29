import { marked } from 'marked';
import { describe, expect, it } from 'vitest';
import {
  badSectionLine,
  checkAiThreadLines,
  checkProse,
  checkSectionLine,
  FORBIDDEN_ANYWHERE,
  outsideCodeSpans,
} from '../../test/markdown-check';
import { codeSpan, markerOf, replyMarker } from '../scm/markdown';
import {
  AI_SECTION_MAX_BYTES,
  AI_THREAD_MAX_BYTES,
  aiSummarySection,
  aiThreadBody,
  aiThreadNote,
  commandNote,
  REPLY_NOTE_MAX_BYTES,
  replyNote,
  withMergeRequestHead,
  withUnplacedFindings,
  type AiThreadInput,
  type ReviewSummaryState,
} from './render';

type Done = Extract<ReviewSummaryState, { kind: 'done' }>;

const SHA = 'a'.repeat(40);
const NEWER = 'b'.repeat(40);

const done = (over: Partial<Done> = {}): Done => ({
  kind: 'done',
  verdict: 'The change adds refunds; one path can fail silently.',
  walkthrough: ['Adds a refund endpoint', 'Validates the amount'],
  counts: { high: 1, medium: 2, low: 0 },
  unplaced: [],
  moreUnplaced: 0,
  reviewedSha: SHA,
  mergeRequestHeadSha: null,
  tokenLimitReached: false,
  snapshotPartial: false,
  fixPrompt: [],
  ...over,
});
const section = (
  state: ReviewSummaryState,
  provider: 'gitlab' | 'github' = 'gitlab',
  maxBytes: number = AI_SECTION_MAX_BYTES,
): string[] => aiSummarySection(state, provider, maxBytes);
const bytesOf = (lines: readonly string[]): number => Buffer.byteLength(lines.join('\n'), 'utf8');

const finding = (n: number, over: Partial<Done['unplaced'][number]> = {}) => ({
  severity: 'medium',
  path: `src/file${n}.ts`,
  line: n,
  title: `Finding number ${n}`,
  url: `https://q.example/projects/p/issues/i${n}`,
  ...over,
});
const promptFinding = (n: number, over: Partial<Done['fixPrompt'][number]> = {}) => ({
  path: `src/file${n}.ts`,
  line: n,
  title: `Finding number ${n}`,
  body: `The call in file ${n} can fail when the input is empty, so check it first.`,
  ...over,
});

describe('the AI review section', () => {
  it('each section state renders its fixed text', () => {
    // In progress.
    expect(section({ kind: 'pending' })).toEqual(['#### AI review', '', 'AI review in progress…']);

    // Skipped: a sentence for each reason; a missing snapshot points to the job log and fetch-depth.
    const skipped = {
      no_snapshot:
        'AI review did not run: no repository snapshot came for this commit. See the CI job’s log and the guide’s `fetch-depth` note.',
      snapshot_rejected:
        'AI review did not run: the server refused the repository snapshot of this commit.',
      draft:
        'AI review is skipped while this merge request is a draft; the next pipeline after it is ready reviews it, and a `qualor review` note reviews it now.',
      closed: 'AI review did not run because this merge request is merged or closed.',
      inactive: 'AI review is switched off for this project.',
      empty_diff: 'AI review found nothing to review in the changed files.',
      unchanged:
        'AI review did not repeat: the changes it reviews are the same as in its last review, whose findings stay open.',
      budget_spent: 'AI review did not run because its token budget for today is spent.',
    } as const;
    for (const [reason, sentence] of Object.entries(skipped)) {
      expect(
        section({ kind: 'skipped', reason: reason as keyof typeof skipped, detail: null }),
      ).toEqual(['#### AI review', '', sentence]);
    }

    // Failed: a sentence for each reason, then that the next push reviews again.
    const failed = {
      provider_error:
        'AI review failed: the model provider returned an error or could not be reached.',
      provider_no_tools:
        'AI review failed: the model provider does not support the tool calls the review needs.',
      bad_answer: 'AI review failed: the model’s answers could not be read.',
      internal: 'AI review failed because of an error in Qualor.',
    } as const;
    for (const [reason, sentence] of Object.entries(failed)) {
      expect(section({ kind: 'failed', reason: reason as keyof typeof failed })).toEqual([
        '#### AI review',
        '',
        `${sentence} The next push reviews again.`,
      ]);
    }

    // Done: the verdict, the counts, the walkthrough and the commit.
    expect(section(done())).toEqual([
      '#### AI review',
      '',
      'The change adds refunds; one path can fail silently.',
      '',
      '**Findings:** 1 high · 2 medium · 0 low',
      '',
      '- Adds a refund endpoint',
      '- Validates the amount',
      '',
      'Reviewed commit: ` aaaaaaaaaaaa `',
    ]);
  });

  it('says it in GitHub’s words for GitHub', () => {
    const skipped = (reason: 'draft' | 'closed') =>
      section({ kind: 'skipped', reason, detail: null }, 'github')[2];
    expect(skipped('draft')).toBe(
      'AI review is skipped while this pull request is a draft; the next workflow run after it is ready reviews it, and a `qualor review` comment reviews it now.',
    );
    expect(skipped('closed')).toBe(
      'AI review did not run because this pull request is merged or closed.',
    );
  });

  it('says that a merge request is too large for the per-review budget, apart from the day’s budget', () => {
    const tooLarge = { kind: 'skipped', reason: 'budget_spent', detail: 'too_large' } as const;
    expect(section(tooLarge)).toEqual([
      '#### AI review',
      '',
      'AI review did not run because this merge request is too large for the Tokens per review budget; raise it in Settings → AI.',
    ]);
    expect(section(tooLarge, 'github')[2]).toBe(
      'AI review did not run because this pull request is too large for the Tokens per review budget; raise it in Settings → AI.',
    );
    // The day's budget keeps its own sentence.
    expect(section({ kind: 'skipped', reason: 'budget_spent', detail: null })[2]).toBe(
      'AI review did not run because its token budget for today is spent.',
    );
  });

  it('says that a review failed for the model’s context window, in each provider’s words, and what to change', () => {
    const full = { kind: 'failed', reason: 'provider_error', detail: 'window_full' } as const;
    expect(section(full)).toEqual([
      '#### AI review',
      '',
      'AI review failed because the model’s context window is too small for this merge request; raise Context window in the AI provider settings, or use a model with a larger window.',
    ]);
    expect(section(full, 'github')[2]).toBe(
      'AI review failed because the model’s context window is too small for this pull request; raise Context window in the AI provider settings, or use a model with a larger window.',
    );
    for (const provider of ['gitlab', 'github'] as const) {
      const text = section(full, provider).join('\n');
      // Not the provider's error, and not a push that would fail the same way.
      expect(text).not.toContain('returned an error');
      expect(text).not.toContain('The next push reviews again.');
      expect(badSectionLine(section(full, provider))).toBeNull();
    }
    // Without the detail, the provider's error as before.
    expect(section({ kind: 'failed', reason: 'provider_error', detail: null })[2]).toBe(
      'AI review failed: the model provider returned an error or could not be reached. The next push reviews again.',
    );
  });

  it('says that a review failed because it ran out of time, and that the next push reviews again', () => {
    const late = { kind: 'failed', reason: 'provider_error', detail: 'time_limit' } as const;
    const TIME = 'AI review failed because it ran out of time. The next push reviews again.';
    for (const provider of ['gitlab', 'github'] as const) {
      expect(section(late, provider)).toEqual(['#### AI review', '', TIME]);
      // Not the provider's error.
      expect(section(late, provider).join('\n')).not.toContain('returned an error');
      expect(badSectionLine(section(late, provider))).toBeNull();
    }
    expect(checkProse(TIME)).toBe(true);
  });

  it('says that a merge request is too large for the model’s context window, and never to raise Tokens per review', () => {
    const tooSmall = {
      kind: 'skipped',
      reason: 'budget_spent',
      detail: 'window_too_small',
    } as const;
    expect(section(tooSmall)).toEqual([
      '#### AI review',
      '',
      'AI review did not run because this merge request is too large for the model’s context window; raise Context window in the AI provider settings if the model takes more.',
    ]);
    expect(section(tooSmall, 'github')[2]).toBe(
      'AI review did not run because this pull request is too large for the model’s context window; raise Context window in the AI provider settings if the model takes more.',
    );
    for (const provider of ['gitlab', 'github'] as const) {
      const lines = section(tooSmall, provider);
      expect(lines.join('\n')).not.toContain('Tokens per review');
      expect(lines.join('\n')).not.toContain('Reason:');
      expect(badSectionLine(lines)).toBeNull();
    }
  });

  it('names the code a skip or a refusal carries, in a code span, and nothing else', () => {
    expect(
      section({ kind: 'skipped', reason: 'snapshot_rejected', detail: 'SNAPSHOT_INVALID' })[2],
    ).toBe(
      'AI review did not run: the server refused the repository snapshot of this commit. Reason: ` SNAPSHOT_INVALID `.',
    );
    expect(section({ kind: 'skipped', reason: 'inactive', detail: 'consent_outdated' })[2]).toBe(
      'AI review is switched off for this project. Reason: ` consent_outdated `.',
    );
    // A detail that is not a code of Qualor's own is left out: it is never content.
    for (const detail of [
      '',
      'a b',
      '<b>x</b>',
      '@all',
      '/close',
      'x'.repeat(65),
      'SNAPSHOT_INVALID\n/merge',
    ]) {
      expect(section({ kind: 'skipped', reason: 'snapshot_rejected', detail })[2], detail).toBe(
        'AI review did not run: the server refused the repository snapshot of this commit.',
      );
    }
  });

  it('falls back to a plain sentence for a reason it does not know, and shows nothing for a state it does not know', () => {
    expect(section({ kind: 'skipped', reason: 'weird' as never, detail: null })[2]).toBe(
      'AI review did not run.',
    );
    expect(section({ kind: 'failed', reason: 'weird' as never })[2]).toBe(
      'AI review failed. The next push reviews again.',
    );
    expect(section({ kind: 'bogus' } as never)).toEqual([]);
  });

  it('says there are no findings, and leaves out what there is none of', () => {
    const lines = section(
      done({ counts: { high: 0, medium: 0, low: 0 }, verdict: '', walkthrough: [] }),
    );
    expect(lines).toEqual([
      '#### AI review',
      '',
      'No findings.',
      '',
      'Reviewed commit: ` aaaaaaaaaaaa `',
    ]);
    // A walkthrough item that is nothing once cleaned is not listed.
    expect(section(done({ walkthrough: ['\u200b', '  ', 'Real item'] }))).toContain('- Real item');
    expect(section(done({ walkthrough: ['\u200b', '  '] })).join('\n')).not.toContain('- ');
  });

  it('lists the findings that are not on changed lines, with a link, and says how many more there are', () => {
    const lines = section(
      done({
        unplaced: [
          finding(1, { severity: 'high' }),
          finding(2, { severity: 'low', url: null }),
          finding(3, { severity: 'blocker', title: '' }),
        ],
        moreUnplaced: 4,
      }),
    );
    expect(lines.slice(9)).toEqual([
      '**Not on changed lines:**',
      '',
      '- **High** · ` src/file1.ts:1 ` · Finding number 1 · [View in Qualor](https://q.example/projects/p/issues/i1)',
      '- **Low** · ` src/file2.ts:2 ` · Finding number 2',
      '- **Unknown** · ` src/file3.ts:3 ` · [View in Qualor](https://q.example/projects/p/issues/i3)',
      '',
      '…and 4 more in Qualor',
      '',
      'Reviewed commit: ` aaaaaaaaaaaa `',
    ]);
  });

  it('lists ten of the findings that are not on changed lines at most, and counts the rest as more', () => {
    const lines = section(
      done({ unplaced: Array.from({ length: 13 }, (_, i) => finding(i + 1)), moreUnplaced: 2 }),
    );
    expect(lines.filter((line) => line.startsWith('- **Medium**'))).toHaveLength(10);
    expect(lines).toContain('…and 5 more in Qualor');
  });

  it('reads a severity that is not one of the three as unknown, whatever its name', () => {
    for (const severity of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'info', '']) {
      const lines = section(done({ unplaced: [finding(1, { severity })] }));
      expect(lines.join('\n'), severity).toContain('- **Unknown** · ` src/file1.ts:1 ` · ');
    }
  });

  it('adds the notes, each a sentence of its own, after the findings', () => {
    const lines = section(
      done({
        tokenLimitReached: true,
        snapshotPartial: true,
        notes: ['reviewer_unreadable', 'token_limit_reached', 'verification_capped'],
      }),
    );
    expect(lines.slice(9)).toEqual([
      'The review reached its token limit, so it may have missed problems. The scanner left some files out of the repository snapshot to stay within its limits, so the review did not see all of them. A reviewer’s answer could not be read, so part of the review is missing. There were more serious security findings than the review verifies, so the rest were not checked a second time.',
      '',
      'Reviewed commit: ` aaaaaaaaaaaa `',
    ]);
    // The token limit is said once, whether the run or its summary tells it.
    for (const over of [{ tokenLimitReached: true }, { notes: ['token_limit_reached' as const] }]) {
      const text = section(done(over)).join('\n');
      expect(text.match(/reached its token limit/g)).toHaveLength(1);
    }
    expect(section(done()).join('\n')).not.toContain('token limit');
  });

  it('says that a reviewer reached its turn limit in a sentence of its own, apart from the token limit', () => {
    const TOKENS = 'The review reached its token limit, so it may have missed problems.';
    const TURNS = 'A reviewer reached its limit of 16 turns, so it may have missed problems.';
    const notesLine = (over: Partial<Done>) => section(done(over)).at(-3);
    expect(notesLine({ notes: ['turn_limit_reached'] })).toBe(TURNS);
    expect(section(done({ notes: ['turn_limit_reached'] })).join('\n')).not.toContain(
      'token limit',
    );
    expect(notesLine({ tokenLimitReached: true })).toBe(TOKENS);
    // Both, the token limit first, each once.
    expect(
      notesLine({
        tokenLimitReached: true,
        notes: ['turn_limit_reached', 'token_limit_reached', 'turn_limit_reached'],
      }),
    ).toBe(`${TOKENS} ${TURNS}`);
    expect(checkProse(TURNS)).toBe(true);
  });

  it('says that the review reached its time limit in a sentence of its own, after the other limits', () => {
    const TOKENS = 'The review reached its token limit, so it may have missed problems.';
    const TURNS = 'A reviewer reached its limit of 16 turns, so it may have missed problems.';
    const TIME = 'The review reached its time limit, so it may have missed problems.';
    const WINDOW = 'A reviewer reached the model’s context window, so it may have missed problems.';
    for (const provider of ['gitlab', 'github'] as const) {
      const notesLine = (over: Partial<Done>) => section(done(over), provider).at(-3);
      expect(notesLine({ notes: ['time_limit_reached'] }), provider).toBe(TIME);
      // Beside the others, each once: tokens, turns, time, window.
      expect(
        notesLine({
          tokenLimitReached: true,
          notes: [
            'context_window_reached',
            'time_limit_reached',
            'turn_limit_reached',
            'time_limit_reached',
          ],
        }),
        provider,
      ).toBe(`${TOKENS} ${TURNS} ${TIME} ${WINDOW}`);
      expect(badSectionLine(section(done({ notes: ['time_limit_reached'] }), provider))).toBeNull();
    }
    expect(checkProse(TIME)).toBe(true);
    expect(section(done()).join('\n')).not.toContain('time limit');
  });

  it('says that a reviewer reached the model’s context window in a sentence of its own, on GitLab and GitHub', () => {
    const TOKENS = 'The review reached its token limit, so it may have missed problems.';
    const WINDOW = 'A reviewer reached the model’s context window, so it may have missed problems.';
    for (const provider of ['gitlab', 'github'] as const) {
      const notesLine = (over: Partial<Done>) => section(done(over), provider).at(-3);
      expect(notesLine({ notes: ['context_window_reached'] }), provider).toBe(WINDOW);
      expect(
        section(done({ notes: ['context_window_reached'] }), provider).join('\n'),
      ).not.toContain('token limit');
      // Beside the token limit, each once, the token limit first.
      expect(
        notesLine({
          tokenLimitReached: true,
          notes: ['context_window_reached', 'token_limit_reached', 'context_window_reached'],
        }),
        provider,
      ).toBe(`${TOKENS} ${WINDOW}`);
      expect(
        badSectionLine(section(done({ notes: ['context_window_reached'] }), provider)),
      ).toBeNull();
    }
    expect(checkProse(WINDOW)).toBe(true);
  });

  it('says that the instructions files were shortened to fit the context window, after the lists', () => {
    const FILES =
      'The repository’s instructions files were shortened to fit the model’s context window, so the review may not follow all of them.';
    for (const provider of ['gitlab', 'github'] as const) {
      const notesLine = (over: Partial<Done>) => section(done(over), provider).at(-3);
      expect(notesLine({ notes: ['instructions_shortened'] }), provider).toBe(FILES);
      expect(
        notesLine({
          notes: ['instructions_shortened', 'lists_shortened', 'instructions_shortened'],
        })?.endsWith(FILES),
        provider,
      ).toBe(true);
      expect(
        badSectionLine(section(done({ notes: ['instructions_shortened'] }), provider)),
      ).toBeNull();
    }
    expect(checkProse(FILES)).toBe(true);
    expect(section(done()).join('\n')).not.toContain('instructions files');
  });

  it('says that a large merge request was reviewed with shorter lists, in a sentence of its own, on GitLab and GitHub', () => {
    const TOKENS = 'The review reached its token limit, so it may have missed problems.';
    const WINDOW = 'A reviewer reached the model’s context window, so it may have missed problems.';
    for (const provider of ['gitlab', 'github'] as const) {
      const LISTS = `This ${provider === 'gitlab' ? 'merge' : 'pull'} request is large, so the reviewers were shown a shorter list of its changes and read the rest with their tools.`;
      const notesLine = (over: Partial<Done>) => section(done(over), provider).at(-3);
      expect(notesLine({ notes: ['lists_shortened'] }), provider).toBe(LISTS);
      // Beside the others, each once: the limits first, then this.
      expect(
        notesLine({
          tokenLimitReached: true,
          notes: [
            'lists_shortened',
            'context_window_reached',
            'token_limit_reached',
            'lists_shortened',
          ],
        }),
        provider,
      ).toBe(`${TOKENS} ${WINDOW} ${LISTS}`);
      expect(badSectionLine(section(done({ notes: ['lists_shortened'] }), provider))).toBeNull();
    }
    expect(
      checkProse(
        'This merge request is large, so the reviewers were shown a shorter list of its changes and read the rest with their tools.',
      ),
    ).toBe(true);
    expect(section(done()).join('\n')).not.toContain('shorter list');
  });

  it('says when the merge request has moved on, and what the next pipeline does', () => {
    const moved = (provider: 'gitlab' | 'github', head: string | null) =>
      section(done({ mergeRequestHeadSha: head }), provider).at(-1);
    expect(moved('gitlab', NEWER)).toBe(
      'Reviewed commit: ` aaaaaaaaaaaa `; the merge request is now at ` bbbbbbbbbbbb `; the next pipeline reviews the new commits.',
    );
    expect(moved('github', NEWER)).toBe(
      'Reviewed commit: ` aaaaaaaaaaaa `; the pull request is now at ` bbbbbbbbbbbb `; the next workflow run reviews the new commits.',
    );
    // Not when it is the commit that was reviewed (in either case), or when it is not known.
    expect(moved('gitlab', SHA)).toBe('Reviewed commit: ` aaaaaaaaaaaa `');
    expect(moved('gitlab', SHA.toUpperCase())).toBe('Reviewed commit: ` aaaaaaaaaaaa `');
    expect(moved('gitlab', null)).toBe('Reviewed commit: ` aaaaaaaaaaaa `');
    // No commit to name, none named.
    expect(section(done({ reviewedSha: '' })).join('\n')).not.toContain('Reviewed commit');
  });

  it('puts the live head on a finished review only', () => {
    const state = done();
    expect(withMergeRequestHead(state, NEWER)).toEqual({ ...state, mergeRequestHeadSha: NEWER });
    expect(withMergeRequestHead(state, null)).toEqual(state);
    expect(state.mergeRequestHeadSha).toBeNull();
    for (const other of [{ kind: 'pending' }, { kind: 'failed', reason: 'internal' }] as const) {
      expect(withMergeRequestHead(other, NEWER)).toBe(other);
    }
    expect(withMergeRequestHead(null, NEWER)).toBeNull();
  });
});

describe('the findings a decoration could not post as threads', () => {
  it('joins the ones that are not on changed lines, most severe first, ten listed and the rest counted', () => {
    const state = done({
      unplaced: [finding(1, { severity: 'medium' }), finding(2, { severity: 'low' })],
      moreUnplaced: 3,
    });
    expect(
      withUnplacedFindings(state, [
        finding(3, { severity: 'low' }),
        finding(4, { severity: 'high' }),
      ]),
    ).toEqual({
      ...state,
      unplaced: [
        finding(4, { severity: 'high' }),
        finding(1, { severity: 'medium' }),
        finding(2, { severity: 'low' }),
        finding(3, { severity: 'low' }),
      ],
      moreUnplaced: 3,
    });
    // Ten are listed: the rest are counted with the ones the state counted already.
    const many = withUnplacedFindings(
      state,
      Array.from({ length: 12 }, (_, i) => finding(10 + i, { severity: 'high' })),
    );
    if (many?.kind !== 'done') throw new Error('not done');
    expect(many.unplaced.map((f) => f.line)).toEqual([10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    expect(many.moreUnplaced).toBe(3 + 2 + 12 - 10);
    expect(section(many).join('\n')).toContain('…and 7 more in Qualor');
  });

  it('changes nothing but the finished review of the newest analysis, and nothing with none to add', () => {
    const more = [finding(1)];
    for (const other of [{ kind: 'pending' }, { kind: 'failed', reason: 'internal' }] as const) {
      expect(withUnplacedFindings(other, more)).toBe(other);
    }
    expect(withUnplacedFindings(null, more)).toBeNull();
    const older = done({ latest: false });
    expect(withUnplacedFindings(older, more)).toBe(older);
    const state = done();
    expect(withUnplacedFindings(state, [])).toBe(state);
  });
});

describe('the first note of an AI review thread', () => {
  const ISSUE = '01920000-0000-7000-8000-000000000001';
  const URL_OF_ISSUE = 'https://q.example/projects/p/issues/i1';
  const input = (over: Partial<AiThreadInput> = {}): AiThreadInput => ({
    provider: 'gitlab',
    issueId: ISSUE,
    severity: 'medium',
    category: 'logic',
    confidence: 'high',
    ruleKey: 'ai:logic',
    title: 'The loop skips the last item',
    body: 'The loop stops one item early, so the last item is never added to the sum.',
    assumption: null,
    verification: null,
    suggestion: null,
    issueUrl: URL_OF_ISSUE,
    ...over,
  });
  const LOOP = {
    startLine: 3,
    endLine: 4,
    lines: ['  for (let i = 0; i < items.length; i += 1) {', '    sum += items[i];'],
  };

  it('starts with the issue marker and a fixed header, then the title, the body and the link', () => {
    expect(aiThreadBody(input()).split('\n')).toEqual([
      `<!-- qualor:issue ${ISSUE} -->`,
      '**AI review** · Medium · Logic · likely · ` ai:logic `',
      '',
      '**The loop skips the last item**',
      '',
      'The loop stops one item early, so the last item is never added to the sum.',
      '',
      `[View in Qualor](${URL_OF_ISSUE})`,
    ]);
    expect(markerOf(aiThreadBody(input()))).toEqual({ kind: 'issue', issueId: ISSUE });
    // Without Qualor's address there is no link, and an empty title or body leaves no line.
    expect(aiThreadBody(input({ issueUrl: null, title: '​', body: ' ' })).split('\n')).toEqual([
      `<!-- qualor:issue ${ISSUE} -->`,
      '**AI review** · Medium · Logic · likely · ` ai:logic `',
    ]);
  });

  it('names the severity, the category and the confidence in fixed words', () => {
    const header = (over: Partial<AiThreadInput>) => aiThreadBody(input(over)).split('\n')[1];
    expect(header({ severity: 'high', confidence: 'medium' })).toBe(
      '**AI review** · High · Logic · possible · ` ai:logic `',
    );
    // A severity a person set in Qualor reads as the AI review's three, as the summary counts it.
    expect(header({ severity: 'blocker' })).toContain('· High ·');
    expect(header({ severity: 'low' })).toContain('· Low ·');
    expect(header({ severity: 'info' })).toContain('· Low ·');
    for (const severity of ['constructor', '__proto__', 'critical', '']) {
      expect(header({ severity }), severity).toContain('· Unknown ·');
    }
    const labels = {
      logic: 'Logic',
      'error-handling': 'Error handling',
      compatibility: 'Compatibility',
      concurrency: 'Concurrency',
      security: 'Security',
      performance: 'Performance',
      tests: 'Tests',
      docs: 'Documentation',
    } as const;
    for (const [category, label] of Object.entries(labels)) {
      expect(header({ category: category as keyof typeof labels, ruleKey: `ai:${category}` })).toBe(
        `**AI review** · Medium · ${label} · likely · \` ai:${category} \``,
      );
    }
  });

  it('says what the finding assumes, and that an independent check could not settle it', () => {
    const lines = aiThreadBody(
      input({
        category: 'security',
        ruleKey: 'ai:security',
        confidence: 'medium',
        assumption: 'The handler is reachable without signing in.',
        verification: 'needs_validation',
      }),
    ).split('\n');
    expect(lines.slice(5)).toEqual([
      'The loop stops one item early, so the last item is never added to the sum.',
      '',
      'Assumes: The handler is reachable without signing in.',
      '',
      'Needs validation: an independent check could not tell from the repository whether this holds.',
      '',
      `[View in Qualor](${URL_OF_ISSUE})`,
    ]);
    // A confirmed finding, or one with no assumption, says neither.
    const confirmed = aiThreadBody(input({ verification: 'confirmed', assumption: '  ' }));
    expect(confirmed).not.toContain('Assumes:');
    expect(confirmed).not.toContain('Needs validation:');
  });

  it('writes GitLab’s suggestion block over the lines it replaces, and GitHub’s', () => {
    const gitlab = aiThreadBody(input({ suggestion: LOOP }));
    expect(gitlab.split('\n').slice(5)).toEqual([
      'The loop stops one item early, so the last item is never added to the sum.',
      '',
      '```suggestion:-0+1',
      '  for (let i = 0; i < items.length; i += 1) {',
      '    sum += items[i];',
      '```',
      '',
      `[View in Qualor](${URL_OF_ISSUE})`,
    ]);
    expect(
      aiThreadBody(input({ suggestion: { startLine: 7, endLine: 7, lines: ['x'] } })),
    ).toContain('```suggestion:-0+0\nx\n```');
    // A suggestion that removes the lines it replaces writes an empty block.
    expect(aiThreadBody(input({ suggestion: { startLine: 7, endLine: 8, lines: [] } }))).toContain(
      '```suggestion:-0+1\n```',
    );
    const github = aiThreadBody(input({ provider: 'github', suggestion: LOOP }));
    expect(github).toContain(
      '```suggestion\n  for (let i = 0; i < items.length; i += 1) {\n    sum += items[i];\n```',
    );
    for (const body of [gitlab, github]) expect(checkAiThreadLines(body), body).toBe(true);
  });

  it('leaves out a suggestion that would not be safe to post, and keeps the finding', () => {
    for (const lines of [
      ['```', 'x'],
      ['~~~'],
      ['/merge'],
      ['  /close now'],
      ['a‮b'],
      ['a\rb'],
      [`token = "${'«redacted»'}"`],
      ['x'.repeat(401)],
      Array.from({ length: 31 }, () => 'x'),
    ]) {
      const body = aiThreadBody(input({ suggestion: { startLine: 3, endLine: 3, lines } }));
      expect(body, lines.join('|')).not.toContain('```suggestion');
      expect(body).toContain('**The loop skips the last item**');
    }
    // Neither does a range that is no range, or more than fifteen lines.
    for (const [startLine, endLine] of [
      [0, 1],
      [4, 3],
      [1, 16],
      [1.5, 2],
    ] as const) {
      expect(
        aiThreadBody(input({ suggestion: { startLine, endLine, lines: ['x'] } })),
      ).not.toContain('```suggestion');
    }
  });

  it('stays within 8 KiB: the suggestion goes first, then the body is shortened', () => {
    const bytes = (text: string) => Buffer.byteLength(text, 'utf8');
    // Thirty lines of comment words: a suggestion that passes every check, and is too large.
    const long = Array.from({ length: 30 }, (_, i) => `// ${'word '.repeat(74)}${i}`);
    const suggestion = { startLine: 1, endLine: 15, lines: long };
    const big = aiThreadBody(input({ suggestion }));
    expect(bytes(big)).toBeLessThanOrEqual(AI_THREAD_MAX_BYTES);
    expect(big).not.toContain('```suggestion');
    expect(big).toContain(
      'The loop stops one item early, so the last item is never added to the sum.',
    );
    // Thirty lines of fifty such words fit, and are kept.
    const fitting = long.map((line) => line.slice(0, 250));
    expect(aiThreadBody(input({ suggestion: { ...suggestion, lines: fitting } }))).toContain(
      '```suggestion:-0+14',
    );
    // The longest body a finding has, of words that each need a code span, with the longest
    // assumption and a long link: past the bound once the suggestion is gone, so the body is
    // shortened, and the note keeps its header, its title, its assumption and its link.
    const words = Array.from({ length: 600 }, () => '@').join(' ');
    const link = `https://q.example/${'a'.repeat(4_000)}`;
    const shortened = aiThreadBody(
      input({ body: words, assumption: '@ '.repeat(150), issueUrl: link, suggestion: LOOP }),
    );
    expect(bytes(shortened)).toBeLessThanOrEqual(AI_THREAD_MAX_BYTES);
    expect(shortened).not.toContain('```suggestion');
    const lines = shortened.split('\n');
    expect(lines[1]).toBe('**AI review** · Medium · Logic · likely · ` ai:logic `');
    expect(lines).toContain('**The loop skips the last item**');
    expect(lines.some((line) => line.startsWith('Assumes: ` @ `'))).toBe(true);
    expect(lines.at(-1)).toBe(`[View in Qualor](${link})`);
    const spansOf = (text: string) => text.split('` @ `').length - 1;
    const body = lines.find((line) => line.startsWith('` @ `')) ?? '';
    expect(spansOf(body)).toBeGreaterThan(0);
    expect(spansOf(body)).toBeLessThan(600);
    expect(checkAiThreadLines(shortened)).toBe(true);
    // Without the long link the whole body fits.
    const whole = aiThreadBody(input({ body: words }));
    expect(spansOf(whole.split('\n').find((line) => line.startsWith('` @ `')) ?? '')).toBe(600);
  });

  it('says which suggestion its block offers: the one it was given, or none once it left it out', () => {
    expect(aiThreadNote(input({ suggestion: LOOP }))).toEqual({
      body: aiThreadBody(input({ suggestion: LOOP })),
      suggestion: LOOP,
    });
    expect(aiThreadNote(input()).suggestion).toBeNull();
    // Left out: one that is not safe to post, and one that would make the note too long.
    const unsafe = { startLine: 3, endLine: 3, lines: ['/merge'] };
    const long = {
      startLine: 1,
      endLine: 15,
      lines: Array.from({ length: 30 }, (_, i) => `// ${'word '.repeat(74)}${i}`),
    };
    for (const suggestion of [unsafe, long]) {
      const note = aiThreadNote(input({ suggestion }));
      expect(note.suggestion).toBeNull();
      expect(note.body).not.toContain('```suggestion');
      expect(note.body).toBe(aiThreadBody(input({ suggestion })));
    }
  });

  it('is checked by a body check that refuses markup where it does not belong', () => {
    const good = aiThreadBody(input({ suggestion: LOOP, assumption: 'It runs once.' }));
    expect(checkAiThreadLines(good)).toBe(true);
    const lines = good.split('\n');
    const withLine = (index: number, line: string) =>
      [...lines.slice(0, index), line, ...lines.slice(index + 1)].join('\n');
    // Model text out of its code spans, on any line after the header.
    for (const bad of ['[x](https://e.example)', '@all', '# heading', 'a * b', '**a** *b*']) {
      expect(checkAiThreadLines(withLine(5, bad)), bad).toBe(false);
      expect(checkAiThreadLines(withLine(7, `Assumes: ${bad}`)), bad).toBe(false);
    }
    // A marker or a header that is not the note's own.
    expect(checkAiThreadLines(withLine(0, '<!-- qualor:summary x -->'))).toBe(false);
    expect(
      checkAiThreadLines(withLine(1, '**AI review** · High · Logic · sure · ` ai:logic `')),
    ).toBe(false);
    // A suggestion block that holds a fence, starts a quick action, or is never closed.
    const block = lines.indexOf('```suggestion:-0+1');
    expect(block).toBeGreaterThan(0);
    for (const bad of ['````', '~~~ x', '/merge', '  /close']) {
      expect(checkAiThreadLines(withLine(block + 1, bad)), bad).toBe(false);
    }
    expect(checkAiThreadLines(lines.slice(0, block + 2).join('\n'))).toBe(false);
    // A link that is not Qualor's.
    expect(
      checkAiThreadLines(withLine(lines.length - 1, '[View in Qualor](https://e.example/x)')),
    ).toBe(false);
  });

  const HOSTILE: readonly (readonly [string, string])[] = [
    ['a link', '[x](https://e.example)'],
    ['a mention', '@all and @group/sub'],
    ['references', '#12 !12 ~label %milestone &epic $snippet'],
    ['HTML', '<img src=x onerror=y> <details></details> <script>alert(1)</script>'],
    ['a quick action', '/close\n/merge'],
    ['a heading, a quote and a table', '# heading\n> quote\n| a | b |'],
    ['fences', '```\n~~~\n````'],
    ['a forged marker', '<!-- qualor:issue 01920000-0000-7000-8000-000000000000 -->'],
    ['bold and a rule', '**x** __y__ ***'],
    ['invisible and bidirectional characters', 'a​b‮c d\u0000e﻿'],
    ['backtick runs', '`'.repeat(300)],
    ['a hash and a key', 'deadbeef0123 GH-26 JIRA-12'],
    ['long words', 'w'.repeat(3_000)],
  ];

  it.each(HOSTILE)('keeps %s inert in every slot', (_name, value) => {
    for (const provider of ['gitlab', 'github'] as const) {
      const body = aiThreadBody(
        input({ provider, title: value, body: value, assumption: value, suggestion: LOOP }),
      );
      expect(body).not.toMatch(FORBIDDEN_ANYWHERE);
      expect(markerOf(body)).toEqual({ kind: 'issue', issueId: ISSUE });
      expect(Buffer.byteLength(body, 'utf8')).toBeLessThanOrEqual(AI_THREAD_MAX_BYTES);
      expect(checkAiThreadLines(body), body).toBe(true);
      for (const line of body.split('\n')) expect(line, line).not.toMatch(/^\s*\//);
      // Nothing is a link but Qualor's own, and nothing renders as markup the note did not write.
      const html = marked.parse(body, { async: false, gfm: true, breaks: false });
      for (const [, href] of html.matchAll(/<a [^>]*href="([^"]*)"/g)) {
        expect(href).toMatch(/^https:\/\/q\.example\//);
      }
      expect(html).not.toMatch(
        /<(?:img|script|style|iframe|input|blockquote|table|details|h[1-6]|hr)\b/,
      );
      // The one code block is the suggestion.
      expect(html.match(/<pre>/g) ?? []).toHaveLength(1);
    }
  });
});

describe('the prompt for an AI agent', () => {
  const prompt = (state: Done, maxBytes?: number): string[] => {
    const lines = section(state, 'gitlab', maxBytes);
    const from = lines.indexOf('<details><summary>Prompt for an AI agent</summary>');
    return from < 0 ? [] : lines.slice(from);
  };

  it('lists the open findings in a fenced text block inside a details block, last', () => {
    const lines = section(
      done({
        counts: { high: 1, medium: 1, low: 0 },
        fixPrompt: [promptFinding(1), promptFinding(2, { title: 'Second `thing`' })],
      }),
    );
    expect(lines.slice(-14)).toEqual([
      '<details><summary>Prompt for an AI agent</summary>',
      '',
      '```text',
      'Fix the problems below, which an AI review found in this merge request.',
      'The review can be wrong: read the code first and skip a finding that does not hold.',
      'Keep each change small and run the tests afterwards.',
      '',
      '1. src/file1.ts:1 Finding number 1',
      '   The call in file 1 can fail when the input is empty, so check it first.',
      '2. src/file2.ts:2 Second `thing`',
      '   The call in file 2 can fail when the input is empty, so check it first.',
      '```',
      '',
      '</details>',
    ]);
    // It follows the commit line after a blank line.
    expect(lines.at(-15)).toBe('');
    expect(lines.at(-16)).toBe('Reviewed commit: ` aaaaaaaaaaaa `');
    // The block is opened and closed, and the fence is a block of its own.
    expect(lines.filter((line) => line === '```text')).toHaveLength(1);
    expect(lines.filter((line) => line === '```')).toHaveLength(1);
  });

  it('says it in GitHub’s words for GitHub', () => {
    const lines = section(done({ fixPrompt: [promptFinding(1)] }), 'github');
    expect(lines).toContain(
      'Fix the problems below, which an AI review found in this pull request.',
    );
  });

  it('writes the model’s words in the block as they were written, cleaned, and the place plain', () => {
    const lines = prompt(
      done({
        counts: { high: 1, medium: 0, low: 0 },
        fixPrompt: [
          promptFinding(1, {
            path: 'src/orders/discounts.js',
            line: 12,
            title: 'Throws `CheckoutError`s at @all',
            body: 'Use `try`/`catch` (see x.y).\n\n\n- once\n/close\r\nok\u202eevil\u200bhidden   ',
          }),
        ],
      }),
    );
    expect(lines.slice(7, -3)).toEqual([
      '1. src/orders/discounts.js:12 Throws `CheckoutError`s at @all',
      '   Use `try`/`catch` (see x.y).',
      '',
      '   - once',
      '   /close',
      '   ok evil hidden',
    ]);
    // The place is plain too, and one line: a line break or a bidirectional control in it is a space.
    const odd = prompt(
      done({
        fixPrompt: [promptFinding(1, { path: 'src/a\n/close\u202e.ts', line: 3, title: '' })],
      }),
    );
    expect(odd).toContain('1. src/a /close .ts:3');
  });

  it('gives the block a fence longer than the backticks the model wrote', () => {
    const lines = prompt(done({ fixPrompt: [promptFinding(1, { title: 'A ``` fence' })] }));
    expect(lines[2]).toBe('````text');
    expect(lines).toContain('1. src/file1.ts:1 A ``` fence');
    expect(lines.at(-3)).toBe('````');
    // Three backticks are the shortest fence, and a longer run makes it longer still.
    expect(prompt(done({ fixPrompt: [promptFinding(1)] }))[2]).toBe('```text');
    const long = prompt(done({ fixPrompt: [promptFinding(1, { body: `x ${'`'.repeat(9)} y` })] }));
    expect(long[2]).toBe(`${'`'.repeat(10)}text`);
    expect(long).toContain(`   x ${'`'.repeat(9)} y`);
  });

  it('writes the threads’ and the rest of the section’s words through safeProse, as before', () => {
    const words = 'Use `try`/`catch` (see x.y).';
    const lines = section(
      done({
        verdict: words,
        walkthrough: [words],
        unplaced: [finding(1, { title: words })],
        fixPrompt: [promptFinding(1, { title: words, body: words })],
      }),
    );
    const prose = 'Use ` try `/` catch ` (see ` x.y `).';
    expect(lines[2]).toBe(prose);
    expect(lines).toContain(`- ${prose}`);
    expect(lines.find((line) => line.startsWith('- **Medium**'))).toContain(` · ${prose} · `);
    // In the block the same words are as the model wrote them.
    expect(lines).toContain(`1. src/file1.ts:1 ${words}`);
    expect(lines).toContain(`   ${words}`);
    const thread = aiThreadBody({
      provider: 'gitlab',
      issueId: '01920000-0000-7000-8000-000000000001',
      severity: 'high',
      category: 'logic',
      confidence: 'high',
      ruleKey: 'ai:logic',
      title: words,
      body: words,
      assumption: null,
      verification: null,
      suggestion: null,
      issueUrl: null,
    });
    expect(thread.split('\n').slice(3)).toEqual([`**${prose}**`, '', prose]);
  });

  it('uses a fence longer than any run of backticks inside it', () => {
    const lines = prompt(
      done({
        fixPrompt: [
          promptFinding(1, { body: `Use \`${'`'.repeat(5)}\` and ${'`'.repeat(7)} here` }),
          promptFinding(2, { path: `src/${'`'.repeat(40)}.ts`, title: '```' }),
        ],
      }),
    );
    const content = lines.slice(3, lines.lastIndexOf('</details>') - 2);
    const longest = Math.max(
      ...content.flatMap((line) => line.match(/`+/g) ?? []).map((run) => run.length),
    );
    const fence = lines[2]!;
    expect(fence).toMatch(/^`+text$/);
    expect(fence.length - 'text'.length).toBeGreaterThan(longest);
    expect(lines.at(-3)).toBe('`'.repeat(fence.length - 'text'.length));
  });

  it('says how many open findings it leaves out, when it lists fewer than there are', () => {
    const lines = prompt(
      done({
        counts: { high: 2, medium: 2, low: 1 },
        fixPrompt: [promptFinding(1), promptFinding(2)],
      }),
    );
    expect(lines).toContain('And 3 more open findings are in Qualor.');
    const one = prompt(
      done({ counts: { high: 1, medium: 1, low: 0 }, fixPrompt: [promptFinding(1)] }),
    );
    expect(one).toContain('And 1 more open finding is in Qualor.');
    expect(
      prompt(
        done({
          counts: { high: 1, medium: 1, low: 0 },
          fixPrompt: [promptFinding(1), promptFinding(2)],
        }),
      ).join('\n'),
    ).not.toContain('more open');
  });

  it('has no block at all without a finding to list', () => {
    expect(section(done()).join('\n')).not.toContain('<details>');
  });

  it('is cut down to the findings that fit, and left out when none does', () => {
    const state = done({
      counts: { high: 4, medium: 8, low: 0 },
      fixPrompt: Array.from({ length: 12 }, (_, i) =>
        promptFinding(i + 1, { body: 'word '.repeat(150) }),
      ),
    });
    const whole = section(state);
    expect(bytesOf(whole)).toBeLessThanOrEqual(AI_SECTION_MAX_BYTES);
    const listed = whole.filter((line) => /^\d+\. src\//.test(line)).length;
    expect(listed).toBeGreaterThan(0);
    expect(listed).toBeLessThan(12);
    // The ones it lists are the first, and it says how many it leaves out.
    for (let n = 1; n <= listed; n += 1)
      expect(whole).toContain(`${n}. src/file${n}.ts:${n} Finding number ${n}`);
    expect(whole).toContain(`And ${12 - listed} more open findings are in Qualor.`);
    // With less room than the first finding takes, the whole block goes and the rest stays.
    const withoutPrompt = section({ ...state, fixPrompt: [] });
    expect(section(state, 'gitlab', bytesOf(withoutPrompt) + 200)).toEqual(withoutPrompt);
    expect(withoutPrompt.join('\n')).not.toContain('<details>');
  });
});

describe('what the section drops when space runs out', () => {
  const full = done({
    verdict:
      'The verdict of this review is a long sentence about many things the change does and breaks.',
    walkthrough: Array.from(
      { length: 6 },
      (_, i) => `Walkthrough item number ${i + 1} describes a part of the change`,
    ),
    unplaced: Array.from({ length: 10 }, (_, i) => finding(i + 1)),
    moreUnplaced: 3,
    fixPrompt: Array.from({ length: 3 }, (_, i) => promptFinding(i + 1)),
    snapshotPartial: true,
    mergeRequestHeadSha: NEWER,
  });

  /** What of the section there is at `maxBytes`. */
  const parts = (maxBytes: number) => {
    const lines = section(full, 'gitlab', maxBytes);
    const text = lines.join('\n');
    return {
      lines,
      prompt: text.includes('<details>'),
      walkthrough: text.includes('- Walkthrough item number 6'),
      anyWalkthrough: text.includes('- Walkthrough item'),
      unplaced: lines.filter((line) => line.startsWith('- **Medium**')).length,
      verdict: text.includes(
        'The verdict of this review is a long sentence about many things the change does and breaks.',
      ),
      anyVerdict: text.includes('The verdict'),
      commit: text.includes('Reviewed commit'),
    };
  };

  it('drops the prompt, then the walkthrough, then the tail of the list, then cuts the verdict', () => {
    const fullBytes = bytesOf(section(full));
    expect(fullBytes).toBeLessThanOrEqual(AI_SECTION_MAX_BYTES);
    let previous = parts(fullBytes);
    expect(previous).toMatchObject({
      prompt: true,
      walkthrough: true,
      unplaced: 10,
      verdict: true,
      commit: true,
    });
    const seen = new Set<string>();
    for (let maxBytes = fullBytes; maxBytes >= 0; maxBytes -= 7) {
      const now = parts(maxBytes);
      expect(bytesOf(now.lines), `${maxBytes}`).toBeLessThanOrEqual(maxBytes);
      if (now.lines.length === 0) break;
      // Each part is there only while every part dropped before it is.
      if (now.prompt) expect(now.walkthrough, `${maxBytes}`).toBe(true);
      if (now.walkthrough) expect(now.unplaced, `${maxBytes}`).toBe(10);
      if (now.anyWalkthrough) expect(now.unplaced, `${maxBytes}`).toBe(10);
      if (now.unplaced === 10 || now.unplaced > 0)
        expect(now.verdict || now.anyVerdict, `${maxBytes}`).toBe(true);
      if (now.unplaced > 0 && now.unplaced < 10)
        expect(now.anyWalkthrough, `${maxBytes}`).toBe(false);
      // The list only gets shorter, and what is left of it is its head.
      expect(now.unplaced, `${maxBytes}`).toBeLessThanOrEqual(previous.unplaced);
      expect(now.commit, `${maxBytes}`).toBe(true);
      seen.add(`${now.prompt}|${now.anyWalkthrough}|${now.unplaced === 10}|${now.verdict}`);
      previous = now;
    }
    // Every step of the order was passed through.
    expect([...seen]).toEqual(
      expect.arrayContaining([
        'true|true|true|true',
        'false|true|true|true',
        'false|false|true|true',
        'false|false|false|true',
        'false|false|false|false',
      ]),
    );
  });

  it('counts the findings it no longer lists among the ones in Qualor', () => {
    const fullBytes = bytesOf(section(full));
    for (let maxBytes = fullBytes; maxBytes >= 0; maxBytes -= 25) {
      const lines = section(full, 'gitlab', maxBytes);
      if (lines.length === 0) break;
      const listed = lines.filter((line) => line.startsWith('- **Medium**')).length;
      const more = Number(
        /^…and (\d+) more in Qualor$/.exec(
          lines.find((line) => line.startsWith('…and')) ?? '',
        )?.[1] ?? 0,
      );
      expect(listed + more, `${maxBytes}`).toBe(13);
    }
  });

  it('shows nothing, rather than a cut section, when even the least of it does not fit', () => {
    expect(section(full, 'gitlab', 20)).toEqual([]);
    expect(section({ kind: 'pending' }, 'gitlab', 10)).toEqual([]);
    expect(section(full, 'gitlab', -1)).toEqual([]);
  });

  it('stays within the bound it is given, whatever the section is made of', () => {
    const hostile = done({
      verdict: '界'.repeat(500),
      walkthrough: Array.from({ length: 6 }, () => '😀'.repeat(300)),
      unplaced: Array.from({ length: 10 }, (_, i) =>
        finding(i, { path: `src/${'界'.repeat(300)}`, title: '界'.repeat(300) }),
      ),
      moreUnplaced: 200,
      fixPrompt: Array.from({ length: 20 }, (_, i) =>
        promptFinding(i, { body: '界'.repeat(3_000), title: '界'.repeat(300) }),
      ),
      notes: ['reviewer_unreadable', 'token_limit_reached', 'verification_capped'],
      snapshotPartial: true,
      mergeRequestHeadSha: NEWER,
    });
    for (const maxBytes of [AI_SECTION_MAX_BYTES, 4_096, 3_000, 2_000, 1_500, 1_000, 700]) {
      const lines = section(hostile, 'github', maxBytes);
      expect(bytesOf(lines), `${maxBytes}`).toBeLessThanOrEqual(maxBytes);
    }
    expect(section(hostile).length).toBeGreaterThan(0);
  });
});

describe('model text in the section is inert', () => {
  const HOSTILE: readonly (readonly [string, string])[] = [
    ['a link', '[x](https://e.example)'],
    ['a mention', '@all and @group/sub'],
    ['references', '#12 !12 ~label %milestone &epic $snippet'],
    ['HTML', '<img src=x onerror=y> <details></details> <script>alert(1)</script>'],
    ['a quick action', '/close\n/merge'],
    ['a heading and a quote', '# heading\n> quote\n| a | b |'],
    ['fences', '```\n~~~\n````'],
    ['a forged marker', '<!-- qualor:summary 01920000-0000-7000-8000-000000000000 -->'],
    ['invisible and bidirectional characters', 'a\u200bb\u202ec\u2028d\u0000e\ufeff'],
    ['backtick runs', '`'.repeat(300)],
    ['an end of the block', '</details>\n```\n</details>'],
    ['a hash and a key', 'deadbeef0123 GH-26 JIRA-12'],
    ['long words', 'w'.repeat(3_000)],
  ];

  it.each(HOSTILE)('keeps %s inert in every slot', (_name, value) => {
    const lines = section(
      done({
        verdict: value,
        walkthrough: [value, `- ${value}`],
        unplaced: [finding(1, { title: value, path: value, severity: value })],
        fixPrompt: [promptFinding(1, { title: value, body: value, path: value })],
        notes: [],
        reviewedSha: value,
        mergeRequestHeadSha: value,
      }),
    );
    const body = lines.join('\n');
    expect(body).not.toMatch(FORBIDDEN_ANYWHERE);
    expect(markerOf(body)).toBeNull();
    expect(bytesOf(lines)).toBeLessThanOrEqual(AI_SECTION_MAX_BYTES);
    expect(badSectionLine(lines)).toBeNull();
    // The prompt is there, with the model's words in it: the check read its block.
    expect(lines).toContain('<details><summary>Prompt for an AI agent</summary>');
    // Nothing is a link but Qualor's own, and the details block is the one block there is.
    const html = marked.parse(body, { async: false, gfm: true, breaks: false });
    for (const [, href] of html.matchAll(/<a [^>]*href="([^"]*)"/g)) {
      expect(href).toMatch(/^https:\/\/q\.example\//);
    }
    expect(html).not.toMatch(/<(?:img|script|style|iframe|input|blockquote|table)\b/);
    // The one heading is the section's own.
    expect(html.match(/<h[1-6]\b/g) ?? []).toHaveLength(1);
    expect(html.match(/<details>/g) ?? []).toHaveLength(1);
    expect(html.match(/<\/details>/g) ?? []).toHaveLength(1);
  });

  it('holds only fixed text and Qualor’s links outside what the model wrote', () => {
    for (const provider of ['gitlab', 'github'] as const) {
      const lines = section(
        done({
          unplaced: [finding(1)],
          moreUnplaced: 1,
          fixPrompt: [promptFinding(1)],
          tokenLimitReached: true,
          snapshotPartial: true,
          notes: ['reviewer_unreadable', 'verification_capped'],
          mergeRequestHeadSha: NEWER,
        }),
        provider,
      );
      expect(badSectionLine(lines)).toBeNull();
      expect(lines.some((line) => line.startsWith('```'))).toBe(true);
    }
    for (const state of [
      { kind: 'pending' },
      { kind: 'skipped', reason: 'no_snapshot', detail: null },
      { kind: 'skipped', reason: 'snapshot_rejected', detail: 'SNAPSHOT_INVALID' },
      { kind: 'skipped', reason: 'budget_spent', detail: 'too_large' },
      { kind: 'failed', reason: 'bad_answer' },
    ] as const) {
      expect(badSectionLine(section(state))).toBeNull();
    }
    // The check has teeth: a link, a mention or a heading outside a code span is refused.
    for (const bad of [
      '[x](https://e.example)',
      '@all',
      '# heading',
      'see https://e.example',
      'a * b',
    ]) {
      expect(checkSectionLine(bad), bad).toBe(false);
    }
    expect(outsideCodeSpans('` @all `')).not.toContain('@');
    // Only the title, the model's prose, may join two of its code spans with a mark: the place is
    // one span alone, as Qualor writes it.
    const link = '[View in Qualor](https://q.example/projects/p/issues/i)';
    expect(checkSectionLine(`- **High** · \` a.ts:3 \` · Use \`try\`/\`catch\` · ${link}`)).toBe(
      true,
    );
    expect(checkSectionLine(`- **High** · \` a.ts \`/\` 3 \` · A title · ${link}`)).toBe(false);
  });

  it('accepts a fixed text that holds markup only as a whole line or where it belongs', () => {
    const base = 'https://q.example/projects/p/issues/i';
    // The lines the section writes, each in its place.
    for (const good of [
      '#### AI review',
      'AI review in progress…',
      '**Not on changed lines:**',
      '<details><summary>Prompt for an AI agent</summary>',
      '</details>',
      '```text',
      '`````text',
      '```',
      '**Findings:** 1 high · 2 medium · 0 low',
      '…and 3 more in Qualor',
      '- **High** · ` src/a.ts:1 `',
      '- **Medium** · ` src/a.ts:1 ` · Some title words',
      `- **Low** · \` src/a.ts:1 \` · [View in Qualor](${base})`,
      `- **Unknown** · \` a \` · A title · [View in Qualor](${base}1)`,
      '- **High** · ` a · b ` · A title with ` code · spans `',
    ]) {
      expect(checkSectionLine(good), good).toBe(true);
    }
    // The same texts anywhere else in a line are model text out of its code spans. (The ellipsis
    // and the dashes are ordinary text now, so a line with one is no markup.)
    for (const bad of [
      'see </details> here',
      '</details> x',
      'x </details>',
      'text <details><summary>Prompt for an AI agent</summary>',
      '<details><summary>Prompt for an AI agent</summary> x',
      'foo #### AI review',
      '#### AI review x',
      '#### AI review #### AI review',
      'a **Not on changed lines:** b',
      'x **Findings:** 1 high · 2 medium · 0 low',
      '**Findings:** 1 high · 2 medium · 0 low x',
      '**Findings:** 1 high · 2 medium',
      'a **High** b',
      'x - **High** · ` a `',
      '- x **High** · ` a `',
      '- **High** x ` a `',
      '- **High** · a · b',
      '- **High** · ` a ` · one · two',
      '- **High** · ` a ` · title · **High** · ` b `',
      '- **High** · ` a ` extra',
      '- **Critical** · ` a `',
      '1. **High** · ` a `',
    ]) {
      expect(checkSectionLine(bad), bad).toBe(false);
    }
    // A link is Qualor's: the test's base, over https, and nothing but a path after it.
    for (const bad of [
      '- **High** · ` a ` · [View in Qualor](https://evil.example/x)',
      '- **High** · ` a ` · [View in Qualor](http://q.example/x)',
      '- **High** · ` a ` · [View in Qualor](https://q.example.evil.example/x)',
      '- **High** · ` a ` · [View in Qualor](https://q.example/x?y=1)',
      '- **High** · ` a ` · [View in Qualor](https://q.example/x) more',
      '- **High** · ` a ` · [Click](https://q.example/x)',
      '- **High** · ` a ` · [View in Qualor](https://q.example/x) · [View in Qualor](https://q.example/y)',
      '[View in Qualor](https://q.example/x)',
    ]) {
      expect(checkSectionLine(bad), bad).toBe(false);
    }
  });

  it('checks the prompt block as code: nothing in it may end its fence or begin a line', () => {
    const block = (...text: string[]) => [
      '#### AI review',
      '',
      '<details><summary>Prompt for an AI agent</summary>',
      '',
      '````text',
      'Keep each change small and run the tests afterwards.',
      '',
      ...text,
      '````',
      '',
      '</details>',
    ];
    expect(badSectionLine(block('1. @all /merge `x` ``` #1', '   /close <img src=x>', ''))).toBe(
      null,
    );
    // A run as long as the fence, a line that starts with model text, or one unindented.
    expect(badSectionLine(block('1. a ```` b'))).toBe('1. a ```` b');
    expect(badSectionLine(block('/close'))).toBe('/close');
    expect(badSectionLine(block('  /close'))).toBe('  /close');
    expect(badSectionLine(block('# heading'))).toBe('# heading');
    // A fence that is never closed, or that is not between the block's tags.
    expect(badSectionLine(block('1. x').slice(0, -3))).toBe('````text');
    expect(badSectionLine(block('1. x').slice(0, -1))).toBe('````text');
    expect(badSectionLine(['#### AI review', '', '````text', '1. x', '````'])).toBe('````text');
    // Outside the block a slash, a fence of its own and model text out of its spans are refused.
    for (const bad of ['  /close', '```', 'see @all']) {
      expect(badSectionLine(['#### AI review', '', bad]), bad).toBe(bad);
    }
  });

  it('shows the verdict, the notes and the commit of an older analysis, and none of the branch’s findings', () => {
    // The findings of the branch are the current ones: an analysis that is no longer the newest
    // is not given them, whatever the state holds.
    const lines = section(
      done({
        latest: false,
        counts: { high: 2, medium: 1, low: 0 },
        unplaced: [finding(1)],
        moreUnplaced: 3,
        fixPrompt: [promptFinding(1)],
        tokenLimitReached: true,
        notes: ['reviewer_unreadable'],
        mergeRequestHeadSha: NEWER,
      }),
    );
    expect(lines).toEqual([
      '#### AI review',
      '',
      'The change adds refunds; one path can fail silently.',
      '',
      'The review reached its token limit, so it may have missed problems. A reviewer’s answer could not be read, so part of the review is missing.',
      '',
      'Reviewed commit: ` aaaaaaaaaaaa `',
    ]);
    const text = lines.join('\n');
    for (const gone of [
      'Findings',
      'No findings',
      'Not on changed lines',
      '<details>',
      '- ',
      'now at',
    ]) {
      expect(text, gone).not.toContain(gone);
    }
    // Nothing else of it changes: the newest analysis shows it all, whether `latest` is true or left out.
    expect(section(done({ latest: true }))).toEqual(section(done()));
    expect(section(done()).join('\n')).toContain('**Findings:**');
    // A review that is not done has no findings to leave out.
    expect(section({ kind: 'pending' })).toEqual(['#### AI review', '', 'AI review in progress…']);
  });
});

describe('the answer to a reply', () => {
  const ROW = '01920000-0000-7000-8000-0000000000aa';
  const bytes = (text: string) => Buffer.byteLength(text, 'utf8');
  /** The lines of the answer itself: after the marker, the heading and the blank line. */
  const answerLines = (note: string, statusLine: boolean) => {
    const lines = note.split('\n').slice(3);
    return statusLine ? lines.slice(0, -2) : lines;
  };

  it('starts with the reply marker and a fixed heading, then the answer', () => {
    expect(replyNote(ROW, 'The loop covers the last item.', null).split('\n')).toEqual([
      `<!-- qualor:reply ${ROW} -->`,
      '**AI review** · reply',
      '',
      'The loop covers the last item.',
    ]);
    expect(replyMarker(ROW)).toBe(`<!-- qualor:reply ${ROW} -->`);
  });

  it('says in a fixed line of its own what became of the finding when the reply changed its status', () => {
    expect(
      replyNote(ROW, 'Understood: the team accepts it for now.', 'wont_fix').split('\n'),
    ).toEqual([
      `<!-- qualor:reply ${ROW} -->`,
      '**AI review** · reply',
      '',
      'Understood: the team accepts it for now.',
      '',
      "Marked won't fix.",
    ]);
    expect(replyNote(ROW, 'The guard above covers it.', 'false_positive').split('\n').at(-1)).toBe(
      'Marked as a false positive: the code shows it does not hold.',
    );
    // An empty answer leaves the heading and the line.
    expect(replyNote(ROW, '', 'wont_fix').split('\n')).toEqual([
      `<!-- qualor:reply ${ROW} -->`,
      '**AI review** · reply',
      '',
      "Marked won't fix.",
    ]);
  });

  it('writes the model’s answer through safeProse: a link, a mention and a quick action stay code', () => {
    const note = replyNote(
      ROW,
      'See https://evil.example/x and ping @all about #12.\n/close\n- [click](https://evil.example)',
      'wont_fix',
    );
    expect(note).toContain('See ` https://evil.example/x ` and ping ` @all ` about ` #12 `.');
    expect(note).not.toMatch(FORBIDDEN_ANYWHERE);
    const lines = answerLines(note, true);
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) {
      expect(checkProse(line), line).toBe(true);
      expect(line, line).not.toMatch(/^\s*\//);
    }
    // Rendered, nothing of it is a link.
    expect(marked.parse(note, { async: false, gfm: true, breaks: false })).not.toContain('<a ');
  });

  it('is never taken for a thread: the marker is no marker of an issue or a summary', () => {
    expect(markerOf(replyNote(ROW, 'An answer.', 'wont_fix'))).toBeNull();
    expect(markerOf(replyMarker(ROW))).toBeNull();
    expect(() => replyMarker('not-a-uuid')).toThrow();
  });

  it('stays within 4 KiB: the fixed lines stay, and the answer is cut at whole lines or shortened', () => {
    // The longest answer, of words that each need a code span: past the bound whole.
    const spans = Array.from({ length: 600 }, () => '①').join(' ');
    expect(spans.length).toBeLessThanOrEqual(1_200);
    const note = replyNote(ROW, spans, 'false_positive');
    expect(bytes(note)).toBeLessThanOrEqual(REPLY_NOTE_MAX_BYTES);
    const lines = note.split('\n');
    expect(lines.slice(0, 3)).toEqual([
      `<!-- qualor:reply ${ROW} -->`,
      '**AI review** · reply',
      '',
    ]);
    expect(lines.at(-1)).toBe('Marked as a false positive: the code shows it does not hold.');
    const shown = answerLines(note, true).join('\n');
    const count = shown.split('` ① `').length - 1;
    expect(count).toBeGreaterThan(0);
    expect(count).toBeLessThan(600);
    for (const line of answerLines(note, true)) expect(checkProse(line), line).toBe(true);
    // Lines that fit are kept whole: twenty lines of plain words are all there.
    const plain = Array.from({ length: 20 }, (_, i) => `Line ${i + 1} of the answer.`).join('\n');
    expect(answerLines(replyNote(ROW, plain, 'wont_fix'), true)).toEqual(plain.split('\n'));
  });
});

describe('the answer to a command', () => {
  const ROW = '01920000-0000-7000-8000-0000000000bb';

  it('is the reply marker of its row, the fixed heading and the text as it was given', () => {
    const text = `Reviewing this commit (${codeSpan(SHA.slice(0, 12))}).`;
    expect(commandNote(ROW, text).split('\n')).toEqual([
      `<!-- qualor:reply ${ROW} -->`,
      '**AI review** · reply',
      '',
      'Reviewing this commit (` aaaaaaaaaaaa `).',
    ]);
  });

  it('is never taken for a thread or a summary: the marker is no marker of either', () => {
    expect(markerOf(commandNote(ROW, 'A review of this commit is in progress.'))).toBeNull();
    expect(() => commandNote('not-a-uuid', 'Text.')).toThrow();
  });
});
