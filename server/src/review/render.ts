import { redactText, suggestionLineProblem } from '@qualor/shared';
import type { AiCategory, ReviewFailureReason, ReviewSkipReason } from '../db/schema';
import {
  codeSpan,
  issueMarker,
  linesWithinBytes,
  MAX_PATH_CHARS,
  plainProse,
  plainValue,
  qualorLink,
  replyMarker,
  safeProse,
} from '../scm/markdown';
import { CONVERSATION_LIMITS } from './conversation';
import { aiSeverityOf, type AiSeverity } from './rules';
import { ANSWER_LIMITS, type ReviewNote } from './schemas';

/*
 * The AI review section of the summary comment, for GitLab and GitHub alike: what the review of
 * the merge request is doing or did, as lines of Markdown that the summary adds after the
 * analyzers' part. Everything in it is Qualor's fixed text (a sentence for each reason a review was
 * skipped or failed, for each note it makes of itself), a number, a code in a code span, Qualor's
 * own link, or the model's words through `safeProse`: its verdict, the items of its walkthrough,
 * the titles and bodies of its findings. A path is a code span. Nothing the model or the
 * repository wrote is anything but a word to GitLab or GitHub. The prompt for an agent is the one
 * place they are plain: a fenced block, which renders none of its text and which nothing in it can
 * end, holds the findings' places and the model's words cleaned (`plainProse`), as an agent reads
 * them.
 *
 * The section has its own bound (AI_SECTION_MAX_BYTES) and gives way to the room the note has, by
 * whole lines: it drops the prompt for an agent first (or lists fewer findings in it), then the
 * walkthrough, then the tail of the findings not on changed lines, then cuts the verdict; and shows
 * nothing when even that does not fit.
 *
 * The first note of a finding's thread (aiThreadNote) is made of the same pieces, and of the one
 * text no model word goes through `safeProse` in: the lines of its one-click suggestion, code that a
 * person applies, which the storing of the finding checked and which are checked again here. So is
 * Qualor's answer to a person's reply in such a thread (replyNote). Its answer to a command
 * (commandNote) is Qualor's own sentence, with a commit in a code span, and holds no other word.
 */

/** The most bytes of the section; the summary comment as a whole has 16 KiB. */
export const AI_SECTION_MAX_BYTES = 6 * 1024;
/** The findings not on changed lines the section lists; the rest are counted. */
export const UNPLACED_LISTED = 10;
/** The open findings the prompt for an agent may list, and what it keeps of the body of each. */
export const PROMPT_FINDINGS = 20;
const PROMPT_BODY_CHARS = 600;
const PROMPT_BODY_LINES = 8;

/** What the section says: the state of the review of the analysis' merge request. */
export type ReviewSummaryState =
  | { kind: 'pending' }
  | { kind: 'skipped'; reason: ReviewSkipReason; detail: string | null }
  | {
      kind: 'failed';
      reason: ReviewFailureReason;
      /**
       * `window_full`: the model's context window had no room for the judge's call; `time_limit`:
       * the judge had no answer when the review's time was up.
       */
      detail?: string | null;
    }
  | {
      kind: 'done';
      /**
       * False when the analysis is no longer the branch's newest: the findings below are the
       * branch's now, not this run's, so the section tells the verdict, the notes and the commit
       * only. Left out, the analysis is the newest.
       */
      latest?: boolean;
      /** The judge's one line about the merge request, and its walkthrough of what changed. */
      verdict: string;
      walkthrough: string[];
      /** The merge request's open AI findings by severity (Qualor's: `blocker` counts as high). */
      counts: { high: number; medium: number; low: number };
      /** Open AI findings with no changed line to sit on, most severe first, and how many more. */
      unplaced: {
        severity: string;
        path: string;
        line: number;
        title: string;
        url: string | null;
      }[];
      moreUnplaced: number;
      /** The commit the review covered, and the merge request's head now, when it is known. */
      reviewedSha: string;
      mergeRequestHeadSha: string | null;
      tokenLimitReached: boolean;
      snapshotPartial: boolean;
      /** What the review said of itself besides those two (`reviewer_unreadable`, ...). */
      notes?: readonly ReviewNote[];
      /** The open findings the prompt for an agent lists. */
      fixPrompt: { path: string; line: number; title: string; body: string }[];
    };
type Done = Extract<ReviewSummaryState, { kind: 'done' }>;

/** The state with the merge request's head as the provider says it is now, when the review is done. */
export function withMergeRequestHead(
  state: ReviewSummaryState | null,
  head: string | null,
): ReviewSummaryState | null {
  return state?.kind === 'done' ? { ...state, mergeRequestHeadSha: head } : state;
}

/** The order of the review's three severities in the section's list; any other comes last. */
const SEVERITY_ORDER: Readonly<Record<string, number>> = { high: 0, medium: 1, low: 2 };
const severityOrder = (severity: string): number =>
  Object.hasOwn(SEVERITY_ORDER, severity) ? (SEVERITY_ORDER[severity] ?? 3) : 3;

/**
 * The finished review of the newest analysis with `more` among its findings not on changed lines:
 * the ones a decoration could not post as threads this time (the merge request moved on, they are
 * past the cap of threads, the provider's diff had no place for them or the provider refused the
 * place). Most severe first, as the loader gives its own (a stable order within a severity), at
 * most UNPLACED_LISTED of them listed and the rest counted. Any other state is given back as it is.
 */
export function withUnplacedFindings(
  state: ReviewSummaryState | null,
  more: readonly Done['unplaced'][number][],
): ReviewSummaryState | null {
  if (state?.kind !== 'done' || state.latest === false || more.length === 0) return state;
  const all = [...state.unplaced, ...more].sort(
    (a, b) => severityOrder(a.severity) - severityOrder(b.severity),
  );
  const listed = all.slice(0, UNPLACED_LISTED);
  return {
    ...state,
    unplaced: listed,
    moreUnplaced: count(state.moreUnplaced) + all.length - listed.length,
  };
}

// ─── Qualor's fixed text ─────────────────────────────────────────────────────

type Provider = 'gitlab' | 'github';
/** The words that differ between GitLab and GitHub. */
interface Words {
  request: string;
  run: string;
  /** What a person's note in the request is called: the note that gives a command. */
  note: string;
}
const WORDS: Record<Provider, Words> = {
  gitlab: { request: 'merge request', run: 'pipeline', note: 'note' },
  github: { request: 'pull request', run: 'workflow run', note: 'comment' },
};

const HEADING = '#### AI review';
const PENDING = 'AI review in progress…';

/** Why a review did not run. A missing snapshot points to the CI job's log and the guide's `fetch-depth` note. */
const SKIPPED: Record<ReviewSkipReason, (words: Words) => string> = {
  no_snapshot: () =>
    'AI review did not run: no repository snapshot came for this commit. See the CI job’s log and the guide’s `fetch-depth` note.',
  snapshot_rejected: () =>
    'AI review did not run: the server refused the repository snapshot of this commit.',
  draft: (words) =>
    `AI review is skipped while this ${words.request} is a draft; the next ${words.run} after it is ready reviews it, and a \`qualor review\` ${words.note} reviews it now.`,
  closed: (words) => `AI review did not run because this ${words.request} is merged or closed.`,
  inactive: () => 'AI review is switched off for this project.',
  empty_diff: () => 'AI review found nothing to review in the changed files.',
  unchanged: () =>
    'AI review did not repeat: the changes it reviews are the same as in its last review, whose findings stay open.',
  budget_spent: () => 'AI review did not run because its token budget for today is spent.',
};
/**
 * A spent budget that is not the day's: the merge request is too large for what one review may
 * use (`budget_spent`, detail `too_large`). The detail picks the sentence, so it is not repeated.
 */
const TOO_LARGE = (words: Words): string =>
  `AI review did not run because this ${words.request} is too large for the Tokens per review budget; raise it in Settings → AI.`;
/**
 * A spent budget that is the model's context window (`budget_spent`, detail `window_too_small`):
 * Tokens per review holds the merge request, the window does not. Never says to raise the budget.
 */
const WINDOW_TOO_SMALL = (words: Words): string =>
  `AI review did not run because this ${words.request} is too large for the model’s context window; raise Context window in the AI provider settings if the model takes more.`;
const SKIPPED_OTHER = 'AI review did not run.';
const REASON = 'Reason:';
/** A code of Qualor's own that a skip carries (`SNAPSHOT_INVALID`, `consent_outdated`): never content. */
const DETAIL_CODE = /^[A-Za-z0-9_]{1,64}$/;

/** Why a review failed. */
const FAILED: Record<ReviewFailureReason, string> = {
  provider_error: 'AI review failed: the model provider returned an error or could not be reached.',
  provider_no_tools:
    'AI review failed: the model provider does not support the tool calls the review needs.',
  bad_answer: 'AI review failed: the model’s answers could not be read.',
  internal: 'AI review failed because of an error in Qualor.',
};
const FAILED_OTHER = 'AI review failed.';
/**
 * A failure that is the model's context window (`provider_error`, detail `window_full`): the judge's
 * call had no room in it, whatever was cut. The detail picks the sentence, and the next push would
 * fail the same way, so it says what to change instead.
 */
const WINDOW_FULL = (words: Words): string =>
  `AI review failed because the model’s context window is too small for this ${words.request}; raise Context window in the AI provider settings, or use a model with a larger window.`;
/**
 * A failure that is the review's time (`provider_error`, detail `time_limit`): the judge had no
 * answer when it was up. The detail picks the sentence; the operator may set another time, so it
 * names none.
 */
const TIME_LIMIT = 'AI review failed because it ran out of time.';
const NEXT_PUSH = 'The next push reviews again.';

/** What a finished review says of itself. */
const NOTES: Record<ReviewNote, string | ((words: Words) => string)> = {
  reviewer_unreadable: 'A reviewer’s answer could not be read, so part of the review is missing.',
  token_limit_reached: 'The review reached its token limit, so it may have missed problems.',
  turn_limit_reached: `A reviewer reached its limit of ${CONVERSATION_LIMITS.maxTurns} turns, so it may have missed problems.`,
  verification_capped:
    'There were more serious security findings than the review verifies, so the rest were not checked a second time.',
  context_window_reached:
    'A reviewer reached the model’s context window, so it may have missed problems.',
  lists_shortened: (words) =>
    `This ${words.request} is large, so the reviewers were shown a shorter list of its changes and read the rest with their tools.`,
  time_limit_reached: 'The review reached its time limit, so it may have missed problems.',
  instructions_shortened:
    'The repository’s instructions files were shortened to fit the model’s context window, so the review may not follow all of them.',
};
/** The text of a note, for the words of the provider. */
const noteText = (note: ReviewNote, words: Words): string => {
  const text = NOTES[note];
  return typeof text === 'string' ? text : text(words);
};
const SNAPSHOT_PARTIAL =
  'The scanner left some files out of the repository snapshot to stay within its limits, so the review did not see all of them.';

const FINDINGS = '**Findings:**';
const NO_FINDINGS = 'No findings.';
const UNPLACED = '**Not on changed lines:**';
const SEVERITY_LABEL: Readonly<Record<string, string>> = {
  high: '**High**',
  medium: '**Medium**',
  low: '**Low**',
};
const SEVERITY_OTHER = '**Unknown**';
const SEPARATOR = ' · ';
const MORE_PREFIX = '…and';
const REVIEWED = 'Reviewed commit:';
const PROMPT_OPEN = '<details><summary>Prompt for an AI agent</summary>';
const PROMPT_CLOSE = '</details>';
const PROMPT_INTRO = (words: Words): string[] => [
  `Fix the problems below, which an AI review found in this ${words.request}.`,
  'The review can be wrong: read the code first and skip a finding that does not hold.',
  'Keep each change small and run the tests afterwards.',
];

/**
 * The fixed lines of the section that hold markup, each written whole on a line of its own: its
 * heading, the label of its list of findings and the two tags of its prompt block. Its other fixed
 * texts are prose, or sit in lines of a shape the checks of server/test/markdown-check.ts know (the
 * count line, the line of a finding).
 */
export const AI_SECTION_MARKUP_LINES: readonly string[] = [
  HEADING,
  UNPLACED,
  PROMPT_OPEN,
  PROMPT_CLOSE,
];

// ─── Pieces ──────────────────────────────────────────────────────────────────

const bytesOf = (lines: readonly string[]): number => Buffer.byteLength(lines.join('\n'), 'utf8');

/** A count as fixed text: a non-negative integer, else 0. */
const count = (n: number): number => (Number.isSafeInteger(n) && n > 0 ? n : 0);

const LIST_MARKER = /^(?:- |\d+[.)] )/;

/** The model's words as one line inside a line of ours: prose without the marker of a list item. */
export function inlineProse(text: string, maxChars: number): string {
  return safeProse(text, { maxChars, maxLines: 1 }).replace(LIST_MARKER, '');
}

const location = (path: string, line: number): string =>
  Number.isSafeInteger(line) && line > 0 ? `${path}:${line}` : path;

function skippedText(
  state: Extract<ReviewSummaryState, { kind: 'skipped' }>,
  words: Words,
): string {
  if (state.reason === 'budget_spent' && state.detail === 'too_large') return TOO_LARGE(words);
  if (state.reason === 'budget_spent' && state.detail === 'window_too_small') {
    return WINDOW_TOO_SMALL(words);
  }
  const sentence = Object.hasOwn(SKIPPED, state.reason)
    ? SKIPPED[state.reason](words)
    : SKIPPED_OTHER;
  const detail = state.detail ?? '';
  return DETAIL_CODE.test(detail) ? `${sentence} ${REASON} ${codeSpan(detail)}.` : sentence;
}

function failedText(state: Extract<ReviewSummaryState, { kind: 'failed' }>, words: Words): string {
  if (state.detail === 'window_full') return WINDOW_FULL(words);
  if (state.detail === 'time_limit') return `${TIME_LIMIT} ${NEXT_PUSH}`;
  const sentence = Object.hasOwn(FAILED, state.reason) ? FAILED[state.reason] : FAILED_OTHER;
  return `${sentence} ${NEXT_PUSH}`;
}

function findingsLine(counts: Done['counts']): string {
  const [high, medium, low] = [count(counts.high), count(counts.medium), count(counts.low)];
  return high + medium + low === 0
    ? NO_FINDINGS
    : `${FINDINGS} ${high} high${SEPARATOR}${medium} medium${SEPARATOR}${low} low`;
}

function unplacedItem(finding: Done['unplaced'][number]): string {
  const known = Object.hasOwn(SEVERITY_LABEL, finding.severity)
    ? SEVERITY_LABEL[finding.severity]
    : undefined;
  const severity = known ?? SEVERITY_OTHER;
  const title = inlineProse(finding.title, ANSWER_LIMITS.titleChars);
  const link = qualorLink('View in Qualor', finding.url);
  const parts = [severity, codeSpan(location(finding.path, finding.line), MAX_PATH_CHARS)];
  if (title !== '') parts.push(title);
  if (link !== null) parts.push(link);
  return `- ${parts.join(SEPARATOR)}`;
}

/** The notes the review makes of itself, once each, in the order they are told. */
function noteSentences(state: Done, words: Words): string[] {
  const notes = new Set<string>(state.notes ?? []);
  const sentences: string[] = [];
  if (state.tokenLimitReached || notes.has('token_limit_reached')) {
    sentences.push(noteText('token_limit_reached', words));
  }
  if (notes.has('turn_limit_reached')) sentences.push(noteText('turn_limit_reached', words));
  if (notes.has('time_limit_reached')) sentences.push(noteText('time_limit_reached', words));
  if (notes.has('context_window_reached'))
    sentences.push(noteText('context_window_reached', words));
  if (notes.has('lists_shortened')) sentences.push(noteText('lists_shortened', words));
  if (notes.has('instructions_shortened')) {
    sentences.push(noteText('instructions_shortened', words));
  }
  if (state.snapshotPartial) sentences.push(SNAPSHOT_PARTIAL);
  if (notes.has('reviewer_unreadable')) sentences.push(noteText('reviewer_unreadable', words));
  if (notes.has('verification_capped')) sentences.push(noteText('verification_capped', words));
  return sentences;
}

/** The commit the review covered, and where the merge request is now when it has moved on. */
function reviewedLine(state: Done, words: Words): string | null {
  if (state.reviewedSha === '') return null;
  const reviewed = `${REVIEWED} ${codeSpan(state.reviewedSha.slice(0, 12))}`;
  const head = state.mergeRequestHeadSha;
  // An older analysis' commit is not the one the next run reviews: nothing is said of where the request is.
  if (state.latest === false) return reviewed;
  if (head === null || head.toLowerCase() === state.reviewedSha.toLowerCase()) return reviewed;
  return `${reviewed}; the ${words.request} is now at ${codeSpan(head.slice(0, 12))}; the next ${words.run} reviews the new commits.`;
}

// ─── The prompt for an AI agent ──────────────────────────────────────────────

/**
 * A finding of the prompt: its place, its title and a part of its body, indented under it. The
 * block renders none of it, so they are plain, as an agent reads them: the place `path:line` and
 * the model's words cleaned (`plainProse`), not code-spanned. Each line starts with Qualor's own
 * text, the finding's number or the indent of its body.
 */
function promptItem(finding: Done['fixPrompt'][number], index: number): string[] {
  const where = plainValue(location(finding.path, finding.line), MAX_PATH_CHARS);
  const title = plainProse(finding.title, { maxChars: ANSWER_LIMITS.titleChars, maxLines: 1 });
  const body = plainProse(finding.body, {
    maxChars: PROMPT_BODY_CHARS,
    maxLines: PROMPT_BODY_LINES,
  });
  const heading = title === '' ? where : `${where} ${title}`;
  return [
    `${index + 1}. ${heading}`,
    ...(body === '' ? [] : body.split('\n').map((line) => (line === '' ? '' : `   ${line}`))),
  ];
}

/**
 * The block: a fence longer than any run of backticks inside it (its content as it is written), so
 * that nothing in it can end it, and its text renders as code.
 */
function promptBlock(content: readonly string[]): string[] {
  let longest = 0;
  for (const line of content) {
    for (const run of line.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  }
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return [PROMPT_OPEN, '', `${fence}text`, ...content, fence, '', PROMPT_CLOSE];
}

/**
 * The prompt for an agent that lists the open findings: as many, from the most severe, as fit in
 * `budget` bytes, and how many it leaves out; null when not even one fits (or there is none).
 */
function promptFor(state: Done, words: Words, budget: number): string[] | null {
  const items = state.fixPrompt.slice(0, PROMPT_FINDINGS).map(promptItem);
  const open = count(state.counts.high) + count(state.counts.medium) + count(state.counts.low);
  for (let listed = items.length; listed >= 1; listed -= 1) {
    const left = Math.max(0, open - listed);
    const block = promptBlock([
      ...PROMPT_INTRO(words),
      '',
      ...items.slice(0, listed).flat(),
      ...(left > 0
        ? ['', `And ${left} more open ${left === 1 ? 'finding is' : 'findings are'} in Qualor.`]
        : []),
    ]);
    if (bytesOf(block) <= budget) return block;
  }
  return null;
}

// ─── The section ─────────────────────────────────────────────────────────────

/** What of a finished review's section is kept when space is short. */
interface Plan {
  verdictChars: number;
  walkthrough: boolean;
  /** How many of the findings not on changed lines are listed. */
  unplaced: number;
}

/** The block of the findings not on changed lines, `listedCount` of them listed; null when there are none. */
function unplacedBlock(
  items: readonly string[],
  beyond: number,
  listedCount: number,
): string[] | null {
  if (items.length + beyond === 0) return null;
  const listed = items.slice(0, listedCount);
  const more = beyond + items.length - listed.length;
  const separator = listed.length > 0 && more > 0 ? [''] : [];
  return [
    UNPLACED,
    '',
    ...listed,
    ...separator,
    ...(more > 0 ? [`${MORE_PREFIX} ${more} more in Qualor`] : []),
  ];
}

function doneSection(state: Done, words: Words, maxBytes: number): string[] {
  // The findings are the branch's, as they are now: only the newest analysis' section shows them.
  const current = state.latest !== false;
  const findings = findingsLine(state.counts);
  const walkthrough = state.walkthrough
    .slice(0, ANSWER_LIMITS.walkthroughItems)
    .map((item) => inlineProse(item, ANSWER_LIMITS.walkthroughChars))
    .filter((item) => item !== '')
    .map((item) => `- ${item}`);
  const items = state.unplaced.slice(0, UNPLACED_LISTED).map(unplacedItem);
  const beyond = count(state.moreUnplaced) + Math.max(0, state.unplaced.length - items.length);
  const notes = noteSentences(state, words).join(' ');
  const reviewed = reviewedLine(state, words);

  const assemble = (plan: Plan): string[] => {
    const blocks: string[][] = [];
    const verdict = plan.verdictChars > 0 ? inlineProse(state.verdict, plan.verdictChars) : '';
    if (verdict !== '') blocks.push([verdict]);
    if (current) {
      blocks.push([findings]);
      if (plan.walkthrough && walkthrough.length > 0) blocks.push(walkthrough);
      const unplaced = unplacedBlock(items, beyond, plan.unplaced);
      if (unplaced !== null) blocks.push(unplaced);
    }
    if (notes !== '') blocks.push([notes]);
    if (reviewed !== null) blocks.push([reviewed]);
    return [HEADING, ...blocks.flatMap((block) => ['', ...block])];
  };

  // In the order space gives way: the prompt, the walkthrough, the findings from the end of the
  // list, the verdict.
  const verdictChars = ANSWER_LIMITS.verdictChars;
  const plans: Plan[] = [{ verdictChars, walkthrough: true, unplaced: items.length }];
  if (current) {
    plans.push({ verdictChars, walkthrough: false, unplaced: items.length });
    for (let listed = items.length - 1; listed >= 0; listed -= 1) {
      plans.push({ verdictChars, walkthrough: false, unplaced: listed });
    }
  }
  for (let chars = verdictChars >> 1; chars >= 25; chars >>= 1) {
    plans.push({ verdictChars: chars, walkthrough: false, unplaced: 0 });
  }
  for (const [index, plan] of plans.entries()) {
    const lines = assemble(plan);
    const size = bytesOf(lines);
    if (size > maxBytes) continue;
    if (index > 0 || !current) return lines;
    // Whatever room the whole of it leaves is the prompt's: its two newlines are the blank line.
    const prompt = promptFor(state, words, maxBytes - size - 2);
    return prompt === null ? lines : [...lines, '', ...prompt];
  }
  return [];
}

/**
 * The AI review section for the summary comment, as lines: its heading and the state of the
 * review in Qualor's words, at most `maxBytes` (no lines at all when it does not fit). A state this
 * code does not know shows nothing.
 */
export function aiSummarySection(
  state: ReviewSummaryState,
  provider: Provider,
  maxBytes: number,
): string[] {
  const words = provider === 'github' ? WORDS.github : WORDS.gitlab;
  let lines: string[];
  switch (state.kind) {
    case 'pending':
      lines = [HEADING, '', PENDING];
      break;
    case 'skipped':
      lines = [HEADING, '', skippedText(state, words)];
      break;
    case 'failed':
      lines = [HEADING, '', failedText(state, words)];
      break;
    case 'done':
      return doneSection(state, words, maxBytes);
    default:
      return [];
  }
  return bytesOf(lines) <= maxBytes ? lines : [];
}

// ─── The first note of a finding's thread ────────────────────────────────────

/** The most bytes of the first note of an AI review thread. */
export const AI_THREAD_MAX_BYTES = 8 * 1024;
/** What the note keeps of the finding's body, in characters: all a finding has, then less. */
const THREAD_BODY_CHARS = [ANSWER_LIMITS.bodyChars, 600, 300, 0] as const;
const THREAD_BODY_LINES = 20;

const THREAD_HEADING = '**AI review**';
/** The words of the AI review's three severities in the header. */
const THREAD_SEVERITY: Readonly<Record<AiSeverity, string>> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};
const CATEGORY_LABEL: Readonly<Record<AiCategory, string>> = {
  logic: 'Logic',
  'error-handling': 'Error handling',
  compatibility: 'Compatibility',
  concurrency: 'Concurrency',
  security: 'Security',
  performance: 'Performance',
  tests: 'Tests',
  docs: 'Documentation',
};
/** How sure the review is, in a word: a finding of medium confidence is a possible one. */
const CONFIDENCE_WORD = { high: 'likely', medium: 'possible' } as const;
const ASSUMES = 'Assumes:';
/** What the independent verification of a security finding said, when it could not decide. */
const NEEDS_VALIDATION =
  'Needs validation: an independent check could not tell from the repository whether this holds.';

/** What the first note of a finding's thread is made of. */
export interface AiThreadInput {
  provider: Provider;
  issueId: string;
  /** The issue's severity: blocker and high read as high, low and info as low. */
  severity: string;
  category: AiCategory;
  confidence: 'high' | 'medium';
  ruleKey: string;
  title: string;
  body: string;
  assumption: string | null;
  verification: 'confirmed' | 'needs_validation' | null;
  /**
   * The one-click replacement of the head lines `startLine` to `endLine`, when it still applies to
   * the provider's diff (the caller checks that): on GitLab the thread sits on `startLine`.
   */
  suggestion: { startLine: number; endLine: number; lines: string[] } | null;
  /** Qualor's own link to the issue, or null. */
  issueUrl: string | null;
}

/**
 * The suggestion block, GitLab's `suggestion:-0+N` (the line the thread is on and the N below it) or
 * GitHub's, or null when the suggestion is none a person should be offered: a range that is no
 * range or is over the bounds, or a line that could end the block, start a quick action, hide or
 * reorder characters, or hold a secret. The storing of the finding refused all of them already; a
 * row written otherwise is refused here too, and the finding keeps its thread without it.
 */
function suggestionBlock(input: AiThreadInput): string[] | null {
  const s = input.suggestion;
  if (s === null) return null;
  const { startLine, endLine, lines } = s;
  if (!Number.isSafeInteger(startLine) || !Number.isSafeInteger(endLine)) return null;
  if (startLine < 1 || endLine < startLine) return null;
  if (endLine - startLine + 1 > ANSWER_LIMITS.suggestionReplacedLines) return null;
  if (lines.length > ANSWER_LIMITS.suggestionLines) return null;
  if (lines.some((line) => suggestionLineProblem(line) !== null)) return null;
  if (redactText(lines.join('\n')).count > 0) return null;
  const fence =
    input.provider === 'gitlab' ? `\`\`\`suggestion:-0+${endLine - startLine}` : '```suggestion';
  return [fence, ...lines, '```'];
}

/** The first note of an AI finding's thread, and the suggestion its block offers. */
export interface AiThreadNote {
  body: string;
  /**
   * The input's suggestion when the note holds its block; null when it has none: there was none,
   * or the note left it out, as one not safe to post or one that would make the note too long. A
   * low finding is posted for its suggestion only, so one whose note has none is not posted.
   */
  suggestion: AiThreadInput['suggestion'];
}

/**
 * The first note of an AI finding's thread, on GitLab or GitHub: the issue marker (the thread is
 * reconciled through it as an analyzer's is), the fixed header (severity, category, how sure the
 * review is, and the rule's key in a code span), the title in bold and the body, what the finding
 * assumes and whether it needs validation, its one-click suggestion, and Qualor's link. Every word
 * of the model is written through `safeProse`. At most AI_THREAD_MAX_BYTES: the suggestion is left
 * out first, then the body is shortened. Says whether it kept the suggestion.
 */
export function aiThreadNote(input: AiThreadInput): AiThreadNote {
  const severity = aiSeverityOf(input.severity);
  const category = Object.hasOwn(CATEGORY_LABEL, input.category)
    ? CATEGORY_LABEL[input.category]
    : undefined;
  const header = [
    THREAD_HEADING,
    severity === null ? 'Unknown' : THREAD_SEVERITY[severity],
    category ?? 'Unknown',
    input.confidence === 'high' ? CONFIDENCE_WORD.high : CONFIDENCE_WORD.medium,
    codeSpan(input.ruleKey),
  ].join(SEPARATOR);
  const title = inlineProse(input.title, ANSWER_LIMITS.titleChars);
  const assumption =
    input.assumption === null ? '' : inlineProse(input.assumption, ANSWER_LIMITS.assumptionChars);
  const head = [issueMarker(input.issueId), header, ...(title === '' ? [] : ['', `**${title}**`])];
  const notes = [
    ...(assumption === '' ? [] : ['', `${ASSUMES} ${assumption}`]),
    ...(input.verification === 'needs_validation' ? ['', NEEDS_VALIDATION] : []),
  ];
  const link = qualorLink('View in Qualor', input.issueUrl);
  const tail = link === null ? [] : ['', link];
  const note = (suggestion: readonly string[] | null, bodyChars: number): string => {
    const body =
      bodyChars === 0
        ? ''
        : safeProse(input.body, { maxChars: bodyChars, maxLines: THREAD_BODY_LINES });
    return [
      ...head,
      ...(body === '' ? [] : ['', body]),
      ...notes,
      ...(suggestion === null ? [] : ['', ...suggestion]),
      ...tail,
    ].join('\n');
  };
  const block = suggestionBlock(input);
  if (block !== null) {
    const whole = note(block, THREAD_BODY_CHARS[0]);
    if (Buffer.byteLength(whole, 'utf8') <= AI_THREAD_MAX_BYTES) {
      return { body: whole, suggestion: input.suggestion };
    }
  }
  for (const chars of THREAD_BODY_CHARS) {
    const shorter = note(null, chars);
    if (Buffer.byteLength(shorter, 'utf8') <= AI_THREAD_MAX_BYTES) {
      return { body: shorter, suggestion: null };
    }
  }
  // Only a link longer than the bound gets here: the note is cut at whole lines.
  return {
    body: linesWithinBytes([...head, ...notes, ...tail], AI_THREAD_MAX_BYTES),
    suggestion: null,
  };
}

/** The text of the first note of an AI finding's thread (`aiThreadNote`). */
export function aiThreadBody(input: AiThreadInput): string {
  return aiThreadNote(input).body;
}

// ─── The answer to a reply ───────────────────────────────────────────────────

/** The most bytes of Qualor's answer to a reply in one of its threads. */
export const REPLY_NOTE_MAX_BYTES = 4 * 1024;
const REPLY_HEADING = '**AI review** · reply';
/** What the note keeps of the model's answer, in characters: all an answer has, then less. */
const REPLY_ANSWER_CHARS = [ANSWER_LIMITS.replyChars, 600, 300] as const;
const REPLY_ANSWER_LINES = 20;
/** The line that says what became of the finding, when the reply changed its status. */
const STATUS_CHANGED: Readonly<Record<'wont_fix' | 'false_positive', string>> = {
  wont_fix: "Marked won't fix.",
  false_positive: 'Marked as a false positive: the code shows it does not hold.',
};

/**
 * Qualor's answer to a reply in one of its threads (6I-4), on GitLab or GitHub: the reply marker
 * of the ledger row it answers (`rowId`), which the job looks for before it posts again; the fixed
 * heading; the model's answer through `safeProse`; and, when the reply changed the finding's status
 * (`statusChange`), a fixed line that says so. At most REPLY_NOTE_MAX_BYTES: the fixed lines always
 * stay, and the answer has the room they leave, its whole lines as far as they fit, from a shorter
 * cut of it when not even its first line does.
 */
export function replyNote(
  rowId: string,
  answer: string,
  statusChange: 'wont_fix' | 'false_positive' | null,
): string {
  const head = [replyMarker(rowId), REPLY_HEADING];
  const tail = statusChange === null ? [] : ['', STATUS_CHANGED[statusChange]];
  // The answer comes after a blank line: two bytes more besides its own.
  const room = REPLY_NOTE_MAX_BYTES - bytesOf([...head, ...tail]) - 2;
  for (const maxChars of REPLY_ANSWER_CHARS) {
    const prose = safeProse(answer, { maxChars, maxLines: REPLY_ANSWER_LINES });
    if (prose === '') break;
    const shown = linesWithinBytes(prose.split('\n'), room);
    if (shown !== '') return [...head, '', shown, ...tail].join('\n');
  }
  return [...head, ...tail].join('\n');
}

/**
 * Qualor's answer to a command (6I-4), on GitLab or GitHub: the reply marker of the ledger row it
 * answers (`rowId`), which the job looks for before it posts again, the fixed heading of an
 * answer, and `text`. The text is fixed (commands.ts: a sentence of Qualor's, a commit in a code
 * span): no word of a person or of the model, so it does not go through `safeProse`.
 */
export function commandNote(rowId: string, text: string): string {
  return [replyMarker(rowId), REPLY_HEADING, '', text].join('\n');
}
