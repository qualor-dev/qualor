import { createHash } from 'node:crypto';
import {
  QUALITIES,
  type ScmProvider,
  resolveMetricKey,
  type GateResult,
  type Quality,
  type Severity,
} from '@qualor/shared';
import {
  AI_SECTION_MAX_BYTES,
  aiSummarySection,
  inlineProse,
  type ReviewSummaryState,
} from '../review/render';
import type { CommitState } from './gitlab/client';
import {
  codeSpan,
  fixedMarker,
  issueMarker,
  linesWithinBytes,
  MAX_MESSAGE_CHARS,
  MAX_PATH_CHARS,
  MAX_VALUE_CHARS,
  plainValue,
  qualorLink,
  ruleKeyMarkdown,
  summaryMarker,
} from './markdown';

/** GitLab's bound on a commit status name (`ci_builds.name`). */
export const STATUS_NAME_MAX_CHARS = 255;
/** The characters of a project key (`PROJECT_KEY_PATTERN`); anything else becomes `-`. */
const STATUS_NAME_UNSAFE = /[^A-Za-z0-9._/:-]/g;

/**
 * scm.md §5.1 (ruling G4): the commit status's name, `qualor/<project key>`, so the Qualor projects
 * of a monorepo (one GitLab project) each keep their own status on a commit instead of replacing
 * one another's. At most {@link STATUS_NAME_MAX_CHARS}: a longer name is cut and ends with `~` and
 * 12 hex characters of the key's SHA-256, so two long keys never share a name.
 */
export function statusName(projectKey: string): string {
  const name = `qualor/${projectKey.replace(STATUS_NAME_UNSAFE, '-')}`;
  if (name.length <= STATUS_NAME_MAX_CHARS) return name;
  const hash = createHash('sha256').update(projectKey, 'utf8').digest('hex').slice(0, 12);
  return `${name.slice(0, STATUS_NAME_MAX_CHARS - hash.length - 1)}~${hash}`;
}
/** scm.md §6 bounds. */
export const SUMMARY_MAX_BYTES = 16 * 1024;
export const INLINE_MAX_BYTES = 4 * 1024;
export const STATUS_DESCRIPTION_MAX_CHARS = 255;
/** scm.md §5.2: at most this many issues are listed in the summary. */
export const SUMMARY_TOP_ISSUES = 10;

const SEVERITY_LABEL: Record<Severity, string> = {
  blocker: 'Blocker',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};
const SEVERITIES: readonly Severity[] = ['blocker', 'high', 'medium', 'low', 'info'];

const HEADLINE: Record<GateResult['status'], string> = {
  passed: 'quality gate passed',
  failed: 'quality gate failed',
  error: 'the quality gate could not be evaluated',
  none: 'no quality gate',
};

/**
 * Catalog text only: a severity, quality or metric that is not a known, plain key (a value read
 * back from storage that no longer matches the types) is shown as fixed text instead.
 */
export function severityLabel(severity: Severity): string {
  return Object.hasOwn(SEVERITY_LABEL, severity) ? SEVERITY_LABEL[severity] : 'Unknown';
}

export function qualityLabel(quality: Quality): string {
  return (QUALITIES as readonly string[]).includes(quality) ? quality : 'unknown';
}

/**
 * "Possible" for a medium-confidence finding of the C# taint engine (6B-C# engine spec R-9), as the
 * issue screens show it: fixed text, after the quality; nothing for any other finding.
 */
export function possibleLabel(confidence: 'high' | 'medium' | null | undefined): string[] {
  return confidence === 'medium' ? ['Possible'] : [];
}

/** A metric key as the catalog writes them; anything else could break a table cell. */
const METRIC_KEY = /^[a-z][a-z0-9_]{0,99}$/;

function metricName(metric: string): string | null {
  return METRIC_KEY.test(metric) ? metric : null;
}

/** A measure as the comments show it: integers as they are, others with one decimal. */
export function formatValue(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return 'no value';
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatThreshold(value: number): string {
  return Number.isFinite(value) ? String(value) : 'no value';
}

function operator(op: 'gt' | 'lt'): string {
  return op === 'gt' ? '>' : '<';
}

/** scm.md §5.1: the commit status of a gate verdict. The description holds catalog text only. */
export function commitStatusFor(gate: GateResult): { state: CommitState; description: string } {
  switch (gate.status) {
    case 'passed':
      return { state: 'success', description: 'Quality gate passed' };
    case 'none':
      return { state: 'success', description: 'No quality gate' };
    case 'error':
      return {
        state: 'failed',
        description: 'Quality gate could not be evaluated (new code unavailable)',
      };
    case 'failed': {
      const failed = gate.conditions
        .filter((c) => c.status === 'failed')
        .map(
          (c) =>
            `${metricName(c.metric) ?? 'unknown metric'} ${formatValue(c.value)} ${operator(c.operator)} ${formatThreshold(c.threshold)}`,
        );
      const text = `Quality gate failed: ${failed.join(', ')}`;
      return {
        state: 'failed',
        description:
          text.length <= STATUS_DESCRIPTION_MAX_CHARS
            ? text
            : `${text.slice(0, STATUS_DESCRIPTION_MAX_CHARS - 1)}…`,
      };
    }
    default:
      // A status this code does not know (a stored result of a newer version, say) fails closed:
      // a merge request is never shown as passing on a gate Qualor could not read.
      return { state: 'failed', description: 'Quality gate status unknown' };
  }
}

export interface IssueLine {
  id: string;
  severity: Severity;
  quality: Quality;
  /** The rule's key (`sonarjs:S3776`), shown in a code span. */
  ruleKey: string;
  /** The rule's documentation link: the key links to it when it is a safe https URL. */
  helpUri?: string | null;
  path: string | null;
  line: number | null;
  message: string;
  /** The C# taint engine's confidence (6B-C# engine spec R-9): `medium` is shown as "Possible". */
  confidence?: 'high' | 'medium' | null;
  /** The issue in Qualor, or null without `QUALOR_PUBLIC_URL`. */
  url: string | null;
}

export interface SummaryInput {
  projectId: string;
  revision: string;
  gate: GateResult;
  /** `new_issues` and `new_<severity>_issues` of the analysis (null without a baseline). */
  newIssues: { total: number | null; bySeverity: Partial<Record<Severity, number | null>> };
  /** The most severe open new issues, at most {@link SUMMARY_TOP_ISSUES}. */
  topIssues: readonly IssueLine[];
  /** Open new issues in all (the list may show fewer). */
  topIssuesTotal: number;
  inline: {
    /** Issues with a Qualor discussion on the diff (open ones). */
    commented: number;
    /** Desired issues GitLab's diff has no place for. */
    unplaced: number;
    /**
     * Why no discussion was created or changed this time, if so. `checkout_other` (GitHub only):
     * the workflow analysed a commit other than the pull request's head (github.md §6.2).
     * `failed` (GitHub only): reading or changing the threads failed, so the counts are unknown.
     */
    skipped: 'stale' | 'merged_result' | 'checkout_other' | 'failed' | null;
    /**
     * GitHub only: Qualor's conversations that were to be resolved or reopened, and stay as they
     * are because the App may not (it lacks Contents: Read and write). None when absent.
     */
    unresolved?: number;
  };
  /** The branch in Qualor, or null without `QUALOR_PUBLIC_URL`. */
  branchUrl: string | null;
  /** The merge request's head when it is no longer the analysed revision. */
  mergeRequestHead: string | null;
  /** Whose words the summary uses (github.md §6.2); GitLab's when absent. */
  vocabulary?: ScmProvider;
  /**
   * The instance's small-changeset threshold (gates.md §6 rule 3), for the reason of a skipped
   * condition; without it the reason says "small change".
   */
  smallChangesetLines?: number | null;
  /**
   * How the AI review of this analysis stands, or null/absent when it has none: the summary
   * ends with its section. It has up to {@link AI_SECTION_MAX_BYTES} of the note; the analyzers'
   * issue list gives way for it.
   */
  review?: ReviewSummaryState | null;
}

/** The words that differ between the providers (github.md §6.2). */
interface Words {
  request: string;
  placed: string;
  stale: string;
}
const WORDS: Record<ScmProvider, Words> = {
  gitlab: {
    request: 'merge request',
    placed: 'commented inline',
    stale: 'Inline comments wait for the analysis of the merge request’s latest commit.',
  },
  github: {
    request: 'pull request',
    placed: 'commented inline',
    stale: 'Inline comments wait for the analysis of the pull request’s latest commit.',
  },
  azure: {
    // azure-pending(4): the words of an Azure DevOps pull request's summary
    request: 'pull request',
    placed: 'commented inline',
    stale: 'Inline comments wait for the analysis of the pull request’s latest commit.',
  },
};
/**
 * github.md §6.2. Fixed text: the `${{ … }}` is an Actions expression, not a template. It speaks of
 * the analyzers' issues only: the AI review's threads are posted after such a checkout too.
 */
const CHECKOUT_OTHER =
  'The analyzers’ issues are not commented inline: the workflow analysed a commit other than the pull request’s head (GitHub’s merge commit, by default); check out the head to get them (`ref: ${{ github.event.pull_request.head.sha }}`).';
/** github.md §6.2: the threads could not be read or changed; the next decoration tries again. */
const NOT_UPDATED = 'Inline comments could not be updated this time.';

/**
 * GitHub: how many of Qualor's conversations stay as they are because the App may not resolve or
 * reopen them, and what to give it; null when there is none.
 */
function unresolvedSentence(input: SummaryInput): string | null {
  const n = count(input.inline.unresolved ?? 0);
  if (n === 0) return null;
  return `${n} ${plural(n, 'conversation', 'conversations')} could not be resolved or reopened: give the GitHub App Contents: Read and write.`;
}

/** The headline's marker of a gate status; one this code does not know is a warning. */
const STATUS_ICON: Record<GateResult['status'], string> = {
  passed: '✅',
  failed: '❌',
  error: '⚠️',
  none: '➖',
};
const SEVERITY_ICON: Record<Severity, string> = {
  blocker: '⛔',
  high: '🔴',
  medium: '🟠',
  low: '🟡',
  info: '🔵',
};
/** A condition's marker in the table: passed, failed, or no value (and anything else). */
const CONDITION_ICON: Record<string, string> = { passed: '✅', failed: '❌' };
const SKIPPED = '➖';
/** Catalog names that read better in a table next to their value. */
const METRIC_NAME_OVERRIDE: Readonly<Record<string, string>> = {
  duplicated_lines_density: 'Duplication',
};

/** A count as fixed text: a non-negative integer, else 0. */
function count(n: number): number {
  return Number.isSafeInteger(n) && n > 0 ? n : 0;
}

/**
 * A metric as the summary's table names it: the catalog's name (`Coverage on new code`, `New
 * issues`), a catalog-shaped key the catalog does not know in a code span (safe: the key pattern
 * holds no backtick or `|`), else fixed text.
 */
function metricLabel(metric: string): string {
  const resolved = resolveMetricKey(metric);
  if (resolved === undefined) {
    const key = metricName(metric);
    return key === null ? 'unknown metric' : `\`${key}\``;
  }
  const { definition, scope } = resolved;
  const name = Object.hasOwn(METRIC_NAME_OVERRIDE, definition.key)
    ? (METRIC_NAME_OVERRIDE[definition.key] ?? definition.name)
    : definition.name;
  if (scope === 'overall') return name;
  if (definition.domain === 'issues') {
    return `New ${name.charAt(0).toLowerCase()}${name.slice(1)}`;
  }
  return `${name} on new code`;
}

/** A condition's value in the table: a percentage with one decimal and `%`, else as measured. */
function cellValue(metric: string, value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '—';
  return resolveMetricKey(metric)?.definition.type === 'percent'
    ? `${value.toFixed(1)}%`
    : formatValue(value);
}

/** The sign of the passing side: a gate fails `gt t` above t, so it requires `≤ t`. */
function requiredSign(operator: string): string | null {
  if (operator === 'gt') return '≤';
  if (operator === 'lt') return '≥';
  return null;
}

/** The passing side of a condition: a gate fails `gt t` above t, so it requires `≤ t`. */
function required(c: { operator: string; threshold: number }): string {
  const sign = requiredSign(c.operator);
  return sign === null ? 'unknown' : `${sign} ${formatThreshold(c.threshold)}`;
}

function skipReason(reason: string, smallChangesetLines: number | null | undefined): string {
  if (reason === 'overall_on_branch') return 'skipped: overall condition on a branch';
  if (reason === 'small_changeset') {
    return typeof smallChangesetLines === 'number' &&
      Number.isSafeInteger(smallChangesetLines) &&
      smallChangesetLines > 0
      ? `skipped: fewer than ${smallChangesetLines} new lines`
      : 'skipped: small change';
  }
  return 'skipped';
}

/**
 * The table of the gate's conditions (passed ones too), then the ones the gate skipped. A table
 * cell is split at `|` before code spans are parsed, so a cell holds catalog text, a number or
 * fixed text, never a code span of a value.
 */
function conditionTable(input: SummaryInput): string[] {
  const rows = input.gate.conditions.map(
    (c) =>
      `| ${Object.hasOwn(CONDITION_ICON, c.status) ? CONDITION_ICON[c.status] : SKIPPED} | ${metricLabel(c.metric)} | ${cellValue(c.metric, c.value)} | ${required(c)} |`,
  );
  const ignored = Array.isArray(input.gate.ignoredConditions) ? input.gate.ignoredConditions : [];
  for (const c of ignored) {
    rows.push(
      `| ${SKIPPED} | ${metricLabel(c.metric)} | — | ${skipReason(c.reason, input.smallChangesetLines)} |`,
    );
  }
  return rows.length === 0
    ? []
    : ['', '| | Condition | Value | Required |', '|---|---|---|---|', ...rows];
}

/**
 * A gate name in bold when it is plain words (letters and digits, single spaces, no word a
 * provider could turn into a commit link), else in a code span: a name is entered by a user.
 */
const PLAIN_NAME = /^[\p{L}\p{N}]+(?: [\p{L}\p{N}]+)*$/u;
const COMMIT_LIKE = /^[0-9a-f]{7,40}$/i;

function gateName(name: string): string {
  const plain = plainValue(name, MAX_VALUE_CHARS);
  const safe =
    plain === name &&
    PLAIN_NAME.test(plain) &&
    !plain.split(' ').some((word) => COMMIT_LIKE.test(word));
  return safe ? `**${plain}**` : codeSpan(name);
}

/** The line under the headline: the gate, the analysed commit and the count of new issues. */
function contextLine(input: SummaryInput, request: string): string {
  const parts: string[] = [];
  if (input.gate.gate) parts.push(gateName(input.gate.gate.name));
  parts.push(`analysis ${codeSpan(input.revision.slice(0, 12))}`);
  const total = input.newIssues.total;
  if (total !== null) {
    const n = count(total);
    const issues = n === 0 ? 'no new issues' : `${n} new ${plural(n, 'issue', 'issues')}`;
    parts.push(`**${issues}** in this ${request}`);
  }
  return parts.join(' · ');
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

function location(path: string, line: number | null): string {
  return line === null ? path : `${path}:${line}`;
}

/**
 * An analyzer's message as one line of prose. Its lines are joined by a space first, so that what
 * a line after the first says (gosec's `Severity: …`, or advice) is kept.
 */
function messageProse(message: string): string {
  const lines = message.split(/[\r\n]+/).map((line) => line.trim());
  return inlineProse(lines.filter((line) => line !== '').join(' '), MAX_MESSAGE_CHARS);
}

function issueItem(issue: IssueLine, index: number): string[] {
  const icon = Object.hasOwn(SEVERITY_ICON, issue.severity)
    ? SEVERITY_ICON[issue.severity]
    : SKIPPED;
  const parts = [
    `${index + 1}. ${icon} **${severityLabel(issue.severity)}**`,
    qualityLabel(issue.quality),
    ...possibleLabel(issue.confidence),
    ruleKeyMarkdown(issue.ruleKey, issue.helpUri),
  ];
  const where =
    issue.path === null ? null : codeSpan(location(issue.path, issue.line), MAX_PATH_CHARS);
  // A link's text is a code span or fixed text, never a value.
  const link = qualorLink(where ?? 'details', issue.url);
  if (link !== null) parts.push(link);
  else if (where !== null) parts.push(where);
  // A trailing backslash is a CommonMark hard break: the message goes on its own line on GitLab
  // and in a GitHub check run, where a single line break renders as a space.
  return [`${parts.join(' · ')}\\`, `   ${messageProse(issue.message)}`];
}

/**
 * Why the analyzers' issues have no inline comments, or how many have; null when there is nothing
 * to say.
 */
function inlineSentence(
  input: SummaryInput,
  words: (typeof WORDS)[keyof typeof WORDS],
): string | null {
  const inline = input.inline;
  const commented = count(inline.commented);
  const unplaced = count(inline.unplaced);
  if (inline.skipped === 'stale') return words.stale;
  // The AI review's threads follow the head it read, and are posted after these two too (a
  // merged-results pipeline, a checkout of GitHub's merge commit): the sentences speak for the
  // analyzers' issues only.
  if (inline.skipped === 'merged_result') {
    return 'The analyzers’ issues are not commented inline: this was a merged-results pipeline, whose line numbers are not the merge request’s.';
  }
  if (inline.skipped === 'checkout_other') return CHECKOUT_OTHER;
  if (inline.skipped === 'failed') return NOT_UPDATED;
  if (commented > 0 || unplaced > 0) {
    return `${commented} new ${commented === 1 ? 'issue is' : 'issues are'} ${words.placed}${
      unplaced > 0 ? `; ${unplaced} could not be placed on the diff` : ''
    }.`;
  }
  return null;
}

/**
 * The end of the summary: how many issues the list leaves out (and that all of them are inline,
 * when so), why there are no inline comments or how many there are, the link to Qualor last on
 * its line, how many conversations the GitHub App may not resolve or reopen, then the note that
 * the request moved on.
 */
function footer(
  input: SummaryInput,
  words: (typeof WORDS)[keyof typeof WORDS],
  listed: number,
): string[] {
  const inline = input.inline;
  const totalIssues = count(input.topIssuesTotal);
  const more = listed > 0 ? totalIssues - listed : 0;
  const allInline =
    inline.skipped === null &&
    count(inline.unplaced) === 0 &&
    count(inline.commented) >= totalIssues;
  const lines: string[] = [];
  let sentence = inlineSentence(input, words);
  if (more > 0) {
    if (allInline && sentence !== null) {
      lines.push(`…and ${more} more, all ${words.placed}`);
      sentence = null;
    } else {
      lines.push(`…and ${more} more`);
    }
  }
  if (sentence !== null) lines.push(sentence);
  const link = qualorLink('Open in Qualor →', input.branchUrl);
  if (link !== null) {
    const last = lines.pop();
    lines.push(last === undefined ? `**${link}**` : `${last} · **${link}**`);
  }
  const unresolved = unresolvedSentence(input);
  if (unresolved !== null) lines.push(unresolved);
  // scm.md §5.2 item 7: not for a merged-results or merge-train pipeline, whose merge commit is
  // never the merge request's head.
  if (input.mergeRequestHead !== null && inline.skipped !== 'merged_result') {
    lines.push(
      `This analysis is of ${codeSpan(input.revision.slice(0, 12))}; the ${words.request} is now at ${codeSpan(input.mergeRequestHead.slice(0, 12))}.`,
    );
  }
  return lines.flatMap((line) => ['', line]);
}

/**
 * scm.md §5.2: the summary note. Only fixed text, catalog keys, numbers, Qualor's own links, rules'
 * documentation links, code spans and, in the AI review section, the model's words made inert by
 * `safeProse`; at most {@link SUMMARY_MAX_BYTES}. The section comes last, within what the note
 * has left once its head and footer are in; the issue list is shortened first, then the section
 * gives way part by part (review/render.ts), and only a head too large for the note is cut at
 * whole lines from the end.
 */
export function summaryBody(input: SummaryInput): string {
  const vocabulary = input.vocabulary ?? 'gitlab';
  const words = WORDS[vocabulary];
  const status = input.gate.status;
  const known = Object.hasOwn(HEADLINE, status);
  const head = [
    summaryMarker(input.projectId),
    `### ${known ? STATUS_ICON[status] : '⚠️'} Qualor: ${known ? HEADLINE[status] : 'quality gate status unknown'}`,
    '',
    contextLine(input, words.request),
    ...conditionTable(input),
  ];
  const counts = SEVERITIES.flatMap((s) => {
    const n = input.newIssues.bySeverity[s];
    return typeof n === 'number' && count(n) > 0 ? [`${SEVERITY_ICON[s]} ${count(n)} ${s}`] : [];
  });
  if (input.newIssues.total === null) {
    head.push('', '**New issues:** not available (no new-code baseline)');
  } else if (counts.length > 0) {
    head.push('', `**By severity:** ${counts.join(' · ')}`);
  }
  // The AI section takes the room the head and the footer without any issue leave, up to its own
  // bound, and the issue list the rest: the section is whole whenever it can be.
  const bare = [...head, ...footer(input, words, 0)];
  const room = SUMMARY_MAX_BYTES - Buffer.byteLength(bare.join('\n'), 'utf8') - 2; // the blank line
  const review = input.review ?? null;
  const section =
    review === null
      ? []
      : aiSummarySection(review, vocabulary, Math.min(AI_SECTION_MAX_BYTES, room));
  const tail = section.length === 0 ? [] : ['', ...section];
  for (let listed = Math.min(input.topIssues.length, SUMMARY_TOP_ISSUES); listed >= 0; listed--) {
    const list = input.topIssues.slice(0, listed).flatMap(issueItem);
    const body = [
      ...head,
      ...(list.length > 0 ? ['', '#### Most severe new issues', '', ...list] : []),
      ...footer(input, words, listed),
      ...tail,
    ].join('\n');
    if (Buffer.byteLength(body, 'utf8') <= SUMMARY_MAX_BYTES) return body;
  }
  return linesWithinBytes(bare, SUMMARY_MAX_BYTES);
}

export interface InlineInput {
  issueId: string;
  severity: Severity;
  quality: Quality;
  ruleKey: string;
  /** The rule's documentation link: the key links to it when it is a safe https URL. */
  helpUri?: string | null;
  message: string;
  /** The C# taint engine's confidence (R-9): `medium` is shown as "Possible". */
  confidence?: 'high' | 'medium' | null;
  url: string | null;
}

/** scm.md §5.4: the first note of an issue's discussion; at most {@link INLINE_MAX_BYTES}. */
export function inlineBody(input: InlineInput): string {
  const link = qualorLink('View in Qualor', input.url);
  return linesWithinBytes(
    [
      issueMarker(input.issueId),
      [
        `**${severityLabel(input.severity)}**`,
        qualityLabel(input.quality),
        ...possibleLabel(input.confidence),
        ruleKeyMarkdown(input.ruleKey, input.helpUri),
      ].join(' · '),
      '',
      messageProse(input.message),
      ...(link === null ? [] : ['', link]),
    ],
    INLINE_MAX_BYTES,
  );
}

/**
 * Qualor's note in the open thread of an issue that was found fixed at `sha` while a person's reply
 * keeps the thread open for them (6I-4), on GitLab or GitHub: its marker, then a sentence of fixed
 * text with the commit in a code span.
 */
export function fixedNote(issueId: string, sha: string): string {
  return [
    fixedMarker(issueId, sha),
    `Fixed in ${codeSpan(sha.slice(0, 7))}. Qualor leaves this thread open because someone replied in it.`,
  ].join('\n');
}

/** A GitLab title as the branch keeps it (scm.md §8): no control characters, 255 at most. */
export function mergeRequestTitle(title: string): string {
  return plainValue(title, 255).trim();
}
