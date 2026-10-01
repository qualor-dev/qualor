import { createHash } from 'node:crypto';
import {
  QUALITIES,
  resolveMetricKey,
  type GateResult,
  type Quality,
  type Severity,
} from '@qualor/shared';
import type { CommitState } from './gitlab/client';
import {
  codeSpan,
  issueMarker,
  linesWithinBytes,
  MAX_MESSAGE_CHARS,
  MAX_PATH_CHARS,
  MAX_VALUE_CHARS,
  plainValue,
  qualorLink,
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
  path: string | null;
  line: number | null;
  message: string;
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
     */
    skipped: 'stale' | 'merged_result' | 'checkout_other' | null;
  };
  /** The branch in Qualor, or null without `QUALOR_PUBLIC_URL`. */
  branchUrl: string | null;
  /** The merge request's head when it is no longer the analysed revision. */
  mergeRequestHead: string | null;
  /** Whose words the summary uses (github.md §6.2); GitLab's when absent. */
  vocabulary?: 'gitlab' | 'github';
  /**
   * The instance's small-changeset threshold (gates.md §6 rule 3), for the reason of a skipped
   * condition; without it the reason says "small change".
   */
  smallChangesetLines?: number | null;
}

/** The words that differ between GitLab and GitHub (github.md §6.2). */
const WORDS = {
  gitlab: {
    request: 'merge request',
    placed: 'commented inline',
    stale: 'Inline comments wait for the analysis of the merge request’s latest commit.',
  },
  github: {
    request: 'pull request',
    placed: 'annotated inline',
    stale: 'Inline annotations wait for the analysis of the pull request’s latest commit.',
  },
} as const;
/** github.md §6.2. Fixed text: the `${{ … }}` is an Actions expression, not a template. */
const CHECKOUT_OTHER =
  'No inline annotations: the workflow analysed a commit other than the pull request’s head (GitHub’s merge commit, by default); check out the head to get them (`ref: ${{ github.event.pull_request.head.sha }}`).';

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

function issueItem(issue: IssueLine, index: number): string[] {
  const icon = Object.hasOwn(SEVERITY_ICON, issue.severity)
    ? SEVERITY_ICON[issue.severity]
    : SKIPPED;
  const parts = [
    `${index + 1}. ${icon} **${severityLabel(issue.severity)}**`,
    qualityLabel(issue.quality),
    codeSpan(issue.ruleKey),
  ];
  const where =
    issue.path === null ? null : codeSpan(location(issue.path, issue.line), MAX_PATH_CHARS);
  // A link's text is a code span or fixed text, never a value.
  const link = qualorLink(where ?? 'details', issue.url);
  if (link !== null) parts.push(link);
  else if (where !== null) parts.push(where);
  // A trailing backslash is a CommonMark hard break: the message goes on its own line on GitLab
  // and in a GitHub check run, where a single line break renders as a space.
  return [`${parts.join(' · ')}\\`, `   ${codeSpan(issue.message, MAX_MESSAGE_CHARS)}`];
}

/** Why there are no inline comments, or how many there are; null when there is nothing to say. */
function inlineSentence(
  input: SummaryInput,
  words: (typeof WORDS)[keyof typeof WORDS],
): string | null {
  const inline = input.inline;
  const commented = count(inline.commented);
  const unplaced = count(inline.unplaced);
  if (inline.skipped === 'stale') return words.stale;
  if (inline.skipped === 'merged_result') {
    return 'No inline comments: this was a merged-results pipeline, whose line numbers are not the merge request’s.';
  }
  if (inline.skipped === 'checkout_other') return CHECKOUT_OTHER;
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
 * its line, then the note that the request moved on.
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
 * scm.md §5.2: the summary note. Only fixed text, catalog keys, numbers, Qualor's own links and
 * code spans; at most {@link SUMMARY_MAX_BYTES} (the issue list is shortened first, then whole
 * lines are dropped from the end).
 */
export function summaryBody(input: SummaryInput): string {
  const words = WORDS[input.vocabulary === 'github' ? 'github' : 'gitlab'];
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
  for (let listed = Math.min(input.topIssues.length, SUMMARY_TOP_ISSUES); listed >= 0; listed--) {
    const list = input.topIssues.slice(0, listed).flatMap(issueItem);
    const body = [
      ...head,
      ...(list.length > 0 ? ['', '#### Most severe new issues', '', ...list] : []),
      ...footer(input, words, listed),
    ].join('\n');
    if (Buffer.byteLength(body, 'utf8') <= SUMMARY_MAX_BYTES) return body;
  }
  return linesWithinBytes([...head, ...footer(input, words, 0)], SUMMARY_MAX_BYTES);
}

export interface InlineInput {
  issueId: string;
  severity: Severity;
  quality: Quality;
  ruleKey: string;
  message: string;
  url: string | null;
}

/** scm.md §5.4: the first note of an issue's discussion; at most {@link INLINE_MAX_BYTES}. */
export function inlineBody(input: InlineInput): string {
  const link = qualorLink('View in Qualor', input.url);
  return linesWithinBytes(
    [
      issueMarker(input.issueId),
      `**${severityLabel(input.severity)}** · ${qualityLabel(input.quality)} · ${codeSpan(input.ruleKey)}`,
      '',
      codeSpan(input.message, MAX_MESSAGE_CHARS),
      ...(link === null ? [] : ['', link]),
    ],
    INLINE_MAX_BYTES,
  );
}

/** A GitLab title as the branch keeps it (scm.md §8): no control characters, 255 at most. */
export function mergeRequestTitle(title: string): string {
  return plainValue(title, 255).trim();
}
