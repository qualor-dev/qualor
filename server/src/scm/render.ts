import { createHash } from 'node:crypto';
import { QUALITIES, type GateResult, type Quality, type Severity } from '@qualor/shared';
import type { CommitState } from './gitlab/client';
import {
  codeSpan,
  issueMarker,
  linesWithinBytes,
  MAX_MESSAGE_CHARS,
  MAX_PATH_CHARS,
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

/** A count as fixed text: a non-negative integer, else 0. */
function count(n: number): number {
  return Number.isSafeInteger(n) && n > 0 ? n : 0;
}

function issueLine(issue: IssueLine): string {
  const where =
    issue.path === null
      ? ''
      : ` ${codeSpan(issue.line === null ? issue.path : `${issue.path}:${issue.line}`, MAX_PATH_CHARS)}`;
  const link = qualorLink('details', issue.url);
  return `- **${severityLabel(issue.severity)}**${where} ${codeSpan(issue.message, MAX_MESSAGE_CHARS)}${
    link === null ? '' : ` · ${link}`
  }`;
}

/**
 * scm.md §5.2: the summary note. Only fixed text, catalog keys, numbers, Qualor's own links and
 * code spans; at most {@link SUMMARY_MAX_BYTES} (the issue list is shortened first, then whole
 * lines are dropped from the end).
 */
export function summaryBody(input: SummaryInput): string {
  const words = WORDS[input.vocabulary === 'github' ? 'github' : 'gitlab'];
  const head = [
    summaryMarker(input.projectId),
    `### Qualor: ${HEADLINE[input.gate.status]}`,
    '',
    `Analysis of ${codeSpan(input.revision.slice(0, 12))}${
      input.gate.gate ? ` · quality gate ${codeSpan(input.gate.gate.name)}` : ''
    }`,
  ];
  const shown = input.gate.conditions.filter((c) => c.status !== 'passed');
  if (shown.length > 0) {
    head.push('', '| Condition | Value | Threshold | Status |', '|---|---|---|---|');
    for (const c of shown) {
      // A table cell is split at `|` before code spans are parsed, so a cell holds a catalog
      // key or fixed text, never a code span of a value.
      const metric = metricName(c.metric);
      head.push(
        `| ${metric === null ? 'unknown metric' : `\`${metric}\``} | ${formatValue(c.value)} | ${operator(c.operator)} ${formatThreshold(c.threshold)} | ${
          c.status === 'failed' ? 'failed' : 'no value'
        } |`,
      );
    }
  }
  const counts = SEVERITIES.flatMap((s) => {
    const n = input.newIssues.bySeverity[s];
    return typeof n === 'number' && count(n) > 0 ? [`${count(n)} ${s}`] : [];
  });
  const total = input.newIssues.total;
  head.push(
    '',
    total === null
      ? '**New issues:** not available (no new-code baseline)'
      : `**New issues:** ${count(total)}${counts.length > 0 ? ` (${counts.join(', ')})` : ''}`,
  );
  const tail: string[] = [];
  const inline = input.inline;
  const commented = count(inline.commented);
  const unplaced = count(inline.unplaced);
  if (inline.skipped === 'stale') {
    tail.push('', words.stale);
  } else if (inline.skipped === 'merged_result') {
    tail.push(
      '',
      'No inline comments: this was a merged-results pipeline, whose line numbers are not the merge request’s.',
    );
  } else if (inline.skipped === 'checkout_other') {
    tail.push('', CHECKOUT_OTHER);
  } else if (commented > 0 || unplaced > 0) {
    tail.push(
      '',
      `${commented} new ${commented === 1 ? 'issue is' : 'issues are'} ${words.placed}${
        unplaced > 0 ? `; ${unplaced} could not be placed on the diff` : ''
      }.`,
    );
  }
  const branchLink = qualorLink('View in Qualor', input.branchUrl);
  if (branchLink !== null) tail.push('', branchLink);
  // scm.md §5.2 item 7: not for a merged-results or merge-train pipeline, whose merge commit is
  // never the merge request's head.
  if (input.mergeRequestHead !== null && inline.skipped !== 'merged_result') {
    tail.push(
      '',
      `This analysis is of ${codeSpan(input.revision.slice(0, 12))}; the ${words.request} is now at ${codeSpan(input.mergeRequestHead.slice(0, 12))}.`,
    );
  }
  const totalIssues = count(input.topIssuesTotal);
  for (let listed = Math.min(input.topIssues.length, SUMMARY_TOP_ISSUES); listed >= 0; listed--) {
    const list = input.topIssues.slice(0, listed).map(issueLine);
    const more = totalIssues - listed;
    const body = [
      ...head,
      ...(list.length > 0 ? ['', ...list] : []),
      ...(more > 0 && listed > 0 ? [`- … and ${more} more`] : []),
      ...tail,
    ].join('\n');
    if (Buffer.byteLength(body, 'utf8') <= SUMMARY_MAX_BYTES) return body;
  }
  return linesWithinBytes([...head, ...tail], SUMMARY_MAX_BYTES);
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
