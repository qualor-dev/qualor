import type { Severity } from '@qualor/shared';
import { issueUrl } from '../scm/decoration-data';
import type { VulnerabilitySeverity } from '../vulnerabilities/order';
import { advisoryUrl, cutText, escapeIdentifier as e, noformat, wikiLink } from './markup';
import type { JiraMappingRow } from './mapping';

export const SUMMARY_MAX = 255;
export const DESCRIPTION_MAX = 30_000;
export const MESSAGE_MAX = 20_000;
export const FOUND_IN_MAX = 20;

export interface CodeIssueFacts {
  issueId: string;
  projectId: string;
  projectName: string;
  projectKey: string;
  branchName: string;
  path: string | null;
  line: number | null;
  ruleKey: string;
  ruleName: string;
  severity: Severity;
  quality: string;
  message: string;
  firstSeenAt: Date;
  closedAt: Date | null;
  lastSeenAt: Date | null;
}

export interface VulnerabilityFacts {
  projectId: string;
  projectName: string;
  packageName: string;
  vulnerabilityId: string;
  title: string | null;
  severity: VulnerabilitySeverity;
  installedVersions: string[];
  fixedVersion: string | null;
  primaryUrl: string | null;
  foundIn: string[];
  /** Left null without `vuln.priority`. */
  exploited: { dateAdded: string } | null;
  epss: { score: number; percentile: number } | null;
}

/**
 * What the fixed and found-again comments need. Built by the sync pass from the link row, the
 * project and the tracked targets, so it works when the pair or the issue is already gone.
 * `link` is the full Qualor URL, or null without `QUALOR_PUBLIC_URL`; `day` is `YYYY-MM-DD` (UTC).
 */
export type CommentFacts = { projectName: string; day: string; link: string | null } & (
  | { kind: 'code'; branchName: string; ruleKey: string }
  | { kind: 'vulnerability'; vulnerabilityId: string; packageName: string; foundIn: string[] }
);

export interface JiraContent {
  summary: string;
  description: string;
}

/** An advisory URL longer than this (encoded) is left out of the description. */
const ADVISORY_URL_MAX = 2_000;
const LINE_SPACE = /[\s\u0085]+/g;

const day = (d: Date): string => d.toISOString().slice(0, 10);

function qualorLine(url: string | null): string[] {
  return url === null ? [] : [wikiLink('Open in Qualor', url)];
}

function foundInText(names: string[]): string {
  const shown = names.slice(0, FOUND_IN_MAX).map((n) => e(n));
  const more = names.length - shown.length;
  return `${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
}

export function codeIssueContent(f: CodeIssueFacts, publicUrl: string | null): JiraContent {
  const place = f.path === null ? [] : [`File: ${e(f.path)}${f.line === null ? '' : `:${f.line}`}`];
  const build = (messageMax: number): string =>
    [
      `h3. ${e(f.ruleName)}`,
      noformat(cutText(f.message, messageMax)),
      `Project: ${e(f.projectName)} \\(${e(f.projectKey)}\\)`,
      `Branch: ${e(f.branchName)}`,
      ...place,
      `Rule: ${e(f.ruleKey)}, ${f.severity}, ${e(f.quality)}`,
      `First seen: ${day(f.firstSeenAt)}`,
      ...qualorLine(issueUrl(publicUrl, f.projectId, f.issueId)),
    ].join('\n');
  // The message is the only unbounded part: shrink it until the whole description fits.
  let messageMax = MESSAGE_MAX;
  let description = build(messageMax);
  while (description.length > DESCRIPTION_MAX && messageMax > 0) {
    messageMax = Math.max(0, messageMax - (description.length - DESCRIPTION_MAX) - 1);
    description = build(messageMax);
  }
  return { summary: cutText(f.message.replace(LINE_SPACE, ' ').trim(), SUMMARY_MAX), description };
}

export function vulnerabilityContent(f: VulnerabilityFacts, publicUrl: string | null): JiraContent {
  const heading =
    f.title === null ? e(f.vulnerabilityId) : `${e(f.vulnerabilityId)}: ${e(f.title)}`;
  const date = f.exploited && /^\d{4}-\d{2}-\d{2}$/.test(f.exploited.dateAdded);
  const encoded = advisoryUrl(f.primaryUrl);
  const url = encoded !== null && encoded.length <= ADVISORY_URL_MAX ? encoded : null;
  // Every part is capped, so this holds; the fallbacks only drop optional parts if it ever did not.
  const build = (withUrl: boolean, withInstalled: boolean): string =>
    [
      `h3. ${heading}`,
      `Package: ${e(f.packageName)}${withInstalled && f.installedVersions.length > 0 ? `, installed ${foundInText(f.installedVersions)}` : ''}`,
      f.fixedVersion === null ? 'Fixed in: no fixed version yet' : `Fixed in: ${e(f.fixedVersion)}`,
      `Severity: ${f.severity}`,
      ...(f.exploited
        ? [`Exploited: CISA KEV, added ${date ? f.exploited.dateAdded : e(f.exploited.dateAdded)}`]
        : []),
      ...(f.epss
        ? [
            `EPSS: ${(f.epss.score * 100).toFixed(1)}% (percentile ${Math.round(f.epss.percentile * 100)})`,
          ]
        : []),
      `Found in: ${foundInText(f.foundIn)}`,
      ...(withUrl && url !== null ? [`Advisory: ${wikiLink(f.vulnerabilityId, url)}`] : []),
      ...qualorLine(
        publicUrl === null
          ? null
          : `${publicUrl}/projects/${f.projectId}/vulnerabilities?view=vulnerability`,
      ),
    ].join('\n');
  const fits = (d: string): boolean => d.length <= DESCRIPTION_MAX;
  const description = [build(true, true), build(false, true), build(false, false)].find(fits);
  return {
    summary: cutText(
      `${f.vulnerabilityId} in ${f.packageName} (${f.severity})`.replace(LINE_SPACE, ' '),
      SUMMARY_MAX,
    ),
    description: description ?? build(false, false),
  };
}

function withLink(text: string, link: string | null): string {
  return link === null ? text : `${text}\n${wikiLink('Open in Qualor', link)}`;
}

export function fixedComment(f: CommentFacts): string {
  const text =
    f.kind === 'code'
      ? `Qualor no longer finds this issue on ${e(f.branchName)} (analysis of ${f.day}).`
      : `Qualor no longer finds ${e(f.vulnerabilityId)} in ${e(f.packageName)} on the tracked branches and versions of ${e(f.projectName)}.`;
  return withLink(text, f.link);
}

export function foundAgainComment(f: CommentFacts): string {
  const text =
    f.kind === 'code'
      ? `Qualor finds this again: ${e(f.ruleKey)} on ${e(f.branchName)} (analysis of ${f.day}).`
      : `Qualor finds this again: ${e(f.vulnerabilityId)} in ${e(f.packageName)} on ${foundInText(f.foundIn)}.`;
  return withLink(text, f.link);
}

export function reconciliationLabel(linkId: string, generation: number): string {
  return `qualor-${linkId.replaceAll('-', '')}-${generation}`;
}

const ISSUE_SEVERITY: Record<VulnerabilitySeverity, Severity> = {
  critical: 'blocker',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'medium',
};

export function issueSeverityOf(s: VulnerabilitySeverity): Severity {
  return ISSUE_SEVERITY[s];
}

/** The `fields` of a create call. */
export function issueFields(
  mapping: JiraMappingRow,
  content: JiraContent,
  severity: Severity,
  link: { id: string; generation: number },
): Record<string, unknown> {
  const priority = mapping.priorityAvailable ? mapping.priorities?.[severity] : undefined;
  return {
    project: { id: mapping.jiraProjectId },
    issuetype: { id: mapping.issueTypeId },
    summary: content.summary,
    description: content.description,
    ...(mapping.labelsAvailable
      ? { labels: ['qualor', ...mapping.labels, reconciliationLabel(link.id, link.generation)] }
      : {}),
    ...(priority === undefined ? {} : { priority: { id: priority } }),
  };
}
