import { issueUrl } from '../scm/decoration-data';
import type { AzureJsonPatch } from '../scm/azure/client';
import { advisoryUrl, cutText } from '../jira/markup';
import {
  DESCRIPTION_MAX,
  FOUND_IN_MAX,
  MESSAGE_MAX,
  SUMMARY_MAX,
  vulnerabilitiesUrl,
  type CodeIssueFacts,
  type CommentFacts,
  type VulnerabilityFacts,
} from '../jira/content';
import { DESCRIPTION_FIELD, REPRO_STEPS_FIELD, workItemTags } from './mapping';

/**
 * The contents of the Azure Boards work items, in HTML (design §7.8). Escaping `& < > " '` alone
 * keeps every form inert in Description, Repro Steps and History (probe, Part B h); free text goes
 * into `<pre>`, identifiers into `<code>`. The facts and the caps are the Jira ones.
 */
export interface WorkItemContent {
  title: string;
  descriptionHtml: string;
  /** The Qualor URL (a Hyperlink relation), or null without `QUALOR_PUBLIC_URL`. */
  link: string | null;
}

const LINE_SPACE = /[\s\u0085]+/g;
/** An advisory URL longer than this (encoded) is left out of the description. */
const ADVISORY_URL_MAX = 2_000;

export function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/** A short identifier, as Jira cuts it: at most 255 characters. */
const IDENTIFIER_MAX = 255;
const short = (text: string): string => escapeHtml(cutText(text, IDENTIFIER_MAX));
const code = (text: string): string => `<code>${short(text)}</code>`;
const pre = (text: string): string => `<pre>${escapeHtml(text)}</pre>`;
const para = (html: string): string => `<p>${html}</p>`;
const anchor = (text: string, url: string): string =>
  `<a href="${escapeHtml(url)}">${escapeHtml(text)}</a>`;
const day = (d: Date): string => d.toISOString().slice(0, 10);

/** `qualor-<link id, 32 hex>-<generation>`: the reconciliation key, the description's last paragraph. */
export function reconciliationKey(linkId: string, generation: number): string {
  return `qualor-${linkId.replaceAll('-', '')}-${generation}`;
}

const KEY_PATTERN = /Qualor reference:\s*(qualor-[0-9a-f]{32}-\d+)/g;

/**
 * The key in a description as Azure stores it. Azure adds a space before `</p>`, so the paragraph is
 * not matched exactly; the last match wins, as the key is the last paragraph.
 */
export function keyOfDescription(html: string | null): string | null {
  if (html === null) return null;
  let key: string | null = null;
  for (const m of html.matchAll(KEY_PATTERN)) key = m[1] ?? key;
  return key;
}

const keyParagraph = (key: string): string => para(`Qualor reference: ${escapeHtml(key)}`);

function qualorLine(url: string | null): string[] {
  return url === null ? [] : [para(anchor('Open in Qualor', url))];
}

function foundInHtml(names: string[]): string {
  const shown = names.slice(0, FOUND_IN_MAX).map(code);
  const more = names.length - shown.length;
  return shown.join(', ') + (more > 0 ? ` and ${more} more` : '');
}

export function codeIssueWorkItem(
  f: CodeIssueFacts,
  publicUrl: string | null,
  key: string,
): WorkItemContent {
  const link = issueUrl(publicUrl, f.projectId, f.issueId);
  const place =
    f.path === null
      ? []
      : [para(`File: ${code(f.line === null ? f.path : `${f.path}:${f.line}`)}`)];
  const build = (messageMax: number): string =>
    [
      `<h3>${short(f.ruleName)}</h3>`,
      pre(cutText(f.message, messageMax)),
      para(`Project: ${code(f.projectName)} (${code(f.projectKey)})`),
      para(`Branch: ${code(f.branchName)}`),
      ...place,
      para(`Rule: ${code(f.ruleKey)}, ${f.severity}, ${code(f.quality)}`),
      para(`First seen: ${day(f.firstSeenAt)}`),
      ...qualorLine(link),
      keyParagraph(key),
    ].join('\n');
  // The message is the only unbounded part: shrink it until the whole description fits.
  let messageMax = MESSAGE_MAX;
  let html = build(messageMax);
  while (html.length > DESCRIPTION_MAX && messageMax > 0) {
    messageMax = Math.max(0, messageMax - (html.length - DESCRIPTION_MAX) - 1);
    html = build(messageMax);
  }
  return {
    title: cutText(f.message.replace(LINE_SPACE, ' ').trim(), SUMMARY_MAX),
    descriptionHtml: html,
    link,
  };
}

export function vulnerabilityWorkItem(
  f: VulnerabilityFacts,
  publicUrl: string | null,
  key: string,
): WorkItemContent {
  const link = vulnerabilitiesUrl(publicUrl, f.projectId);
  const heading =
    f.title === null ? short(f.vulnerabilityId) : `${short(f.vulnerabilityId)}: ${short(f.title)}`;
  const date = f.exploited && /^\d{4}-\d{2}-\d{2}$/.test(f.exploited.dateAdded);
  const encoded = advisoryUrl(f.primaryUrl);
  const url = encoded !== null && encoded.length <= ADVISORY_URL_MAX ? encoded : null;
  const installed =
    f.installedVersions.length > 0 ? `, installed ${foundInHtml(f.installedVersions)}` : '';
  const build = (withUrl: boolean, withInstalled: boolean): string =>
    [
      `<h3>${heading}</h3>`,
      para(`Package: ${code(f.packageName)}${withInstalled ? installed : ''}`),
      para(
        f.fixedVersion === null
          ? 'Fixed in: no fixed version yet'
          : `Fixed in: ${code(f.fixedVersion)}`,
      ),
      para(`Severity: ${f.severity}`),
      ...(f.exploited
        ? [
            para(
              `Exploited: CISA KEV, added ${date ? f.exploited.dateAdded : code(f.exploited.dateAdded)}`,
            ),
          ]
        : []),
      ...(f.epss
        ? [
            para(
              `EPSS: ${(f.epss.score * 100).toFixed(1)}% (percentile ${Math.round(f.epss.percentile * 100)})`,
            ),
          ]
        : []),
      para(`Found in: ${foundInHtml(f.foundIn)}`),
      ...(withUrl && url !== null ? [para(`Advisory: ${anchor(f.vulnerabilityId, url)}`)] : []),
      ...qualorLine(link),
      keyParagraph(key),
    ].join('\n');
  const html =
    [build(true, true), build(false, true), build(false, false)].find(
      (d) => d.length <= DESCRIPTION_MAX,
    ) ?? build(false, false);
  return {
    title: cutText(
      `${f.vulnerabilityId} in ${f.packageName} (${f.severity})`.replace(LINE_SPACE, ' '),
      SUMMARY_MAX,
    ),
    descriptionHtml: html,
    link,
  };
}

function note(html: string, link: string | null): string {
  return para(link === null ? html : `${html} ${anchor('Open in Qualor', link)}`);
}

export function fixedNote(f: CommentFacts): string {
  const text =
    f.kind === 'code'
      ? `Qualor no longer finds this issue on ${code(f.branchName)} (analysis of ${f.day}).`
      : `Qualor no longer finds ${code(f.vulnerabilityId)} in ${code(f.packageName)} on the tracked branches and versions of ${code(f.projectName)}.`;
  return note(text, f.link);
}

export function foundAgainNote(f: CommentFacts): string {
  const text =
    f.kind === 'code'
      ? `Qualor finds this again: ${code(f.ruleKey)} on ${code(f.branchName)} (analysis of ${f.day}).`
      : `Qualor finds this again: ${code(f.vulnerabilityId)} in ${code(f.packageName)} on ${foundInHtml(f.foundIn)}.`;
  return note(text, f.link);
}

const add = (path: string, value: unknown): AzureJsonPatch => ({ op: 'add', path, value });

/** The JSON Patch of a create call. Repro Steps (a Bug) gets the description as well. */
export function workItemOps(
  content: WorkItemContent,
  mapping: { tags: readonly string[]; areaPath: string | null; iterationPath: string | null },
  reproSteps: boolean,
): AzureJsonPatch[] {
  return [
    add('/fields/System.Title', content.title),
    add(`/fields/${DESCRIPTION_FIELD}`, content.descriptionHtml),
    ...(reproSteps ? [add(`/fields/${REPRO_STEPS_FIELD}`, content.descriptionHtml)] : []),
    add('/fields/System.Tags', workItemTags(mapping.tags)),
    ...(mapping.areaPath === null ? [] : [add('/fields/System.AreaPath', mapping.areaPath)]),
    ...(mapping.iterationPath === null
      ? []
      : [add('/fields/System.IterationPath', mapping.iterationPath)]),
    ...(content.link === null
      ? []
      : [add('/relations/-', { rel: 'Hyperlink', url: content.link })]),
  ];
}
