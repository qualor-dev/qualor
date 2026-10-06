import { createHash } from 'node:crypto';
import type { GateResult, Quality, Severity } from '@qualor/shared';
import { linesWithinBytes, MAX_MESSAGE_CHARS, plainValue, ruleDocUrl } from '../markdown';
import { commitStatusFor, qualityLabel, severityLabel, SUMMARY_MAX_BYTES } from '../render';
import type { AnnotationLevel, GitHubAnnotation } from './client';

/** github.md §6.4: GitHub's limit per request, and Qualor's per pull request. */
export const MAX_ANNOTATIONS = 50;
/** GitHub's bound on a check run's `output.title` and an annotation's `title`. */
const TITLE_MAX = 255;
/** A link longer than this is not one of Qualor's own (an origin and two UUIDs); it is left out. */
const URL_MAX = 2_048;

const LEVEL: Record<Severity, AnnotationLevel> = {
  blocker: 'failure',
  high: 'failure',
  medium: 'warning',
  low: 'notice',
  info: 'notice',
};

/**
 * {@link plainValue} bounded to `max` UTF-16 code units as well as code points: GitHub counts a
 * title's length in characters, and a value outside the BMP takes two units each.
 */
function plainWithin(value: string, max: number): string {
  let bound = max;
  let text = plainValue(value, bound);
  while (text.length > max && bound > 1) {
    // A code point is one or two units: dropping half the excess never drops more than needed.
    bound -= Math.ceil((text.length - max) / 2);
    text = plainValue(value, bound);
  }
  return text;
}

/**
 * Qualor's own issue link as plain text, or null: an http(s) URL without credentials, which
 * {@link plainValue} leaves as it is (no control, space or invisible character) and short.
 */
function plainLink(url: string | null): string | null {
  if (url === null || url.length > URL_MAX || !URL.canParse(url)) return null;
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (parsed.username !== '' || parsed.password !== '') return null;
  return plainValue(url, URL_MAX) === url && !/\s/.test(url) ? url : null;
}

/**
 * github.md §6.4: one annotation, plain text through `plainValue` (scm.md §6, github.md §7):
 * GitHub renders no Markdown in annotations. The message is at most 300 characters, the rule's
 * documentation link (a safe https URL of at most 512) and Qualor's link, far below GitHub's
 * 64 KiB; the title at most 255.
 */
export function annotationFor(issue: {
  path: string;
  line: number;
  severity: Severity;
  quality: Quality;
  ruleKey: string;
  /** The rule's documentation link, shown when it is a safe https URL. */
  helpUri?: string | null;
  message: string;
  url: string | null;
}): GitHubAnnotation {
  const text = plainValue(issue.message, MAX_MESSAGE_CHARS);
  const docs = ruleDocUrl(issue.helpUri);
  const message = `${text.trim() === '' ? 'Qualor issue' : text}${
    docs === null
      ? ''
      : `

Rule: ${docs}`
  }`;
  const link = plainLink(issue.url);
  return {
    path: issue.path,
    start_line: issue.line,
    end_line: issue.line,
    annotation_level: Object.hasOwn(LEVEL, issue.severity) ? LEVEL[issue.severity] : 'warning',
    title: plainWithin(
      `${severityLabel(issue.severity)} · ${qualityLabel(issue.quality)} · ${issue.ruleKey}`,
      TITLE_MAX,
    ),
    message: link === null ? message : `${message}\n\nView in Qualor: ${link}`,
  };
}

/** github.md §6.4: 16 hex characters of the SHA-256 of the annotations as sent. */
export function annotationsDigest(annotations: readonly GitHubAnnotation[]): string {
  const canonical = annotations.map((a) => [
    a.path,
    a.start_line,
    a.end_line,
    a.annotation_level,
    a.title,
    a.message,
  ]);
  return createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex').slice(0, 16);
}

const EXTERNAL_ID =
  /^qualor:v1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([0-9a-f]{16})$/;

/** github.md §6.1: `qualor:v1:<analysisId>:<digest>`; throws on anything it could not read back. */
export function checkRunExternalId(analysisId: string, digest: string): string {
  const id = `qualor:v1:${analysisId}:${digest}`;
  if (!EXTERNAL_ID.test(id)) throw new Error('not a Qualor check run id');
  return id;
}

/** The analysis and digest of a Qualor check run's `external_id`, or null for any other. */
export function parseCheckRunExternalId(
  value: string | null,
): { analysisId: string; digest: string } | null {
  const match = value === null ? null : EXTERNAL_ID.exec(value);
  return match?.[1] && match[2] ? { analysisId: match[1], digest: match[2] } : null;
}

/** github.md §6.1: the conclusion and title, from scm.md §5.1's table (catalog text only). */
export function checkRunVerdict(gate: GateResult): {
  conclusion: 'success' | 'failure';
  title: string;
} {
  const { state, description } = commitStatusFor(gate);
  return {
    conclusion: state === 'success' ? 'success' : 'failure',
    title: plainWithin(description, TITLE_MAX),
  };
}

/**
 * github.md §6.1: the summary comment's body without its marker line, at most 16 KiB (cut at
 * whole lines, so no code span is left open), far below GitHub's 65 535 characters.
 */
export function checkRunSummary(body: string): string {
  const lines = body.split('\n');
  return linesWithinBytes(
    lines[0]?.startsWith('<!-- qualor:') ? lines.slice(1) : lines,
    SUMMARY_MAX_BYTES,
  );
}
