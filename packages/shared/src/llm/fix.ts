import {
  CONTROL_CHARS,
  INVISIBLE_CHARS,
  JOINER_CHARS,
  LONE_SURROGATE_SOURCE,
} from '../markdown/code-span';
import { REDACTED } from '../sarif/normalize';
import type { LlmIssueInput } from './input';
import type { FixAnswer } from './output';
import { redactText } from './redact';

export const FIX_BOUNDS = {
  maxRangeLines: 15,
  maxReplacementLines: 30,
  maxLineChars: 400,
} as const;

export const FIX_PROBLEMS = [
  'range',
  'source_line_unusable',
  'size',
  'unchanged',
  'control_character',
  'fence',
  'redacted',
  'secret',
  'quick_action',
] as const;
export type FixProblem = (typeof FIX_PROBLEMS)[number];

export type FixResult =
  | {
      kind: 'fix';
      status: 'fixed';
      startLine: number;
      endLine: number;
      original: string[];
      replacement: string[];
      explanation: string;
    }
  | { kind: 'fix'; status: 'not_applicable'; explanation: string };

/**
 * Refused in a suggestion line, once a tab is read as a space (one list with code-span.ts): the
 * controls, separators, bidi controls and invisible characters of llm.md §9.4, the joiners and
 * selectors that text for people keeps, every other format character (Cf) and a lone surrogate.
 */
const UNSAFE = new RegExp(
  String.raw`[${CONTROL_CHARS}${INVISIBLE_CHARS}${JOINER_CHARS}\p{Cf}]|${LONE_SURROGATE_SOURCE}`,
  'u',
);
/** A run that could open or close a Markdown code fence around the suggestion. */
const FENCE = /`{3,}|~{3,}/;
/**
 * A GitLab quick action (llm.md §9.5), in any case and with digits (`/MERGE`, `/h1`),
 * failing closed; `//`, `/*` and `/regex/` do not match.
 */
const QUICK_ACTION = /^\/[a-z0-9_]+(\s|$)/i;

/** llm.md §9.5: why one replacement line may not go into a suggestion block, or null. */
export function suggestionLineProblem(line: string): FixProblem | null {
  // UTF-16 units: stricter than the schema's code points, and the unit of the CLI's cut.
  if (line.length > FIX_BOUNDS.maxLineChars) return 'size';
  if (UNSAFE.test(line.replaceAll('\t', ' '))) return 'control_character';
  if (FENCE.test(line)) return 'fence';
  if (line.includes(REDACTED)) return 'redacted';
  if (redactText(line).count > 0) return 'secret';
  if (QUICK_ACTION.test(line.trim())) return 'quick_action';
  return null;
}

/** A line the CLI cut at 400 characters (report-format.md §7) ends with `…` at 399 or more. */
function unusable(line: string): boolean {
  return line.includes(REDACTED) || (line.length >= 399 && line.endsWith('…'));
}

/** llm.md §9.5: a `fixed` answer that may become a suggestion, or the first rule it breaks. */
export function checkFix(
  answer: FixAnswer,
  input: LlmIssueInput,
): { ok: true; value: FixResult } | { ok: false; problem: FixProblem } {
  if (answer.status === 'not_applicable') {
    return {
      ok: true,
      value: { kind: 'fix', status: 'not_applicable', explanation: answer.explanation },
    };
  }
  const snippet = input.snippet;
  const start = answer.startLine;
  const end = answer.endLine;
  const fail = (problem: FixProblem) => ({ ok: false as const, problem });
  if (!snippet || input.startLine === null) return fail('range');
  // The type says integer; a caller that skipped the schema may still pass NaN or 2.5.
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return fail('range');
  const last = snippet.startLine + snippet.lines.length - 1;
  if (end < start || start < snippet.startLine || end > last) return fail('range');
  if (input.startLine < start || input.startLine > end) return fail('range');
  if (end - start + 1 > FIX_BOUNDS.maxRangeLines) return fail('range');
  const original = snippet.lines.slice(start - snippet.startLine, end - snippet.startLine + 1);
  if (original.some(unusable)) return fail('source_line_unusable');
  if (answer.replacement.length > FIX_BOUNDS.maxReplacementLines) return fail('size');
  if (
    answer.replacement.length === original.length &&
    answer.replacement.every((l, i) => l === original[i])
  ) {
    return fail('unchanged');
  }
  for (const line of answer.replacement) {
    const problem = suggestionLineProblem(line);
    if (problem) return fail(problem);
  }
  // Line by line misses a secret split over lines or a key block; §5.2 on the whole catches them.
  if (redactText(answer.replacement.join('\n')).count > 0) return fail('secret');
  return {
    ok: true,
    value: {
      kind: 'fix',
      status: 'fixed',
      startLine: start,
      endLine: end,
      original,
      replacement: answer.replacement,
      explanation: answer.explanation,
    },
  };
}
