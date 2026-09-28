import { cutAtGrapheme } from '../markdown/code-span';
import { LANGUAGES, type IssueKind, type Quality, type Severity } from '../report/taxonomy';
import { LLM_INPUT_BOUNDS, llmIssueInputSchema, type LlmIssueInput } from './input';

/** An issue (server) or a report finding (fixture harness) before the bounds of llm.md §5.1. */
export interface RawIssueInput {
  rule: { key: string; name: string; description: string | null; cwe: readonly number[] };
  severity: Severity;
  quality: Quality;
  kind: IssueKind;
  message: string;
  path: string | null;
  startLine: number | null;
  endLine: number | null;
  language: string | null;
  /** A stored or reported snippet; anything not of the report's shape counts as none. */
  snippet: unknown;
}

const B = LLM_INPUT_BOUNDS;

/** A positive integer line, or null. */
const line = (n: number | null): number | null =>
  n !== null && Number.isInteger(n) && n > 0 ? n : null;

/** The one mapping from an issue or a finding to the bounded prompt input (llm.md §5.1). */
export function llmInputFrom(raw: RawIssueInput): LlmIssueInput {
  const snippet = llmIssueInputSchema.shape.snippet.safeParse(raw.snippet ?? null);
  const language = (LANGUAGES as readonly string[]).includes(raw.language ?? '')
    ? (raw.language as NonNullable<LlmIssueInput['language']>)
    : null;
  return {
    rule: {
      key: cutAtGrapheme(raw.rule.key, B.ruleKey),
      name: cutAtGrapheme(raw.rule.name, B.ruleName),
      description: cutAtGrapheme(raw.rule.description ?? '', B.ruleDescription),
      cwe: raw.rule.cwe.filter((n) => Number.isInteger(n) && n > 0).slice(0, B.cwe),
    },
    severity: raw.severity,
    quality: raw.quality,
    kind: raw.kind,
    message: cutAtGrapheme(raw.message, B.message),
    path: raw.path === null ? null : cutAtGrapheme(raw.path, B.path),
    startLine: line(raw.startLine),
    endLine: line(raw.endLine),
    language,
    snippet: snippet.success ? snippet.data : null,
  };
}
