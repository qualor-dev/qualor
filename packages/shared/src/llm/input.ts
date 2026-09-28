import { z } from 'zod';
import { ISSUE_KINDS, LANGUAGES, QUALITIES, SEVERITIES } from '../report/taxonomy';

/**
 * llm.md §5.1: the bounds of what one prompt may carry, in code points (zod 4 counts a string's
 * length in code points; `cutAtGrapheme` cuts in code points). checkFix counts a suggestion line in
 * UTF-16 units, the stricter unit and the one of the CLI's cut (report-format.md §7).
 */
export const LLM_INPUT_BOUNDS = {
  ruleKey: 200,
  ruleName: 200,
  ruleDescription: 2_000,
  cwe: 10,
  message: 1_000,
  path: 400,
  snippetLines: 50,
  snippetLineChars: 400,
} as const;

const B = LLM_INPUT_BOUNDS;

export const llmIssueInputSchema = z.strictObject({
  rule: z.strictObject({
    // May be empty: llmInputFrom passes an empty key through instead of failing the request.
    key: z.string().max(B.ruleKey),
    name: z.string().max(B.ruleName),
    description: z.string().max(B.ruleDescription),
    cwe: z.array(z.number().int().positive()).max(B.cwe),
  }),
  severity: z.enum(SEVERITIES),
  quality: z.enum(QUALITIES),
  kind: z.enum(ISSUE_KINDS),
  message: z.string().max(B.message),
  path: z.string().max(B.path).nullable(),
  startLine: z.number().int().positive().nullable(),
  endLine: z.number().int().positive().nullable(),
  language: z.enum(LANGUAGES).nullable(),
  snippet: z
    .strictObject({
      startLine: z.number().int().positive(),
      lines: z.array(z.string().max(B.snippetLineChars)).max(B.snippetLines),
    })
    .nullable(),
});

export type LlmIssueInput = z.infer<typeof llmIssueInputSchema>;
