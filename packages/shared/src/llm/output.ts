import { z } from 'zod';
import { cutAtGrapheme, safePlainValue } from '../markdown/code-span';
import type { LlmFeature } from './features';

export const TRIAGE_VERDICTS = [
  'likely_false_positive',
  'likely_true_positive',
  'uncertain',
] as const;
export type TriageVerdict = (typeof TRIAGE_VERDICTS)[number];
export const TRIAGE_CONFIDENCES = ['low', 'medium', 'high'] as const;
export type TriageConfidence = (typeof TRIAGE_CONFIDENCES)[number];

/** Displayed bounds (llm.md §6–§8); the schemas accept up to twice as much, which is then cut. */
export const OUTPUT_BOUNDS = {
  summary: 300,
  explanation: 2_000,
  howToFix: 1_200,
  reason: 300,
  fixExplanation: 600,
  maxLines: 20,
} as const;
const O = OUTPUT_BOUNDS;

/**
 * An answer text longer than this is refused before `JSON.parse` (llm.md §9.3). The largest valid
 * answer (a fix: 30 lines of 400 characters, JSON-escaped) stays well below it.
 */
export const MAX_ANSWER_CHARS = 65_536;

export const explainOutputSchema = z.strictObject({
  summary: z
    .string()
    .min(1)
    .max(O.summary * 2),
  explanation: z
    .string()
    .min(1)
    .max(O.explanation * 2),
  howToFix: z.string().max(O.howToFix * 2),
});
export const triageOutputSchema = z.strictObject({
  verdict: z.enum(TRIAGE_VERDICTS),
  confidence: z.enum(TRIAGE_CONFIDENCES),
  reasons: z
    .array(
      z
        .string()
        .min(1)
        .max(O.reason * 2),
    )
    .min(1)
    .max(5),
});
/** A `fixed` answer: whole positive lines, bounded replacement (llm.md §8.1). */
const fixedOutputSchema = z.strictObject({
  status: z.literal('fixed'),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  replacement: z.array(z.string().max(400)).max(30),
  explanation: z.string().max(O.fixExplanation * 2),
});
/** `not_applicable` (llm.md §8.1): its lines, if any, are ignored, whatever they are. */
const notApplicableOutputSchema = z.strictObject({
  status: z.literal('not_applicable'),
  startLine: z.number().nullable().optional(),
  endLine: z.number().nullable().optional(),
  replacement: z.array(z.string().max(400)).max(30).optional(),
  explanation: z.string().max(O.fixExplanation * 2),
});
export const fixOutputSchema = z.discriminatedUnion('status', [
  fixedOutputSchema,
  notApplicableOutputSchema,
]);

export type ExplainResult = {
  kind: 'explain';
  summary: string;
  explanation: string;
  howToFix: string;
};
export type TriageResult = {
  kind: 'triage';
  verdict: TriageVerdict;
  confidence: TriageConfidence;
  reasons: string[];
};
/** What checkFix receives: a `not_applicable` answer keeps only its explanation. */
export type FixAnswer =
  z.infer<typeof fixedOutputSchema> | { status: 'not_applicable'; explanation: string };
export type AnswerFailure = 'MALFORMED_OUTPUT' | 'OUTPUT_TRUNCATED' | 'MODEL_REFUSED';
export type FinishReason = 'stop' | 'length' | 'refusal' | 'tool' | 'other';

/** llm.md §9.4: text for people: one value per line, controls and bidi gone, bounded. */
export function safeMultilineText(
  value: string,
  maxChars: number,
  maxLines: number = O.maxLines,
): string {
  const lines = value
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .slice(0, maxLines)
    .map((line) => safePlainValue(line, maxChars).trimEnd());
  const joined = lines
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return cutAtGrapheme(joined, maxChars);
}

/** The fence tag `json` in any case (`JSON`, `Json`), or none. */
const FENCED = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n[ \t]*```$/i;

/** The longest leading `<think>` block skipped (a local reasoning model's, plan 3B ruling). */
export const MAX_THINK_CHARS = 32_768;
const THINK_OPEN = '<think>';
const THINK_CLOSE = '</think>';

/**
 * llm.md §9.3: exactly one JSON object, bare or alone in one fenced block, maybe after ONE leading
 * `<think>…</think>` block of at most {@link MAX_THINK_CHARS} characters; else undefined.
 */
export function parseModelJson(text: string): Record<string, unknown> | undefined {
  if (text.length > MAX_ANSWER_CHARS) return undefined;
  let body = text.trim();
  if (body.startsWith(THINK_OPEN)) {
    const close = body.indexOf(THINK_CLOSE, THINK_OPEN.length);
    if (close < 0 || close - THINK_OPEN.length > MAX_THINK_CHARS) return undefined;
    body = body.slice(close + THINK_CLOSE.length).trim();
  }
  const fenced = FENCED.exec(body);
  if (fenced) body = (fenced[1] ?? '').trim();
  if (!body.startsWith('{') || !body.endsWith('}')) return undefined;
  try {
    const value: unknown = JSON.parse(body);
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

export function parseAnswer(
  feature: LlmFeature,
  answer: { text: string; finishReason: FinishReason },
):
  | { ok: true; value: ExplainResult | TriageResult | FixAnswer }
  | { ok: false; code: AnswerFailure } {
  if (answer.finishReason === 'length') return { ok: false, code: 'OUTPUT_TRUNCATED' };
  if (answer.finishReason === 'refusal') return { ok: false, code: 'MODEL_REFUSED' };
  if (answer.finishReason === 'tool') return { ok: false, code: 'MALFORMED_OUTPUT' };
  const json = parseModelJson(answer.text);
  const malformed = { ok: false as const, code: 'MALFORMED_OUTPUT' as const };
  if (json === undefined) return malformed;
  if (feature === 'explain') {
    const p = explainOutputSchema.safeParse(json);
    if (!p.success) return malformed;
    return {
      ok: true,
      value: {
        kind: 'explain',
        summary: safeMultilineText(p.data.summary, O.summary, 3),
        explanation: safeMultilineText(p.data.explanation, O.explanation),
        howToFix: safeMultilineText(p.data.howToFix, O.howToFix),
      },
    };
  }
  if (feature === 'triage') {
    const p = triageOutputSchema.safeParse(json);
    if (!p.success) return malformed;
    return {
      ok: true,
      value: {
        kind: 'triage',
        verdict: p.data.verdict,
        confidence: p.data.confidence,
        reasons: p.data.reasons.map((r) => safeMultilineText(r, O.reason, 3)),
      },
    };
  }
  const p = fixOutputSchema.safeParse(json);
  if (!p.success) return malformed;
  const explanation = safeMultilineText(p.data.explanation, O.fixExplanation, 5);
  if (p.data.status === 'not_applicable') {
    return { ok: true, value: { status: 'not_applicable', explanation } };
  }
  return { ok: true, value: { ...p.data, explanation } };
}
