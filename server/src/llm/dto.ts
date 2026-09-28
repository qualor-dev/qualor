import {
  FIX_PROBLEMS,
  LLM_FEATURES,
  TRIAGE_CONFIDENCES,
  TRIAGE_VERDICTS,
  type FixProblem,
} from '@qualor/shared';
import { z } from 'zod';
import { LLM_REQUEST_STATUSES, type LlmRequestRow } from '../db/schema';
import { iso, isoOrNull, timestamp } from '../http/schemas';
import { LLM_ERROR_CODES, type LlmErrorCode } from './errors';

const explainResult = z.object({
  kind: z.literal('explain'),
  summary: z.string(),
  explanation: z.string(),
  howToFix: z.string(),
});
const triageResult = z.object({
  kind: z.literal('triage'),
  verdict: z.enum(TRIAGE_VERDICTS),
  confidence: z.enum(TRIAGE_CONFIDENCES),
  reasons: z.array(z.string()),
});
const fixedResult = z.object({
  kind: z.literal('fix'),
  status: z.literal('fixed'),
  startLine: z.number().int(),
  endLine: z.number().int(),
  original: z.array(z.string()),
  replacement: z.array(z.string()),
  explanation: z.string(),
});
const notApplicableResult = z.object({
  kind: z.literal('fix'),
  status: z.literal('not_applicable'),
  explanation: z.string(),
});
/** The validated answer a succeeded request stored (llm.md §6–§8): plain text only. */
export const aiResultSchema = z.union([
  explainResult,
  triageResult,
  fixedResult,
  notApplicableResult,
]);

export const aiRequestSchema = z.object({
  id: z.uuid(),
  issueId: z.uuid().nullable(),
  feature: z.enum(LLM_FEATURES),
  status: z.enum(LLM_REQUEST_STATUSES),
  model: z.string(),
  promptVersion: z.string(),
  createdAt: timestamp,
  finishedAt: timestamp.nullable(),
  /** llm.md §14; `detail` is the rule of §9.5 for `OUTPUT_REFUSED`. */
  error: z
    .object({ code: z.enum(LLM_ERROR_CODES), detail: z.enum(FIX_PROBLEMS).nullable() })
    .nullable(),
  result: aiResultSchema.nullable(),
  post: z
    .object({
      status: z.enum(['queued', 'posted', 'failed']),
      reason: z.string().nullable(),
      url: z.string().nullable(),
      at: timestamp,
    })
    .nullable(),
});
export type AiRequestDto = z.infer<typeof aiRequestSchema>;

const isErrorCode = (value: string | undefined): value is LlmErrorCode =>
  (LLM_ERROR_CODES as readonly string[]).includes(value ?? '');
const isFixProblem = (value: string | undefined): value is FixProblem =>
  (FIX_PROBLEMS as readonly string[]).includes(value ?? '');

/**
 * `error_code` is `CODE` or `OUTPUT_REFUSED:<rule>` (Task 11); an unknown code reads as
 * PROVIDER_BAD_ANSWER, never as raw text. A stored result that no longer parses reads as none.
 */
export function aiRequestDto(row: LlmRequestRow): AiRequestDto {
  const [code, detail] = (row.errorCode ?? '').split(':');
  const parsedResult = aiResultSchema.safeParse(row.result);
  return {
    id: row.id,
    issueId: row.issueId,
    feature: row.feature,
    status: row.status,
    model: row.model,
    promptVersion: row.promptVersion,
    createdAt: iso(row.createdAt),
    finishedAt: isoOrNull(row.finishedAt),
    error:
      row.errorCode === null
        ? null
        : {
            code: isErrorCode(code) ? code : 'PROVIDER_BAD_ANSWER',
            detail: isFixProblem(detail) ? detail : null,
          },
    result: parsedResult.success ? parsedResult.data : null,
    post: row.post
      ? {
          status: row.post.status,
          reason: row.post.reason ?? null,
          url: row.post.url ?? null,
          at: row.post.at,
        }
      : null,
  };
}
