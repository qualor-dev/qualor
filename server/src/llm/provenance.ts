import type { TriageResult } from '@qualor/shared';
import { and, eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { issues, llmRequests, projects, type LlmRequestRow } from '../db/schema';
import { USERNAME_PATTERN } from '../patterns';
import { aiResultSchema } from './dto';
import { MODEL_PATTERN } from './settings';

/** llm.md §7: the person's own part of the comment when a suggestion is recorded with it. */
export const PROVENANCE_COMMENT_MAX = 1_700;
/** data-model.md §6 (issue_changes_comment_length): the whole changelog comment. */
const CHANGE_COMMENT_MAX = 2_000;
const SEPARATOR = '\n\n';
const PROMPT_VERSION_PATTERN = /^[a-z]+\.v[0-9]{1,4}$/;

/**
 * The succeeded triage answer `suggestionId` names, when it is one of this issue in the issue's
 * own organisation; else null. The caller has already checked that the person sees the issue,
 * so a suggestion id never discloses another organisation's request.
 */
export async function triageSuggestionFor(
  db: Executor,
  issueId: string,
  suggestionId: string,
): Promise<{ row: LlmRequestRow; result: TriageResult } | null> {
  const [found] = await db
    .select({ row: llmRequests })
    .from(llmRequests)
    .innerJoin(issues, eq(issues.id, llmRequests.issueId))
    .innerJoin(projects, eq(projects.id, issues.projectId))
    .where(
      and(
        eq(llmRequests.id, suggestionId),
        eq(llmRequests.issueId, issueId),
        eq(llmRequests.organizationId, projects.organizationId),
        eq(llmRequests.feature, 'triage'),
        eq(llmRequests.status, 'succeeded'),
      ),
    );
  if (!found) return null;
  const parsed = aiResultSchema.safeParse(found.row.result);
  if (!parsed.success || parsed.data.kind !== 'triage') return null;
  return { row: found.row, result: parsed.data };
}

/** A value that is not what its setting allows reads as `unknown`, never as raw text. */
const checked = (value: string, pattern: RegExp) => (pattern.test(value) ? value : 'unknown');

/**
 * llm.md §7, the one fixed line appended to the changelog comment. Only ids and values
 * from closed sets or validated settings go in (the verdict and confidence are enums of the
 * validated answer); the model's reasons never do.
 */
export function provenanceLine(row: LlmRequestRow, result: TriageResult, username: string): string {
  const model = checked(row.model, MODEL_PATTERN);
  const version = checked(row.promptVersion, PROMPT_VERSION_PATTERN);
  const who = checked(username, USERNAME_PATTERN);
  return `AI triage suggestion ${row.id} (${result.verdict}, ${result.confidence}; model ${model}, ${version}) was shown; the decision is ${who}'s.`;
}

/**
 * The most the person's own comment may hold next to `line`: 1 700, less when a long model name
 * would otherwise take the whole comment past the 2 000 of data-model.md §6.
 */
export function ownCommentMax(line: string): number {
  return Math.min(PROVENANCE_COMMENT_MAX, CHANGE_COMMENT_MAX - SEPARATOR.length - line.length);
}

/** The changelog comment: the person's own part (if any), then the provenance line. */
export function withProvenance(comment: string | null, line: string): string {
  return comment === null ? line : `${comment}${SEPARATOR}${line}`;
}
