import { createHash } from 'node:crypto';
import {
  llmInputFrom,
  PROMPT_VERSIONS,
  promptData,
  redactInput,
  type IssueKind,
  type LlmFeature,
  type LlmIssueInput,
  type Quality,
  type Severity,
} from '@qualor/shared';
import { and, eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { branchFiles, issues, rules } from '../db/schema';

type IssueRow = typeof issues.$inferSelect;
type RuleRow = typeof rules.$inferSelect;

export interface BuiltInput {
  issue: IssueRow;
  rule: RuleRow;
  input: LlmIssueInput;
  redactions: number;
  /** The data object between the prompt's markers (llm.md §9.2), after redaction. */
  data: string;
  inputSha256: string;
  /** The names of llm.md §5.1's fields the data carries (`LLM_DATA_FIELDS` order). */
  fields: string[];
}

export const sha256 = (text: string): string =>
  createHash('sha256').update(text, 'utf8').digest('hex');

/**
 * llm.md §5.1–§5.2, §9.2: the issue's redacted data object, its hash and the fields it carries,
 * read from the database (never from what a client sent). Null when the issue is gone.
 */
export async function buildIssueInput(
  db: Executor,
  issueId: string,
  feature: LlmFeature,
): Promise<BuiltInput | null> {
  const [row] = await db
    .select({ issue: issues, rule: rules })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(eq(issues.id, issueId));
  if (!row) return null;
  const { issue, rule } = row;
  let language: string | null = null;
  if (issue.path !== null) {
    const [f] = await db
      .select({ language: branchFiles.language })
      .from(branchFiles)
      .where(and(eq(branchFiles.branchId, issue.branchId), eq(branchFiles.path, issue.path)));
    language = f?.language ?? null;
  }
  const { input, redactions } = redactInput(
    llmInputFrom({
      rule: { key: rule.key, name: rule.name, description: rule.descriptionMd, cwe: rule.cwe },
      severity: issue.severity as Severity,
      quality: issue.quality as Quality,
      kind: issue.kind as IssueKind,
      message: issue.message,
      path: issue.path,
      startLine: issue.startLine,
      endLine: issue.endLine,
      language,
      snippet: issue.snippet,
    }),
  );
  const data = promptData(feature, input);
  const fields = ['rule', 'message'];
  if (input.path !== null) fields.push('path');
  if (input.language !== null) fields.push('language');
  if (input.snippet !== null) fields.push('snippet');
  return { issue, rule, input, redactions, data, inputSha256: sha256(data), fields };
}

/**
 * The SHA-256 of a provider base URL, carried by a request's job (llm.md §14): the job sends
 * nothing when the base URL is no longer the one the person asked under.
 */
export const baseUrlHash = (baseUrl: string): string => sha256(baseUrl);

/**
 * llm.md §10.2, the cache key. The organisation is part of it (as well as a column the
 * lookup filters on), so a cached answer can never be found from another organisation.
 */
export function cacheKeyOf(
  organizationId: string,
  feature: LlmFeature,
  provider: { kind: string; model: string },
  ruleKey: string,
  fingerprint: string,
  inputSha256: string,
): string {
  return sha256(
    JSON.stringify([
      organizationId,
      feature,
      PROMPT_VERSIONS[feature],
      provider.kind,
      provider.model,
      ruleKey,
      fingerprint,
      inputSha256,
    ]),
  );
}
