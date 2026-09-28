import {
  GITHUB_CHECKOUTS,
  GITHUB_ID,
  GITLAB_ID,
  GITLAB_MR_EVENT_TYPES,
  type Report,
} from '@qualor/shared';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';

/**
 * `analyses.scm_context` (scm.md §7, data-model.md §4.3): what a re-evaluation must know of the
 * report it can no longer read (reports are kept 7 days): whether it came from GitLab CI, and the
 * CI context a decoration uses. Small and bounded: no free text beyond the merge request's id
 * (at most 64 characters, as the report allows it).
 */
export const scmContextSchema = z.strictObject({
  provider: z.enum(['gitlab', 'github', 'none']),
  /** `scm.mergeRequest.id`, or null for a branch analysis. */
  mergeRequestId: z.string().min(1).max(64).nullable(),
  /** `scm.gitlab` (scm.md §3), or null outside GitLab CI. */
  gitlab: z
    .strictObject({
      projectId: z.string().regex(GITLAB_ID).optional(),
      pipelineId: z.string().regex(GITLAB_ID).optional(),
      mergeRequestEventType: z.enum(GITLAB_MR_EVENT_TYPES).optional(),
    })
    .nullable(),
  /** `scm.github` (github.md §3), or null outside GitHub Actions; absent in 2A rows. */
  github: z
    .strictObject({
      repositoryId: z.string().regex(GITHUB_ID).optional(),
      runId: z.string().regex(GITHUB_ID).optional(),
      checkout: z.enum(GITHUB_CHECKOUTS).optional(),
    })
    .nullable()
    .optional(),
});
export type ScmContext = z.infer<typeof scmContextSchema>;

/**
 * What is stored when a report's `scm` does not fit {@link scmContextSchema} (it cannot, for a
 * report that passed validation, but if it ever did): a value that reads back as `invalid`, so a
 * re-evaluation fails closed and says why, instead of taking the analysis for an older one.
 */
export const INVALID_SCM_CONTEXT = { invalid: true } as const;

/**
 * The context to store for a validated report; {@link INVALID_SCM_CONTEXT}, logged, if it does not
 * fit.
 */
export function scmContextOf(
  report: Report,
  logger?: Pick<FastifyBaseLogger, 'warn'>,
): ScmContext | typeof INVALID_SCM_CONTEXT {
  const parsed = scmContextSchema.safeParse({
    provider: report.scm.provider,
    mergeRequestId: report.scm.mergeRequest?.id ?? null,
    gitlab: report.scm.gitlab ?? null,
    // Only for a GitHub report that has one: a GitLab or local analysis stores the 2A shape
    // unchanged, and an absent key reads as null (D2, ruling C1).
    ...(report.scm.provider !== 'github' || report.scm.github === undefined
      ? {}
      : { github: report.scm.github }),
  });
  if (parsed.success) return parsed.data;
  logger?.warn(
    { issues: parsed.error.issues.map((i) => i.path.join('.')) },
    "the report's SCM context does not fit analyses.scm_context; stored as invalid, so a gate re-evaluation will not decorate this analysis",
  );
  return INVALID_SCM_CONTEXT;
}

/**
 * A stored `scm_context`: `missing` when NULL (an analysis ingested before the column existed),
 * `invalid` when it is not what Qualor writes; both fail closed.
 */
export function readScmContext(
  value: unknown,
): { kind: 'ok'; context: ScmContext } | { kind: 'missing' } | { kind: 'invalid' } {
  if (value === null || value === undefined) return { kind: 'missing' };
  const parsed = scmContextSchema.safeParse(value);
  return parsed.success ? { kind: 'ok', context: parsed.data } : { kind: 'invalid' };
}
