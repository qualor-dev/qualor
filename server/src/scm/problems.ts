import { and, eq, inArray, isNotNull, isNull, or, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { scmConnections, type ScmProblemValue } from '../db/schema';
import { type TestProblemCode } from './connections';

/**
 * The failures of a decoration that the connection's own settings can fix: the credential was
 * refused or cannot be read, it lacks a permission, or the address is no longer allowed. Anything
 * else (a timeout, a rate limit, a 5xx) passes by itself and is never recorded.
 */
export const SCM_CREDENTIAL_PROBLEM_CODES = [
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
  'permission_missing',
  'undecryptable',
  'url_not_allowed',
] as const satisfies readonly TestProblemCode[];

/**
 * The state of Qualor's service hooks in Azure DevOps, which the backstop pass records (sub-plan
 * 5): a subscription on probation or disabled. They share the connection's one problem slot under
 * the credential codes: a credential code overwrites them, and they never overwrite one.
 */
export const SCM_HOOK_PROBLEM_CODES = [
  'hook_probation',
  'hook_disabled',
] as const satisfies readonly TestProblemCode[];

export const SCM_BACKGROUND_PROBLEM_CODES = [
  ...SCM_CREDENTIAL_PROBLEM_CODES,
  ...SCM_HOOK_PROBLEM_CODES,
] as const satisfies readonly TestProblemCode[];

export type ScmBackgroundProblemCode = (typeof SCM_BACKGROUND_PROBLEM_CODES)[number];

export function isScmBackgroundProblem(code: TestProblemCode): code is ScmBackgroundProblemCode {
  return (SCM_BACKGROUND_PROBLEM_CODES as readonly string[]).includes(code);
}

const isHookCode = (code: ScmBackgroundProblemCode): boolean =>
  (SCM_HOOK_PROBLEM_CODES as readonly string[]).includes(code);

/**
 * Records the problem on the connection. The same problem again keeps its time, so the settings'
 * "Problem since" is when it began; another problem replaces it with its own time, except that a
 * hook code only takes an empty slot or a hook code's: a credential problem stays.
 */
export async function recordScmProblem(
  db: Executor,
  connectionId: string,
  code: ScmBackgroundProblemCode,
): Promise<void> {
  const value: ScmProblemValue = { code, at: new Date().toISOString() };
  const current = sql`(${scmConnections.problem} ->> 'code')`;
  await db
    .update(scmConnections)
    .set({ problem: value })
    .where(
      and(
        eq(scmConnections.id, connectionId),
        sql`${current} is distinct from ${code}`,
        ...(isHookCode(code)
          ? [or(isNull(scmConnections.problem), inArray(current, [...SCM_HOOK_PROBLEM_CODES]))]
          : []),
      ),
    );
}

/**
 * Clears the recorded problem when its code is one of `codes` (whatever its code, without
 * `codes`); a connection without a problem, or with another, is not written.
 */
export async function clearScmProblem(
  db: Executor,
  connectionId: string,
  codes?: readonly ScmBackgroundProblemCode[],
): Promise<void> {
  await db
    .update(scmConnections)
    .set({ problem: null })
    .where(
      and(
        eq(scmConnections.id, connectionId),
        isNotNull(scmConnections.problem),
        ...(codes === undefined
          ? []
          : [inArray(sql`(${scmConnections.problem} ->> 'code')`, [...codes])]),
      ),
    );
}
