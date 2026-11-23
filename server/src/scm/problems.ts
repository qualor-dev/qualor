import { and, eq, isNotNull, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { scmConnections, type ScmProblemValue } from '../db/schema';
import { type TestProblemCode } from './connections';

/**
 * The failures of a decoration that the connection's own settings can fix: the credential was
 * refused or cannot be read, it lacks a permission, or the address is no longer allowed. Anything
 * else (a timeout, a rate limit, a 5xx) passes by itself and is never recorded.
 */
export const SCM_BACKGROUND_PROBLEM_CODES = [
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
  'permission_missing',
  'undecryptable',
  'url_not_allowed',
] as const satisfies readonly TestProblemCode[];

export type ScmBackgroundProblemCode = (typeof SCM_BACKGROUND_PROBLEM_CODES)[number];

export function isScmBackgroundProblem(code: TestProblemCode): code is ScmBackgroundProblemCode {
  return (SCM_BACKGROUND_PROBLEM_CODES as readonly string[]).includes(code);
}

/**
 * Records the problem on the connection. The same problem again keeps its time, so the settings'
 * "Problem since" is when it began; another problem replaces it with its own time.
 */
export async function recordScmProblem(
  db: Executor,
  connectionId: string,
  code: ScmBackgroundProblemCode,
): Promise<void> {
  const value: ScmProblemValue = { code, at: new Date().toISOString() };
  await db
    .update(scmConnections)
    .set({ problem: value })
    .where(
      and(
        eq(scmConnections.id, connectionId),
        sql`(${scmConnections.problem} ->> 'code') is distinct from ${code}`,
      ),
    );
}

/** Clears the recorded problem; a connection without one is not written. */
export async function clearScmProblem(db: Executor, connectionId: string): Promise<void> {
  await db
    .update(scmConnections)
    .set({ problem: null })
    .where(and(eq(scmConnections.id, connectionId), isNotNull(scmConnections.problem)));
}
