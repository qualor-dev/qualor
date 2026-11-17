import { and, eq, inArray, notInArray, sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { jiraConnections, type JiraProblemValue } from '../db/schema';
import type { JiraError } from './client';

/** spec §6.1: why a Test fails, as a stable code the UI turns into its own words. */
export const JIRA_PROBLEM_CODES = [
  'undecryptable',
  'url_not_allowed',
  'not_public',
  'unresolved',
  'timeout',
  'unreachable',
  'token_refused',
  'not_found',
  'http_error',
  'bad_answer',
  'permission_missing',
  'no_projects',
  'captcha',
  'redirected',
  'rate_limited',
] as const;
export type JiraProblemCode = (typeof JIRA_PROBLEM_CODES)[number];

/** spec §6.1: the failures that concern the whole connection, recorded on it by a job. */
export const BACKGROUND_PROBLEM_CODES = [
  'token_refused',
  'captcha',
  'unreachable',
  'timeout',
  'redirected',
  'not_public',
  'url_not_allowed',
  'undecryptable',
] as const;
export type BackgroundProblemCode = (typeof BACKGROUND_PROBLEM_CODES)[number];

/** spec §6.1: the background problems that need an administrator (the others pass by themselves). */
export const CREDENTIAL_PROBLEM_CODES = [
  'token_refused',
  'captcha',
  'redirected',
  'not_public',
  'url_not_allowed',
  'undecryptable',
] as const satisfies readonly BackgroundProblemCode[];

/**
 * The one table of the texts people read for a Jira problem (ruling P14): a Test answer, the
 * connection's background problem and a failed Jira call all show `JIRA_PROBLEM_TEXT[code]`.
 * `JiraError.message` is only the code, and no remote text ever lands in these.
 */
export const JIRA_PROBLEM_TEXT: Record<JiraProblemCode, string> = {
  undecryptable:
    'The stored token cannot be decrypted (QUALOR_SECRET_KEY changed?). Save the token again.',
  url_not_allowed:
    'The address is not allowed. A Data Center on a private address or over http must be listed in QUALOR_JIRA_INTERNAL_HOSTS.',
  not_public:
    'The address resolves to a private or internal address. A Jira Cloud site must have a public address.',
  unresolved: 'The address of Jira could not be resolved. Check it for typing mistakes.',
  timeout: 'Jira did not answer in time.',
  unreachable: 'Jira could not be reached. Check the address and that Jira is running.',
  token_refused:
    'Jira refused the token (HTTP 401). A Jira Cloud API token lives at most 365 days: create a new one and save it here.',
  not_found: 'Jira answered that this does not exist (HTTP 404). Check the address.',
  http_error: 'Jira answered with an error Qualor cannot use.',
  bad_answer:
    'Jira answered with something that is not Jira data, usually a sign-in page of a proxy. Use the address of Jira itself.',
  permission_missing: 'The account of the token may not do this in Jira (HTTP 403).',
  no_projects:
    'The account sees no Jira projects. A scoped API token works only through the API URL https://api.atlassian.com/ex/jira/<cloud id>: set it, or give the account access to a project.',
  captcha:
    'Jira locked the account after failed sign-ins (CAPTCHA). A Jira administrator must reset the lockout before Qualor can sign in again.',
  redirected:
    'Jira answered with a redirect, usually a sign-in proxy or a wrong address. Use the address of Jira itself.',
  rate_limited: 'Jira asked Qualor to slow down (HTTP 429). Try again in a moment.',
};

/** The Test code of a failed Jira call. */
export function problemCodeOf(err: JiraError): JiraProblemCode {
  switch (err.code) {
    case 'field_refused':
    case 'limit_reached':
    case 'server_error':
    case 'http_error':
      return 'http_error';
    case 'budget':
      return 'bad_answer';
    default:
      return err.code;
  }
}

/**
 * The background problem a failed call records on the connection, or null when it concerns
 * nothing but the call (R16): `unresolved` and a 5xx are an unreachable Jira; a bad answer, a 429
 * and a refused element record nothing.
 */
export function backgroundCodeOf(err: JiraError): BackgroundProblemCode | null {
  switch (err.code) {
    case 'token_refused':
    case 'captcha':
    case 'redirected':
    case 'not_public':
    case 'timeout':
    case 'unreachable':
      return err.code;
    case 'unresolved':
    case 'server_error':
      return 'unreachable';
    default:
      return null;
  }
}

const CREDENTIAL_CODES: ReadonlySet<string> = new Set(CREDENTIAL_PROBLEM_CODES);

/** Whether the stored problem needs an administrator (creates are refused while it is set). */
export function isCredentialProblem(problem: JiraProblemValue | null): boolean {
  return problem !== null && CREDENTIAL_CODES.has(problem.code);
}

/** spec §6.1: the background problems that pass by themselves (they block nothing). */
export const TRANSIENT_PROBLEM_CODES = [
  'timeout',
  'unreachable',
] as const satisfies readonly BackgroundProblemCode[];

/** Whether a background code needs an administrator (else it passes by itself). */
export function isCredentialCode(code: BackgroundProblemCode): boolean {
  return CREDENTIAL_CODES.has(code);
}

/**
 * spec §6.1: a Jira call that was answered clears a transient problem, never a credential one,
 * whatever the connection holds by the time it does. True when it cleared one.
 */
export async function clearTransientProblem(db: Executor, connectionId: string): Promise<boolean> {
  const cleared = await db
    .update(jiraConnections)
    .set({ problem: sql`NULL`, updatedAt: sql`now()` })
    .where(
      and(
        eq(jiraConnections.id, connectionId),
        inArray(sql`${jiraConnections.problem} ->> 'code'`, [...TRANSIENT_PROBLEM_CODES]),
      ),
    )
    .returning({ id: jiraConnections.id });
  return cleared.length > 0;
}

/** The stored value of `code`: its fixed text, stamped with the database clock; NULL for null. */
function problemValue(code: BackgroundProblemCode | null): SQL {
  return code === null
    ? sql`NULL`
    : sql`jsonb_build_object('code', ${code}::text, 'message', ${JIRA_PROBLEM_TEXT[code]}::text, 'at', to_jsonb(now()))`;
}

/**
 * Sets the connection's background problem to `code` with its fixed text, stamped with the
 * database clock, or clears it with null, whatever it holds: for a writer that holds the row (a
 * PUT). A job or a Test writes with {@link replaceConnectionProblem}.
 */
export async function setConnectionProblem(
  db: Executor,
  connectionId: string,
  code: BackgroundProblemCode | null,
): Promise<void> {
  await db
    .update(jiraConnections)
    .set({ problem: problemValue(code), updatedAt: sql`now()` })
    .where(eq(jiraConnections.id, connectionId));
}

/** What a run or a Test last saw of its connection's background problem. */
export interface ProblemView {
  readonly id: string;
  problem: JiraProblemValue | null;
}

async function storedProblem(db: Executor, connectionId: string): Promise<JiraProblemValue | null> {
  const [row] = await db
    .select({ problem: jiraConnections.problem })
    .from(jiraConnections)
    .where(eq(jiraConnections.id, connectionId));
  return row?.problem ?? null;
}

/**
 * When `code` may be written over the stored problem: while it is still the one the writer saw;
 * a credential code also over any transient one (creates must be refused at once, spec §6.1), and
 * a transient code never over a credential one.
 */
function writable(seen: string | null, code: BackgroundProblemCode | null): SQL {
  const unchanged = sql`${jiraConnections.problem} IS NOT DISTINCT FROM ${seen}::jsonb`;
  if (code === null) return unchanged;
  const stored = sql`${jiraConnections.problem} ->> 'code'`;
  if (isCredentialCode(code)) {
    return sql`(${unchanged} OR ${inArray(stored, [...TRANSIENT_PROBLEM_CODES])})`;
  }
  return sql`(${unchanged} AND (${jiraConnections.problem} IS NULL OR ${notInArray(stored, [...CREDENTIAL_PROBLEM_CODES])}))`;
}

/**
 * Sets the background problem to `code` (null clears it) only while the stored one is still
 * `view.problem`, so a job or a Test never overwrites what another writer stored since it read the
 * row (a fresher problem, or an admin's clear). A credential code also replaces a transient one
 * another job stored meanwhile; a transient code never replaces a credential one. The view
 * follows the stored value either way, read again when this call did not write; true when it did.
 */
export async function replaceConnectionProblem(
  db: Executor,
  view: ProblemView,
  code: BackgroundProblemCode | null,
): Promise<boolean> {
  const seen = view.problem === null ? null : JSON.stringify(view.problem);
  const [written] = await db
    .update(jiraConnections)
    .set({ problem: problemValue(code), updatedAt: sql`now()` })
    .where(and(eq(jiraConnections.id, view.id), writable(seen, code)))
    .returning({ problem: jiraConnections.problem });
  if (written) {
    view.problem = written.problem;
    return true;
  }
  view.problem = await storedProblem(db, view.id);
  return false;
}

/**
 * spec §6.1: after an answered call, a transient problem in the view is cleared (conditionally,
 * {@link clearTransientProblem}); the view follows.
 */
export async function clearAfterAnswer(db: Executor, view: ProblemView): Promise<void> {
  if (view.problem === null || isCredentialProblem(view.problem)) return;
  view.problem = (await clearTransientProblem(db, view.id))
    ? null
    : await storedProblem(db, view.id);
}
