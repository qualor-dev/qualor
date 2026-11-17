import { eq } from 'drizzle-orm';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { jiraConnections } from '../db/schema';
import { JiraClient, JiraError, type JiraClientOptions } from './client';
import { JIRA_PROBLEM_TEXT, problemCodeOf, type JiraProblemCode } from './problems';
import { jiraApiUrlProblem, jiraHostAllowed, jiraSiteUrlProblem } from './url';

/** data-model.md §2: the AAD binding an encrypted token to its column. */
export const JIRA_TOKEN_AAD = 'jira_connections.token_enc';
/** spec §6.1: printable ASCII without spaces (it goes into a header), 1–1 024 characters. */
export const JIRA_TOKEN_PATTERN = /^[\x21-\x7e]{1,1024}$/;

export type JiraConnectionRow = typeof jiraConnections.$inferSelect;

export interface JiraDeps {
  secretKey: string;
  /** `QUALOR_JIRA_INTERNAL_HOSTS` (config.ts). */
  internalHosts: ReadonlySet<string>;
  /** Tests substitute DNS; `timeoutMs` is never passed on (it would cut the 30 s project list). */
  clientOptions?: JiraClientOptions;
}

/**
 * A client for the connection, or why there is none: a token that no longer decrypts, or an
 * address the current `QUALOR_JIRA_INTERNAL_HOSTS` no longer allows (checked again before any
 * request, as `gitlabClientFor` does, so removing a host from the list stops requests at once).
 */
export function jiraClientFor(
  row: JiraConnectionRow,
  deps: JiraDeps,
): { client: JiraClient } | { problem: 'undecryptable' | 'url_not_allowed' } {
  const token = decryptSecret(encryptionKey(deps.secretKey), row.tokenEnc, JIRA_TOKEN_AAD);
  if (token === null) return { problem: 'undecryptable' };
  const apiBase = row.deployment === 'cloud' ? (row.apiUrl ?? row.siteUrl) : row.siteUrl;
  if (
    jiraSiteUrlProblem(row.siteUrl, row.deployment, deps.internalHosts) !== null ||
    (row.apiUrl !== null && jiraApiUrlProblem(row.apiUrl) !== null)
  ) {
    return { problem: 'url_not_allowed' };
  }
  const { connectTimeoutMs, resolve, maxRequests } = deps.clientOptions ?? {};
  const options: JiraClientOptions = {
    ...(connectTimeoutMs === undefined ? {} : { connectTimeoutMs }),
    ...(resolve === undefined ? {} : { resolve }),
    ...(maxRequests === undefined ? {} : { maxRequests }),
  };
  return {
    client: new JiraClient(
      {
        deployment: row.deployment,
        apiBase,
        auth:
          row.deployment === 'cloud'
            ? { kind: 'basic', email: row.email ?? '', token }
            : { kind: 'bearer', token },
        allowInternalHosts: jiraHostAllowed(row.siteUrl, row.deployment, deps.internalHosts),
      },
      options,
    ),
  };
}

export interface ConnectionTestResult {
  ok: boolean;
  user: { displayName: string } | null;
  projectsVisible: number | null;
  /** One of `JIRA_PROBLEM_TEXT` with its code; never Jira's own words. */
  problem: { code: JiraProblemCode; message: string } | null;
}

const failed = (
  code: JiraProblemCode,
  seen: Pick<ConnectionTestResult, 'user' | 'projectsVisible'> = {
    user: null,
    projectsVisible: null,
  },
): ConnectionTestResult => ({
  ok: false,
  ...seen,
  problem: { code, message: JIRA_PROBLEM_TEXT[code] },
});

/**
 * spec §6.1: `GET /myself`, then the projects the account sees. None is a problem
 * (`no_projects`: a scoped token on the site URL answers 200 with empty lists, spec §11.7).
 */
export async function runConnectionTest(client: JiraClient): Promise<ConnectionTestResult> {
  try {
    const user = await client.myself();
    const projectsVisible = await client.projectsVisible();
    if (projectsVisible === 0) return failed('no_projects', { user, projectsVisible });
    return { ok: true, user, projectsVisible, problem: null };
  } catch (err) {
    if (err instanceof JiraError) return failed(problemCodeOf(err));
    throw err;
  }
}

/** `POST /organizations/{id}/jira/test`: the stored connection, with its stored token. */
export async function testJiraConnection(
  row: JiraConnectionRow,
  deps: JiraDeps,
): Promise<ConnectionTestResult> {
  const found = jiraClientFor(row, deps);
  if ('problem' in found) return failed(found.problem);
  return runConnectionTest(found.client);
}

/** The organisation's connection, or null. */
export async function connectionOf(
  db: Executor,
  organizationId: string,
): Promise<JiraConnectionRow | null> {
  const [row] = await db
    .select()
    .from(jiraConnections)
    .where(eq(jiraConnections.organizationId, organizationId));
  return row ?? null;
}
