import { sql, type SQL } from 'drizzle-orm';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Executor } from '../db/client';
import type { scmConnections } from '../db/schema';
import type { GitHubClientOptions } from './github/client';
import { GitLabClient, GitLabError, type GitLabClientOptions } from './gitlab/client';
import { isInternalHostAllowed, scmBaseUrlProblem } from './url';

/** data-model.md §2: the AAD binding an encrypted token to its column. */
export const SCM_TOKEN_AAD = 'scm_connections.token_enc';
/** scm.md §2.1: a resource bound per organisation. */
export const MAX_SCM_CONNECTIONS_PER_ORGANIZATION = 10;
/** scm.md §2.1: printable ASCII without spaces (it goes into a header), 1–1 024 characters. */
export const SCM_TOKEN_PATTERN = /^[\x21-\x7e]{1,1024}$/;
/** scm.md §4.4. */
export const UNDECRYPTABLE_TOKEN =
  'The stored token cannot be decrypted (QUALOR_SECRET_KEY changed?); set it again';

export type ScmConnectionRow = typeof scmConnections.$inferSelect;

export interface ScmDeps {
  secretKey: string;
  /** `QUALOR_SCM_INTERNAL_HOSTS` (config.ts). */
  internalHosts: ReadonlySet<string>;
  /** Tests shorten the timeouts and substitute DNS. */
  clientOptions?: GitLabClientOptions;
  /** The same for GitHub clients (github/connections.ts). */
  githubClientOptions?: GitHubClientOptions;
}

/**
 * A client for the connection, or why there is none: a token that no longer decrypts, or a base
 * URL the current `QUALOR_SCM_INTERNAL_HOSTS` no longer allows (checked again before any request,
 * like a webhook URL, so removing a host from the list stops requests to it at once).
 */
export function gitlabClientFor(
  row: ScmConnectionRow,
  deps: ScmDeps,
): { client: GitLabClient } | { problem: string } {
  const token = decryptSecret(encryptionKey(deps.secretKey), row.tokenEnc, SCM_TOKEN_AAD);
  if (token === null) return { problem: UNDECRYPTABLE_TOKEN };
  const problem = scmBaseUrlProblem(row.baseUrl, deps.internalHosts);
  if (problem) return { problem };
  return {
    client: new GitLabClient(
      {
        baseUrl: row.baseUrl,
        token,
        allowInternalHosts: isInternalHostAllowed(new URL(row.baseUrl), deps.internalHosts),
      },
      deps.clientOptions,
    ),
  };
}

/** scm.md §4.4: why a test failed, as a stable code the UI turns into its own words. */
export const TEST_PROBLEM_CODES = [
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
  'not_installed',
  'permission_missing',
] as const;
export type TestProblemCode = (typeof TEST_PROBLEM_CODES)[number];

export interface ConnectionTest {
  ok: boolean;
  user: { username: string } | null;
  project: { id: number; pathWithNamespace: string } | null;
  /** One of scm.md §4.4's fixed texts with its code; never GitLab's own words. */
  problem: { code: TestProblemCode; message: string } | null;
}

function problemCode(err: GitLabError): TestProblemCode {
  if (err.kind === 'auth') return 'token_refused';
  if (err.kind === 'not_found') return 'not_found';
  switch (err.reason) {
    case 'not_public':
    case 'unresolved':
    case 'timeout':
    case 'unreachable':
    case 'bad_answer':
      return err.reason;
    case 'budget':
    case 'invalid_input':
      return 'bad_answer';
    // GitLab never raises not_installed or permission_missing (GitHub only); the switch stays
    // exhaustive.
    case 'http':
    case 'other':
    case 'not_installed':
    case 'permission_missing':
      return 'http_error';
  }
}

/**
 * `POST /scm-connections/{id}/test` (scm.md §2.1): `GET /user` and, with a project ref,
 * `GET /projects/:ref`, with the stored token. Answers only fixed texts (scm.md §4.4) and their
 * codes, never GitLab's own words.
 */
export async function testConnection(
  row: ScmConnectionRow,
  deps: ScmDeps,
  projectRef: string | null,
): Promise<ConnectionTest> {
  const failed = (code: TestProblemCode, message: string): ConnectionTest => ({
    ok: false,
    user: null,
    project: null,
    problem: { code, message },
  });
  const found = gitlabClientFor(row, deps);
  if ('problem' in found) {
    return failed(
      found.problem === UNDECRYPTABLE_TOKEN ? 'undecryptable' : 'url_not_allowed',
      found.problem,
    );
  }
  try {
    const user = await found.client.currentUser();
    const project = projectRef === null ? null : await found.client.project(projectRef);
    return {
      ok: true,
      user: { username: user.username },
      project: project ? { id: project.id, pathWithNamespace: project.path_with_namespace } : null,
      problem: null,
    };
  } catch (err) {
    if (err instanceof GitLabError) return failed(problemCode(err), err.message);
    throw err;
  }
}

/**
 * github.md §10: where a connection's merge request links live, in SQL (the twin of
 * `githubWebBase`, tested against it): the base URL for GitLab, the web base for GitHub. `c` is
 * the alias of `scm_connections` in the query (a fixed identifier, never user input).
 */
export function webBaseSql(c: string): SQL {
  const col = sql.raw(`${c}.base_url`);
  return sql`CASE WHEN ${sql.raw(`${c}.provider`)} <> 'github' THEN ${col}
    WHEN ${col} = 'https://api.github.com' THEN 'https://github.com'
    WHEN ${col} ~ '^https://api\\.[a-z0-9-]+\\.ghe\\.com$' THEN 'https://' || substr(${col}, 13)
    WHEN right(${col}, 7) = '/api/v3' THEN left(${col}, length(${col}) - 7)
    ELSE ${col} END`;
}

/**
 * scm.md §8, github.md §10: a branch keeps its merge request's URL only while the URL is on the
 * web base of the connection its project is mapped to (the decoration job checks that when it
 * stores one). Called when a connection's base URL changes and when a project is mapped to another
 * connection, in the same transaction; a link that is no longer on the address is forgotten until
 * the next decoration records the merge request again. A project without a connection keeps its
 * links.
 */
export async function forgetForeignMergeRequestUrls(
  db: Executor,
  scope: { connectionId: string } | { projectId: string },
): Promise<void> {
  const where =
    'connectionId' in scope
      ? sql`p.scm_connection_id = ${scope.connectionId}`
      : sql`p.id = ${scope.projectId}`;
  await db.execute(sql`
    UPDATE branches b SET mr_url = NULL, updated_at = now()
      FROM projects p JOIN scm_connections c ON c.id = p.scm_connection_id
     WHERE b.project_id = p.id AND ${where} AND b.mr_url IS NOT NULL
       AND left(b.mr_url, length(${webBaseSql('c')}) + 1) <> ${webBaseSql('c')} || '/'`);
}
