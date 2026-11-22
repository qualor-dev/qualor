import { encryptionKey } from '../../crypto/secrets';
import {
  TEST_PROBLEM_CODES,
  type ConnectionTest,
  type MissingAccess,
  type ScmConnectionRow,
  type ScmDeps,
  type TestProblemCode,
} from '../connections';
import { ScmError } from '../provider';
import { isInternalHostAllowed, scmBaseUrlProblem } from '../url';
import {
  credentialsId,
  isGitHubAppId,
  type InstallationTokenCache,
  type MutationPacer,
} from './app-auth';
import { GitHubClient, GITHUB_TEXT, type InstallationAccess } from './client';
import { decryptPrivateKey, UNDECRYPTABLE_KEY } from './credentials';
import { githubBaseUrlProblem, parseRepoRef } from './url';

/**
 * A client for a GitHub connection, or why there is none: no usable App id (a row the API would
 * refuse), a private key that no longer decrypts, or a base URL the current
 * `QUALOR_SCM_INTERNAL_HOSTS` or GitHub's URL rules no longer allow (checked again before any
 * request, like a webhook URL).
 */
export function githubClientFor(
  row: ScmConnectionRow,
  deps: ScmDeps,
  runtime?: { githubTokens: InstallationTokenCache; githubPacer: MutationPacer },
): { client: GitHubClient; appId: string } | { problem: string } {
  const appId = row.appId;
  if (appId === null || !isGitHubAppId(appId)) return { problem: UNDECRYPTABLE_KEY };
  const privateKey = decryptPrivateKey(encryptionKey(deps.secretKey), row.tokenEnc);
  if (privateKey === null) return { problem: UNDECRYPTABLE_KEY };
  const problem =
    scmBaseUrlProblem(row.baseUrl, deps.internalHosts) ?? githubBaseUrlProblem(row.baseUrl);
  if (problem) return { problem };
  return {
    appId,
    client: new GitHubClient(
      {
        connectionId: row.id,
        baseUrl: row.baseUrl,
        appId,
        privateKey: privateKey.key,
        credentials: credentialsId(appId, privateKey.pkcs8),
        allowInternalHosts: isInternalHostAllowed(new URL(row.baseUrl), deps.internalHosts),
      },
      {
        ...deps.githubClientOptions,
        ...(runtime ? { tokens: runtime.githubTokens, pacer: runtime.githubPacer } : {}),
      },
    ),
  };
}

function problemCode(err: ScmError): TestProblemCode {
  if (err.reason === 'not_installed') return 'not_installed';
  if (err.reason === 'permission_missing') return 'permission_missing';
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
    // GitHub never raises the Azure DevOps reasons; the switch stays exhaustive.
    case 'http':
    case 'other':
    case 'token_endpoint':
    case 'token_endpoint_unreachable':
    case 'token_endpoint_timeout':
    case 'token_endpoint_error':
    case 'sign_in_required':
    case 'html_answer':
      return 'http_error';
  }
}

/** The events the test checks the App subscribes to, each with the code that says it does not. */
const CHECKED_EVENTS = [
  ['check_run', 'event_check_run'],
  ['issue_comment', 'event_issue_comment'],
  ['pull_request_review_comment', 'event_pull_request_review_comment'],
] as const;

/**
 * What the installation lacks of the access Qualor uses beyond what every job needs, in the order
 * of `MISSING_ACCESS`: Contents (write), which resolves and reopens Qualor's conversations, Issues
 * (read or write), and each event the test checks.
 */
function missingAccess({ permissions, events }: InstallationAccess): MissingAccess[] {
  const missing: MissingAccess[] = [];
  if (permissions['contents'] !== 'write') missing.push('contents_write');
  const issues = permissions['issues'];
  if (issues !== 'read' && issues !== 'write') missing.push('issues_read');
  for (const [event, code] of CHECKED_EVENTS) if (!events.includes(event)) missing.push(code);
  return missing;
}

/**
 * `POST /scm-connections/{id}/test` for GitHub (github.md §2.2): `GET /app` with the JWT and, with
 * `owner/repo`, the installation, a scoped token and the repository, and what the installation
 * lacks of the rest of the access Qualor uses (`missingAccess`), which is no failure. Fixed texts
 * and codes only.
 */
export async function testGitHubConnection(
  row: ScmConnectionRow,
  deps: ScmDeps,
  projectRef: string | null,
): Promise<ConnectionTest> {
  const failed = (code: TestProblemCode, message: string): ConnectionTest => ({
    ok: false,
    user: null,
    project: null,
    problem: { code, message },
    missingAccess: null,
    visible: null,
  });
  const found = githubClientFor(row, deps);
  if ('problem' in found) {
    return failed(
      found.problem === UNDECRYPTABLE_KEY ? 'undecryptable' : 'url_not_allowed',
      found.problem,
    );
  }
  try {
    const app = await found.client.app();
    let project: ConnectionTest['project'] = null;
    let missing: ConnectionTest['missingAccess'] = null;
    if (projectRef !== null) {
      const ref = parseRepoRef(projectRef);
      if (ref === null) return failed('not_found', GITHUB_TEXT.notFound);
      const repo = await found.client.useRepository(ref);
      project = { id: repo.id, pathWithNamespace: repo.full_name, accessLevel: null };
      const access = found.client.installationAccess;
      missing = access === null ? null : missingAccess(access);
    }
    return {
      ok: true,
      user: { username: `${app.slug}[bot]` },
      project,
      problem: null,
      missingAccess: missing,
      visible: null,
    };
  } catch (err) {
    if (err instanceof ScmError) return failed(problemCode(err), err.message);
    throw err;
  }
}

/** github.md §2.2: the App's webhook URL, or null without `QUALOR_PUBLIC_URL`. */
export function githubWebhookUrl(publicUrl: string | null, connectionId: string): string | null {
  return publicUrl === null ? null : `${publicUrl}/api/v0/github/webhooks/${connectionId}`;
}

/** The URL of a GitLab project's webhook (6I-4), or null without `QUALOR_PUBLIC_URL`. */
export function gitlabWebhookUrl(publicUrl: string | null, connectionId: string): string | null {
  return publicUrl === null ? null : `${publicUrl}/api/v0/gitlab/webhooks/${connectionId}`;
}

export { TEST_PROBLEM_CODES };
