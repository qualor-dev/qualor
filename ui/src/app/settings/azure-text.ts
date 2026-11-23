import type { ResponseBody } from '../api/types';
import { formatDate } from '../shared/date-time.pipe';

type TestResult = ResponseBody<'/api/v0/scm-connections/{id}/test', 'post'>;
type Problem = NonNullable<TestResult['problem']>;

/**
 * When the connection's certificate has expired, the day it did in the page's language; else null.
 * A service principal with a certificate that Microsoft Entra refuses is most often this.
 */
export function azureCertificateExpiredOn(
  connection: { azure?: { certificate: { notAfter: string } | null } | null } | undefined,
  locale: string,
  now: Date = new Date(),
): string | null {
  const notAfter = connection?.azure?.certificate?.notAfter;
  if (!notAfter || new Date(notAfter).getTime() >= now.getTime()) return null;
  return formatDate(notAfter, locale) || null;
}

/**
 * A failed Azure DevOps test in the UI's own words, never the server's. `expiredOn` (see
 * {@link azureCertificateExpiredOn}) makes a token failure say that the certificate expired.
 */
export function azureProblemText(
  problem: { code: Problem['code']; message?: string },
  expiredOn: string | null = null,
): string {
  switch (problem.code) {
    case 'undecryptable':
      return $localize`:@@azure.problem.undecryptable:The stored credential can no longer be read (the server key changed). Set it again.`;
    case 'url_not_allowed':
      return $localize`:@@azure.problem.urlNotAllowed:The server no longer allows this Azure DevOps address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'not_public':
      return $localize`:@@azure.problem.notPublic:This Azure DevOps Server is on an internal address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'unresolved':
      return $localize`:@@azure.problem.unresolved:The Azure DevOps host name could not be found.`;
    case 'timeout':
      return $localize`:@@azure.problem.timeout:Azure DevOps did not answer in time.`;
    case 'unreachable':
      return $localize`:@@azure.problem.unreachable:Azure DevOps could not be reached.`;
    case 'token_refused':
      return $localize`:@@azure.problem.tokenRefused:Azure DevOps refused the credential. Check that it is valid, has not expired and may read the organization.`;
    case 'sign_in_required':
      return $localize`:@@azure.problem.signInRequired:The identity is not a member of this Azure DevOps organization or has no access level. Add it under Organization settings → Users with the Basic access level.`;
    case 'html_answer':
      return $localize`:@@azure.problem.htmlAnswer:Azure DevOps answered with a web page instead of data. Check the credential and the address.`;
    case 'token_endpoint':
      return expiredOn === null
        ? $localize`:@@azure.problem.tokenEndpoint:Microsoft Entra refused the service principal. Check the tenant id, client id and the secret or certificate.`
        : $localize`:@@azure.problem.certificateExpired:The certificate expired on ${expiredOn}:date:. Replace it, then test again.`;
    case 'token_endpoint_unreachable':
      return $localize`:@@azure.problem.entraUnreachable:Microsoft Entra could not be reached. Check that the server can reach login.microsoftonline.com.`;
    case 'token_endpoint_timeout':
      return $localize`:@@azure.problem.entraTimeout:Microsoft Entra did not answer in time. Check that the server can reach login.microsoftonline.com.`;
    case 'token_endpoint_error':
      return $localize`:@@azure.problem.entraError:Microsoft Entra answered with an error. Try again later; if it persists, check that the server can reach login.microsoftonline.com.`;
    case 'permission_missing':
      return $localize`:@@azure.problem.permission:The credential lacks a permission in Azure DevOps. Give it read access to Code.`;
    case 'not_found':
      return $localize`:@@azure.problem.notFound:The Azure DevOps repository was not found, or the credential cannot see it.`;
    case 'http_error':
      return $localize`:@@azure.problem.httpError:Azure DevOps answered with an error.`;
    case 'bad_answer':
      return $localize`:@@azure.problem.badAnswer:Azure DevOps' answer was not understood. Check the address.`;
    default:
      return $localize`:@@azure.problem.unknown:The test failed.`;
  }
}

/**
 * A problem the server recorded while it decorated a pull request, in the UI's own words. A
 * missing permission there is one a pull request needs, not the Test's read access; every other
 * code reads as the Test's.
 */
export function azureBackgroundProblemText(
  problem: { code: Problem['code'] },
  expiredOn: string | null = null,
): string {
  if (problem.code === 'permission_missing') {
    return $localize`:@@azure.problem.permissionBackground:The credential lacks a permission in Azure DevOps. Give Qualor's identity Contribute to pull requests on the repository; a personal access token also needs Code: Read & write.`;
  }
  if (problem.code === 'hook_probation') {
    return $localize`:@@azure.problem.hookProbation:Azure DevOps put Qualor's service hook subscriptions on probation, so it may skip events. Replies and commands are still read every 15 minutes. Open Settings → Azure DevOps → Service hooks and choose "Create or update Qualor's subscriptions".`;
  }
  if (problem.code === 'hook_disabled') {
    return $localize`:@@azure.problem.hookDisabled:Azure DevOps disabled Qualor's service hook subscriptions. Replies and commands are read every 15 minutes instead. Open Settings → Azure DevOps → Service hooks and choose "Create or update Qualor's subscriptions".`;
  }
  return azureProblemText(problem, expiredOn);
}

/** An Azure DevOps test answer as the pages show it: who connected, and what that identity sees. */
export function azureTestText(result: TestResult, expiredOn: string | null = null): string {
  if (!result.ok || !result.user) {
    return result.problem
      ? azureProblemText(result.problem, expiredOn)
      : $localize`:@@azure.problem.unknown:The test failed.`;
  }
  const name = result.user.username;
  if (result.project) {
    const repository = result.project.pathWithNamespace;
    return $localize`:@@azure.testOkRepository:Connected as ${name}:user:; the repository ${repository}:repository: is reachable.`;
  }
  if (result.visible) {
    const repositories = countText(result.visible.repositories, 'repository');
    const projects = countText(result.visible.projects, 'project');
    return $localize`:@@azure.testOkVisible:Connected as ${name}:user:; ${repositories}:repositories: in ${projects}:projects: visible.`;
  }
  return $localize`:@@azure.testOk:Connected as ${name}:user:.`;
}

export type HookState = NonNullable<TestResult['hooks']>[number]['state'];
export type HookOutcome = 'created' | 'replaced' | 'unchanged' | 'refused';

/** The state of Qualor's subscriptions in one Azure DevOps project, in the UI's own words. */
export function azureHookStateText(state: HookState): string {
  switch (state) {
    case 'enabled':
      return $localize`:@@azure.hooks.state.enabled:Active`;
    case 'onProbation':
      return $localize`:@@azure.hooks.state.onProbation:On probation: Azure DevOps is retrying failed deliveries`;
    case 'disabled':
      return $localize`:@@azure.hooks.state.disabled:Switched off in Azure DevOps`;
    case 'stale':
      return $localize`:@@azure.hooks.state.stale:Older password`;
    case 'missing':
      return $localize`:@@azure.hooks.state.missing:Not subscribed`;
  }
}

/** What writing the subscriptions did in one project: one word for each of the two. */
export function azureHookOutcomeText(comment: HookOutcome, updated: HookOutcome): string {
  const word = (outcome: HookOutcome): string => {
    switch (outcome) {
      case 'created':
        return $localize`:@@azure.hooks.outcome.created:created`;
      case 'replaced':
        return $localize`:@@azure.hooks.outcome.replaced:replaced`;
      case 'unchanged':
        return $localize`:@@azure.hooks.outcome.unchanged:unchanged`;
      case 'refused':
        return $localize`:@@azure.hooks.outcome.refused:refused`;
    }
  };
  const first = word(comment);
  const second = word(updated);
  return $localize`:@@azure.hooks.outcome:Comments: ${first}:comment:, pull request updates: ${second}:updated:`;
}

/** The 409 of the subscribe route, and the reason its button is disabled. */
export function azureHooksNeedHttps(): string {
  return $localize`:@@azure.hooks.needHttps:Azure DevOps sends service hooks with a password only to an https address. Set QUALOR_PUBLIC_URL to one; until then Qualor reads replies every 15 minutes.`;
}

/** The 502 of the subscribe route: Azure DevOps failed part-way. */
export function azureHooksPartial(): string {
  return $localize`:@@azure.hooks.partial:Azure DevOps could not be reached or refused a request. Some subscriptions may already be written: test the connection to see each project's state, then try again.`;
}

/** "1 repository", "12 repositories", "1 project", "3 projects". */
function countText(count: number, noun: 'repository' | 'project'): string {
  if (noun === 'repository') {
    return count === 1
      ? $localize`:@@azure.oneRepository:1 repository`
      : $localize`:@@azure.manyRepositories:${count}:count: repositories`;
  }
  return count === 1
    ? $localize`:@@azure.oneProject:1 project`
    : $localize`:@@azure.manyProjects:${count}:count: projects`;
}
