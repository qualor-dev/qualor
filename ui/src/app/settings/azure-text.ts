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
export function azureProblemText(problem: Problem, expiredOn: string | null = null): string {
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
        ? entraText(problem.message)
        : $localize`:@@azure.problem.certificateExpired:The certificate expired on ${expiredOn}:date:. Replace it, then test again.`;
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
 * A failed token request: the cause class when the server's fixed text names one (Microsoft Entra
 * could not be reached, did not answer, or answered with an error), else a refusal.
 */
function entraText(serverText: string): string {
  if (serverText.includes('could not be reached')) {
    return $localize`:@@azure.problem.entraUnreachable:Microsoft Entra could not be reached. Check that the server can reach login.microsoftonline.com.`;
  }
  if (serverText.includes('did not answer')) {
    return $localize`:@@azure.problem.entraTimeout:Microsoft Entra did not answer in time. Check that the server can reach login.microsoftonline.com.`;
  }
  if (serverText.includes('answered with an error')) {
    return $localize`:@@azure.problem.entraError:Microsoft Entra answered with an error. Try again later.`;
  }
  return $localize`:@@azure.problem.tokenEndpoint:Microsoft Entra refused the service principal. Check the tenant id, client id and the secret or certificate.`;
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
