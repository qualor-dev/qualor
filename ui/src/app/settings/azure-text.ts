import type { ResponseBody } from '../api/types';

type TestResult = ResponseBody<'/api/v0/scm-connections/{id}/test', 'post'>;
type Problem = NonNullable<TestResult['problem']>;

/**
 * A failed Azure DevOps test in the UI's own words. `token_endpoint` shows the server's text: it is
 * fixed and safe, and says whether the stored certificate expired, which a fixed sentence here
 * could not.
 */
export function azureProblemText(problem: Problem): string {
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
      return $localize`:@@azure.problem.signInRequired:Azure DevOps asked for a sign-in: the credential was not accepted. Check it and the address.`;
    case 'html_answer':
      return $localize`:@@azure.problem.htmlAnswer:Azure DevOps answered with a web page instead of data. Check the address.`;
    case 'token_endpoint':
      return problem.message !== ''
        ? problem.message
        : $localize`:@@azure.problem.tokenEndpoint:Microsoft Entra did not issue a token for this service principal. Check the tenant id, the client id and the credential.`;
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

/** An Azure DevOps test answer as the pages show it: who connected, and what that identity sees. */
export function azureTestText(result: TestResult): string {
  if (!result.ok || !result.user) {
    return result.problem
      ? azureProblemText(result.problem)
      : $localize`:@@azure.problem.unknown:The test failed.`;
  }
  const name = result.user.username;
  if (result.project) {
    const repository = result.project.pathWithNamespace;
    return $localize`:@@azure.testOkRepository:Connected as ${name}:user:; the repository ${repository}:repository: is reachable.`;
  }
  if (result.visible) {
    const repositories = result.visible.repositories;
    const projects = result.visible.projects;
    return $localize`:@@azure.testOkVisible:Connected as ${name}:user:; ${repositories}:repositories: repositories in ${projects}:projects: projects visible.`;
  }
  return $localize`:@@azure.testOk:Connected as ${name}:user:.`;
}
