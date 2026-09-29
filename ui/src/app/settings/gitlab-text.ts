import type { ResponseBody } from '../api/types';

type TestResult = ResponseBody<'/api/v0/scm-connections/{id}/test', 'post'>;
type ProblemCode = NonNullable<TestResult['problem']>['code'];

/** scm.md §4.4: a failed test in the UI's own words (the server's English text is never shown). */
export function testProblemText(code: ProblemCode): string {
  switch (code) {
    case 'undecryptable':
      return $localize`:@@gitlab.problem.undecryptable:The stored token can no longer be read (the server key changed). Replace the token.`;
    case 'url_not_allowed':
      return $localize`:@@gitlab.problem.urlNotAllowed:The server no longer allows this GitLab address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'not_public':
      return $localize`:@@gitlab.problem.notPublic:This GitLab is on an internal address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'unresolved':
      return $localize`:@@gitlab.problem.unresolved:The GitLab host name could not be found.`;
    case 'timeout':
      return $localize`:@@gitlab.problem.timeout:GitLab did not answer in time.`;
    case 'unreachable':
      return $localize`:@@gitlab.problem.unreachable:GitLab could not be reached.`;
    case 'token_refused':
      return $localize`:@@gitlab.problem.tokenRefused:GitLab refused the token. Check that it is valid and has not expired.`;
    case 'permission_missing':
      return $localize`:@@gitlab.problem.permission:The token lacks a permission in the GitLab project. Give it the api scope and the Maintainer role.`;
    case 'not_found':
      return $localize`:@@gitlab.problem.notFound:The GitLab project was not found, or the token cannot see it.`;
    case 'http_error':
      return $localize`:@@gitlab.problem.httpError:GitLab answered with an error.`;
    case 'bad_answer':
      return $localize`:@@gitlab.problem.badAnswer:GitLab's answer was not understood. Check the address.`;
    default:
      return $localize`:@@gitlab.problem.unknown:The test failed.`;
  }
}

/** GitLab's access level of the Maintainer role (Developer is 30). */
const MAINTAINER = 40;

/**
 * A GitLab test answer as the pages show it: fixed sentences and the names GitLab gave, as text only. A
 * token below Maintainer in the project is reachable, but cannot set the commit status on a
 * protected branch, so the answer says so.
 */
export function gitlabTestText(result: TestResult): string {
  if (!result.ok || !result.user) {
    return result.problem
      ? testProblemText(result.problem.code)
      : $localize`:@@gitlab.problem.unknown:The test failed.`;
  }
  if (!result.project) {
    return $localize`:@@gitlab.testOk:Connected as ${result.user.username}:user:.`;
  }
  const reachable = $localize`:@@gitlab.testOkProject:Connected as ${result.user.username}:user:; the project ${result.project.pathWithNamespace}:project: is reachable.`;
  const level = result.project.accessLevel;
  return level !== null && level < MAINTAINER
    ? `${reachable} ${$localize`:@@gitlab.belowMaintainer:The token is below Maintainer: merge request comments work, but a commit status on a protected branch (such as the default branch) is refused. Give it the Maintainer role.`}`
    : reachable;
}
