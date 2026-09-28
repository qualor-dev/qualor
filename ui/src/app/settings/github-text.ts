import type { ResponseBody } from '../api/types';

/*
 * The GitHub test answer's texts, apart from the lazy GitHub page: the GitLab tab's mapping
 * tests a GitHub connection too, and must not load the GitHub page's module to word the answer.
 */

type TestResult = ResponseBody<'/api/v0/scm-connections/{id}/test', 'post'>;
type ProblemCode = NonNullable<TestResult['problem']>['code'];

/** github.md §5.4: a failed test in the UI's own words (the server's text is never shown). */
export function githubProblemText(code: ProblemCode): string {
  switch (code) {
    case 'undecryptable':
      return $localize`:@@github.problem.undecryptable:The stored key can no longer be read (the server key changed). Set the App id and the private key again.`;
    case 'url_not_allowed':
      return $localize`:@@github.problem.urlNotAllowed:The server does not allow this GitHub address. Use https://api.github.com, or ask the operator to list your GitHub Enterprise Server in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'not_public':
      return $localize`:@@github.problem.notPublic:This GitHub is on an internal address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'unresolved':
      return $localize`:@@github.problem.unresolved:The GitHub host name could not be found.`;
    case 'timeout':
      return $localize`:@@github.problem.timeout:GitHub did not answer in time.`;
    case 'unreachable':
      return $localize`:@@github.problem.unreachable:GitHub could not be reached.`;
    case 'token_refused':
      return $localize`:@@github.problem.refused:GitHub refused the App's credentials. Check the App id, the private key and the server's clock.`;
    case 'not_found':
      return $localize`:@@github.problem.notFound:The repository was not found, or the App cannot see it. Use owner/repo.`;
    case 'not_installed':
      return $localize`:@@github.problem.notInstalled:The App is not installed on this repository. Install it from the App's page on GitHub.`;
    case 'permission_missing':
      return $localize`:@@github.problem.permission:The App lacks a permission, or its installation is suspended. Give it Checks and Pull requests (read and write) and accept the new permissions on the installation, or unsuspend it.`;
    case 'http_error':
      return $localize`:@@github.problem.httpError:GitHub answered with an error.`;
    case 'bad_answer':
      return $localize`:@@github.problem.badAnswer:GitHub's answer was not understood. Check the address: it is the API root, not the web address.`;
    default:
      return $localize`:@@github.problem.unknown:The test failed.`;
  }
}

/** A GitHub test answer as a page shows it: fixed sentences and the names GitHub gave, as text only. */
export function githubTestText(result: TestResult): string {
  if (!result.ok || !result.user) {
    return result.problem
      ? githubProblemText(result.problem.code)
      : $localize`:@@github.problem.unknown:The test failed.`;
  }
  return result.project
    ? $localize`:@@github.testOkRepository:Connected as ${result.user.username}:user:; the repository ${result.project.pathWithNamespace}:repository: is reachable.`
    : $localize`:@@github.testOk:Connected as ${result.user.username}:user:.`;
}
