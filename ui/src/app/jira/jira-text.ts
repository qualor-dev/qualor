/**
 * Jira problems in the UI's own words (Jira spec §6.1). The server's `message` is a fixed English
 * text and is never shown, except a `field_refused` failure, which carries Jira's own reason. Tasks
 * 11 and 12 reuse these for the project panel and the link states.
 */

/** What went wrong, by the code of a test answer, a background problem or a link failure. */
export function jiraProblemText(code: string): string {
  switch (code) {
    case 'undecryptable':
      return $localize`:@@jira.problem.undecryptable:The stored token can no longer be read (the server key changed).`;
    case 'url_not_allowed':
      return $localize`:@@jira.problem.urlNotAllowed:The server no longer allows this Jira address.`;
    case 'not_public':
      return $localize`:@@jira.problem.notPublic:This Jira is on an internal address that the server does not allow.`;
    case 'unresolved':
      return $localize`:@@jira.problem.unresolved:The Jira host name could not be found.`;
    case 'timeout':
      return $localize`:@@jira.problem.timeout:Jira did not answer in time.`;
    case 'unreachable':
      return $localize`:@@jira.problem.unreachable:Jira could not be reached.`;
    case 'token_refused':
      return $localize`:@@jira.problem.tokenRefused:Jira refused the token or the email.`;
    case 'not_found':
      return $localize`:@@jira.problem.notFound:Jira could not find what was asked for, or the account cannot see it.`;
    case 'http_error':
      return $localize`:@@jira.problem.httpError:Jira answered with an error.`;
    case 'bad_answer':
      return $localize`:@@jira.problem.badAnswer:Jira's answer was not understood. Check the address.`;
    case 'permission_missing':
      return $localize`:@@jira.problem.permissionMissing:The account lacks a permission in Jira.`;
    case 'no_projects':
      return $localize`:@@jira.problem.noProjects:The account sees no Jira project.`;
    case 'captcha':
      return $localize`:@@jira.problem.captcha:Jira asks for a CAPTCHA after too many failed sign-ins.`;
    case 'redirected':
      return $localize`:@@jira.problem.redirected:Jira answered with a redirect, which Qualor does not follow.`;
    case 'rate_limited':
      return $localize`:@@jira.problem.rateLimited:Jira is limiting requests. Qualor tries again later.`;
    case 'limit_reached':
      return $localize`:@@jira.problem.limitReached:Jira refused the request as too large.`;
    case 'not_mapped':
      return $localize`:@@jira.problem.notMapped:The project had no Jira mapping when the Jira issue was to be created.`;
    case 'finding_gone':
      return $localize`:@@jira.problem.findingGone:The finding no longer exists.`;
    case 'outcome_unknown':
      return $localize`:@@jira.problem.outcomeUnknown:Qualor could not tell whether Jira created the issue.`;
    default:
      return $localize`:@@jira.problem.unknown:The Jira request failed.`;
  }
}

/** What to do about it. */
export function jiraProblemFix(code: string): string {
  switch (code) {
    case 'undecryptable':
      return $localize`:@@jira.fix.undecryptable:Enter the token again and save.`;
    case 'url_not_allowed':
    case 'not_public':
      return $localize`:@@jira.fix.hosts:Ask the operator to list the host in QUALOR_JIRA_INTERNAL_HOSTS, or use the address of a Jira that is reachable from the internet.`;
    case 'unresolved':
    case 'unreachable':
    case 'timeout':
      return $localize`:@@jira.fix.network:Check the address and that the Qualor server can reach Jira, then test again.`;
    case 'token_refused':
      return $localize`:@@jira.fix.tokenRefused:Check the token (and, on Jira Cloud, the email), then save it again.`;
    case 'captcha':
      return $localize`:@@jira.fix.captcha:Sign in to Jira in a browser with the same account and solve the CAPTCHA, then test again.`;
    case 'redirected':
      return $localize`:@@jira.fix.redirected:Use the final address of your Jira, without a redirect.`;
    case 'permission_missing':
    case 'no_projects':
      return $localize`:@@jira.fix.permission:Give the account the Browse projects and Create issues permissions in the Jira project.`;
    case 'bad_answer':
      return $localize`:@@jira.fix.badAnswer:Check the address, and that no sign-in page sits in front of Jira.`;
    case 'not_mapped':
      return $localize`:@@jira.fix.notMapped:Map the project to a Jira project again, then try again.`;
    case 'rate_limited':
    case 'http_error':
    case 'not_found':
    case 'limit_reached':
    case 'finding_gone':
    case 'outcome_unknown':
    default:
      return $localize`:@@jira.fix.tryAgain:Try again later.`;
  }
}

/**
 * A failure of a test or a link: its own text per code. `field_refused` shows the server's message,
 * Jira's own reason for refusing a field, the one place its words reach users.
 */
export function jiraFailureText(failure: { code: string; message: string }): string {
  return failure.code === 'field_refused' ? failure.message : jiraProblemText(failure.code);
}
