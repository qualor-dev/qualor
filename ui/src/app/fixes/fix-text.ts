import type { FixSettingsAnswer } from '../api/types';

/** What decides whether a fix MR can be requested for a project, as the settings answer has it. */
export type FixPreconditions = FixSettingsAnswer['preconditions'];

/**
 * Why a fix failed, in the UI's own words. The messages of `package_manager`, `upload_refused` and
 * `unplanned_change` are the server's (the package manager's output, the rule an upload broke, the
 * change that was not planned): they are shown as they are, and only ever as text. Every other
 * code has a sentence here.
 */
export function fixFailureText(failure: { code: string; message: string }): string {
  switch (failure.code) {
    case 'package_manager':
    case 'upload_refused':
    case 'unplanned_change':
      return failure.message === '' ? failedText() : failure.message;
    case 'manifest_unsupported':
      return $localize`:@@fix.failure.manifestUnsupported:Qualor cannot edit this project's dependency files automatically.`;
    case 'missing_tool':
      return $localize`:@@fix.failure.missingTool:The fix job's image does not have the package manager this fix needs.`;
    case 'verify_failed':
      return $localize`:@@fix.failure.verifyFailed:The package manager's result still holds a vulnerable version.`;
    case 'timeout':
      return $localize`:@@fix.failure.timeout:The fix job ran out of time.`;
    case 'scm_permission':
      return $localize`:@@fix.failure.scmPermission:The connection's token may not write to the repository. Check its permissions.`;
    case 'scm_refused':
      return $localize`:@@fix.failure.scmRefused:The repository refused the change, for example because of a protected branch.`;
    case 'scm_unavailable':
      return $localize`:@@fix.failure.scmUnavailable:The repository could not be reached. Try the fix again later.`;
    case 'scm_not_bound':
      return $localize`:@@fix.failure.scmNotBound:The project is no longer mapped to a repository.`;
    case 'fixes_disabled':
      return $localize`:@@fix.failure.fixesDisabled:Fix MRs were switched off for the project or its connection.`;
    default:
      return failedText();
  }
}

function failedText(): string {
  return $localize`:@@fix.failure.unknown:The fix failed.`;
}

/** Why no fix MR exists for a package, by the reason of a `no_fix` fix. */
export function noFixText(reason: string): string {
  switch (reason) {
    case 'no_fixed_version':
      return $localize`:@@fix.noFix.noFixedVersion:No released version of this package fixes the vulnerabilities yet.`;
    case 'declined':
      return $localize`:@@fix.noFix.declined:The proposed version was declined. Qualor does not propose it again.`;
    case 'several_lines':
      return $localize`:@@fix.noFix.severalLines:Yarn classic cannot pin several release lines of this package at once.`;
    case 'not_installed':
      return $localize`:@@fix.noFix.notInstalled:The vulnerable version is no longer installed.`;
    case 'unresolvable':
      return $localize`:@@fix.noFix.unresolvable:The package manager found no way to install the fixed version.`;
    default:
      return $localize`:@@fix.noFix.unknown:There is no automatic fix for this package.`;
  }
}

/**
 * The first precondition of a fix MR request that is not met, as a sentence; null when all are.
 * The order is the order a person fixes them in: the repository, the connection's switch, then
 * monitoring.
 */
export function fixPreconditionText(p: FixPreconditions): string | null {
  if (!p.scmBound) {
    return $localize`:@@fix.precondition.notBound:The project is not mapped to a repository.`;
  }
  if (!p.fixMrsAllowed) {
    return $localize`:@@fix.precondition.notAllowed:An organisation admin must allow fix MRs on the connection.`;
  }
  if (!p.monitoringOn) {
    return $localize`:@@fix.precondition.monitoringOff:Vulnerability monitoring is off for this project.`;
  }
  return null;
}
