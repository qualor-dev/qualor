import type { FixSettingsAnswer } from '../api/types';

/** What decides whether a fix MR can be requested for a project, as the settings answer has it. */
export type FixPreconditions = FixSettingsAnswer['preconditions'];

/**
 * Why a fix failed, in the UI's own words. The messages of `package_manager`, `upload_refused` and
 * `unplanned_change` are the server's (the package manager's output, the rule an upload broke, the
 * change that was not planned): they are shown as they are, and only ever as text. Ruling FW12:
 * `manifest_unsupported`, `missing_tool`, `verify_failed` and `timeout` have a sentence here, then
 * the fix job's own message (which file or layout, which tool), as text. The SCM codes have only
 * their sentence.
 */
export function fixFailureText(failure: { code: string; message: string }): string {
  switch (failure.code) {
    case 'package_manager':
    case 'upload_refused':
    case 'unplanned_change':
      return failure.message === '' ? failedText() : failure.message;
    case 'manifest_unsupported':
      return withMessage(
        $localize`:@@fix.failure.manifestUnsupported:Qualor cannot edit this project's dependency files automatically.`,
        failure.message,
      );
    case 'missing_tool':
      return withMessage(
        $localize`:@@fix.failure.missingTool:The fix job's image does not have the package manager this fix needs.`,
        failure.message,
      );
    case 'verify_failed':
      return withMessage(
        $localize`:@@fix.failure.verifyFailed:The package manager's result still holds a vulnerable version.`,
        failure.message,
      );
    case 'timeout':
      return withMessage(
        $localize`:@@fix.failure.timeout:The fix job ran out of time.`,
        failure.message,
      );
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

/** The UI's sentence, then the fix job's own message when it sent one. */
function withMessage(sentence: string, message: string): string {
  const own = message.trim();
  return own === '' ? sentence : `${sentence} ${own}`;
}

/** The reasons of a `no_fix` fix (spec §6.4); an open MR whose refresh found no fix keeps one (R8). */
const NO_FIX_REASONS = new Set([
  'no_fixed_version',
  'declined',
  'several_lines',
  'not_installed',
  'unresolvable',
]);

/**
 * Ruling FW12: why a fix failed or has no fix, by its `failure`: a no-fix reason in
 * {@link noFixText}'s words whatever the state (an open MR whose refresh found no fix carries
 * one), any other code in {@link fixFailureText}'s.
 */
export function fixReasonText(state: string, failure: { code: string; message: string }): string {
  return state === 'no_fix' || isNoFixReason(failure.code)
    ? noFixText(failure.code)
    : fixFailureText(failure);
}

/** Whether `code` is a reason for no fix rather than a failure. */
export function isNoFixReason(code: string): boolean {
  return NO_FIX_REASONS.has(code);
}

/** Why no fix MR exists for a package, by the reason of a `no_fix` fix. */
export function noFixText(reason: string): string {
  switch (reason) {
    case 'no_fixed_version':
      return $localize`:@@fix.noFix.noFixedVersion:No released version of this package fixes the vulnerabilities yet.`;
    case 'declined':
      return $localize`:@@fix.noFix.declined:The proposed version was declined. Qualor does not propose it again.`;
    case 'several_lines':
      return $localize`:@@fix.noFix.severalLines:The package is on several release lines that cannot all be moved to a fixed version in one change.`;
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
    return $localize`:@@fix.precondition.notAllowed:An organization admin must allow fix MRs on the connection.`;
  }
  if (!p.monitoringOn) {
    return $localize`:@@fix.precondition.monitoringOff:Vulnerability monitoring is off for this project.`;
  }
  return null;
}
