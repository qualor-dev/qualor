import { azureProblemText } from '../settings/azure-text';

/**
 * Azure Boards link problems in the UI's own words, chosen by code. The server's `message` is a
 * fixed English text and is never shown, except a `field_refused` failure, which carries Azure
 * DevOps' own reason (cut to 500 characters by the server), shown as text.
 */

/** Why a work item could not be created, by the code of the link's failure. */
function failureCodeText(code: string): string {
  switch (code) {
    case 'permission_missing':
      return $localize`:@@boards.failure.permissionMissing:The credential may not create work items in the mapped area path of Azure DevOps.`;
    case 'not_found':
      return $localize`:@@boards.failure.notFound:Azure DevOps did not find the project, or the credential cannot see it.`;
    case 'limit_reached':
      return $localize`:@@boards.failure.limitReached:Azure DevOps refused the work item as too large.`;
    case 'not_mapped':
      return $localize`:@@boards.failure.notMapped:The project had no Azure Boards mapping when the work item was to be created.`;
    case 'finding_gone':
      return $localize`:@@boards.failure.findingGone:The finding is closed or can no longer have a work item.`;
    case 'outcome_unknown':
      return $localize`:@@boards.failure.outcomeUnknown:Qualor could not tell whether Azure DevOps created the work item.`;
    case 'type_unsupported':
      return $localize`:@@boards.failure.typeUnsupported:The mapped work item type no longer exists or needs fields Qualor does not set. Map the project again.`;
    default:
      return $localize`:@@boards.failure.unknown:The work item could not be created.`;
  }
}

/**
 * A link's failure: its own text per code. `field_refused` shows the server's message, Azure
 * DevOps' own reason for refusing a field, the one place its words reach a finding.
 */
export function boardsFailureText(failure: { code: string; message: string }): string {
  return failure.code === 'field_refused' ? failure.message : failureCodeText(failure.code);
}

/**
 * The credential problems of `BOARDS_CONNECTION_BROKEN`'s `problemCode` that the connection test's
 * words describe; any other code reads as the plain "connection has a problem".
 */
const CREDENTIAL_PROBLEMS = new Set([
  'undecryptable',
  'url_not_allowed',
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
]);

type CredentialProblem = Parameters<typeof azureProblemText>[0]['code'];

/** A refused link request (create, retry) in the UI's own words, by its code; null for others. */
export function boardsProblemText(code: string | null, problemCode?: string): string | null {
  switch (code) {
    case 'BOARDS_NOT_CONNECTED':
      return $localize`:@@boards.error.notConnected:This project has no Azure DevOps connection for Azure Boards any more. An organization admin connects Azure DevOps under Settings → Azure DevOps.`;
    case 'BOARDS_CONNECTION_BROKEN': {
      const broken = $localize`:@@boards.error.connectionBroken:The Azure DevOps connection has a problem that an organization admin must fix under Settings → Azure DevOps.`;
      return problemCode !== undefined && CREDENTIAL_PROBLEMS.has(problemCode)
        ? `${azureProblemText({ code: problemCode as CredentialProblem })} ${broken}`
        : broken;
    }
    case 'BOARDS_PROJECT_NOT_MAPPED':
      return $localize`:@@boards.error.projectNotMapped:This project is not mapped to an Azure DevOps project any more.`;
    case 'BOARDS_LINK_NOT_RETRYABLE':
      return $localize`:@@boards.error.linkNotRetryable:This can no longer be tried again: the finding is closed or can no longer have a work item, or its work item changed meanwhile.`;
    default:
      return null;
  }
}
