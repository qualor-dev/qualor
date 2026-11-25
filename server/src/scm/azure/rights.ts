import { ScmError, type ScmErrorKind } from '../provider';
import { MAX_AUTHORS_LOOKED_UP } from '../rights-limits';
import type { AzureDevOpsClient } from './client';

/** What the check says when an answer is not one it can use; a caller may add what it is about. */
export interface RightsLogger {
  warn(details: object, message: string): void;
}

/** The kinds of answer that settle the question: this person may not (as far as Qualor can see). */
const DEFINITIVE_KINDS: ReadonlySet<ScmErrorKind> = new Set(['refused', 'not_found', 'bad_answer']);

/** A 403 is kind `auth` with reason `permission_missing`: the identity may not read the ACL. */
const isDefinitive = (err: ScmError): boolean =>
  DEFINITIVE_KINDS.has(err.kind) || err.reason === 'permission_missing';

/**
 * A 401 from the identities host or the ACL. The same credential has just read the repository (and,
 * in a reply job, the thread), so it is not dead: it lacks the scope these two reads need.
 */
const isMissingScope = (err: ScmError): boolean => err.kind === 'auth' && err.status === 401;

/**
 * What {@link azureTriageRight} found: every author may, one may not, or Qualor's own credential
 * was refused a read of the check (`unreadable`), which says nothing of the authors.
 */
export type AzureTriageRight = 'may' | 'may_not' | 'unreadable';

/**
 * Whether every one of these people may change a finding's status through a reply, or ask for a
 * review through a command: each has Contribute on the repository's Git security (bit 4 of the
 * effective allow of the repository's ACL). An author is the id of an Azure DevOps identity: it is
 * turned into a descriptor on the identities host, then asked of the ACL. Nobody else may: an
 * identity the organisation does not know, a reader, no author at all, or more than
 * `MAX_AUTHORS_LOOKED_UP` distinct authors (no request is sent for those). A definitive failure
 * (refused, 403 included, not found, an answer not understood, and a 401 of the identities or ACL
 * read, which is a scope the credential lacks) is no too, with one warn line that names its kind
 * and never the text of the answer: `unreadable` when it is an auth error (401 or 403), as that
 * refused Qualor's credential, not the author; `may_not` otherwise. A transient or rate-limited
 * failure, or a credential (a 401 of the repository read) or budget problem, is thrown, so that
 * the reply job retries, as for GitHub.
 */
export async function azureTriageRight(
  client: AzureDevOpsClient,
  repositoryId: string,
  authorIds: readonly string[],
  logger?: RightsLogger,
): Promise<AzureTriageRight> {
  // Identity ids are GUIDs, which Azure writes in either case: one person counts once.
  const authors = [...new Map(authorIds.map((id) => [id.toLowerCase(), id])).values()];
  // Unlike GitHub's and GitLab's checks, no author is no (not a vacuous yes): a comment whose
  // author is unknown (a deleted comment has none) must never change a status.
  if (authors.length === 0 || authors.length > MAX_AUTHORS_LOOKED_UP) return 'may_not';
  let rightsRead = false;
  try {
    const { projectId } = await client.repository(repositoryId);
    rightsRead = true;
    for (const author of authors) {
      const descriptor = await client.identityDescriptor(author);
      if (descriptor === null) return 'may_not';
      if (!(await client.contributeAllowed(projectId, repositoryId, descriptor))) return 'may_not';
    }
    return 'may';
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    if (!isDefinitive(err) && !(rightsRead && isMissingScope(err))) throw err;
    logger?.warn({ kind: err.kind }, 'azure devops contribute check failed');
    return err.kind === 'auth' ? 'unreadable' : 'may_not';
  }
}

/** {@link azureTriageRight} as a yes or no: only `may` may. */
export async function azureMayTriage(
  client: AzureDevOpsClient,
  repositoryId: string,
  authorIds: readonly string[],
  logger?: RightsLogger,
): Promise<boolean> {
  return (await azureTriageRight(client, repositoryId, authorIds, logger)) === 'may';
}

/**
 * Whether the identity can read what {@link azureMayTriage} reads, for the connection Test: its own
 * identity on the identities host, and the permissions of `repository`. False on a definitive
 * failure of either read (as {@link azureMayTriage} counts them) or when the identities host does
 * not know the identity; null on any other failure (a timeout, a 5xx), which says nothing either
 * way. Whether the identity itself has Contribute is not asked.
 */
export async function azureRightsReadable(
  client: AzureDevOpsClient,
  repository: { id: string; projectId: string },
  identityId: string,
): Promise<boolean | null> {
  try {
    const descriptor = await client.identityDescriptor(identityId);
    if (descriptor === null) return false;
    await client.contributeAllowed(repository.projectId, repository.id, descriptor);
    return true;
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    return isDefinitive(err) || isMissingScope(err) ? false : null;
  }
}
