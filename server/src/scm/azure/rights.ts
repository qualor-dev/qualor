import type { WorkerLogger } from '../../queue/worker';
import { ScmError, type ScmErrorKind } from '../provider';
import { MAX_AUTHORS_LOOKED_UP } from '../rights-limits';
import type { AzureDevOpsClient } from './client';

/** The kinds of answer that settle the question: this person may not (as far as Qualor can see). */
const DEFINITIVE_KINDS: ReadonlySet<ScmErrorKind> = new Set(['refused', 'not_found', 'bad_answer']);

/** A 403 is kind `auth` with reason `permission_missing`: the identity may not read the ACL. */
const isDefinitive = (err: ScmError): boolean =>
  DEFINITIVE_KINDS.has(err.kind) || err.reason === 'permission_missing';

/**
 * Whether every one of these people may change a finding's status through a reply, or ask for a
 * review through a command: each has Contribute on the repository's Git security (bit 4 of the
 * effective allow of the repository's ACL). An author is the id of an Azure DevOps identity: it is
 * turned into a descriptor on the identities host, then asked of the ACL. Nobody else may: an
 * identity the organisation does not know, a reader, no author at all, or more than
 * `MAX_AUTHORS_LOOKED_UP` distinct authors (no request is sent for those). A definitive failure
 * (refused, 403 included, not found, an answer not understood) is no too, with one warn line that
 * names its kind and never the text of the answer. A transient or rate-limited failure, or a
 * credential or budget problem, is thrown, so that the reply job retries, as for GitHub.
 */
export async function azureMayTriage(
  client: AzureDevOpsClient,
  repositoryId: string,
  authorIds: readonly string[],
  logger?: Pick<WorkerLogger, 'warn'>,
): Promise<boolean> {
  // Identity ids are GUIDs, which Azure writes in either case: one person counts once.
  const authors = [...new Map(authorIds.map((id) => [id.toLowerCase(), id])).values()];
  // Unlike GitHub's and GitLab's checks, no author is no (not a vacuous yes): a comment whose
  // author is unknown (a deleted comment has none) must never change a status.
  if (authors.length === 0 || authors.length > MAX_AUTHORS_LOOKED_UP) return false;
  try {
    const { projectId } = await client.repository(repositoryId);
    for (const author of authors) {
      const descriptor = await client.identityDescriptor(author);
      if (descriptor === null) return false;
      if (!(await client.contributeAllowed(projectId, repositoryId, descriptor))) return false;
    }
    return true;
  } catch (err) {
    if (!(err instanceof ScmError) || !isDefinitive(err)) throw err;
    logger?.warn({ kind: err.kind }, 'azure devops contribute check failed');
    return false;
  }
}
