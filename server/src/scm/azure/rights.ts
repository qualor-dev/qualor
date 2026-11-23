import type { WorkerLogger } from '../../queue/worker';
import { MAX_AUTHORS_LOOKED_UP } from '../../review/reply-sides';
import { ScmError } from '../provider';
import type { AzureDevOpsClient } from './client';

/**
 * Whether every one of these people may change a finding's status through a reply, or ask for a
 * review through a command: each has Contribute on the repository's Git security (bit 4 of the
 * effective allow of the repository's ACL). An author is the id of an Azure DevOps identity: it is
 * turned into a descriptor on the identities host, then asked of the ACL. Nobody else may: an
 * identity the organisation does not know, a reader, no author at all, or more than
 * `MAX_AUTHORS_LOOKED_UP` distinct authors (no request is sent for those). Any provider failure
 * means no too (fail closed): one warn line names its kind and never the text of the answer.
 */
export async function azureMayTriage(
  client: AzureDevOpsClient,
  repositoryId: string,
  authorIds: readonly string[],
  logger?: Pick<WorkerLogger, 'warn'>,
): Promise<boolean> {
  const authors = [...new Set(authorIds)];
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
    if (!(err instanceof ScmError)) throw err;
    logger?.warn({ kind: err.kind }, 'azure devops contribute check failed');
    return false;
  }
}
