import { ScmError } from './provider';
import type { ScmConnectionRow, ScmDeps } from './connections';
import { listInstallationRepositories } from './github/installations';

export type CiSetupReason = 'not_allowed' | 'missing_permissions' | 'no_public_url';
export type CiSetupMissing = 'workflows_write' | 'secrets_write';

/** Whether Qualor can set up CI through a connection, and if not, why (the Connections page). */
export interface CiSetupStatus {
  available: boolean;
  reason: CiSetupReason | null;
  missing: CiSetupMissing[];
}

/** How long a GitHub connection's permissions are kept: the Connections page must not call GitHub on every render. */
export const CI_SETUP_CACHE_MS = 60_000;
const MAX_CACHED = 200;

interface Cached {
  expires: number;
  /** What the cached answer was read for: a changed address, App or key reads again. */
  fingerprint: string;
  permissions: { missing: CiSetupMissing[]; granted: boolean };
}

/**
 * The CI-setup status of a connection. GitLab needs the connection's setting; GitHub needs an
 * installation granting Workflows and Secrets (write), read from the App's installations and kept
 * for {@link CI_SETUP_CACHE_MS} per connection. An SCM error while reading counts as missing
 * permissions (no names), and is logged without anything the provider said.
 */
export function createCiSetupStatus(options: {
  deps: ScmDeps;
  publicUrl: string | null;
  warn: (message: string, context: Record<string, unknown>) => void;
  now?: () => number;
}): (row: ScmConnectionRow) => Promise<CiSetupStatus> {
  const { deps, publicUrl, warn, now = Date.now } = options;
  const cache = new Map<string, Cached>();

  const githubPermissions = async (row: ScmConnectionRow): Promise<Cached['permissions']> => {
    const fingerprint = `${row.baseUrl}|${row.appId ?? ''}|${JSON.stringify(row.tokenEnc)}`;
    const hit = cache.get(row.id);
    if (hit && hit.fingerprint === fingerprint && hit.expires > now()) return hit.permissions;
    let permissions: Cached['permissions'];
    try {
      const { installations } = await listInstallationRepositories(row, deps, undefined, {
        page: 1,
        perPage: 100,
      });
      const missing: CiSetupMissing[] = [];
      if (!installations.some((i) => i.workflowsWrite)) missing.push('workflows_write');
      if (!installations.some((i) => i.secretsWrite)) missing.push('secrets_write');
      permissions = {
        missing,
        granted: installations.some((i) => i.workflowsWrite && i.secretsWrite),
      };
    } catch (err) {
      if (!(err instanceof ScmError)) throw err;
      warn('Could not read the GitHub App installations for the CI-setup status', {
        connectionId: row.id,
        kind: err.kind,
        reason: err.reason,
      });
      permissions = { missing: [], granted: false };
    }
    if (cache.size >= MAX_CACHED) {
      for (const [id, entry] of cache) if (entry.expires <= now()) cache.delete(id);
      if (cache.size >= MAX_CACHED) cache.clear();
    }
    cache.set(row.id, { expires: now() + CI_SETUP_CACHE_MS, fingerprint, permissions });
    return permissions;
  };

  return async (row) => {
    if (row.provider === 'gitlab') {
      if (publicUrl === null) return { available: false, reason: 'no_public_url', missing: [] };
      return row.ciSetupAllowed
        ? { available: true, reason: null, missing: [] }
        : { available: false, reason: 'not_allowed', missing: [] };
    }
    const { missing, granted } = await githubPermissions(row);
    if (publicUrl === null) return { available: false, reason: 'no_public_url', missing };
    return granted
      ? { available: true, reason: null, missing: [] }
      : { available: false, reason: 'missing_permissions', missing };
  };
}
