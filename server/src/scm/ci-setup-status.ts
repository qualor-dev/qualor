import { ScmError } from './provider';
import type { ScmConnectionRow, ScmDeps } from './connections';
import { listInstallations } from './github/installations';

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
/** A failed read is kept briefly: one transient error must not show missing permissions for a minute. */
export const CI_SETUP_FAILURE_CACHE_MS = 10_000;
const MAX_CACHED = 200;

interface Cached {
  expires: number;
  /** What the cached answer was read for: a changed address, App or key reads again. */
  fingerprint: string;
  permissions: Grants;
}

interface Grants {
  missing: CiSetupMissing[];
  granted: boolean;
}

/** Whether one GitHub App installation grants Workflows and Secrets (write); errors are ScmErrors. */
async function githubGrants(row: ScmConnectionRow, deps: ScmDeps): Promise<Grants> {
  const installations = await listInstallations(row, deps);
  const missing: CiSetupMissing[] = [];
  if (!installations.some((i) => i.workflowsWrite)) missing.push('workflows_write');
  if (!installations.some((i) => i.secretsWrite)) missing.push('secrets_write');
  return { missing, granted: installations.some((i) => i.workflowsWrite && i.secretsWrite) };
}

function statusOf(
  row: ScmConnectionRow,
  publicUrl: string | null,
  grants: Grants | null,
): CiSetupStatus {
  if (row.provider === 'gitlab') {
    if (publicUrl === null) return { available: false, reason: 'no_public_url', missing: [] };
    return row.ciSetupAllowed
      ? { available: true, reason: null, missing: [] }
      : { available: false, reason: 'not_allowed', missing: [] };
  }
  const { missing, granted } = grants ?? { missing: [], granted: false };
  if (publicUrl === null) return { available: false, reason: 'no_public_url', missing };
  return granted
    ? { available: true, reason: null, missing: [] }
    : { available: false, reason: 'missing_permissions', missing };
}

/**
 * The CI-setup status of a connection read now, without a cache: for the repository-setup job,
 * which must tell a definite "not available" from a failed read. A failed GitHub read throws its
 * ScmError instead of counting as missing permissions.
 */
export async function readCiSetupStatus(
  row: ScmConnectionRow,
  deps: ScmDeps,
  publicUrl: string | null,
): Promise<CiSetupStatus> {
  return statusOf(row, publicUrl, row.provider === 'github' ? await githubGrants(row, deps) : null);
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

  const githubPermissions = async (row: ScmConnectionRow): Promise<Grants> => {
    const fingerprint = `${row.baseUrl}|${row.appId ?? ''}|${JSON.stringify(row.tokenEnc)}`;
    const hit = cache.get(row.id);
    if (hit && hit.fingerprint === fingerprint && hit.expires > now()) return hit.permissions;
    let permissions: Grants;
    let ttl = CI_SETUP_CACHE_MS;
    try {
      permissions = await githubGrants(row, deps);
    } catch (err) {
      if (!(err instanceof ScmError)) throw err;
      warn('Could not read the GitHub App installations for the CI-setup status', {
        connectionId: row.id,
        kind: err.kind,
        reason: err.reason,
      });
      permissions = { missing: [], granted: false };
      ttl = CI_SETUP_FAILURE_CACHE_MS;
    }
    if (cache.size >= MAX_CACHED) {
      for (const [id, entry] of cache) if (entry.expires <= now()) cache.delete(id);
      if (cache.size >= MAX_CACHED) cache.clear();
    }
    cache.set(row.id, { expires: now() + ttl, fingerprint, permissions });
    return permissions;
  };

  return async (row) =>
    statusOf(row, publicUrl, row.provider === 'github' ? await githubPermissions(row) : null);
}
