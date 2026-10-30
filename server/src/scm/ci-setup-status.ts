import { ScmError } from './provider';
import type { ScmConnectionRow, ScmDeps } from './connections';
import { listInstallations, type GitHubInstallationAccess } from './github/installations';

export type CiSetupReason = 'not_allowed' | 'missing_permissions' | 'no_public_url';
/**
 * What a GitHub CI setup needs from one installation, in write: Contents (the branch), Workflows
 * (the workflow file) and Secrets (QUALOR_TOKEN).
 */
export const CI_SETUP_MISSING = ['contents_write', 'workflows_write', 'secrets_write'] as const;
export type CiSetupMissing = (typeof CI_SETUP_MISSING)[number];

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

const GRANTED: Record<CiSetupMissing, (i: GitHubInstallationAccess) => boolean> = {
  contents_write: (i) => i.contentsWrite,
  workflows_write: (i) => i.workflowsWrite,
  secrets_write: (i) => i.secretsWrite,
};

/** What one installation lacks for CI setup. */
function lacks(installation: GitHubInstallationAccess | null): CiSetupMissing[] {
  return CI_SETUP_MISSING.filter((p) => installation === null || !GRANTED[p](installation));
}

/**
 * Whether one GitHub App installation grants Contents, Workflows and Secrets (write); errors are
 * ScmErrors. `missing` is what the best installation lacks (the first that grants the most of the
 * three): permissions split over installations do not add up, since a run changes a repository
 * through its own installation only.
 */
async function githubGrants(row: ScmConnectionRow, deps: ScmDeps): Promise<Grants> {
  const installations = await listInstallations(row, deps);
  let missing = lacks(null);
  for (const installation of installations) {
    const lacking = lacks(installation);
    if (lacking.length < missing.length) missing = lacking;
  }
  return { missing, granted: missing.length === 0 };
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
 * installation granting Contents, Workflows and Secrets (write), read from the App's installations
 * and kept for {@link CI_SETUP_CACHE_MS} per connection. An SCM error while reading counts as
 * missing permissions (no names), and is logged without anything the provider said.
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
