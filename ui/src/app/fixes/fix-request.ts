import { type Api, done, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import type { DependencyFix } from '../api/types';

/**
 * A fix as a vulnerability item or an issue embeds it, and as a request answers it. A fix of the
 * project's list has more fields (its package, its branch); the pill needs only these.
 */
export type FixShown = Pick<
  DependencyFix,
  'id' | 'state' | 'refresh' | 'targetVersion' | 'mrNumber' | 'mrUrl' | 'failure' | 'updatedAt'
>;

/** The package a fix MR is for: the vulnerability item's ecosystem and the package's name. */
export interface FixTarget {
  ecosystem: string;
  packageName: string;
}

/** Asks a fix MR for a package of the main branch; the answer is the fix, `requested`. */
export function createFix(api: Api, projectId: string, body: FixTarget): Promise<FixShown> {
  return ok(
    api.client.POST('/api/v0/projects/{id}/fixes', { params: { path: { id: projectId } }, body }),
  );
}

/** Retry (an ended fix) and Create again: the fix is `requested` again. */
export function retryFix(api: Api, id: string): Promise<FixShown> {
  return ok(api.client.POST('/api/v0/fixes/{id}/retry', { params: { path: { id } } }));
}

export function cancelFix(api: Api, id: string): Promise<void> {
  return done(api.client.DELETE('/api/v0/fixes/{id}', { params: { path: { id } } }));
}

/**
 * A refused request in the UI's words. A full project says how full ("5 of 5 fix MRs are open")
 * when `maxOpen` is known; every other problem has its own text (`problemMessage`).
 */
export function fixRequestError(err: unknown, maxOpen?: number): string {
  if (err instanceof ApiError && err.code === 'FIX_LIMIT_REACHED' && maxOpen !== undefined) {
    const open = maxOpen;
    return $localize`:@@fix.request.limit:${open}:open: of ${maxOpen}:max: fix MRs are open. Close or cancel one first.`;
  }
  return problemMessage(err);
}

/**
 * Whether a shown fix is still moving: waiting for the job, being prepared or written, or an open
 * MR the job rebuilds. A page reads its data again while one is (like a pending Jira link).
 */
export function fixPending(fix: FixShown | null | undefined): boolean {
  if (!fix) return false;
  return (
    fix.state === 'requested' ||
    fix.state === 'preparing' ||
    fix.state === 'committing' ||
    (fix.state === 'open' && fix.refresh)
  );
}

/** The Trivy package type of a lockfile's name; the server reads the family of it. */
const LOCKFILE_ECOSYSTEM: Readonly<Record<string, string>> = {
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'go.mod': 'gomod',
  'go.sum': 'gomod',
  'pom.xml': 'pom',
  'uv.lock': 'uv',
  'poetry.lock': 'poetry',
};

/**
 * The ecosystem of a Trivy issue, read from the lockfile it was found in (an issue does not carry
 * one); null for a file with no automatic fix.
 */
export function ecosystemOfLockfile(path: string | null): string | null {
  if (path === null) return null;
  const name = path.slice(path.lastIndexOf('/') + 1);
  return Object.hasOwn(LOCKFILE_ECOSYSTEM, name) ? (LOCKFILE_ECOSYSTEM[name] ?? null) : null;
}
