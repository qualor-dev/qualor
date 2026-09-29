import { type Api, ok } from '../api/api';
import { ApiError } from '../api/errors';
import type { ItemOf } from '../api/types';

export type Branch = ItemOf<'/api/v0/projects/{id}/branches'>;

const PAGE_SIZE = 500;
/** 10 000 branches: past that the lookup stops rather than walk an endless list. */
const MAX_PAGES = 20;

/**
 * A branch of a project: the main branch when `branchId` is absent. The API has no single-branch
 * read (api.md §3), so this pages through `GET /projects/{id}/branches` until it finds it, for at
 * most {@link MAX_PAGES} pages.
 */
export async function findBranch(
  api: Api,
  projectId: string,
  branchId: string | undefined,
): Promise<Branch> {
  let cursor: string | undefined;
  for (let pages = 0; pages < MAX_PAGES; pages++) {
    const page = await ok(
      api.client.GET('/api/v0/projects/{id}/branches', {
        params: {
          path: { id: projectId },
          query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) },
        },
      }),
    );
    const found = page.items.find((b) => (branchId ? b.id === branchId : b.isMain));
    if (found) return found;
    if (!page.nextCursor || page.nextCursor === cursor) break;
    cursor = page.nextCursor;
  }
  throw notFound();
}

/** The API's 404 problem, for what the UI itself found missing. */
export function notFound(): ApiError {
  return new ApiError(404, {
    type: 'urn:qualor:problem:not-found',
    title: 'Not found',
    status: 404,
    code: 'NOT_FOUND',
  });
}

/** What a branch overview needs: which branch, its title, and where its gate result lives. */
export interface BranchView {
  id: string;
  title: string;
  isMain: boolean;
  kind: 'branch' | 'merge_request';
  /** The merge request's own title (GitLab or GitHub), or null. */
  mrTitle: string | null;
  /** The merge request's page, as the server stored it; shown only through `safeHelpUri`. */
  mrUrl: string | null;
  gateStatus: string | null;
  /** The last succeeded analysis (never a failed or stale upload); null before the first. */
  lastAnalysisId: string | null;
}

export function branchView(branch: Branch): BranchView {
  return {
    id: branch.id,
    title: branchTitle(branch),
    isMain: branch.isMain,
    kind: branch.kind,
    mrTitle: branch.mrTitle,
    mrUrl: branch.mrUrl,
    gateStatus: branch.gateStatus,
    lastAnalysisId: branch.lastAnalysisId,
  };
}

/** The project's main branch, from `GET /projects/{id}` (no paging through its branches). */
export async function mainBranchView(api: Api, projectId: string): Promise<BranchView> {
  const project = await ok(
    api.client.GET('/api/v0/projects/{id}', { params: { path: { id: projectId } } }),
  );
  const main = project.mainBranch;
  if (!main) throw notFound();
  return {
    id: main.id,
    title: main.name,
    isMain: true,
    kind: 'branch',
    mrTitle: null,
    mrUrl: null,
    gateStatus: main.gateStatus,
    lastAnalysisId: main.lastAnalysisId,
  };
}

/** "main", or "!42 feature/refund-limits → main" for a merge request. */
export function branchTitle(branch: Branch): string {
  if (branch.kind !== 'merge_request') return branch.name;
  const source = branch.mrSourceBranch ?? '';
  const target = branch.mrTargetBranch ?? '';
  const route = source && target ? `${source} → ${target}` : source || (target && `→ ${target}`);
  return route ? `!${branch.name} ${route}` : `!${branch.name}`;
}
