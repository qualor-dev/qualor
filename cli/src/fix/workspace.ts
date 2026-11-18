import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import path from 'node:path';
import { CliError, EXIT } from '../errors';
import { gitText, type Git } from '../git/git';

/**
 * spec §6.5: a fix is made in a scratch copy of HEAD, never in the checkout: `git worktree add` in
 * a temporary directory, removed after. `close` may be called more than once.
 */
export interface Scratch {
  root: string;
  close(): Promise<void>;
}

/**
 * The scratch copy checks out the blobs as they are (`core.autocrlf=false`), so a file the tools
 * leave alone reads as unchanged and an uploaded file is what the commit will hold.
 */
const AS_COMMITTED = ['-c', 'core.autocrlf=false'];

/** Removes the scratch directory, then the worktree entry git keeps for it (best effort). */
async function removeScratch(git: Git, parent: string, root: string): Promise<void> {
  await git(['worktree', 'remove', '--force', root]).catch(() => undefined);
  // Retries cover Windows' short delay before a stopped tool's handles close.
  rmSync(parent, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await git(['worktree', 'prune']).catch(() => undefined);
}

/**
 * `git worktree add --detach <tmp> HEAD` in a new private directory under `tempRoot`. A checkout
 * git cannot add a worktree to (not a repository, no commit) is a usage error (exit 2).
 */
export async function openScratch(git: Git, tempRoot: string): Promise<Scratch> {
  const parent = realpathSync.native(mkdtempSync(path.join(tempRoot, 'qualor-fix-')));
  const root = path.join(parent, 'checkout');
  const added = await git([...AS_COMMITTED, 'worktree', 'add', '--detach', root, 'HEAD']);
  if (added.code !== 0) {
    await removeScratch(git, parent, root);
    const why = added.stderr.trim() || `exit code ${added.code}`;
    throw new CliError(EXIT.USAGE, `cannot make a scratch copy of HEAD (git worktree add): ${why}`);
  }
  let closed = false;
  return {
    root,
    close: async () => {
      if (closed) return;
      closed = true;
      await removeScratch(git, parent, root);
    },
  };
}

/** Paths a fix never uploads and its tools may write: installed packages and Yarn's state. */
function isToolOutput(p: string): boolean {
  return p.split('/').some((segment) => segment === 'node_modules' || segment === '.yarn');
}

/** One `status --porcelain=v1 -z` entry: its two status letters and its path. */
interface StatusEntry {
  status: string;
  path: string;
}

function parseStatus(out: string): StatusEntry[] {
  const entries: StatusEntry[] = [];
  // A rename or copy is followed by its source: gone after a rename, kept after a copy.
  let source: 'renamed' | 'copied' | null = null;
  for (const field of out.split('\0')) {
    if (source !== null) {
      if (source === 'renamed') entries.push({ status: ' D', path: field });
      source = null;
    } else if (field.length >= 4) {
      const status = field.slice(0, 2);
      entries.push({ status, path: field.slice(3) });
      if (status.includes('R')) source = 'renamed';
      else if (status.includes('C')) source = 'copied';
    }
  }
  return entries;
}

const isAdded = (status: string): boolean => status === '??' || /[ARC]/.test(status);

/**
 * What the tools changed in the scratch copy: `changed` the tracked files they modified or deleted,
 * `added` the files that are new (untracked ones included); paths under `node_modules/` and `.yarn/`
 * are left out. Repository-relative, `/`-separated.
 */
export async function changedPaths(
  git: Git,
  scratch: Pick<Scratch, 'root'>,
): Promise<{ changed: string[]; added: string[] }> {
  const out = await gitText(git, [
    '-C',
    scratch.root,
    ...AS_COMMITTED,
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
  ]);
  const changed: string[] = [];
  const added: string[] = [];
  for (const entry of parseStatus(out)) {
    if (entry.path === '' || isToolOutput(entry.path)) continue;
    (isAdded(entry.status) ? added : changed).push(entry.path);
  }
  return { changed, added };
}
