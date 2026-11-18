import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
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

/** The empty directory, beside the scratch copy, that its git calls take their hooks from. */
const NO_HOOKS = 'no-hooks';

/**
 * Git's settings for every call on a scratch copy:
 * - `core.autocrlf=false`: blobs are checked out and staged as they are, whatever the job's own
 *   configuration says (`.gitattributes` still applies);
 * - ruling T12d: no hook of the checkout runs (`post-checkout` on `worktree add`): hooks come from
 *   an empty directory, and no file-system monitor is started.
 */
export function scratchGitOptions(root: string): string[] {
  return [
    '-c',
    'core.autocrlf=false',
    '-c',
    `core.hooksPath=${path.join(path.dirname(root), NO_HOOKS)}`,
    '-c',
    'core.fsmonitor=false',
  ];
}

/** Git in the scratch copy `root`, with {@link scratchGitOptions}. */
export function inScratch(root: string, args: readonly string[]): string[] {
  return [...scratchGitOptions(root), '-C', root, ...args];
}

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
  mkdirSync(path.join(parent, NO_HOOKS));
  const added = await git([
    ...scratchGitOptions(root),
    'worktree',
    'add',
    '--detach',
    root,
    'HEAD',
  ]);
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
  const out = await gitText(
    git,
    inScratch(scratch.root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']),
  );
  const changed: string[] = [];
  const added: string[] = [];
  for (const entry of parseStatus(out)) {
    if (entry.path === '' || isToolOutput(entry.path)) continue;
    (isAdded(entry.status) ? added : changed).push(entry.path);
  }
  return { changed, added };
}

/**
 * Ruling T12e: the files as a commit holds them. They are staged in the scratch copy's own index
 * (`git add`, which applies `.gitattributes`: a file checked out with CRLF for `eol=crlf` goes
 * back to LF), then read back from the index as bytes (`git show :<path>`).
 */
export async function committedForm(
  git: Git,
  scratch: Pick<Scratch, 'root'>,
  paths: readonly string[],
): Promise<Buffer[]> {
  await gitText(git, inScratch(scratch.root, ['--literal-pathspecs', 'add', '--', ...paths]));
  const blobs: Buffer[] = [];
  for (const p of paths) {
    const chunks: Buffer[] = [];
    const r = await git(inScratch(scratch.root, ['show', `:${p}`]), {
      onStdout: (chunk) => {
        chunks.push(chunk);
        return true;
      },
    });
    if (r.code !== 0) {
      const why = r.stderr.trim() || `exit code ${r.code}`;
      throw new CliError(EXIT.USAGE, `git show :${p} failed: ${why}`);
    }
    blobs.push(Buffer.concat(chunks));
  }
  return blobs;
}
