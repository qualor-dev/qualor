/** A full commit id as git prints it (SHA-1 or SHA-256, lower case). */
const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export const PROBLEM_SHALLOW =
  'The pull request head is not in the clone. Set fetchDepth: 0 on the checkout step.';
const PROBLEM_UNREADABLE = 'Could not read the pull request head from the clone: ';

/**
 * Every git call on the agent: no hooks (`checkout` would run `post-checkout`) and no fsmonitor
 * command, whatever the clone's or the agent's git config says.
 */
const SAFE_GIT = ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false'];

/** A commit id from a pipeline variable, in any case, as the CLI reads it; else null. */
function fullSha(value: string | undefined): string | null {
  const v = value?.trim().toLowerCase();
  return v !== undefined && FULL_SHA.test(v) ? v : null;
}

/**
 * Why a failed `rev-parse --verify --quiet` failed. Exit code 1 means the commit is not in the
 * clone; anything else (git missing, not a repository, `safe.directory`) is named by the first
 * line of git's standard error, or by the error itself when git wrote nothing.
 */
function revParseProblem(err: unknown): string {
  const { code, stderr } = (err ?? {}) as { code?: unknown; stderr?: unknown };
  if (code === 1) return PROBLEM_SHALLOW;
  const firstLine = (text: string): string => text.trim().split(/\r?\n/)[0] ?? '';
  const detail =
    (typeof stderr === 'string' ? firstLine(stderr) : '') ||
    firstLine(err instanceof Error ? err.message : String(err));
  return PROBLEM_UNREADABLE + detail;
}

/**
 * In a pull request build, checks out the pull request head instead of the merge commit Azure
 * checks out, so the scan reports `checkout: head` and its findings sit on the source branch's
 * lines.
 *
 * The head is `SYSTEM_PULLREQUEST_SOURCECOMMITID` when it is a full commit id, else the second
 * parent of the merge commit (Azure DevOps Server 2022 may not set the variable):
 * `BUILD_SOURCEVERSION^2`, or `HEAD^2` without that variable. The merge commit is named rather
 * than taken from HEAD so that a second run in the same job finds HEAD already on the head.
 * A shallow clone (`fetchDepth: 1`) does not hold the head: that is a problem, not a scan of the
 * merge commit.
 *
 * `git` runs git in the sources directory and resolves with its standard output; it rejects
 * with Node's execFile error (`code` = the exit code, `stderr`) when git fails.
 */
export async function headCheckout(
  git: (args: string[]) => Promise<string>,
  env: Readonly<Record<string, string | undefined>>,
): Promise<{ checkedOut: string | null } | { problem: string }> {
  if (env['BUILD_REASON']?.trim() !== 'PullRequest') return { checkedOut: null };
  const run = (...args: string[]): Promise<string> => git([...SAFE_GIT, ...args]);
  const named = fullSha(env['SYSTEM_PULLREQUEST_SOURCECOMMITID']);
  const merge = fullSha(env['BUILD_SOURCEVERSION']) ?? 'HEAD';
  const wanted = named === null ? `${merge}^2^{commit}` : `${named}^{commit}`;
  let head: string;
  try {
    head = (await run('rev-parse', '--verify', '--quiet', wanted)).trim();
  } catch (err) {
    return { problem: revParseProblem(err) };
  }
  const current = (await run('rev-parse', 'HEAD')).trim();
  if (current === head) return { checkedOut: null };
  await run('checkout', '--detach', head);
  return { checkedOut: head };
}
