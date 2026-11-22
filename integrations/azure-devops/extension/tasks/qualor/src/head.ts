/** A full commit id as Azure Pipelines and git print it (SHA-1 or SHA-256, lower case). */
const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export const PROBLEM_SHALLOW =
  'The pull request head is not in the clone. Set fetchDepth: 0 on the checkout step.';

function fullSha(value: string | undefined): string | null {
  const v = value?.trim();
  return v !== undefined && FULL_SHA.test(v) ? v : null;
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
 * when git exits with an error.
 */
export async function headCheckout(
  git: (args: string[]) => Promise<string>,
  env: Readonly<Record<string, string | undefined>>,
): Promise<{ checkedOut: string | null } | { problem: string }> {
  if (env['BUILD_REASON']?.trim() !== 'PullRequest') return { checkedOut: null };
  const named = fullSha(env['SYSTEM_PULLREQUEST_SOURCECOMMITID']);
  const merge = fullSha(env['BUILD_SOURCEVERSION']) ?? 'HEAD';
  const wanted = named === null ? `${merge}^2^{commit}` : `${named}^{commit}`;
  let head: string;
  try {
    head = (await git(['rev-parse', '--verify', '--quiet', wanted])).trim();
  } catch {
    return { problem: PROBLEM_SHALLOW };
  }
  const current = (await git(['rev-parse', 'HEAD'])).trim();
  if (current === head) return { checkedOut: null };
  await git(['checkout', '--detach', head]);
  return { checkedOut: head };
}
