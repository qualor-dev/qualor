import type { Report } from '@qualor/shared';
import type { Logger } from '../log';
import type { Warnings } from '../warnings';
import { GIT_FETCH_TIMEOUT_MS, type Git } from './git';

export type Baseline = Report['scm']['baseline'];

export interface FetchPolicy {
  autoFetch: boolean;
  /** `git fetch --deepen=N` steps tried before `--unshallow`. */
  deepenSteps: readonly number[];
}

export interface BaselineContext {
  log: Logger;
  warnings: Warnings;
}

export const DEFAULT_DEEPEN_STEPS: readonly number[] = [50, 500];
export const REVISION = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

async function hasCommit(git: Git, rev: string): Promise<boolean> {
  return (await git(['rev-parse', '--verify', '--quiet', `${rev}^{commit}`])).code === 0;
}

async function isShallow(git: Git): Promise<boolean> {
  const r = await git(['rev-parse', '--is-shallow-repository']);
  return r.code === 0 && r.stdout.trim() === 'true';
}

async function validBranch(git: Git, name: string): Promise<boolean> {
  if (name.startsWith('-')) return false;
  return (await git(['check-ref-format', `refs/heads/${name}`])).code === 0;
}

async function fetch(git: Git, args: readonly string[], log: Logger): Promise<boolean> {
  log.info(`git fetch ${args.join(' ')}`);
  const r = await git(['fetch', '--no-tags', '--quiet', '--no-recurse-submodules', ...args], {
    timeoutMs: GIT_FETCH_TIMEOUT_MS,
  });
  if (r.code !== 0) log.debug(`git fetch failed: ${r.stderr.trim()}`);
  return r.code === 0;
}

async function mergeBase(git: Git, ref: string): Promise<string | null> {
  const r = await git(['merge-base', 'HEAD', ref]);
  const sha = r.stdout.trim();
  return r.code === 0 && REVISION.test(sha) ? sha : null;
}

function unavailable(kind: Baseline['kind'], why: string, ctx: BaselineContext): Baseline {
  ctx.warnings.add('BASELINE_UNAVAILABLE', `the new-code baseline could not be determined: ${why}`);
  ctx.log.warn(`new code unavailable: ${why}`);
  return { revision: null, kind, status: 'unavailable' };
}

/** MR and branch analyses: merge-base with origin/<target>, fetching what a shallow clone lacks. */
export async function mergeBaseBaseline(
  git: Git,
  target: string,
  policy: FetchPolicy,
  ctx: BaselineContext,
): Promise<Baseline> {
  if (!(await validBranch(git, target))) {
    return unavailable('merge_base', `"${target}" is not a valid branch name`, ctx);
  }
  const ref = `refs/remotes/origin/${target}`;
  const refspec = `+refs/heads/${target}:${ref}`;
  const local = await hasCommit(git, ref);
  if (!policy.autoFetch) {
    if (!local) {
      return unavailable(
        'merge_base',
        `origin/${target} is not in the clone and scm.autoFetch is false`,
        ctx,
      );
    }
  } else if (!(await fetch(git, ['origin', refspec], ctx.log))) {
    // Always refreshed when autoFetch is on: a cached workspace's origin/<target> can be stale,
    // which would move the merge-base back and count the target's newer commits as new code.
    if (!local) return unavailable('merge_base', `fetching origin/${target} failed`, ctx);
    // Not a warning: a checkout without credentials (GitHub's with persist-credentials: false and
    // fetch-depth: 0, github.md §11) has just fetched the target and cannot fetch it again.
    ctx.log.info(`could not refresh origin/${target}; using the copy already in the clone`);
  }
  let base = await mergeBase(git, ref);
  if (base === null && policy.autoFetch && (await isShallow(git))) {
    for (const depth of policy.deepenSteps) {
      if (!(await fetch(git, [`--deepen=${depth}`, 'origin', refspec], ctx.log))) break;
      base = await mergeBase(git, ref);
      if (base !== null) break;
    }
    if (
      base === null &&
      (await isShallow(git)) &&
      (await fetch(git, ['--unshallow', 'origin', refspec], ctx.log))
    ) {
      base = await mergeBase(git, ref);
    }
  }
  if (base === null) {
    return unavailable(
      'merge_base',
      `HEAD and origin/${target} have no common commit in this clone${policy.autoFetch ? '' : ' (scm.autoFetch is false)'}`,
      ctx,
    );
  }
  return { revision: base, kind: 'merge_base', status: 'ok' };
}

/** Main-branch analyses: the server's baseline commit, fetched by SHA if the clone lacks it. */
export async function serverBaselineCommit(
  git: Git,
  revision: string | null,
  policy: FetchPolicy,
  ctx: BaselineContext,
): Promise<Baseline> {
  if (revision === null)
    return { revision: null, kind: 'server_baseline', status: 'first_analysis' };
  const ok: Baseline = { revision, kind: 'server_baseline', status: 'ok' };
  if (!REVISION.test(revision))
    return unavailable('server_baseline', 'the server returned an invalid revision', ctx);
  if (await hasCommit(git, revision)) return ok;
  if (!policy.autoFetch) {
    return unavailable(
      'server_baseline',
      `${revision} is not in the clone and scm.autoFetch is false`,
      ctx,
    );
  }
  if ((await fetch(git, ['origin', revision], ctx.log)) && (await hasCommit(git, revision)))
    return ok;
  if (await isShallow(git)) {
    for (const depth of policy.deepenSteps) {
      if (!(await fetch(git, [`--deepen=${depth}`, 'origin'], ctx.log))) break;
      if (await hasCommit(git, revision)) return ok;
    }
    if (
      (await isShallow(git)) &&
      (await fetch(git, ['--unshallow', 'origin'], ctx.log)) &&
      (await hasCommit(git, revision))
    ) {
      return ok;
    }
  }
  return unavailable('server_baseline', `${revision} could not be fetched from origin`, ctx);
}
