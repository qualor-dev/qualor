import { normalizeRepoPath, type LineRange, type Report, type ReportFile } from '@qualor/shared';
import type { Settings } from '../config/settings';
import type { CiInfo } from '../config/ci';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import { BASELINE_WARNING_MESSAGES, type NewCodeBaselineClient } from '../server/baseline-client';
import type { Warnings } from '../warnings';
import {
  DEFAULT_DEEPEN_STEPS,
  mergeBaseBaseline,
  REVISION,
  serverBaselineCommit,
  type Baseline,
  type BaselineContext,
  type FetchPolicy,
} from './baseline';
import { parseBinaryPaths, parseNameStatusZ, parseUnifiedDiff } from './diff';
import { gitText, type Git } from './git';

export type NewLines = NonNullable<ReportFile['newLines']>;

export interface ScmFlags {
  branch?: string;
  mr?: string;
  mrTarget?: string;
}

export interface ScmResolution {
  scm: Report['scm'];
  /** undefined when the baseline is not `ok` (newLines omitted, report-format §6, ruling C5). */
  newLines(path: string): NewLines | undefined;
}

export interface ResolveScmOptions {
  git: Git;
  settings: Settings;
  flags: ScmFlags;
  baselineClient: NewCodeBaselineClient | null;
  warnings: Warnings;
  log: Logger;
  deepenSteps?: readonly number[];
}

export interface DiffResult {
  renames: { from: string; to: string }[];
  /**
   * `undefined` for a path git reports as a binary diff (report-format §6 has no line-level
   * shape for that): a modified binary file's content cannot be split into changed lines, so
   * omitting `newLines` is the honest answer, unlike `[]` ("unchanged") which would hide a real
   * change from new-code gating. An *added* binary file is still `'all'`, from the `added` set
   * below, since "the whole file is new" needs no line numbers.
   */
  newLines(path: string): NewLines | undefined;
}

function repoPath(p: string): string | null {
  try {
    return normalizeRepoPath(p);
  } catch {
    return null;
  }
}

/** Ruling C15: the working tree against the baseline, rename-aware, relative to the scan root. */
export async function diffAgainst(git: Git, baseline: string): Promise<DiffResult> {
  const statuses = parseNameStatusZ(
    await gitText(git, [
      'diff',
      '--name-status',
      '-z',
      '-M',
      '--relative',
      '--no-ext-diff',
      baseline,
      '--',
    ]),
  );
  // --inter-hunk-context=0 and --no-textconv are belt and braces alongside GIT_OPTIONS'
  // `-c diff.interHunkContext=0` and parseUnifiedDiff's body-walk: they stop a merged hunk or a
  // .gitattributes textconv driver from ever reaching the parser in the first place.
  const patchText = await gitText(git, [
    'diff',
    '-U0',
    '--no-color',
    '--no-ext-diff',
    '--no-textconv',
    '--inter-hunk-context=0',
    '-M',
    '--relative',
    '--src-prefix=a/',
    '--dst-prefix=b/',
    baseline,
    '--',
  ]);
  const patch = parseUnifiedDiff(patchText);
  const binary = new Set(
    [...parseBinaryPaths(patchText)].map(repoPath).filter((p): p is string => p !== null),
  );
  const tracked = new Set(
    (await gitText(git, ['ls-files', '-z']))
      .split('\u0000')
      .map(repoPath)
      .filter((p): p is string => p !== null),
  );
  const added = new Set<string>();
  const renames: { from: string; to: string }[] = [];
  for (const entry of statuses) {
    const to = repoPath(entry.path);
    if (to === null) continue;
    if (entry.status === 'A' || entry.status === 'C') added.add(to);
    if (entry.status === 'R' && entry.from !== undefined) {
      const from = repoPath(entry.from);
      if (from !== null) renames.push({ from, to });
    }
  }
  const ranges = new Map<string, LineRange[]>();
  for (const [p, r] of patch) {
    const normalized = repoPath(p);
    if (normalized !== null) ranges.set(normalized, r);
  }
  return {
    renames,
    newLines: (p) => {
      if (added.has(p) || !tracked.has(p)) return 'all';
      if (binary.has(p)) return undefined;
      return ranges.get(p) ?? [];
    },
  };
}

async function currentBranch(git: Git): Promise<string | null> {
  const r = await git(['symbolic-ref', '--short', '-q', 'HEAD']);
  const name = r.stdout.trim();
  return r.code === 0 && name !== '' ? name : null;
}

async function originHead(git: Git): Promise<string | null> {
  const r = await git(['symbolic-ref', '--short', '-q', 'refs/remotes/origin/HEAD']);
  const name = r.stdout.trim();
  return r.code === 0 && name.startsWith('origin/') ? name.slice('origin/'.length) : null;
}

async function mainBranchBaseline(
  o: ResolveScmOptions,
  branch: string,
  policy: FetchPolicy,
  ctx: BaselineContext,
): Promise<Baseline> {
  const projectKey = o.settings.config.project.key;
  if (o.baselineClient === null) {
    o.warnings.add(
      'BASELINE_SERVER_NOT_CONFIGURED',
      'no server is configured, so the main-branch new-code baseline is unknown',
    );
    return { revision: null, kind: 'server_baseline', status: 'unavailable' };
  }
  if (projectKey === undefined) {
    o.warnings.add(
      'BASELINE_PROJECT_KEY_MISSING',
      'project.key is not set, so the main-branch new-code baseline cannot be requested',
    );
    return { revision: null, kind: 'server_baseline', status: 'unavailable' };
  }
  const version = o.settings.config.project.version;
  const answer = await o.baselineClient.fetchBaseline({
    projectKey,
    branch,
    // Ruling U8: the version this scan reports, for a `previous_version` new-code definition.
    version: version === undefined || version === '' ? undefined : version,
  });
  if (answer === 'unsupported') {
    o.warnings.add(
      'BASELINE_ENDPOINT_UNAVAILABLE',
      'the server does not provide GET /api/v0/projects/new-code-baseline yet; new code is unavailable',
    );
    return { revision: null, kind: 'server_baseline', status: 'unavailable' };
  }
  // report-format §4: the server's warnings reach the report, and so the gate result.
  for (const code of answer.warnings) {
    o.warnings.add(code, BASELINE_WARNING_MESSAGES[code]);
  }
  return serverBaselineCommit(o.git, answer.revision, policy, ctx);
}

export async function resolveScm(o: ResolveScmOptions): Promise<ScmResolution> {
  const { git, settings, flags, warnings, log } = o;
  const inside = await git(['rev-parse', '--is-inside-work-tree']);
  if (inside.code !== 0 || inside.stdout.trim() !== 'true') {
    // git's stderr carries the real reason (e.g. "detected dubious ownership" and the
    // `git config --global --add safe.directory ...` remedy), which is otherwise invisible.
    const detail = inside.stderr.trim();
    throw new CliError(
      EXIT.USAGE,
      `${settings.root} is not inside a git work tree; qualor scan needs git history` +
        (detail === '' ? '' : `: ${detail}`),
    );
  }
  const head = await git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  const headSha = head.stdout.trim();
  if (head.code !== 0 || !REVISION.test(headSha)) {
    throw new CliError(EXIT.USAGE, 'the repository has no commits yet');
  }
  let revision = headSha;
  const ciRevision = settings.ci.revision;
  if (ciRevision !== null) {
    if (REVISION.test(ciRevision)) revision = ciRevision;
    else
      warnings.add('CI_REVISION_INVALID', 'the CI commit SHA is not a git revision; HEAD was used');
  }
  const branch = flags.branch ?? settings.ci.branch ?? (await currentBranch(git));
  const mainBranch =
    settings.config.scm.mainBranch ?? settings.ci.mainBranch ?? (await originHead(git)) ?? 'main';
  const mr =
    flags.mr !== undefined && flags.mrTarget !== undefined
      ? { id: flags.mr, targetBranch: flags.mrTarget }
      : settings.ci.mergeRequest;
  const mergeRequest = mr === null ? null : { ...mr, sourceBranch: branch ?? 'HEAD' };
  const policy: FetchPolicy = {
    autoFetch: settings.config.scm.autoFetch,
    deepenSteps: o.deepenSteps ?? DEFAULT_DEEPEN_STEPS,
  };
  const ctx: BaselineContext = { log, warnings };

  let baseline: Baseline;
  if (mergeRequest !== null) {
    baseline = await mergeBaseBaseline(git, mergeRequest.targetBranch, policy, ctx);
  } else if (branch === null) {
    warnings.add(
      'BASELINE_DETACHED_HEAD',
      'HEAD is detached and no --branch was given; new code is unavailable',
    );
    baseline = { revision: null, kind: 'none', status: 'unavailable' };
  } else if (branch !== mainBranch) {
    baseline = await mergeBaseBaseline(
      git,
      settings.config.newCode.referenceBranch ?? mainBranch,
      policy,
      ctx,
    );
  } else {
    baseline = await mainBranchBaseline(o, branch, policy, ctx);
  }

  const diff =
    baseline.status === 'ok' && baseline.revision !== null
      ? await diffAgainst(git, baseline.revision)
      : null;
  return {
    scm: {
      provider: settings.ci.provider,
      revision,
      branch,
      mainBranch,
      mergeRequest,
      baseline,
      renames: diff?.renames ?? [],
      // scm.md §3: only in GitLab CI, and only with at least one well-formed value.
      ...(settings.ci.gitlab === null || Object.keys(settings.ci.gitlab).length === 0
        ? {}
        : { gitlab: settings.ci.gitlab }),
      // github.md §3: only in GitHub Actions, and only with at least one well-formed value.
      ...githubContext(settings.ci, mergeRequest !== null, headSha),
    },
    newLines: (p) => diff?.newLines(p),
  };
}

/**
 * `scm.github`: the CI ids, plus `checkout` for a pull request whose head the event names
 * (`head` when HEAD is that commit, `other` for GitHub's merge commit or anything else).
 */
function githubContext(
  ci: CiInfo,
  isPullRequest: boolean,
  headSha: string,
): { github?: NonNullable<Report['scm']['github']> } {
  if (ci.provider !== 'github' || ci.github === null) return {};
  const github: NonNullable<Report['scm']['github']> = {
    ...ci.github,
    ...(isPullRequest && ci.pullRequestHead !== null
      ? { checkout: ci.pullRequestHead === headSha ? ('head' as const) : ('other' as const) }
      : {}),
  };
  return Object.keys(github).length === 0 ? {} : { github };
}
