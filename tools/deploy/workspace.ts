import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { must, REPO_ROOT, run, SCANNER_IMAGE, type RunResult } from './stack';

/**
 * A checkout of this repository inside a Docker volume, for scans by the `qualor/scanner` image
 * (plan 1G). A volume rather than a bind mount, so the same code works with a local daemon, on
 * GitHub runners and with GitLab's `docker:dind` (where the job's files are not on the daemon's
 * host). The clone keeps its full history (the CLI diffs against the baseline) and gets its
 * dependencies installed on Linux (the repository's ESLint config needs typescript-eslint).
 */

/** The same Node 22 image the Dockerfiles build with (pinned by digest). */
export const NODE_IMAGE =
  'node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7';
/**
 * On every container and volume the deploy scripts create outside compose, so the CI jobs can
 * remove what a cancelled run leaves behind (compose labels the stacks itself).
 */
export const DEPLOY_LABEL = 'qualor.deploy';
/**
 * The scanner image is only ever run from a local build (`--pull=never`): these scripts test this
 * checkout's build, never an image a registry happens to hold under the same name and tag
 * (`qualor/scanner` on Docker Hub).
 */
const LOCAL_SCANNER = ['--pull=never', SCANNER_IMAGE];
/**
 * A pnpm store kept between runs on purpose, so a repeat install copies instead of downloading. It
 * holds only public npm packages. It carries DEPLOY_LABEL, so the CI jobs' teardown removes it with
 * the rest; on a developer machine it stays as a cache (`docker volume rm qualor-deploy-pnpm-store`).
 */
const PNPM_STORE_VOLUME = 'qualor-deploy-pnpm-store';
/** The scanner image's user (`node`), who must own the checkout it commits to. */
const SCANNER_UID = '1000:1000';

const GIT_IDENTITY = [
  '-c',
  'user.name=Qualor dogfood',
  '-c',
  'user.email=dogfood@qualor.invalid',
  '-c',
  'commit.gpgsign=false',
];

export interface Workspace {
  volume: string;
}

function hostGit(cwd: string, args: string[]): string {
  return must(
    run('git', ['-c', 'core.autocrlf=false', ...args], { cwd }),
    `git ${args[0]}`,
  ).stdout.trim();
}

/**
 * Clones `REPO_ROOT` at `revision` as local branch `baseBranch` (the merge requests' target,
 * default `main`) into a fresh volume and installs its dependencies there. The clone's `origin`
 * is the workspace itself (`/src`), with `origin/<baseBranch>` its default branch and no other
 * remote-tracking ref: the CLI resolves a merge request's target as `origin/<target>` and
 * refreshes it with `git fetch origin`, which then reads the local branch.
 */
export function createWorkspace(volume: string, revision: string, baseBranch = 'main'): Workspace {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-workspace-'));
  try {
    const clone = path.join(dir, 'repo');
    hostGit(dir, ['clone', '--quiet', '--no-local', '--no-checkout', REPO_ROOT, clone]);
    hostGit(clone, ['config', 'core.autocrlf', 'false']);
    hostGit(clone, ['checkout', '--quiet', '-B', baseBranch, revision]);
    hostGit(clone, ['remote', 'set-url', 'origin', '/src']);
    const remoteRefs = hostGit(clone, ['for-each-ref', '--format=%(refname)', 'refs/remotes/']);
    for (const ref of remoteRefs.split('\n').filter((r) => r !== '')) {
      hostGit(clone, ['update-ref', '-d', ref]);
    }
    hostGit(clone, ['update-ref', `refs/remotes/origin/${baseBranch}`, baseBranch]);
    hostGit(clone, [
      'symbolic-ref',
      'refs/remotes/origin/HEAD',
      `refs/remotes/origin/${baseBranch}`,
    ]);
    must(
      run('docker', ['volume', 'create', '--label', DEPLOY_LABEL, volume]),
      'docker volume create',
    );
    const tar = spawnSync('tar', ['-c', '-C', clone, '.'], { maxBuffer: 1024 * 1024 * 1024 });
    if (tar.status !== 0) throw new Error(`tar failed: ${String(tar.stderr)}`);
    must(
      run(
        'docker',
        [
          'run',
          '--rm',
          '--label',
          DEPLOY_LABEL,
          '-i',
          '-v',
          `${volume}:/src`,
          NODE_IMAGE,
          'sh',
          '-c',
          `tar -x -C /src && chown -R ${SCANNER_UID} /src`,
        ],
        { input: tar.stdout },
      ),
      'copying the checkout into the volume',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  }
  // Idempotent: an existing store is kept as it is.
  must(
    run('docker', ['volume', 'create', '--label', DEPLOY_LABEL, PNPM_STORE_VOLUME]),
    'docker volume create',
  );
  must(
    run('docker', [
      'run',
      '--rm',
      '--label',
      DEPLOY_LABEL,
      '-v',
      `${volume}:/src`,
      '-v',
      `${PNPM_STORE_VOLUME}:/pnpm-store`,
      '-w',
      '/src',
      NODE_IMAGE,
      'sh',
      '-c',
      `corepack enable && pnpm install --frozen-lockfile --store-dir /pnpm-store --reporter=silent && chown -R ${SCANNER_UID} /src`,
    ]),
    'pnpm install in the workspace',
  );
  return { volume };
}

/** Runs git in the workspace, as the scanner image's user. */
export function workspaceGit(ws: Workspace, args: string[]): string {
  return must(
    run('docker', [
      'run',
      '--rm',
      '--label',
      DEPLOY_LABEL,
      '-v',
      `${ws.volume}:/src`,
      '-w',
      '/src',
      '--entrypoint',
      'git',
      ...LOCAL_SCANNER,
      ...GIT_IDENTITY,
      ...args,
    ]),
    `git ${args[0]} in the workspace`,
  ).stdout.trim();
}

/** Writes `text` to `file` in the workspace (a path relative to its root). */
export function workspaceWrite(ws: Workspace, file: string, text: string): void {
  must(
    run(
      'docker',
      [
        'run',
        '--rm',
        '--label',
        DEPLOY_LABEL,
        '-i',
        '-v',
        `${ws.volume}:/src`,
        '-w',
        '/src',
        '--entrypoint',
        'sh',
        ...LOCAL_SCANNER,
        '-c',
        'mkdir -p "$(dirname "$1")" && cat > "$1"',
        'sh',
        file,
      ],
      { input: text },
    ),
    `writing ${file}`,
  );
}

export interface ScanOptions {
  network: string;
  token: string;
  args: string[];
  /** The repository to scan inside the volume (default `/src`). */
  workdir?: string;
}

/**
 * `qualor scan` in the scanner image against the stack's server. The token reaches the container
 * through the environment (`-e QUALOR_TOKEN` without a value), never on a command line.
 */
export function scanWorkspace(ws: Workspace, o: ScanOptions): RunResult {
  return run(
    'docker',
    [
      'run',
      '--rm',
      '--label',
      DEPLOY_LABEL,
      '--network',
      o.network,
      '-v',
      `${ws.volume}:/src`,
      '-e',
      'QUALOR_URL=http://server:8080',
      '-e',
      'QUALOR_TOKEN',
      '-w',
      o.workdir ?? '/src',
      ...LOCAL_SCANNER,
      'scan',
      ...o.args,
    ],
    { env: { QUALOR_TOKEN: o.token } },
  );
}

/** Runs a shell script in the workspace, as the scanner image's user. */
export function workspaceShell(ws: Workspace, script: string): string {
  return must(
    run('docker', [
      'run',
      '--rm',
      '--label',
      DEPLOY_LABEL,
      '-v',
      `${ws.volume}:/src`,
      '-w',
      '/src',
      '--entrypoint',
      'sh',
      ...LOCAL_SCANNER,
      '-c',
      script,
    ]),
    'a shell script in the workspace',
  ).stdout.trim();
}

export function removeWorkspace(ws: Workspace): void {
  run('docker', ['volume', 'rm', '--force', ws.volume]);
}
