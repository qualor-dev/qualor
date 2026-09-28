import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseConfig, type QualorConfigInput } from '@qualor/shared';
import { detectCi, type CiInfo } from '../src/config/ci';
import type { Settings } from '../src/config/settings';

// An empty global config file. `os.devNull` does not work: Git for Windows refuses `\\.\nul`.
const EMPTY_GITCONFIG = path.join(os.tmpdir(), 'qualor-test-empty.gitconfig');
writeFileSync(EMPTY_GITCONFIG, '');

/** Isolated from the user's git configuration (hooks, signing, diff settings). */
export const GIT_TEST_ENV: Record<string, string | undefined> = {
  ...process.env,
  GIT_CONFIG_GLOBAL: EMPTY_GITCONFIG,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Qualor Test',
  GIT_AUTHOR_EMAIL: 'test@qualor.invalid',
  GIT_COMMITTER_NAME: 'Qualor Test',
  GIT_COMMITTER_EMAIL: 'test@qualor.invalid',
};

export function gitSync(cwd: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    env: GIT_TEST_ENV,
    encoding: 'utf8',
  }).trim();
}

export function initRepo(dir: string): void {
  gitSync(dir, 'init', '-q', '-b', 'main');
}

export function commitAll(dir: string, message: string): string {
  gitSync(dir, 'add', '-A');
  gitSync(dir, 'commit', '-q', '-m', message);
  return gitSync(dir, 'rev-parse', 'HEAD');
}

export function fileUrl(dir: string): string {
  return pathToFileURL(dir).href;
}

export function settingsFor(
  root: string,
  config: Partial<QualorConfigInput> = {},
  ci: CiInfo = detectCi({}),
): Settings {
  return {
    root,
    configPath: null,
    config: parseConfig({ version: 1, project: { key: 'acme/app' }, ...config }),
    token: null,
    ci,
    serverUrlSource: null,
    caFileSource: null,
  };
}

const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*)$/i;

/** For end-to-end scans: no CI detection, no QUALOR_* leaking in from the developer's shell or CI. */
export const SCAN_TEST_ENV: Record<string, string | undefined> = Object.fromEntries(
  Object.entries(GIT_TEST_ENV).filter(([key]) => !CI_VARIABLE.test(key)),
);
