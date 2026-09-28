import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import { createRequire } from 'node:module';
import path from 'node:path';
import { parseArgs } from 'node:util';

/**
 * `pnpm gitlab:real` (scm.md §11): the opt-in checks against a real GitLab, never part of
 * `pnpm test`.
 *
 * - Without arguments: GitLab CE in Docker (server/test/gitlab-real-setup.ts), the Vitest project
 *   `gitlab-real`, which vitest.config.ts only defines with QUALOR_GITLAB_REAL=1. Set
 *   QUALOR_GITLAB_URL and QUALOR_GITLAB_TOKEN (an admin's `api` token) to use a GitLab CE that is
 *   already running instead.
 * - `--url <GitLab> --project <group/project>`: a GitLab that is already running and a project the
 *   token may write to (server/test/gitlab-live.live.test.ts, the Vitest project `gitlab-live`,
 *   QUALOR_GITLAB_LIVE=1). The token is read only from QUALOR_GITLAB_TEST_TOKEN, never from an
 *   argument, so it stays out of the process list and shell history. The check pushes a temporary
 *   branch `qualor-test/<time>`, opens a merge request, and closes it and deletes the branch
 *   afterwards.
 */
const { values } = parseArgs({
  options: { url: { type: 'string' }, project: { type: 'string' } },
  strict: true,
});
const vitest = path.join(
  path.dirname(createRequire(import.meta.url).resolve('vitest/package.json')),
  'vitest.mjs',
);

let env: NodeJS.ProcessEnv = { ...process.env, QUALOR_GITLAB_REAL: '1' };
let project = 'gitlab-real';
if (values.url !== undefined || values.project !== undefined) {
  if (values.url === undefined || values.project === undefined) {
    console.error('pnpm gitlab:real: --url and --project go together');
    process.exit(2);
  }
  if (!process.env['QUALOR_GITLAB_TEST_TOKEN']) {
    console.error(
      'pnpm gitlab:real: set QUALOR_GITLAB_TEST_TOKEN (the token is never an argument)',
    );
    process.exit(2);
  }
  env = {
    ...process.env,
    QUALOR_GITLAB_LIVE: '1',
    // What GitLab did (never the token), printed below.
    QUALOR_GITLAB_LIVE_OBSERVED: path.join(
      mkdtempSync(path.join(os.tmpdir(), 'qualor-gitlab-live-')),
      'observed.json',
    ),
    QUALOR_GITLAB_LIVE_URL: values.url,
    QUALOR_GITLAB_LIVE_PROJECT: values.project,
  };
  project = 'gitlab-live';
}
const run = spawnSync(process.execPath, [vitest, 'run', '--project', project], {
  stdio: 'inherit',
  env,
});
const observed = env['QUALOR_GITLAB_LIVE_OBSERVED'];
if (observed !== undefined) {
  if (existsSync(observed))
    console.log(`GitLab behaviour observed:
${readFileSync(observed, 'utf8')}`);
  rmSync(path.dirname(observed), { recursive: true, force: true });
}
process.exit(run.status ?? 1);
