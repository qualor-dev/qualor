import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { DockerSeed } from '../../ui/e2e/docker-seed';
import {
  commitOnBranch,
  EXIT_TEST_FILE,
  log,
  logBranches,
  LOOSE_EQUALITY_SOURCE,
  portableLcov,
  QUALOR_PROJECT,
  resolveRevision,
  scanAs,
} from './scans';
import { Api, REPO_ROOT, run, startStack, stopStack, stopStacksOnSignal } from './stack';
import {
  createWorkspace,
  removeWorkspace,
  workspaceGit,
  workspaceShell,
  workspaceWrite,
  type Workspace,
} from './workspace';

/**
 * `pnpm deploy:screenshots` (plan 1G): the final screenshots, taken against the dockerized server
 * (compose stack, both images) with realistic data: this repository's last three first-parent
 * commits as main-branch history, a merge request that fails the gate (`a == b`), and the three
 * fixtures, each scanned as its own repository by the scanner image. Then the Playwright project
 * of ui/playwright.docker.config.ts writes one PNG per screen to `.tmp/screenshots-docker/`. Run
 * `pnpm test:coverage` first to show this repository's coverage too.
 * `--keep` leaves the stack running afterwards (its address and admin password are printed).
 */
const OUT = path.join(REPO_ROOT, '.tmp', 'screenshots-docker');
const LCOV = path.join(REPO_ROOT, 'coverage', 'lcov.info');
const FIXTURES = [
  { dir: 'ts-basic', name: 'Fixture: TypeScript' },
  { dir: 'java-basic', name: 'Fixture: Java' },
  { dir: 'mixed-secrets', name: 'Fixture: mixed with secrets' },
] as const;

/**
 * A fixture as its own one-commit repository inside the workspace (as the fixture suite scans it),
 * with a link to the workspace's node_modules for ESLint and typescript-eslint.
 */
function fixtureRepo(ws: Workspace, dir: string): string {
  const repo = `/src/.fixtures/${dir}`;
  workspaceShell(
    ws,
    [
      `rm -rf ${repo} && mkdir -p /src/.fixtures && cp -a /src/fixtures/${dir} ${repo} && cd ${repo}`,
      'ln -s /src/node_modules node_modules',
      'git init -q -b main && echo /node_modules >> .git/info/exclude',
      'git add -A && git -c user.name=fixture -c user.email=fixture@qualor.invalid commit -qm fixture',
    ].join(' && '),
  );
  return repo;
}

async function main(): Promise<void> {
  const keep = process.argv.includes('--keep');
  const history = ['HEAD~2', 'HEAD~1', 'HEAD'].map((rev) => resolveRevision(rev));
  // A cancelled run (Ctrl+C) tears the stack down too, as in tools/deploy/dogfood.ts.
  const undoSignals = stopStacksOnSignal();
  const stack = await startStack(`qualor-screenshots-${process.pid}`);
  log(`stack up in ${(stack.upMs / 1000).toFixed(1)} s at ${stack.url}`);
  // Removed in `finally` even when copying the checkout into it fails halfway.
  const ws: Workspace = { volume: `qualor-screenshots-${process.pid}` };
  try {
    createWorkspace(ws.volume, history[0] as string);
    const api = new Api(stack.url);
    await api.login(stack.admin.username, stack.admin.password);

    const qualor = await api.createProject(QUALOR_PROJECT.key, QUALOR_PROJECT.name);
    const target = { ws, stack, token: qualor.token, projectKey: QUALOR_PROJECT.key };
    for (const revision of history) {
      workspaceGit(ws, ['checkout', '--quiet', '-B', 'main', revision]);
      // HEAD's analysis imports the coverage of a `pnpm test:coverage` run, when there is one.
      if (revision === history.at(-1) && existsSync(LCOV)) {
        workspaceWrite(ws, 'coverage/lcov.info', portableLcov(readFileSync(LCOV, 'utf8')));
        log(`with the coverage of ${LCOV}`);
      }
      scanAs(target, `Qualor main at ${revision.slice(0, 12)}`, ['--branch', 'main']);
    }
    commitOnBranch(ws, 'dogfood/eqeqeq', EXIT_TEST_FILE, LOOSE_EQUALITY_SOURCE);
    scanAs(target, 'Qualor MR !1', [
      '--branch',
      'dogfood/eqeqeq',
      '--mr',
      '1',
      '--mr-target',
      'main',
    ]);
    const branches = await logBranches(api, qualor.id);
    const mr = branches.find((b) => b.kind === 'merge_request');
    if (!mr) throw new Error('the merge request analysis did not arrive');

    const fixtures = {} as DockerSeed['fixtures'];
    for (const f of FIXTURES) {
      const key = `fixtures/${f.dir}`;
      const project = await api.createProject(key, f.name);
      const repo = fixtureRepo(ws, f.dir);
      scanAs({ ws, stack, token: project.token, projectKey: key, workdir: repo }, key, [
        '--branch',
        'main',
      ]);
      await logBranches(api, project.id);
      fixtures[f.dir] = { id: project.id, name: f.name };
    }

    rmSync(OUT, { recursive: true, force: true });
    mkdirSync(OUT, { recursive: true });
    const seedFile = path.join(OUT, 'seed.json');
    const seed: DockerSeed = { qualor: { id: qualor.id, mergeRequestBranchId: mr.id }, fixtures };
    writeFileSync(seedFile, JSON.stringify(seed, null, 2));
    const playwright = path.join(REPO_ROOT, 'ui', 'node_modules', '@playwright', 'test', 'cli.js');
    const shots = run(process.execPath, [playwright, 'test', '-c', 'playwright.docker.config.ts'], {
      cwd: path.join(REPO_ROOT, 'ui'),
      inherit: true,
      env: {
        QUALOR_DOCKER_URL: stack.url,
        QUALOR_DOCKER_ADMIN_PASSWORD: stack.admin.password,
        QUALOR_DOCKER_SEED: seedFile,
      },
    });
    log(`screenshots in ${OUT}`);
    if (keep) log(`stack kept at ${stack.url}: sign in as admin / ${stack.admin.password}`);
    process.exitCode = shots.code;
  } finally {
    removeWorkspace(ws);
    if (!keep) stopStack(stack);
    undoSignals();
  }
}

await main();
