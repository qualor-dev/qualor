import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  createFakeNpmRegistry,
  type FakeNpmRegistry,
  type FakeNpmVersion,
} from '@qualor/shared/test/npm-registry';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { toolInstalled } from '../../cli/test/fix/tools';
import { dependencyFixes, targetVulnerabilities } from '../src/db/schema';
import { goneComment } from '../src/fixes/body';
import { type FixJobDeps } from '../src/fixes/run';
import { runFixSyncPass } from '../src/fixes/sync';
import { communityLimits } from '../src/limits';
import { createScmRuntime } from '../src/scm/runtime';
import { createFakeGitLab, type FakeGitLab } from './fake-gitlab';
import { enableFixes, runFixJobs, seedMainVulnerability } from './fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';
import { mainBranchId } from './issues';
import { mappedProject, PUBLIC_URL, scmTestConfig, silentLogger } from './scm';

/**
 * 0.16 fix MRs, Task 20 (spec §6, §11): the whole path with nothing faked but the outside world.
 * The real `qualor fix` (a child process: the TypeScript sources, or `QUALOR_BIN`) runs real npm
 * against a fake registry, claims and uploads through a real server, the SCM worker commits to a
 * fake GitLab, and a later pass closes the MR once main no longer has the vulnerability.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const qualorBin = process.env['QUALOR_BIN'];
const cliCommand: [string, string[]] =
  qualorBin !== undefined && qualorBin !== ''
    ? [path.resolve(repoRoot, qualorBin), []]
    : [process.execPath, ['--import', tsxLoader, cliEntry]];
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*|NPM_.*)$/i;
/** A CLI that runs longer than this is killed and the test fails: nothing here may hang. */
const CLI_KILL_MS = 150_000;

const GITLAB_ID = 7001;
const BRANCH = 'qualor/fix/js/qf-a';
const TITLE = 'Bump qf-a from 1.2.5 to 1.2.6';
const CVE = 'CVE-2026-9701';

// Assembled at run time, so the repository's own Gitleaks pass finds no fake secret here.
const REGISTRY_TOKEN = ['npm', 'S3CR3T', 'e2e', '0123456789'].join('_');

const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-fix-e2e-'));
const gitConfig = path.join(work, 'empty.gitconfig');
writeFileSync(gitConfig, '');
const npmHome = path.join(work, 'npm-home');
mkdirSync(npmHome);

const baseEnv: Record<string, string> = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      (e): e is [string, string] => e[1] !== undefined && !CI_VARIABLE.test(e[0]),
    ),
  ),
  GIT_CONFIG_GLOBAL: gitConfig,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'e2e',
  GIT_AUTHOR_EMAIL: 'e2e@qualor.invalid',
  GIT_COMMITTER_NAME: 'e2e',
  GIT_COMMITTER_EMAIL: 'e2e@qualor.invalid',
  HOME: npmHome,
  USERPROFILE: npmHome,
};

function git(cwd: string, ...args: string[]): string {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    env: baseEnv,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

/** npm's own settings: the fake registry, a token for it in the user's `.npmrc`, caches of its own. */
function npmEnv(registry: string): Record<string, string> {
  const userConfig = path.join(npmHome, '.npmrc');
  const host = new URL(registry).host;
  writeFileSync(userConfig, `//${host}/:_authToken=${REGISTRY_TOKEN}\n`);
  return {
    ...baseEnv,
    CI: 'true',
    npm_config_registry: registry,
    npm_config_userconfig: userConfig,
    npm_config_cache: path.join(npmHome, 'npm-cache'),
    npm_config_update_notifier: 'false',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
  };
}

/**
 * The lockfile npm makes for the fixture's manifest against the registry as it is now. Never
 * `spawnSync`: the fake registry answers from this very process.
 */
function makeLockfile(root: string, env: Record<string, string>): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('npm install --package-lock-only --ignore-scripts', {
      cwd: root,
      env,
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (d: Buffer) => (output += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (output += d.toString('utf8')));
    child.on('close', (code) =>
      code === 0 ? resolve() : reject(new Error('npm install: ' + output)),
    );
  });
}

interface CliRun {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runFixCli(cwd: string, args: string[], env: Record<string, string>): Promise<CliRun> {
  return new Promise((resolve) => {
    const child = spawn(cliCommand[0], [...cliCommand[1], 'fix', ...args], {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const killer = setTimeout(() => {
      stderr += `\n[killed after ${CLI_KILL_MS} ms]`;
      child.kill('SIGKILL');
    }, CLI_KILL_MS);
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      resolve({ code, stdout, stderr });
    });
  });
}

describe.runIf(toolInstalled('npm'))(
  'qualor fix end to end: the real CLI, npm, a real server and a fake GitLab (0.16 fix MRs §6, §11)',
  () => {
    let h: IngestHarness;
    let fake: FakeGitLab;
    let registry: FakeNpmRegistry;
    let project: IngestProject & { connectionId: string };
    let url: string;
    let checkout: string;
    let localHead: string;
    let cliOut: CliRun;
    let fixId: string;
    let main: string;
    // Read by the registry on each request: a version pushed later is published from then on.
    const packages: Record<string, FakeNpmVersion[]> = { 'qf-a': [{ version: '1.2.5' }] };
    const runtime = createScmRuntime();

    const db = () => h.ctx.db;
    const deps = (): FixJobDeps => ({
      db: db(),
      scm: {
        secretKey: h.ctx.config.secretKey,
        internalHosts: h.ctx.config.scmInternalHosts,
        clientOptions: { timeoutMs: 2_000 },
      },
      runtime,
      publicUrl: PUBLIC_URL,
      limits: () => communityLimits(),
      logger: silentLogger,
    });
    const api = async <T>(method: 'GET' | 'POST', route: string, payload?: object): Promise<T> => {
      const res = await h.ctx.app.inject({
        method,
        url: `/api/v0${route}`,
        headers: h.orgAdmin.headers,
        ...(payload !== undefined && { payload }),
      });
      expect(res.statusCode, res.body).toBeLessThan(300);
      return res.json() as T;
    };
    interface ListedFix {
      state: string;
      mrUrl: string | null;
    }
    const listedFix = async (): Promise<ListedFix | null> => {
      const { items } = await api<{
        items: { packageName: string; fix: ListedFix | null }[];
      }>('GET', `/projects/${project.id}/vulnerabilities?pageSize=100&target=branch:${main}`);
      return items.find((i) => i.packageName === 'qf-a')?.fix ?? null;
    };

    beforeAll(async () => {
      registry = await createFakeNpmRegistry(packages);
      const env = npmEnv(registry.url);

      // The fixture's repository: its manifest and the lockfile npm makes while only 1.2.5 exists.
      checkout = path.join(work, 'app');
      mkdirSync(checkout);
      writeFileSync(
        path.join(checkout, 'package.json'),
        readFileSync(path.join(repoRoot, 'fixtures', 'fix-npm', 'package.json')),
      );
      await makeLockfile(checkout, env);
      git(checkout, 'init', '-q', '-b', 'main');
      git(checkout, 'add', 'package.json', 'package-lock.json');
      git(checkout, 'commit', '-q', '-m', 'first');
      localHead = git(checkout, 'rev-parse', 'HEAD');

      // The fix is published after the lockfile was made.
      packages['qf-a']!.push({ version: '1.2.6' });

      fake = await createFakeGitLab();
      fake.addProject({ id: GITLAB_ID, path: 'acme/fix-e2e' });
      fake.pushAs(
        GITLAB_ID,
        'main',
        {
          'package.json': readFileSync(path.join(checkout, 'package.json'), 'utf8'),
          'package-lock.json': readFileSync(path.join(checkout, 'package-lock.json'), 'utf8'),
        },
        { sha: localHead },
      );

      h = await createIngestHarness({ config: scmTestConfig(fake) });
      await h.ctx.app.listen({ port: 0, host: '127.0.0.1' });
      url = `http://127.0.0.1:${(h.ctx.app.server.address() as AddressInfo).port}`;
      project = await mappedProject(h, fake, 'acme/fix-e2e', GITLAB_ID, { ownConnection: true });
      main = await mainBranchId(db(), project.id);
      await seedMainVulnerability(
        db(),
        { id: project.id, mainBranchId: main },
        {
          ecosystem: 'npm',
          packageName: 'qf-a',
          version: '1.2.5',
          vulnerabilityId: CVE,
          severity: 'high',
          fixedVersion: '1.2.6',
        },
      );
    }, 180_000);

    afterAll(async () => {
      await h?.close();
      await fake?.close();
      await registry?.close();
      rmSync(work, { recursive: true, force: true, maxRetries: 5 });
    });

    it('requests the fix, runs qualor fix and commits the branch and the MR', async () => {
      await enableFixes(h, project.id);
      const requested = await api<{ id: string; state: string }>(
        'POST',
        `/projects/${project.id}/fixes`,
        { ecosystem: 'npm', packageName: 'qf-a' },
      );
      expect(requested.state).toBe('requested');
      fixId = requested.id;

      const env = {
        ...npmEnv(registry.url),
        QUALOR_URL: url,
        QUALOR_TOKEN: project.token,
        GITLAB_CI: 'true',
        CI_COMMIT_REF_NAME: 'main',
        CI_DEFAULT_BRANCH: 'main',
        CI_COMMIT_SHA: localHead,
      };
      cliOut = await runFixCli(checkout, ['--project-key', project.key], env);
      expect(cliOut.code, cliOut.stderr).toBe(0);

      await runFixJobs(db(), deps());
      expect(fake.branches(GITLAB_ID)).toContain(BRANCH);
      const head = fake.headOf(GITLAB_ID, BRANCH)!;
      expect(head).not.toBe(localHead);
      expect(fake.fileAt(GITLAB_ID, head, 'package.json')).toContain('"qf-a": "^1.2.6"');
      expect(fake.fileAt(GITLAB_ID, head, 'package-lock.json')).toContain('1.2.6');
      const commits = fake.requests.filter(
        (r) => r.method === 'POST' && /\/repository\/commits$/.test(r.path),
      );
      expect(commits).toHaveLength(1);
      const sent = JSON.parse(commits[0]!.body) as {
        start_sha: string;
        actions: { file_path: string }[];
      };
      expect(sent.start_sha).toBe(localHead);
      expect(sent.actions.map((a) => a.file_path).sort()).toEqual([
        'package-lock.json',
        'package.json',
      ]);
      const [mr, ...others] = fake.mergeRequestsOf(GITLAB_ID);
      expect(others).toEqual([]);
      expect(mr).toMatchObject({
        title: TITLE,
        state: 'opened',
        sourceBranch: BRANCH,
        targetBranch: 'main',
      });
    }, 240_000);

    it('shows the open fix with its MR on the vulnerabilities API', async () => {
      const fix = await listedFix();
      expect(fix?.state).toBe('open');
      expect(fix?.mrUrl).toContain(`/merge_requests/${fake.mergeRequestsOf(GITLAB_ID)[0]!.iid}`);
    });

    it('closes the MR with the gone comment and deletes the branch once main is clean', async () => {
      await db().delete(targetVulnerabilities);
      const outcome = await runFixSyncPass(deps(), h.organizationId);
      expect(outcome.fixed).toBe(1);
      await runFixJobs(db(), deps());
      const [mr] = fake.mergeRequestsOf(GITLAB_ID);
      expect(mr!.state).toBe('closed');
      const notes = fake.discussions(GITLAB_ID, mr!.iid).flatMap((d) => d.notes.map((n) => n.body));
      expect(notes).toContain(goneComment('qf-a', 'main'));
      expect(fake.branches(GITLAB_ID)).not.toContain(BRANCH);
      const [row] = await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, fixId));
      expect(row?.state).toBe('fixed');
    });

    it('leaks no token: not in the CLI output, not in the requests the fakes saw', () => {
      for (const secret of [project.token, REGISTRY_TOKEN]) {
        expect(cliOut.stderr).not.toContain(secret);
        expect(cliOut.stdout).not.toContain(secret);
        expect(JSON.stringify(fake.requests)).not.toContain(secret);
        expect(registry.requests.join('\n')).not.toContain(secret);
      }
    });
  },
);
