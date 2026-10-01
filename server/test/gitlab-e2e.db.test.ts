import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { branches, issues } from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { jobHandlers } from '../src/ingest/handlers';
import { startWorker, type Worker } from '../src/queue/worker';
import { scmHandlers } from '../src/scm/decorate';
import { markerOf } from '../src/scm/markdown';
import { statusName } from '../src/scm/render';
import { createScmRuntime } from '../src/scm/runtime';
import { createFakeGitLab, type FakeGitLab } from './fake-gitlab';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';
import { PUBLIC_URL, scmTestConfig } from './scm';

/**
 * Plan 2A, scm.md §11: the whole GitLab flow end to end, against the local fake GitLab only. The
 * real CLI (TypeScript sources, as a child process) scans a git repository as GitLab CI would
 * (`GITLAB_CI`, `CI_*`), uploads to a real server (Fastify on a local port, Postgres through
 * Testcontainers) whose workers run as in main.ts (analyses and re-evaluations, decorations), and
 * the server decorates the fake's merge request. Nothing contacts a real GitLab.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*)$/i;
const CLI_KILL_MS = 90_000;
const GITLAB_PROJECT = 4711;
const PIPELINE = 99001;
const IID = 5;

let harness: IngestHarness;
let project: IngestProject;
let fake: FakeGitLab;
let url: string;
let workers: Worker[] = [];
const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-gitlab-e2e-'));
const gitConfig = path.join(work, 'empty.gitconfig');
writeFileSync(gitConfig, '');

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

function write(root: string, files: Record<string, string>): void {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    writeFileSync(path.join(root, rel), text);
  }
}

/** The hunks of a `git diff` (from the first `@@`), as GitLab's `diff` field holds them. */
function hunks(diff: string): string {
  return `${diff.slice(diff.indexOf('@@'))}\n`;
}

/** An external SARIF result whose message tries every Markdown trick (scm.md §6). */
function sarif(file: string, line: number): string {
  return JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'e2e-tool', rules: [{ id: 'no-magic' }] } },
        results: [
          {
            ruleId: 'no-magic',
            level: 'warning',
            message: { text: 'Magic @all\n/merge ![x](http://evil.example/x.png) `tick`' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: file },
                  region: { startLine: line },
                },
              },
            ],
          },
        ],
      },
    ],
  });
}

function runCli(
  cwd: string,
  args: string[],
  env: Record<string, string>,
): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', tsxLoader, cliEntry, 'scan', ...args], {
      cwd,
      env: { ...baseEnv, QUALOR_URL: url, QUALOR_TOKEN: project.token, ...env },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    const killer = setTimeout(() => child.kill('SIGKILL'), CLI_KILL_MS);
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      resolve({ code, stderr });
    });
  });
}

/** What GitLab CI sets for a pipeline of this project (config.md §4, scm.md §3). */
function gitlabEnv(sha: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    GITLAB_CI: 'true',
    CI_COMMIT_SHA: sha,
    CI_DEFAULT_BRANCH: 'main',
    CI_PROJECT_PATH: 'acme/shop',
    CI_PROJECT_ID: String(GITLAB_PROJECT),
    CI_PIPELINE_ID: String(PIPELINE),
    ...extra,
  };
}

/** Waits until `check` holds (the workers run in the background). */
async function eventually(check: () => boolean | Promise<boolean>, what: string): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const statuses = (sha: string) =>
  fake.statuses.filter((s) => s.projectId === GITLAB_PROJECT && s.sha === sha);
const notes = () => fake.discussions(GITLAB_PROJECT, IID).flatMap((d) => d.notes);
const summaries = () => notes().filter((n) => markerOf(n.body)?.kind === 'summary');
const threads = () =>
  fake
    .discussions(GITLAB_PROJECT, IID)
    .filter((d) => d.notes[0] && markerOf(d.notes[0].body)?.kind === 'issue');

beforeAll(async () => {
  fake = await createFakeGitLab();
  fake.addProject({ id: GITLAB_PROJECT, path: 'acme/shop' });
  fake.addPipeline(GITLAB_PROJECT, PIPELINE);
  harness = await createIngestHarness({ config: scmTestConfig(fake) });
  project = await harness.project('acme/shop');
  await harness.ctx.app.listen({ port: 0, host: '127.0.0.1' });
  url = `http://127.0.0.1:${(harness.ctx.app.server.address() as AddressInfo).port}`;
  const { ctx } = harness;
  // As main.ts: analyses and re-evaluations in one worker, decorations in their own.
  workers = [
    startWorker({
      db: ctx.db,
      handlers: {
        ...jobHandlers({ db: ctx.db, upload: ctx.config.upload, logger: ctx.app.log }),
        ...gateHandlers({ db: ctx.db, logger: ctx.app.log }),
      },
      concurrency: 1,
      logger: ctx.app.log,
      pollIntervalMs: 50,
    }),
    startWorker({
      db: ctx.db,
      handlers: scmHandlers({
        db: ctx.db,
        scm: { secretKey: ctx.config.secretKey, internalHosts: ctx.config.scmInternalHosts },
        runtime: createScmRuntime(),
        publicUrl: ctx.config.publicUrl,
        logger: ctx.app.log,
      }),
      concurrency: 2,
      logger: ctx.app.log,
      pollIntervalMs: 50,
    }),
  ];
});

afterAll(async () => {
  for (const w of workers) await w.stop();
  await harness.close();
  await fake.close();
  rmSync(work, { recursive: true, force: true, maxRetries: 5 });
});

describe('GitLab end to end, against the fake GitLab (scm.md §11)', () => {
  it('decorates a merge request, re-evaluates after a false positive, and follows a fix', async () => {
    const { ctx, orgAdmin } = harness;
    // An org admin connects GitLab and maps the project, through the API.
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: orgAdmin.headers,
      payload: {
        organizationId: harness.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: fake.token,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    const mapped = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${project.id}`,
      headers: orgAdmin.headers,
      payload: {
        scmConnectionId: (created.json() as { id: string }).id,
        scmProjectRef: 'acme/shop',
      },
    });
    expect(mapped.statusCode, mapped.body).toBe(200);

    // The default branch: one clean commit, scanned by a branch pipeline.
    const root = path.join(work, 'repo');
    mkdirSync(root);
    git(root, 'init', '-q', '-b', 'main');
    write(root, {
      'qualor.yml': 'version: 1\nanalyzers:\n  gitleaks:\n    enabled: false\n',
      'src/a.ts': 'export const a = 1;\n',
    });
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'first');
    const main = git(root, 'rev-parse', 'HEAD');
    git(root, 'update-ref', 'refs/remotes/origin/main', main);
    const onMain = await runCli(
      root,
      ['--project-key', 'acme/shop'],
      gitlabEnv(main, { CI_COMMIT_REF_NAME: 'main' }),
    );
    expect(onMain.code, onMain.stderr).toBe(0);
    await eventually(() => statuses(main).length === 1, 'the main-branch commit status');
    expect(statuses(main)[0]).toMatchObject({
      name: statusName('acme/shop'),
      state: 'success',
      pipelineId: PIPELINE,
    });

    // A merge request adds lines; an external tool flags one of them with a hostile message.
    git(root, 'checkout', '-q', '-b', 'feature/x');
    write(root, {
      'src/b.ts':
        Array.from({ length: 30 }, (_, i) => `export const b${i} = ${i};`).join('\n') + '\n',
    });
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'second');
    const head = git(root, 'rev-parse', 'HEAD');
    fake.addMergeRequest(GITLAB_PROJECT, {
      iid: IID,
      title: 'Add b',
      state: 'opened',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: head,
      baseSha: main,
      startSha: main,
      diffs: [
        {
          oldPath: 'src/b.ts',
          newPath: 'src/b.ts',
          newFile: true,
          diff: hunks(git(root, 'diff', main, head, '--', 'src/b.ts')),
        },
      ],
    });
    const findings = path.join(work, 'finding.sarif');
    writeFileSync(findings, sarif('src/b.ts', 7));
    const mrEnv = gitlabEnv(head, {
      CI_COMMIT_REF_NAME: 'feature/x',
      CI_MERGE_REQUEST_IID: String(IID),
      CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
      CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
    });
    // The report files go in the checkout, as in CI (scm.md §9: never outside the working directory).
    const gl = (name: string) => path.join(root, name);
    const onMr = await runCli(
      root,
      [
        '--project-key',
        'acme/shop',
        '--sarif',
        findings,
        '--gitlab-code-quality',
        gl('cq.json'),
        '--gitlab-sast',
        gl('sast.json'),
      ],
      mrEnv,
    );
    expect(onMr.code, onMr.stderr).toBe(1);
    expect(JSON.parse(readFileSync(gl('cq.json'), 'utf8'))).toEqual([
      expect.objectContaining({
        check_name: 'e2e-tool:no-magic',
        location: { path: 'src/b.ts', lines: { begin: 7 } },
      }),
    ]);
    expect(JSON.parse(readFileSync(gl('sast.json'), 'utf8'))).toMatchObject({
      vulnerabilities: [],
    });

    await eventually(() => threads().length === 1 && summaries().length === 1, 'the decoration');
    expect(statuses(head).map((s) => s.state)).toEqual(['failed']);
    expect(statuses(head)[0]?.description).toBe('Quality gate failed: new_issues 1 > 0');
    const [summary] = summaries();
    expect(summary?.body).toContain('### ❌ Qualor: quality gate failed');
    expect(summary?.body).toContain('1 new issue is commented inline.');
    const [thread] = threads();
    expect(thread?.notes[0]?.position).toMatchObject({
      new_path: 'src/b.ts',
      new_line: 7,
      head_sha: head,
      base_sha: main,
    });
    for (const body of notes().map((n) => n.body)) {
      for (const line of body.split('\n')) expect(line).not.toMatch(/^\s*\//);
    }
    const [mrBranch] = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    expect(mrBranch).toMatchObject({
      mrTitle: 'Add b',
      mrUrl: `${fake.url}/acme/shop/-/merge_requests/${IID}`,
    });
    expect(summary?.body).toContain(
      `${PUBLIC_URL}/projects/${project.id}/branches/${mrBranch!.id}`,
    );

    // marking the issue a false positive passes the gate without a new scan.
    const [issue] = await ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, mrBranch!.id), eq(issues.status, 'open')));
    const transition = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/transition`,
      headers: orgAdmin.headers,
      payload: { to: 'false_positive', comment: 'intended' },
    });
    expect(transition.statusCode, transition.body).toBe(200);
    // The job posts the status, then resolves the thread, then edits the summary: wait for the
    // last of the three, or a check between two requests of the job sees a half-done decoration.
    await eventually(
      () =>
        statuses(head).at(-1)?.state === 'success' &&
        thread?.notes[0]?.resolved === true &&
        summaries()[0]?.body.includes('### ✅ Qualor: quality gate passed') === true,
      'the re-decoration',
    );
    expect(summaries()).toHaveLength(1);
    expect(summaries()[0]?.body).toContain('### ✅ Qualor: quality gate passed');

    // A fix removes the flagged line: a new head, a new analysis, the same summary note.
    write(root, { 'src/b.ts': 'export const b = 1;\n' });
    git(root, 'commit', '-q', '-am', 'fix');
    const fixed = git(root, 'rev-parse', 'HEAD');
    fake.updateMergeRequest(GITLAB_PROJECT, IID, {
      headSha: fixed,
      diffs: [
        {
          oldPath: 'src/b.ts',
          newPath: 'src/b.ts',
          newFile: true,
          diff: '@@ -0,0 +1 @@\n+export const b = 1;\n',
        },
      ],
    });
    const onFix = await runCli(
      root,
      ['--project-key', 'acme/shop'],
      gitlabEnv(fixed, {
        CI_COMMIT_REF_NAME: 'feature/x',
        CI_MERGE_REQUEST_IID: String(IID),
        CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
        CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
      }),
    );
    expect(onFix.code, onFix.stderr).toBe(0);
    await eventually(() => statuses(fixed).length === 1, 'the status of the fix');
    expect(statuses(fixed)[0]?.state).toBe('success');
    await eventually(
      () => (summaries()[0]?.body ?? '').includes(fixed.slice(0, 12)),
      'the edited summary',
    );
    expect(summaries()).toHaveLength(1);
    expect(threads()).toHaveLength(1);

    // Only the fake was contacted, and the token went only into PRIVATE-TOKEN; no log has it.
    for (const request of fake.requests) {
      expect(request.headers['private-token']).toBe(fake.token);
      expect(`${request.path}?${request.query}${request.body}`).not.toContain(fake.token);
    }
    expect(ctx.logs.join('\n')).not.toContain(fake.token);
  }, 240_000);
});
