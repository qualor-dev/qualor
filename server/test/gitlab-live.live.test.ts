import { spawn, spawnSync } from 'node:child_process';
import {
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { and, eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyses, branches, issues, jobs } from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { jobHandlers } from '../src/ingest/handlers';
import { startWorker, type Worker } from '../src/queue/worker';
import { GitLabClient } from '../src/scm/gitlab/client';
import { scmHandlers } from '../src/scm/decorate';
import { markerOf } from '../src/scm/markdown';
import { statusName } from '../src/scm/render';
import { createScmRuntime } from '../src/scm/runtime';
import { gitlabShape } from './fake-gitlab';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';
import { PUBLIC_URL } from './scm';

/**
 * scm.md §11, opt-in (`pnpm gitlab:real --url <GitLab> --project <path>`): the whole flow against
 * a GitLab that is already running and a project the token may write to, never part of
 * `pnpm test`. The token (a project access token, `api` scope, Developer role, scm.md §2.1) comes
 * only from `QUALOR_GITLAB_TEST_TOKEN` and goes only into request headers: never into a file, the
 * clone's git config, an argument or a log line.
 *
 * It starts Qualor in process (Postgres through Testcontainers, workers as in main.ts), connects
 * the GitLab project, pushes a branch `qualor-test/<time>` with one TypeScript file whose added
 * line has an `eqeqeq` finding (with the ESLint configuration that turns the rule on, and a qualor.yml) through the
 * GitLab API (`[skip ci]`: the project's own pipeline does not run), opens a merge request, clones
 * the project over https, scans the branch with the real CLI as GitLab CI would, and lets the
 * server decorate the merge request over the network. It checks the decoration, repeats the scan
 * (nothing may change on GitLab), marks the issue a false positive, and records the GitLab
 * behaviours the fake GitLab models (the `observed` block that `pnpm gitlab:real` prints). Afterwards it closes the
 * merge request and deletes the branch; the notes stay on the closed merge request.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(import.meta.url);
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(require.resolve('tsx')).href;
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*|GIT_CONFIG_.*)$/i;
const CLI_KILL_MS = 180_000;
const WAIT_MS = 180_000;
const PROJECT_KEY = 'gitlab-live';
const FILE = 'qualor-test/eqeqeq.ts';
/** The flagged line: `a == b` on an added line (line 3 of the new file). */
const FLAGGED_LINE = 3;
const SOURCE = [
  '// Qualor live check: an eqeqeq finding on an added line.',
  'export function same(a, b) {',
  '  return a == b;',
  '}',
  '',
].join('\n');
const ESLINT_CONFIG =
  "export default [{ files: ['qualor-test/**/*.ts'], rules: { eqeqeq: 'error' } }];\n";

const QUALOR_CONFIG = 'version: 1\nanalyzers:\n  gitleaks:\n    enabled: false\n';

const gitlab = (process.env['QUALOR_GITLAB_LIVE_URL'] ?? '').replace(/\/+$/, '');
const projectRef = process.env['QUALOR_GITLAB_LIVE_PROJECT'] ?? '';
const token = process.env['QUALOR_GITLAB_TEST_TOKEN'] ?? '';

/** What this GitLab did, printed at the end (never the token). */
const observed: Record<string, unknown> = {};

let h: IngestHarness;
let project: IngestProject;
let url: string;
let workers: Worker[] = [];
let work = '';
let clone = '';
let glProject: {
  id: number;
  path_with_namespace: string;
  default_branch: string;
  http_url_to_repo: string;
};
let glUser: { id: number; username: string };
let branch = '';
let head = '';
let iid = 0;
let mrUrl = '';
let mrTitle = '';
const cliOutput: string[] = [];

interface Status {
  id: number;
  name: string;
  status: string;
  description: string | null;
  target_url: string | null;
  ref: string | null;
  pipeline_id?: number | null;
  [key: string]: unknown;
}
interface Note {
  id: number;
  body: string;
  author: { id: number };
  resolvable?: boolean;
  resolved?: boolean;
  resolved_by?: { id: number } | null;
  updated_at: string;
  position?: { new_path: string; new_line: number | null; head_sha: string } | null;
}
interface Discussion {
  id: string;
  notes: Note[];
}

async function api<T = unknown>(
  method: string,
  route: string,
  body?: unknown,
): Promise<{ status: number; json: T }> {
  const res = await fetch(`${gitlab}/api/v4${route}`, {
    method,
    headers: {
      'private-token': token,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text.slice(0, 500);
  }
  return { status: res.status, json: json as T };
}

async function ok<T>(method: string, route: string, body?: unknown): Promise<T> {
  const res = await api<T>(method, route, body);
  if (res.status >= 300) {
    throw new Error(`${method} ${route}: ${res.status} ${JSON.stringify(res.json).slice(0, 500)}`);
  }
  return res.json;
}

const baseEnv: Record<string, string> = Object.fromEntries(
  Object.entries(process.env).filter(
    (e): e is [string, string] => e[1] !== undefined && !CI_VARIABLE.test(e[0]),
  ),
);

/** git with no system or global configuration, so no credential helper stores anything. */
function git(cwd: string, args: string[], extraEnv: Record<string, string> = {}): string {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'credential.helper=', ...args], {
    cwd,
    env: {
      ...baseEnv,
      GIT_CONFIG_GLOBAL: path.join(work, 'empty.gitconfig'),
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      ...extraEnv,
    },
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    throw new Error(`git ${args[0]}: ${(r.stderr ?? '').split(token).join('[token]')}`);
  }
  return r.stdout.trim();
}

/** The token as an HTTP header for git, through the environment only (git-config(1) GIT_CONFIG_*). */
function gitAuthEnv(): Record<string, string> {
  const basic = Buffer.from(`oauth2:${token}`, 'utf8').toString('base64');
  return {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: `http.${new URL(gitlab).origin}/.extraHeader`,
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
  };
}

function runCli(env: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ['--import', tsxLoader, cliEntry, 'scan', '--project-key', PROJECT_KEY],
      {
        cwd: clone,
        env: {
          ...baseEnv,
          GIT_CONFIG_GLOBAL: path.join(work, 'empty.gitconfig'),
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_TERMINAL_PROMPT: '0',
          QUALOR_URL: url,
          QUALOR_TOKEN: project.token,
          ...env,
        },
        stdio: ['ignore', 'ignore', 'pipe'],
      },
    );
    let stderr = '';
    const killer = setTimeout(() => child.kill('SIGKILL'), CLI_KILL_MS);
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      cliOutput.push(stderr);
      resolve({ code, stderr });
    });
  });
}

/** What GitLab CI sets in a merge request pipeline (config.md §4); no pipeline ran, so no id. */
function mergeRequestEnv(): Record<string, string> {
  return {
    GITLAB_CI: 'true',
    CI_COMMIT_SHA: head,
    CI_COMMIT_REF_NAME: branch,
    CI_DEFAULT_BRANCH: glProject.default_branch,
    CI_PROJECT_PATH: glProject.path_with_namespace,
    CI_PROJECT_ID: String(glProject.id),
    CI_MERGE_REQUEST_IID: String(iid),
    CI_MERGE_REQUEST_SOURCE_BRANCH_NAME: branch,
    CI_MERGE_REQUEST_TARGET_BRANCH_NAME: glProject.default_branch,
    CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
  };
}

async function eventually<T>(
  check: () => Promise<T | false | null | undefined>,
  what: string,
): Promise<T> {
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    const got = await check();
    if (got) return got;
    await new Promise((resolve) => setTimeout(resolve, 1_500));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const mrPath = () => `/projects/${glProject.id}/merge_requests/${iid}`;
const statusesOf = (all: boolean, name = statusName(PROJECT_KEY)) =>
  ok<Status[]>(
    'GET',
    `/projects/${glProject.id}/repository/commits/${head}/statuses?${new URLSearchParams({
      name,
      all: String(all),
      per_page: '100',
    }).toString()}`,
  );
const discussions = () => ok<Discussion[]>('GET', `${mrPath()}/discussions?per_page=100`);
const ours = (list: Discussion[], kind: 'summary' | 'issue') =>
  list.filter(
    (d) => d.notes[0]?.author.id === glUser.id && markerOf(d.notes[0].body)?.kind === kind,
  );

/** The fields of a recorded shape (server/test/gitlab-shapes/) that GitLab's real answer lacks. */
function missingFields(name: string, real: unknown): string[] {
  const shape = gitlabShape<unknown>(name);
  const recorded = Object.keys((Array.isArray(shape) ? shape[0] : shape) as object);
  return recorded.filter((k) => !(k in (real as Record<string, unknown>)));
}

/** Every decoration and analysis job has run (none queued or running). */
async function settled(): Promise<boolean> {
  const pending = await h.ctx.db
    .select({ id: jobs.id })
    .from(jobs)
    .where(inArray(jobs.status, ['queued', 'running']));
  return pending.length === 0;
}

/** What Qualor owns on the merge request, to compare two runs. */
async function snapshot() {
  const list = await discussions();
  return {
    statusRows: (await statusesOf(true)).map((s) => [s.id, s.status, s.description]),
    notes: [...ours(list, 'summary'), ...ours(list, 'issue')].map((d) => ({
      id: d.id,
      notes: d.notes.map((n) => [n.id, n.body, n.updated_at, n.resolved ?? null]),
    })),
  };
}

beforeAll(async () => {
  if (!gitlab || !projectRef || !token) {
    throw new Error(
      'set QUALOR_GITLAB_LIVE_URL, QUALOR_GITLAB_LIVE_PROJECT and QUALOR_GITLAB_TEST_TOKEN (pnpm gitlab:real --url … --project …)',
    );
  }
  work = mkdtempSync(path.join(os.tmpdir(), 'qualor-gitlab-live-'));
  writeFileSync(path.join(work, 'empty.gitconfig'), '');
  observed['version'] = await ok('GET', '/version');
  glUser = await ok('GET', '/user');
  glProject = await ok('GET', `/projects/${encodeURIComponent(projectRef)}`);
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  branch = `qualor-test/${stamp}`;
  // `[skip ci]`: the test project's own pipeline does not run for this commit.
  const commit = await ok<{ id: string }>('POST', `/projects/${glProject.id}/repository/commits`, {
    branch,
    start_branch: glProject.default_branch,
    commit_message: 'Qualor live check (temporary branch) [skip ci]',
    actions: [
      { action: 'create', file_path: FILE, content: SOURCE },
      { action: 'create', file_path: 'eslint.config.mjs', content: ESLINT_CONFIG },
      // Gitleaks is not installed outside the scanner image; a required analyzer that cannot run
      // would fail the scan (exit 3).
      { action: 'create', file_path: 'qualor.yml', content: QUALOR_CONFIG },
    ],
  });
  head = commit.id;
  mrTitle = `Qualor live check ${stamp}`;
  const mr = await ok<{ iid: number; web_url: string }>(
    'POST',
    `/projects/${glProject.id}/merge_requests`,
    { source_branch: branch, target_branch: glProject.default_branch, title: mrTitle },
  );
  iid = mr.iid;
  mrUrl = mr.web_url;
  // GitLab prepares the merge request's diff in the background.
  await eventually(async () => {
    const got = await ok<{ diff_refs: { head_sha: string | null } | null }>('GET', mrPath());
    return got.diff_refs?.head_sha === head;
  }, 'the merge request diff');

  // Qualor, as main.ts runs it: analyses and re-evaluations in one worker, decorations in another.
  h = await createIngestHarness({ config: { publicUrl: PUBLIC_URL } });
  await h.ctx.app.listen({ port: 0, host: '127.0.0.1' });
  url = `http://127.0.0.1:${(h.ctx.app.server.address() as AddressInfo).port}`;
  const { ctx } = h;
  workers = [
    startWorker({
      db: ctx.db,
      handlers: {
        ...jobHandlers({ db: ctx.db, upload: ctx.config.upload, logger: ctx.app.log }),
        ...gateHandlers({ db: ctx.db, logger: ctx.app.log }),
      },
      concurrency: 1,
      logger: ctx.app.log,
      pollIntervalMs: 100,
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
      pollIntervalMs: 100,
    }),
  ];
}, 300_000);

afterAll(async () => {
  for (const w of workers) await w.stop();
  if (iid) {
    const closed = await api('PUT', mrPath(), { state_event: 'close' });
    observed['cleanup.mergeRequestClosed'] = closed.status;
  }
  if (branch && head) {
    const deleted = await api(
      'DELETE',
      `/projects/${glProject.id}/repository/branches/${encodeURIComponent(branch)}`,
    );
    observed['cleanup.branchDeleted'] = deleted.status;
  }
  // The ESLint link first, so removing the clone never follows it into this repository.
  const link = clone && path.join(clone, 'node_modules');
  try {
    if (link && lstatSync(link).isSymbolicLink()) unlinkSync(link);
  } catch {
    // Not created.
  }
  if (work) rmSync(work, { recursive: true, force: true, maxRetries: 5 });
  await h?.close();
  // tools/gitlab/real.ts prints it whatever the reporter shows of a passing test's output.
  const out = process.env['QUALOR_GITLAB_LIVE_OBSERVED'];
  if (out)
    writeFileSync(
      out,
      `${JSON.stringify(observed, null, 2)}
`,
    );
  else console.log(`gitlab-live observed ${JSON.stringify(observed, null, 2)}`);
}, 120_000);

describe(`decoration against a running GitLab (scm.md §11)`, () => {
  it('connects, decorates a merge request, changes nothing on a rerun, and follows a false positive', async () => {
    const { ctx, orgAdmin } = h;

    // 1. An org admin connects GitLab, tests the connection and checks the project (the UI's Test and Check).
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: orgAdmin.headers,
      payload: { organizationId: h.organizationId, provider: 'gitlab', baseUrl: gitlab, token },
    });
    expect(created.statusCode, created.body).toBe(201);
    expect(created.body).not.toContain(token);
    const connectionId = (created.json() as { id: string }).id;
    const tested = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/scm-connections/${connectionId}/test`,
      headers: orgAdmin.headers,
      payload: {},
    });
    expect(tested.json()).toMatchObject({ ok: true, user: { username: glUser.username } });
    const checked = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/scm-connections/${connectionId}/test`,
      headers: orgAdmin.headers,
      payload: { projectRef: glProject.path_with_namespace },
    });
    expect(checked.json()).toMatchObject({
      ok: true,
      project: { id: glProject.id, pathWithNamespace: glProject.path_with_namespace },
      problem: null,
    });
    project = await h.project(PROJECT_KEY);
    const mapped = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${project.id}`,
      headers: orgAdmin.headers,
      payload: { scmConnectionId: connectionId, scmProjectRef: glProject.path_with_namespace },
    });
    expect(mapped.statusCode, mapped.body).toBe(200);

    // 2. A clone over https, the token only in the environment of this one git process.
    clone = path.join(work, 'repo');
    git(work, ['clone', '-q', '--no-tags', glProject.http_url_to_repo, clone], gitAuthEnv());
    git(clone, ['checkout', '-q', branch]);
    expect(git(clone, ['rev-parse', 'HEAD'])).toBe(head);
    expect(readFileSync(path.join(clone, '.git', 'config'), 'utf8')).not.toContain(token);
    // ESLint comes from the project's node_modules (config.md §6): link this repository's.
    const eslintModules = path.dirname(path.dirname(require.resolve('eslint/package.json')));
    symlinkSync(eslintModules, path.join(clone, 'node_modules'), 'junction');

    // 3. The scan, as a merge request pipeline would run it; the server decorates over the network.
    const first = await runCli(mergeRequestEnv());
    expect(first.code, first.stderr).toBe(1);
    await eventually(async () => {
      const list = await discussions();
      return (
        (await settled()) &&
        ours(list, 'summary').length === 1 &&
        ours(list, 'issue').length === 1 &&
        (await statusesOf(false)).length === 1
      );
    }, 'the decoration');

    // 4. What GitLab shows.
    const statuses = await statusesOf(false);
    expect(statuses.map((s) => s.status)).toEqual(['failed']);
    expect(statuses[0]?.description).toMatch(/^Quality gate failed: new_issues 1 > 0/);
    observed['status.fields'] = Object.keys(statuses[0] ?? {}).sort();
    observed['status.pipelineIdPresent'] =
      statuses[0] !== undefined && 'pipeline_id' in statuses[0];
    observed['status.pipelineId'] = statuses[0]?.pipeline_id ?? null;
    observed['status.ref'] = statuses[0]?.ref ?? null;
    const list = await discussions();
    const [summary] = ours(list, 'summary');
    const [thread] = ours(list, 'issue');
    expect(summary?.notes[0]?.author.id).toBe(glUser.id);
    expect(summary?.notes[0]?.body).toContain('### ❌ Qualor: quality gate failed');
    expect(thread?.notes[0]?.position).toMatchObject({
      new_path: FILE,
      new_line: FLAGGED_LINE,
      head_sha: head,
    });
    // The recorded shapes the fake answers with have every field GitLab's real answers have.
    const diffs = await ok<unknown[]>('GET', `${mrPath()}/diffs`);
    const missing = {
      user: missingFields('user', glUser),
      project: missingFields('project', glProject),
      merge_request: missingFields('merge_request', await ok('GET', mrPath())),
      merge_request_diffs: missingFields('merge_request_diffs', diffs[0]),
      discussion: missingFields('discussion', thread),
      note: missingFields('note', summary?.notes[0]),
      commit_status: missingFields('commit_status', statuses[0]),
    };
    observed['shapes.missingFields'] = missing;
    expect(Object.values(missing).flat()).toEqual([]);
    const [mrBranch] = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    expect(mrBranch).toMatchObject({ mrTitle, mrUrl });

    // (a) A final state posted twice: GitLab adds a row, or refuses the transition.
    const probe = `qualor-probe/${Date.now().toString(36)}`;
    const postProbe = () =>
      api<Status>('POST', `/projects/${glProject.id}/statuses/${head}`, {
        state: 'success',
        name: probe,
        description: 'Qualor live check probe',
        ref: branch,
      });
    const probe1 = await postProbe();
    const probe2 = await postProbe();
    // (c) A status with `ref` and no pipeline is accepted.
    expect(probe1.status).toBe(201);
    observed['a.sameFinalStateTwice.httpStatuses'] = [probe1.status, probe2.status];
    observed['a.sameFinalStateTwice.secondAnswer'] =
      probe2.status >= 300 ? probe2.json : { id: probe2.json.id, status: probe2.json.status };
    observed['a.sameFinalStateTwice.rows'] = {
      all: (await statusesOf(true, probe)).map((s) => [s.id, s.status, s.pipeline_id ?? null]),
      latest: (await statusesOf(false, probe)).map((s) => [s.id, s.status, s.pipeline_id ?? null]),
    };
    // As the fake models it (scm.md §5.1): the second post is a new row, and only it is the latest.
    expect(probe2.status).toBe(201);
    expect(await statusesOf(true, probe)).toHaveLength(2);
    expect(await statusesOf(false, probe)).toHaveLength(1);
    observed['c.refOnlyNoPipeline'] = {
      httpStatus: probe1.status,
      pipelineId: probe1.json.pipeline_id ?? null,
      ref: probe1.json.ref ?? null,
    };

    // (d) A note body comes back as it was sent.
    const sentBody = [
      '<!-- qualor-probe -->',
      '### Probe `a` | b',
      'trailing spaces   ',
      '\ttab, non-ASCII: é ✓ 🙂, a code span `` ` ``',
      '',
      'end',
    ].join('\n');
    const note = await ok<Note>('POST', `${mrPath()}/notes`, { body: sentBody });
    const noteBack = await ok<Note>('GET', `${mrPath()}/notes/${note.id}`);
    observed['d.noteBodyStoredAsSent'] = noteBack.body === sentBody && note.body === sentBody;
    expect(noteBack.body).toBe(sentBody);
    await api('DELETE', `${mrPath()}/notes/${note.id}`);

    // (e) A reply to a resolved thread.
    const probeThread = await ok<Discussion>('POST', `${mrPath()}/discussions`, {
      body: 'Qualor live check probe: resolved, then replied to',
    });
    await ok('PUT', `${mrPath()}/discussions/${probeThread.id}?resolved=true`);
    await ok('POST', `${mrPath()}/discussions/${probeThread.id}/notes`, { body: 'a reply' });
    const replied = await ok<Discussion>('GET', `${mrPath()}/discussions/${probeThread.id}`);
    observed['e.replyToResolvedThread'] = replied.notes.map((n) => ({
      resolvable: n.resolvable ?? null,
      resolved: n.resolved ?? null,
      resolvedBy: n.resolved_by?.id ?? null,
    }));
    // As the fake models it: the reply is created resolved, by its author; the thread stays resolved.
    expect(replied.notes.map((n) => [n.resolved, n.resolved_by?.id])).toEqual([
      [true, glUser.id],
      [true, glUser.id],
    ]);
    for (const n of replied.notes) await api('DELETE', `${mrPath()}/notes/${n.id}`);

    // (f) A position GitLab cannot place is a 400 that Qualor's client reads as "not placed".
    const mr = await ok<{ diff_refs: { base_sha: string; start_sha: string; head_sha: string } }>(
      'GET',
      mrPath(),
    );
    const refs = mr.diff_refs;
    const rawRejected = await api<{ message?: unknown }>('POST', `${mrPath()}/discussions`, {
      body: 'Qualor live check probe: a position outside the diff',
      position: {
        position_type: 'text',
        base_sha: refs.base_sha,
        start_sha: refs.start_sha,
        head_sha: refs.head_sha,
        old_path: FILE,
        new_path: FILE,
        new_line: 999,
      },
    });
    observed['f.rejectedPosition'] = { status: rawRejected.status, body: rawRejected.json };
    const client = new GitLabClient({ baseUrl: gitlab, token, allowInternalHosts: false });
    const viaClient = await client.createDiscussion(String(glProject.id), String(iid), 'probe', {
      baseSha: refs.base_sha,
      startSha: refs.start_sha,
      headSha: refs.head_sha,
      oldPath: 'README.md',
      newPath: 'README.md',
      newLine: 1,
    });
    observed['f.unchangedFileViaClient'] =
      viaClient === 'position_rejected' ? viaClient : 'created';
    for (const d of [
      rawRejected.status < 300 ? (rawRejected.json as unknown as Discussion) : null,
      viaClient === 'position_rejected' ? null : viaClient,
    ]) {
      for (const n of d?.notes ?? []) await api('DELETE', `${mrPath()}/notes/${n.id}`);
    }
    expect(rawRejected.status).toBe(400);
    expect(viaClient).toBe('position_rejected');

    // 5. The same scan again changes nothing on GitLab (read before post; notes edited only on change).
    const before = await snapshot();
    const second = await runCli(mergeRequestEnv());
    expect(second.code, second.stderr).toBe(1);
    await eventually(async () => {
      const done = await ctx.db
        .select({ id: analyses.id })
        .from(analyses)
        .where(and(eq(analyses.projectId, project.id), eq(analyses.status, 'succeeded')));
      return done.length === 2 && (await settled());
    }, 'the second analysis and its decoration');
    expect(await snapshot()).toEqual(before);

    // 6. a false positive passes the gate, turns the status to success, resolves the thread.
    const [issue] = await ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, mrBranch!.id), eq(issues.status, 'open')));
    const transition = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/transition`,
      headers: orgAdmin.headers,
      payload: { to: 'false_positive', comment: 'Qualor live check' },
    });
    expect(transition.statusCode, transition.body).toBe(200);
    await eventually(async () => {
      const latest = await statusesOf(false);
      const now = await discussions();
      return (
        (await settled()) &&
        latest.length === 1 &&
        latest[0]?.status === 'success' &&
        ours(now, 'summary')[0]?.notes[0]?.body.includes('### ✅ Qualor: quality gate passed') &&
        ours(now, 'issue')[0]?.notes[0]?.resolved === true
      );
    }, 'the re-decoration after the false positive');
    const after = await discussions();
    expect(ours(after, 'summary')).toHaveLength(1);
    expect(ours(after, 'summary')[0]?.id).toBe(summary?.id);
    expect(ours(after, 'issue')).toHaveLength(1);
    expect(ours(after, 'issue')[0]?.notes[0]?.resolved_by?.id).toBe(glUser.id);
    observed['ql13.statusRows'] = (await statusesOf(true)).map((s) => [
      s.status,
      s.pipeline_id ?? null,
    ]);

    // The token went nowhere else: not in Qualor's logs, the CLI's output or the clone's files.
    expect(ctx.logs.join('\n')).not.toContain(token);
    expect(cliOutput.join('\n')).not.toContain(token);
    const gitDir = path.join(clone, '.git');
    for (const name of readdirSync(gitDir)) {
      const file = path.join(gitDir, name);
      if (lstatSync(file).isFile()) expect(readFileSync(file, 'latin1')).not.toContain(token);
    }
  }, 900_000);
});
