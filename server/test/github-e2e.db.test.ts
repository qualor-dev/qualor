import { spawn, spawnSync } from 'node:child_process';
import { createHmac, createPrivateKey, randomUUID } from 'node:crypto';
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { encryptionKey } from '../src/crypto/secrets';
import {
  analyses,
  analysisReports,
  branches,
  issues,
  jobs,
  scmConnections,
} from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { jobHandlers } from '../src/ingest/handlers';
import { runUntilIdle, startWorker, type Worker } from '../src/queue/worker';
import { readScmContext } from '../src/scm/context';
import { scmHandlers } from '../src/scm/decorate';
import { decryptPrivateKey, decryptWebhookSecret } from '../src/scm/github/credentials';
import { githubWebBase } from '../src/scm/github/url';
import { markerOf } from '../src/scm/markdown';
import { enqueueDecoration, SCM_QUEUE } from '../src/scm/queue';
import { statusName } from '../src/scm/render';
import { createFakeGitHub, type FakeGitHub } from './fake-github';
import { githubDeps, githubTestConfig, WEBHOOK_SECRET } from './github';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';
import { queuedDecorations } from './scm';

/**
 * Plan 2C, github.md §11: the whole GitHub flow end to end, against the local fake GitHub only.
 * The real CLI (TypeScript sources, as a child process) scans a git repository as a
 * GitHub Actions `pull_request` run would, uploads to a real server (Fastify on a local port,
 * Postgres through Testcontainers), and the server's `scm` queue decorates the fake's pull request.
 * Every log line, response body, job row, stored report and decoration is then searched for every
 * secret of the flow (github.md §12). Nothing contacts a real GitHub.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*|RUNNER_.*|ACTIONS_.*)$/i;
const CLI_KILL_MS = 90_000;
const REPO_ID = 424242;
const INSTALLATION = 777;
const PR = 7;
const RUN_ID = 99;
const KEY = 'acme/shop';
const CI_TOKEN = 'ghs_must_not_leak';

let harness: IngestHarness;
let project: IngestProject;
let fake: FakeGitHub;
let url: string;
const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-github-e2e-'));
const gitConfig = path.join(work, 'empty.gitconfig');
writeFileSync(gitConfig, '');
/**
 * Every HTTP response body of the server (an `onSend` hook: the API calls of the test and the
 * CLI's uploads and polls alike) and the CLI's output, for the leak search.
 */
const bodies: string[] = [];

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

/** A file's `patch` as GitHub's pull request files list holds it: the hunks, from the first `@@`. */
function patchOf(diff: string): string {
  return diff.slice(diff.indexOf('@@')).trimEnd();
}

function runCli(
  cwd: string,
  env: Record<string, string>,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ['--import', tsxLoader, cliEntry, 'scan', '--project-key', KEY],
      {
        cwd,
        env: { ...baseEnv, QUALOR_URL: url, QUALOR_TOKEN: project.token, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    const killer = setTimeout(() => child.kill('SIGKILL'), CLI_KILL_MS);
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      bodies.push(stdout, stderr);
      resolve({ code, stdout, stderr });
    });
  });
}

/** What GitHub Actions sets for a `pull_request` run of #7 at `head` (config.md §4, github.md §3). */
function actionsEnv(head: string): Record<string, string> {
  const event = path.join(work, `event-${head.slice(0, 12)}.json`);
  writeFileSync(
    event,
    JSON.stringify({
      action: 'synchronize',
      number: PR,
      pull_request: { number: PR, head: { sha: head, ref: 'feature/x' }, base: { ref: 'main' } },
      repository: { id: REPO_ID, full_name: KEY, default_branch: 'main' },
    }),
  );
  return {
    CI: 'true',
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_EVENT_PATH: event,
    GITHUB_HEAD_REF: 'feature/x',
    GITHUB_BASE_REF: 'main',
    GITHUB_REF_NAME: `${PR}/merge`,
    GITHUB_REPOSITORY: KEY,
    GITHUB_REPOSITORY_ID: String(REPO_ID),
    GITHUB_RUN_ID: String(RUN_ID),
    GITHUB_TOKEN: CI_TOKEN,
  };
}

/**
 * A scan with the analysis worker running as in main.ts (analyses and re-evaluations), which the
 * CLI waits for; the worker stops with the scan, so every decoration waits for {@link runScm}.
 */
async function scan(cwd: string, head: string) {
  const { ctx } = harness;
  const worker: Worker = startWorker({
    db: ctx.db,
    handlers: {
      ...jobHandlers({ db: ctx.db, upload: ctx.config.upload, logger: ctx.app.log }),
      ...gateHandlers({ db: ctx.db, logger: ctx.app.log }),
    },
    concurrency: 1,
    logger: ctx.app.log,
    pollIntervalMs: 50,
  });
  try {
    return await runCli(cwd, actionsEnv(head));
  } finally {
    await worker.stop();
  }
}

/** Runs the `gate` queue (re-evaluations) until idle, logging to the captured log. */
async function runGate(): Promise<number> {
  const { ctx } = harness;
  return runUntilIdle(ctx.db, gateHandlers({ db: ctx.db, logger: ctx.app.log }), ctx.app.log);
}

/** Makes every queued decoration due now and runs the `scm` queue until idle, logging to the captured log. */
async function runScm(): Promise<number> {
  const { ctx } = harness;
  await ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(eq(jobs.queue, SCM_QUEUE));
  return runUntilIdle(ctx.db, scmHandlers(githubDeps(harness)), ctx.app.log);
}

/** An API call through the app (its body reaches the leak search through the `onSend` hook). */
async function api(
  method: 'GET' | 'POST' | 'PATCH',
  target: string,
  payload?: string | Record<string, unknown>,
  headers: Record<string, string> = harness.orgAdmin.headers,
) {
  const res = await harness.ctx.app.inject({
    method,
    url: target,
    headers,
    ...(payload === undefined ? {} : { payload }),
  });
  return res;
}

/** Every request the fake received, across {@link clearRequests}: the JWTs are searched for. */
const received: FakeGitHub['requests'] = [];
function clearRequests(): void {
  received.push(...fake.requests);
  fake.clearRequests();
}

const runs = () => fake.checkRuns.filter((r) => r.repoId === REPO_ID);
const runsOn = (sha: string) => runs().filter((r) => r.headSha === sha);
const summaries = () =>
  fake.comments.filter(
    (c) => c.repoId === REPO_ID && c.issue === PR && markerOf(c.body)?.kind === 'summary',
  );
/** Requests that change something on GitHub (an installation token changes nothing). */
const writes = () =>
  fake.requests
    .filter((r) => r.method !== 'GET' && !r.path.endsWith('/access_tokens'))
    .map((r) => `${r.method} ${r.path}`);

beforeAll(async () => {
  fake = await createFakeGitHub();
  fake.addRepository({ id: REPO_ID, owner: 'acme', name: 'shop', installationId: INSTALLATION });
  // Every line the server logs at its configured level goes to `harness.ctx.logs` (a pino
  // destination appending to an array), the loggers of the workers and jobs included.
  harness = await createIngestHarness({
    config: githubTestConfig(fake),
    beforeReady: (app) =>
      app.addHook('onSend', async (_request, _reply, payload) => {
        if (typeof payload === 'string') bodies.push(payload);
        else if (Buffer.isBuffer(payload)) bodies.push(payload.toString('utf8'));
        return payload;
      }),
  });
  project = await harness.project(KEY);
  await harness.ctx.app.listen({ port: 0, host: '127.0.0.1' });
  url = `http://127.0.0.1:${(harness.ctx.app.server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await harness.close();
  await fake.close();
  rmSync(work, { recursive: true, force: true, maxRetries: 5 });
});

describe('GitHub end to end, against the fake GitHub (github.md §11, §12)', () => {
  it('decorates a pull request, re-evaluates after a false positive, re-runs, follows a fix, and leaks no secret', async () => {
    const { ctx } = harness;

    // An org admin connects the App, tests it, and maps the project, through the API.
    const created = await api('POST', '/api/v0/scm-connections', {
      organizationId: harness.organizationId,
      provider: 'github',
      baseUrl: fake.url,
      appId: String(fake.appId),
      privateKey: fake.privateKeyPem,
      webhookSecret: WEBHOOK_SECRET,
    });
    expect(created.statusCode, created.body).toBe(201);
    const connectionId = (created.json() as { id: string }).id;
    const tested = await api('POST', `/api/v0/scm-connections/${connectionId}/test`, {
      projectRef: KEY,
    });
    expect(tested.statusCode, tested.body).toBe(200);
    expect(tested.json()).toEqual({
      ok: true,
      user: { username: `${fake.slug}[bot]` },
      project: { id: REPO_ID, pathWithNamespace: KEY },
      problem: null,
    });
    const mapped = await api('PATCH', `/api/v0/projects/${project.id}`, {
      scmConnectionId: connectionId,
      scmProjectRef: KEY,
    });
    expect(mapped.statusCode, mapped.body).toBe(200);
    const listed = await api(
      'GET',
      `/api/v0/scm-connections?organizationId=${harness.organizationId}`,
    );
    expect(listed.statusCode, listed.body).toBe(200);

    // A repository: `src/a.ts` on main, and feature/x adding `if (a == b) {}` on line 2. The
    // project's ESLint (the repository's own, through a link, as the fixture runner does) flags it.
    const root = path.join(work, 'repo');
    mkdirSync(root);
    git(root, 'init', '-q', '-b', 'main');
    symlinkSync(path.join(repoRoot, 'node_modules'), path.join(root, 'node_modules'), 'junction');
    appendFileSync(path.join(root, '.git', 'info', 'exclude'), '/node_modules\n');
    write(root, {
      'qualor.yml': 'version: 1\nanalyzers:\n  gitleaks:\n    enabled: false\n',
      'eslint.config.mjs': "export default [{ files: ['**/*.ts'], rules: { eqeqeq: 'error' } }];\n",
      'src/a.ts': 'export const a = 1;\n',
    });
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'first');
    const main = git(root, 'rev-parse', 'HEAD');
    git(root, 'update-ref', 'refs/remotes/origin/main', main);
    git(root, 'checkout', '-q', '-b', 'feature/x');
    write(root, { 'src/a.ts': 'export const a = 1;\nif (a == b) {}\n' });
    git(root, 'commit', '-q', '-am', 'compare');
    const head = git(root, 'rev-parse', 'HEAD');
    fake.addPull(REPO_ID, {
      number: PR,
      title: 'Compare a and b',
      state: 'open',
      headSha: head,
      baseSha: main,
      files: [
        { filename: 'src/a.ts', patch: patchOf(git(root, 'diff', main, head, '--', 'src/a.ts')) },
      ],
    });

    // The CLI in GitHub Actions: the gate fails on eqeqeq, and the analysis keeps the CI context.
    const onPr = await scan(root, head);
    expect(onPr.code, onPr.stderr).toBe(1);
    const [prBranch] = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    const [prAnalysis] = await ctx.db
      .select()
      .from(analyses)
      .where(eq(analyses.id, prBranch!.lastAnalysisId!));
    expect(prAnalysis?.status).toBe('succeeded');
    expect(prAnalysis?.revision).toBe(head);
    const stored = readScmContext(prAnalysis?.scmContext);
    expect(stored.kind).toBe('ok');
    const context = stored.kind === 'ok' ? stored.context : null;
    expect(context?.github ?? null).toEqual({
      repositoryId: String(REPO_ID),
      runId: String(RUN_ID),
      checkout: 'head',
    });

    // The `scm` queue decorates: a failing check run with one annotation, one summary, the PR's
    // title and link on the branch.
    expect(await runScm()).toBe(1);
    expect(runs()).toHaveLength(1);
    const [first] = runs();
    expect(first).toMatchObject({
      name: statusName(KEY),
      headSha: head,
      conclusion: 'failure',
    });
    expect(first?.annotations).toEqual([
      expect.objectContaining({ path: 'src/a.ts', start_line: 2, end_line: 2 }),
    ]);
    expect(summaries()).toHaveLength(1);
    const summaryId = summaries()[0]?.id;
    expect(summaries()[0]?.user).toMatchObject({ login: `${fake.slug}[bot]`, type: 'Bot' });
    expect(summaries()[0]?.body).toContain('### Qualor: quality gate failed');
    const [decorated] = await ctx.db.select().from(branches).where(eq(branches.id, prBranch!.id));
    expect(decorated).toMatchObject({
      mrTitle: 'Compare a and b',
      mrUrl: `${githubWebBase(fake.url)}/acme/shop/pull/${PR}`,
    });

    // The same job again (github.md §11 #1, §6.1): nothing but reads and a token.
    clearRequests();
    await enqueueDecoration(ctx.db, {
      analysisId: prAnalysis!.id,
      branchId: prBranch!.id,
      gitlab: context?.gitlab ?? null,
      github: context?.github ?? null,
    });
    expect(await runScm()).toBe(1);
    expect(fake.requests.length).toBeGreaterThan(0);
    expect(writes()).toEqual([]);

    // A new analysis with the same result (the workflow run again): exactly one PATCH of the check
    // run, which moves its analysis id (§6.1).
    clearRequests();
    const again = await scan(root, head);
    expect(again.code, again.stderr).toBe(1);
    expect(await runScm()).toBe(1);
    expect(writes()).toEqual([`PATCH /repos/acme/shop/check-runs/${first!.id}`]);
    expect(runs()).toHaveLength(1);

    // G5: a false positive passes the gate without a scan; the re-evaluation re-decorates.
    const [issue] = await ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, prBranch!.id), eq(issues.status, 'open')));
    const transition = await api('POST', `/api/v0/issues/${issue!.id}/transition`, {
      to: 'false_positive',
      comment: 'intended',
    });
    expect(transition.statusCode, transition.body).toBe(200);
    expect(await runGate()).toBeGreaterThan(0);
    expect(await runScm()).toBe(1);
    expect(runs().at(-1)).toMatchObject({ headSha: head, conclusion: 'success', annotations: [] });
    // Another digest (the annotation is gone): a new check run beside the first (§6.1).
    expect(runs()).toHaveLength(2);
    expect(summaries()).toHaveLength(1);
    expect(summaries()[0]?.body).toContain('### Qualor: quality gate passed');

    // The check run's Re-run (a signed check_run.rerequested): one decoration, which changes nothing.
    const newest = runs().at(-1)!;
    const delivery = JSON.stringify({
      action: 'rerequested',
      check_run: {
        id: newest.id,
        name: newest.name,
        head_sha: newest.headSha,
        external_id: newest.externalId,
        app: { id: fake.appId, slug: fake.slug },
      },
      repository: { id: REPO_ID, full_name: KEY },
      installation: { id: INSTALLATION },
    });
    const hook = await api('POST', `/api/v0/github/webhooks/${connectionId}`, delivery, {
      'content-type': 'application/json',
      'x-github-event': 'check_run',
      'x-github-delivery': randomUUID(),
      'x-hub-signature-256': `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(delivery).digest('hex')}`,
    });
    expect(hook.statusCode, hook.body).toBe(204);
    expect(await queuedDecorations(harness)).toHaveLength(1);
    clearRequests();
    const runsBefore = runs().length;
    expect(await runScm()).toBe(1);
    expect(writes()).toEqual([]);
    expect(runs()).toHaveLength(runsBefore);

    // A fix: a new head, a new analysis, a new check run on it, the same summary edited in place.
    write(root, { 'src/a.ts': 'export const a = 1;\nif (a === b) {}\n' });
    git(root, 'commit', '-q', '-am', 'fix');
    const fixed = git(root, 'rev-parse', 'HEAD');
    fake.updatePull(REPO_ID, PR, {
      headSha: fixed,
      files: [
        { filename: 'src/a.ts', patch: patchOf(git(root, 'diff', main, fixed, '--', 'src/a.ts')) },
      ],
    });
    const onFix = await scan(root, fixed);
    expect(onFix.code, onFix.stderr).toBe(0);
    expect(await runScm()).toBe(1);
    expect(runsOn(fixed)).toEqual([
      expect.objectContaining({ name: statusName(KEY), conclusion: 'success', annotations: [] }),
    ]);
    expect(summaries()).toHaveLength(1);
    expect(summaries()[0]?.id).toBe(summaryId);
    expect(summaries()[0]?.body).toContain(fixed.slice(0, 12));
    expect(fake.comments.filter((c) => c.repoId === REPO_ID)).toHaveLength(1);

    // A transient failure (GitHub answers 502 once): the decoration is retried, and logs so; its
    // log lines join the leak search below.
    const [latest] = await ctx.db.select().from(branches).where(eq(branches.id, prBranch!.id));
    await enqueueDecoration(ctx.db, {
      analysisId: latest!.lastAnalysisId!,
      branchId: prBranch!.id,
      gitlab: null,
      github: { repositoryId: String(REPO_ID), runId: String(RUN_ID), checkout: 'head' },
    });
    fake.inject('GET', /^\/app$/, { status: 502, body: { message: 'Server Error' } });
    expect(await runScm()).toBe(1);
    expect(ctx.logs.some((line) => line.includes('GitHub decoration retried'))).toBe(true);
    clearRequests();
    expect(await runScm()).toBe(1);
    expect(writes()).toEqual([]);

    // github.md §12: the leak search.
    const pkcs1 = fake.privateKeyPem;
    const keyObject = createPrivateKey(pkcs1);
    const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'pem' }).toString();
    const der = keyObject.export({ type: 'pkcs1', format: 'der' });
    const jwk = keyObject.export({ format: 'jwk' });
    const jwts = [
      ...new Set(
        [...received, ...fake.requests]
          .filter((r) => r.auth === 'jwt')
          .map((r) => String(r.headers.authorization).slice('Bearer '.length)),
      ),
    ];
    const secrets: [string, string][] = [
      ['the PEM (PKCS#1) body', pkcs1.split('\n')[1]!],
      ['the PEM (PKCS#8) body', pkcs8.split('\n')[1]!],
      ['the key in base64 (DER)', der.toString('base64').slice(64, 128)],
      ['the key in base64url (DER)', der.toString('base64url').slice(64, 128)],
      ['the PEM in base64', Buffer.from(pkcs1).toString('base64').slice(120, 180)],
      ['the key as a JWK', String(jwk.d).slice(0, 40)],
      ['a PEM header', 'PRIVATE KEY'],
      ['the webhook secret', WEBHOOK_SECRET],
      ['the webhook secret in base64', Buffer.from(WEBHOOK_SECRET).toString('base64')],
      ['the CI token', CI_TOKEN],
      ...[...fake.tokens.keys()].map((t): [string, string] => ['an installation token', t]),
      ...jwts.flatMap((j): [string, string][] => [
        ['a JWT', j],
        ['a JWT signature', j.split('.')[2]!],
      ]),
    ];
    expect(fake.tokens.size).toBeGreaterThan(0);
    expect(jwts.length).toBeGreaterThan(0);

    const connections = await ctx.db.select().from(scmConnections);
    expect(connections).toHaveLength(1);
    const [connection] = connections;
    expect(connection?.appId).toBe(String(fake.appId));
    for (const envelope of [connection?.tokenEnc, connection?.webhookSecretEnc]) {
      expect(Object.keys(envelope ?? {}).sort()).toEqual(['ct', 'iv', 'tag', 'v']);
    }
    const serverKey = encryptionKey(ctx.config.secretKey);
    expect(decryptPrivateKey(serverKey, connection!.tokenEnc)?.pkcs8).toBe(pkcs8);
    expect(decryptWebhookSecret(serverKey, connection!.webhookSecretEnc)).toBe(WEBHOOK_SECRET);

    const jobRows = await ctx.db.select().from(jobs);
    expect(jobRows.some((j) => j.queue === SCM_QUEUE)).toBe(true);
    const analysisRows = await ctx.db
      .select({ id: analyses.id, scmContext: analyses.scmContext, error: analyses.error })
      .from(analyses);
    const reports = await ctx.db.select({ body: analysisReports.body }).from(analysisReports);
    const places: [string, string][] = [
      ['the log', ctx.logs.join('\n')],
      ...bodies.map((b, i): [string, string] => [`response ${i}`, b]),
      ...jobRows.map((j): [string, string] => [`job ${j.id}`, JSON.stringify(j)]),
      ...analysisRows.map((a): [string, string] => [`analysis ${a.id}`, JSON.stringify(a)]),
      ...reports.map((r, i): [string, string] => [
        `stored report ${i}`,
        gunzipSync(r.body).toString('utf8'),
      ]),
      ['the check runs', JSON.stringify(fake.checkRuns)],
      ['the comments', JSON.stringify(fake.comments)],
      [
        'the requests to GitHub (bodies and paths)',
        JSON.stringify([...received, ...fake.requests].map((r) => [r.method, r.path, r.body])),
      ],
      ['the scm_connections row', JSON.stringify(connection)],
    ];
    expect(ctx.logs.length).toBeGreaterThan(0);
    // The search covers the decoration's own log lines, not only the HTTP server's.
    expect(ctx.logs.some((line) => /decoration|re-evaluated/.test(line))).toBe(true);
    // The CLI's calls to the server went through the hook too.
    expect(bodies.some((b) => b.includes('"status":"succeeded"'))).toBe(true);
    expect(reports.length).toBeGreaterThan(0);
    const found = places.flatMap(([where, text]) =>
      secrets.filter(([, secret]) => text.includes(secret)).map(([what]) => `${what} in ${where}`),
    );
    expect(found).toEqual([]);
  }, 300_000);
});
