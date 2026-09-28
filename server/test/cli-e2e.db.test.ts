import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import net, { type AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { count, eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyses, organizations } from '../src/db/schema';
import { jobHandlers } from '../src/ingest/handlers';
import { startWorker, type Worker } from '../src/queue/worker';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';

/**
 * Plan 1D Task 10: the real CLI (TypeScript sources, as a child process: the CLI never imports
 * server code) against a real server (Fastify on a local port, Postgres via Testcontainers, the
 * analysis worker running), end to end: new-code baseline, upload with Expect: 100-continue,
 * processing, gate polling and the exit codes of config.md §7.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
/** `QUALOR_BIN` runs a compiled binary (the cli-binary CI job), otherwise the TypeScript sources. */
const qualorBin = process.env['QUALOR_BIN'];
const cliCommand: [string, string[]] =
  qualorBin !== undefined && qualorBin !== ''
    ? [path.resolve(repoRoot, qualorBin), []]
    : [process.execPath, ['--import', tsxLoader, cliEntry]];
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*)$/i;
/** A CLI that runs longer than this is killed and the test fails: nothing here may hang. */
const CLI_KILL_MS = 90_000;

let harness: IngestHarness;
let project: IngestProject;
let url: string;
let worker: Worker | undefined;
const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-cli-e2e-'));
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

/** Only the analyzers every machine has are enabled; external SARIF supplies the findings. */
const QUALOR_YML = 'version: 1\nanalyzers:\n  gitleaks:\n    enabled: false\n';

function newRepo(name: string, qualorYml = QUALOR_YML): string {
  const root = path.join(work, name);
  mkdirSync(root);
  git(root, 'init', '-q', '-b', 'main');
  write(root, { 'qualor.yml': qualorYml, 'src/a.ts': 'export const a = 1;\n' });
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '-m', 'first');
  return root;
}

function runCli(
  cwd: string,
  args: string[],
  env: Record<string, string> = {},
): Promise<{ code: number | null; stderr: string; ms: number }> {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(cliCommand[0], [...cliCommand[1], 'scan', ...args], {
      cwd,
      env: { ...baseEnv, QUALOR_URL: url, QUALOR_TOKEN: project.token, ...env },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    const killer = setTimeout(() => {
      stderr += `\n[killed after ${CLI_KILL_MS} ms]`;
      child.kill('SIGKILL');
    }, CLI_KILL_MS);
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      resolve({ code, stderr, ms: Date.now() - started });
    });
  });
}

/** One external SARIF result (engine `e2e-tool`) on `path:line`. */
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
            message: { text: 'A magic number.' },
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

function startAnalysisWorker(): Worker {
  return startWorker({
    db: harness.ctx.db,
    handlers: jobHandlers({
      db: harness.ctx.db,
      upload: harness.ctx.config.upload,
      logger: harness.ctx.app.log,
    }),
    concurrency: 1,
    logger: harness.ctx.app.log,
    pollIntervalMs: 50,
  });
}

beforeAll(async () => {
  harness = await createIngestHarness();
  project = await harness.project('acme/e2e');
  await harness.ctx.app.listen({ port: 0, host: '127.0.0.1' });
  url = `http://127.0.0.1:${(harness.ctx.app.server.address() as AddressInfo).port}`;
  worker = startAnalysisWorker();
});

afterAll(async () => {
  await worker?.stop();
  await harness.close();
  rmSync(work, { recursive: true, force: true, maxRetries: 5 });
});

describe('qualor scan against a real server', () => {
  it('passes the gate on the first main-branch analysis, then fails it for a new issue on new code', async () => {
    // A project of its own: its main-branch history is only these two analyses, whatever other
    // tests ran before (the second scan's baseline is the first scan's revision).
    const flow = await harness.project('acme/e2e-flow');
    const env = { QUALOR_TOKEN: flow.token };
    const root = newRepo('main-flow');
    const first = await runCli(root, ['--project-key', 'acme/e2e-flow'], env);
    expect(first.code, first.stderr).toBe(0);
    expect(first.stderr).toContain('quality gate "Qualor way": passed');

    // A new commit adds lines; an external tool flags one of them.
    write(root, {
      'src/b.ts':
        Array.from({ length: 30 }, (_, i) => `export const b${i} = ${i};`).join('\n') + '\n',
    });
    git(root, 'add', '-A');
    git(root, 'commit', '-q', '-m', 'second');
    writeFileSync(path.join(work, 'finding.sarif'), sarif('src/b.ts', 7));
    const second = await runCli(
      root,
      ['--project-key', 'acme/e2e-flow', '--sarif', path.join(work, 'finding.sarif')],
      env,
    );
    expect(second.code, second.stderr).toBe(1);
    expect(second.stderr).toContain('quality gate "Qualor way": failed');
    expect(second.stderr).toContain('new_issues > 0: 1 (failed)');
    expect(second.stderr).not.toContain(flow.token);
  }, 120_000);

  it('exits 0 at once with --no-wait', async () => {
    const root = newRepo('no-wait');
    const r = await runCli(root, ['--project-key', 'acme/e2e', '--no-wait']);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain('queued');
    expect(r.stderr).toContain('not waiting for the quality gate');
    expect(r.stderr).not.toContain('quality gate "');
    // Nothing keeps the process alive after its last request (server.timeoutSeconds is 30 s).
    expect(r.ms).toBeLessThan(20_000);
  }, 120_000);

  it('exits 4 for an unknown project, 5 for a bad token, 2 for a main-branch mismatch', async () => {
    const root = newRepo('errors');
    const unknown = await runCli(root, ['--project-key', 'acme/nope']);
    expect(unknown.code, unknown.stderr).toBe(4);
    expect(unknown.stderr).toContain('project acme/nope does not exist on the server');

    const badToken = await runCli(root, ['--project-key', 'acme/e2e'], {
      QUALOR_TOKEN: 'qlr_prj_00000000000000000000000000000000',
    });
    expect(badToken.code, badToken.stderr).toBe(5);

    const trunk = newRepo('trunk', `${QUALOR_YML}scm:\n  mainBranch: trunk\n`);
    const mismatch = await runCli(trunk, ['--project-key', 'acme/e2e', '--branch', 'trunk']);
    expect(mismatch.code, mismatch.stderr).toBe(2);
    expect(mismatch.stderr).toContain(
      'this scan treats "trunk" as the main branch, but the server\'s main branch for acme/e2e is main',
    );
  }, 120_000);

  it('after a lapse, an upload to the fifth organisation succeeds (enterprise.md §8)', async () => {
    // The community edition (no key, as after a lapse) and four organisations older than the
    // project's: before 5A the fifth organisation was read-only and the upload answered 409.
    const info = await harness.ctx.app.inject({
      method: 'GET',
      url: '/api/v0/system/info',
      headers: harness.orgAdmin.headers,
    });
    expect(info.json()).toMatchObject({ edition: 'community', features: [] });
    const older = await harness.ctx.db
      .insert(organizations)
      .values(
        ['cli-lapse-a', 'cli-lapse-b', 'cli-lapse-c', 'cli-lapse-d'].map((key) => ({
          key,
          name: key,
          createdAt: new Date('2000-01-01T00:00:00Z'),
        })),
      )
      .returning({ id: organizations.id });
    const analysesOf = async () =>
      (
        await harness.ctx.db
          .select({ n: count() })
          .from(analyses)
          .where(eq(analyses.projectId, project.id))
      )[0]!.n;
    try {
      expect((await harness.ctx.db.select({ n: count() }).from(organizations))[0]!.n).toBe(5);
      const before = await analysesOf();
      const r = await runCli(newRepo('after-lapse'), ['--project-key', 'acme/e2e', '--no-wait']);
      expect(r.code, r.stderr).toBe(0);
      expect(r.stderr).not.toContain('read-only');
      expect(await analysesOf()).toBe(before + 1);
    } finally {
      await harness.ctx.db.delete(organizations).where(
        inArray(
          organizations.id,
          older.map((o) => o.id),
        ),
      );
    }
  }, 120_000);

  it('refuses a server.url that only qualor.yml names, without any request', async () => {
    const root = newRepo('qb9', `${QUALOR_YML}server:\n  url: ${url}\n`);
    const r = await runCli(root, ['--project-key', 'acme/e2e'], { QUALOR_URL: '' });
    expect(r.code, r.stderr).toBe(2);
    expect(r.stderr).toContain('or pass --server-url');
  }, 120_000);

  it('exits 4 within server.timeoutSeconds when the server accepts connections and never answers', async () => {
    const sockets: net.Socket[] = [];
    const hung = net.createServer((s) => {
      s.on('error', () => undefined);
      sockets.push(s);
    });
    await new Promise<void>((resolve) => hung.listen(0, '127.0.0.1', resolve));
    const hungUrl = `http://127.0.0.1:${(hung.address() as AddressInfo).port}`;
    try {
      const root = newRepo('hung', `${QUALOR_YML}server:\n  timeoutSeconds: 2\n`);
      // The main branch asks for the new-code baseline first: that request times out.
      const baseline = await runCli(root, ['--project-key', 'acme/e2e'], { QUALOR_URL: hungUrl });
      expect(baseline.code, baseline.stderr).toBe(4);
      // The same words under Node and in the Bun binary, well before anything is a hang.
      expect(baseline.stderr).toContain('cannot reach');
      expect(baseline.stderr).toContain('no response within 2 s');
      // A branch scan asks for nothing before the upload: the upload times out.
      git(root, 'checkout', '-q', '-b', 'feature/hung');
      const upload = await runCli(root, ['--project-key', 'acme/e2e', '--branch', 'feature/hung'], {
        QUALOR_URL: hungUrl,
      });
      expect(upload.code, upload.stderr).toBe(4);
      expect(upload.stderr).toContain('cannot reach');
      for (const r of [baseline, upload]) expect(r.ms).toBeLessThan(30_000);
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => hung.close(() => resolve()));
    }
  }, 120_000);

  it('exits 4 naming the analysis when it does not finish within gate.timeoutSeconds', async () => {
    // No worker: the analysis stays queued. A project of its own, so nothing else sees it.
    await worker?.stop();
    worker = undefined;
    const stalled = await harness.project('acme/e2e-stalled');
    try {
      const root = newRepo('stalled', `${QUALOR_YML}gate:\n  timeoutSeconds: 3\n`);
      const r = await runCli(root, ['--project-key', 'acme/e2e-stalled'], {
        QUALOR_TOKEN: stalled.token,
      });
      expect(r.code, r.stderr).toBe(4);
      expect(r.stderr).toMatch(
        /the quality gate was not available after 3 s \(analysis [0-9a-f-]{36} is still queued\)/,
      );
      expect(r.stderr).not.toContain(stalled.token);
      expect(r.ms).toBeLessThan(20_000);
    } finally {
      worker = startAnalysisWorker();
    }
  }, 120_000);

  it('exits 4 at gate.timeoutSeconds when the server hangs while the CLI polls', async () => {
    // Answers the baseline and the upload like a Qualor server, then never answers a poll:
    // each poll must end at the gate deadline, not after server.timeoutSeconds (30 s).
    const analysisId = '0192a4c6-1c2e-7a3b-9f00-00000000e2e0';
    let polls = 0;
    const hanging = http.createServer((req, res) => {
      const p = new URL(req.url ?? '/', 'http://x').pathname;
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (p === '/api/v0/projects/new-code-baseline') {
        send(200, { revision: null, warnings: [] });
      } else if (p === '/api/v0/analyses' && req.method === 'POST') {
        req.resume();
        req.on('end', () =>
          send(202, { analysisId, status: 'queued', statusUrl: `/api/v0/analyses/${analysisId}` }),
        );
      } else if (p === `/api/v0/analyses/${analysisId}`) {
        polls += 1; // never answered
      } else {
        send(404, { code: 'NOT_FOUND' });
      }
    });
    await new Promise<void>((resolve) => hanging.listen(0, '127.0.0.1', resolve));
    const hangingUrl = `http://127.0.0.1:${(hanging.address() as AddressInfo).port}`;
    try {
      const root = newRepo('poll-hang', `${QUALOR_YML}gate:\n  timeoutSeconds: 3\n`);
      const r = await runCli(root, ['--project-key', 'acme/e2e'], { QUALOR_URL: hangingUrl });
      expect(r.code, r.stderr).toBe(4);
      expect(r.stderr).toContain(`analysis ${analysisId} queued`);
      expect(r.stderr).toContain(
        `the quality gate was not available after 3 s (the state of analysis ${analysisId} is unknown; last error: cannot reach`,
      );
      expect(polls).toBeGreaterThanOrEqual(1);
      expect(r.ms).toBeLessThan(20_000);
    } finally {
      hanging.closeAllConnections();
      await new Promise<void>((resolve) => hanging.close(() => resolve()));
    }
  }, 120_000);
});
