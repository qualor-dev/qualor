import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { reportSchema, type Report } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { commitAll, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { json, problem, useTestServers } from '../../test/http';
import { captureIO } from '../../test/io';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { Analyzer } from '../analyzers/types';
import { CliError } from '../errors';
import { parseCommandLine, type ScanFlags } from '../args';
import { createLogger } from '../log';
import { runScan, type ScanDeps } from './run';

const tmp = useTempDirs();
const serve = useTestServers();
const ID = '0192a4c6-1c2e-7a3b-9f00-0000000000aa';
const TOKEN = 'qlr_prj_upload_flow_token';

function repo(qualorYml = 'version: 1\n'): string {
  const root = path.join(tmp(), 'repo');
  writeTree(root, { 'qualor.yml': qualorYml, 'src/a.ts': 'export const a = 1;\n' });
  initRepo(root);
  commitAll(root, 'init');
  return root;
}

function flags(argv: string[] = []): ScanFlags {
  const c = parseCommandLine(['scan', '--project-key', 'acme/app', ...argv]);
  if (c.name !== 'scan') throw new Error('not a scan');
  return c.flags;
}

interface Fake {
  url: string;
  uploaded: Report[];
  paths: string[];
}

/** A Qualor server double: the baseline, the upload and a scripted analysis status. */
async function fakeServer(
  statuses: unknown[],
  upload?: (res: Parameters<typeof json>[0]) => void,
): Promise<Fake> {
  const uploaded: Report[] = [];
  const paths: string[] = [];
  const { url } = await serve((req, res, recorded) => {
    const u = new URL(req.url ?? '/', 'http://x');
    paths.push(`${req.method} ${u.pathname}`);
    if (u.pathname === '/api/v0/projects/new-code-baseline') {
      json(res, 200, { revision: null, warnings: [] });
    } else if (u.pathname === '/api/v0/analyses' && req.method === 'POST') {
      if (upload !== undefined) {
        upload(res);
        return;
      }
      uploaded.push(reportSchema.parse(JSON.parse(gunzipSync(recorded.body).toString('utf8'))));
      json(res, 202, { analysisId: ID, status: 'queued', statusUrl: `/api/v0/analyses/${ID}` });
    } else if (u.pathname === `/api/v0/analyses/${ID}`) {
      json(
        res,
        200,
        statuses.shift() ?? { id: ID, status: 'queued', gateStatus: null, error: null },
      );
    } else {
      problem(res, 404, 'NOT_FOUND');
    }
  });
  return { url, uploaded, paths };
}

const done = (gateStatus: string | null, status = 'succeeded') => ({
  id: ID,
  status,
  gateStatus,
  gateResult: null,
  error: status === 'failed' ? { code: 'PROCESSING_ERROR', message: 'boom' } : null,
});

async function scan(
  root: string,
  server: Fake,
  argv: string[] = [],
  deps: ScanDeps = {},
): Promise<{ code: number; stderr: string }> {
  const c = captureIO({
    cwd: root,
    env: { ...SCAN_TEST_ENV, QUALOR_URL: server.url, QUALOR_TOKEN: TOKEN },
  });
  const log = createLogger('info', c.io.stderr);
  // As `main` does: a CliError becomes its exit code and its message on stderr.
  const code = await runScan(flags(argv), c.io, log, {
    analyzers: [],
    wait: () => Promise.resolve(),
    ...deps,
  }).catch((err: unknown) => {
    if (!(err instanceof CliError)) throw err;
    log.error(err.message);
    return err.exitCode;
  });
  return { code, stderr: c.stderr() };
}

describe('qualor scan: upload, gate polling and exit codes (config.md §7)', () => {
  it(
    'uploads the report, waits for the gate and exits 0 when it passed',
    { timeout: 60_000 },
    async () => {
      const server = await fakeServer([done(null, 'queued'), done('passed')]);
      const { code, stderr } = await scan(repo(), server);
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([
        'GET /api/v0/projects/new-code-baseline',
        'POST /api/v0/analyses',
        `GET /api/v0/analyses/${ID}`,
        `GET /api/v0/analyses/${ID}`,
      ]);
      expect(server.uploaded[0]?.project.key).toBe('acme/app');
      expect(server.uploaded[0]?.scm.baseline.status).toBe('first_analysis');
      expect(stderr).toContain('quality gate: passed');
      expect(stderr).not.toContain(TOKEN);
    },
  );

  it.each([
    ['failed', 'succeeded', 'version: 1\n', 1],
    ['error', 'succeeded', 'version: 1\n', 1],
    ['error', 'succeeded', 'version: 1\ngate:\n  failOnError: false\n', 0],
    [null, 'failed', 'version: 1\n', 1],
    ['none', 'succeeded', 'version: 1\n', 0],
  ])(
    'gate %s of a %s analysis with %j exits %i',
    { timeout: 60_000 },
    async (gate, status, yml, exit) => {
      const server = await fakeServer([done(gate, status)]);
      expect((await scan(repo(yml), server)).code).toBe(exit);
    },
  );

  it('does not wait with --no-wait', { timeout: 60_000 }, async () => {
    const server = await fakeServer([]);
    const { code } = await scan(repo(), server, ['--no-wait']);
    expect(code).toBe(0);
    expect(server.paths).not.toContain(`GET /api/v0/analyses/${ID}`);
  });

  it(
    'exits 4 when the gate does not arrive within gate.timeoutSeconds',
    { timeout: 60_000 },
    async () => {
      const server = await fakeServer([]);
      let t = 0;
      const { code, stderr } = await scan(
        repo('version: 1\ngate:\n  timeoutSeconds: 5\n'),
        server,
        [],
        {
          clock: () => t,
          wait: (ms) => {
            t += ms;
            return Promise.resolve();
          },
        },
      );
      expect(code).toBe(4);
      expect(stderr).toContain('not available after 5 s');
    },
  );

  it(
    'uploads but exits 3 without waiting when a required analyzer failed (ruling E3)',
    { timeout: 60_000 },
    async () => {
      const server = await fakeServer([done('passed')]);
      const failing: Analyzer = {
        id: 'pmd',
        languages: [],
        prepare: () => Promise.resolve({ skip: 'pmd is not installed' }),
      };
      const { code, stderr } = await scan(
        repo('version: 1\nanalyzers:\n  pmd:\n    enabled: true\n'),
        server,
        [],
        { analyzers: [failing] },
      );
      expect(code).toBe(3);
      expect(server.uploaded[0]?.engines).toEqual([
        expect.objectContaining({ id: 'pmd', status: 'failed', reason: 'pmd is not installed' }),
      ]);
      expect(server.paths).not.toContain(`GET /api/v0/analyses/${ID}`);
      expect(stderr).toContain('required analyzers failed: pmd');
    },
  );

  it(
    'exits 5 when the upload is refused for the token, and 4 for an unknown project',
    { timeout: 60_000 },
    async () => {
      const auth = await fakeServer([], (res) => problem(res, 403, 'TOKEN_NOT_ALLOWED'));
      expect((await scan(repo(), auth, ['--branch', 'feature/x'])).code).toBe(5);
      const missing = await fakeServer([], (res) => problem(res, 404, 'PROJECT_NOT_FOUND'));
      const r = await scan(repo(), missing, ['--branch', 'feature/x']);
      expect(r.code).toBe(4);
      expect(r.stderr).toContain('project acme/app does not exist on the server');
    },
  );

  it(
    'refuses to send the token to a server.url that only qualor.yml names',
    { timeout: 60_000 },
    async () => {
      const server = await fakeServer([]);
      const root = repo(`version: 1\nserver:\n  url: ${server.url}\n`);
      const c = captureIO({ cwd: root, env: { ...SCAN_TEST_ENV, QUALOR_TOKEN: TOKEN } });
      const code = await runScan(flags(), c.io, createLogger('info', c.io.stderr), {
        analyzers: [],
      }).catch((e: unknown) => e);
      expect(code).toMatchObject({ exitCode: 2 });
      expect(server.paths).toEqual([]);
      // --server-url (like QUALOR_URL) is trusted.
      const trusted = captureIO({ cwd: root, env: { ...SCAN_TEST_ENV, QUALOR_TOKEN: TOKEN } });
      server.paths.length = 0;
      const ok = await runScan(
        flags(['--server-url', server.url, '--no-wait']),
        trusted.io,
        createLogger('info', trusted.io.stderr),
        { analyzers: [] },
      );
      expect(ok).toBe(0);
      expect(server.paths).toContain('POST /api/v0/analyses');
    },
  );
});
