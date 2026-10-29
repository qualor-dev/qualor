import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import {
  REDACTED,
  redactText,
  reportSchema,
  REVIEW_SNAPSHOT_CONTENT_TYPE,
  type Language,
  type Report,
  type SnapshotChangeLine,
  type SnapshotFileLine,
  type SnapshotHeaderLine,
  type SnapshotLine,
  type SnapshotOmittedLine,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { describeWithTools } from '../../test/analyzers';
import { commitAll, gitSync, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { json, problem, useTestServers } from '../../test/http';
import { captureIO } from '../../test/io';
import { snapshotLinesOf } from '../../test/review-snapshot';
import { fakeSecret, fakeSecretEngine } from '../../test/secret-engine';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createQualorAnalyzer } from '../analyzers/qualor';
import { builtinAnalyzers } from '../analyzers/registry';
import { createSemgrepAnalyzer } from '../analyzers/semgrep';
import type { Analyzer } from '../analyzers/types';
import { CliError } from '../errors';
import { parseCommandLine, type ScanFlags } from '../args';
import { createGit, type Git } from '../git/git';
import { VERSION } from '../index';
import { createLogger } from '../log';
import { runScan, type ScanDeps } from './run';

const tmp = useTempDirs();
const serve = useTestServers();
const ID = '0192a4c6-1c2e-7a3b-9f00-0000000000aa';
const SNAPSHOT_ID = '0192a4c6-1c2e-7a3b-9f00-0000000000bb';
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
  /** The uploaded reports' JSON as sent, before any schema strips a field. */
  reportTexts: string[];
  paths: string[];
  /** The query strings of `GET /projects/review-context`. */
  contextQueries: string[];
  /** The review snapshots uploaded: their URL, headers and gzip'd body as sent. */
  snapshots: { url: string; headers: IncomingHttpHeaders; body: Buffer }[];
}

/** AI review on the server double (6I-2). */
interface FakeReview {
  /** The 200 answer of `GET /projects/review-context`; without one, 404 (an older server). */
  context?: unknown;
  /** Runs when the review context is asked for, before the answer. */
  onContext?: () => void;
  /** Answers the snapshot upload, once its body is read; 202 without it. */
  snapshot?: (req: IncomingMessage, res: ServerResponse) => void;
}

/** A Qualor server double: the baseline, the upload and a scripted analysis status. */
async function fakeServer(
  statuses: unknown[],
  upload?: (res: Parameters<typeof json>[0]) => void,
  review: FakeReview = {},
): Promise<Fake> {
  const uploaded: Report[] = [];
  const reportTexts: string[] = [];
  const paths: string[] = [];
  const contextQueries: string[] = [];
  const snapshots: Fake['snapshots'] = [];
  const { url } = await serve((req, res, recorded) => {
    const u = new URL(req.url ?? '/', 'http://x');
    paths.push(`${req.method} ${u.pathname}`);
    if (u.pathname === '/api/v0/system/version') {
      json(res, 200, { version: VERSION });
    } else if (u.pathname === '/api/v0/projects/new-code-baseline') {
      json(res, 200, { revision: null, warnings: [] });
    } else if (u.pathname === '/api/v0/analyses' && req.method === 'POST') {
      if (upload !== undefined) {
        upload(res);
        return;
      }
      const text = gunzipSync(recorded.body).toString('utf8');
      reportTexts.push(text);
      uploaded.push(reportSchema.parse(JSON.parse(text)));
      json(res, 202, { analysisId: ID, status: 'queued', statusUrl: `/api/v0/analyses/${ID}` });
    } else if (u.pathname === `/api/v0/analyses/${ID}`) {
      json(
        res,
        200,
        statuses.shift() ?? { id: ID, status: 'queued', gateStatus: null, error: null },
      );
    } else if (u.pathname === '/api/v0/projects/review-context' && review.context !== undefined) {
      contextQueries.push(u.search.slice(1));
      review.onContext?.();
      json(res, 200, review.context);
    } else if (u.pathname === `/api/v0/analyses/${ID}/review-snapshot` && req.method === 'POST') {
      snapshots.push({ url: req.url ?? '', headers: req.headers, body: recorded.body });
      if (review.snapshot !== undefined) {
        review.snapshot(req, res);
        return;
      }
      json(res, 202, { snapshotId: SNAPSHOT_ID, status: 'uploaded' });
    } else {
      problem(res, 404, 'NOT_FOUND');
    }
  });
  return { url, uploaded, reportTexts, paths, contextQueries, snapshots };
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
  env: Record<string, string> = {},
): Promise<{ code: number; stderr: string }> {
  const c = captureIO({
    cwd: root,
    env: { ...SCAN_TEST_ENV, QUALOR_URL: server.url, QUALOR_TOKEN: TOKEN, ...env },
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
        'GET /api/v0/system/version',
        'GET /api/v0/projects/new-code-baseline',
        'POST /api/v0/analyses',
        `GET /api/v0/analyses/${ID}`,
        `GET /api/v0/analyses/${ID}`,
      ]);
      expect(server.uploaded[0]?.project.key).toBe('acme/app');
      expect(server.uploaded[0]?.scm.baseline.status).toBe('first_analysis');
      expect(stderr).toContain('quality gate: passed');
      expect(stderr).toContain(`qualor ${VERSION} (`);
      expect(stderr).toContain(`runs Qualor ${VERSION}`);
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

// ─── AI review: the repository snapshot of a merge request (6I-2) ───────────

const MiB = 1024 * 1024;
const REVIEW_ON = {
  review: true,
  reason: null,
  lastReviewedCommit: null,
  limits: {
    maxCompressedBytes: 50 * MiB,
    maxDecompressedBytes: 500 * MiB,
    maxFileBytes: MiB,
    maxFiles: 50_000,
  },
};
/** The scans below fetch nothing: origin/main and the head are in the clone. */
const MR_YML = 'version: 1\nscm:\n  autoFetch: false\n';
const MR_TITLE = 'Add the b module';
const MR_DESCRIPTION = 'Adds b to the app, with its tests.';

interface Mr {
  /** The scan root. */
  root: string;
  base: string;
  head: string;
}

/**
 * A merge request's checkout below `dir` of a new repository: `main`, also origin/main, at the
 * merge base, and HEAD on `feature` at the merge request's head, which changes src/a.ts and adds
 * src/b.ts unless `head` says otherwise.
 */
function mrRepo(
  o: {
    yml?: string;
    base?: Record<string, string | Uint8Array>;
    head?: Record<string, string | Uint8Array>;
    dir?: string;
  } = {},
): Mr {
  const top = path.join(tmp(), 'repo');
  const root = o.dir === undefined ? top : path.join(top, ...o.dir.split('/'));
  writeTree(root, {
    'qualor.yml': o.yml ?? MR_YML,
    'src/a.ts': 'export const a = 1;\n',
    ...o.base,
  });
  initRepo(top);
  const base = commitAll(top, 'base');
  gitSync(top, 'update-ref', 'refs/remotes/origin/main', base);
  gitSync(top, 'checkout', '-q', '-b', 'feature');
  writeTree(
    root,
    o.head ?? { 'src/a.ts': 'export const a = 2;\n', 'src/b.ts': 'export const b = 1;\n' },
  );
  return { root, base, head: commitAll(top, 'head') };
}

/** A GitLab merge request pipeline for `head` (detached unless `more` says otherwise). */
function gitlabMr(head: string, more: Record<string, string> = {}): Record<string, string> {
  return {
    GITLAB_CI: 'true',
    CI_COMMIT_SHA: head,
    CI_COMMIT_REF_NAME: 'feature',
    CI_DEFAULT_BRANCH: 'main',
    CI_MERGE_REQUEST_IID: '7',
    CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
    CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
    CI_MERGE_REQUEST_TITLE: MR_TITLE,
    CI_MERGE_REQUEST_DESCRIPTION: MR_DESCRIPTION,
    ...more,
  };
}

const isChange = (l: SnapshotLine): l is SnapshotChangeLine => l.type === 'change';
const isFile = (l: SnapshotLine): l is SnapshotFileLine => l.type === 'file';
const isHeader = (l: SnapshotLine): l is SnapshotHeaderLine => l.type === 'header';
const isOmitted = (l: SnapshotLine): l is SnapshotOmittedLine => l.type === 'omitted';
const omittedOf = (lines: SnapshotLine[]) =>
  Object.fromEntries(lines.filter(isOmitted).map((l) => [l.path, l.reason]));
/** The only snapshot `server` received: its inflated text and its lines. */
function sent(server: Fake): { text: string; lines: SnapshotLine[] } {
  const body = server.snapshots[0]?.body ?? Buffer.alloc(0);
  return { text: gunzipSync(body).toString('utf8'), lines: snapshotLinesOf(body) };
}
const reviewWarnings = (stderr: string) =>
  stderr.split('\n').filter((l) => l.startsWith('warn: AI review'));

const TOO_SLOW =
  'warn: AI review: building the repository snapshot took longer than 10 minutes, so none is sent';

const UNTIL_REPORT = ['GET /api/v0/system/version', 'POST /api/v0/analyses'];
const CONTEXT = 'GET /api/v0/projects/review-context';
const SNAPSHOT = `POST /api/v0/analyses/${ID}/review-snapshot`;
const GATE = `GET /api/v0/analyses/${ID}`;

describe('qualor scan: the AI review snapshot of a merge request (6I-2)', () => {
  it(
    'a merge request scan with review on uploads a snapshot after the report',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const server = await fakeServer([done('failed')], undefined, { context: REVIEW_ON });
      const temp = tmp();
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { reviewTempRoot: temp },
        gitlabMr(mr.head),
      );
      // The gate decides the exit code: it failed.
      expect(code, stderr).toBe(1);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      expect(server.contextQueries).toEqual(['projectKey=acme%2Fapp&mergeRequest=7']);
      const [snapshot] = server.snapshots;
      expect(snapshot?.url).toBe(`/api/v0/analyses/${ID}/review-snapshot?projectKey=acme%2Fapp`);
      expect(snapshot?.headers).toMatchObject({
        'content-type': REVIEW_SNAPSHOT_CONTENT_TYPE,
        'content-encoding': 'gzip',
        authorization: `Bearer ${TOKEN}`,
      });
      const lines = snapshotLinesOf(snapshot?.body ?? Buffer.alloc(0));
      expect(lines.find(isHeader)).toMatchObject({
        headSha: mr.head,
        baseSha: mr.base,
        sinceSha: null,
        targetBranch: 'main',
        partial: false,
        mergeRequest: { id: '7', title: MR_TITLE, description: MR_DESCRIPTION },
      });
      expect(lines.filter(isChange).map((l) => [l.path, l.status])).toEqual([
        ['src/a.ts', 'modified'],
        ['src/b.ts', 'added'],
      ]);
      expect(lines.filter(isFile).map((l) => l.path)).toEqual([
        'src/a.ts',
        'src/b.ts',
        'qualor.yml',
      ]);
      expect(stderr).toContain('AI review: repository snapshot uploaded');
      expect(reviewWarnings(stderr)).toEqual([]);
      expect(stderr).not.toContain(TOKEN);
      // The merge request's title and description go to the snapshot only, never to the report.
      expect(server.uploaded[0]?.scm.mergeRequest).toEqual({
        id: '7',
        targetBranch: 'main',
        sourceBranch: 'feature',
      });
      expect(server.reportTexts[0]).not.toContain(MR_TITLE);
      expect(server.reportTexts[0]).not.toContain(MR_DESCRIPTION);
      // The snapshot's private directory is gone.
      expect(readdirSync(temp)).toEqual([]);
    },
  );

  it('a snapshot path past its deadline sends nothing and warns', { timeout: 60_000 }, async () => {
    const mr = mrRepo();
    // The clock passes the snapshot's ten minutes while the server is asked whether it reviews.
    let t = 0;
    const server = await fakeServer([done('passed')], undefined, {
      context: REVIEW_ON,
      onContext: () => {
        t += 10 * 60_000 + 1;
      },
    });
    const temp = tmp();
    // git as the scan has it, with the calls made past the deadline: there are none.
    const real = createGit(mr.root, { ...SCAN_TEST_ENV, ...gitlabMr(mr.head) });
    const late: string[] = [];
    const git: Git = (args, options) => {
      if (t > 10 * 60_000) late.push(args.join(' '));
      return real(args, options);
    };
    const { code, stderr } = await scan(
      mr.root,
      server,
      [],
      { reviewTempRoot: temp, clock: () => t, git },
      gitlabMr(mr.head),
    );
    // The gate decides the exit code, as for any failure of the snapshot path.
    expect(code, stderr).toBe(0);
    expect(late).toEqual([]);
    expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
    expect(server.snapshots).toEqual([]);
    expect(reviewWarnings(stderr)).toEqual([
      'warn: AI review: building the repository snapshot took longer than 10 minutes, so none is sent',
    ]);
    expect(stderr).not.toContain('AI review: uploading');
    // Nothing of the repository is left behind.
    expect(readdirSync(temp)).toEqual([]);
  });

  it('a git call the deadline cuts short says the deadline only', { timeout: 60_000 }, async () => {
    const mr = mrRepo();
    const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
    const temp = tmp();
    const real = createGit(mr.root, { ...SCAN_TEST_ENV, ...gitlabMr(mr.head) });
    let t = 0;
    // The merge request's diff runs into the deadline: git is stopped there, and fails as git does.
    const git: Git = (args, options) => {
      if (!args.includes('-U3')) return real(args, options);
      t = 10 * 60_000;
      return Promise.resolve({ code: 1, stdout: '', stderr: 'git was stopped' });
    };
    const { code, stderr } = await scan(
      mr.root,
      server,
      [],
      { reviewTempRoot: temp, clock: () => t, git },
      gitlabMr(mr.head),
    );
    expect(code, stderr).toBe(0);
    expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
    // Not also that the diff could not be read: the deadline cut it.
    expect(reviewWarnings(stderr)).toEqual([TOO_SLOW]);
    expect(readdirSync(temp)).toEqual([]);
  });

  it(
    'a snapshot whose build ends past the deadline is not sent',
    { timeout: 120_000 },
    async () => {
      /** A scan whose snapshot path's git calls are counted; the clock passes the deadline as call `last` ends. */
      const scanUntil = async (last: number | null, temp: string) => {
        const mr = mrRepo();
        let t = 0;
        let asked = false;
        const server = await fakeServer([done('passed')], undefined, {
          context: REVIEW_ON,
          onContext: () => {
            asked = true;
          },
        });
        const real = createGit(mr.root, { ...SCAN_TEST_ENV, ...gitlabMr(mr.head) });
        const calls: string[] = [];
        const git: Git = async (args, options) => {
          if (!asked) return real(args, options);
          calls.push(args.join(' '));
          const result = await real(args, options);
          if (calls.length === last) t = 10 * 60_000;
          return result;
        };
        const out = await scan(
          mr.root,
          server,
          [],
          { reviewTempRoot: temp, clock: () => t, git },
          gitlabMr(mr.head),
        );
        return { ...out, server, calls };
      };
      const onTime = await scanUntil(null, tmp());
      expect(onTime.server.snapshots).toHaveLength(1);
      // The clock passes the deadline as the build's last git call ends: the build itself ends, and
      // only its end finds the deadline passed.
      const lateTemp = tmp();
      const late = await scanUntil(onTime.calls.length, lateTemp);
      expect(late.calls).toHaveLength(onTime.calls.length);
      expect(late.code, late.stderr).toBe(0);
      expect(late.server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(late.stderr)).toEqual([TOO_SLOW]);
      expect(late.stderr).not.toContain('AI review: uploading');
      expect(readdirSync(lateTemp)).toEqual([]);
    },
  );

  it('sends the snapshot without waiting for the gate as well', { timeout: 60_000 }, async () => {
    const mr = mrRepo();
    const server = await fakeServer([], undefined, { context: REVIEW_ON });
    const { code, stderr } = await scan(mr.root, server, ['--no-wait'], {}, gitlabMr(mr.head));
    expect(code, stderr).toBe(0);
    expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT]);
  });

  it('review off: no snapshot', { timeout: 60_000 }, async () => {
    const mr = mrRepo();
    const server = await fakeServer([done('passed')], undefined, {
      context: { ...REVIEW_ON, review: false, reason: 'review_disabled' },
    });
    const { code, stderr } = await scan(mr.root, server, [], {}, gitlabMr(mr.head));
    expect(code, stderr).toBe(0);
    expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
    expect(stderr).toContain('AI review is off for this project (review_disabled)');
    expect(reviewWarnings(stderr)).toEqual([]);
  });

  it(
    'a server without the review context route: no snapshot, and no warning',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const server = await fakeServer([done('passed')]);
      const { code, stderr } = await scan(mr.root, server, [], {}, gitlabMr(mr.head));
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(stderr).not.toMatch(/^warn: /m);
    },
  );

  it(
    'secret scan unreadable: no snapshot and a warning (Review Focus 2)',
    { timeout: 60_000 },
    async () => {
      // Not required, so the scan does not exit 3 on it.
      const mr = mrRepo({ yml: `${MR_YML}analyzers:\n  gitleaks:\n    enabled: auto\n` });
      const engine = fakeSecretEngine(tmp(), 'unreadable');
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [engine.analyzer] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(server.snapshots).toEqual([]);
      expect(reviewWarnings(stderr)).toEqual([
        "warn: AI review: no snapshot sent, the secret scan's output could not be read",
      ]);
    },
  );

  it(
    'a scan whose required analyzer failed exits 3 and sends no snapshot',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const engine = fakeSecretEngine(tmp(), 'fail');
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [engine.analyzer] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(3);
      expect(server.paths).toEqual(UNTIL_REPORT);
    },
  );

  /** An analyzer `id` with `languages` that cannot run here (its tool is not installed). */
  const notInstalled = (id: 'semgrep' | 'qualor', languages: Language[]): Analyzer => ({
    id,
    languages,
    prepare: () => Promise.resolve({ unavailable: `${id} is not installed here` }),
  });
  /** `qualor.yml` with these lines under `analyzers:`. */
  const withAnalyzers = (lines: string) =>
    lines === '' ? MR_YML : `${MR_YML}analyzers:\n${lines}`;

  it.each([
    [
      'Gitleaks failed',
      '  gitleaks:\n    enabled: auto\n',
      (dir: string) => [fakeSecretEngine(dir, 'fail').analyzer],
      'gitleaks',
    ],
    [
      'Gitleaks timed out',
      '  gitleaks:\n    enabled: auto\n    timeoutSeconds: 1\n',
      (dir: string) => [fakeSecretEngine(dir, 'hang').analyzer],
      'gitleaks',
    ],
    [
      'Gitleaks is not installed',
      '  gitleaks:\n    enabled: auto\n',
      (dir: string) => [fakeSecretEngine(dir, 'unavailable').analyzer],
      'gitleaks',
    ],
    [
      'Semgrep, whose secret rules mask too, is not installed',
      '',
      () => [notInstalled('semgrep', [])],
      'semgrep',
    ],
    [
      "Qualor's rules did not run over files of their languages",
      '',
      () => [notInstalled('qualor', ['typescript'])],
      'qualor',
    ],
  ])(
    'a secret scan enabled for the scan that did not complete (%s): no snapshot and a warning (Review Focus 2)',
    { timeout: 60_000 },
    async (_name, lines, analyzers, engine) => {
      // Not required, so the scan does not exit 3 on it.
      const mr = mrRepo({ yml: withAnalyzers(lines) });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: analyzers(tmp()) },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        `warn: AI review: no snapshot sent, the secret scan (${engine}) did not complete`,
      ]);
    },
  );

  it.each([
    ['Gitleaks completed', '', (dir: string) => [fakeSecretEngine(dir).analyzer], false],
    [
      "Gitleaks is off in qualor.yml, the user's choice",
      '  gitleaks:\n    enabled: false\n',
      (dir: string) => [fakeSecretEngine(dir).analyzer],
      true,
    ],
    [
      "Qualor's rules had no file of their languages to scan",
      '',
      () => [notInstalled('qualor', ['python'])],
      false,
    ],
  ])(
    'the secret scans are complete (%s): the snapshot is sent',
    { timeout: 60_000 },
    async (_name, lines, analyzers, off) => {
      const mr = mrRepo({ yml: withAnalyzers(lines) });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: analyzers(tmp()) },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([]);
      const said = stderr
        .split('\n')
        .filter(
          (l) =>
            l ===
            'AI review: the secret scan is off in qualor.yml; only built-in patterns mask secrets in the snapshot',
        );
      expect(said).toHaveLength(off ? 1 : 0);
    },
  );

  // The real analyzers, not fakes: what their own preparation answers decides (ruling G6). Each
  // is given directories of its own, so the machine running the tests (the scanner image, CI)
  // never decides: no rules directory of the host is read.
  const realGitleaks = (): Analyzer => {
    const found = builtinAnalyzers().find((a) => a.id === 'gitleaks');
    if (found === undefined) throw new Error('no gitleaks analyzer');
    return found;
  };
  /** The real Semgrep analyzer for a runner without the image: its rules directory is absent. */
  const semgrepWithoutImage = (): Analyzer => createSemgrepAnalyzer(path.join(tmp(), 'absent'));
  /** The real Semgrep analyzer on a machine with no OpenGrep or Semgrep, whatever this one has. */
  const semgrepWithoutTools = (rulesDir: string): Analyzer => {
    const real = createSemgrepAnalyzer(rulesDir);
    return { ...real, prepare: (ctx) => real.prepare({ ...ctx, resolveBinary: () => null }) };
  };
  /** An existing rules directory without a rule in it: how the qualor/scanner image ships it. */
  const emptyRulesDir = (): string => {
    const dir = path.join(tmp(), 'semgrep-rules');
    mkdirSync(dir);
    return dir;
  };
  const SECRET_RULE =
    'rules:\n  - id: hard-coded-key\n    languages: [typescript]\n    message: a key\n    severity: ERROR\n    pattern: const key = "..."\n';

  it.each([
    [
      'Semgrep on its defaults, on a host without the image (no rules directory)',
      () => [semgrepWithoutImage()],
    ],
    [
      'Semgrep on its defaults in the scanner image, whose rules directory holds no rule',
      () => [createSemgrepAnalyzer(emptyRulesDir())],
    ],
    [
      "Qualor's rules without their pack, off the scanner image",
      () => [createQualorAnalyzer({ defaultDir: path.join(tmp(), 'no-pack') })],
    ],
  ])(
    'a secret rule engine with nothing to run does not hold the snapshot up: %s',
    { timeout: 60_000 },
    async (_name, analyzers) => {
      const mr = mrRepo();
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [fakeSecretEngine(tmp()).analyzer, ...analyzers()] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      // It was skipped, not run: the report says so, and the snapshot goes all the same.
      const engine = server.uploaded[0]?.engines.map((e) => [e.id, e.status]);
      expect(engine).toContainEqual([expect.stringMatching(/^(semgrep|qualor)$/), 'skipped']);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([]);
    },
  );

  it(
    'Semgrep with rule files to run and no OpenGrep or Semgrep to run them holds the snapshot up',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo({
        yml: withAnalyzers('  semgrep:\n    configs: [rules/secrets.yml]\n'),
        base: { 'rules/secrets.yml': SECRET_RULE },
      });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [fakeSecretEngine(tmp()).analyzer, semgrepWithoutTools(emptyRulesDir())] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.uploaded[0]?.engines).toContainEqual(
        expect.objectContaining({ id: 'semgrep', status: 'skipped' }),
      );
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        'warn: AI review: no snapshot sent, the secret scan (semgrep) did not complete',
      ]);
    },
  );

  // Semgrep skips when none of the rule files the configuration names exists: those rules never
  // ran, which is not "nothing to run". It skips before it looks for OpenGrep, so the machine
  // running the tests does not decide.
  it.each([
    ['a named rule file that does not exist', '[rules/missing.yml]', {}],
    [
      'a typo in the name of a rule file',
      '[rules/secret.yml]',
      { 'rules/secrets.yml': SECRET_RULE },
    ],
  ])(
    'Semgrep rules that were named and never ran hold the snapshot up: %s',
    { timeout: 60_000 },
    async (_name, configs, base) => {
      const mr = mrRepo({
        yml: withAnalyzers(`  semgrep:\n    configs: ${configs}\n`),
        base,
      });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [fakeSecretEngine(tmp()).analyzer, semgrepWithoutImage()] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.uploaded[0]?.engines).toContainEqual(
        expect.objectContaining({ id: 'semgrep', status: 'skipped' }),
      );
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        'warn: AI review: no snapshot sent, the secret scan (semgrep) did not complete',
      ]);
    },
  );

  // With a rule file to run, Semgrep runs the files that exist: what then holds the snapshot up is
  // a named file that does not exist, not an unusable qualor-default.
  describeWithTools([['opengrep', 'semgrep']])('Semgrep with OpenGrep or Semgrep installed', () => {
    const semgrepRun = async (configs: string) => {
      const mr = mrRepo({
        yml: withAnalyzers(`  semgrep:\n    configs: ${configs}\n`),
        base: { 'rules/secrets.yml': SECRET_RULE },
      });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [fakeSecretEngine(tmp()).analyzer, semgrepWithoutImage()] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.uploaded[0]?.engines).toContainEqual(
        expect.objectContaining({ id: 'semgrep', status: 'ok' }),
      );
      return { server, stderr };
    };

    it(
      'two named rule files, the second gone: the first runs and the snapshot is held up',
      { timeout: 120_000 },
      async () => {
        const { server, stderr } = await semgrepRun('[rules/secrets.yml, rules/old.yml]');
        expect(server.uploaded[0]?.warnings).toContainEqual(
          expect.objectContaining({ code: 'SEMGREP_CONFIG_MISSING' }),
        );
        expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
        expect(reviewWarnings(stderr)).toEqual([
          'warn: AI review: no snapshot sent, the secret scan (semgrep) did not complete',
        ]);
      },
    );

    it(
      'qualor-default next to a named rule file, on a runner without the image: the file runs and the snapshot goes',
      { timeout: 120_000 },
      async () => {
        const { server, stderr } = await semgrepRun('[qualor-default, rules/secrets.yml]');
        expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
        expect(reviewWarnings(stderr)).toEqual([]);
      },
    );
  });

  it.each([
    ['does not exist', 'missing.toml', {}],
    ['is not a regular file', 'config-dir', { 'config-dir/notes.txt': 'a directory\n' }],
  ])(
    'Gitleaks that was skipped because its configFile %s scanned nothing, so it holds the snapshot up',
    { timeout: 60_000 },
    async (_name, configFile, base) => {
      const mr = mrRepo({
        yml: withAnalyzers(`  gitleaks:\n    enabled: auto\n    configFile: ${configFile}\n`),
        base,
      });
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [realGitleaks()] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.uploaded[0]?.engines).toContainEqual(
        expect.objectContaining({ id: 'gitleaks', status: 'skipped' }),
      );
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        'warn: AI review: no snapshot sent, the secret scan (gitleaks) did not complete',
      ]);
    },
  );

  it.each([
    [
      '409 SNAPSHOT_EXISTS',
      'passed',
      0,
      (_req: IncomingMessage, res: ServerResponse) => problem(res, 409, 'SNAPSHOT_EXISTS'),
    ],
    [
      '500 INTERNAL_ERROR',
      'failed',
      1,
      (_req: IncomingMessage, res: ServerResponse) => problem(res, 500, 'INTERNAL_ERROR'),
    ],
    [
      'a dropped connection',
      'passed',
      0,
      (req: IncomingMessage) => {
        req.socket.destroy();
      },
    ],
  ])(
    'the snapshot upload fails (%s): a warning, the gate (%s) decides the exit code (%i)',
    { timeout: 60_000 },
    async (_name, gate, exit, answer) => {
      const mr = mrRepo();
      const server = await fakeServer([done(gate)], undefined, {
        context: REVIEW_ON,
        snapshot: answer,
      });
      const temp = tmp();
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { reviewTempRoot: temp },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(exit);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        expect.stringMatching(/^warn: AI review: no snapshot sent/),
      ]);
      expect(stderr).not.toContain(TOKEN);
      // Removed after the failed upload too.
      expect(readdirSync(temp)).toEqual([]);
    },
  );

  it.each([
    [
      "a merged-result pipeline that does not name the merge request's head",
      { CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result' },
      REVIEW_ON,
      /head commit is unknown/,
    ],
    [
      'a head that is not in the clone, with scm.autoFetch false (R12)',
      {
        CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result',
        CI_MERGE_REQUEST_SOURCE_BRANCH_SHA: 'e'.repeat(40),
      },
      REVIEW_ON,
      /head commit e{40} is not in the clone/,
    ],
    [
      "changes over the server's limits",
      {},
      { ...REVIEW_ON, limits: { ...REVIEW_ON.limits, maxDecompressedBytes: 16 } },
      /limits/,
    ],
  ])('%s: a warning and no snapshot', { timeout: 60_000 }, async (_name, ci, context, why) => {
    const mr = mrRepo();
    const server = await fakeServer([done('passed')], undefined, { context });
    const temp = tmp();
    const { code, stderr } = await scan(
      mr.root,
      server,
      [],
      { reviewTempRoot: temp },
      gitlabMr(mr.head, ci),
    );
    expect(code, stderr).toBe(0);
    expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
    const warned = reviewWarnings(stderr);
    expect(warned).toHaveLength(1);
    expect(warned[0]).toMatch(why);
    expect(readdirSync(temp)).toEqual([]);
  });

  it(
    '--mr naming another merge request than CI runs for: a warning and no snapshot',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const other = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        other,
        ['--mr', '8', '--mr-target', 'main'],
        {},
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(other.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        expect.stringContaining('--mr and --mr-target name another merge request'),
      ]);
      // The one CI runs for: sent.
      const same = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const again = await scan(
        mr.root,
        same,
        ['--mr', '7', '--mr-target', 'main'],
        {},
        gitlabMr(mr.head),
      );
      expect(again.code, again.stderr).toBe(0);
      expect(same.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
    },
  );

  it('a branch scan never asks', { timeout: 60_000 }, async () => {
    const mr = mrRepo();
    const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
    const { code, stderr } = await scan(
      mr.root,
      server,
      [],
      {},
      {
        GITLAB_CI: 'true',
        CI_COMMIT_SHA: mr.head,
        CI_COMMIT_REF_NAME: 'feature',
        CI_DEFAULT_BRANCH: 'main',
      },
    );
    expect(code, stderr).toBe(0);
    expect(server.paths).toEqual([...UNTIL_REPORT, GATE]);
  });

  it(
    'a GitHub pull request: the snapshot of the head its event names, with its title and body (R9)',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const event = path.join(tmp(), 'event.json');
      writeFileSync(
        event,
        JSON.stringify({
          pull_request: {
            number: 7,
            head: { sha: mr.head },
            base: { ref: 'main' },
            title: MR_TITLE,
            body: null,
          },
          repository: { default_branch: 'main' },
        }),
      );
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        {},
        {
          GITHUB_ACTIONS: 'true',
          GITHUB_EVENT_PATH: event,
          GITHUB_SHA: 'f'.repeat(40),
          GITHUB_HEAD_REF: 'feature',
          GITHUB_BASE_REF: 'main',
          GITHUB_REF_NAME: '7/merge',
          GITHUB_REPOSITORY: 'acme/app',
        },
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      const lines = snapshotLinesOf(server.snapshots[0]?.body ?? Buffer.alloc(0));
      expect(lines.find(isHeader)).toMatchObject({
        headSha: mr.head,
        mergeRequest: { id: '7', title: MR_TITLE, description: null },
      });
    },
  );

  it(
    'masks the secrets of the scan and of the merge base, and the token, the scan root a subdirectory (Review Focus 2, R13)',
    { timeout: 60_000 },
    async () => {
      const headSecret = fakeSecret('head0secret0value');
      const baseSecret = fakeSecret('base0secret0value');
      // A rule for src/ only: the merge base's files are found by it only when they are laid out
      // as the head scan saw its files, below the scan root.
      const rules = `[[rules]]\nid = "src-token"\nregex = '''qk7-[A-Za-z0-9-]{8,}'''\npath = '''^src/'''\n`;
      const mr = mrRepo({
        dir: 'pkg',
        base: {
          '.gitleaks.toml': rules,
          'src/a.ts': `export const a = 1;\nconst old = '${baseSecret}';\n`,
        },
        head: {
          'src/a.ts': `export const a = 2;\nconst key = '${headSecret}';\n`,
          'src/token.ts': `export const token = '${TOKEN}';\n`,
        },
      });
      const engine = fakeSecretEngine(tmp());
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const temp = tmp();
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [engine.analyzer], reviewTempRoot: temp },
        gitlabMr(mr.head, {
          CI_MERGE_REQUEST_DESCRIPTION: `Rotates ${headSecret} and ${baseSecret}; token ${TOKEN}`,
        }),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      // The head scan and the merge base's scan, both against the scan root.
      expect(engine.prepared).toEqual([mr.root, mr.root]);
      // The snapshot, the merge base's files and the engine's output there are all gone.
      expect(readdirSync(temp)).toEqual([]);
      const body = server.snapshots[0]?.body ?? Buffer.alloc(0);
      const text = gunzipSync(body).toString('utf8');
      for (const secret of [headSecret, baseSecret, TOKEN]) expect(text).not.toContain(secret);
      const lines = snapshotLinesOf(body);
      const patch = lines.filter(isChange).find((l) => l.path === 'src/a.ts')?.patch ?? '';
      // The removed line is sent, masked: the merge base's scan found its secret at src/a.ts.
      expect(patch).toContain(`-const old = '${REDACTED}';`);
      expect(patch).toContain(`+const key = '${REDACTED}';`);
      const files = new Map(lines.filter(isFile).map((l) => [l.path, l.text]));
      expect(files.get('src/a.ts')).toBe(`export const a = 2;\nconst key = '${REDACTED}';\n`);
      expect(files.get('src/token.ts')).toBe(`export const token = '${REDACTED}';\n`);
      expect(lines.find(isHeader)?.mergeRequest.description).toBe(
        `Rotates ${REDACTED} and ${REDACTED}; token ${REDACTED}`,
      );
      expect(stderr).not.toContain(TOKEN);
      expect(stderr).not.toContain(headSecret);
      expect(stderr).not.toContain(baseSecret);
    },
  );

  describeWithTools(['gitleaks'])(
    'the merge-base secret scan with the real Gitleaks (6I, R43)',
    () => {
      // The fixture's own value (mixed-secrets/src/config.ts:2, `apiKey = "Zx9Q…"`) is caught by the
      // shared patterns, which read the name. A Shopify token under a plain name is found by
      // Gitleaks' default shopify-access-token rule only. A made-up value, no real token, put
      // together at run time so that this file holds no token of that form: Qualor's own Gitleaks
      // scan of the repository (.gitleaks.toml) and a host's push protection would flag one.
      const SECRET = ['shpat', 'a1b2c3d4e5f60718293a4b5c6d7e8f90'].join('_');
      const REMOVED_LINE = `const store = "${SECRET}";`;
      const KEPT = 'export const endpoint = "https://api.example.com";\n';
      /** A merge request whose only change to src/config.ts removes the line with the secret. */
      const removingRepo = (yml?: string) =>
        mrRepo({
          ...(yml === undefined ? {} : { yml }),
          base: { 'src/config.ts': `${KEPT}${REMOVED_LINE}\nexport const after = 1;\n` },
          head: { 'src/config.ts': `${KEPT}export const after = 1;\n` },
        });
      const configPatch = (server: Fake): string =>
        sent(server)
          .lines.filter(isChange)
          .find((l) => l.path === 'src/config.ts')?.patch ?? '';

      it(
        'the real Gitleaks masks a secret the merge request removes, which the shared patterns miss (R13)',
        { timeout: 120_000 },
        async () => {
          // The precondition: if a shared pattern ever catches this value, the test would pass
          // without Gitleaks. Pick another format that only Gitleaks finds, then.
          expect(redactText(REMOVED_LINE).text).toContain(SECRET);
          const mr = removingRepo();
          const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
          const { code, stderr } = await scan(
            mr.root,
            server,
            [],
            { analyzers: [realGitleaks()] },
            gitlabMr(mr.head),
          );
          expect(code, stderr).toBe(0);
          expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
          expect(configPatch(server)).toContain(`-const store = "${REDACTED}";`);
          expect(sent(server).text).not.toContain(SECRET);
          expect(stderr).not.toContain(SECRET);
        },
      );

      it(
        'with Gitleaks off in qualor.yml, the removed line is not sent',
        { timeout: 120_000 },
        async () => {
          const mr = removingRepo(`${MR_YML}analyzers:\n  gitleaks:\n    enabled: false\n`);
          const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
          const { code, stderr } = await scan(
            mr.root,
            server,
            [],
            { analyzers: [realGitleaks()] },
            gitlabMr(mr.head),
          );
          expect(code, stderr).toBe(0);
          expect(configPatch(server)).toContain('\n-[1 removed line not sent]\n');
          expect(sent(server).text).not.toContain(SECRET);
          expect(
            stderr
              .split('\n')
              .filter(
                (l) =>
                  l ===
                  'AI review: the secret scan is off in qualor.yml; only built-in patterns mask secrets in the snapshot',
              ),
          ).toHaveLength(1);
        },
      );
    },
  );
});

describe('qualor scan: the head files the scan did not see (6I-2, ruling R14)', () => {
  /** The secret main had at the merge base and removed after it, in a file the MR never touches. */
  const LEAKED = fakeSecret('leaked0before0removal');

  interface MergeCheckout {
    root: string;
    /** The merge request's head, whose tree the snapshot sends. */
    head: string;
    /** The merge commit checked out (detached), which the analyzers scan. */
    merge: string;
  }

  /**
   * A merge commit checked out, as a GitLab merged-result pipeline and GitHub's pull request
   * checkout give it: main at the merge base holds LEAKED in src/leak.ts; the merge request
   * (feature) changes src/a.ts only; main then removes the secret (origin/main); HEAD is the merge
   * of the merge request into main.
   */
  function mergeCheckout(
    o: {
      base?: Record<string, string>;
      head?: Record<string, string>;
      target?: Record<string, string>;
    } = {},
  ): MergeCheckout {
    const root = path.join(tmp(), 'repo');
    writeTree(root, {
      'qualor.yml': MR_YML,
      'src/a.ts': 'export const a = 1;\n',
      'src/leak.ts': `export const key = '${LEAKED}';\n`,
      ...o.base,
    });
    initRepo(root);
    commitAll(root, 'base');
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'src/a.ts': 'export const a = 2;\n', ...o.head });
    const head = commitAll(root, 'the merge request');
    gitSync(root, 'checkout', '-q', 'main');
    writeTree(root, { 'src/leak.ts': "export const key = process.env['KEY'];\n", ...o.target });
    const target = commitAll(root, 'remove the leaked key');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', target);
    gitSync(root, 'merge', '-q', '--no-ff', '--no-edit', 'feature');
    const merge = gitSync(root, 'rev-parse', 'HEAD');
    gitSync(root, 'checkout', '-q', '--detach', merge);
    return { root, head, merge };
  }

  /** GitHub's pull request event for `m`, written to a file, and the environment naming it. */
  function githubPr(m: MergeCheckout): Record<string, string> {
    const event = path.join(tmp(), 'event.json');
    writeFileSync(
      event,
      JSON.stringify({
        pull_request: {
          number: 7,
          head: { sha: m.head },
          base: { ref: 'main' },
          title: MR_TITLE,
          body: MR_DESCRIPTION,
        },
        repository: { default_branch: 'main' },
      }),
    );
    return {
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_PATH: event,
      GITHUB_SHA: m.merge,
      GITHUB_HEAD_REF: 'feature',
      GITHUB_BASE_REF: 'main',
      GITHUB_REF_NAME: '7/merge',
      GITHUB_REPOSITORY: 'acme/app',
    };
  }

  const pipelines: [string, (m: MergeCheckout) => Record<string, string>][] = [
    [
      'a GitLab merged-result pipeline',
      (m) =>
        gitlabMr(m.merge, {
          CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result',
          CI_MERGE_REQUEST_SOURCE_BRANCH_SHA: m.head,
        }),
    ],
    ["GitHub's merge checkout of a pull request", githubPr],
  ];

  /** The runs of the secret engine over head files that differ from the checkout. */
  const headRuns = (engine: ReturnType<typeof fakeSecretEngine>) =>
    engine.runs().filter((cwd) => path.basename(cwd).startsWith('qualor-review-head-'));

  it.each(pipelines)(
    '%s: a secret main removed after the merge base, in a file the merge request never touched, is masked',
    { timeout: 60_000 },
    async (_name, ci) => {
      const m = mergeCheckout();
      const engine = fakeSecretEngine(tmp());
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        m.root,
        server,
        [],
        { analyzers: [engine.analyzer] },
        ci(m),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      const body = server.snapshots[0]?.body ?? Buffer.alloc(0);
      expect(gunzipSync(body).toString('utf8')).not.toContain(LEAKED);
      const lines = snapshotLinesOf(body);
      expect(lines.find(isHeader)?.headSha).toBe(m.head);
      // The head's version, which the checkout (the merge) does not have, masked.
      const files = new Map(lines.filter(isFile).map((l) => [l.path, l.text]));
      expect(files.get('src/leak.ts')).toBe(`export const key = '${REDACTED}';\n`);
      expect(headRuns(engine)).toHaveLength(1);
      expect(stderr).not.toContain(LEAKED);
    },
  );

  it.each(pipelines)(
    '%s: the secret engine failing over those files: no snapshot and a warning',
    { timeout: 60_000 },
    async (_name, ci) => {
      const m = mergeCheckout();
      // The scan's own run succeeds; every later one fails.
      const engine = fakeSecretEngine(tmp(), 'fail-after-first');
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const temp = tmp();
      const { code, stderr } = await scan(
        m.root,
        server,
        [],
        { analyzers: [engine.analyzer], reviewTempRoot: temp },
        ci(m),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, GATE]);
      expect(reviewWarnings(stderr)).toEqual([
        'warn: AI review: no snapshot sent, the head files that differ from the scanned checkout could not be scanned',
      ]);
      expect(headRuns(engine)).toHaveLength(1);
      expect(readdirSync(temp)).toEqual([]);
    },
  );

  it(
    'a tracked file a CI step edited after the checkout: its head version is scanned too',
    { timeout: 60_000 },
    async () => {
      const secret = fakeSecret('edited0away0in0ci');
      const mr = mrRepo({
        head: {
          'src/a.ts': 'export const a = 2;\n',
          'src/config.ts': `export const key = '${secret}';\n`,
        },
      });
      // A CI step rewrote the file before the scan: the analyzers never saw the commit's version.
      writeTree(mr.root, { 'src/config.ts': "export const key = process.env['KEY'];\n" });
      const engine = fakeSecretEngine(tmp());
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [engine.analyzer] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      const body = server.snapshots[0]?.body ?? Buffer.alloc(0);
      expect(gunzipSync(body).toString('utf8')).not.toContain(secret);
      const files = new Map(
        snapshotLinesOf(body)
          .filter(isFile)
          .map((l) => [l.path, l.text]),
      );
      expect(files.get('src/config.ts')).toBe(`export const key = '${REDACTED}';\n`);
      expect(headRuns(engine)).toHaveLength(1);
    },
  );

  it(
    'a detached pipeline, the head checked out as it is: no extra run',
    { timeout: 60_000 },
    async () => {
      const mr = mrRepo();
      const engine = fakeSecretEngine(tmp());
      const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
      const { code, stderr } = await scan(
        mr.root,
        server,
        [],
        { analyzers: [engine.analyzer] },
        gitlabMr(mr.head),
      );
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      // The scan's own run and the merge base's (the old side of src/a.ts), nothing else.
      expect(engine.runs()).toHaveLength(2);
      expect(headRuns(engine)).toEqual([]);
    },
  );

  /** A merge request scan with the fake Gitleaks, in the GitLab pipeline `ci`. */
  async function scanWithEngine(
    root: string,
    ci: Record<string, string>,
  ): Promise<{ code: number; stderr: string; server: Fake; engine: FakeEngine }> {
    const engine = fakeSecretEngine(tmp());
    const server = await fakeServer([done('passed')], undefined, { context: REVIEW_ON });
    const r = await scan(root, server, [], { analyzers: [engine.analyzer] }, ci);
    return { ...r, server, engine };
  }
  type FakeEngine = ReturnType<typeof fakeSecretEngine>;
  const mergedResult = (m: MergeCheckout) =>
    gitlabMr(m.merge, {
      CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result',
      CI_MERGE_REQUEST_SOURCE_BRANCH_SHA: m.head,
    });

  it(
    'N1: a file too large to send whole, rewritten by a CI step: the secret the merge request adds is masked on its patch',
    { timeout: 60_000 },
    async () => {
      const secret = fakeSecret('added0to0a0big0file');
      // 1.6 MB: over the snapshot's 1 MiB for a file, so only its patch shows it.
      const big = `${'x'.repeat(79)}\n`.repeat(20_000);
      const mr = mrRepo({
        base: { 'src/big.txt': big },
        head: { 'src/a.ts': 'export const a = 2;\n', 'src/big.txt': `${big}key = ${secret}\n` },
      });
      // A CI step rewrote the file before the scan: the analyzers never saw the line.
      writeTree(mr.root, { 'src/big.txt': big });
      const { code, stderr, server, engine } = await scanWithEngine(mr.root, gitlabMr(mr.head));
      expect(code, stderr).toBe(0);
      const { text, lines } = sent(server);
      expect(text).not.toContain(secret);
      expect(omittedOf(lines)['src/big.txt']).toBe('too_large');
      const patch = lines.filter(isChange).find((l) => l.path === 'src/big.txt')?.patch ?? '';
      expect(patch).toContain(`\n+key = ${REDACTED}\n`);
      expect(headRuns(engine)).toHaveLength(1);
    },
  );

  it(
    'N1: a file too large to scan, whose patch context shows a secret main removed after the merge base: the patch is not sent',
    { timeout: 120_000 },
    async () => {
      const secret = fakeSecret('in0a0huge0file');
      // 17 MB: over the 16 MiB the secret scan of a commit's file takes.
      const filler = Array.from(
        { length: 175_000 },
        (_, i) => `line ${String(i + 1).padStart(6, '0')} ${'y'.repeat(85)}\n`,
      );
      const huge = (lines: Record<number, string>) =>
        filler.map((l, i) => lines[i + 1] ?? l).join('');
      const m = mergeCheckout({
        base: { 'src/huge.txt': huge({ 1004: `key = ${secret}\n` }) },
        // Line 1001 changes: line 1004 is in the patch's context.
        head: { 'src/huge.txt': huge({ 1001: 'changed\n', 1004: `key = ${secret}\n` }) },
        target: { 'src/huge.txt': huge({ 1004: "key = process.env['KEY']\n" }) },
      });
      const { code, stderr, server } = await scanWithEngine(m.root, mergedResult(m));
      expect(code, stderr).toBe(0);
      const { text, lines } = sent(server);
      expect(text).not.toContain(secret);
      expect(lines.filter(isChange).find((l) => l.path === 'src/huge.txt')).toMatchObject({
        status: 'modified',
        patch: null,
      });
      expect(omittedOf(lines)['src/huge.txt']).toBe('too_large');
      expect(stderr).toContain('cannot be given to the secret scan');
    },
  );

  it(
    'N2: a sparse checkout: a head file outside its cone, which the scan never saw, is scanned',
    { timeout: 60_000 },
    async () => {
      const secret = fakeSecret('outside0the0sparse0cone');
      const mr = mrRepo({ base: { 'lib/leak.ts': `export const key = '${secret}';\n` } });
      gitSync(mr.root, 'sparse-checkout', 'set', '--cone', 'src');
      expect(existsSync(path.join(mr.root, 'lib', 'leak.ts'))).toBe(false);
      const { code, stderr, server, engine } = await scanWithEngine(mr.root, gitlabMr(mr.head));
      expect(code, stderr).toBe(0);
      const { text, lines } = sent(server);
      expect(text).not.toContain(secret);
      const sentFiles = new Map(lines.filter(isFile).map((l) => [l.path, l.text]));
      expect(sentFiles.get('lib/leak.ts')).toBe(`export const key = '${REDACTED}';\n`);
      expect(headRuns(engine)).toHaveLength(1);
    },
  );

  it(
    'N2: a file marked assume-unchanged and edited after the checkout: its head version is scanned',
    { timeout: 60_000 },
    async () => {
      const secret = fakeSecret('hidden0by0assume0unchanged');
      const mr = mrRepo({
        head: {
          'src/a.ts': 'export const a = 2;\n',
          'src/config.ts': `export const key = '${secret}';\n`,
        },
      });
      gitSync(mr.root, 'update-index', '--assume-unchanged', 'src/config.ts');
      writeTree(mr.root, { 'src/config.ts': "export const key = process.env['KEY'];\n" });
      // git takes the index's word for the file: it sees no difference.
      expect(gitSync(mr.root, 'diff', '--name-only', mr.head)).toBe('');
      const { code, stderr, server } = await scanWithEngine(mr.root, gitlabMr(mr.head));
      expect(code, stderr).toBe(0);
      const { text, lines } = sent(server);
      expect(text).not.toContain(secret);
      const sentFiles = new Map(lines.filter(isFile).map((l) => [l.path, l.text]));
      expect(sentFiles.get('src/config.ts')).toBe(`export const key = '${REDACTED}';\n`);
    },
  );

  it(
    'N3: a file the checkout holds in another encoding (working-tree-encoding): its UTF-8 head version is scanned',
    { timeout: 60_000 },
    async () => {
      const secret = fakeSecret('in0a0utf16le0checkout');
      const mr = mrRepo({
        head: {
          'src/a.ts': 'export const a = 2;\n',
          '.gitattributes': '*.txt text working-tree-encoding=UTF-16LE\n',
          // The working tree's file is UTF-16LE; the commit holds it in UTF-8.
          'notes.txt': Buffer.from(`key = ${secret}\n`, 'utf16le'),
        },
      });
      expect(gitSync(mr.root, 'diff', '--name-only', mr.head)).toBe('');
      const { code, stderr, server } = await scanWithEngine(mr.root, gitlabMr(mr.head));
      expect(code, stderr).toBe(0);
      const { text, lines } = sent(server);
      expect(text).not.toContain(secret);
      const sentFiles = new Map(lines.filter(isFile).map((l) => [l.path, l.text]));
      expect(sentFiles.get('notes.txt')).toBe(`key = ${REDACTED}\n`);
    },
  );

  it(
    "N4: the target changed the scan's root .gitleaksignore after the merge base: it is never sent, and no longer in the way",
    { timeout: 60_000 },
    async () => {
      const m = mergeCheckout({
        base: { '.gitleaksignore': 'src/old.ts:fake-secret:1\n' },
        target: { '.gitleaksignore': 'src/new.ts:fake-secret:1\n' },
      });
      const { code, stderr, server } = await scanWithEngine(m.root, mergedResult(m));
      expect(code, stderr).toBe(0);
      expect(server.paths).toEqual([...UNTIL_REPORT, CONTEXT, SNAPSHOT, GATE]);
      const { text, lines } = sent(server);
      expect(text).not.toContain(LEAKED);
      expect(omittedOf(lines)['.gitleaksignore']).toBe('excluded');
      expect(reviewWarnings(stderr)).toEqual([]);
    },
  );
});
