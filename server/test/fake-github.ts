import {
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  verify,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * A local fake of the GitHub REST endpoints Qualor uses (github.md §4–§6, §13), served under
 * `/api/v3` as GitHub Enterprise Server serves them, for tests: nothing in `pnpm test` contacts a
 * real GitHub. Answers are built from `github-shapes/`, written from GitHub's REST documentation
 * (API version 2022-11-28), NOT captured from a live GitHub: a behaviour listed here is
 * what the documentation says, and plan 2C lists the ones no real answer confirmed.
 *
 * What it checks where Qualor depends on it: the App JWT (RS256 with the App's public key, `iss`
 * the App id, `iat` not in the fake's future, at most 10 minutes); installation tokens (issued
 * only for repositories and permissions the installation has, expiring after an hour, revocable);
 * each endpoint's permission; at most 50 annotations per request (appended on PATCH, as GitHub
 * does); `filter=latest` and `app_id` of the check-run listing; `Link` headers with `rel="next"`.
 */

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'github-shapes');

export function githubShape(name: string): Record<string, unknown>;
export function githubShape<T>(name: string): T;
export function githubShape(name: string): unknown {
  return JSON.parse(readFileSync(path.join(SHAPES, `${name}.json`), 'utf8'));
}

type Access = 'read' | 'write';
export interface FakeRepository {
  id: number;
  owner: string;
  name: string;
  /** Null: the App is not installed on it. */
  installationId: number | null;
  /** What the installation was granted (default: checks, pull_requests write, metadata read). */
  permissions?: Record<string, Access>;
  /**
   * Renamed or transferred to this `owner/name`: a 301 which, as GitHub's, points to
   * `/repositories/{id}` rather than to the new name.
   */
  movedTo?: string;
  /** The installation is suspended: a 403 on the token request. */
  suspended?: boolean;
}
export interface FakeFile {
  filename: string;
  status?: string;
  /** Absent for a binary or too-large file. */
  patch?: string;
}
export interface FakePull {
  number: number;
  title: string;
  state: 'open' | 'closed';
  headSha: string;
  baseSha: string;
  files: FakeFile[];
}
export interface FakeComment {
  id: number;
  repoId: number;
  issue: number;
  body: string;
  user: { login: string; id: number; type: 'Bot' | 'User' };
}
/** A pull request review comment: a comment on RIGHT-side lines of one file's diff. */
export interface FakeReviewComment {
  id: number;
  repoId: number;
  pull: number;
  body: string;
  path: string;
  line: number;
  startLine: number | null;
  side: string;
  commitId: string;
  user: { login: string; id: number; type: 'Bot' | 'User' };
}
export interface FakeCheckRun {
  id: number;
  repoId: number;
  appId: number;
  name: string;
  headSha: string;
  conclusion: string | null;
  externalId: string | null;
  detailsUrl: string | null;
  title: string | null;
  summary: string | null;
  annotations: Record<string, unknown>[];
}
export interface RecordedRequest {
  method: string;
  /** Without the `/api/v3` prefix, with the query. */
  path: string;
  auth: 'jwt' | 'token' | 'none';
  body: string;
  headers: Record<string, string | string[] | undefined>;
}
export interface InjectedAnswer {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}
export interface FakeGitHub {
  /** The API base URL (`http://127.0.0.1:<port>/api/v3`). */
  url: string;
  appId: number;
  slug: string;
  privateKeyPem: string;
  requests: RecordedRequest[];
  comments: FakeComment[];
  /** Pull request review comments (`/pulls/{n}/comments`). */
  reviewComments: FakeReviewComment[];
  checkRuns: FakeCheckRun[];
  /** Every check run created with annotations is refused (422), until set back to false. */
  rejectAnnotations: boolean;
  /** Issued installation tokens and their scope. */
  tokens: Map<
    string,
    {
      installationId: number;
      repositories: string[];
      permissions: Record<string, Access>;
      expiresAt: number;
    }
  >;
  addRepository(repo: FakeRepository): void;
  addPull(repoId: number, pull: FakePull): void;
  updatePull(repoId: number, number: number, changes: Partial<FakePull>): void;
  addComment(
    repoId: number,
    issue: number,
    comment: { body: string; login: string; type?: 'Bot' | 'User' },
  ): FakeComment;
  /** Every issued token stops working (an uninstall, a revocation). */
  revokeTokens(): void;
  inject(method: string, path: RegExp, ...answers: InjectedAnswer[]): void;
  clearRequests(): void;
  close(): Promise<void>;
}

/** A check run's request body as a client may send it (types unchecked until validated). */
interface CheckRunBody {
  name?: string;
  head_sha?: string;
  status?: string;
  conclusion?: string;
  external_id?: string;
  details_url?: string;
  output?: { title?: string; summary?: string; annotations?: Record<string, unknown>[] };
}

const DEFAULT_PERMISSIONS: Record<string, Access> = {
  checks: 'write',
  pull_requests: 'write',
  metadata: 'read',
};
const PREFIX = '/api/v3';
const LEVELS = new Set(['notice', 'warning', 'failure']);
const CONCLUSIONS = new Set([
  'success',
  'failure',
  'neutral',
  'cancelled',
  'skipped',
  'timed_out',
  'action_required',
]);

/**
 * The new-file lines a patch shows (added and context lines of its hunks): where GitHub places a
 * RIGHT-side review comment. Written apart from the server's diff reader, so the two check each
 * other.
 */
function rightSideLines(patch: string): Set<number> {
  const lines = new Set<number>();
  let next = 0;
  for (const text of patch.split('\n')) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) next = Number(hunk[1]);
    else if (next > 0 && (text.startsWith('+') || text.startsWith(' '))) lines.add(next++);
  }
  return lines;
}

let sharedKey: { privateKey: KeyObject; pem: string } | null = null;
/** One 2048-bit key per test process (generating one takes ~100 ms). */
function appKey(): { privateKey: KeyObject; pem: string } {
  if (!sharedKey) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    sharedKey = { privateKey, pem: privateKey.export({ type: 'pkcs1', format: 'pem' }).toString() };
  }
  return sharedKey;
}

export async function createFakeGitHub(
  options: { appId?: number; slug?: string; now?: () => number } = {},
): Promise<FakeGitHub> {
  const appId = options.appId ?? 123456;
  const slug = options.slug ?? 'qualor-acme';
  const now = options.now ?? Date.now;
  const key = appKey();
  const publicKey = createPublicKey(key.privateKey);
  const repos = new Map<string, FakeRepository>();
  const pulls = new Map<string, FakePull>();
  const injections: { method: string; path: RegExp; answers: InjectedAnswer[] }[] = [];
  let nextId = 1;

  const fake: FakeGitHub = {
    url: '',
    appId,
    slug,
    privateKeyPem: key.pem,
    requests: [],
    comments: [],
    reviewComments: [],
    checkRuns: [],
    rejectAnnotations: false,
    tokens: new Map(),
    addRepository: (repo) => repos.set(`${repo.owner}/${repo.name}`.toLowerCase(), repo),
    addPull: (repoId, pull) => pulls.set(`${repoId}#${pull.number}`, structuredClone(pull)),
    updatePull: (repoId, number, changes) => {
      const pull = pulls.get(`${repoId}#${number}`);
      if (pull) Object.assign(pull, changes);
    },
    addComment: (repoId, issue, c) => {
      const comment: FakeComment = {
        id: nextId++,
        repoId,
        issue,
        body: c.body,
        user: { login: c.login, id: c.type === 'Bot' ? 41898282 : 5, type: c.type ?? 'User' },
      };
      fake.comments.push(comment);
      return comment;
    },
    revokeTokens: () => fake.tokens.clear(),
    inject: (method, p, ...answers) => injections.push({ method, path: p, answers }),
    clearRequests: () => {
      fake.requests.length = 0;
    },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };

  const send = (
    res: ServerResponse,
    status: number,
    body?: unknown,
    headers: Record<string, string> = {},
  ) => {
    const text = body === undefined ? '' : JSON.stringify(body);
    res
      .writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers })
      .end(text);
  };
  const deny = (res: ServerResponse, status: number, message: string) =>
    send(res, status, {
      message,
      documentation_url: 'https://docs.github.com/rest',
      status: String(status),
    });

  const jwtOk = (token: string): boolean => {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) return false;
    if (!verify('sha256', Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, 'base64url')))
      return false;
    try {
      const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as { alg?: string };
      const claims = JSON.parse(Buffer.from(p, 'base64url').toString()) as {
        iat: number;
        exp: number;
        iss: unknown;
      };
      const t = Math.floor(now() / 1000);
      return (
        header.alg === 'RS256' &&
        String(claims.iss) === String(appId) &&
        claims.iat <= t &&
        claims.exp > t &&
        claims.exp - claims.iat <= 600
      );
    } catch {
      return false;
    }
  };

  const page = <T>(req: URL, res: ServerResponse, items: T[]) => {
    const per = Math.min(Number(req.searchParams.get('per_page') ?? '30'), 100);
    const n = Number(req.searchParams.get('page') ?? '1');
    const slice = items.slice((n - 1) * per, n * per);
    const headers: Record<string, string> = {};
    if (n * per < items.length) {
      const next = new URL(req.href);
      next.searchParams.set('page', String(n + 1));
      headers.link = `<${next.href}>; rel="next", <${next.href}>; rel="last"`;
    }
    send(res, 200, slice, headers);
  };

  /** Where the fake's own links live, as GitHub Enterprise Server's are: the API URL without `/api/v3`. */
  const webBase = () => fake.url.slice(0, -PREFIX.length);

  const checkRunJson = (run: FakeCheckRun) => ({
    ...githubShape('check_run'),
    id: run.id,
    name: run.name,
    head_sha: run.headSha,
    status: 'completed',
    conclusion: run.conclusion,
    external_id: run.externalId,
    details_url: run.detailsUrl,
    output: {
      title: run.title,
      summary: run.summary,
      text: null,
      annotations_count: run.annotations.length,
      annotations_url: '',
    },
    app: { id: run.appId, slug, name: 'Qualor' },
  });

  const commentJson = (c: FakeComment) => ({
    ...githubShape('issue_comment'),
    id: c.id,
    body: c.body,
    user: c.user,
    performed_via_github_app: c.user.type === 'Bot' ? { id: appId, slug } : null,
  });

  const reviewCommentJson = (repo: FakeRepository) => (c: FakeReviewComment) => ({
    ...githubShape('pull_request_review_comment'),
    id: c.id,
    body: c.body,
    path: c.path,
    commit_id: c.commitId,
    original_commit_id: c.commitId,
    line: c.line,
    original_line: c.line,
    start_line: c.startLine,
    original_start_line: c.startLine,
    start_side: c.startLine === null ? null : 'RIGHT',
    side: c.side,
    user: c.user,
    html_url: `${webBase()}/${repo.owner}/${repo.name}/pull/${c.pull}#discussion_r${c.id}`,
    performed_via_github_app: c.user.type === 'Bot' ? { id: appId, slug } : null,
  });

  /** GitHub requires `title` and `summary` in a check run's `output`, when it is sent. */
  const badCheckRunOutput = (output: CheckRunBody['output']): string | null => {
    if (output === undefined) return null;
    if (typeof output.title !== 'string' || typeof output.summary !== 'string')
      return 'Invalid request.\n\n"title" and "summary" are required keys of "output".';
    return null;
  };

  /** Validates a check run's output annotations as GitHub documents them; null when valid. */
  const badAnnotations = (annotations: unknown): string | null => {
    if (annotations === undefined) return null;
    if (!Array.isArray(annotations) || annotations.length > 50)
      return 'Invalid request.\n\nOnly 50 annotations are allowed per request.';
    for (const a of annotations as Record<string, unknown>[]) {
      if (typeof a.path !== 'string' || a.path === '') return 'Invalid request.';
      if (!Number.isInteger(a.start_line) || (a.start_line as number) < 1)
        return 'Invalid request.';
      if (!Number.isInteger(a.end_line) || (a.end_line as number) < (a.start_line as number))
        return 'Invalid request.';
      if (!LEVELS.has(String(a.annotation_level))) return 'Invalid request.';
      if (
        typeof a.message !== 'string' ||
        a.message === '' ||
        Buffer.byteLength(a.message) > 64 * 1024
      )
        return 'Invalid request.';
      if (a.title !== undefined && (typeof a.title !== 'string' || a.title.length > 255))
        return 'Invalid request.';
    }
    return null;
  };

  const handle = (req: IncomingMessage, res: ServerResponse, body: string) => {
    const url = new URL(req.url ?? '/', 'http://fake');
    const method = req.method ?? 'GET';
    const authorization = req.headers.authorization ?? '';
    const bearer = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    const auth: RecordedRequest['auth'] =
      bearer.split('.').length === 3 ? 'jwt' : bearer ? 'token' : 'none';
    const p = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : url.pathname;
    fake.requests.push({ method, path: p + url.search, auth, body, headers: { ...req.headers } });
    for (const injection of injections) {
      if (injection.method === method && injection.path.test(p) && injection.answers.length > 0) {
        const answer = injection.answers.shift()!;
        return send(res, answer.status, answer.body, answer.headers);
      }
    }
    if (!url.pathname.startsWith(PREFIX)) return deny(res, 404, 'Not Found');
    if (typeof req.headers['user-agent'] !== 'string')
      return deny(
        res,
        403,
        'Request forbidden by administrative rules. Please make sure your request has a User-Agent header',
      );
    let parsedBody: Record<string, unknown> = {};
    if (body !== '') {
      try {
        parsedBody = JSON.parse(body) as Record<string, unknown>;
      } catch {
        return deny(res, 400, 'Problems parsing JSON');
      }
    }
    const json = (): Record<string, unknown> => parsedBody;

    // App-level endpoints (JWT).
    if (auth === 'jwt' && !jwtOk(bearer))
      return deny(
        res,
        401,
        "'Issued at' claim ('iat') must be an Integer representing the time that the assertion was issued",
      );
    if (method === 'GET' && p === '/app') {
      if (auth !== 'jwt') return deny(res, 401, 'A JSON web token could not be decoded');
      return send(res, 200, { ...githubShape('app'), id: appId, slug });
    }
    const tokenMatch = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(p);
    if (method === 'POST' && tokenMatch) {
      if (auth !== 'jwt') return deny(res, 401, 'A JSON web token could not be decoded');
      const installationId = Number(tokenMatch[1]);
      const installed = [...repos.values()].filter((r) => r.installationId === installationId);
      const request = json() as { repositories?: string[]; permissions?: Record<string, Access> };
      const names = request.repositories ?? installed.map((r) => r.name);
      if (!names.every((n) => installed.some((r) => r.name.toLowerCase() === n.toLowerCase()))) {
        return deny(
          res,
          422,
          'There is at least one repository that does not exist or is not accessible to the parent installation.',
        );
      }
      if (installed.some((r) => r.suspended))
        return deny(res, 403, 'This installation has been suspended');
      const granted = installed[0]?.permissions ?? DEFAULT_PERMISSIONS;
      const wanted = request.permissions ?? granted;
      for (const [name, access] of Object.entries(wanted)) {
        const has = granted[name];
        if (!has || (access === 'write' && has !== 'write'))
          return deny(res, 422, 'The permissions requested are not granted to this installation.');
      }
      const token = `ghs_${randomBytes(18).toString('hex')}`;
      const expiresAt = now() + 60 * 60_000;
      fake.tokens.set(token, {
        installationId,
        repositories: names.map((n) => n.toLowerCase()),
        permissions: wanted,
        expiresAt,
      });
      return send(res, 201, {
        ...githubShape('installation_token'),
        token,
        expires_at: new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, 'Z'),
        permissions: wanted,
      });
    }

    const repoMatch = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(p);
    if (!repoMatch) return deny(res, 404, 'Not Found');
    const repo = repos.get(
      `${decodeURIComponent(repoMatch[1]!)}/${decodeURIComponent(repoMatch[2]!)}`.toLowerCase(),
    );
    const rest = repoMatch[3] ?? '';
    if (repo?.movedTo) {
      return send(
        res,
        301,
        {
          message: 'Moved Permanently',
          url: `${fake.url}/repositories/${repo.id}${rest}`,
          documentation_url:
            'https://docs.github.com/rest/guides/best-practices-for-using-the-rest-api#follow-redirects',
        },
        { location: `${fake.url}/repositories/${repo.id}${rest}` },
      );
    }
    if (method === 'GET' && rest === '/installation') {
      if (auth !== 'jwt') return deny(res, 401, 'A JSON web token could not be decoded');
      if (!repo || repo.installationId === null) return deny(res, 404, 'Not Found');
      return send(res, 200, {
        ...githubShape('installation'),
        id: repo.installationId,
        app_id: appId,
        app_slug: slug,
      });
    }
    // Repository endpoints (installation token).
    const grant = fake.tokens.get(bearer);
    if (auth !== 'token' || !grant || grant.expiresAt <= now())
      return deny(res, 401, 'Bad credentials');
    if (
      !repo ||
      repo.installationId !== grant.installationId ||
      !grant.repositories.includes(repo.name.toLowerCase())
    )
      return deny(res, 404, 'Not Found');
    const need = (permission: string, access: Access) => {
      const has = grant.permissions[permission];
      return has !== undefined && (access === 'read' || has === 'write');
    };
    const forbidden = () => deny(res, 403, 'Resource not accessible by integration');

    if (method === 'GET' && rest === '') {
      if (!need('metadata', 'read')) return forbidden();
      return send(res, 200, {
        ...githubShape('repository'),
        id: repo.id,
        name: repo.name,
        full_name: `${repo.owner}/${repo.name}`,
        html_url: `${webBase()}/${repo.owner}/${repo.name}`,
      });
    }
    const listRuns = /^\/commits\/([0-9a-f]{40,64})\/check-runs$/.exec(rest);
    if (method === 'GET' && listRuns) {
      if (!need('checks', 'read')) return forbidden();
      const name = url.searchParams.get('check_name');
      const app = url.searchParams.get('app_id');
      let runs = fake.checkRuns.filter(
        (r) =>
          r.repoId === repo.id &&
          r.headSha === listRuns[1] &&
          (name === null || r.name === name) &&
          (app === null || String(r.appId) === app),
      );
      if (url.searchParams.get('filter') !== 'all') {
        const newest = new Map<string, FakeCheckRun>();
        for (const r of runs) if ((newest.get(r.name)?.id ?? -1) < r.id) newest.set(r.name, r);
        runs = [...newest.values()];
      }
      return send(res, 200, { total_count: runs.length, check_runs: runs.map(checkRunJson) });
    }
    if (method === 'POST' && rest === '/check-runs') {
      if (!need('checks', 'write')) return forbidden();
      const b = json() as CheckRunBody;
      if (
        typeof b.name !== 'string' ||
        b.name === '' ||
        !/^[0-9a-f]{40,64}$/.test(String(b.head_sha))
      )
        return deny(res, 422, 'Invalid request.');
      if (b.status === 'completed' && !CONCLUSIONS.has(String(b.conclusion)))
        return deny(res, 422, 'Invalid request.');
      const badOutput = badCheckRunOutput(b.output);
      if (badOutput) return deny(res, 422, badOutput);
      const bad = badAnnotations(b.output?.annotations);
      if (bad) return deny(res, 422, bad);
      if (fake.rejectAnnotations && (b.output?.annotations?.length ?? 0) > 0)
        return deny(res, 422, 'Invalid request.');
      const run: FakeCheckRun = {
        id: nextId++,
        repoId: repo.id,
        appId,
        name: b.name,
        headSha: String(b.head_sha),
        conclusion: b.conclusion ?? null,
        externalId: b.external_id ?? null,
        detailsUrl: b.details_url ?? null,
        title: b.output?.title ?? null,
        summary: b.output?.summary ?? null,
        annotations: b.output?.annotations ?? [],
      };
      fake.checkRuns.push(run);
      return send(res, 201, checkRunJson(run));
    }
    const patchRun = /^\/check-runs\/(\d+)$/.exec(rest);
    if (method === 'PATCH' && patchRun) {
      if (!need('checks', 'write')) return forbidden();
      const run = fake.checkRuns.find((r) => r.id === Number(patchRun[1]) && r.repoId === repo.id);
      if (!run) return deny(res, 404, 'Not Found');
      if (run.appId !== appId) return forbidden();
      const b = json() as CheckRunBody;
      const badOutput = badCheckRunOutput(b.output);
      if (badOutput) return deny(res, 422, badOutput);
      const bad = badAnnotations(b.output?.annotations);
      if (bad) return deny(res, 422, bad);
      if (b.conclusion !== undefined) run.conclusion = b.conclusion;
      if (b.external_id !== undefined) run.externalId = b.external_id;
      if (b.details_url !== undefined) run.detailsUrl = b.details_url;
      if (b.output?.title !== undefined) run.title = b.output.title;
      if (b.output?.summary !== undefined) run.summary = b.output.summary;
      // GitHub appends annotations on an update; it never removes one.
      if (Array.isArray(b.output?.annotations)) run.annotations.push(...b.output.annotations);
      return send(res, 200, checkRunJson(run));
    }
    const pullMatch = /^\/pulls\/(\d+)(\/files)?$/.exec(rest);
    if (method === 'GET' && pullMatch) {
      if (!need('pull_requests', 'read')) return forbidden();
      const pull = pulls.get(`${repo.id}#${pullMatch[1]}`);
      if (!pull) return deny(res, 404, 'Not Found');
      if (pullMatch[2]) {
        return page(
          url,
          res,
          pull.files.map((f) => ({
            ...(githubShape<unknown[]>('pull_request_files')[0] as object),
            filename: f.filename,
            status: f.status ?? 'modified',
            ...(f.patch === undefined ? { patch: undefined } : { patch: f.patch }),
          })),
        );
      }
      return send(res, 200, {
        ...githubShape('pull_request'),
        number: pull.number,
        title: pull.title,
        state: pull.state,
        html_url: `${webBase()}/${repo.owner}/${repo.name}/pull/${pull.number}`,
        head: { ref: 'feature/x', sha: pull.headSha, label: 'x' },
        base: { ref: 'main', sha: pull.baseSha, label: 'y' },
      });
    }
    const reviewComments = /^\/pulls\/(\d+)\/comments$/.exec(rest);
    if (reviewComments && method === 'GET') {
      if (!need('pull_requests', 'read')) return forbidden();
      return page(
        url,
        res,
        fake.reviewComments
          .filter((c) => c.repoId === repo.id && c.pull === Number(reviewComments[1]))
          .map(reviewCommentJson(repo)),
      );
    }
    if (reviewComments && method === 'POST') {
      if (!need('pull_requests', 'write')) return forbidden();
      const pull = pulls.get(`${repo.id}#${reviewComments[1]}`);
      if (!pull) return deny(res, 404, 'Not Found');
      const b = json() as {
        body?: unknown;
        commit_id?: unknown;
        path?: unknown;
        side?: unknown;
        line?: unknown;
        start_line?: unknown;
        start_side?: unknown;
      };
      const line = Number(b.line);
      const start = b.start_line === undefined ? line : Number(b.start_line);
      const patch = pull.files.find((f) => f.filename === b.path)?.patch;
      const lines = patch === undefined ? new Set<number>() : rightSideLines(patch);
      const placed = Array.from({ length: Math.max(0, line - start + 1) }, (_, i) => start + i);
      if (
        typeof b.body !== 'string' ||
        b.body === '' ||
        b.body.length > 65_536 ||
        b.commit_id !== pull.headSha ||
        b.side !== 'RIGHT' ||
        !Number.isInteger(line) ||
        !Number.isInteger(start) ||
        start > line ||
        (b.start_line !== undefined && b.start_side !== 'RIGHT') ||
        placed.length === 0 ||
        !placed.every((n) => lines.has(n))
      ) {
        return deny(res, 422, 'Validation Failed');
      }
      const created: FakeReviewComment = {
        id: nextId++,
        repoId: repo.id,
        pull: pull.number,
        body: b.body,
        path: String(b.path),
        line,
        startLine: b.start_line === undefined ? null : start,
        side: 'RIGHT',
        commitId: pull.headSha,
        user: { login: `${slug}[bot]`, id: 41898282, type: 'Bot' },
      };
      fake.reviewComments.push(created);
      return send(res, 201, reviewCommentJson(repo)(created));
    }
    const issueComments = /^\/issues\/(\d+)\/comments$/.exec(rest);
    if (issueComments && method === 'GET') {
      if (!need('pull_requests', 'read')) return forbidden();
      return page(
        url,
        res,
        fake.comments
          .filter((c) => c.repoId === repo.id && c.issue === Number(issueComments[1]))
          .map(commentJson),
      );
    }
    if (issueComments && method === 'POST') {
      if (!need('pull_requests', 'write')) return forbidden();
      const b = json() as { body?: unknown };
      if (typeof b.body !== 'string' || b.body.length > 65_536)
        return deny(res, 422, 'Validation Failed');
      const created = fake.addComment(repo.id, Number(issueComments[1]), {
        body: b.body,
        login: `${slug}[bot]`,
        type: 'Bot',
      });
      return send(res, 201, commentJson(created));
    }
    const editComment = /^\/issues\/comments\/(\d+)$/.exec(rest);
    if (editComment && method === 'PATCH') {
      if (!need('pull_requests', 'write')) return forbidden();
      const comment = fake.comments.find(
        (c) => c.id === Number(editComment[1]) && c.repoId === repo.id,
      );
      if (!comment) return deny(res, 404, 'Not Found');
      if (comment.user.login !== `${slug}[bot]`) return forbidden();
      const b = json() as { body?: unknown };
      if (typeof b.body !== 'string') return deny(res, 422, 'Validation Failed');
      comment.body = b.body;
      return send(res, 200, commentJson(comment));
    }
    return deny(res, 404, 'Not Found');
  };

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => handle(req, res, Buffer.concat(chunks).toString('utf8')));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  fake.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}${PREFIX}`;
  return fake;
}
