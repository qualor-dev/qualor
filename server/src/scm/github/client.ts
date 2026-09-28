import type { KeyObject } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { z } from 'zod';
import { outboundRequest, type OutboundResult, type Resolver } from '../../http/outbound';
import { VERSION } from '../../index';
import { MAX_RETRY_AFTER_SECONDS } from '../gitlab/client';
import { ScmError, type Paged } from '../provider';
import { scmRefusedAddress } from '../url';
import {
  appJwt,
  InstallationTokenCache,
  isGitHubAppId,
  MutationPacer,
  tokenCacheKey,
} from './app-auth';
import { GITHUB_REPO_PATTERN, type GitHubRepoRef } from './url';

/** github.md §5.3. */
export const GITHUB_TIMEOUT_MS = 10_000;
export const MAX_GITHUB_RESPONSE_BYTES = 8 * 1024 * 1024;
export const GITHUB_PAGE_SIZE = 100;
export const MAX_GITHUB_REQUESTS = 120;
/** GitHub's advice for a secondary rate limit without `Retry-After`: wait at least a minute. */
export const SECONDARY_LIMIT_SECONDS = 60;
export const GITHUB_API_VERSION = '2022-11-28';
/** A pull request number, 1–10 digits (the only form sent in a path). */
export const GITHUB_PR_NUMBER = /^[0-9]{1,10}$/;
const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
/** github.md §4: what an installation token may do, and nothing more. */
export const INSTALLATION_PERMISSIONS = {
  checks: 'write',
  pull_requests: 'write',
  metadata: 'read',
} as const;

/** github.md §5.4: the fixed texts; GitHub's own words are never shown or logged. */
export const GITHUB_TEXT = {
  appRefused:
    "GitHub refused the App's credentials (HTTP 401); check the App id, the private key and the server's clock",
  tokenRefused: 'GitHub refused the installation token (HTTP 401)',
  notInstalled: 'The GitHub App is not installed on the repository',
  permission:
    'The GitHub App lacks a permission Qualor needs (checks: write, pull requests: write)',
  /** A 403 on the token request: GitHub answers so for a suspended installation too. */
  permissionOrSuspended:
    'The GitHub App lacks a permission Qualor needs (checks: write, pull requests: write), or its installation is suspended',
  notFound: 'The GitHub repository was not found, or the App cannot see it',
  badAnswer: "GitHub's answer was not understood",
  budget: `More than ${MAX_GITHUB_REQUESTS} GitHub requests in one job`,
  prNumber: 'The pull request id is not a GitHub pull request number',
  revision: 'The revision is not a full commit SHA',
  id: 'The id is not a GitHub id',
  line: 'The line is not a line number of the file',
  appId: 'The App id is not a GitHub App id (a positive integer)',
  repo: 'The repository is not a GitHub owner/repo',
  notPublic:
    'The GitHub host resolves to a private, loopback or otherwise non-public address; list it in QUALOR_SCM_INTERNAL_HOSTS',
  refusedAddress: 'The GitHub host resolves to a link-local, cloud metadata or loopback address',
  unresolved: 'The GitHub host could not be resolved',
  timeout: 'GitHub did not answer within 10 s',
} as const;

// ─── Response shapes (the fields Qualor reads; server/test/github-shapes/ holds recorded ones) ──

const sha = z.string().regex(SHA);
const app = z.looseObject({ id: z.number().int(), slug: z.string().min(1).max(100) });
export type GitHubApp = z.infer<typeof app>;
const installation = z.looseObject({ id: z.number().int(), app_id: z.number().int() });
const installationToken = z.looseObject({
  token: z.string().regex(/^[\x21-\x7e]{1,512}$/),
  expires_at: z.iso.datetime(),
});
const repository = z.looseObject({
  id: z.number().int(),
  full_name: z.string(),
  html_url: z.string(),
});
export type GitHubRepository = z.infer<typeof repository>;
const checkRun = z.looseObject({
  id: z.number().int(),
  name: z.string(),
  head_sha: sha,
  status: z.string(),
  conclusion: z.string().nullable(),
  external_id: z.string().nullable(),
  details_url: z.string().nullable(),
  output: z.looseObject({
    title: z.string().nullable(),
    summary: z.string().nullable(),
    annotations_count: z.number().int(),
  }),
  app: z.looseObject({ id: z.number().int() }).nullable(),
});
export type GitHubCheckRun = z.infer<typeof checkRun>;
const checkRuns = z.looseObject({ total_count: z.number().int(), check_runs: z.array(checkRun) });
const pullRequest = z.looseObject({
  number: z.number().int(),
  state: z.string(),
  title: z.string(),
  html_url: z.string(),
  head: z.looseObject({ sha, ref: z.string() }),
  base: z.looseObject({ ref: z.string() }),
});
export type GitHubPullRequest = z.infer<typeof pullRequest>;
const file = z.looseObject({
  filename: z.string(),
  status: z.string(),
  patch: z.string().optional(),
});
export type GitHubFile = z.infer<typeof file>;
const comment = z.looseObject({
  id: z.number().int(),
  body: z.string().nullable(),
  user: z.looseObject({ login: z.string(), type: z.string() }).nullable(),
});
export type GitHubComment = z.infer<typeof comment>;
/** A pull request review comment (llm.md §8.4): a comment on lines of the diff. */
const reviewComment = z.looseObject({
  id: z.number().int(),
  body: z.string(),
  user: z.looseObject({ login: z.string(), type: z.string() }).nullable(),
  html_url: z.string().optional(),
});
export type GitHubReviewComment = z.infer<typeof reviewComment>;
const errorBody = z.looseObject({ message: z.unknown().optional() });

/** Every recorded shape the client parses, for the shape tests (server/test/github-shapes/). */
export const GITHUB_SHAPES = {
  app,
  installation,
  installationToken,
  repository,
  checkRun,
  checkRuns,
  pullRequest,
  pullRequestFiles: z.array(file),
  issueComment: comment,
  issueComments: z.array(comment),
  reviewComment,
  reviewComments: z.array(reviewComment),
} as const;

export type AnnotationLevel = 'notice' | 'warning' | 'failure';
/** github.md §6.4: one annotation, keys in the order the digest uses. */
export interface GitHubAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: AnnotationLevel;
  title: string;
  message: string;
}

export interface CheckRunUpdate {
  conclusion: 'success' | 'failure';
  title: string;
  summary: string;
  detailsUrl: string | null;
  externalId: string;
}
export interface CheckRunInput extends CheckRunUpdate {
  name: string;
  headSha: string;
  annotations: readonly GitHubAnnotation[];
}

export interface GitHubConnectionInput {
  connectionId: string;
  /** Normalised, without a trailing slash (scm/url.ts), allowed by github/url.ts. */
  baseUrl: string;
  appId: string;
  privateKey: KeyObject;
  /** `credentialsId(appId, pkcs8)`: keys the token cache. */
  credentials: string;
  /** The host is in `QUALOR_SCM_INTERNAL_HOSTS` (scm.md §2.1). */
  allowInternalHosts: boolean;
}

export interface GitHubClientOptions {
  timeoutMs?: number;
  connectTimeoutMs?: number;
  resolve?: Resolver;
  maxRequests?: number;
  now?: () => number;
  /** The worker's per-process cache and pacer (scm/runtime.ts); fresh ones otherwise. */
  tokens?: InstallationTokenCache;
  pacer?: MutationPacer;
}

/**
 * github.md §5.3: whether a 403 or 429 is a rate limit, and when to try again (`null`: the
 * backoff). `Retry-After` wins, then an exhausted primary limit's reset, then a secondary limit
 * named only in the message (60 s); a 429 is always a rate limit; any other 403 is not.
 */
export function githubRateLimit(
  status: number,
  headers: IncomingHttpHeaders,
  message: string | null,
  nowMs: number = Date.now(),
): { retryAfterSeconds: number | null } | null {
  if (status !== 403 && status !== 429) return null;
  const clamp = (s: number) => Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(s)));
  const retryAfter = headers['retry-after'];
  if (typeof retryAfter === 'string' && /^\d{1,9}$/.test(retryAfter.trim())) {
    return { retryAfterSeconds: clamp(Number(retryAfter)) };
  }
  if (headers['x-ratelimit-remaining'] === '0') {
    const reset = headers['x-ratelimit-reset'];
    return {
      retryAfterSeconds:
        typeof reset === 'string' && /^\d{1,12}$/.test(reset)
          ? clamp(Number(reset) - nowMs / 1000)
          : null,
    };
  }
  if (message !== null && /secondary rate limit/i.test(message)) {
    return { retryAfterSeconds: SECONDARY_LIMIT_SECONDS };
  }
  return status === 429 ? { retryAfterSeconds: null } : null;
}

/** Longer than any `Link` header GitHub sends (at most four relations of one URL each). */
const MAX_LINK_HEADER_CHARS = 4_096;

/**
 * Whether a `Link` header has a `rel="next"` entry; null when it is too long to read, which the
 * caller must not take for the last page. Its URL is never used (github.md §5.3).
 */
export function hasNextPage(link: string | string[] | undefined): boolean | null {
  if (typeof link !== 'string') return false;
  if (link.length > MAX_LINK_HEADER_CHARS) return null;
  return link.split(',').some((part) => /;\s*rel="?next"?\s*$/.test(part.trim()));
}

/** GitHub's `message`, for decisions only, with every credential cut out should it echo one. */
function githubMessage(body: Buffer, secrets: readonly string[]): string | null {
  try {
    const parsed = errorBody.safeParse(JSON.parse(body.toString('utf8')));
    if (!parsed.success || typeof parsed.data.message !== 'string') return null;
    let text = parsed.data.message;
    for (const secret of secrets) if (secret !== '') text = text.split(secret).join('[secret]');
    return text.slice(0, 1_000);
  } catch {
    return null;
  }
}

function transportError(result: Extract<OutboundResult, { kind: 'failed' }>): ScmError {
  switch (result.cause) {
    case 'not_public':
      return new ScmError('refused', GITHUB_TEXT.notPublic, { reason: 'not_public' });
    case 'refused_address':
      return new ScmError('refused', GITHUB_TEXT.refusedAddress, { reason: 'not_public' });
    case 'unresolved':
      return new ScmError('transient', GITHUB_TEXT.unresolved, { reason: 'unresolved' });
    case 'too_large':
      return new ScmError('bad_answer', GITHUB_TEXT.badAnswer);
    case 'timeout':
    case 'connect_timeout':
      return new ScmError('transient', GITHUB_TEXT.timeout, { reason: 'timeout' });
    default:
      return new ScmError(
        'transient',
        result.code
          ? `GitHub could not be reached (${result.code})`
          : 'GitHub could not be reached',
        { reason: 'unreachable' },
      );
  }
}

type Auth = 'app' | 'installation';
type Method = 'GET' | 'POST' | 'PATCH';

/**
 * The GitHub REST API (github.md §4–§6), through {@link outboundRequest}: the connection's base
 * URL only, no redirect, 10 s per request, bounded answers, pages built by number, a budget of
 * {@link MAX_GITHUB_REQUESTS} per client (one client per job), mutations paced per installation.
 * The private key, the JWT and the installation token live in `#private` fields; no error, return
 * value or log line carries them.
 */
export class GitHubClient {
  private requestCount = 0;
  private readonly maxRequests: number;
  private readonly now: () => number;
  private readonly tokens: InstallationTokenCache;
  private readonly pacer: MutationPacer;
  readonly #connection: GitHubConnectionInput;
  #token: string | null = null;
  #jwt: string | null = null;
  #tokenKey: string | null = null;
  #installationId: number | null = null;
  #repo: GitHubRepoRef | null = null;
  #refreshed = false;

  constructor(
    connection: GitHubConnectionInput,
    private readonly options: GitHubClientOptions = {},
  ) {
    if (!isGitHubAppId(connection.appId)) {
      throw new ScmError('refused', GITHUB_TEXT.appId, { reason: 'invalid_input' });
    }
    this.#connection = connection;
    this.maxRequests = options.maxRequests ?? MAX_GITHUB_REQUESTS;
    this.now = options.now ?? Date.now;
    this.tokens = options.tokens ?? new InstallationTokenCache(this.now);
    this.pacer = options.pacer ?? new MutationPacer(this.now);
  }

  get requests(): number {
    return this.requestCount;
  }

  toJSON(): { baseUrl: string; requests: number } {
    return { baseUrl: this.#connection.baseUrl, requests: this.requestCount };
  }

  private invalid(text: string): ScmError {
    return new ScmError('refused', text, { reason: 'invalid_input' });
  }

  private repoPath(): string {
    if (!this.#repo) throw new Error('useRepository first');
    return `/repos/${encodeURIComponent(this.#repo.owner)}/${encodeURIComponent(this.#repo.repo)}`;
  }

  private number(value: string): string {
    if (!GITHUB_PR_NUMBER.test(value)) throw this.invalid(GITHUB_TEXT.prNumber);
    return value;
  }

  private sha(value: string): string {
    if (!SHA.test(value)) throw this.invalid(GITHUB_TEXT.revision);
    return value;
  }

  private parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new ScmError('bad_answer', GITHUB_TEXT.badAnswer);
    return parsed.data;
  }

  private async call(
    method: Method,
    path: string,
    auth: Auth,
    body?: unknown,
  ): Promise<{ headers: IncomingHttpHeaders; json: unknown }> {
    if (this.requestCount >= this.maxRequests) {
      throw new ScmError('budget', GITHUB_TEXT.budget, { reason: 'budget' });
    }
    this.requestCount += 1;
    const credential =
      auth === 'app'
        ? appJwt(this.#connection.appId, this.#connection.privateKey, Math.floor(this.now() / 1000))
        : this.#token;
    if (credential === null) throw new Error('no installation token');
    if (auth === 'app') this.#jwt = credential;
    if (method !== 'GET') {
      await this.pacer.wait(`${this.#connection.baseUrl}|${this.#installationId ?? 'app'}`);
    }
    const result = await outboundRequest(
      {
        url: `${this.#connection.baseUrl}${path}`,
        method,
        headers: {
          authorization: `Bearer ${credential}`,
          accept: 'application/vnd.github+json',
          'x-github-api-version': GITHUB_API_VERSION,
          'user-agent': `Qualor/${VERSION}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      {
        allowInternalHosts: this.#connection.allowInternalHosts,
        refuseAddress: scmRefusedAddress(new URL(this.#connection.baseUrl)),
        timeoutMs: this.options.timeoutMs ?? GITHUB_TIMEOUT_MS,
        ...(this.options.connectTimeoutMs === undefined
          ? {}
          : { connectTimeoutMs: this.options.connectTimeoutMs }),
        ...(this.options.resolve ? { resolve: this.options.resolve } : {}),
        maxResponseBytes: MAX_GITHUB_RESPONSE_BYTES,
        overflow: 'fail',
        names: { noun: 'GitHub', target: 'GitHub' },
      },
    );
    if (result.kind === 'failed') throw transportError(result);
    const { status, headers } = result;
    if (status >= 200 && status < 300) {
      if (result.body.length === 0) return { headers, json: null };
      try {
        return { headers, json: JSON.parse(result.body.toString('utf8')) };
      } catch {
        throw new ScmError('bad_answer', GITHUB_TEXT.badAnswer, { status });
      }
    }
    const message = githubMessage(result.body, [credential, this.#token ?? '', this.#jwt ?? '']);
    if (status >= 300 && status < 400) {
      throw new ScmError('not_found', GITHUB_TEXT.notFound, { status, reason: 'http' });
    }
    const limit = githubRateLimit(status, headers, message, this.now());
    if (limit) {
      throw new ScmError('rate_limited', `GitHub answered HTTP ${status}`, {
        status,
        reason: 'http',
        retryAfterSeconds: limit.retryAfterSeconds,
        providerMessage: message,
      });
    }
    if (status === 401) {
      throw new ScmError(
        'auth',
        auth === 'app' ? GITHUB_TEXT.appRefused : GITHUB_TEXT.tokenRefused,
        {
          status,
          reason: 'http',
        },
      );
    }
    if (status === 403) {
      throw new ScmError('auth', GITHUB_TEXT.permission, { status, reason: 'permission_missing' });
    }
    if (status === 404) {
      throw new ScmError('not_found', GITHUB_TEXT.notFound, {
        status,
        reason: 'http',
        providerMessage: message,
      });
    }
    throw new ScmError(status >= 500 ? 'transient' : 'refused', `GitHub answered HTTP ${status}`, {
      status,
      reason: 'http',
      providerMessage: message,
    });
  }

  /** A repository call; after a 401, one fresh installation token and one more try (§4). */
  private async repoCall(
    method: Method,
    path: string,
    body?: unknown,
  ): Promise<{ headers: IncomingHttpHeaders; json: unknown }> {
    try {
      return await this.call(method, path, 'installation', body);
    } catch (err) {
      if (!(err instanceof ScmError) || err.status !== 401 || this.#refreshed) throw err;
      this.#refreshed = true;
      if (this.#tokenKey !== null) this.tokens.drop(this.#tokenKey);
      await this.issueToken();
      return this.call(method, path, 'installation', body);
    }
  }

  private async pages<T>(path: string, schema: z.ZodType<T>, maxPages: number): Promise<Paged<T>> {
    const items: T[] = [];
    for (let page = 1; page <= maxPages; page++) {
      const separator = path.includes('?') ? '&' : '?';
      const { headers, json } = await this.repoCall(
        'GET',
        `${path}${separator}per_page=${GITHUB_PAGE_SIZE}&page=${page}`,
      );
      items.push(...this.parse(z.array(schema), json));
      const next = hasNextPage(headers.link);
      // An unreadable Link header is not understood, never "the last page": a list taken as
      // complete would let the caller post a second summary comment (github.md §6.3).
      if (next === null) throw new ScmError('bad_answer', GITHUB_TEXT.badAnswer);
      if (!next) return { items, complete: true };
    }
    return { items, complete: false };
  }

  /** `GET /app` with the JWT: the App's id (checked) and slug (github.md §6.3). */
  async app(): Promise<GitHubApp> {
    const { json } = await this.call('GET', '/app', 'app');
    const found = this.parse(app, json);
    if (String(found.id) !== this.#connection.appId) {
      throw new ScmError('bad_answer', GITHUB_TEXT.badAnswer);
    }
    return found;
  }

  /**
   * github.md §4: the repository's installation (JWT), a token scoped to it (cached), then
   * `GET /repos/{owner}/{repo}`. Every later call of this client is on this repository.
   */
  async useRepository(ref: GitHubRepoRef): Promise<GitHubRepository> {
    // Checked here too, not only where the mapping is saved: no dot segment or slash reaches a path.
    const dotSegment = (part: string) => part === '.' || part === '..';
    if (
      dotSegment(ref.owner) ||
      dotSegment(ref.repo) ||
      !GITHUB_REPO_PATTERN.test(`${ref.owner}/${ref.repo}`)
    ) {
      throw this.invalid(GITHUB_TEXT.repo);
    }
    this.#repo = { owner: ref.owner, repo: ref.repo };
    let found: z.infer<typeof installation>;
    try {
      const { json } = await this.call('GET', `${this.repoPath()}/installation`, 'app');
      found = this.parse(installation, json);
    } catch (err) {
      if (err instanceof ScmError && err.status === 404) {
        throw new ScmError('not_found', GITHUB_TEXT.notInstalled, {
          status: 404,
          reason: 'not_installed',
        });
      }
      throw err;
    }
    if (String(found.app_id) !== this.#connection.appId) {
      throw new ScmError('bad_answer', GITHUB_TEXT.badAnswer);
    }
    this.#installationId = found.id;
    this.#tokenKey = tokenCacheKey({
      connectionId: this.#connection.connectionId,
      credentials: this.#connection.credentials,
      installationId: found.id,
      repo: `${ref.owner}/${ref.repo}`,
    });
    this.#token = this.tokens.get(this.#tokenKey);
    if (this.#token === null) await this.issueToken();
    const { json } = await this.repoCall('GET', this.repoPath());
    return this.parse(repository, json);
  }

  private async issueToken(): Promise<void> {
    if (this.#installationId === null || this.#repo === null || this.#tokenKey === null) {
      throw new Error('useRepository first');
    }
    let json: unknown;
    try {
      ({ json } = await this.call(
        'POST',
        `/app/installations/${this.#installationId}/access_tokens`,
        'app',
        { repositories: [this.#repo.repo], permissions: INSTALLATION_PERMISSIONS },
      ));
    } catch (err) {
      if (
        err instanceof ScmError &&
        err.kind !== 'rate_limited' &&
        (err.status === 422 || err.status === 403)
      ) {
        // 422: a permission or the repository is not granted to the installation; 403: the same,
        // or the installation is suspended (GitHub's message tells them apart; it is never shown).
        throw new ScmError(
          'auth',
          err.status === 403 ? GITHUB_TEXT.permissionOrSuspended : GITHUB_TEXT.permission,
          {
            status: err.status,
            reason: 'permission_missing',
          },
        );
      }
      throw err;
    }
    const issued = this.parse(installationToken, json);
    this.#token = issued.token;
    this.tokens.set(this.#tokenKey, issued.token, Date.parse(issued.expires_at));
  }

  /** Qualor's current check runs of `name` on `sha`: this App's only, the newest per name. */
  async checkRuns(revision: string, name: string): Promise<GitHubCheckRun[]> {
    const path = `${this.repoPath()}/commits/${this.sha(revision)}/check-runs?check_name=${encodeURIComponent(name)}&app_id=${this.#connection.appId}&filter=latest&per_page=${GITHUB_PAGE_SIZE}`;
    const { json } = await this.repoCall('GET', path);
    const appId = Number(this.#connection.appId);
    return this.parse(checkRuns, json).check_runs.filter(
      (r) => r.name === name && r.app?.id === appId,
    );
  }

  private checkRunBody(input: CheckRunUpdate) {
    return {
      status: 'completed',
      conclusion: input.conclusion,
      completed_at: new Date(this.now()).toISOString(),
      external_id: input.externalId,
      ...(input.detailsUrl === null ? {} : { details_url: input.detailsUrl }),
    };
  }

  /** A new check run; `'annotations_rejected'` when GitHub refuses its annotations (a 422). */
  async createCheckRun(input: CheckRunInput): Promise<GitHubCheckRun | 'annotations_rejected'> {
    try {
      const { json } = await this.repoCall('POST', `${this.repoPath()}/check-runs`, {
        name: input.name,
        head_sha: this.sha(input.headSha),
        ...this.checkRunBody(input),
        output: { title: input.title, summary: input.summary, annotations: input.annotations },
      });
      return this.parse(checkRun, json);
    } catch (err) {
      // GitHub answers 422 for an invalid request; with annotations sent, one of them is the
      // likely cause (a path or line it does not accept), so the caller retries without them.
      // Without annotations a 422 is a plain refusal.
      if (err instanceof ScmError && err.status === 422 && input.annotations.length > 0) {
        return 'annotations_rejected';
      }
      throw err;
    }
  }

  /** Updates conclusion and output, never annotations (GitHub appends them on an update). */
  async updateCheckRun(id: number, input: CheckRunUpdate): Promise<GitHubCheckRun> {
    if (!Number.isSafeInteger(id) || id <= 0) throw this.invalid(GITHUB_TEXT.id);
    const { json } = await this.repoCall('PATCH', `${this.repoPath()}/check-runs/${id}`, {
      ...this.checkRunBody(input),
      output: { title: input.title, summary: input.summary },
    });
    return this.parse(checkRun, json);
  }

  async pullRequest(number: string): Promise<GitHubPullRequest> {
    const { json } = await this.repoCall('GET', `${this.repoPath()}/pulls/${this.number(number)}`);
    return this.parse(pullRequest, json);
  }

  pullRequestFiles(number: string, maxPages: number): Promise<Paged<GitHubFile>> {
    return this.pages(`${this.repoPath()}/pulls/${this.number(number)}/files`, file, maxPages);
  }

  issueComments(number: string, maxPages: number): Promise<Paged<GitHubComment>> {
    return this.pages(
      `${this.repoPath()}/issues/${this.number(number)}/comments`,
      comment,
      maxPages,
    );
  }

  async createComment(number: string, body: string): Promise<GitHubComment> {
    const { json } = await this.repoCall(
      'POST',
      `${this.repoPath()}/issues/${this.number(number)}/comments`,
      { body },
    );
    return this.parse(comment, json);
  }

  /** The pull request's review comments (comments on lines of its diff), oldest first. */
  reviewComments(number: string, maxPages: number): Promise<Paged<GitHubReviewComment>> {
    return this.pages(
      `${this.repoPath()}/pulls/${this.number(number)}/comments`,
      reviewComment,
      maxPages,
    );
  }

  /**
   * llm.md §8.4: a review comment on RIGHT-side lines `startLine..line` of `path` at `commitId`
   * (one line without `startLine`); `position_rejected` on a 422 (lines GitHub will not place).
   */
  async createReviewComment(
    number: string,
    input: { body: string; commitId: string; path: string; line: number; startLine?: number },
  ): Promise<GitHubReviewComment | 'position_rejected'> {
    const lineOk = (n: number) => Number.isSafeInteger(n) && n > 0;
    if (
      !lineOk(input.line) ||
      (input.startLine !== undefined && (!lineOk(input.startLine) || input.startLine > input.line))
    ) {
      throw this.invalid(GITHUB_TEXT.line);
    }
    const range =
      input.startLine !== undefined && input.startLine !== input.line
        ? { start_line: input.startLine, start_side: 'RIGHT' }
        : {};
    try {
      const { json } = await this.repoCall(
        'POST',
        `${this.repoPath()}/pulls/${this.number(number)}/comments`,
        {
          body: input.body,
          commit_id: this.sha(input.commitId),
          path: input.path,
          side: 'RIGHT',
          line: input.line,
          ...range,
        },
      );
      return this.parse(reviewComment, json);
    } catch (err) {
      if (err instanceof ScmError && err.kind === 'refused' && err.status === 422) {
        return 'position_rejected';
      }
      throw err;
    }
  }

  async updateComment(id: number, body: string): Promise<GitHubComment> {
    if (!Number.isSafeInteger(id) || id <= 0) throw this.invalid(GITHUB_TEXT.id);
    const { json } = await this.repoCall('PATCH', `${this.repoPath()}/issues/comments/${id}`, {
      body,
    });
    return this.parse(comment, json);
  }
}
