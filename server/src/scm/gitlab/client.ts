import type { IncomingHttpHeaders } from 'node:http';
import { z } from 'zod';
import { outboundRequest, type Resolver } from '../../http/outbound';
import { VERSION } from '../../index';
import { ScmError, type Paged, type ScmErrorKind, type ScmErrorReason } from '../provider';
import { scmRefusedAddress } from '../url';

/** scm.md §4.3: every request has 10 s in all ... */
export const GITLAB_TIMEOUT_MS = 10_000;
/** ... answers over 8 MiB are refused ... */
export const MAX_GITLAB_RESPONSE_BYTES = 8 * 1024 * 1024;
/** ... pages hold 100 items ... */
export const GITLAB_PAGE_SIZE = 100;
/** ... and one job makes at most this many requests. */
export const MAX_GITLAB_REQUESTS = 400;
/** A `Retry-After` (or `RateLimit-Reset`) is clamped to 1 s – 15 min. */
export const MAX_RETRY_AFTER_SECONDS = 15 * 60;
/**
 * What a 403 means per request: the token is valid (that is a 401), but its user may not do this.
 * A commit status on a protected branch needs the Maintainer role; a Developer may post one only
 * on an unprotected branch, such as a merge request's source branch.
 */
export const GITLAB_FORBIDDEN = {
  request:
    'The GitLab token lacks the permission for this request (HTTP 403); it needs the api scope and the Maintainer role',
  commitStatus:
    'The GitLab token lacks the permission to set the commit status (HTTP 403); a commit status on a protected branch needs the Maintainer role',
  deleteNote:
    "The GitLab token lacks the permission to delete another user's note (HTTP 403); that needs the Maintainer role",
} as const;

export type GitLabErrorKind = ScmErrorKind;
export type GitLabErrorReason = ScmErrorReason;
export type { Paged };

/** A failed GitLab request (scm.md §4.3–§4.4); see {@link ScmError}. */
export class GitLabError extends ScmError {
  constructor(
    kind: GitLabErrorKind,
    message: string,
    options: {
      status?: number | null;
      retryAfterSeconds?: number | null;
      gitlabMessage?: string | null;
      reason?: GitLabErrorReason;
    } = {},
  ) {
    const { gitlabMessage, ...rest } = options;
    super(kind, message, { ...rest, providerMessage: gitlabMessage ?? null });
    this.name = 'GitLabError';
  }

  /** GitLab's own `message` (decisions only). */
  get gitlabMessage(): string | null {
    return this.providerMessage;
  }
}

// ─── Response shapes (the fields Qualor reads; server/test/gitlab-shapes/ holds recorded ones) ──

const user = z.looseObject({ id: z.number().int(), username: z.string() });
export type GitLabUser = z.infer<typeof user>;

const access = z.looseObject({ access_level: z.number().int() }).nullable().optional();
const project = z.looseObject({
  id: z.number().int(),
  path_with_namespace: z.string(),
  web_url: z.string(),
  /** The token user's own access (a member of the project, or of its group); absent for some. */
  permissions: z
    .looseObject({ project_access: access, group_access: access })
    .nullable()
    .optional(),
});
export type GitLabProject = z.infer<typeof project>;

/**
 * The token user's access level in the project (the higher of its project and group membership),
 * or null when GitLab does not say (an administrator's token, an inherited membership it omits).
 */
export function accessLevelOf(p: GitLabProject): number | null {
  const levels = [p.permissions?.project_access, p.permissions?.group_access]
    .map((a) => a?.access_level)
    .filter((level): level is number => typeof level === 'number');
  return levels.length === 0 ? null : Math.max(...levels);
}

const sha = z.string().regex(/^[0-9a-f]{40,64}$/);
const mergeRequest = z.looseObject({
  id: z.number().int(),
  iid: z.number().int(),
  project_id: z.number().int(),
  title: z.string(),
  state: z.string(),
  web_url: z.string(),
  source_branch: z.string(),
  target_branch: z.string(),
  sha: sha.nullable(),
  diff_refs: z
    .looseObject({ base_sha: sha.nullable(), head_sha: sha.nullable(), start_sha: sha.nullable() })
    .nullable(),
});
export type GitLabMergeRequest = z.infer<typeof mergeRequest>;

const diff = z.looseObject({
  old_path: z.string(),
  new_path: z.string(),
  diff: z.string(),
  new_file: z.boolean(),
  renamed_file: z.boolean(),
  deleted_file: z.boolean(),
});
export type GitLabDiff = z.infer<typeof diff>;

const note = z.looseObject({
  id: z.number().int(),
  body: z.string(),
  author: z.looseObject({ id: z.number().int() }),
  system: z.boolean(),
  resolvable: z.boolean().optional(),
  resolved: z.boolean().optional(),
  /** Who resolved it (scm.md §5.4: Qualor reopens only threads it resolved itself). */
  resolved_by: z.looseObject({ id: z.number().int() }).nullable().optional(),
});
export type GitLabNote = z.infer<typeof note>;

const discussion = z.looseObject({
  id: z.string(),
  individual_note: z.boolean(),
  notes: z.array(note),
});
export type GitLabDiscussion = z.infer<typeof discussion>;

const commitStatus = z.looseObject({
  id: z.number().int(),
  sha,
  status: z.string(),
  name: z.string(),
  description: z.string().nullable().optional(),
  target_url: z.string().nullable().optional(),
  ref: z.string().nullable().optional(),
  pipeline_id: z.number().int().nullable().optional(),
});
export type GitLabCommitStatus = z.infer<typeof commitStatus>;

const errorBody = z.looseObject({ message: z.unknown().optional(), error: z.unknown().optional() });

/**
 * GitLab's 400 for a diff position it cannot place: `Note {:line_code=>["can't be blank", "must be
 * a valid line code"]}`, or a message about the `position` itself.
 */
const POSITION_REJECTED = /line_code|line code|position/i;

/** Every recorded shape the client parses, for the shape tests (server/test/gitlab-shapes/). */
export const GITLAB_SHAPES = {
  user,
  project,
  mergeRequest,
  diffs: z.array(diff),
  note,
  discussions: z.array(discussion),
  discussion,
  commitStatus,
  commitStatuses: z.array(commitStatus),
} as const;

/** scm.md §4.2–§4.3: a GitLab merge request IID, 1–10 digits (the only form sent in a path). */
export const GITLAB_MR_IID = /^[0-9]{1,10}$/;

export type CommitState = 'pending' | 'running' | 'success' | 'failed' | 'canceled' | 'skipped';

export interface CommitStatusInput {
  state: CommitState;
  name: string;
  description: string;
  targetUrl: string | null;
  pipelineId: string | null;
  /**
   * The branch the status is for (a merge request's source branch), sent only without a pipeline:
   * GitLab takes a pipeline's own ref from it, and a ref that is not the pipeline's would make it
   * look for another pipeline. A merge-result commit is on no branch, so without a pipeline GitLab
   * needs the ref to place the status.
   */
  ref: string | null;
  /**
   * When the post with `pipelineId` is refused (400/404) and would be sent again without it: true
   * when the status without a pipeline already says this (the caller read it), so nothing is
   * posted again. GitLab attaches a status without a pipeline to another pipeline, so a rerun
   * never finds it on `pipelineId`, and without this each rerun would add a row.
   */
  unchangedWithoutPipeline?: boolean;
}

export interface DiffPosition {
  baseSha: string;
  startSha: string;
  headSha: string;
  oldPath: string;
  newPath: string;
  newLine: number;
}

export interface GitLabConnectionInput {
  /** Normalised, without a trailing slash (scm/url.ts). */
  baseUrl: string;
  token: string;
  /** The host is in `QUALOR_SCM_INTERNAL_HOSTS` (scm.md §2.1). */
  allowInternalHosts: boolean;
}

export interface GitLabClientOptions {
  timeoutMs?: number;
  connectTimeoutMs?: number;
  resolve?: Resolver;
  maxRequests?: number;
}

/** Seconds from `Retry-After` (seconds or an HTTP date), else `RateLimit-Reset` (epoch seconds). */
export function retryAfterSeconds(headers: IncomingHttpHeaders, nowMs = Date.now()): number | null {
  const clamp = (s: number) => Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(s)));
  const retryAfter = headers['retry-after'];
  if (typeof retryAfter === 'string' && retryAfter.trim() !== '') {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return clamp(seconds);
    const date = Date.parse(retryAfter);
    if (!Number.isNaN(date)) return clamp((date - nowMs) / 1000);
  }
  const reset = headers['ratelimit-reset'];
  if (typeof reset === 'string' && /^\d{1,12}$/.test(reset)) {
    return clamp(Number(reset) - nowMs / 1000);
  }
  return null;
}

/**
 * GitLab's `message` (a string, or an object of field errors) as text, for decisions only, with
 * the token cut out should GitLab ever echo it.
 */
function gitlabMessage(body: Buffer, token: string): string | null {
  try {
    const parsed = errorBody.safeParse(JSON.parse(body.toString('utf8')));
    if (!parsed.success) return null;
    const value = parsed.data.message ?? parsed.data.error;
    if (value === undefined) return null;
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.split(token).join('[token]').slice(0, 1_000);
  } catch {
    return null;
  }
}

/**
 * GitLab REST v4 (scm.md §4.3), through {@link outboundRequest}: the connection's base URL only,
 * the SSRF rules of ruling W3 unless the host is listed in `QUALOR_SCM_INTERNAL_HOSTS`, 10 s per
 * request, bounded answers, bounded pages and a request budget per client (one client per job).
 * The token goes only into `PRIVATE-TOKEN`; no error, return value or log line carries it.
 */
export class GitLabClient {
  private requestCount = 0;
  private readonly maxRequests: number;
  /** A true private field: the token is not an own enumerable property a logger could print. */
  readonly #connection: GitLabConnectionInput;

  constructor(
    connection: GitLabConnectionInput,
    private readonly options: GitLabClientOptions = {},
  ) {
    this.#connection = connection;
    this.maxRequests = options.maxRequests ?? MAX_GITLAB_REQUESTS;
  }

  /** Requests made so far. */
  get requests(): number {
    return this.requestCount;
  }

  private projectPath(ref: string): string {
    return `/projects/${encodeURIComponent(ref)}`;
  }

  /** `/projects/:ref/merge_requests/:iid`; an iid is 1–10 digits, checked here, not by callers. */
  private mergeRequestPath(ref: string, iid: string): string {
    if (!GITLAB_MR_IID.test(iid)) {
      throw new GitLabError('refused', 'The merge request id is not a GitLab merge request IID', {
        reason: 'invalid_input',
      });
    }
    return `${this.projectPath(ref)}/merge_requests/${iid}`;
  }

  /** `forbidden` is the text of a 403 ({@link GITLAB_FORBIDDEN}), which says what was refused. */
  private async call(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown,
    forbidden: string = GITLAB_FORBIDDEN.request,
  ): Promise<{ status: number; headers: IncomingHttpHeaders; json: unknown }> {
    if (this.requestCount >= this.maxRequests) {
      throw new GitLabError('budget', `More than ${this.maxRequests} GitLab requests in one job`);
    }
    this.requestCount += 1;
    const result = await outboundRequest(
      {
        url: `${this.#connection.baseUrl}/api/v4${path}`,
        method,
        headers: {
          'private-token': this.#connection.token,
          accept: 'application/json',
          'user-agent': `Qualor/${VERSION}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      {
        allowInternalHosts: this.#connection.allowInternalHosts,
        refuseAddress: scmRefusedAddress(new URL(this.#connection.baseUrl)),
        timeoutMs: this.options.timeoutMs ?? GITLAB_TIMEOUT_MS,
        ...(this.options.connectTimeoutMs === undefined
          ? {}
          : { connectTimeoutMs: this.options.connectTimeoutMs }),
        ...(this.options.resolve ? { resolve: this.options.resolve } : {}),
        maxResponseBytes: MAX_GITLAB_RESPONSE_BYTES,
        overflow: 'fail',
        names: { noun: 'GitLab', target: 'GitLab' },
      },
    );
    if (result.kind === 'failed') {
      switch (result.cause) {
        case 'not_public':
          throw new GitLabError(
            'refused',
            'The GitLab host resolves to a private, loopback or otherwise non-public address; list it in QUALOR_SCM_INTERNAL_HOSTS',
            { reason: 'not_public' },
          );
        case 'refused_address':
          throw new GitLabError(
            'refused',
            'The GitLab host resolves to a link-local, cloud metadata or loopback address',
            { reason: 'not_public' },
          );
        case 'unresolved':
          throw new GitLabError('transient', 'The GitLab host could not be resolved', {
            reason: 'unresolved',
          });
        case 'too_large':
          throw new GitLabError('bad_answer', "GitLab's answer was not understood");
        case 'timeout':
        case 'connect_timeout':
          throw new GitLabError('transient', 'GitLab did not answer within 10 s', {
            reason: 'timeout',
          });
        default:
          throw new GitLabError(
            'transient',
            result.code
              ? `GitLab could not be reached (${result.code})`
              : 'GitLab could not be reached',
            { reason: 'unreachable' },
          );
      }
    }
    const { status, headers } = result;
    if (status >= 200 && status < 300) {
      if (result.body.length === 0) return { status, headers, json: null };
      try {
        return { status, headers, json: JSON.parse(result.body.toString('utf8')) };
      } catch {
        throw new GitLabError('bad_answer', "GitLab's answer was not understood", { status });
      }
    }
    const message = gitlabMessage(result.body, this.#connection.token);
    if (status === 429) {
      throw new GitLabError('rate_limited', 'GitLab answered HTTP 429', {
        reason: 'http',
        status,
        retryAfterSeconds: retryAfterSeconds(headers),
        gitlabMessage: message,
      });
    }
    if (status === 401) {
      throw new GitLabError('auth', 'GitLab refused the token (HTTP 401)', {
        status,
        reason: 'http',
      });
    }
    if (status === 403) {
      throw new GitLabError('auth', forbidden, {
        status,
        reason: 'permission_missing',
        gitlabMessage: message,
      });
    }
    if (status === 404) {
      throw new GitLabError(
        'not_found',
        'The GitLab project was not found, or the token cannot see it',
        { status, gitlabMessage: message, reason: 'http' },
      );
    }
    throw new GitLabError(
      status >= 500 ? 'transient' : 'refused',
      `GitLab answered HTTP ${status}`,
      { status, gitlabMessage: message, reason: 'http' },
    );
  }

  private parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new GitLabError('bad_answer', "GitLab's answer was not understood");
    return parsed.data;
  }

  private async pages<T>(path: string, schema: z.ZodType<T>, maxPages: number): Promise<Paged<T>> {
    const items: T[] = [];
    let page = 1;
    for (let n = 0; n < maxPages; n++) {
      const separator = path.includes('?') ? '&' : '?';
      const { headers, json } = await this.call(
        'GET',
        `${path}${separator}per_page=${GITLAB_PAGE_SIZE}&page=${page}`,
      );
      items.push(...this.parse(z.array(schema), json));
      const next = headers['x-next-page'];
      if (typeof next !== 'string' || !/^\d{1,9}$/.test(next)) return { items, complete: true };
      const nextPage = Number(next);
      if (nextPage <= page) return { items, complete: true };
      page = nextPage;
    }
    return { items, complete: false };
  }

  currentUser(): Promise<GitLabUser> {
    return this.call('GET', '/user').then(({ json }) => this.parse(user, json));
  }

  project(ref: string): Promise<GitLabProject> {
    return this.call('GET', this.projectPath(ref)).then(({ json }) => this.parse(project, json));
  }

  async mergeRequest(ref: string, iid: string): Promise<GitLabMergeRequest> {
    const { json } = await this.call('GET', this.mergeRequestPath(ref, iid));
    return this.parse(mergeRequest, json);
  }

  async mergeRequestDiffs(ref: string, iid: string, maxPages: number): Promise<Paged<GitLabDiff>> {
    return this.pages(`${this.mergeRequestPath(ref, iid)}/diffs`, diff, maxPages);
  }

  async discussions(ref: string, iid: string, maxPages: number): Promise<Paged<GitLabDiscussion>> {
    return this.pages(`${this.mergeRequestPath(ref, iid)}/discussions`, discussion, maxPages);
  }

  async createNote(ref: string, iid: string, body: string): Promise<GitLabNote> {
    const { json } = await this.call('POST', `${this.mergeRequestPath(ref, iid)}/notes`, { body });
    return this.parse(note, json);
  }

  async updateNote(ref: string, iid: string, noteId: number, body: string): Promise<GitLabNote> {
    if (!Number.isSafeInteger(noteId) || noteId < 1) {
      throw new GitLabError('refused', 'The note id is not a GitLab note id', {
        reason: 'invalid_input',
      });
    }
    const { json } = await this.call('PUT', `${this.mergeRequestPath(ref, iid)}/notes/${noteId}`, {
      body,
    });
    return this.parse(note, json);
  }

  /**
   * Deletes a note of the merge request (`DELETE …/notes/:id`, 204). GitLab lets the note's author
   * delete it, and a Maintainer any note.
   */
  async deleteNote(ref: string, iid: string, noteId: number): Promise<void> {
    if (!Number.isSafeInteger(noteId) || noteId < 1) {
      throw new GitLabError('refused', 'The note id is not a GitLab note id', {
        reason: 'invalid_input',
      });
    }
    await this.call(
      'DELETE',
      `${this.mergeRequestPath(ref, iid)}/notes/${noteId}`,
      undefined,
      GITLAB_FORBIDDEN.deleteNote,
    );
  }

  /**
   * A diff discussion, or `position_rejected` when GitLab refuses the position: only a 400 whose
   * message is about the position or its line code (scm.md §5.4); any other 400 is an error.
   */
  async createDiscussion(
    ref: string,
    iid: string,
    body: string,
    position: DiffPosition,
  ): Promise<GitLabDiscussion | 'position_rejected'> {
    try {
      const { json } = await this.call('POST', `${this.mergeRequestPath(ref, iid)}/discussions`, {
        body,
        position: {
          position_type: 'text',
          base_sha: position.baseSha,
          start_sha: position.startSha,
          head_sha: position.headSha,
          old_path: position.oldPath,
          new_path: position.newPath,
          new_line: position.newLine,
        },
      });
      return this.parse(discussion, json);
    } catch (err) {
      if (
        err instanceof GitLabError &&
        err.status === 400 &&
        POSITION_REJECTED.test(err.gitlabMessage ?? '')
      ) {
        return 'position_rejected';
      }
      throw err;
    }
  }

  async resolveDiscussion(
    ref: string,
    iid: string,
    discussionId: string,
    resolved: boolean,
  ): Promise<void> {
    await this.call(
      'PUT',
      `${this.mergeRequestPath(ref, iid)}/discussions/${encodeURIComponent(discussionId)}?resolved=${resolved}`,
    );
  }

  private checkRevision(revision: string): void {
    if (!/^[0-9a-f]{40,64}$/.test(revision)) {
      throw new GitLabError('refused', 'The revision is not a full commit SHA', {
        reason: 'invalid_input',
      });
    }
  }

  /**
   * The latest statuses named `name` of a commit (`GET …/repository/commits/:sha/statuses`,
   * `all=false`: not those a newer status of the same name and pipeline replaced); one page.
   */
  async commitStatuses(ref: string, revision: string, name: string): Promise<GitLabCommitStatus[]> {
    this.checkRevision(revision);
    const query = new URLSearchParams({ name, all: 'false' });
    const listed = await this.pages(
      `${this.projectPath(ref)}/repository/commits/${revision}/statuses?${query.toString()}`,
      commitStatus,
      1,
    );
    return listed.items;
  }

  /**
   * `POST /projects/:ref/statuses/:sha` (scm.md §5.1). GitLab reuses only a pending or running
   * status of the same name: a final state posted again adds a row, so callers read
   * {@link commitStatuses} first to post only a change. A 400 "Cannot transition status" means a
   * pending or running status already has this state (`unchanged`); a 400 or 404 caused by
   * `pipeline_id` (another pipeline, or one GitLab no longer has) is retried once without it (and
   * with the ref).
   */
  async setCommitStatus(
    ref: string,
    revision: string,
    input: CommitStatusInput,
  ): Promise<'set' | 'unchanged'> {
    this.checkRevision(revision);
    const post = async (pipelineId: string | null): Promise<'set' | 'unchanged'> => {
      try {
        const { json } = await this.call(
          'POST',
          `${this.projectPath(ref)}/statuses/${revision}`,
          {
            state: input.state,
            name: input.name,
            description: input.description,
            ...(input.targetUrl === null ? {} : { target_url: input.targetUrl }),
            ...(pipelineId === null ? {} : { pipeline_id: Number(pipelineId) }),
            ...(pipelineId === null && input.ref !== null ? { ref: input.ref } : {}),
          },
          GITLAB_FORBIDDEN.commitStatus,
        );
        this.parse(commitStatus, json);
        return 'set';
      } catch (err) {
        if (
          err instanceof GitLabError &&
          err.status === 400 &&
          /^Cannot transition status/.test(err.gitlabMessage ?? '')
        ) {
          return 'unchanged';
        }
        throw err;
      }
    };
    if (input.pipelineId === null) return post(null);
    try {
      return await post(input.pipelineId);
    } catch (err) {
      if (err instanceof GitLabError && (err.status === 400 || err.status === 404)) {
        return input.unchangedWithoutPipeline === true ? 'unchanged' : post(null);
      }
      throw err;
    }
  }
}
