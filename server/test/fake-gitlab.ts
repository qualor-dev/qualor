import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * A local fake of the GitLab REST v4 endpoints Qualor uses (scm.md §4, §11), for tests: nothing
 * in `pnpm test` contacts a real GitLab. Answers are built from the recorded shapes in
 * `gitlab-shapes/` (GitLab 18 REST v4 answers, the fields Qualor reads plus the usual rest), with
 * the fake's own ids and values laid over them. It checks what a real GitLab checks where Qualor
 * depends on it: the `PRIVATE-TOKEN`, a diff position on an added line of the merge request's
 * current diff, commit statuses as GitLab keeps them (only a pending or running status of the same
 * name, ref and pipeline is reused, where the same state again is a 400 "Cannot transition status";
 * a final state posted again is a new row, and the row it replaces is `retried`), edits only of
 * the token's own notes, deletes of other users' notes only for a Maintainer (the token's access
 * level, which `GET /projects/:id` reports in `permissions`), and pagination with `x-next-page`. A resolved note carries `resolved_by`
 * (the token's user, or whoever `resolveAs` names), as GitLab's discussions API returns it.
 *
 * Where each shape comes from. They were written from GitLab's REST v4 API documentation (the
 * example answers of the pages below, GitLab 18.x/19.x) with Qualor's example values, not captured
 * from a live instance; the opt-in checks (`pnpm gitlab:real`) compare their fields with real
 * answers, and found none missing on GitLab CE 19.3.3 (Docker) and CE 18.11.11 (a running
 * instance, 2026-09-25). The behaviours modelled here were confirmed there too (scm.md §11): a
 * final status posted again is a new row (201) with `all=false` listing only the newest, status
 * entries carry `pipeline_id`, a status with `ref` and no pipeline is accepted, note bodies come
 * back as sent, a reply in a resolved thread is created resolved by its author, and a position
 * outside the diff is the 400 `line_code` answer below. Fields Qualor reads are what `GITLAB_SHAPES` in
 * `src/scm/gitlab/client.ts` parses; the rest is kept so the fake answers like GitLab does.
 * - `user.json`: `GET /user` (doc/api/users.md, "Get the current user"; a project access token's
 *   bot user: `bot: true`, `project_<id>_bot_<suffix>` user name).
 * - `project.json`: `GET /projects/:id` (doc/api/projects.md, "Get a single project"; trimmed).
 * - `merge_request.json`: `GET /projects/:id/merge_requests/:iid` (doc/api/merge_requests.md,
 *   "Get single MR"; `diff_refs` as that page documents it).
 * - `merge_request_diffs.json`: `GET /projects/:id/merge_requests/:iid/diffs`
 *   (doc/api/merge_requests.md, "List merge request diffs", GitLab 15.7+).
 * - `note.json`: `POST /projects/:id/merge_requests/:iid/notes` (doc/api/notes.md, "Create new
 *   merge request note").
 * - `discussion.json`, `discussions.json`: `POST` and `GET /projects/:id/merge_requests/:iid/
 *   discussions` (doc/api/discussions.md, "Create new merge request thread", "List project merge
 *   request discussion items"; a `DiffNote` with a `text` position).
 * - `commit_status.json`: `POST /projects/:id/statuses/:sha` (doc/api/commits.md, "Set the
 *   pipeline status of a commit").
 * - `commit_statuses.json`: `GET /projects/:id/repository/commits/:sha/statuses`
 *   (doc/api/commits.md, "List the statuses of a commit"; the same entity as the POST answer).
 * Error answers (`{ message }` / `{ error }` bodies, the 400 "Cannot transition status via …" and
 * the 400 on a diff position without a line code) follow the texts GitLab's API returns for them.
 */

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'gitlab-shapes');

/** A recorded GitLab answer (`gitlab-shapes/<name>.json`). */
export function gitlabShape<T = Record<string, unknown>>(name: string): T {
  return JSON.parse(readFileSync(path.join(SHAPES, `${name}.json`), 'utf8')) as T;
}

export interface FakeDiff {
  oldPath: string;
  newPath: string;
  /** A unified diff (hunks only), as GitLab's `diff` field holds it. */
  diff: string;
  newFile?: boolean;
  renamedFile?: boolean;
  deletedFile?: boolean;
}

export interface FakeMergeRequest {
  iid: number;
  title: string;
  state: 'opened' | 'closed' | 'merged';
  sourceBranch: string;
  targetBranch: string;
  headSha: string;
  baseSha: string;
  startSha: string;
  diffs: FakeDiff[];
}

export interface FakeNote {
  id: number;
  body: string;
  authorId: number;
  resolvable: boolean;
  resolved: boolean;
  /** Who resolved the note (GitLab's `resolved_by`); unset or null while it is open. */
  resolvedBy?: number | null;
  position: Record<string, unknown> | null;
}

export interface FakeDiscussion {
  id: string;
  individualNote: boolean;
  notes: FakeNote[];
}

export interface FakeStatus {
  projectId: number;
  sha: string;
  name: string;
  state: string;
  description: string | null;
  targetUrl: string | null;
  pipelineId: number | null;
  /** The `ref` sent, else the pipeline's ref. */
  ref: string | null;
}

export interface RecordedRequest {
  method: string;
  /** The path under `/api/v4`, still percent-encoded, without the query. */
  path: string;
  query: string;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface InjectedAnswer {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
  /** Never answer (the client's deadline must fire). */
  hang?: boolean;
  /** Runs before the answer (a test's change in the middle of a job). */
  before?: () => Promise<void>;
  /** After `before`, answer as the fake normally would (`status` is then ignored). */
  passThrough?: boolean;
}

interface Injection {
  method: string;
  path: RegExp;
  answers: InjectedAnswer[];
}

interface FakeProject {
  id: number;
  path: string;
  mergeRequests: Map<number, FakeMergeRequest>;
  discussions: Map<number, FakeDiscussion[]>;
  /** Pipeline id -> its ref. */
  pipelines: Map<number, string>;
}

export interface FakeGitLab {
  /** The base URL (no trailing slash), as a connection stores it. */
  readonly url: string;
  readonly token: string;
  readonly botUserId: number;
  /** The token user's access level in every project (30 Developer, the default; 40 Maintainer). */
  accessLevel: number;
  readonly requests: RecordedRequest[];
  readonly statuses: FakeStatus[];
  addProject(project: { id: number; path: string }): void;
  addMergeRequest(projectId: number, mr: FakeMergeRequest): void;
  updateMergeRequest(projectId: number, iid: number, changes: Partial<FakeMergeRequest>): void;
  /** A pipeline of the project, on `ref` (default `main`). */
  addPipeline(projectId: number, pipelineId: number, ref?: string): void;
  /** Adds a note by another user (or the bot), as a discussion of its own. */
  addNote(projectId: number, iid: number, note: { body: string; authorId: number }): FakeDiscussion;
  discussions(projectId: number, iid: number): FakeDiscussion[];
  /** A reply in an existing discussion, as another GitLab user (or the bot) would post it. */
  reply(
    projectId: number,
    iid: number,
    discussionId: string,
    note: { body: string; authorId: number },
  ): FakeNote;
  /** Resolves (or reopens) a discussion as another GitLab user would in the UI. */
  resolveAs(
    projectId: number,
    iid: number,
    discussionId: string,
    userId: number,
    resolved: boolean,
  ): void;
  /** The next matching requests get these answers, in order, before the fake answers normally. */
  inject(method: string, path: RegExp, ...answers: InjectedAnswer[]): void;
  /** Forgets the recorded requests (not the state). */
  clearRequests(): void;
  close(): Promise<void>;
}

const BAD_POSITION = {
  message: '400 Bad request - Note {:line_code=>["can\'t be blank", "must be a valid line code"]}',
};

/** The added lines of a unified diff, by new line number. */
export function addedLines(diff: string): Set<number> {
  const added = new Set<number>();
  let line = 0;
  for (const text of diff.split('\n')) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) {
      line = Number(hunk[1]);
      continue;
    }
    if (text.startsWith('+')) added.add(line++);
    else if (text.startsWith(' ')) line++;
  }
  return added;
}

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const text = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(text);
}

export async function createFakeGitLab(
  options: { token?: string; botUserId?: number } = {},
): Promise<FakeGitLab> {
  const token = options.token ?? `glpat-${randomBytes(12).toString('hex')}`;
  const botUserId = options.botUserId ?? 42;
  let accessLevel = 30;
  const projects = new Map<number, FakeProject>();
  const requests: RecordedRequest[] = [];
  const statuses: FakeStatus[] = [];
  const injections: Injection[] = [];
  let nextNoteId = 1000;
  let nextStatusId = 9000;
  const userShape = gitlabShape('user');
  const projectShape = gitlabShape('project');
  const mrShape = gitlabShape('merge_request');
  const noteShape = gitlabShape<Record<string, unknown>>('note');
  const diffNoteShape = gitlabShape<{ notes: Record<string, unknown>[] }>('discussion').notes[0]!;
  const statusShape = gitlabShape('commit_status');
  /** Per-row bookkeeping beside the rows tests read (`statuses`). */
  const statusMeta = new Map<FakeStatus, { id: number; retried: boolean }>();
  const statusJson = (s: FakeStatus) => ({
    ...(statusShape as Record<string, unknown>),
    id: statusMeta.get(s)?.id,
    sha: s.sha,
    ref: s.ref,
    status: s.state,
    name: s.name,
    description: s.description,
    target_url: s.targetUrl,
    pipeline_id: s.pipelineId ?? 1,
  });
  const author = (id: number) => ({
    ...(userShape as Record<string, unknown>),
    id,
    username: id === botUserId ? 'project_7_bot_4b1e2c' : `user${id}`,
  });

  const findProject = (ref: string): FakeProject | undefined => {
    if (/^\d+$/.test(ref)) return projects.get(Number(ref));
    return [...projects.values()].find((p) => p.path === ref);
  };
  const noteJson = (note: FakeNote) => ({
    ...(note.position ? diffNoteShape : noteShape),
    id: note.id,
    body: note.body,
    author: author(note.authorId),
    resolvable: note.resolvable,
    ...(note.resolvable
      ? {
          resolved: note.resolved,
          resolved_by:
            note.resolved && typeof note.resolvedBy === 'number' ? author(note.resolvedBy) : null,
        }
      : {}),
    ...(note.position ? { position: note.position, type: 'DiffNote' } : { type: null }),
  });
  const discussionJson = (d: FakeDiscussion) => ({
    id: d.id,
    individual_note: d.individualNote,
    notes: d.notes.map(noteJson),
  });
  const mrJson = (project: FakeProject, mr: FakeMergeRequest) => ({
    ...(mrShape as Record<string, unknown>),
    id: 3000 + mr.iid,
    iid: mr.iid,
    project_id: project.id,
    title: mr.title,
    state: mr.state,
    source_branch: mr.sourceBranch,
    target_branch: mr.targetBranch,
    sha: mr.headSha,
    web_url: `${url}/${project.path}/-/merge_requests/${mr.iid}`,
    diff_refs: { base_sha: mr.baseSha, head_sha: mr.headSha, start_sha: mr.startSha },
  });
  const paged = (res: ServerResponse, query: URLSearchParams, all: unknown[]) => {
    const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? '20')));
    const page = Math.max(1, Number(query.get('page') ?? '1'));
    const pages = Math.max(1, Math.ceil(all.length / perPage));
    send(res, 200, all.slice((page - 1) * perPage, page * perPage), {
      'x-page': String(page),
      'x-per-page': String(perPage),
      'x-total': String(all.length),
      'x-total-pages': String(pages),
      'x-next-page': page < pages ? String(page + 1) : '',
      'x-prev-page': page > 1 ? String(page - 1) : '',
    });
  };

  const handle = (
    req: IncomingMessage,
    res: ServerResponse,
    body: string,
    injectedAlready = false,
  ): void => {
    const raw = req.url ?? '/';
    const [pathname = '/', query = ''] = raw.split('?', 2) as [string, string?];
    const apiPath = pathname.replace(/^\/api\/v4/, '');
    const injected = injectedAlready
      ? undefined
      : injections.find(
          (i) => i.method === req.method && i.path.test(apiPath) && i.answers.length > 0,
        );
    if (!injectedAlready) {
      requests.push({ method: req.method ?? '', path: apiPath, query, headers: req.headers, body });
    }
    if (injected) {
      const answer = injected.answers.shift()!;
      if (answer.before) {
        const { before, ...rest } = answer;
        void before().then(() => {
          if (rest.passThrough) handle(req, res, body, true);
          else if (!rest.hang) {
            send(res, rest.status, rest.body ?? { message: `${rest.status}` }, rest.headers);
          }
        });
        return;
      }
      if (answer.hang) return;
      if (!answer.passThrough) {
        send(res, answer.status, answer.body ?? { message: `${answer.status}` }, answer.headers);
        return;
      }
    }
    if (!pathname.startsWith('/api/v4/')) return send(res, 404, { error: '404 Not Found' });
    if (req.headers['private-token'] !== token) {
      return send(res, 401, { message: '401 Unauthorized' });
    }
    const params = new URLSearchParams(query);
    let json: Record<string, unknown> = {};
    if (body !== '') {
      try {
        json = JSON.parse(body) as Record<string, unknown>;
      } catch {
        return send(res, 400, { error: 'invalid JSON' });
      }
    }
    const segments = apiPath.split('/').slice(1).map(decodeURIComponent);
    if (req.method === 'GET' && apiPath === '/user') return send(res, 200, author(botUserId));
    if (segments[0] !== 'projects' || segments[1] === undefined) {
      return send(res, 404, { error: '404 Not Found' });
    }
    const project = findProject(segments[1]);
    if (!project) return send(res, 404, { message: '404 Project Not Found' });
    const rest = segments.slice(2);
    if (req.method === 'GET' && rest.length === 0) {
      return send(res, 200, {
        ...(projectShape as Record<string, unknown>),
        id: project.id,
        path_with_namespace: project.path,
        web_url: `${url}/${project.path}`,
        permissions: {
          project_access: { access_level: accessLevel, notification_level: 3 },
          group_access: null,
        },
      });
    }
    if (
      req.method === 'GET' &&
      rest.length === 4 &&
      rest[0] === 'repository' &&
      rest[1] === 'commits' &&
      rest[3] === 'statuses'
    ) {
      const name = params.get('name');
      const ref = params.get('ref');
      const all = params.get('all') === 'true';
      return paged(
        res,
        params,
        statuses
          .filter(
            (s) =>
              s.projectId === project.id &&
              s.sha === rest[2] &&
              (name === null || s.name === name) &&
              (ref === null || s.ref === ref) &&
              (all || !statusMeta.get(s)?.retried),
          )
          .map(statusJson),
      );
    }
    if (req.method === 'POST' && rest[0] === 'statuses' && rest.length === 2) {
      const sha = rest[1]!;
      const state = String(json['state'] ?? '');
      if (!['pending', 'running', 'success', 'failed', 'canceled', 'skipped'].includes(state)) {
        return send(res, 400, { error: 'state does not have a valid value' });
      }
      const pipelineId = json['pipeline_id'] === undefined ? null : Number(json['pipeline_id']);
      const pipelineRef = pipelineId === null ? undefined : project.pipelines.get(pipelineId);
      if (pipelineId !== null && pipelineRef === undefined) {
        return send(res, 404, { message: '404 Pipeline Not Found' });
      }
      const ref = typeof json['ref'] === 'string' ? json['ref'] : (pipelineRef ?? null);
      const name = String(json['name'] ?? 'default');
      const same = (s: FakeStatus) =>
        s.projectId === project.id &&
        s.sha === sha &&
        s.name === name &&
        s.ref === ref &&
        s.pipelineId === pipelineId;
      // GitLab: `CommitStatus.running_or_pending.find_or_initialize_by(...)`, then a transition.
      const open = statuses.findLast(
        (s) => same(s) && (s.state === 'pending' || s.state === 'running'),
      );
      if (open?.state === state) {
        const event = state === 'pending' ? 'enqueue' : 'run';
        return send(res, 400, {
          message: `Cannot transition status via :${event} from :${state} (Reason(s): Status cannot transition via "${event}")`,
        });
      }
      const description = typeof json['description'] === 'string' ? json['description'] : null;
      const targetUrl = typeof json['target_url'] === 'string' ? json['target_url'] : null;
      if (open) {
        Object.assign(open, { state, description, targetUrl });
        return send(res, 201, statusJson(open));
      }
      for (const s of statuses) {
        const meta = statusMeta.get(s);
        if (meta && same(s)) meta.retried = true;
      }
      const status: FakeStatus = {
        projectId: project.id,
        sha,
        name,
        state,
        description,
        targetUrl,
        pipelineId,
        ref,
      };
      statuses.push(status);
      statusMeta.set(status, { id: nextStatusId++, retried: false });
      return send(res, 201, statusJson(status));
    }
    if (rest[0] !== 'merge_requests' || rest[1] === undefined) {
      return send(res, 404, { error: '404 Not Found' });
    }
    const mr = project.mergeRequests.get(Number(rest[1]));
    if (!mr) return send(res, 404, { message: '404 Not found' });
    const discussions = project.discussions.get(mr.iid) ?? [];
    project.discussions.set(mr.iid, discussions);
    const tail = rest.slice(2);
    if (req.method === 'GET' && tail.length === 0) return send(res, 200, mrJson(project, mr));
    if (req.method === 'GET' && tail[0] === 'diffs' && tail.length === 1) {
      return paged(
        res,
        params,
        mr.diffs.map((d) => ({
          ...gitlabShape<Record<string, unknown>[]>('merge_request_diffs')[0],
          old_path: d.oldPath,
          new_path: d.newPath,
          diff: d.diff,
          new_file: d.newFile ?? false,
          renamed_file: d.renamedFile ?? false,
          deleted_file: d.deletedFile ?? false,
        })),
      );
    }
    if (req.method === 'GET' && tail[0] === 'discussions' && tail.length === 1) {
      return paged(res, params, discussions.map(discussionJson));
    }
    if (req.method === 'POST' && tail[0] === 'notes' && tail.length === 1) {
      if (typeof json['body'] !== 'string' || json['body'] === '') {
        return send(res, 400, { message: { body: ["can't be blank"] } });
      }
      const note: FakeNote = {
        id: nextNoteId++,
        body: json['body'],
        authorId: botUserId,
        resolvable: false,
        resolved: false,
        position: null,
      };
      discussions.push({
        id: randomBytes(20).toString('hex'),
        individualNote: true,
        notes: [note],
      });
      return send(res, 201, noteJson(note));
    }
    if (req.method === 'PUT' && tail[0] === 'notes' && tail.length === 2) {
      const note = discussions.flatMap((d) => d.notes).find((n) => n.id === Number(tail[1]));
      if (!note) return send(res, 404, { message: '404 Note Not Found' });
      if (note.authorId !== botUserId) return send(res, 403, { message: '403 Forbidden' });
      if (typeof json['body'] !== 'string' || json['body'] === '') {
        return send(res, 400, { message: { body: ["can't be blank"] } });
      }
      note.body = json['body'];
      return send(res, 200, noteJson(note));
    }
    if (req.method === 'DELETE' && tail[0] === 'notes' && tail.length === 2) {
      const discussion = discussions.find((d) => d.notes.some((n) => n.id === Number(tail[1])));
      const note = discussion?.notes.find((n) => n.id === Number(tail[1]));
      if (!discussion || !note) return send(res, 404, { message: '404 Note Not Found' });
      if (note.authorId !== botUserId && accessLevel < 40) {
        return send(res, 403, { message: '403 Forbidden' });
      }
      discussion.notes.splice(discussion.notes.indexOf(note), 1);
      if (discussion.notes.length === 0) discussions.splice(discussions.indexOf(discussion), 1);
      res.writeHead(204).end();
      return;
    }
    if (req.method === 'POST' && tail[0] === 'discussions' && tail.length === 1) {
      const position = json['position'] as Record<string, unknown> | undefined;
      if (typeof json['body'] !== 'string' || json['body'] === '' || !position) {
        return send(res, 400, { message: '400 Bad request' });
      }
      const file = mr.diffs.find((d) => d.newPath === position['new_path']);
      if (
        position['position_type'] !== 'text' ||
        position['head_sha'] !== mr.headSha ||
        position['base_sha'] !== mr.baseSha ||
        position['start_sha'] !== mr.startSha ||
        !file ||
        position['old_path'] !== file.oldPath ||
        !addedLines(file.diff).has(Number(position['new_line']))
      ) {
        return send(res, 400, BAD_POSITION);
      }
      const note: FakeNote = {
        id: nextNoteId++,
        body: json['body'],
        authorId: botUserId,
        resolvable: true,
        resolved: false,
        position: { ...position, old_line: null, line_range: null },
      };
      const discussion = {
        id: randomBytes(20).toString('hex'),
        individualNote: false,
        notes: [note],
      };
      discussions.push(discussion);
      return send(res, 201, discussionJson(discussion));
    }
    if (req.method === 'PUT' && tail[0] === 'discussions' && tail.length === 2) {
      const discussion = discussions.find((d) => d.id === tail[1]);
      if (!discussion) return send(res, 404, { message: '404 Discussion Not Found' });
      const resolved = params.get('resolved');
      if (resolved !== 'true' && resolved !== 'false') {
        return send(res, 400, { error: 'resolved is missing' });
      }
      if (!discussion.notes.some((n) => n.resolvable)) {
        return send(res, 400, { message: '400 Bad request - discussion is not resolvable' });
      }
      for (const n of discussion.notes) {
        if (!n.resolvable) continue;
        n.resolved = resolved === 'true';
        n.resolvedBy = n.resolved ? botUserId : null;
      }
      return send(res, 200, discussionJson(discussion));
    }
    return send(res, 404, { error: '404 Not Found' });
  };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => handle(req, res, Buffer.concat(chunks).toString('utf8')));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const projectOf = (id: number): FakeProject => {
    const project = projects.get(id);
    if (!project) throw new Error(`fake GitLab: no project ${id}`);
    return project;
  };
  return {
    url,
    token,
    botUserId,
    get accessLevel() {
      return accessLevel;
    },
    set accessLevel(level: number) {
      accessLevel = level;
    },
    requests,
    statuses,
    addProject({ id, path: projectPath }) {
      projects.set(id, {
        id,
        path: projectPath,
        mergeRequests: new Map(),
        discussions: new Map(),
        pipelines: new Map(),
      });
    },
    addMergeRequest(projectId, mr) {
      projectOf(projectId).mergeRequests.set(mr.iid, mr);
    },
    updateMergeRequest(projectId, iid, changes) {
      const mr = projectOf(projectId).mergeRequests.get(iid);
      if (!mr) throw new Error(`fake GitLab: no merge request !${iid}`);
      Object.assign(mr, changes);
    },
    addPipeline(projectId, pipelineId, ref = 'main') {
      projectOf(projectId).pipelines.set(pipelineId, ref);
    },
    addNote(projectId, iid, { body, authorId }) {
      const project = projectOf(projectId);
      const list = project.discussions.get(iid) ?? [];
      project.discussions.set(iid, list);
      const discussion: FakeDiscussion = {
        id: randomBytes(20).toString('hex'),
        individualNote: true,
        notes: [
          { id: nextNoteId++, body, authorId, resolvable: false, resolved: false, position: null },
        ],
      };
      list.push(discussion);
      return discussion;
    },
    reply(projectId, iid, discussionId, { body, authorId }) {
      const discussion = (projectOf(projectId).discussions.get(iid) ?? []).find(
        (d) => d.id === discussionId,
      );
      if (!discussion) throw new Error(`fake GitLab: no discussion ${discussionId}`);
      // GitLab: a reply in a resolvable (diff) thread is resolvable too. It is open in an open
      // thread; in a resolved thread it is created resolved, by its own author, so the thread stays
      // resolved (Notes::BuildService: `note.resolve_without_save(current_user) if
      // discussion&.resolved?`; seen on GitLab CE 18.11.11, scm.md §11).
      const resolvable = discussion.notes.some((n) => n.resolvable);
      const threadResolved =
        resolvable && discussion.notes.every((n) => !n.resolvable || n.resolved);
      const note: FakeNote = {
        id: nextNoteId++,
        body,
        authorId,
        resolvable,
        resolved: threadResolved,
        ...(threadResolved ? { resolvedBy: authorId } : {}),
        position: null,
      };
      discussion.notes.push(note);
      return note;
    },
    resolveAs(projectId, iid, discussionId, userId, resolved) {
      const discussion = (projectOf(projectId).discussions.get(iid) ?? []).find(
        (d) => d.id === discussionId,
      );
      if (!discussion) throw new Error(`fake GitLab: no discussion ${discussionId}`);
      for (const n of discussion.notes) {
        if (!n.resolvable) continue;
        n.resolved = resolved;
        n.resolvedBy = resolved ? userId : null;
      }
    },
    discussions(projectId, iid) {
      return projectOf(projectId).discussions.get(iid) ?? [];
    },
    inject(method, pathPattern, ...answers) {
      injections.push({ method, path: pathPattern, answers: [...answers] });
    },
    clearRequests() {
      requests.length = 0;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
