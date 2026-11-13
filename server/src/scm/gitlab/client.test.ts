import { readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addedLines,
  createFakeGitLab,
  gitlabShape,
  type FakeGitLab,
} from '../../../test/fake-gitlab';
import {
  accessLevelOf,
  GITLAB_FORBIDDEN,
  GITLAB_SHAPES,
  GitLabClient,
  GitLabError,
  gitlabRoute,
  MAX_GITLAB_RESPONSE_BYTES,
  retryAfterSeconds,
} from './client';

const SHAPES_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/gitlab-shapes',
);
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
/** A diff position on the added line of the merge request the fake serves (src/a.ts, line 2). */
const POSITION = {
  baseSha: BASE,
  startSha: BASE,
  headSha: HEAD,
  oldPath: 'src/a.ts',
  newPath: 'src/a.ts',
  newLine: 2,
};

async function failure(promise: Promise<unknown>): Promise<GitLabError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof GitLabError) return err;
    throw err;
  }
  throw new Error('expected a GitLabError');
}

describe('GitLab client (scm.md §4.3) against the fake GitLab', () => {
  let fake: FakeGitLab;
  /** The fake's clock: what a note it makes gets as `created_at`. */
  let clock = Date.now();
  const client = (
    overrides: { token?: string; allowInternalHosts?: boolean; maxRequests?: number } = {},
  ) =>
    new GitLabClient(
      {
        baseUrl: fake.url,
        token: overrides.token ?? fake.token,
        allowInternalHosts: overrides.allowInternalHosts ?? true,
      },
      {
        timeoutMs: 1_000,
        ...(overrides.maxRequests ? { maxRequests: overrides.maxRequests } : {}),
      },
    );

  beforeAll(async () => {
    fake = await createFakeGitLab({ now: () => clock });
    fake.addProject({ id: 7, path: 'acme/payments/api' });
    fake.addPipeline(7, 99001);
    fake.addMergeRequest(7, {
      iid: 12,
      title: 'Refund limits',
      state: 'opened',
      sourceBranch: 'feature/refund-limits',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [
        {
          oldPath: 'src/a.ts',
          newPath: 'src/a.ts',
          diff: '@@ -1,2 +1,3 @@\n export const a = 1;\n+console.log(a);\n export const b = 2;\n',
        },
      ],
    });
  });
  afterAll(() => fake.close());
  beforeEach(() => fake.clearRequests());

  it('parses every recorded shape with the schema the client uses', () => {
    const files = readdirSync(SHAPES_DIR).filter((f) => f.endsWith('.json'));
    const schemaOf: Record<string, keyof typeof GITLAB_SHAPES> = {
      'user.json': 'user',
      'project.json': 'project',
      'merge_request.json': 'mergeRequest',
      'merge_request_diffs.json': 'diffs',
      'note.json': 'note',
      'discussion.json': 'discussion',
      'discussions.json': 'discussions',
      'commit_status.json': 'commitStatus',
      'commit_statuses.json': 'commitStatuses',
      'member.json': 'member',
    };
    expect(files.sort()).toEqual(Object.keys(schemaOf).sort());
    for (const file of files) {
      const parsed = GITLAB_SHAPES[schemaOf[file]!].safeParse(gitlabShape(file.slice(0, -5)));
      expect(parsed.success, file).toBe(true);
    }
  });

  it('reads a draft flag that is missing, null or not a boolean as false: the merge request still parses', () => {
    const shape = gitlabShape('merge_request') as Record<string, unknown>;
    /** The recorded merge request with `flags` over it; a flag set to undefined is left out. */
    const parse = (flags: Record<string, unknown>) =>
      GITLAB_SHAPES.mergeRequest.safeParse(
        Object.fromEntries(
          Object.entries({ ...shape, ...flags }).filter(([, value]) => value !== undefined),
        ),
      );
    for (const flags of [
      { draft: null, work_in_progress: null },
      { draft: undefined, work_in_progress: undefined },
      { draft: 'yes', work_in_progress: 1 },
    ]) {
      const parsed = parse(flags);
      expect(parsed.success, JSON.stringify(flags)).toBe(true);
      expect(parsed.data, JSON.stringify(flags)).toMatchObject({
        draft: false,
        work_in_progress: false,
      });
    }
    // A flag that says draft still does.
    expect(parse({ draft: null, work_in_progress: true }).data).toMatchObject({
      draft: false,
      work_in_progress: true,
    });
    expect(parse({ draft: true }).data).toMatchObject({ draft: true });
  });

  it('sends the token only in PRIVATE-TOKEN, never in the URL', async () => {
    const user = await client().currentUser();
    expect(user).toMatchObject({ id: fake.botUserId });
    const [request] = fake.requests;
    expect(request?.headers['private-token']).toBe(fake.token);
    expect(request?.headers['user-agent']).toMatch(/^Qualor\//);
    expect(`${request?.path}?${request?.query}`).not.toContain(fake.token);
  });

  it('addresses a project by id or by its URL-encoded path', async () => {
    expect((await client().project('7')).path_with_namespace).toBe('acme/payments/api');
    expect((await client().project('acme/payments/api')).id).toBe(7);
    expect(fake.requests.at(-1)?.path).toBe('/projects/acme%2Fpayments%2Fapi');
    const mr = await client().mergeRequest('acme/payments/api', '12');
    expect(mr.diff_refs).toEqual({ base_sha: BASE, head_sha: HEAD, start_sha: BASE });
  });

  it('turns 401 into "GitLab refused the token", 403 into a missing permission, 404 into "not found"', async () => {
    const refused = await failure(client({ token: 'glpat-wrong' }).currentUser());
    expect(refused.kind).toBe('auth');
    expect(refused.message).toBe('GitLab refused the token (HTTP 401)');
    // 403: the token is valid, its user may not do this; the text says what was refused.
    fake.inject('GET', /^\/user$/, { status: 403 });
    expect(await failure(client().currentUser())).toMatchObject({
      kind: 'auth',
      reason: 'permission_missing',
      status: 403,
      message: GITLAB_FORBIDDEN.request,
    });
    fake.inject('POST', /^\/projects\/7\/statuses\//, { status: 403 });
    const status = await failure(
      client().setCommitStatus('7', 'a'.repeat(40), {
        state: 'success',
        name: 'qualor/app',
        description: 'Quality gate passed',
        targetUrl: null,
        pipelineId: null,
        ref: 'main',
      }),
    );
    expect(status.message).toBe(
      'The GitLab token lacks the permission to set the commit status (HTTP 403); a commit status on a protected branch needs the Maintainer role',
    );
    const missing = await failure(client().project('nope/nope'));
    expect(missing.kind).toBe('not_found');
    expect(missing.message).toBe('The GitLab project was not found, or the token cannot see it');
  });

  it('reports 429 with its Retry-After, 5xx as transient, a foreign redirect as refused', async () => {
    fake.inject('GET', /^\/user$/, { status: 429, headers: { 'retry-after': '7' } });
    const limited = await failure(client().currentUser());
    expect(limited).toMatchObject({ kind: 'rate_limited', retryAfterSeconds: 7, status: 429 });
    fake.inject('GET', /^\/user$/, { status: 502 });
    expect(await failure(client().currentUser())).toMatchObject({
      kind: 'transient',
      message: 'GitLab answered HTTP 502',
    });
    fake.inject('GET', /^\/user$/, { status: 302, headers: { location: 'https://evil.example/' } });
    expect(await failure(client().currentUser())).toMatchObject({
      kind: 'refused',
      message: 'GitLab answered HTTP 302',
    });
  });

  it('reads RateLimit-Reset when there is no Retry-After, and clamps both', () => {
    const now = Date.UTC(2026, 8, 25, 9, 0, 0);
    expect(retryAfterSeconds({ 'ratelimit-reset': String(now / 1000 + 30) }, now)).toBe(30);
    expect(retryAfterSeconds({ 'retry-after': '0' }, now)).toBe(1);
    expect(retryAfterSeconds({ 'retry-after': '86400' }, now)).toBe(900);
    expect(retryAfterSeconds({ 'retry-after': new Date(now + 5_000).toUTCString() }, now)).toBe(5);
    expect(retryAfterSeconds({}, now)).toBeNull();
  });

  it('gives up on a GitLab that never answers, with a fixed text', async () => {
    fake.inject('GET', /^\/user$/, { status: 200, hang: true });
    const err = await failure(
      new GitLabClient(
        { baseUrl: fake.url, token: fake.token, allowInternalHosts: true },
        { timeoutMs: 200 },
      ).currentUser(),
    );
    expect(err).toMatchObject({ kind: 'transient', message: 'GitLab did not answer within 10 s' });
  });

  it('refuses a loopback GitLab unless its host is listed (SSRF, ruling W3)', async () => {
    const err = await failure(client({ allowInternalHosts: false }).currentUser());
    expect(err.kind).toBe('refused');
    expect(err.message).toMatch(/QUALOR_SCM_INTERNAL_HOSTS/);
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses an answer over 8 MiB and a body that is not JSON', async () => {
    const big = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(Buffer.alloc(MAX_GITLAB_RESPONSE_BYTES + 10, 0x20));
    });
    await new Promise<void>((resolve) => big.listen(0, '127.0.0.1', resolve));
    const port = (big.address() as AddressInfo).port;
    const err = await failure(
      new GitLabClient(
        { baseUrl: `http://127.0.0.1:${port}`, token: 't', allowInternalHosts: true },
        { timeoutMs: 5_000 },
      ).currentUser(),
    );
    big.closeAllConnections();
    big.close();
    expect(err).toMatchObject({ kind: 'bad_answer' });
    fake.inject('GET', /^\/user$/, { status: 200, body: 'not json' });
    expect((await failure(client().currentUser())).kind).toBe('bad_answer');
  });

  it('follows x-next-page and stops at the page bound', async () => {
    for (let i = 0; i < 205; i++) fake.addNote(7, 12, { body: `note ${i}`, authorId: 5 });
    const all = await client().discussions('7', '12', 50);
    expect(all.complete).toBe(true);
    expect(all.items).toHaveLength(205);
    expect(fake.requests.map((r) => r.query)).toEqual([
      'per_page=100&page=1',
      'per_page=100&page=2',
      'per_page=100&page=3',
    ]);
    const bounded = await client().discussions('7', '12', 2);
    expect(bounded).toMatchObject({ complete: false });
    expect(bounded.items).toHaveLength(200);
  });

  it('stops at the request budget of a job', async () => {
    const small = client({ maxRequests: 2 });
    await small.currentUser();
    await small.currentUser();
    expect(await failure(small.currentUser())).toMatchObject({ kind: 'budget' });
    expect(small.requests).toBe(2);
  });

  it('creates and edits notes, and reports a rejected diff position', async () => {
    const c = client();
    const note = await c.createNote('7', '12', 'first');
    expect(note.author.id).toBe(fake.botUserId);
    expect((await c.updateNote('7', '12', note.id, 'second')).body).toBe('second');
    const position = {
      baseSha: BASE,
      startSha: BASE,
      headSha: HEAD,
      oldPath: 'src/a.ts',
      newPath: 'src/a.ts',
      newLine: 2,
    };
    const created = await c.createDiscussion('7', '12', 'inline', position);
    expect(created).not.toBe('position_rejected');
    if (created === 'position_rejected') return;
    expect(created.notes[0]?.resolved).toBe(false);
    await c.resolveDiscussion('7', '12', created.id, true);
    expect(fake.discussions(7, 12).find((d) => d.id === created.id)?.notes[0]?.resolved).toBe(true);
    expect(await c.createDiscussion('7', '12', 'x', { ...position, newLine: 1 })).toBe(
      'position_rejected',
    );
  });

  it("deletes its own note, and another user's only as a Maintainer", async () => {
    const c = client();
    const own = await c.createNote('7', '12', 'mine');
    await c.deleteNote('7', '12', own.id);
    const notes = () => fake.discussions(7, 12).flatMap((d) => d.notes);
    expect(notes().some((n) => n.id === own.id)).toBe(false);
    const other = fake.addNote(7, 12, { body: 'theirs', authorId: 5 }).notes[0]!;
    expect(await failure(c.deleteNote('7', '12', other.id))).toMatchObject({
      kind: 'auth',
      reason: 'permission_missing',
      status: 403,
      message: GITLAB_FORBIDDEN.deleteNote,
    });
    fake.accessLevel = 40;
    try {
      await c.deleteNote('7', '12', other.id);
    } finally {
      fake.accessLevel = 30;
    }
    expect(notes().some((n) => n.id === other.id)).toBe(false);
    expect((await failure(c.deleteNote('7', '12', other.id))).kind).toBe('not_found');
    expect((await failure(c.deleteNote('7', '12', 0))).reason).toBe('invalid_input');
  });

  it('a reply goes into the discussion and comes back as a note', async () => {
    const c = client();
    const thread = await c.createDiscussion('7', '12', 'inline issue', POSITION);
    if (thread === 'position_rejected') throw new Error('expected a discussion');
    fake.clearRequests();
    const reply = await c.replyToDiscussion('7', '12', thread.id, 'That guard is on purpose.');
    expect(reply).toMatchObject({
      body: 'That guard is on purpose.',
      system: false,
      author: { id: fake.botUserId },
      resolvable: true,
      resolved: false,
    });
    // One POST into the discussion, carrying the text and nothing else.
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      `POST /projects/7/merge_requests/12/discussions/${thread.id}/notes`,
    ]);
    expect(JSON.parse(fake.requests[0]?.body ?? '{}')).toEqual({
      body: 'That guard is on purpose.',
    });
    // GitLab appends it to that discussion, after the note it answers, and starts none of its own.
    const discussions = (await c.discussions('7', '12', 50)).items;
    expect(discussions.filter((d) => d.id === thread.id)).toHaveLength(1);
    expect(discussions.find((d) => d.id === thread.id)?.notes.map((n) => n.id)).toEqual([
      thread.notes[0]?.id,
      reply.id,
    ]);
    // A person's plain note is a discussion of its own, which a reply joins just the same.
    const theirs = fake.addNote(7, 12, { body: 'qualor review', authorId: 5 });
    const answer = await c.replyToDiscussion('7', '12', theirs.id, 'Reviewing this commit.');
    expect(
      fake
        .discussions(7, 12)
        .find((d) => d.id === theirs.id)
        ?.notes.map((n) => n.id),
    ).toEqual([theirs.notes[0]?.id, answer.id]);
  });

  it('a 404 is not_found', async () => {
    const c = client();
    // A discussion the merge request does not have (deleted, or another merge request's) ...
    expect(await failure(c.replyToDiscussion('7', '12', 'f'.repeat(40), 'x'))).toMatchObject({
      kind: 'not_found',
      status: 404,
    });
    // ... and a merge request or a project the token cannot see, as for every request.
    expect((await failure(c.replyToDiscussion('7', '99', 'f'.repeat(40), 'x'))).kind).toBe(
      'not_found',
    );
    expect((await failure(c.replyToDiscussion('nope/nope', '12', 'f'.repeat(40), 'x'))).kind).toBe(
      'not_found',
    );
    expect(fake.requests).toHaveLength(3); // each tried once
  });

  it("both requests count against the client's budget", async () => {
    const theirs = fake.addNote(7, 12, { body: 'qualor review', authorId: 5 });
    const small = client({ maxRequests: 2 });
    await small.replyToDiscussion('7', '12', theirs.id, 'one');
    await small.replyToDiscussion('7', '12', theirs.id, 'two');
    expect(small.requests).toBe(2);
    expect(await failure(small.replyToDiscussion('7', '12', theirs.id, 'three'))).toMatchObject({
      kind: 'budget',
    });
    expect(small.requests).toBe(2);
    expect(fake.requests).toHaveLength(2);
    expect(
      fake
        .discussions(7, 12)
        .find((d) => d.id === theirs.id)
        ?.notes.map((n) => n.body),
    ).toEqual(['qualor review', 'one', 'two']);
  });

  it("created_at and the author's username are read", async () => {
    const c = client();
    clock = Date.parse('2026-10-25T08:00:00.000Z');
    const theirs = fake.addNote(7, 12, { body: 'a question', authorId: 5 });
    clock += 90_000;
    const reply = await c.replyToDiscussion('7', '12', theirs.id, 'an answer');
    expect(reply).toMatchObject({
      created_at: '2026-10-25T08:01:30.000Z',
      author: { id: fake.botUserId, username: 'project_7_bot_4b1e2c' },
    });
    const listed = (await c.discussions('7', '12', 50)).items.find((d) => d.id === theirs.id);
    expect(listed?.notes.map((n) => [n.author.username, n.created_at])).toEqual([
      ['user5', '2026-10-25T08:00:00.000Z'],
      ['project_7_bot_4b1e2c', '2026-10-25T08:01:30.000Z'],
    ]);
    // GitLab sends both on every note: a note without either is not understood.
    const recorded = gitlabShape<Record<string, unknown>>('note');
    const withoutDate = Object.fromEntries(
      Object.entries(recorded).filter(([key]) => key !== 'created_at'),
    );
    for (const body of [withoutDate, { ...recorded, author: { id: fake.botUserId } }]) {
      fake.inject('POST', /\/discussions\/[0-9a-f]+\/notes$/, { status: 201, body });
      expect((await failure(c.replyToDiscussion('7', '12', theirs.id, 'x'))).kind).toBe(
        'bad_answer',
      );
    }
  });

  it("reads a user's access level in the project, an inherited one too, and null for no member", async () => {
    const c = client();
    fake.setMember(7, 5, 30);
    fake.setMember(7, 8, 50);
    expect(await c.memberAccessLevel('7', 5)).toBe(30);
    expect(await c.memberAccessLevel('acme/payments/api', 8)).toBe(50);
    // GitLab's 404: no member of the project.
    expect(await c.memberAccessLevel('7', 6)).toBeNull();
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'GET /projects/7/members/all/5',
      'GET /projects/acme%2Fpayments%2Fapi/members/all/8',
      'GET /projects/7/members/all/6',
    ]);
    // A user id it would not put into a path is refused before any request.
    fake.clearRequests();
    for (const id of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(await failure(c.memberAccessLevel('7', id)), String(id)).toMatchObject({
        kind: 'refused',
        reason: 'invalid_input',
      });
    }
    expect(fake.requests).toHaveLength(0);
    // An answer without a level is not understood, and any other error is no answer either.
    fake.inject('GET', /\/members\/all\/5$/, { status: 200, body: { id: 5 } }, { status: 500 });
    expect((await failure(c.memberAccessLevel('7', 5))).kind).toBe('bad_answer');
    expect((await failure(c.memberAccessLevel('7', 5))).kind).toBe('transient');
    // Each lookup is a request of the job's budget.
    const small = client({ maxRequests: 1 });
    expect(await small.memberAccessLevel('7', 5)).toBe(30);
    expect((await failure(small.memberAccessLevel('7', 5))).kind).toBe('budget');
    fake.setMember(7, 5, null);
    fake.setMember(7, 8, null);
  });

  it('counts only the membership of an active user that is in force today', async () => {
    // Midday of 2026-10-25, UTC.
    const c = new GitLabClient(
      { baseUrl: fake.url, token: fake.token, allowInternalHosts: true },
      { timeoutMs: 1_000, now: () => Date.parse('2026-10-25T12:00:00.000Z') },
    );
    const levelOf = async (membership: Parameters<FakeGitLab['setMember']>[3]) => {
      fake.setMember(7, 20, 40, membership);
      return c.memberAccessLevel('7', 20);
    };
    // Active, with no end, or one after today: the level counts. An older GitLab may name no
    // state of the membership.
    expect(await levelOf({})).toBe(40);
    expect(await levelOf({ membershipState: null })).toBe(40);
    expect(await levelOf({ expiresAt: '2026-10-26' })).toBe(40);
    // A blocked or deactivated user, an invitation not yet accepted, a membership that ends today
    // or has ended: no access, as for no member.
    expect(await levelOf({ state: 'blocked' })).toBeNull();
    expect(await levelOf({ state: 'deactivated' })).toBeNull();
    expect(await levelOf({ membershipState: 'awaiting' })).toBeNull();
    expect(await levelOf({ membershipState: 'created' })).toBeNull();
    expect(await levelOf({ expiresAt: '2026-10-25' })).toBeNull();
    expect(await levelOf({ expiresAt: '2026-10-24' })).toBeNull();
    // A date-time, as some of GitLab's examples write the last day: its UTC date is the day.
    expect(await levelOf({ expiresAt: '2026-10-26T00:00:00Z' })).toBe(40);
    expect(await levelOf({ expiresAt: '2026-10-25T22:00:00.000-03:00' })).toBe(40);
    expect(await levelOf({ expiresAt: '2026-10-25T23:59:59Z' })).toBeNull();
    expect(await levelOf({ expiresAt: '2026-10-26T01:00:00+02:00' })).toBeNull();
    // A day that is no day, or no date at all, is not understood: the error names the field and
    // never what it held.
    for (const expiresAt of ['2026-13-01', 'soon', '2026-10-26T10:00:00', 20261026]) {
      fake.inject('GET', /\/members\/all\/20$/, {
        status: 200,
        body: { ...(gitlabShape('member') as object), expires_at: expiresAt },
      });
      const err = await failure(c.memberAccessLevel('7', 20));
      expect(err, String(expiresAt)).toMatchObject({ kind: 'bad_answer', field: 'expires_at' });
      expect(inspect(err, { depth: 5, showHidden: true })).not.toContain(String(expiresAt));
    }
    // An answer without the user's state is not understood either.
    fake.inject('GET', /\/members\/all\/20$/, {
      status: 200,
      body: Object.fromEntries(
        Object.entries(gitlabShape('member')).filter(([key]) => key !== 'state'),
      ),
    });
    expect((await failure(c.memberAccessLevel('7', 20))).kind).toBe('bad_answer');
    fake.setMember(7, 20, null);
  });

  it('checks the discussion id before putting it into a path', async () => {
    const c = client();
    const malformed = [
      '',
      'G'.repeat(40),
      'ABCDEF',
      '../notes',
      'a/../../x',
      'a?x=1',
      '1 2',
      '1\n',
    ];
    for (const id of [...malformed, 'a'.repeat(65)]) {
      expect(await failure(c.replyToDiscussion('7', '12', id, 'x')), id).toMatchObject({
        kind: 'refused',
        reason: 'invalid_input',
      });
    }
    // The merge request id is checked as everywhere.
    expect((await failure(c.replyToDiscussion('7', '12/../x', 'a'.repeat(40), 'x'))).reason).toBe(
      'invalid_input',
    );
    expect(fake.requests).toHaveLength(0);
    // The shortest and the longest well-formed ids reach GitLab, which has no such discussion.
    for (const id of ['a', 'a'.repeat(64)]) {
      expect((await failure(c.replyToDiscussion('7', '12', id, 'x'))).kind, id).toBe('not_found');
    }
  });

  it('is served by a fake that answers a reply as GitLab does, and takes its injected answers', async () => {
    const c = client();
    const thread = await c.createDiscussion('7', '12', 'inline', POSITION);
    if (thread === 'position_rejected') throw new Error('expected a discussion');
    const notesOf = () => fake.discussions(7, 12).find((d) => d.id === thread.id)?.notes ?? [];
    const post = (body: string, token = fake.token, id = thread.id) =>
      fetch(`${fake.url}/api/v4/projects/7/merge_requests/12/discussions/${id}/notes`, {
        method: 'POST',
        headers: { 'private-token': token, 'content-type': 'application/json' },
        body,
      });
    expect((await post('{"body":"x"}', 'glpat-wrong')).status).toBe(401);
    expect((await post('{not json')).status).toBe(400);
    expect((await post('{}')).status).toBe(400);
    expect((await post('{"body":""}')).status).toBe(400);
    expect((await post('{"body":"x"}', fake.token, 'f'.repeat(40))).status).toBe(404);
    expect(notesOf()).toHaveLength(1);
    // The fake's injected answers reach the new route too, and are mapped as for any request.
    fake.inject(
      'POST',
      /\/discussions\/[0-9a-f]+\/notes$/,
      { status: 403 },
      { status: 429, headers: { 'retry-after': '7' } },
    );
    expect(await failure(c.replyToDiscussion('7', '12', thread.id, 'x'))).toMatchObject({
      kind: 'auth',
      reason: 'permission_missing',
      status: 403,
      message: GITLAB_FORBIDDEN.request,
    });
    expect(await failure(c.replyToDiscussion('7', '12', thread.id, 'x'))).toMatchObject({
      kind: 'rate_limited',
      retryAfterSeconds: 7,
    });
    expect(notesOf()).toHaveLength(1);
    // A reply in a resolved thread is created resolved, by its author, so the thread stays
    // resolved (seen on GitLab CE 18.11.11, scm.md §11).
    await c.resolveDiscussion('7', '12', thread.id, true);
    expect(await c.replyToDiscussion('7', '12', thread.id, 'late')).toMatchObject({
      resolved: true,
      resolved_by: { id: fake.botUserId },
    });
    expect(notesOf().map((n) => n.body)).toEqual(['inline', 'late']);
  });

  it("reads the token's access level in the project, the higher of project and group", async () => {
    expect(accessLevelOf(await client().project('7'))).toBe(30);
    const base = { id: 1, path_with_namespace: 'a/b', web_url: 'https://x/a/b' };
    expect(accessLevelOf(base)).toBeNull();
    expect(accessLevelOf({ ...base, permissions: null })).toBeNull();
    expect(
      accessLevelOf({
        ...base,
        permissions: { project_access: null, group_access: { access_level: 40 } },
      }),
    ).toBe(40);
    expect(
      accessLevelOf({
        ...base,
        permissions: { project_access: { access_level: 50 }, group_access: { access_level: 30 } },
      }),
    ).toBe(50);
  });

  it('calls a host whose lookup does not finish in time unresolved, not a timeout', async () => {
    const err = await failure(
      new GitLabClient(
        { baseUrl: 'https://gitlab-ce', token: fake.token, allowInternalHosts: true },
        { timeoutMs: 1_000, connectTimeoutMs: 50, resolve: () => new Promise(() => undefined) },
      ).currentUser(),
    );
    expect(err).toMatchObject({
      kind: 'transient',
      reason: 'unresolved',
      message: 'The GitLab host could not be resolved',
    });
  });

  it('adds a status row for a final state posted again, as GitLab does, and drops an unknown pipeline_id', async () => {
    const c = client();
    const input = {
      state: 'failed' as const,
      name: 'qualor/quality-gate',
      description: 'Quality gate failed',
      targetUrl: null,
      pipelineId: '99001',
      ref: 'feature/refund-limits',
    };
    // GitLab reuses only a pending or running status: a final state posted again is a new row, so
    // the decoration job reads the statuses first (commitStatuses) to stay idempotent.
    expect(await c.setCommitStatus('7', HEAD, input)).toBe('set');
    expect(await c.setCommitStatus('7', HEAD, input)).toBe('set');
    expect(
      await c.setCommitStatus('7', HEAD, { ...input, state: 'success', pipelineId: '5' }),
    ).toBe('set');
    // With a pipeline, GitLab takes the ref from it; without one (or once it is dropped) the ref
    // is sent.
    expect(fake.statuses.map((s) => [s.state, s.pipelineId, s.ref])).toEqual([
      ['failed', 99001, 'main'],
      ['failed', 99001, 'main'],
      ['success', null, 'feature/refund-limits'],
    ]);
    const posted = fake.requests
      .filter((r) => r.method === 'POST')
      .map((r) => JSON.parse(r.body) as Record<string, unknown>);
    expect(posted[0]).toMatchObject({ pipeline_id: 99001 });
    expect(posted[0]).not.toHaveProperty('ref');
    expect(posted.at(-1)).toMatchObject({ ref: 'feature/refund-limits' });
    expect(posted.at(-1)).not.toHaveProperty('pipeline_id');
  });

  it('treats a pending status posted again as unchanged (GitLab: "Cannot transition status")', async () => {
    const c = client();
    const input = {
      state: 'pending' as const,
      name: 'qualor/pending-check',
      description: 'Waiting',
      targetUrl: null,
      pipelineId: null,
      ref: 'main',
    };
    expect(await c.setCommitStatus('7', BASE, input)).toBe('set');
    expect(await c.setCommitStatus('7', BASE, input)).toBe('unchanged');
    expect(await c.setCommitStatus('7', BASE, { ...input, state: 'success' })).toBe('set');
    expect(fake.statuses.filter((s) => s.name === 'qualor/pending-check')).toMatchObject([
      { state: 'success' },
    ]);
  });

  it('lists the latest statuses of a commit by name', async () => {
    const c = client();
    const sha = 'c'.repeat(40);
    const input = {
      state: 'failed' as const,
      name: 'qualor/quality-gate',
      description: 'Quality gate failed',
      targetUrl: 'https://qualor.example.com/x',
      pipelineId: null,
      ref: 'main',
    };
    expect(await c.commitStatuses('7', sha, 'qualor/quality-gate')).toEqual([]);
    await c.setCommitStatus('7', sha, input);
    await c.setCommitStatus('7', sha, { ...input, state: 'success', description: 'passed' });
    await c.setCommitStatus('7', sha, { ...input, name: 'other' });
    const listed = await c.commitStatuses('7', sha, 'qualor/quality-gate');
    expect(listed).toMatchObject([
      {
        sha,
        name: 'qualor/quality-gate',
        status: 'success',
        description: 'passed',
        target_url: 'https://qualor.example.com/x',
        ref: 'main',
      },
    ]);
    const request = fake.requests.at(-1);
    expect(request?.path).toBe(`/projects/7/repository/commits/${sha}/statuses`);
    expect(new URLSearchParams(request?.query).get('name')).toBe('qualor/quality-gate');
    expect(new URLSearchParams(request?.query).get('all')).toBe('false');
  });

  it('finds the added lines of a unified diff', () => {
    expect([...addedLines('@@ -1,2 +1,3 @@\n a\n+b\n c\n@@ -10 +11,2 @@\n+x\n y\n')]).toEqual([
      2, 11,
    ]);
  });

  it('refuses an unlisted name that resolves to an internal address, and pins a listed one', async () => {
    const port = new URL(fake.url).port;
    const viaName = (
      allowInternalHosts: boolean,
      addresses: string[],
      host = 'gitlab.corp.internal',
    ) =>
      new GitLabClient(
        { baseUrl: `http://${host}:${port}`, token: fake.token, allowInternalHosts },
        {
          timeoutMs: 1_000,
          resolve: () => Promise.resolve(addresses.map((address) => ({ address, family: 4 }))),
        },
      );
    // Unlisted: one non-public address among public ones is enough to refuse, before any request.
    for (const addresses of [['127.0.0.1'], ['93.184.215.14', '10.0.0.8'], ['169.254.169.254']]) {
      const err = await failure(viaName(false, addresses).currentUser());
      expect(err).toMatchObject({ kind: 'refused', status: null });
      expect(err.message).toMatch(/QUALOR_SCM_INTERNAL_HOSTS/);
    }
    expect(fake.requests).toHaveLength(0);
    // Listed, but not itself a loopback host: loopback, link-local and metadata addresses stay
    // refused (defence in depth), before any request.
    for (const addresses of [['127.0.0.1'], ['10.0.0.8', '169.254.169.254']]) {
      const err = await failure(viaName(true, addresses).currentUser());
      expect(err).toMatchObject({ kind: 'refused', reason: 'not_public', status: null });
    }
    expect(fake.requests).toHaveLength(0);
    // Listed as localhost: the connection goes to the checked loopback address, never resolving
    // the name again.
    expect((await viaName(true, ['127.0.0.1'], 'localhost').currentUser()).id).toBe(fake.botUserId);
    expect(fake.requests).toHaveLength(1);
  });

  it('checks merge request ids, note ids and revisions before putting them into a path', async () => {
    const c = client();
    for (const iid of ['', '12/../../user', '1e3', '-1', '12345678901', '12?x=1']) {
      expect(await failure(c.mergeRequest('7', iid)), iid).toMatchObject({
        kind: 'refused',
        reason: 'invalid_input',
      });
      expect((await failure(c.discussions('7', iid, 1))).reason).toBe('invalid_input');
    }
    expect((await failure(c.updateNote('7', '12', 1.5, 'x'))).reason).toBe('invalid_input');
    const input = {
      state: 'success' as const,
      name: 'qualor/quality-gate',
      description: 'x',
      targetUrl: null,
      pipelineId: null,
      ref: null,
    };
    for (const revision of ['', 'HEAD', 'A'.repeat(40), `${'a'.repeat(40)}/../x`, 'a'.repeat(39)]) {
      expect((await failure(c.setCommitStatus('7', revision, input))).reason, revision).toBe(
        'invalid_input',
      );
      expect((await failure(c.commitStatuses('7', revision, 'x'))).reason, revision).toBe(
        'invalid_input',
      );
    }
    expect(fake.requests).toHaveLength(0);
  });

  it('reads who resolved a thread, so Qualor reopens only its own (scm.md §5.4, ruling G3)', async () => {
    const c = client();
    const created = await c.createDiscussion('7', '12', 'mine', {
      baseSha: BASE,
      startSha: BASE,
      headSha: HEAD,
      oldPath: 'src/a.ts',
      newPath: 'src/a.ts',
      newLine: 2,
    });
    if (created === 'position_rejected') throw new Error('expected a discussion');
    const thread = async () =>
      (await c.discussions('7', '12', 50)).items.find((d) => d.id === created.id)?.notes[0];
    expect((await thread())?.resolved_by ?? null).toBeNull();
    await c.resolveDiscussion('7', '12', created.id, true);
    expect(await thread()).toMatchObject({ resolved: true, resolved_by: { id: fake.botUserId } });
    fake.resolveAs(7, 12, created.id, 5, false);
    fake.resolveAs(7, 12, created.id, 5, true);
    expect(await thread()).toMatchObject({ resolved: true, resolved_by: { id: 5 } });
  });

  it('treats only a 400 about the position as a rejected position', async () => {
    const position = {
      baseSha: BASE,
      startSha: BASE,
      headSha: HEAD,
      oldPath: 'src/a.ts',
      newPath: 'src/a.ts',
      newLine: 2,
    };
    fake.inject('POST', /\/discussions$/, {
      status: 400,
      body: { message: { body: ["can't be blank"] } },
    });
    expect(await failure(client().createDiscussion('7', '12', 'x', position))).toMatchObject({
      kind: 'refused',
      status: 400,
      message: 'GitLab answered HTTP 400',
    });
    fake.inject('POST', /\/discussions$/, {
      status: 400,
      body: { message: '400 Bad request - Note {:line_code=>["must be a valid line code"]}' },
    });
    expect(await client().createDiscussion('7', '12', 'x', position)).toBe('position_rejected');
  });

  it('follows a moved project once, on the same GitLab, under /api/v4/projects/ (GET only)', async () => {
    const moved = (location: string) => ({ status: 301, headers: { location } });
    // The old path answers 301 to the numeric id; the rest of the path and the query are kept.
    fake.inject('GET', /^\/projects\/old%2Fname$/, moved(`${fake.url}/api/v4/projects/7`));
    expect((await client().project('old/name')).id).toBe(7);
    expect(fake.requests.map((r) => r.path)).toEqual(['/projects/old%2Fname', '/projects/7']);
    expect(fake.requests[1]?.headers['private-token']).toBe(fake.token);
    fake.clearRequests();
    fake.inject(
      'GET',
      /^\/projects\/old%2Fname\/merge_requests\/12$/,
      moved(`${fake.url}/api/v4/projects/7/merge_requests/12?x=1`),
    );
    expect((await client().mergeRequest('old/name', '12')).iid).toBe(12);
    expect(fake.requests.map((r) => `${r.path}?${r.query}`)).toEqual([
      '/projects/old%2Fname/merge_requests/12?',
      '/projects/7/merge_requests/12?x=1',
    ]);
    for (const status of [302, 307, 308]) {
      fake.clearRequests();
      fake.inject('GET', /^\/projects\/old%2Fname$/, {
        status,
        headers: { location: `${fake.url}/api/v4/projects/7` },
      });
      expect((await client().project('old/name')).id).toBe(7);
    }
    // A second redirect is refused.
    fake.clearRequests();
    fake.inject('GET', /^\/projects\/old%2Fname$/, moved(`${fake.url}/api/v4/projects/8`));
    fake.inject('GET', /^\/projects\/8$/, moved(`${fake.url}/api/v4/projects/7`));
    expect(await failure(client().project('old/name'))).toMatchObject({
      kind: 'refused',
      message: 'GitLab answered HTTP 301',
    });
    expect(fake.requests).toHaveLength(2);
  });

  it('refuses a redirect to another origin or outside /api/v4/projects/, and never follows a non-GET', async () => {
    const bad = [
      'https://evil.example/api/v4/projects/7',
      'http://127.0.0.1:1/api/v4/projects/7',
      `${fake.url}/api/v4/user`,
      `${fake.url}/api/v4/projects/../user`,
      `${fake.url}/api/v4/projects`,
      `${fake.url}/other/api/v4/projects/7`,
      '//evil.example/api/v4/projects/7',
      fake.url.replace('://', '://u:p@') + '/api/v4/projects/7',
      '',
    ];
    for (const location of bad) {
      fake.clearRequests();
      fake.inject('GET', /^\/projects\/old%2Fname$/, {
        status: 301,
        headers: location ? { location } : {},
      });
      expect(await failure(client().project('old/name')), location).toMatchObject({
        kind: 'refused',
        message: 'GitLab answered HTTP 301',
      });
      expect(fake.requests, location).toHaveLength(1);
    }
    fake.clearRequests();
    fake.inject('GET', /^\/user$/, {
      status: 301,
      headers: { location: `${fake.url}/api/v4/user` },
    });
    await failure(client().currentUser());
    expect(fake.requests).toHaveLength(1);
    fake.clearRequests();
    fake.inject('POST', /^\/projects\/7\/statuses\//, {
      status: 307,
      headers: { location: `${fake.url}/api/v4/projects/7/statuses/x` },
    });
    expect(
      await failure(
        client().setCommitStatus('7', 'a'.repeat(40), {
          state: 'success',
          name: 'qualor/app',
          description: 'd',
          targetUrl: null,
          pipelineId: null,
          ref: 'main',
        }),
      ),
    ).toMatchObject({ kind: 'refused', message: 'GitLab answered HTTP 307' });
    expect(fake.requests).toHaveLength(1);
  });

  it('counts the redirect hop against the request budget', async () => {
    fake.inject('GET', /^\/projects\/old%2Fname$/, {
      status: 301,
      headers: { location: `${fake.url}/api/v4/projects/7` },
    });
    expect(await failure(client({ maxRequests: 1 }).project('old/name'))).toMatchObject({
      kind: 'budget',
    });
    expect(fake.requests).toHaveLength(1);
  });

  it("never puts GitLab's words or the token in an error", async () => {
    fake.inject('GET', /^\/projects\/7$/, {
      status: 422,
      body: { message: `token ${fake.token} is <b>invalid</b>` },
    });
    const err = await failure(client().project('7'));
    expect(err.message).toBe('GitLab answered HTTP 422');
    // GitLab's own message is kept for decisions only: not enumerable (a logger serialising the
    // error never sees it), and without the token even if GitLab echoed it.
    expect(Object.keys(err)).not.toContain('gitlabMessage');
    expect(JSON.stringify(err)).not.toContain('invalid');
    expect(err.gitlabMessage).toBe('token [token] is <b>invalid</b>');
    expect(err.message).not.toContain(fake.token);
    expect(String(err.stack)).not.toContain(fake.token);
    expect(JSON.stringify(client())).not.toContain(fake.token);
  });
});

describe('gitlabRoute: a request as a fixed text for the logs', () => {
  it('names every value Qualor put in the path, and drops the query', () => {
    const sha = 'b'.repeat(40);
    const cases: [string, string, string][] = [
      ['GET', '/user', 'GET /user'],
      ['GET', '/projects?membership=true&per_page=100', 'GET /projects'],
      ['GET', '/projects/group%2Fapp', 'GET /projects/{id}'],
      ['GET', '/projects/42/languages', 'GET /projects/{id}/languages'],
      [
        'GET',
        '/projects/group%2Fapp/repository/branches/qualor%2Fsetup',
        'GET /projects/{id}/repository/branches/{branch}',
      ],
      [
        'GET',
        '/projects/42/repository/files/.gitlab-ci.yml/raw?ref=main',
        'GET /projects/{id}/repository/files/{path}/raw',
      ],
      ['POST', '/projects/42/repository/commits', 'POST /projects/{id}/repository/commits'],
      ['PUT', '/projects/42/variables/QUALOR_TOKEN', 'PUT /projects/{id}/variables/{key}'],
      ['POST', `/projects/42/statuses/${sha}`, 'POST /projects/{id}/statuses/{sha}'],
      [
        'PUT',
        `/projects/42/merge_requests/7/discussions/${sha}?resolved=true`,
        'PUT /projects/{id}/merge_requests/{id}/discussions/{id}',
      ],
      ['GET', '/projects/42/members/all/9', 'GET /projects/{id}/members/all/{id}'],
    ];
    for (const [method, target, route] of cases) {
      expect(gitlabRoute(method as 'GET', target)).toBe(route);
    }
  });
});
