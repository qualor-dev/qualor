import { readdirSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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
  MAX_GITLAB_RESPONSE_BYTES,
  retryAfterSeconds,
} from './client';

const SHAPES_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/gitlab-shapes',
);
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);

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
    fake = await createFakeGitLab();
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
    };
    expect(files.sort()).toEqual(Object.keys(schemaOf).sort());
    for (const file of files) {
      const parsed = GITLAB_SHAPES[schemaOf[file]!].safeParse(gitlabShape(file.slice(0, -5)));
      expect(parsed.success, file).toBe(true);
    }
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

  it('reports 429 with its Retry-After, 5xx as transient, a redirect as refused', async () => {
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

  it("never follows a redirect and never puts GitLab's words or the token in an error", async () => {
    fake.inject('GET', /^\/user$/, {
      status: 301,
      headers: { location: `${fake.url}/api/v4/user` },
    });
    await failure(client().currentUser());
    expect(fake.requests).toHaveLength(1);
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
