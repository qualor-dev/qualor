import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AZURE_REPOSITORY, recordingListener } from '../../test/azure-pending';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { SCM_TOKEN_AAD } from '../scm/connections';
import type { GitHubClient, GitHubComment } from '../scm/github/client';
import { GitLabClient, GitLabError, type GitLabDiscussion } from '../scm/gitlab/client';
import { issueMarker } from '../scm/markdown';
import { ScmError } from '../scm/provider';
import { createScmRuntime } from '../scm/runtime';
import { parseInternalHosts } from '../scm/url';
import type { ReplyRow } from './replies';
import {
  githubCommandSide,
  githubSide,
  gitlabCommandSide,
  gitlabSide,
  providerClientOf,
  type ReplyInThread,
} from './reply-sides';

/*
 * Whether the author of a command's note has the rights `qualor review` needs, and whether the
 * authors of a reply may change a finding's status (6I-4): the same rights, read through the same
 * functions, and failing closed. The sides are driven here by clients that answer from a list, so that every way the
 * author may be unknown is reached; the answer job's tests (reply-job.db.test.ts) run the whole
 * flow through the provider fakes.
 */

const NOTE = 41;
const ROW = {
  id: '01920000-0000-7000-8000-0000000000cc',
  noteId: NOTE,
  author: 'octocat',
} as ReplyRow;
const REF = '77';
const REPO = { owner: 'acme', repo: 'shop' };

/** What the sides say when an answer of the provider's is not understood. */
const warnings: unknown[][] = [];
const logger = { warn: (...args: unknown[]) => void warnings.push(args) };

describe('whether the author of a command on GitLab has the rights `qualor review` needs', () => {
  /** The command's discussion as GitLab lists it: the person's note, written by user `author`. */
  const discussion = (author: number, noteId = NOTE): GitLabDiscussion => ({
    id: 'abc123',
    individual_note: true,
    notes: [
      {
        id: noteId,
        body: 'qualor review',
        author: { id: author, username: `user${author}` },
        created_at: '2026-10-25T10:00:00Z',
        system: false,
      },
    ],
  });
  /** A client whose listings are `listings`, one for each read, and whose members have `levels`. */
  const client = (
    listings: { items: GitLabDiscussion[]; complete: boolean }[],
    levels: Record<number, number | null | Error> = {},
  ) => {
    const discussions = vi.fn();
    for (const listing of listings) discussions.mockResolvedValueOnce(listing);
    const memberAccessLevel = vi.fn(async (_ref: string, userId: number) => {
      const found = levels[userId] ?? null;
      if (found instanceof Error) throw found;
      return found;
    });
    const stub = {
      currentUser: async () => ({ id: 1, username: 'qualor' }),
      discussions,
      memberAccessLevel,
    } as unknown as GitLabClient;
    return { stub, memberAccessLevel };
  };
  const side = (stub: GitLabClient) =>
    gitlabCommandSide('c1', stub, REF, '12', ROW, 'abc123', logger);

  it.each([
    [30, true],
    [40, true],
    [50, true],
    [20, false],
    [10, false],
    [null, false],
  ] as const)(
    'a member of level %s: %s, by one request for the author the note names',
    async (level, may) => {
      const { stub, memberAccessLevel } = client([{ items: [discussion(5)], complete: true }], {
        5: level,
      });
      const commandSide = side(stub);
      expect(await commandSide.read()).toEqual({ answered: null });
      expect(await commandSide.mayReview()).toBe(may);
      expect(memberAccessLevel).toHaveBeenCalledExactlyOnceWith(REF, 5);
    },
  );

  it('a command whose note its discussion no longer holds is gone, though a reply stays in it', async () => {
    // A discussion is listed with all its notes: this one holds another person's note and not the
    // command's, which was deleted. A listing cut at its page bound lists it whole all the same.
    for (const complete of [true, false]) {
      const { stub, memberAccessLevel } = client([{ items: [discussion(5, NOTE + 1)], complete }], {
        5: 30,
      });
      const commandSide = side(stub);
      expect(await commandSide.read()).toBeNull();
      expect(await commandSide.mayReview()).toBe(false);
      expect(memberAccessLevel).not.toHaveBeenCalled();
    }
  });

  it('a discussion the listing does not show is gone when the listing is whole; its author is unknown, with no request, when it is cut', async () => {
    const whole = client([{ items: [], complete: true }], { 5: 30 });
    const wholeSide = side(whole.stub);
    expect(await wholeSide.read()).toBeNull();
    expect(await wholeSide.mayReview()).toBe(false);
    const cut = client([{ items: [], complete: false }], { 5: 30 });
    const cutSide = side(cut.stub);
    expect(await cutSide.read()).toEqual({ answered: null });
    expect(await cutSide.mayReview()).toBe(false);
    // No read at all: nobody is known.
    const unread = client([], { 5: 30 });
    expect(await side(unread.stub).mayReview()).toBe(false);
    for (const { memberAccessLevel } of [whole, cut, unread]) {
      expect(memberAccessLevel).not.toHaveBeenCalled();
    }
  });

  it('is never the author of an earlier read: what a read does not find it does not know', async () => {
    const second = [
      // The discussion no longer holds the note; it is not listed in a listing cut at its page
      // bound; it is gone from a listing read whole.
      { items: [discussion(5, NOTE + 1)], complete: true },
      { items: [], complete: false },
      { items: [], complete: true },
    ];
    for (const listing of second) {
      const { stub, memberAccessLevel } = client(
        [{ items: [discussion(5)], complete: true }, listing],
        { 5: 30 },
      );
      const commandSide = side(stub);
      await commandSide.read();
      expect(await commandSide.mayReview()).toBe(true);
      await commandSide.read();
      expect(await commandSide.mayReview()).toBe(false);
      expect(memberAccessLevel).toHaveBeenCalledTimes(1);
    }
  });
});

describe('a membership answer of GitLab that does not parse', () => {
  const discussion: GitLabDiscussion = {
    id: 'abc123',
    individual_note: true,
    notes: [
      {
        id: NOTE,
        body: 'qualor review',
        author: { id: 5, username: 'user5' },
        created_at: '2026-10-25T10:00:00Z',
        system: false,
      },
    ],
  };
  const odd = () => new ScmError('bad_answer', 'GitLab answered something unexpected');
  const down = () => new ScmError('transient', 'GitLab could not be reached');
  const stubOf = (failure: Error) =>
    ({
      currentUser: async () => ({ id: 1, username: 'qualor' }),
      discussions: async () => ({ items: [discussion], complete: true }),
      memberAccessLevel: async () => {
        throw failure;
      },
    }) as unknown as GitLabClient;

  it('gives the author of a command no rights, said in one line without its text; any other error is thrown', async () => {
    warnings.length = 0;
    const oddSide = gitlabCommandSide('c1', stubOf(odd()), REF, '12', ROW, 'abc123', logger);
    await oddSide.read();
    expect(await oddSide.mayReview()).toBe(false);
    expect(warnings).toEqual([
      [{ replyId: ROW.id }, 'GitLab membership answer not understood; the command is refused'],
    ]);
    const downSide = gitlabCommandSide('c1', stubOf(down()), REF, '12', ROW, 'abc123', logger);
    await downSide.read();
    await expect(downSide.mayReview()).rejects.toThrow('GitLab could not be reached');
  });

  it('names the field GitLab answered unreadably, never what it held', async () => {
    warnings.length = 0;
    const lastDay = new GitLabError('bad_answer', "GitLab's answer was not understood", {
      field: 'expires_at',
    });
    const oddSide = gitlabCommandSide('c1', stubOf(lastDay), REF, '12', ROW, 'abc123', logger);
    await oddSide.read();
    expect(await oddSide.mayReview()).toBe(false);
    expect(warnings).toEqual([
      [
        { replyId: ROW.id, field: 'expires_at' },
        'GitLab membership answer not understood; the command is refused',
      ],
    ]);
  });

  describe('in the thread of a reply', () => {
    const ISSUE = '01920000-0000-7000-8000-0000000000aa';
    const REPLY = {
      ...ROW,
      threadId: 'abc123',
      issueId: ISSUE,
    } as ReplyInThread;
    /** Qualor's thread (user 1) with a reply by user 5, as GitLab lists it. */
    const thread: GitLabDiscussion = {
      id: 'abc123',
      individual_note: false,
      notes: [
        {
          id: 40,
          body: `${issueMarker(ISSUE)}\nA finding.`,
          author: { id: 1, username: 'qualor' },
          created_at: '2026-10-25T09:00:00Z',
          system: false,
        },
        {
          id: NOTE,
          body: 'We accept this.',
          author: { id: 5, username: 'user5' },
          created_at: '2026-10-25T10:00:00Z',
          system: false,
        },
      ],
    };
    const threadStub = (failure: Error) =>
      ({
        ...stubOf(failure),
        discussions: async () => ({ items: [thread], complete: true }),
      }) as unknown as GitLabClient;

    it('gives the authors of a round no rights, said in one line without its text; any other error is thrown', async () => {
      warnings.length = 0;
      const oddSide = gitlabSide('c1', threadStub(odd()), REF, '12', REPLY, logger);
      await oddSide.read();
      expect(await oddSide.mayChangeStatus([NOTE])).toBe(false);
      expect(warnings).toEqual([
        [
          { replyId: ROW.id },
          'GitLab membership answer not understood; the reply changes no status',
        ],
      ]);
      const downSide = gitlabSide('c1', threadStub(down()), REF, '12', REPLY, logger);
      await downSide.read();
      await expect(downSide.mayChangeStatus([NOTE])).rejects.toThrow('GitLab could not be reached');
    });
  });
});

describe('a GitLab project that moved, mapped by its old path', () => {
  // GitLab answers a GET through a moved project's old path with a 301 to its id, which the client
  // follows, and refuses a POST or a PUT there (405). The sides ask for the id once, and every call
  // after that goes through it, as a decoration's do.
  const ISSUE = '01920000-0000-7000-8000-0000000000aa';
  const OLD = 'acme/old-name';
  const HEAD = 'a'.repeat(40);
  const BASE = 'b'.repeat(40);
  let fake: FakeGitLab;
  const client = () =>
    new GitLabClient(
      { baseUrl: fake.url, token: fake.token, allowInternalHosts: true },
      { timeoutMs: 1_000 },
    );
  /** What reached GitLab, as `METHOD path`. */
  const sent = () => fake.requests.map((r) => `${r.method} ${r.path}`);

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 7, path: 'acme/new-name' });
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
          diff: '@@ -1,1 +1,2 @@\n export const a = 1;\n+console.log(a);\n',
        },
      ],
    });
    fake.moveProject(7, OLD);
    fake.setMember(7, 5, 30);
  });
  afterAll(() => fake.close());

  it('posts the answer to a reply and resolves its thread through the project id', async () => {
    const opened = await client().createDiscussion('7', '12', `${issueMarker(ISSUE)}\nA finding.`, {
      baseSha: BASE,
      startSha: BASE,
      headSha: HEAD,
      oldPath: 'src/a.ts',
      newPath: 'src/a.ts',
      newLine: 2,
    });
    if (opened === 'position_rejected') throw new Error('the position was rejected');
    const said = fake.reply(7, 12, opened.id, { body: 'We accept this.', authorId: 5 });
    const reply = { ...ROW, noteId: said.id, threadId: opened.id, issueId: ISSUE } as ReplyInThread;
    fake.clearRequests();
    const side = gitlabSide('c1', client(), OLD, '12', reply, logger);
    expect(await side.read()).toMatchObject({ notes: [{ id: said.id }], resolved: false });
    expect(await side.mayChangeStatus([said.id])).toBe(true);
    const answer = await side.post('The answer.');
    expect(await side.resolve()).toBe(true);
    const thread = fake.discussions(7, 12).find((d) => d.id === opened.id);
    expect(thread?.notes.at(-1)).toMatchObject({ id: answer, authorId: fake.botUserId });
    expect(thread?.notes.every((n) => n.resolved)).toBe(true);
    // The old path is asked once, for the id; nothing is written through it.
    expect(sent().filter((r) => r.includes(encodeURIComponent(OLD)))).toEqual([
      `GET /projects/${encodeURIComponent(OLD)}`,
    ]);
    expect(sent().filter((r) => !r.startsWith('GET'))).toEqual([
      `POST /projects/7/merge_requests/12/discussions/${opened.id}/notes`,
      `PUT /projects/7/merge_requests/12/discussions/${opened.id}`,
    ]);
  });

  it('posts the answer to a command through the project id', async () => {
    const opened = fake.addNote(7, 12, { body: 'qualor review', authorId: 5 });
    const row = { ...ROW, noteId: opened.notes[0]!.id } as ReplyRow;
    fake.clearRequests();
    const side = gitlabCommandSide('c1', client(), OLD, '12', row, opened.id, logger);
    expect(await side.read()).toEqual({ answered: null });
    expect(await side.mayReview()).toBe(true);
    const answer = await side.post('Reviewing.');
    const discussion = fake.discussions(7, 12).find((d) => d.id === opened.id);
    expect(discussion?.notes.at(-1)).toMatchObject({ id: answer, authorId: fake.botUserId });
    expect(sent().filter((r) => r.includes(encodeURIComponent(OLD)))).toEqual([
      `GET /projects/${encodeURIComponent(OLD)}`,
    ]);
    expect(sent().filter((r) => !r.startsWith('GET'))).toEqual([
      `POST /projects/7/merge_requests/12/discussions/${opened.id}/notes`,
    ]);
  });

  it('a project GitLab does not have is not found, as each side’s other answers are', async () => {
    const reply = { ...ROW, threadId: 'abc123', issueId: ISSUE } as ReplyInThread;
    await expect(
      gitlabSide('c1', client(), 'acme/nowhere', '12', reply, logger).read(),
    ).rejects.toMatchObject({ kind: 'not_found' });
    await expect(
      gitlabCommandSide('c1', client(), 'acme/nowhere', '12', ROW, 'abc123', logger).post('x'),
    ).rejects.toMatchObject({ kind: 'not_found' });
  });
});

describe('the resolution of a reply’s thread on GitHub', () => {
  const ISSUE = '01920000-0000-7000-8000-0000000000aa';
  const FIRST = 3_000_000_001;
  const REPLY = { ...ROW, threadId: String(FIRST), issueId: ISSUE } as ReplyInThread;
  /** A client that lists Qualor's thread of the issue, and answers its resolution with `answer`. */
  const stub = (answer: 'done' | 'not_found' | 'refused') => {
    const setThreadResolved = vi.fn(async () => answer);
    const client = {
      app: async () => ({ id: 1, slug: 'qualor' }),
      useRepository: async () => ({}),
      reviewComments: async () => ({
        items: [
          {
            id: FIRST,
            node_id: 'PRRC_first',
            body: `${issueMarker(ISSUE)}\nA finding.`,
            user: { login: 'qualor[bot]', type: 'Bot' },
            created_at: '2026-10-25T09:00:00Z',
          },
        ],
        complete: true,
      }),
      reviewThreads: async () => ({
        items: [
          {
            id: 'PRRT_thread',
            isResolved: false,
            resolvedByLogin: null,
            firstCommentNodeId: 'PRRC_first',
          },
        ],
        complete: true,
      }),
      setThreadResolved,
    } as unknown as GitHubClient;
    return { client, setThreadResolved };
  };

  it.each([
    ['done', true],
    // GitHub no longer has the thread: the job reads this as it always has, and ends the row.
    ['not_found', false],
    // The App may not resolve it (it lacks Contents: write): the thread stays open.
    ['refused', 'refused'],
  ] as const)('GitHub answers %s: the side answers %s', async (answer, resolved) => {
    const { client, setThreadResolved } = stub(answer);
    const side = githubSide('c1', client, REPO, '7', REPLY, logger);
    expect(await side.read()).toMatchObject({ resolved: false });
    expect(await side.resolve()).toBe(resolved);
    expect(setThreadResolved).toHaveBeenCalledExactlyOnceWith('PRRT_thread', true);
  });

  it('resolves nothing before it has read the thread', async () => {
    const { client, setThreadResolved } = stub('done');
    expect(await githubSide('c1', client, REPO, '7', REPLY, logger).resolve()).toBe(false);
    expect(setThreadResolved).not.toHaveBeenCalled();
  });
});

describe('whether the author of a command on GitHub has the rights `qualor review` needs', () => {
  /** The command's comment on the pull request's page, written by `login` (null: an account that is gone). */
  const comment = (login: string | null, id = NOTE): GitHubComment => ({
    id,
    body: 'qualor review',
    user: login === null ? null : { login, type: 'User' },
    created_at: '2026-10-25T10:00:00Z',
  });
  type Permission = { permission: string; roleName: string | null } | null;
  /** A client whose listings are `listings`, one for each read, and whose accounts have `permissions`. */
  const client = (
    listings: { items: GitHubComment[]; complete: boolean }[],
    permissions: Record<string, Permission | Error> = {},
  ) => {
    const issueComments = vi.fn();
    for (const listing of listings) issueComments.mockResolvedValueOnce(listing);
    const repositoryPermission = vi.fn(async (login: string) => {
      const found = permissions[login] ?? null;
      if (found instanceof Error) throw found;
      return found;
    });
    const stub = {
      app: async () => ({ id: 1, slug: 'qualor' }),
      useRepository: async () => ({}),
      issueComments,
      repositoryPermission,
    } as unknown as GitHubClient;
    return { stub, repositoryPermission };
  };
  const side = (stub: GitHubClient) => githubCommandSide('c1', stub, REPO, '7', ROW, logger);

  it.each([
    { name: 'write', permission: { permission: 'write', roleName: 'write' }, may: true },
    { name: 'maintain', permission: { permission: 'write', roleName: 'maintain' }, may: true },
    { name: 'admin', permission: { permission: 'admin', roleName: 'admin' }, may: true },
    { name: 'triage', permission: { permission: 'read', roleName: 'triage' }, may: true },
    {
      name: 'a custom role on write',
      permission: { permission: 'write', roleName: 'security-lead' },
      may: true,
    },
    {
      name: 'no role named, write',
      permission: { permission: 'write', roleName: null },
      may: true,
    },
    { name: 'read', permission: { permission: 'read', roleName: 'read' }, may: false },
    {
      name: 'a custom role on read',
      permission: { permission: 'read', roleName: 'auditor' },
      may: false,
    },
    { name: 'no role named, read', permission: { permission: 'read', roleName: null }, may: false },
    { name: 'none', permission: { permission: 'none', roleName: 'none' }, may: false },
    { name: 'no permission', permission: null, may: false },
  ])(
    '$name: may ask for a review is $may, by one request for the login the comment names now',
    async ({ permission, may }) => {
      // The comment's author is the login it has now, not the one the ledger recorded.
      const { stub, repositoryPermission } = client(
        [{ items: [comment('hubot')], complete: true }],
        { hubot: permission },
      );
      const commandSide = side(stub);
      expect(await commandSide.read()).toEqual({ answered: null });
      expect(await commandSide.mayReview()).toBe(may);
      expect(repositoryPermission).toHaveBeenCalledExactlyOnceWith('hubot');
    },
  );

  it('a comment the listing does not show is gone when the listing is whole; its author is unknown, with no request, when it is cut', async () => {
    const whole = client([{ items: [comment('hubot', NOTE + 1)], complete: true }], {
      hubot: { permission: 'admin', roleName: 'admin' },
    });
    const wholeSide = side(whole.stub);
    expect(await wholeSide.read()).toBeNull();
    expect(await wholeSide.mayReview()).toBe(false);
    const cut = client([{ items: [comment('hubot', NOTE + 1)], complete: false }], {
      hubot: { permission: 'admin', roleName: 'admin' },
    });
    const cutSide = side(cut.stub);
    expect(await cutSide.read()).toEqual({ answered: null });
    expect(await cutSide.mayReview()).toBe(false);
    expect(whole.repositoryPermission).not.toHaveBeenCalled();
    expect(cut.repositoryPermission).not.toHaveBeenCalled();
  });

  it('an account that is gone, a login that is missing and no read at all have no rights, and none is asked for', async () => {
    const gone = client([{ items: [comment(null)], complete: true }]);
    const goneSide = side(gone.stub);
    expect(await goneSide.read()).toEqual({ answered: null });
    expect(await goneSide.mayReview()).toBe(false);
    const unread = client([]);
    expect(await side(unread.stub).mayReview()).toBe(false);
    expect(gone.repositoryPermission).not.toHaveBeenCalled();
    expect(unread.repositoryPermission).not.toHaveBeenCalled();
  });

  it('is never the login of an earlier read: what a read does not find it does not know', async () => {
    const second = [
      // The comment is not listed in a listing cut at its page bound, is gone from a listing read
      // whole, and is there again with an account that is gone.
      { items: [comment('hubot', NOTE + 1)], complete: false },
      { items: [], complete: true },
      { items: [comment(null)], complete: true },
    ];
    for (const listing of second) {
      const { stub, repositoryPermission } = client(
        [{ items: [comment('hubot')], complete: true }, listing],
        { hubot: { permission: 'admin', roleName: 'admin' } },
      );
      const commandSide = side(stub);
      await commandSide.read();
      expect(await commandSide.mayReview()).toBe(true);
      await commandSide.read();
      expect(await commandSide.mayReview()).toBe(false);
      expect(repositoryPermission).toHaveBeenCalledTimes(1);
    }
  });

  it('a permission answer that does not parse is no permission, said in one line without its text; any other error is thrown', async () => {
    warnings.length = 0;
    const odd = client([{ items: [comment('hubot')], complete: true }], {
      hubot: new ScmError('bad_answer', 'GitHub answered something unexpected'),
    });
    const oddSide = side(odd.stub);
    await oddSide.read();
    expect(await oddSide.mayReview()).toBe(false);
    expect(warnings).toEqual([
      [{ replyId: ROW.id }, 'GitHub permission answer not understood; the command is refused'],
    ]);
    const down = client([{ items: [comment('hubot')], complete: true }], {
      hubot: new ScmError('transient', 'GitHub could not be reached'),
    });
    const downSide = side(down.stub);
    await downSide.read();
    await expect(downSide.mayReview()).rejects.toThrow('GitHub could not be reached');
  });
});

describe('the side of a reply on Azure DevOps: not available yet (Azure sub-plan 2, Task 2)', () => {
  it('has no client, so replies and commands there are unusable, and nothing is sent', async () => {
    const listener = await recordingListener();
    try {
      const secretKey = 'reply-sides-test-key-of-at-least-32-characters';
      const connection = {
        id: randomUUID(),
        organizationId: randomUUID(),
        provider: 'azure' as const,
        baseUrl: `${listener.url}/DefaultCollection`,
        tokenEnc: encryptSecret(encryptionKey(secretKey), 'azure-pat-test', SCM_TOKEN_AAD),
        appId: null,
        webhookSecretEnc: null,
        ciSetupAllowed: false,
        fixMrsAllowed: false,
        azureAuth: 'pat' as const,
        azureTenantId: null,
        azureClientId: null,
        problem: null,
        createdAt: new Date(),
      };
      const scm = {
        secretKey,
        internalHosts: parseInternalHosts(listener.host),
        azureTokenOrigin: null,
        azureTestOrigin: null,
      };
      const target = {
        connection,
        project: { scmProjectRef: AZURE_REPOSITORY },
        branch: { name: '7' },
      };
      expect(providerClientOf({ scm, scmRuntime: createScmRuntime() }, target)).toBeNull();
      expect(listener.requests).toEqual([]);
    } finally {
      await listener.close();
    }
  });
});
