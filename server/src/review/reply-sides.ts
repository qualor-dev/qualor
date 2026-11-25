import { assertNever } from '@qualor/shared';
import type { WorkerLogger } from '../queue/worker';
import {
  AZURE_PR_ID,
  azureThreadOpen,
  type AzureDevOpsClient,
  type AzureThread,
} from '../scm/azure/client';
import { azureClientFor } from '../scm/azure/connections';
import { azureMayTriage, azureTriageRight, type RightsLogger } from '../scm/azure/rights';
import { AZURE_REPOSITORY_ID } from '../scm/azure/url';
import { gitlabClientFor, type ScmConnectionRow } from '../scm/connections';
import {
  GITHUB_PR_NUMBER,
  MAX_THREAD_PAGES,
  type GitHubClient,
  type GitHubComment,
} from '../scm/github/client';
import { githubClientFor } from '../scm/github/connections';
import { MAX_COMMENT_PAGES } from '../scm/github/threads';
import { parseRepoRef, type GitHubRepoRef } from '../scm/github/url';
import {
  discussionResolved,
  GITLAB_MR_IID,
  GitLabError,
  type GitLabClient,
  type GitLabDiscussion,
  type GitLabUser,
  type Paged,
} from '../scm/gitlab/client';
import { MAX_DISCUSSION_PAGES } from '../scm/inline';
import { firstLineOf, markerOf, replyMarker } from '../scm/markdown';
import { ScmError } from '../scm/provider';
import { MAX_AUTHORS_LOOKED_UP } from '../scm/rights-limits';
import type { ReviewRight } from './commands';
import type { ReviewJobDeps } from './job';
import type { ReplyRow } from './replies';
import {
  azureAuthor,
  azureCommentsInOrder,
  azureNoteId,
  githubRounds,
  azureNoteable,
  writtenByPerson,
  writtenByQualor,
  type Round,
} from './reply-detect';
import type { ReplyWindow } from './reply-queue';

/*
 * The thread of a reply on its provider (6I-4), as the `ai-reply` job (reply-job.ts) reads it,
 * asks who may change a finding's status, posts its answer and resolves it: GitLab's discussion of
 * the merge request, GitHub's review thread of the pull request, or Azure DevOps' thread of the
 * pull request, each through the job's own client and its request budget. Beside them, where the
 * answer to a command goes: a reply in the discussion the command's note opened on GitLab, or in
 * the thread its comment opened on Azure DevOps, a comment on the page of the pull request on
 * GitHub; and whether the command's author has the rights a review asks for, which are the rights a
 * reply needs to change a status, by the same functions. And what a scan lists of a merge request's
 * notes, to find the replies and commands nobody has queued yet. All three are made of the same
 * parts: the client of the connection the project is mapped to (`providerClientOf`), Qualor's
 * identity on the provider and the listings, each with the page bounds decoration reads by (Azure
 * DevOps lists a pull request's threads in one answer, with no pages).
 */

/**
 * GitLab's Developer role: the least access level whose reply may change a finding's status, and
 * whose note may ask for a review.
 */
const GITLAB_DEVELOPER = 30;
/**
 * GitHub's roles of a repository whose people may change a finding's status through a reply, or
 * ask for a review.
 */
const GITHUB_TRIAGE_ROLES: ReadonlySet<string> = new Set(['admin', 'maintain', 'write', 'triage']);
/** GitHub's other built-in roles, which may not. */
const GITHUB_OTHER_ROLES: ReadonlySet<string> = new Set(['read', 'none']);
/** The base permissions of a custom role (any other role name) that may. */
const GITHUB_TRIAGE_PERMISSIONS: ReadonlySet<string> = new Set(['admin', 'write']);

/**
 * Whether a person with this permission on the repository may change a finding's status through a
 * reply, or ask for a review through a command: a role of admin, maintain, write or triage, or a
 * custom role whose base permission is admin or write. With no role named (an older GitHub
 * Enterprise Server), the legacy permission decides the same way: admin or write may. Nobody else
 * may: the read role, none, or no permission at all (null).
 */
function githubMayTriage(found: { permission: string; roleName: string | null } | null): boolean {
  if (found === null) return false;
  if (found.roleName !== null && GITHUB_TRIAGE_ROLES.has(found.roleName)) return true;
  if (found.roleName !== null && GITHUB_OTHER_ROLES.has(found.roleName)) return false;
  return GITHUB_TRIAGE_PERMISSIONS.has(found.permission);
}

/**
 * Whether the GitLab user may change a finding's status through a reply, or ask for a review
 * through a command: a membership in force (`memberAccessLevel`: an active user, in an active
 * membership that has not ended) of Developer or more. Nobody else may: no member, a Reporter, a
 * Guest. An answer of GitLab's that does not parse is no membership either: `unparsed` says so in
 * one line without its text, with the field that was not understood when the client names it, so
 * that one author's odd answer never fails the job.
 */
async function gitlabMayTriage(
  client: GitLabClient,
  ref: string,
  userId: number,
  unparsed: (field: string | null) => void,
): Promise<boolean> {
  let level: number | null;
  try {
    level = await client.memberAccessLevel(ref, userId);
  } catch (err) {
    if (!(err instanceof ScmError) || err.kind !== 'bad_answer') throw err;
    unparsed(err instanceof GitLabError ? err.field : null);
    return false;
  }
  return level !== null && level >= GITLAB_DEVELOPER;
}

/** The fields of the warn line of a membership answer that was not understood. */
const unparsedFields = (replyId: string, field: string | null) => ({
  replyId,
  ...(field === null ? {} : { field }),
});

/**
 * The login's permission on the repository (`repositoryPermission`: none for a login GitHub could
 * not have, asked with no request). An answer of GitHub's that does not parse is no permission
 * either: `unparsed` says so in one line without its text, so that one author's odd answer never
 * fails the job.
 */
async function githubPermissionOf(client: GitHubClient, login: string, unparsed: () => void) {
  try {
    return await client.repositoryPermission(login);
  } catch (err) {
    if (!(err instanceof ScmError) || err.kind !== 'bad_answer') throw err;
    unparsed();
    return null;
  }
}

/** The client of a merge request's connection, with the ids of the merge request on its provider. */
export type ProviderClient =
  | { provider: 'gitlab'; client: GitLabClient; ref: string; iid: string }
  | { provider: 'github'; client: GitHubClient; repo: GitHubRepoRef; number: string }
  | { provider: 'azure'; client: AzureDevOpsClient; repositoryId: string; prId: number };

/**
 * The client for the merge request of `target`, with its own request budget (one client for each
 * job), as the `scm` worker's jobs make theirs: the key decrypted and the address checked against
 * the rules of now, a GitHub client sharing the worker's installation tokens and pacer, an Azure
 * DevOps client its Microsoft Entra tokens. Null when there is none: the project is not mapped
 * (the connection is null), the client cannot be made (a key that no longer decrypts, an address
 * the rules no longer allow) or the ids are none of the provider's.
 */
export function providerClientOf(
  deps: Pick<ReviewJobDeps, 'scm' | 'scmRuntime'>,
  target: {
    connection: ScmConnectionRow | null;
    project: { scmProjectRef: string | null };
    branch: { name: string };
  },
): ProviderClient | null {
  const { connection, project, branch } = target;
  if (connection === null || project.scmProjectRef === null) return null;
  switch (connection.provider) {
    case 'github': {
      const repo = parseRepoRef(project.scmProjectRef);
      const found = githubClientFor(connection, deps.scm, deps.scmRuntime);
      if (repo === null || 'problem' in found || !GITHUB_PR_NUMBER.test(branch.name)) return null;
      return { provider: 'github', client: found.client, repo, number: branch.name };
    }
    case 'gitlab': {
      const found = gitlabClientFor(connection, deps.scm);
      if ('problem' in found || !GITLAB_MR_IID.test(branch.name)) return null;
      return {
        provider: 'gitlab',
        client: found.client,
        ref: project.scmProjectRef,
        iid: branch.name,
      };
    }
    case 'azure': {
      const ref = project.scmProjectRef;
      if (!AZURE_REPOSITORY_ID.test(ref) || !AZURE_PR_ID.test(branch.name)) return null;
      const found = azureClientFor(connection, deps.scm, deps.scmRuntime);
      if ('problem' in found) return null;
      return {
        provider: 'azure',
        client: found.client,
        repositoryId: ref,
        prId: Number(branch.name),
      };
    }
    default:
      return assertNever(connection.provider, 'provider');
  }
}

/**
 * The project's id on GitLab, asked for once through `ref`, its path or its id. GitLab sends a GET
 * through a moved project's old path on to its id, and the client follows it; a POST or a PUT
 * there is refused. So a side makes every call through the id, as a decoration does. A ref that is
 * a number is the id already, with no request.
 */
function gitlabProjectId(client: GitLabClient, ref: string): () => Promise<string> {
  let id = /^\d+$/.test(ref) ? ref : undefined;
  return async () => (id ??= String((await client.project(ref)).id));
}

/** Who Qualor is on GitLab, and the merge request's discussions, each with all its notes. */
async function gitlabListing(
  client: GitLabClient,
  ref: string,
  iid: string,
): Promise<{ me: GitLabUser; listed: Paged<GitLabDiscussion> }> {
  const me = await client.currentUser();
  return { me, listed: await client.discussions(ref, iid, MAX_DISCUSSION_PAGES) };
}

/**
 * Qualor's login on GitHub, `<slug>[bot]` as the App names itself (github.md §6.3); the client is
 * pointed at the repository.
 */
async function githubBotLogin(client: GitHubClient, repo: GitHubRepoRef): Promise<string> {
  const app = await client.app();
  await client.useRepository(repo);
  return `${app.slug}[bot]`;
}

/** A row of a reply: in a thread, about an issue. */
export type ReplyInThread = ReplyRow & { threadId: string; issueId: string };

/** A person's note in the thread, as the model is given it. */
export interface ThreadNote {
  id: number;
  author: string;
  body: string;
}

/** The thread as the job reads it again. */
export interface ReadThread {
  /** Qualor's first note, as it was posted. */
  firstNote: string;
  /** The people's notes after it, oldest first. */
  notes: ThreadNote[];
  /** The note of Qualor's whose first line names the row: its answer, posted already. */
  answered: number | null;
  resolved: boolean;
}

/** The thread on its provider, through the job's own client and its request budget. */
export interface ThreadSide {
  /** The SCM connection the requests are made through, whose circuit they pass. */
  connectionId: string;
  /** The thread again; null when it is not there, or cannot be read whole. */
  read(): Promise<ReadThread | null>;
  /** Whether every author of the notes `noteIds` (of the last read) may change a finding's status. */
  mayChangeStatus(noteIds: readonly number[]): Promise<boolean>;
  /** Posts `body` in the thread: answers the new note's id. */
  post(body: string): Promise<number>;
  /**
   * Resolves the thread: false when the provider no longer has it, `refused` when the provider
   * does not let Qualor resolve it (a GitHub App without Contents: write), which leaves it open.
   */
  resolve(): Promise<boolean | 'refused'>;
}

/** What the provider says when it has no such thing: the thread is gone, however it says it. */
export const GONE = Symbol('gone');

/** What `step` answers, or GONE when the provider says it has nothing of the kind (`not_found`). */
export async function orGone<T>(step: () => Promise<T>): Promise<T | typeof GONE> {
  try {
    return await step();
  } catch (err) {
    if (err instanceof ScmError && err.kind === 'not_found') return GONE;
    throw err;
  }
}

/** Whether a note opens with the issue marker of `issueId`: the first note of the issue's thread. */
const marksIssue = (body: string, issueId: string): boolean => {
  const marker = markerOf(body);
  return marker?.kind === 'issue' && marker.issueId === issueId;
};

/** `logger`, whose warnings also name the reply they are about (as GitLab's do). */
const forReply = (logger: Pick<WorkerLogger, 'warn'>, replyId: string): RightsLogger => ({
  warn: (details: object, message: string) => logger.warn({ ...details, replyId }, message),
});

/**
 * The thread on GitLab: the merge request's discussion of the row. `logger` says when a
 * membership GitLab answered is not understood.
 */
export function gitlabSide(
  connectionId: string,
  client: GitLabClient,
  ref: string,
  iid: string,
  row: ReplyInThread,
  logger: Pick<WorkerLogger, 'warn'>,
): ThreadSide {
  /** The GitLab user of each person's note the last read found. */
  const authorOf = new Map<number, number>();
  const projectId = gitlabProjectId(client, ref);
  const mayTriage = async (userId: number) =>
    gitlabMayTriage(client, await projectId(), userId, (field) =>
      logger.warn(
        unparsedFields(row.id, field),
        'GitLab membership answer not understood; the reply changes no status',
      ),
    );
  return {
    connectionId,
    async read() {
      const { me, listed } = await gitlabListing(client, await projectId(), iid);
      // A discussion is listed with all its notes: one that is listed is whole.
      const discussion = listed.items.find((d) => d.id === row.threadId);
      const [first, ...later] = discussion?.notes ?? [];
      if (discussion === undefined || first === undefined) return null;
      if (first.system || first.author.id !== me.id || !marksIssue(first.body, row.issueId)) {
        return null;
      }
      const people = later.filter((note) => !note.system && note.author.id !== me.id);
      for (const note of people) authorOf.set(note.id, note.author.id);
      const marker = replyMarker(row.id);
      const answer = later.find(
        (note) => !note.system && note.author.id === me.id && firstLineOf(note.body) === marker,
      );
      return {
        firstNote: first.body,
        notes: people.map((note) => ({
          id: note.id,
          author: note.author.username,
          body: note.body,
        })),
        answered: answer?.id ?? null,
        resolved: discussionResolved(discussion),
      };
    },
    async mayChangeStatus(noteIds) {
      const authors = [...new Set(noteIds.map((id) => authorOf.get(id)))];
      if (authors.length > MAX_AUTHORS_LOOKED_UP) return false;
      for (const userId of authors) {
        if (userId === undefined) return false;
        if (!(await mayTriage(userId))) return false;
      }
      return true;
    },
    post: async (body) =>
      (await client.replyToDiscussion(await projectId(), iid, row.threadId, body)).id,
    async resolve() {
      const done = await orGone(async () =>
        client.resolveDiscussion(await projectId(), iid, row.threadId, true),
      );
      return done !== GONE;
    },
  };
}

/**
 * The thread on GitHub: the review thread whose first comment is the row's thread id. `logger` says
 * when a permission GitHub answered is not understood.
 */
export function githubSide(
  connectionId: string,
  client: GitHubClient,
  repo: GitHubRepoRef,
  number: string,
  row: ReplyInThread,
  logger: Pick<WorkerLogger, 'warn'>,
): ThreadSide {
  const firstId = Number(row.threadId);
  /** The login of each person's comment the last read found. */
  const loginOf = new Map<number, string>();
  /** The thread's GraphQL node id, which it is resolved by. */
  let threadNode: string | null = null;
  const permissionOf = (login: string) =>
    githubPermissionOf(client, login, () =>
      logger.warn(
        { replyId: row.id },
        'GitHub permission answer not understood; the reply changes no status',
      ),
    );
  return {
    connectionId,
    async read() {
      const bot = await githubBotLogin(client, repo);
      const comments = await client.reviewComments(number, MAX_COMMENT_PAGES);
      // Beyond the page bound a reply, or the answer, may be unseen: the thread is not read whole.
      if (!comments.complete) return null;
      const byApp = (user: { login: string; type: string } | null) =>
        user?.type === 'Bot' && user.login === bot;
      const first = comments.items.find((c) => c.id === firstId);
      if (first === undefined || typeof first.in_reply_to_id === 'number') return null;
      if (!byApp(first.user) || !marksIssue(first.body, row.issueId)) return null;
      const threads = await client.reviewThreads(number, MAX_THREAD_PAGES);
      const thread = threads.items.find((t) => t.firstCommentNodeId === first.node_id);
      if (thread === undefined) return null;
      threadNode = thread.id;
      const replies = comments.items.filter((c) => c.in_reply_to_id === firstId);
      const people = replies.flatMap((c) =>
        c.user?.type === 'User' ? [{ id: c.id, author: c.user.login, body: c.body }] : [],
      );
      for (const note of people) loginOf.set(note.id, note.author);
      const marker = replyMarker(row.id);
      const answer = replies.find((c) => byApp(c.user) && firstLineOf(c.body) === marker);
      return {
        firstNote: first.body,
        notes: people,
        answered: answer?.id ?? null,
        resolved: thread.isResolved,
      };
    },
    async mayChangeStatus(noteIds) {
      const logins = [...new Set(noteIds.map((id) => loginOf.get(id)))];
      if (logins.length > MAX_AUTHORS_LOOKED_UP) return false;
      for (const login of logins) {
        if (login === undefined) return false;
        if (!githubMayTriage(await permissionOf(login))) return false;
      }
      return true;
    },
    post: async (body) => (await client.replyToReviewComment(number, firstId, body)).id,
    async resolve() {
      if (threadNode === null) return false;
      const result = await client.setThreadResolved(threadNode, true);
      return result === 'refused' ? result : result === 'done';
    },
  };
}

/**
 * The thread on Azure DevOps: the pull request's thread of the row (its id is the thread's). It
 * is read alone (`GET …/threads/<id>`), with who Qualor is; the people's comments are the notes
 * `azureNoteId` names, as detection counts them (reply-detect.ts), and the answer is a reply to
 * the thread's first comment. A thread that is neither active nor pending is resolved, and resolving sets it
 * `fixed`: with a person's reply in it, decoration then reads it as a person's resolution, so a
 * finding that comes back does not reopen it (sub-plan 4's rule G3, plan ruling 8). Whether the
 * authors may change a status is whether each has Contribute on the repository
 * (`azureMayTriage`); a transient failure of that is thrown, so that the job tries again.
 */
export function azureSide(
  connectionId: string,
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  row: ReplyInThread,
  logger: Pick<WorkerLogger, 'warn'>,
): ThreadSide {
  const threadId = Number(row.threadId);
  /** The identity of each person's note the last read found. */
  const authorOf = new Map<number, string>();
  /** The first comment of the thread, which the answer replies to; comment ids start at 1. */
  let firstCommentId = 1;
  return {
    connectionId,
    async read() {
      const me = await client.connectionData();
      const thread = await client.thread(repositoryId, prId, threadId);
      const [first, ...later] = azureCommentsInOrder(thread);
      if (first === undefined || thread.status === null || !writtenByQualor(first, me.id)) {
        return null;
      }
      if (!marksIssue(first.content, row.issueId)) return null;
      firstCommentId = first.id;
      authorOf.clear();
      const people = later.filter(
        (comment) => writtenByPerson(comment, me.id) && azureNoteable(comment),
      );
      for (const comment of people) {
        authorOf.set(azureNoteId(thread.id, comment.id), comment.authorId);
      }
      const marker = replyMarker(row.id);
      const answer = later.find(
        (comment) => writtenByQualor(comment, me.id) && firstLineOf(comment.content) === marker,
      );
      return {
        firstNote: first.content,
        notes: people.map((comment) => ({
          id: azureNoteId(thread.id, comment.id),
          author: azureAuthor(comment),
          body: comment.content,
        })),
        answered: answer === undefined ? null : azureNoteId(thread.id, answer.id),
        resolved: !azureThreadOpen(thread.status),
      };
    },
    async mayChangeStatus(noteIds) {
      const authors: string[] = [];
      for (const id of noteIds) {
        const author = authorOf.get(id);
        // A note the last read did not find has no author to ask about: no rights.
        if (author === undefined) return false;
        authors.push(author);
      }
      return azureMayTriage(client, repositoryId, authors, forReply(logger, row.id));
    },
    post: async (body) =>
      azureNoteId(threadId, await client.reply(repositoryId, prId, threadId, firstCommentId, body)),
    async resolve() {
      const done = await orGone(() =>
        client.setThreadStatus(repositoryId, prId, threadId, 'fixed'),
      );
      return done !== GONE;
    },
  };
}

/** Where the answer to a command goes, through the job's own client and its request budget. */
export interface CommandSide {
  /** The SCM connection the requests are made through, whose circuit they pass. */
  connectionId: string;
  /**
   * What the provider holds of the answer: the id of the note of Qualor's whose first line names
   * the row, posted already (a post whose outcome was lost), or null when there is none or the
   * listing was cut at its page bound before it. Null as a whole when the command's note is gone:
   * on GitLab its discussion missing from a listing read whole, or listed without it; on GitHub its
   * comment missing from a listing read whole. It also finds who wrote the command's note, for
   * `mayReview`; whoever an earlier read found is forgotten first.
   */
  read(): Promise<{ answered: number | null } | null>;
  /**
   * Whether the author of the command's note, as the last `read` found it, has the rights
   * `qualor review` needs, which are the ones a reply needs to change a finding's status: one
   * request, through the same functions. It fails closed: no author found (a note a listing cut at
   * its page bound does not show, an account that is gone, no read yet), a login GitHub could not
   * have and an answer of GitHub's that does not parse have no rights. `unreadable` (Azure DevOps):
   * Qualor's own credential was refused the reads that tell.
   */
  mayReview(): Promise<ReviewRight>;
  /** Posts `body` as the answer: answers the new note's id. Comes after `read`. */
  post(body: string): Promise<number>;
}

/**
 * The answer to a command on GitLab: a reply in the discussion the command's note opened
 * (`threadId`), which the merge request's listing finds. A discussion missing from a listing read
 * whole is gone; from one cut at its page bound it may only be unseen, and the post then finds out.
 * A discussion is listed with all its notes: one listed without the command's note has lost it,
 * though a reply stays in it, and the command is gone. `logger` says when a membership GitLab
 * answered is not understood.
 */
export function gitlabCommandSide(
  connectionId: string,
  client: GitLabClient,
  ref: string,
  iid: string,
  row: ReplyRow,
  threadId: string,
  logger: Pick<WorkerLogger, 'warn'>,
): CommandSide {
  const marker = replyMarker(row.id);
  const projectId = gitlabProjectId(client, ref);
  /** The GitLab user who wrote the command's note, as the last read found it: none until it did. */
  let author: number | undefined;
  return {
    connectionId,
    async read() {
      author = undefined;
      const { me, listed } = await gitlabListing(client, await projectId(), iid);
      const discussion = listed.items.find((d) => d.id === threadId);
      if (discussion === undefined) return listed.complete ? null : { answered: null };
      const command = discussion.notes.find((note) => note.id === row.noteId);
      if (command === undefined) return null;
      author = command.author.id;
      const answer = discussion.notes.find(
        (note) => !note.system && note.author.id === me.id && firstLineOf(note.body) === marker,
      );
      return { answered: answer?.id ?? null };
    },
    async mayReview() {
      if (author === undefined) return false;
      return gitlabMayTriage(client, await projectId(), author, (field) =>
        logger.warn(
          unparsedFields(row.id, field),
          'GitLab membership answer not understood; the command is refused',
        ),
      );
    },
    post: async (body) =>
      (await client.replyToDiscussion(await projectId(), iid, threadId, body)).id,
  };
}

/**
 * The answer to a command on GitHub: a comment on the pull request's page, which the page's
 * comment listing finds by its marker, as it finds the command's own comment and the login that
 * wrote it now. Beyond the listing's page bound the answer may be unseen, and is posted all the
 * same. `logger` says when a permission GitHub answered is not understood.
 */
export function githubCommandSide(
  connectionId: string,
  client: GitHubClient,
  repo: GitHubRepoRef,
  number: string,
  row: ReplyRow,
  logger: Pick<WorkerLogger, 'warn'>,
): CommandSide {
  const marker = replyMarker(row.id);
  /** The login that wrote the command's comment, as the last read found it: none until it did. */
  let author: string | undefined;
  return {
    connectionId,
    async read() {
      author = undefined;
      const bot = await githubBotLogin(client, repo);
      const comments = await client.issueComments(number, MAX_COMMENT_PAGES);
      const command = comments.items.find((c) => c.id === row.noteId);
      // A comment missing from a listing read whole was deleted; from one cut at its page bound it
      // may only be unseen, and its author is then unknown.
      if (command === undefined && comments.complete) return null;
      author = command?.user?.login;
      const answer = comments.items.find(
        (c) =>
          c.user?.type === 'Bot' &&
          c.user.login === bot &&
          c.body !== null &&
          firstLineOf(c.body) === marker,
      );
      return { answered: answer?.id ?? null };
    },
    async mayReview() {
      if (author === undefined) return false;
      const permission = await githubPermissionOf(client, author, () =>
        logger.warn(
          { replyId: row.id },
          'GitHub permission answer not understood; the command is refused',
        ),
      );
      return githubMayTriage(permission);
    },
    post: async (body) => (await client.createComment(number, body)).id,
  };
}

/**
 * The answer to a command on Azure DevOps: a reply to the command's comment, in the thread it
 * opened (`threadId`), which is read alone. A thread Azure DevOps no longer has is not found (the
 * job's `orGone`); a command's comment that was deleted, or that its thread no longer holds, is
 * gone. Whether its author may ask for a review is whether they have Contribute on the repository
 * (`azureTriageRight`), as for a reply's status change; `unreadable` when Azure DevOps refused
 * Qualor's own identities or permissions read.
 */
export function azureCommandSide(
  connectionId: string,
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  row: ReplyRow,
  threadId: string,
  logger: Pick<WorkerLogger, 'warn'>,
): CommandSide {
  const marker = replyMarker(row.id);
  const thread = Number(threadId);
  /** The command's comment in its thread: its note id is the thread's and the comment's. */
  const commandId = row.noteId - azureNoteId(thread, 0);
  /** The identity that wrote the command's comment, as the last read found it: none until it did. */
  let author: string | undefined;
  return {
    connectionId,
    async read() {
      author = undefined;
      const me = await client.connectionData();
      const found = await client.thread(repositoryId, prId, thread);
      const command = found.comments.find((comment) => comment.id === commandId);
      if (command === undefined || command.isDeleted) return null;
      author = command.authorId === '' ? undefined : command.authorId;
      const answer = found.comments.find(
        (comment) => writtenByQualor(comment, me.id) && firstLineOf(comment.content) === marker,
      );
      return { answered: answer === undefined ? null : azureNoteId(found.id, answer.id) };
    },
    async mayReview() {
      if (author === undefined) return false;
      const right = await azureTriageRight(
        client,
        repositoryId,
        [author],
        forReply(logger, row.id),
      );
      return right === 'unreadable' ? right : right === 'may';
    },
    post: async (body) =>
      azureNoteId(thread, await client.reply(repositoryId, prId, thread, commandId, body)),
  };
}

/**
 * What a scan lists of a merge request's notes: Qualor's identity there, and the notes, or for
 * GitHub the new replies of its review threads, which are found where the review comments and the
 * threads are listed (`githubRounds`), and the comments on the pull request's own page.
 */
export type Listing =
  | { provider: 'gitlab'; botId: number; discussions: readonly GitLabDiscussion[] }
  | {
      provider: 'github';
      login: string;
      rounds: readonly Round[];
      comments: readonly GitHubComment[];
    }
  | { provider: 'azure'; identityId: string; threads: readonly AzureThread[] };

/** The merge request's notes on its provider, through the job's own client and its request budget. */
export interface ScanSide {
  /** The SCM connection the requests are made through, whose circuit they pass. */
  connectionId: string;
  /**
   * Lists the notes as they are now, up to the page bounds a decoration reads by: what lies beyond
   * a bound is left for a later pass. `window` is where a new reply of a thread counts from.
   */
  list(window: ReplyWindow): Promise<Listing>;
}

/** The notes of a GitLab merge request: who Qualor is, then its discussions with all their notes. */
export function gitlabScanSide(
  connectionId: string,
  client: GitLabClient,
  ref: string,
  iid: string,
): ScanSide {
  return {
    connectionId,
    async list() {
      const { me, listed } = await gitlabListing(client, ref, iid);
      return { provider: 'gitlab', botId: me.id, discussions: listed.items };
    },
  };
}

/**
 * The notes of a GitHub pull request: who Qualor is, its review comments and review threads (whose
 * new replies are the rounds), and the comments on its page.
 */
export function githubScanSide(
  connectionId: string,
  client: GitHubClient,
  repo: GitHubRepoRef,
  number: string,
): ScanSide {
  return {
    connectionId,
    async list(window) {
      const login = await githubBotLogin(client, repo);
      const reviewComments = await client.reviewComments(number, MAX_COMMENT_PAGES);
      const threads = await client.reviewThreads(number, MAX_THREAD_PAGES);
      const comments = await client.issueComments(number, MAX_COMMENT_PAGES);
      const options = { qualor: { githubLogin: login }, ...window };
      return {
        provider: 'github',
        login,
        rounds: githubRounds(reviewComments.items, threads.items, options),
        comments: comments.items,
      };
    },
  };
}

/** The notes of an Azure DevOps pull request: who Qualor is, then every thread with its comments. */
export function azureScanSide(
  connectionId: string,
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
): ScanSide {
  return {
    connectionId,
    async list() {
      const me = await client.connectionData();
      const threads = await client.threads(repositoryId, prId);
      return { provider: 'azure', identityId: me.id, threads };
    },
  };
}
