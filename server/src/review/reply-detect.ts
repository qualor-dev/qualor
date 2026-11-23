import { z } from 'zod';
import type { ReplyCommand } from '../db/schema';
import {
  machineMadeComment,
  sameAzureIdentity,
  type AzureThread,
  type AzureThreadComment,
} from '../scm/azure/client';
import type { GitHubComment, GitHubReviewComment, GitHubReviewThread } from '../scm/github/client';
import { discussionResolved, type GitLabDiscussion } from '../scm/gitlab/client';
import { markerOf } from '../scm/markdown';
import { parseCommand } from './command-parse';

/*
 * Which of the people's notes in a merge request Qualor answers (6I-4): the new replies in its own
 * threads, and the notes that give it a command. Decoration and the webhook's scan list the
 * discussions (GitLab), the review comments, review threads and issue comments (GitHub), or the
 * threads of the pull request (Azure DevOps), and hand them here; what comes back is what the
 * queue (reply-queue.ts) records in the ledger (replies.ts). Plain functions over what they are
 * given: no database, no request and no clock (`since` says how far back a note counts).
 *
 * A thread is Qualor's when its first note is Qualor's own, is no system note, and opens with an
 * issue marker. A reply is a later note that a person wrote (GitLab: anyone but Qualor's user, no
 * system note; GitHub: an account of type `User`; Azure DevOps: an identity other than Qualor's,
 * in a comment that Azure DevOps did not write itself and that was not deleted), that the ledger
 * does not hold yet (its id is above the thread's largest) and that was made at or after `since`.
 * All the replies of a thread make one round, which its newest note keys. A resolved thread has no
 * round (on Azure DevOps, any thread that is not active), and nor has a GitHub thread whose
 * resolution was not listed: it may be closed.
 *
 * A command is the first note of a GitLab discussion (not Qualor's own, no system note), the first
 * comment of an Azure DevOps thread (the same, and not deleted), or a comment on a GitHub pull
 * request's page by a person, made at or after `since`, whose body `parseCommand` reads as one. A
 * note inside a thread is never a command, and in a thread of Qualor's it is a reply.
 *
 * Azure DevOps numbers the comments of each thread from 1, and its threads from one counter of
 * the organisation (probe item 15): a comment is a note of the ledger by `azureNoteId`, the
 * thread's id and the comment's in one number.
 */

/** What Azure DevOps' comment ids stay below: they are 16-bit (at most 500 comments a thread). */
const AZURE_COMMENT_IDS = 65_536;

/**
 * The ledger's note id of comment `commentId` of Azure DevOps thread `threadId`: the thread's id
 * times 65 536, plus the comment's (probe item 12). Two threads' comment 1 are two notes, and
 * within a thread a later comment has a larger note id, as the ledger's largest note of a thread
 * needs. Exact up to thread ids of about 1.3 × 10¹¹.
 */
export function azureNoteId(threadId: number, commentId: number): number {
  return threadId * AZURE_COMMENT_IDS + commentId;
}

export interface DetectOptions {
  /**
   * Qualor's own identity on the provider: GitLab's user id, GitHub's `<slug>[bot]`, Azure
   * DevOps' identity id (a GUID, in any case). Without the one a function needs, it finds nothing:
   * it cannot tell Qualor's notes from people's.
   */
  qualor: { gitlabUserId?: number; githubLogin?: string; azureIdentityId?: string };
  /** The newest note the ledger holds of each thread, by thread id; a thread it holds none of has no entry. */
  largestNoteIds: ReadonlyMap<string, number>;
  /** The earliest note that counts: the later of the review consent and 30 days before the job. */
  since: Date;
}

/** The new replies of one of Qualor's threads, which Qualor answers together. */
export interface Round {
  /**
   * The GitLab discussion's id, the id of the GitHub thread's first comment, or the Azure DevOps
   * thread's id.
   */
  threadId: string;
  /** The issue the thread is for: its first note's marker. */
  issueId: string;
  /** The notes of the round, oldest first. */
  noteIds: number[];
  /** The newest of them, which keys the round. */
  newest: number;
  /** The SCM username of the newest note's author (on Azure DevOps the display name). */
  author: string;
}

/** A note that asks Qualor for something. */
export interface CommandNote {
  noteId: number;
  /**
   * The GitLab discussion or the Azure DevOps thread the note opens, where its answer goes; null
   * for a GitHub comment on the page.
   */
  threadId: string | null;
  command: ReplyCommand;
  /** The SCM username of the note's author (on Azure DevOps the display name). */
  author: string;
}

/** A note a person wrote in a thread of Qualor's. */
interface Reply {
  id: number;
  author: string;
  /** ISO 8601. */
  createdAt: string;
}

/**
 * The shape of a note's date as GitLab and GitHub write it: an ISO 8601 date and time with its
 * zone. `Date.parse` reads far more than that (a year alone, words with a year in them, a time with
 * no zone in the server's own), so nothing else is read.
 */
const NOTE_DATE = z.iso.datetime({ offset: true });

/** Whether `createdAt` (ISO 8601) is at or after `since`: never when either cannot be read. */
function madeSince(createdAt: string, since: Date): boolean {
  return NOTE_DATE.safeParse(createdAt).success && Date.parse(createdAt) >= since.getTime();
}

/**
 * The round of a thread's replies that are new: above the ledger's largest note of the thread and
 * made since `o.since`. Null when none is.
 */
function roundOf(
  threadId: string,
  issueId: string,
  replies: readonly Reply[],
  o: DetectOptions,
): Round | null {
  const largest = o.largestNoteIds.get(threadId) ?? 0;
  const fresh = replies
    .filter((reply) => reply.id > largest && madeSince(reply.createdAt, o.since))
    .sort((a, b) => a.id - b.id);
  const newest = fresh.at(-1);
  if (newest === undefined) return null;
  return {
    threadId,
    issueId,
    noteIds: fresh.map((reply) => reply.id),
    newest: newest.id,
    author: newest.author,
  };
}

/**
 * The rounds of Qualor's GitLab threads (`discussions`: the merge request's, all notes of each):
 * one for each thread that is not resolved and has a new reply. The resolution is decoration's:
 * a discussion is resolved when every note that can be resolved is.
 */
export function gitlabRounds(discussions: readonly GitLabDiscussion[], o: DetectOptions): Round[] {
  const qualor = o.qualor.gitlabUserId;
  if (qualor === undefined) return [];
  const rounds: Round[] = [];
  for (const discussion of discussions) {
    const [first, ...later] = discussion.notes;
    if (first === undefined || first.system || first.author.id !== qualor) continue;
    const marker = markerOf(first.body);
    if (marker?.kind !== 'issue' || discussionResolved(discussion)) continue;
    const replies = later
      .filter((note) => !note.system && note.author.id !== qualor)
      .map((note) => ({ id: note.id, author: note.author.username, createdAt: note.created_at }));
    const round = roundOf(discussion.id, marker.issueId, replies, o);
    if (round !== null) rounds.push(round);
  }
  return rounds;
}

/** GraphQL's thread of each first comment, by the comment's node id: the first one listed. */
function threadsByFirstComment(
  threads: readonly GitHubReviewThread[],
): Map<string, GitHubReviewThread> {
  const listed = new Map<string, GitHubReviewThread>();
  for (const thread of threads) {
    if (thread.firstCommentNodeId !== null && !listed.has(thread.firstCommentNodeId)) {
      listed.set(thread.firstCommentNodeId, thread);
    }
  }
  return listed;
}

/** What people replied, by the id of the first comment it names. */
function repliesByFirstComment(comments: readonly GitHubReviewComment[]): Map<number, Reply[]> {
  const repliesByFirst = new Map<number, Reply[]>();
  for (const comment of comments) {
    const firstId = comment.in_reply_to_id;
    if (typeof firstId !== 'number' || comment.user?.type !== 'User') continue;
    const reply = { id: comment.id, author: comment.user.login, createdAt: comment.created_at };
    const replies = repliesByFirst.get(firstId);
    if (replies === undefined) repliesByFirst.set(firstId, [reply]);
    else replies.push(reply);
  }
  return repliesByFirst;
}

/**
 * The rounds of Qualor's GitHub threads: one for each thread that is not resolved and has a new
 * reply. A thread is the App's top-level review comment with an issue marker, and its replies are
 * the comments of people that name it as the comment they reply to. Whether it is resolved is what
 * GraphQL lists for it; a thread GraphQL did not list (the listing was cut) may be closed and is
 * left alone.
 */
export function githubRounds(
  comments: readonly GitHubReviewComment[],
  threads: readonly GitHubReviewThread[],
  o: DetectOptions,
): Round[] {
  const app = o.qualor.githubLogin;
  if (app === undefined) return [];
  const listed = threadsByFirstComment(threads);
  const repliesByFirst = repliesByFirstComment(comments);
  const rounds: Round[] = [];
  for (const first of comments) {
    if (typeof first.in_reply_to_id === 'number') continue;
    if (first.user?.type !== 'Bot' || first.user.login !== app) continue;
    const marker = markerOf(first.body);
    if (marker?.kind !== 'issue') continue;
    const thread = listed.get(first.node_id);
    if (thread === undefined || thread.isResolved) continue;
    const round = roundOf(String(first.id), marker.issueId, repliesByFirst.get(first.id) ?? [], o);
    if (round !== null) rounds.push(round);
  }
  return rounds;
}

/**
 * The commands in a GitLab merge request's discussions: the first note of each discussion that is
 * neither Qualor's own nor a system note, when its body is a command. The answer goes into that
 * note's discussion, so `threadId` is its id.
 */
export function gitlabCommands(
  discussions: readonly GitLabDiscussion[],
  o: DetectOptions,
): CommandNote[] {
  const qualor = o.qualor.gitlabUserId;
  if (qualor === undefined) return [];
  const found: CommandNote[] = [];
  for (const discussion of discussions) {
    const first = discussion.notes[0];
    if (first === undefined || first.system || first.author.id === qualor) continue;
    const command = parseCommand(first.body);
    if (command === null || !madeSince(first.created_at, o.since)) continue;
    found.push({
      noteId: first.id,
      threadId: discussion.id,
      command,
      author: first.author.username,
    });
  }
  return found;
}

/**
 * The commands in the comments on a GitHub pull request's page (`issueComments`, never its review
 * comments, which are replies when they are in a thread of Qualor's): those by a person, and not by
 * a bot, Qualor's App among them.
 */
export function githubCommands(
  issueComments: readonly GitHubComment[],
  o: DetectOptions,
): CommandNote[] {
  const found: CommandNote[] = [];
  for (const comment of issueComments) {
    if (comment.user?.type !== 'User' || comment.body === null) continue;
    const command = parseCommand(comment.body);
    if (command === null || !madeSince(comment.created_at, o.since)) continue;
    found.push({ noteId: comment.id, threadId: null, command, author: comment.user.login });
  }
  return found;
}

/** The comments of an Azure DevOps thread by their ids: the first is the one that opened it. */
export const azureCommentsInOrder = (thread: AzureThread): AzureThreadComment[] =>
  thread.comments.toSorted((a, b) => a.id - b.id);

/**
 * Whether an Azure DevOps comment is one Qualor's identity (`qualor`) wrote as it is: not Azure
 * DevOps' own, and not deleted.
 */
export const writtenByQualor = (comment: AzureThreadComment, qualor: string): boolean =>
  !comment.isDeleted &&
  !machineMadeComment(comment.commentType) &&
  sameAzureIdentity(comment.authorId, qualor);

/**
 * Whether an Azure DevOps comment is a person's: written by an identity that is not Qualor's
 * (`qualor`), not by Azure DevOps itself, and not deleted (a deleted comment may come without its
 * author).
 */
export const writtenByPerson = (comment: AzureThreadComment, qualor: string): boolean =>
  !comment.isDeleted &&
  !machineMadeComment(comment.commentType) &&
  comment.authorId !== '' &&
  !sameAzureIdentity(comment.authorId, qualor);

/** Who wrote a comment, as the ledger names them: the display name, else the identity's id. */
export const azureAuthor = (comment: AzureThreadComment): string =>
  comment.authorName === '' ? comment.authorId : comment.authorName;

/**
 * The rounds of Qualor's Azure DevOps threads (`threads`: the pull request's, all comments of
 * each): one for each active thread that has a new reply. A thread is Qualor's when its first
 * comment is a text comment of Qualor's identity (`qualor.azureIdentityId`, in any case) that
 * opens with an issue marker; a thread that is not active (fixed, won't fix, closed, by design,
 * pending) is resolved and has none. Each reply is the note `azureNoteId` names.
 */
export function azureRounds(threads: readonly AzureThread[], o: DetectOptions): Round[] {
  const qualor = o.qualor.azureIdentityId;
  if (qualor === undefined) return [];
  const rounds: Round[] = [];
  for (const thread of threads) {
    const [first, ...later] = azureCommentsInOrder(thread);
    if (first === undefined || !writtenByQualor(first, qualor)) continue;
    const marker = markerOf(first.content);
    if (marker?.kind !== 'issue' || thread.status !== 'active') continue;
    const replies = later
      .filter((comment) => writtenByPerson(comment, qualor))
      .map((comment) => ({
        id: azureNoteId(thread.id, comment.id),
        author: azureAuthor(comment),
        createdAt: comment.publishedDate,
      }));
    const round = roundOf(String(thread.id), marker.issueId, replies, o);
    if (round !== null) rounds.push(round);
  }
  return rounds;
}

/**
 * The commands in an Azure DevOps pull request's threads: the first comment of each thread that a
 * person opened (`writtenByPerson`: not Qualor's, not Azure DevOps' own, not deleted), when it is a
 * command. The answer goes into that thread, so `threadId` is its id, and the note is the
 * comment's `azureNoteId`.
 */
export function azureCommands(threads: readonly AzureThread[], o: DetectOptions): CommandNote[] {
  const qualor = o.qualor.azureIdentityId;
  if (qualor === undefined) return [];
  const found: CommandNote[] = [];
  for (const thread of threads) {
    const first = azureCommentsInOrder(thread)[0];
    if (first === undefined || !writtenByPerson(first, qualor)) continue;
    const command = parseCommand(first.content);
    if (command === null || !madeSince(first.publishedDate, o.since)) continue;
    found.push({
      noteId: azureNoteId(thread.id, first.id),
      threadId: String(thread.id),
      command,
      author: azureAuthor(first),
    });
  }
  return found;
}
