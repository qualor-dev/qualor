import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { identitiesOf, patOf } from '../../test/azure';
import {
  azureShape,
  createFakeAzureDevOps,
  type FakeAzureDevOps,
} from '../../test/fake-azure-devops';
import { AzureDevOpsClient, type AzureThread, type AzureThreadComment } from '../scm/azure/client';
import type { GitHubComment, GitHubReviewComment, GitHubReviewThread } from '../scm/github/client';
import type { GitLabDiscussion, GitLabNote } from '../scm/gitlab/client';
import { issueMarker, summaryMarker } from '../scm/markdown';
import {
  azureCommands,
  azureNoteId,
  azureRounds,
  githubCommands,
  githubRounds,
  gitlabCommands,
  gitlabRounds,
  type DetectOptions,
} from './reply-detect';

const ISSUE = '0197c0a8-5b2e-7d3a-9f41-2c6e8b1a4d70';
const OTHER_ISSUE = '0197c0a8-5b2e-7d3a-9f41-2c6e8b1a4d71';
const THIRD_ISSUE = '0197c0a8-5b2e-7d3a-9f41-2c6e8b1a4d72';
const PROJECT = '0197c0a8-5b2e-7d3a-9f41-2c6e8b1a4d00';

/** Qualor's own GitLab user and GitHub App, and two people. */
const QUALOR = { id: 900, username: 'qualor-bot' };
const APP = 'qualor-acme[bot]';
const ANN = { id: 7, username: 'ann' };
const BOB = { id: 8, username: 'bob' };

/** The earliest note that counts: the later of the consent and 30 days before the job. */
const SINCE = new Date('2026-10-01T00:00:00.000Z');
/** When a hand-built note was made, unless its case is about the date: after {@link SINCE}. */
const AFTER = '2026-10-10T08:30:00.000Z';
/** Dates of a note that cannot be read: V8 would read the year, and the time with no zone, its own way. */
const UNREADABLE = [
  '',
  'yesterday',
  '2026-13-45T99:00:00Z',
  '2099',
  'foo 2099',
  '2099-01-01T10:00:00',
];

const BODIES = ['qualor review', 'QUALOR REVIEW', '  qualor review please'];

function options(fields: Partial<DetectOptions> = {}): DetectOptions {
  return {
    qualor: { gitlabUserId: QUALOR.id, githubLogin: APP },
    largestNoteIds: new Map(),
    since: SINCE,
    ...fields,
  };
}

// ─── GitLab ────────────────────────────────────────────────────────────────

/** A person's note, resolvable and open, made after `SINCE`; each case changes what it is about. */
function note(fields: Partial<GitLabNote> & { id: number }): GitLabNote {
  return {
    body: 'This is intended.',
    author: ANN,
    created_at: AFTER,
    system: false,
    resolvable: true,
    resolved: false,
    ...fields,
  };
}

/** Qualor's first note of a thread: its issue marker on the first line. */
function opening(fields: Partial<GitLabNote> = {}): GitLabNote {
  return note({
    id: 10,
    author: QUALOR,
    body: `${issueMarker(ISSUE)}\n**Medium** · a finding`,
    ...fields,
  });
}

const discussion = (id: string, ...notes: GitLabNote[]): GitLabDiscussion => ({
  id,
  individual_note: false,
  notes,
});

/** A person's note on the merge request's page: a discussion of one note that cannot be resolved. */
const overview = (id: string, fields: Partial<GitLabNote> & { id: number }): GitLabDiscussion => ({
  id,
  individual_note: true,
  notes: [note({ resolvable: false, ...fields })],
});

describe('gitlabRounds', () => {
  const rounds = (notes: GitLabNote[], fields: Partial<DetectOptions> = {}) =>
    gitlabRounds([discussion('d1', ...notes)], options(fields));

  it("a person's reply in Qualor's thread is a round", () => {
    expect(rounds([opening(), note({ id: 11, author: BOB })])).toEqual([
      { threadId: 'd1', issueId: ISSUE, noteIds: [11], newest: 11, author: 'bob' },
    ]);
  });

  it('gives each thread its own round, and none to a thread nobody replied in', () => {
    const second = opening({ id: 20, body: `${issueMarker(OTHER_ISSUE)}\nA rule message` });
    const third = opening({ id: 30, body: `${issueMarker(THIRD_ISSUE)}\nAnother finding` });
    expect(
      gitlabRounds(
        [
          discussion('d1', opening(), note({ id: 11 })),
          discussion('d2', second, note({ id: 21, author: BOB })),
          discussion('d3', third),
        ],
        options(),
      ),
    ).toEqual([
      { threadId: 'd1', issueId: ISSUE, noteIds: [11], newest: 11, author: 'ann' },
      { threadId: 'd2', issueId: OTHER_ISSUE, noteIds: [21], newest: 21, author: 'bob' },
    ]);
  });

  it("Qualor's own notes and system notes are never replies", () => {
    // The control: a person's note, in the same place.
    expect(rounds([opening(), note({ id: 11 })])).toHaveLength(1);
    // Qualor's own answer in the thread.
    expect(rounds([opening(), note({ id: 11, author: QUALOR })])).toEqual([]);
    // GitLab's own note ("resolved this thread").
    expect(rounds([opening(), note({ id: 11, system: true })])).toEqual([]);
    // Of all three together, only the person's is in the round.
    expect(
      rounds([
        opening(),
        note({ id: 11, author: QUALOR }),
        note({ id: 12, system: true }),
        note({ id: 13 }),
      ]),
    ).toEqual([{ threadId: 'd1', issueId: ISSUE, noteIds: [13], newest: 13, author: 'ann' }]);
  });

  it("tells Qualor's user by its id, not by its name", () => {
    const renamed = { id: QUALOR.id, username: 'renamed' };
    const lookalike = { id: 901, username: QUALOR.username };
    // As the author of a note in the thread ...
    expect(rounds([opening(), note({ id: 11, author: lookalike })])).toHaveLength(1);
    expect(rounds([opening(), note({ id: 11, author: renamed })])).toEqual([]);
    // ... and of the thread's first note.
    expect(rounds([opening({ author: renamed }), note({ id: 11 })])).toHaveLength(1);
    expect(rounds([opening({ author: lookalike }), note({ id: 11 })])).toEqual([]);
  });

  it("only notes newer than the ledger's largest for the thread count", () => {
    const notes = [opening(), note({ id: 11 }), note({ id: 12 }), note({ id: 13 })];
    const ledger = (largest: number, thread = 'd1') =>
      ({ largestNoteIds: new Map([[thread, largest]]) }) satisfies Partial<DetectOptions>;
    // The control: the ledger holds nothing of this thread (or only another thread's notes).
    expect(rounds(notes)[0]?.noteIds).toEqual([11, 12, 13]);
    expect(rounds(notes, ledger(50, 'd2'))[0]?.noteIds).toEqual([11, 12, 13]);
    // It holds up to 12: that note and the ones before it are done.
    expect(rounds(notes, ledger(12))).toEqual([
      { threadId: 'd1', issueId: ISSUE, noteIds: [13], newest: 13, author: 'ann' },
    ]);
    // It holds the newest: nothing is left.
    expect(rounds(notes, ledger(13))).toEqual([]);
    expect(rounds(notes, ledger(99))).toEqual([]);
  });

  it('a note before the consent or older than 30 days is ignored', () => {
    // `since` is the later of the two moments, so one rule serves both.
    const madeAt = (created_at: string) => rounds([opening(), note({ id: 11, created_at })]);
    // The control: a note made at `since` itself, and one made after it.
    expect(madeAt(SINCE.toISOString())).toHaveLength(1);
    expect(madeAt(AFTER)).toHaveLength(1);
    // One millisecond earlier, and a note from long before.
    expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
    expect(madeAt('2026-09-01T10:00:00.000Z')).toEqual([]);
    // The notes of a thread are judged one by one.
    expect(
      rounds([
        opening({ created_at: '2026-08-01T10:00:00.000Z' }),
        note({ id: 11, created_at: '2026-09-01T10:00:00.000Z' }),
        note({ id: 12 }),
      ]),
    ).toEqual([{ threadId: 'd1', issueId: ISSUE, noteIds: [12], newest: 12, author: 'ann' }]);
  });

  it('judges a date in any time zone, and ignores one that cannot be read', () => {
    const madeAt = (created_at: string) => rounds([opening(), note({ id: 11, created_at })]);
    // The same moment as `since`, written in another time zone, counts; an hour before it does not.
    expect(madeAt('2026-10-01T03:00:00.000+03:00')).toHaveLength(1);
    expect(madeAt('2026-10-01T02:00:00.000+03:00')).toEqual([]);
    // A date nobody can read is never taken for a recent one.
    expect(madeAt(AFTER)).toHaveLength(1);
    // Only an ISO 8601 date and time with its zone is read: a year alone, or words with one, is not.
    for (const unreadable of UNREADABLE) {
      expect(madeAt(unreadable)).toEqual([]);
    }
    // And nothing is recent for a `since` nobody can read.
    expect(rounds([opening(), note({ id: 11 })], { since: new Date(Number.NaN) })).toEqual([]);
  });

  it('a resolved thread has no round', () => {
    const resolved = { resolved: true, resolved_by: { id: 5 } };
    // The control: the same thread, open.
    expect(rounds([opening(), note({ id: 11 })])).toHaveLength(1);
    // GitLab calls a discussion resolved when every note that can be resolved is.
    expect(rounds([opening(resolved), note({ id: 11, ...resolved })])).toEqual([]);
    expect(
      rounds([
        opening({ ...resolved, resolved_by: { id: QUALOR.id } }),
        note({ id: 11, ...resolved }),
      ]),
    ).toEqual([]);
    // A note of the thread that is not resolved keeps it open, as it does for decoration.
    expect(rounds([opening(resolved), note({ id: 11 })])).toHaveLength(1);
    expect(rounds([opening(), note({ id: 11, ...resolved })])).toHaveLength(1);
    // A discussion with nothing to resolve is never resolved, whether its notes say they cannot
    // be or leave the flag out.
    for (const resolvable of [false, undefined]) {
      expect(
        rounds([
          opening({ resolvable, resolved: true }),
          note({ id: 11, resolvable, resolved: true }),
        ]),
      ).toHaveLength(1);
    }
  });

  it('two notes make one round keyed by the newer', () => {
    expect(
      rounds([opening(), note({ id: 11, author: ANN }), note({ id: 12, author: BOB })]),
    ).toEqual([{ threadId: 'd1', issueId: ISSUE, noteIds: [11, 12], newest: 12, author: 'bob' }]);
    // The newest is the one with the largest id, whatever the order of the listing.
    expect(
      rounds([opening(), note({ id: 13, author: BOB }), note({ id: 11 }), note({ id: 12 })]),
    ).toEqual([
      { threadId: 'd1', issueId: ISSUE, noteIds: [11, 12, 13], newest: 13, author: 'bob' },
    ]);
  });

  it("a thread that does not start with Qualor's issue marker is ignored", () => {
    const withFirst = (first: GitLabNote) => rounds([first, note({ id: 11 })]);
    // The control: Qualor's note that opens with the marker.
    expect(withFirst(opening())).toHaveLength(1);
    // Qualor's notes of another kind: no marker, the summary's marker, a marker that is not a UUID.
    expect(withFirst(opening({ body: 'A note with no marker' }))).toEqual([]);
    expect(withFirst(opening({ body: `${summaryMarker(PROJECT)}\nThe summary` }))).toEqual([]);
    expect(withFirst(opening({ body: '<!-- qualor:issue not-a-uuid -->' }))).toEqual([]);
    // A marker quoted below the first line marks nothing.
    expect(withFirst(opening({ body: `Quoting a note:\n${issueMarker(ISSUE)}` }))).toEqual([]);
    // The marker, forged by a person, and in GitLab's own note.
    expect(withFirst(opening({ author: ANN }))).toEqual([]);
    expect(withFirst(opening({ system: true }))).toEqual([]);
    // A discussion without a note has no thread.
    expect(gitlabRounds([discussion('d1')], options())).toEqual([]);
  });

  it('finds nothing when Qualor does not know its own user', () => {
    expect(rounds([opening(), note({ id: 11 })])).toHaveLength(1);
    expect(rounds([opening(), note({ id: 11 })], { qualor: { githubLogin: APP } })).toEqual([]);
  });

  it('a discussion that a person started is no thread of Qualor', () => {
    // A person's note with a marker in a thread of its own, and Qualor's answer in it.
    const theirs = discussion(
      'd2',
      note({ id: 20, body: `${issueMarker(ISSUE)}\nA marker typed by a person` }),
      note({ id: 21, author: QUALOR }),
      note({ id: 22, author: BOB }),
    );
    expect(gitlabRounds([theirs], options())).toEqual([]);
    expect(
      gitlabRounds([discussion('d1', opening(), note({ id: 11 })), theirs], options()),
    ).toEqual([{ threadId: 'd1', issueId: ISSUE, noteIds: [11], newest: 11, author: 'ann' }]);
  });
});

describe('gitlabCommands', () => {
  const commands = (...discussions: GitLabDiscussion[]) => gitlabCommands(discussions, options());

  it('qualor review, QUALOR REVIEW and "  qualor review please" are commands', () => {
    expect(commands(...BODIES.map((body, i) => overview(`d${i}`, { id: 20 + i, body })))).toEqual(
      BODIES.map((_, i) => ({
        noteId: 20 + i,
        threadId: `d${i}`,
        command: 'review',
        author: 'ann',
      })),
    );
  });

  it('gives the command the note asks for', () => {
    expect(
      commands(
        overview('d1', { id: 21, body: 'qualor fix' }),
        overview('d2', { id: 22, body: 'Qualor Stop', author: BOB }),
      ),
    ).toEqual([
      { noteId: 21, threadId: 'd1', command: 'fix', author: 'ann' },
      { noteId: 22, threadId: 'd2', command: 'stop', author: 'bob' },
    ]);
  });

  it('qualor reviewer is not a command', () => {
    expect(commands(overview('d1', { id: 21, body: 'qualor review' }))).toHaveLength(1);
    expect(commands(overview('d1', { id: 21, body: 'qualor reviewer' }))).toEqual([]);
    expect(commands(overview('d1', { id: 21, body: 'please qualor review' }))).toEqual([]);
    expect(commands(overview('d1', { id: 21, body: 'a note about the review' }))).toEqual([]);
  });

  it("Qualor's own notes and system notes are never commands", () => {
    const typed = { id: 21, body: 'qualor review' };
    // The control: a person's note.
    expect(commands(overview('d1', typed))).toHaveLength(1);
    expect(commands(overview('d1', { ...typed, author: QUALOR }))).toEqual([]);
    expect(commands(overview('d1', { ...typed, system: true }))).toEqual([]);
  });

  it('a command inside a thread is a reply, not a command', () => {
    const typed = note({ id: 11, body: 'qualor review' });
    // In Qualor's thread, the note is a reply to answer ...
    const inQualors = discussion('d1', opening(), typed);
    expect(commands(inQualors)).toEqual([]);
    expect(gitlabRounds([inQualors], options())).toEqual([
      { threadId: 'd1', issueId: ISSUE, noteIds: [11], newest: 11, author: 'ann' },
    ]);
    // ... and in a thread of a person's, a note after the first is no command either.
    expect(
      commands(
        discussion(
          'd2',
          note({ id: 20, body: 'A question about this line.' }),
          note({ id: 21, body: 'qualor review' }),
        ),
      ),
    ).toEqual([]);
    // The control: the same note as the first of a discussion is a command, and no reply.
    const first = discussion('d3', note({ id: 30, body: 'qualor review' }));
    expect(commands(first)).toEqual([
      { noteId: 30, threadId: 'd3', command: 'review', author: 'ann' },
    ]);
    expect(gitlabRounds([first], options())).toEqual([]);
  });

  it("a command that opens a person's own thread on a line is a command, answered in that thread", () => {
    const inline = discussion('d1', note({ id: 21, body: 'qualor stop' }), note({ id: 22 }));
    expect(commands(inline)).toEqual([
      { noteId: 21, threadId: 'd1', command: 'stop', author: 'ann' },
    ]);
  });

  it('a command before the consent or older than 30 days is ignored', () => {
    const madeAt = (created_at: string) =>
      commands(overview('d1', { id: 21, body: 'qualor review', created_at }));
    expect(madeAt(SINCE.toISOString())).toHaveLength(1);
    expect(madeAt(AFTER)).toHaveLength(1);
    expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
    expect(madeAt('2026-09-01T10:00:00.000Z')).toEqual([]);
    for (const unreadable of UNREADABLE) expect(madeAt(unreadable)).toEqual([]);
    // And no command is recent for a `since` nobody can read.
    const noSince = options({ since: new Date(Number.NaN) });
    expect(gitlabCommands([overview('d1', { id: 21, body: 'qualor review' })], noSince)).toEqual(
      [],
    );
  });

  it('finds nothing when Qualor does not know its own user', () => {
    const found = [overview('d1', { id: 21, body: 'qualor review' })];
    expect(gitlabCommands(found, options())).toHaveLength(1);
    expect(gitlabCommands(found, options({ qualor: { githubLogin: APP } }))).toEqual([]);
  });
});

// ─── GitHub ────────────────────────────────────────────────────────────────

const person = (login: string): { login: string; type: string } => ({ login, type: 'User' });
const bot = (login: string): { login: string; type: string } => ({ login, type: 'Bot' });

/** A person's review comment, top-level and made after `SINCE`; each case changes what it is about. */
function review(fields: Partial<GitHubReviewComment> & { id: number }): GitHubReviewComment {
  return {
    node_id: `PRRC_${fields.id}`,
    body: 'This is intended.',
    user: person('ann'),
    created_at: AFTER,
    ...fields,
  };
}

/** The App's first comment of a thread, comment 10: its issue marker on the first line. */
function start(fields: Partial<GitHubReviewComment> = {}): GitHubReviewComment {
  return review({
    id: 10,
    user: bot(APP),
    body: `${issueMarker(ISSUE)}\n**Medium** · a finding`,
    ...fields,
  });
}

/** A reply in the thread of comment 10, which GitHub names by that comment's id. */
const reply = (id: number, fields: Partial<GitHubReviewComment> = {}): GitHubReviewComment =>
  review({ id, in_reply_to_id: 10, ...fields });

/** What GraphQL lists of the thread of comment 10: open unless the case says otherwise. */
function listed(fields: Partial<GitHubReviewThread> = {}): GitHubReviewThread {
  return {
    id: 'PRRT_1',
    isResolved: false,
    resolvedByLogin: null,
    firstCommentNodeId: 'PRRC_10',
    ...fields,
  };
}

/** A comment on the pull request's page. */
function issueComment(fields: Partial<GitHubComment> & { id: number }): GitHubComment {
  return { body: 'qualor review', user: person('ann'), created_at: AFTER, ...fields };
}

describe('githubRounds', () => {
  const rounds = (
    comments: GitHubReviewComment[],
    threads: GitHubReviewThread[] = [listed()],
    fields: Partial<DetectOptions> = {},
  ) => githubRounds(comments, threads, options(fields));

  it("a person's reply in Qualor's thread is a round", () => {
    expect(rounds([start(), reply(11, { user: person('bob') })])).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [11], newest: 11, author: 'bob' },
    ]);
  });

  it("gives each thread its own round, keyed by its first comment's id", () => {
    const second = start({
      id: 30,
      body: `${issueMarker(OTHER_ISSUE)}\nA rule message`,
    });
    const third = start({ id: 40, body: `${issueMarker(THIRD_ISSUE)}\nAnother finding` });
    const threads = [
      listed(),
      listed({ id: 'PRRT_2', firstCommentNodeId: 'PRRC_30' }),
      listed({ id: 'PRRT_3', firstCommentNodeId: 'PRRC_40' }),
    ];
    expect(
      rounds(
        [
          start(),
          second,
          third,
          reply(11),
          review({ id: 31, in_reply_to_id: 30, user: person('bob') }),
          reply(12, { user: person('bob') }),
        ],
        threads,
      ),
    ).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [11, 12], newest: 12, author: 'bob' },
      { threadId: '30', issueId: OTHER_ISSUE, noteIds: [31], newest: 31, author: 'bob' },
    ]);
  });

  it("Qualor's own comments and GitHub bots are never replies", () => {
    const withReply = (comment: GitHubReviewComment) => rounds([start(), comment]);
    // The control: a person's reply.
    expect(withReply(reply(11))).toHaveLength(1);
    // Qualor's own answer in the thread, and another App's.
    expect(withReply(reply(11, { user: bot(APP) }))).toEqual([]);
    expect(withReply(reply(11, { user: bot('dependabot[bot]') }))).toEqual([]);
    // A user GitHub no longer has, and an account that is not a user.
    expect(withReply(reply(11, { user: null }))).toEqual([]);
    expect(withReply(reply(11, { user: { login: 'acme', type: 'Organization' } }))).toEqual([]);
    // Of all of them together, only the person's is in the round.
    expect(
      rounds([
        start(),
        reply(11, { user: bot(APP) }),
        reply(12, { user: bot('dependabot[bot]') }),
        reply(13, { user: null }),
        reply(14),
      ]),
    ).toEqual([{ threadId: '10', issueId: ISSUE, noteIds: [14], newest: 14, author: 'ann' }]);
  });

  it("only notes newer than the ledger's largest for the thread count", () => {
    const comments = [start(), reply(11), reply(12), reply(13)];
    const ledger = (...entries: [string, number][]) => ({ largestNoteIds: new Map(entries) });
    // The control: the ledger holds nothing of this thread (the thread is named by the id of its
    // first comment, not by GraphQL's id).
    expect(rounds(comments)[0]?.noteIds).toEqual([11, 12, 13]);
    expect(rounds(comments, undefined, ledger(['99', 50], ['PRRT_1', 50]))[0]?.noteIds).toEqual([
      11, 12, 13,
    ]);
    // It holds up to 12: that note and the ones before it are done.
    expect(rounds(comments, undefined, ledger(['10', 12]))).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [13], newest: 13, author: 'ann' },
    ]);
    // It holds the newest: nothing is left.
    expect(rounds(comments, undefined, ledger(['10', 13]))).toEqual([]);
    expect(rounds(comments, undefined, ledger(['10', 99]))).toEqual([]);
  });

  it('a note before the consent or older than 30 days is ignored', () => {
    const madeAt = (created_at: string) => rounds([start(), reply(11, { created_at })]);
    // The control: a comment made at `since` itself, and one made after it.
    expect(madeAt(SINCE.toISOString())).toHaveLength(1);
    expect(madeAt(AFTER)).toHaveLength(1);
    // One millisecond earlier, and a comment from long before.
    expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
    expect(madeAt('2026-09-01T10:00:00Z')).toEqual([]);
    // The comments of a thread are judged one by one; the first one's date is not asked.
    expect(
      rounds([
        start({ created_at: '2026-08-01T10:00:00Z' }),
        reply(11, { created_at: '2026-09-01T10:00:00Z' }),
        reply(12),
      ]),
    ).toEqual([{ threadId: '10', issueId: ISSUE, noteIds: [12], newest: 12, author: 'ann' }]);
  });

  it('judges a date in any time zone, and ignores one that cannot be read', () => {
    const madeAt = (created_at: string) => rounds([start(), reply(11, { created_at })]);
    expect(madeAt('2026-10-01T03:00:00+03:00')).toHaveLength(1);
    expect(madeAt('2026-10-01T02:00:00+03:00')).toEqual([]);
    expect(madeAt(AFTER)).toHaveLength(1);
    // Only an ISO 8601 date and time with its zone is read: a year alone, or words with one, is not.
    for (const unreadable of UNREADABLE) {
      expect(madeAt(unreadable)).toEqual([]);
    }
    expect(rounds([start(), reply(11)], undefined, { since: new Date(Number.NaN) })).toEqual([]);
  });

  it('a resolved thread has no round', () => {
    const comments = [start(), reply(11)];
    // The control: the thread GraphQL lists is open.
    expect(rounds(comments, [listed()])).toHaveLength(1);
    // Resolved by a person, by Qualor's own App, or by GitHub naming nobody.
    for (const resolvedByLogin of ['ann', APP, null]) {
      expect(rounds(comments, [listed({ isResolved: true, resolvedByLogin })])).toEqual([]);
    }
  });

  it('a thread whose resolution GitHub did not list has no round', () => {
    const comments = [start(), reply(11)];
    // The control: the thread is listed, and open.
    expect(rounds(comments, [listed()])).toHaveLength(1);
    // The listing holds no thread (it was cut at its page bound) ...
    expect(rounds(comments, [])).toEqual([]);
    // ... or another comment's thread only ...
    expect(rounds(comments, [listed({ firstCommentNodeId: 'PRRC_99' })])).toEqual([]);
    // ... or a thread with no first comment, or one named by the reply's id.
    expect(rounds(comments, [listed({ firstCommentNodeId: null })])).toEqual([]);
    expect(rounds(comments, [listed({ firstCommentNodeId: 'PRRC_11' })])).toEqual([]);
  });

  it('takes the first thread GraphQL lists for a comment as its thread', () => {
    const comments = [start(), reply(11)];
    const open = listed();
    const resolved = listed({ id: 'PRRT_9', isResolved: true });
    expect(rounds(comments, [open, resolved])).toHaveLength(1);
    expect(rounds(comments, [resolved, open])).toEqual([]);
  });

  it('two notes make one round keyed by the newer', () => {
    expect(rounds([start(), reply(11), reply(12, { user: person('bob') })])).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [11, 12], newest: 12, author: 'bob' },
    ]);
    // The newest is the one with the largest id, whatever the order of the listing.
    expect(rounds([start(), reply(13, { user: person('bob') }), reply(11), reply(12)])).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [11, 12, 13], newest: 13, author: 'bob' },
    ]);
  });

  it("a thread that does not start with Qualor's issue marker is ignored", () => {
    const withFirst = (first: GitHubReviewComment) => rounds([first, reply(11)]);
    // The control: the App's comment that opens with the marker.
    expect(withFirst(start())).toHaveLength(1);
    // The App's comments of another kind: no marker, another Qualor marker, a marker that is not
    // a UUID.
    expect(withFirst(start({ body: 'A comment with no marker' }))).toEqual([]);
    expect(withFirst(start({ body: `${summaryMarker(PROJECT)}\nThe summary` }))).toEqual([]);
    expect(withFirst(start({ body: '<!-- qualor:issue not-a-uuid -->' }))).toEqual([]);
    // A marker quoted below the first line marks nothing.
    expect(withFirst(start({ body: `Quoting a comment:\n${issueMarker(ISSUE)}` }))).toEqual([]);
    // The marker, forged by a person or by another App, or under the App's name by a user.
    expect(withFirst(start({ user: person('ann') }))).toEqual([]);
    expect(withFirst(start({ user: bot('other-app[bot]') }))).toEqual([]);
    expect(withFirst(start({ user: person(APP) }))).toEqual([]);
    expect(withFirst(start({ user: null }))).toEqual([]);
  });

  it('a comment that replies in a thread does not start one', () => {
    // The App's own comment with an issue marker, an answer in the thread of comment 10 ...
    const answer = review({
      id: 20,
      in_reply_to_id: 10,
      user: bot(APP),
      body: `${issueMarker(OTHER_ISSUE)}\nAn answer`,
    });
    const threads = [listed(), listed({ id: 'PRRT_2', firstCommentNodeId: 'PRRC_20' })];
    // ... and a person's comment that names the thread, as GitHub does a reply: the control names
    // the first comment, the other the answer.
    const stray = (to: number) => review({ id: 21, in_reply_to_id: to });
    expect(rounds([start(), answer, stray(10)], threads)).toEqual([
      { threadId: '10', issueId: ISSUE, noteIds: [21], newest: 21, author: 'ann' },
    ]);
    expect(rounds([start(), answer, stray(20)], threads)).toEqual([]);
  });

  it("a person's comment on the diff is a reply only to a thread it names", () => {
    // The control: the comment replies in Qualor's thread.
    expect(rounds([start(), reply(11)])).toHaveLength(1);
    expect(rounds([start(), review({ id: 11 })])).toEqual([]);
    expect(rounds([start(), review({ id: 11, in_reply_to_id: null })])).toEqual([]);
    expect(rounds([start(), reply(11, { in_reply_to_id: 99 })])).toEqual([]);
  });

  it('finds nothing when Qualor does not know its own login', () => {
    expect(rounds([start(), reply(11)])).toHaveLength(1);
    expect(
      rounds([start(), reply(11)], undefined, { qualor: { gitlabUserId: QUALOR.id } }),
    ).toEqual([]);
  });
});

describe('githubCommands', () => {
  const commands = (...comments: GitHubComment[]) => githubCommands(comments, options());

  it('qualor review, QUALOR REVIEW and "  qualor review please" are commands', () => {
    expect(commands(...BODIES.map((body, i) => issueComment({ id: 20 + i, body })))).toEqual(
      BODIES.map((_, i) => ({ noteId: 20 + i, threadId: null, command: 'review', author: 'ann' })),
    );
  });

  it('gives the command the comment asks for', () => {
    expect(
      commands(
        issueComment({ id: 21, body: 'qualor fix' }),
        issueComment({ id: 22, body: 'Qualor Stop', user: person('bob') }),
      ),
    ).toEqual([
      { noteId: 21, threadId: null, command: 'fix', author: 'ann' },
      { noteId: 22, threadId: null, command: 'stop', author: 'bob' },
    ]);
  });

  it('qualor reviewer is not a command', () => {
    expect(commands(issueComment({ id: 21, body: 'qualor review' }))).toHaveLength(1);
    expect(commands(issueComment({ id: 21, body: 'qualor reviewer' }))).toEqual([]);
    expect(commands(issueComment({ id: 21, body: 'please qualor review' }))).toEqual([]);
    expect(commands(issueComment({ id: 21, body: 'a comment about the review' }))).toEqual([]);
  });

  it("GitHub bots' comments, Qualor's own among them, are never commands", () => {
    // The control: a person's comment.
    expect(commands(issueComment({ id: 21 }))).toHaveLength(1);
    expect(commands(issueComment({ id: 21, user: bot(APP) }))).toEqual([]);
    expect(commands(issueComment({ id: 21, user: bot('dependabot[bot]') }))).toEqual([]);
    expect(commands(issueComment({ id: 21, user: null }))).toEqual([]);
    expect(
      commands(issueComment({ id: 21, user: { login: 'acme', type: 'Organization' } })),
    ).toEqual([]);
  });

  it('a command inside a thread is a reply, not a command', () => {
    // A review comment in Qualor's thread with the command's words is a reply to answer ...
    expect(
      githubRounds([start(), reply(11, { body: 'qualor review' })], [listed()], options()),
    ).toEqual([{ threadId: '10', issueId: ISSUE, noteIds: [11], newest: 11, author: 'ann' }]);
    // ... commands are read from the comments on the pull request's page only, where the control
    // is a command.
    expect(commands(issueComment({ id: 11, body: 'qualor review' }))).toEqual([
      { noteId: 11, threadId: null, command: 'review', author: 'ann' },
    ]);
  });

  it('a command before the consent or older than 30 days is ignored', () => {
    const madeAt = (created_at: string) => commands(issueComment({ id: 21, created_at }));
    expect(madeAt(SINCE.toISOString())).toHaveLength(1);
    expect(madeAt(AFTER)).toHaveLength(1);
    expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
    expect(madeAt('2026-09-01T10:00:00Z')).toEqual([]);
    for (const unreadable of UNREADABLE) expect(madeAt(unreadable)).toEqual([]);
    // And no command is recent for a `since` nobody can read.
    const noSince = options({ since: new Date(Number.NaN) });
    expect(githubCommands([issueComment({ id: 21 })], noSince)).toEqual([]);
  });

  it('a comment without a body is no command', () => {
    expect(commands(issueComment({ id: 21 }))).toHaveLength(1);
    expect(commands(issueComment({ id: 21, body: null }))).toEqual([]);
  });

  it('tells people from bots by the account type, so it needs no login of the App', () => {
    const comment = issueComment({ id: 21 });
    expect(githubCommands([comment], options({ qualor: {} }))).toHaveLength(1);
    expect(
      githubCommands([issueComment({ id: 21, user: bot(APP) })], options({ qualor: {} })),
    ).toEqual([]);
  });
});

// ─── Azure DevOps ──────────────────────────────────────────────────────────

/**
 * Qualor's identity in the recordings of the live decoration (`19-threads-*`) and of probe items 15
 * and 20 (the bench's service principal), and the PAT user who replied in item 20's thread.
 */
const AZURE_QUALOR = '7c429e0c-e3c7-43e0-8633-fa6e0000136d';
const AZURE_PERSON = '8bcb5100-06e4-4ee5-865f-fa6e00005496';
/** The recordings' name of both, as the bench's redaction left it. */
const PROBE_USER = 'Probe User';

/** A thread's comment as an Azure DevOps answer holds it: the fields detection reads. */
interface RecordedComment {
  id: number;
  parentCommentId?: number;
  author?: { id?: string; displayName?: string };
  content?: string;
  commentType?: string;
  publishedDate?: string;
  isDeleted?: boolean;
}
interface RecordedThread {
  id: number;
  status?: string;
  comments: RecordedComment[];
}

function azureOptions(fields: Partial<DetectOptions> = {}): DetectOptions {
  return {
    qualor: { azureIdentityId: AZURE_QUALOR },
    largestNoteIds: new Map(),
    since: SINCE,
    ...fields,
  };
}

/** A comment by a person, made after `SINCE`; each case changes what it is about. */
function comment(fields: Partial<AzureThreadComment> & { id: number }): AzureThreadComment {
  return {
    authorId: AZURE_PERSON,
    authorName: 'Ann Smith',
    content: 'This is intended.',
    commentType: 'text',
    parentCommentId: 1,
    publishedDate: AFTER,
    isDeleted: false,
    ...fields,
  };
}

/** Qualor's first comment of a thread: its issue marker on the first line. */
const qualorFirst = (fields: Partial<AzureThreadComment> = {}): AzureThreadComment =>
  comment({
    id: 1,
    authorId: AZURE_QUALOR,
    authorName: 'Qualor',
    content: `${issueMarker(ISSUE)}\n**Medium** · a finding`,
    parentCommentId: 0,
    ...fields,
  });

/** An active thread on a line, of `comments`. */
const azureThread = (
  id: number,
  comments: AzureThreadComment[],
  fields: Partial<AzureThread> = {},
): AzureThread => ({
  id,
  status: 'active',
  filePath: 'src/cart.ts',
  rightLine: 9,
  publishedDate: AFTER,
  comments,
  ...fields,
});

describe('Azure DevOps detection', () => {
  /** A fake that serves the recordings, and a client that reads them as it reads any answer. */
  let fake: FakeAzureDevOps;
  let client: AzureDevOpsClient;
  let repositoryId: string;

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({
      deployment: 'services',
      repositories: [{ name: 'api', projectName: 'Payments' }],
    });
    repositoryId = fake.repositories[0]!.id;
    fake.addPullRequest(repositoryId, { id: 7 });
    const identities = identitiesOf(fake);
    client = new AzureDevOpsClient(
      {
        baseUrl: fake.url,
        credential: patOf(fake),
        allowInternalHosts: true,
        ...(identities ? { identities } : {}),
      },
      { timeoutMs: 2_000 },
    );
  });
  afterAll(async () => {
    await fake.close();
  });

  /**
   * The threads of the recording `name` (`azure-shapes/services/<name>.json`: a listing, or one
   * thread), changed by `edit`, as the client reads them from an answer of Azure DevOps.
   */
  async function recorded(
    name: string,
    edit: (threads: RecordedThread[]) => void = () => undefined,
  ): Promise<AzureThread[]> {
    const shape = azureShape<{
      status: number;
      contentType: string;
      body: RecordedThread | { value: RecordedThread[] };
    }>('services', name);
    const headers = { 'content-type': shape.contentType };
    if ('value' in shape.body) {
      edit(shape.body.value);
      fake.inject('GET', /\/threads$/, { status: 200, headers, body: shape.body });
      return client.threads(repositoryId, 7);
    }
    edit([shape.body]);
    fake.inject('GET', /\/threads\/\d+$/, { status: 200, headers, body: shape.body });
    return [await client.thread(repositoryId, 7, shape.body.id)];
  }
  /** `edit` with the first comment of each thread made Qualor's first comment of an issue's thread. */
  const issueThreads =
    (issues: readonly string[], edit: (threads: RecordedThread[]) => void = () => undefined) =>
    (threads: RecordedThread[]) => {
      threads.forEach((thread, i) => {
        thread.comments[0]!.content = `${issueMarker(issues[i] ?? ISSUE)}\n**Medium** · a finding`;
      });
      edit(threads);
    };
  /** A person's comment `id`, as Azure DevOps lists one, in reply to the thread's first. */
  const personsComment = (id: number, fields: Partial<RecordedComment> = {}): RecordedComment => ({
    id,
    parentCommentId: 1,
    author: { id: AZURE_PERSON, displayName: 'Ann Smith' },
    content: 'We accept this for now.',
    commentType: 'text',
    publishedDate: '2026-11-23T14:00:00.123Z',
    ...fields,
  });
  /** `edit` that adds a person's reply (comment 2) to each recorded thread. */
  const withReply = (threads: RecordedThread[]) => {
    for (const thread of threads) thread.comments.push(personsComment(2));
  };

  describe('azureNoteId', () => {
    it('is the thread id times 65 536 plus the comment id: one counter for every thread', () => {
      expect(azureNoteId(83, 2)).toBe(83 * 65_536 + 2);
      // Comment ids start at 1 in each thread: comment 1 of two threads is two notes.
      expect(azureNoteId(14, 1)).not.toBe(azureNoteId(15, 1));
      // Within a thread the note ids grow with the comment ids, and the last comment Azure DevOps
      // can number (its ids are 16-bit) comes before the next thread's first.
      expect(azureNoteId(83, 2)).toBeLessThan(azureNoteId(83, 3));
      expect(azureNoteId(14, 32_767)).toBeLessThan(azureNoteId(15, 1));
      // A thread id of a hundred billion still gives an exact number.
      expect(Number.isSafeInteger(azureNoteId(100_000_000_000, 32_767))).toBe(true);
    });
  });

  describe('azureRounds', () => {
    const rounds = (threads: AzureThread[], fields: Partial<DetectOptions> = {}) =>
      azureRounds(threads, azureOptions(fields));

    it("a person's reply in Qualor's thread is a round (probe item 20's thread)", async () => {
      const threads = await recorded('20-thread-get', issueThreads([ISSUE]));
      expect(threads[0]!.comments.map((c) => [c.id, c.parentCommentId])).toEqual([
        [1, 0],
        [2, 1],
      ]);
      expect(rounds(threads)).toEqual([
        {
          threadId: '83',
          issueId: ISSUE,
          noteIds: [azureNoteId(83, 2)],
          newest: azureNoteId(83, 2),
          author: PROBE_USER,
        },
      ]);
      // As the recording is, its first comment carries no marker: no thread of Qualor's.
      expect(rounds(await recorded('20-thread-get'))).toEqual([]);
    });

    it("the live decoration's threads: Qualor's issue thread has a round once a person replies; the summary never", async () => {
      // The issue's thread (76) and the summary's (77), as Qualor left them: nobody replied.
      expect(rounds(await recorded('19-threads-first'))).toEqual([]);
      const replied = await recorded('19-threads-first', withReply);
      expect(rounds(replied)).toEqual([
        {
          threadId: '76',
          issueId: markerIssueOf(replied[0]!),
          noteIds: [azureNoteId(76, 2)],
          newest: azureNoteId(76, 2),
          author: 'Ann Smith',
        },
      ]);
    });

    it('a resolved thread has no round: the fixed one of the live decoration, and any status but active', async () => {
      const fixed = await recorded('19-threads-fixed', (threads) => {
        threads[0]!.comments.push(personsComment(3));
      });
      // Thread 76 is fixed, 77 the summary's, 78 Azure DevOps' own (a push), with no status.
      expect(fixed.map((t) => [t.id, t.status])).toEqual([
        [76, 'fixed'],
        [77, 'closed'],
        [78, null],
      ]);
      expect(rounds(fixed)).toEqual([]);
      const withStatus = (status: string | null) =>
        rounds([azureThread(5, [qualorFirst(), comment({ id: 2 })], { status })]);
      // The control: the same thread, active.
      expect(withStatus('active')).toHaveLength(1);
      for (const status of ['fixed', 'wontFix', 'closed', 'byDesign', 'pending', null]) {
        expect(withStatus(status), String(status)).toEqual([]);
      }
    });

    it("Qualor's own answers, comments Azure DevOps made and deleted comments are never replies", () => {
      expect(
        rounds([
          azureThread(5, [
            qualorFirst(),
            // Qualor's answer to an earlier round, and its note of a fix.
            comment({ id: 2, authorId: AZURE_QUALOR, content: 'An answer' }),
            // Azure DevOps' own comments in the thread.
            comment({ id: 3, commentType: 'system', content: 'Ann Smith updated the thread' }),
            comment({ id: 4, commentType: 'codeChange', content: 'The line changed' }),
            // A person's comment that was deleted, with its author and without one.
            comment({ id: 5, isDeleted: true }),
            comment({ id: 6, isDeleted: true, authorId: '', authorName: '', content: '' }),
            // A comment with no author at all.
            comment({ id: 7, authorId: '', authorName: '' }),
            comment({ id: 8 }),
          ]),
        ]),
      ).toEqual([
        {
          threadId: '5',
          issueId: ISSUE,
          noteIds: [azureNoteId(5, 8)],
          newest: azureNoteId(5, 8),
          author: 'Ann Smith',
        },
      ]);
    });

    it("tells Qualor's identity by its id, in either case, not by its name", () => {
      const shouted = AZURE_QUALOR.toUpperCase();
      // Qualor's identity in upper case is still Qualor's: its comment is no reply ...
      expect(
        rounds([azureThread(5, [qualorFirst(), comment({ id: 2, authorId: shouted })])]),
      ).toEqual([]);
      // ... and the thread it opened is Qualor's.
      expect(
        rounds([azureThread(5, [qualorFirst({ authorId: shouted }), comment({ id: 2 })])]),
      ).toHaveLength(1);
      // A person whose name is Qualor's replies, and opens no thread of Qualor's.
      expect(
        rounds([azureThread(5, [qualorFirst(), comment({ id: 2, authorName: 'Qualor' })])]),
      ).toHaveLength(1);
      expect(
        rounds([
          azureThread(5, [
            qualorFirst({ authorId: AZURE_PERSON }),
            comment({ id: 2, authorId: '0f6c1a5e-3b0d-4c39-9a51-fa6e00000009' }),
          ]),
        ]),
      ).toEqual([]);
    });

    it('comment 2 of two threads of one pull request makes two rounds, by their own note ids (probe item 15)', async () => {
      const a = await recorded('15-thread-a1');
      const b = await recorded('15-threads-b');
      // Probe item 15: thread ids come from one counter, comment ids start at 1 in each thread.
      expect([...a, ...b].map((t) => [t.id, t.comments.map((c) => c.id)])).toEqual([
        [14, [1]],
        [15, [1]],
      ]);
      const replied = [
        ...(await recorded('15-thread-a1', issueThreads([ISSUE], withReply))),
        ...(await recorded('15-threads-b', issueThreads([OTHER_ISSUE], withReply))),
      ];
      expect(rounds(replied)).toEqual([
        {
          threadId: '14',
          issueId: ISSUE,
          noteIds: [azureNoteId(14, 2)],
          newest: azureNoteId(14, 2),
          author: 'Ann Smith',
        },
        {
          threadId: '15',
          issueId: OTHER_ISSUE,
          noteIds: [azureNoteId(15, 2)],
          newest: azureNoteId(15, 2),
          author: 'Ann Smith',
        },
      ]);
    });

    it("only comments newer than the ledger's largest note of the thread count", () => {
      const thread = azureThread(5, [
        qualorFirst(),
        comment({ id: 2 }),
        comment({ id: 3 }),
        comment({ id: 4 }),
      ]);
      const ledger = (largest: number, of = '5') =>
        ({ largestNoteIds: new Map([[of, largest]]) }) satisfies Partial<DetectOptions>;
      const all = [2, 3, 4].map((id) => azureNoteId(5, id));
      // The control: the ledger holds nothing of this thread, or only a later thread's notes.
      expect(rounds([thread])[0]?.noteIds).toEqual(all);
      expect(rounds([thread], ledger(azureNoteId(6, 1), '6'))[0]?.noteIds).toEqual(all);
      // It holds up to comment 3: that one and the ones before it are done.
      expect(rounds([thread], ledger(azureNoteId(5, 3)))[0]?.noteIds).toEqual([azureNoteId(5, 4)]);
      // It holds the newest: nothing is left.
      expect(rounds([thread], ledger(azureNoteId(5, 4)))).toEqual([]);
    });

    it('a comment before the consent or older than 30 days, or whose date cannot be read, is ignored', () => {
      const madeAt = (publishedDate: string) =>
        rounds([azureThread(5, [qualorFirst(), comment({ id: 2, publishedDate })])]);
      expect(madeAt(SINCE.toISOString())).toHaveLength(1);
      // Azure DevOps writes two, three or seven digits of a second.
      expect(madeAt('2026-11-23T13:51:47.48Z')).toHaveLength(1);
      expect(madeAt('2026-11-23T13:51:47.4812345Z')).toHaveLength(1);
      expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
      expect(madeAt('2026-09-01T10:00:00.000Z')).toEqual([]);
      for (const unreadable of UNREADABLE) expect(madeAt(unreadable)).toEqual([]);
    });

    it('an edited comment is the same note: its id is kept, whatever its text says now', () => {
      const before = rounds([azureThread(5, [qualorFirst(), comment({ id: 2 })])]);
      const after = rounds([
        azureThread(5, [qualorFirst(), comment({ id: 2, content: 'Edited: we fix it later.' })]),
      ]);
      expect(after).toEqual(before);
      expect(after).toHaveLength(1);
    });

    it("a thread a person started, or one whose first comment is Azure DevOps' own, is no thread of Qualor's", () => {
      const marked = `${issueMarker(ISSUE)}\nA marker typed by a person`;
      expect(
        rounds([
          azureThread(5, [
            comment({ id: 1, parentCommentId: 0, content: marked }),
            comment({ id: 2, authorId: AZURE_QUALOR }),
            comment({ id: 3, authorId: '0f6c1a5e-3b0d-4c39-9a51-fa6e00000009' }),
          ]),
          azureThread(6, [qualorFirst({ commentType: 'system' }), comment({ id: 2 })]),
          azureThread(7, [qualorFirst({ content: `${summaryMarker(PROJECT)}\nThe summary` })]),
        ]),
      ).toEqual([]);
    });

    it("finds nothing when Qualor does not know its own identity; a person's reply without a display name is named by the id", () => {
      const thread = azureThread(5, [qualorFirst(), comment({ id: 2, authorName: '' })]);
      expect(rounds([thread], { qualor: {} })).toEqual([]);
      expect(rounds([thread])[0]?.author).toBe(AZURE_PERSON);
    });
  });

  describe('azureCommands', () => {
    const commands = (threads: AzureThread[], fields: Partial<DetectOptions> = {}) =>
      azureCommands(threads, azureOptions(fields));
    /** A thread a person opened with `content`, on the pull request as a whole. */
    const opened = (id: number, fields: Partial<AzureThreadComment> = {}) =>
      azureThread(
        id,
        [comment({ id: 1, parentCommentId: 0, content: 'qualor review', ...fields })],
        {
          filePath: null,
          rightLine: null,
        },
      );

    it('the first comment of a thread a person opened is a command: comment 1 of two threads gives two (probe item 15)', async () => {
      const asPerson = (threads: RecordedThread[]) => {
        for (const thread of threads) {
          thread.comments[0]!.author = { id: AZURE_PERSON, displayName: 'Ann Smith' };
          thread.comments[0]!.content = 'qualor review';
        }
      };
      const threads = [
        ...(await recorded('15-thread-a1', asPerson)),
        ...(await recorded('15-threads-b', asPerson)),
      ];
      expect(commands(threads)).toEqual([
        { noteId: azureNoteId(14, 1), threadId: '14', command: 'review', author: 'Ann Smith' },
        { noteId: azureNoteId(15, 1), threadId: '15', command: 'review', author: 'Ann Smith' },
      ]);
      // As recorded, the threads are Qualor's own and say no command.
      expect(
        commands([...(await recorded('15-thread-a1')), ...(await recorded('15-threads-b'))]),
      ).toEqual([]);
    });

    it('reads the command the comment gives, as on GitLab and GitHub', () => {
      for (const content of BODIES)
        expect(commands([opened(5, { content })]), content).toHaveLength(1);
      expect(commands([opened(5, { content: 'qualor fix' })])[0]?.command).toBe('fix');
      expect(commands([opened(5, { content: 'Qualor STOP' })])[0]?.command).toBe('stop');
      expect(commands([opened(5, { content: 'qualor reviewer' })])).toEqual([]);
      expect(commands([opened(5, { content: 'please qualor review' })])).toEqual([]);
    });

    it("Qualor's own comments, Azure DevOps' own and deleted comments are never commands", async () => {
      // The control: a person's comment.
      expect(commands([opened(5)])).toHaveLength(1);
      expect(commands([opened(5, { authorId: AZURE_QUALOR.toUpperCase() })])).toEqual([]);
      expect(commands([opened(5, { commentType: 'system' })])).toEqual([]);
      expect(commands([opened(5, { commentType: 'codeChange' })])).toEqual([]);
      expect(commands([opened(5, { isDeleted: true })])).toEqual([]);
      expect(commands([opened(5, { authorId: '', authorName: '' })])).toEqual([]);
      // The live decoration's threads, Azure DevOps' own thread of a push among them, with the
      // command's words in each: Qualor's threads and Azure DevOps' are nobody's command.
      const said = await recorded('19-threads-fixed', (threads) => {
        for (const thread of threads) thread.comments[0]!.content = 'qualor review';
      });
      expect(said.map((t) => t.comments[0]?.commentType)).toEqual(['text', 'text', 'system']);
      expect(commands(said)).toEqual([]);
    });

    it('a command inside a thread is a reply in a thread of Qualor’s, and nothing in a person’s', () => {
      const inQualors = azureThread(5, [
        qualorFirst(),
        comment({ id: 2, content: 'qualor review' }),
      ]);
      expect(commands([inQualors])).toEqual([]);
      expect(azureRounds([inQualors], azureOptions())).toHaveLength(1);
      const inTheirs = azureThread(6, [
        comment({ id: 1, parentCommentId: 0, content: 'A question' }),
        comment({ id: 2, content: 'qualor review' }),
      ]);
      expect(commands([inTheirs])).toEqual([]);
    });

    it('a command before the consent or older than 30 days is ignored', () => {
      const madeAt = (publishedDate: string) => commands([opened(5, { publishedDate })]);
      expect(madeAt(SINCE.toISOString())).toHaveLength(1);
      expect(madeAt(new Date(SINCE.getTime() - 1).toISOString())).toEqual([]);
      for (const unreadable of UNREADABLE) expect(madeAt(unreadable)).toEqual([]);
    });

    it('finds nothing when Qualor does not know its own identity', () => {
      expect(commands([opened(5)], { qualor: {} })).toEqual([]);
    });
  });
});

/** The issue named by the marker of a thread's first comment. */
function markerIssueOf(thread: AzureThread): string {
  const found = /qualor:issue ([0-9a-f-]+)/.exec(thread.comments[0]?.content ?? '');
  if (found === null) throw new Error(`thread ${thread.id} has no issue marker`);
  return found[1]!;
}

// ─── Both ──────────────────────────────────────────────────────────────────

/** Freezes a value and everything in it: a write to it would throw. */
function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

describe('detection', () => {
  it('reads what it is given without changing it, and answers the same twice', () => {
    const discussions = deepFreeze([
      discussion(
        'd1',
        opening(),
        note({ id: 13, author: BOB }),
        note({ id: 11 }),
        note({ id: 12 }),
      ),
      overview('d2', { id: 20, body: 'qualor review' }),
    ]);
    const comments = deepFreeze([start(), reply(13), reply(11), reply(12)]);
    const threads = deepFreeze([listed()]);
    const issueComments = deepFreeze([
      issueComment({ id: 30 }),
      issueComment({ id: 31, body: 'hello' }),
    ]);
    const ledger = new Map([['d1', 10]]);
    const given = deepFreeze(options({ largestNoteIds: ledger }));

    const run = () => ({
      gitlab: gitlabRounds(discussions, given),
      gitlabCommands: gitlabCommands(discussions, given),
      github: githubRounds(comments, threads, given),
      githubCommands: githubCommands(issueComments, given),
    });
    const once = run();
    // Something was found by each, so the equality below means something.
    expect(once.gitlab[0]?.noteIds).toEqual([11, 12, 13]);
    expect(once.gitlabCommands).toHaveLength(1);
    expect(once.github[0]?.noteIds).toEqual([11, 12, 13]);
    expect(once.githubCommands).toHaveLength(1);
    expect(run()).toEqual(once);
    expect([...ledger]).toEqual([['d1', 10]]);
  });
});
