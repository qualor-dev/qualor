import type { Report } from '@qualor/shared';
import { and, asc, eq, sql } from 'drizzle-orm';
import { createAuditRecorder } from '../src/audit/recorder';
import { encryptionKey, encryptSecret } from '../src/crypto/secrets';
import { uuidv7 } from '../src/db/ids';
import { first } from '../src/db/rows';
import {
  branches,
  issueChanges,
  issues,
  jobs,
  projects,
  reviewFindings,
  reviewReplies,
  reviewRuns,
  scmConnections,
} from '../src/db/schema';
import { createLlmRuntime } from '../src/llm/job';
import { runUntilIdle } from '../src/queue/worker';
import { reviewHandlers, type ReviewJobDeps } from '../src/review/job';
import { replyHandlers } from '../src/review/reply-job';
import { AI_REPLY_MAX_ATTEMPTS, AI_REPLY_QUEUE, replyKey } from '../src/review/reply-queue';
import { AI_REVIEW_QUEUE } from '../src/review/runs';
import { SCM_TOKEN_AAD } from '../src/scm/connections';
import { firstLineOf, issueMarker, markerOf } from '../src/scm/markdown';
import { enqueueDecoration, SCM_QUEUE } from '../src/scm/queue';
import { parseInternalHosts } from '../src/scm/url';
import { QUIET_AUDIT_LOG } from './audit-log';
import { seedAzurePullRequest, servicesUrlOf } from './azure';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzureRole,
  type FakeAzureThread,
} from './fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from './fake-github';
import { createFakeGitLab, type FakeGitLab } from './fake-gitlab';
import { createFakeLlm, type FakeLlm, type RecordedLlmRequest } from './fake-llm';
import { githubConnection, githubDeps, mappedGitHubProject, pullRequestReport } from './github';
import { createIngestHarness, type IngestHarness, type IngestProject } from './ingest';
import { reviewOff } from './replies';
import { engine, file, reportWith } from './reports';
import { seedAiIssue, storeTestSnapshot } from './review';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  runDecorations,
  silentLogger,
} from './scm';

/*
 * What the tests of the `ai-reply` jobs share (6I-4): a GitLab merge request, a GitHub pull request
 * or an Azure DevOps pull request of a project of its own, analysed and reviewed, as a driver sets
 * it up (`Driver`, `Mr`), and the app, the fakes and the helpers around them
 * (`createReplyHarness`). The answer job's tests (review/reply-job.db.test.ts) and the scan's
 * (review/reply-scan.db.test.ts) run on GitLab and GitHub through the same drivers, and their
 * Azure DevOps cases (Azure sub-plan 5) through the Azure DevOps driver.
 */

export const HEAD = '1'.repeat(40);
/** A later commit of the merge request, which no snapshot is of. */
const NEWER = '2'.repeat(40);
const BASE = 'b'.repeat(40);
export const PATH = 'src/cart.ts';
/** The file the merge request adds, as the snapshot holds it. */
const LINES = Array.from({ length: 30 }, (_, i) => `export const line${i + 1} = ${i + 1};`);
/** The patch of a new file of `lines`. */
const addedPatch = (lines: readonly string[]) => {
  const added = lines.map((line) => `+${line}`).join('\n');
  return `@@ -0,0 +1,${lines.length} @@\n${added}`;
};

/**
 * Who replies: five people with the rights to triage (`member` the least of them), someone with no
 * rights at all, and two with less than the rights. `refused` is a login that GitHub's rules refuse
 * (nobody has it, and no request is made for it); on GitLab it is one more user with no membership.
 */
export const INSIDERS = ['member', 'maintainer', 'owner', 'triager', 'customWriter'] as const;
export const OUTSIDERS = ['outsider', 'reporter', 'customReader'] as const;
export type Person = (typeof INSIDERS)[number] | (typeof OUTSIDERS)[number] | 'refused';
/** GitLab's users of every project: each a member with the level `GITLAB_LEVELS` gives. */
export const GITLAB_USERS: Readonly<Record<Person, number>> = {
  member: 5,
  maintainer: 8,
  owner: 9,
  triager: 10,
  customWriter: 11,
  outsider: 6,
  reporter: 7,
  customReader: 12,
  refused: 13,
};
/** Developer, Maintainer and Owner have the rights; no member, Reporter and Guest have not. */
const GITLAB_LEVELS: Readonly<Record<Person, number | null>> = {
  member: 30,
  maintainer: 40,
  owner: 50,
  triager: 30,
  customWriter: 40,
  outsider: null,
  reporter: 20,
  customReader: 10,
  refused: null,
};
/**
 * GitHub's accounts, with the permission each has on every repository: the roles write, maintain,
 * admin and triage, and a custom role whose base permission is write, have the rights; no
 * permission (GitHub's 404), the read role and a custom role on read have not. The maintainer is an
 * Enterprise Managed User, whose login names its enterprise's short code.
 */
export const GITHUB_USERS: Readonly<
  Record<Person, { login: string; permission: { permission: string; roleName: string } | null }>
> = {
  member: { login: 'octocat', permission: { permission: 'write', roleName: 'write' } },
  maintainer: {
    login: 'mona-cat_octo',
    permission: { permission: 'write', roleName: 'maintain' },
  },
  owner: { login: 'hubot', permission: { permission: 'admin', roleName: 'admin' } },
  triager: { login: 'triage-bob', permission: { permission: 'read', roleName: 'triage' } },
  customWriter: {
    login: 'lead-ann',
    permission: { permission: 'write', roleName: 'security-lead' },
  },
  outsider: { login: 'stranger', permission: null },
  reporter: { login: 'visitor', permission: { permission: 'read', roleName: 'read' } },
  customReader: { login: 'auditor', permission: { permission: 'read', roleName: 'auditor' } },
  refused: { login: '-refused-', permission: null },
};
/**
 * Azure DevOps' people: each an identity of the fake organisation with a role, whose Contribute bit
 * the Git ACL answers. The people with the rights to triage are contributors (the owner an
 * owner), the others readers; `refused` is an identity the organisation does not know, so its
 * lookup finds none.
 */
const AZURE_ROLES: Readonly<Record<Exclude<Person, 'refused'>, FakeAzureRole>> = {
  member: 'contributor',
  maintainer: 'contributor',
  owner: 'owner',
  triager: 'contributor',
  customWriter: 'contributor',
  outsider: 'reader',
  reporter: 'reader',
  customReader: 'reader',
};
/** The identity of `refused` on Azure DevOps: a GUID the fake organisation never added. */
const AZURE_STRANGER = '0f6c1a5e-3b0d-4c39-9a51-fa6e0000beef';
/** An Azure DevOps note id: the thread's id times 65 536, plus the comment's (probe item 12). */
export const azureNote = (threadId: number, commentId: number): number =>
  threadId * 65_536 + commentId;

/** What the model answers, as the reply's prompt asks for it. */
export const decision = (
  verdict: 'keep' | 'wont_fix' | 'false_positive',
  intent: string,
  answer: string,
) => JSON.stringify({ intent, verdict, answer });
export const ACCEPTED = 'Understood: the team accepts this for now.';
export const WONT_FIX = decision('wont_fix', 'priority', ACCEPTED);
export const EXPLAINED = 'The rule flags a call left in the code: remove it, or use the logger.';
export const KEEP = decision('keep', 'question', EXPLAINED);
export const MEMBERS_ONLY = 'the people who replied cannot change the status of this finding';

/** Whether a note opens with the marker of the issue's thread. */
const marksIssue = (body: string, issueId: string): boolean => {
  const marker = markerOf(body);
  return marker?.kind === 'issue' && marker.issueId === issueId;
};

/** A merge request of a project of its own, on one provider, and what a test does with it. */
export interface Mr {
  project: IngestProject;
  branchId: string;
  /** The project's SCM connection, whose circuit the jobs ask. */
  connectionId: string;
  /** The analysis of HEAD, which the review read. */
  analysisId: string;
  /** A newer commit of the merge request is analysed, with no snapshot: answers its analysis. */
  analyseNewer(): Promise<string>;
  /** The snapshot of HEAD of one of the merge request's analyses, unpacked and ready. */
  snapshotOf(analysisId: string): Promise<void>;
  /** Decorates it: Qualor's threads, its summary, and the answers queued. */
  decorate(): Promise<void>;
  /** The id of Qualor's thread of the issue, as the replies ledger names it. */
  threadOf(issueId: string): string;
  /** A person writes in the thread; answers the note's id. */
  reply(threadId: string, body: string, who?: Person): number;
  /** The `n`th of the project's other people with the rights to triage writes in the thread. */
  colleague(threadId: string, body: string, n: number): void;
  /**
   * A person gives a command on the merge request (a note of its own): answers its note, and on
   * GitLab the discussion it opened, where Qualor answers.
   */
  command(body: string, who?: Person): { noteId: number; threadId: string | null };
  /** A person writes a note beside the command: in its discussion on GitLab, on the page on GitHub. */
  writeBeside(command: { threadId: string | null }, body: string): void;
  /**
   * Qualor's answers to the commands: its notes beside the people's notes of a command (not those
   * of its own threads), oldest first; on GitLab each with the discussion it is in.
   */
  commandAnswers(): { id: number; body: string; threadId: string | null }[];
  /** The notes of Qualor's summary of the merge request. */
  summaries(): { id: number; body: string }[];
  /** Qualor's summary of the merge request is deleted. */
  deleteSummaries(): void;
  /** The merge request is a draft, or is none. */
  setDraft(draft: boolean): void;
  /** Runs the decorations that are queued, as the `scm` worker does, and queues none of its own. */
  decorateQueued(): Promise<void>;
  /** Qualor's notes in the thread after its first one: its answers. */
  answers(threadId: string): { id: number; body: string }[];
  resolved(threadId: string): boolean;
  resolveAsPerson(threadId: string): void;
  deleteThread(threadId: string): void;
  /** A person deletes their command: its discussion on GitLab, its comment on GitHub. */
  deleteCommand(command: { noteId: number; threadId: string | null }): void;
  /** A person deletes their note of the thread. */
  deleteNote(threadId: string, noteId: number): void;
  close(): void;
  /**
   * The next post of an answer fails; with `stored`, the provider stored it all the same. The answer
   * is the one to a reply, or with `to` the one to a command.
   */
  failNextPost(stored: boolean, to?: 'reply' | 'command'): void;
  /** The next resolution of a thread fails, once the answer before it is posted. */
  failNextResolve(): void;
  /** The provider has no such thread when the next answer is posted. */
  goneOnNextPost(): void;
  /** The provider has no such thread when the next one is resolved, once its answer is posted. */
  goneOnNextResolve(): void;
  /** The next read of the merge request's state fails as a provider that is down does (502). */
  failNextMergeRequestRead(): void;
  /** The next read of the thread's notes fails as a provider that is down does (502). */
  failNextThreadRead(): void;
  /** The provider has no such merge request when the next listing of its notes is asked for. */
  goneOnNextListing(): void;
  /** The provider's name of a person, which the changelog quotes. */
  username(who: Person): string;
}

/** What a driver's merge request is set up with, beside its findings. */
export interface SetupOptions {
  /**
   * GitHub: what the App's installation grants, on an installation of the repository's own; the
   * documented App's when left out. GitLab has no such thing, and takes no notice.
   */
  githubPermissions?: Record<string, 'read' | 'write'>;
}

export interface Driver {
  /** A merge request, analysed with the analyzers' `findings`, and reviewed. */
  setup(key: string, findings?: Report['findings'], options?: SetupOptions): Promise<Mr>;
  /** The requests the provider received since the last clear, as `METHOD path`. */
  requests(): string[];
  clearRequests(): void;
}

/** An Azure DevOps pull request, with what the Azure DevOps cases read of the fake. */
export interface AzureMr extends Mr {
  /** The repository's id (a GUID), which the project is mapped to. */
  repositoryId: string;
  /** The fake's thread of the id, as the ledger names it. */
  thread(threadId: string): FakeAzureThread;
  /** The identity id of a person, which the identities lookup and the ACL are asked about. */
  identityOf(who: Person): string;
}

export interface AzureDriver extends Driver {
  setup(key: string, findings?: Report['findings']): Promise<AzureMr>;
}

/**
 * The app, the fakes of GitLab, GitHub and the model, and the drivers and helpers that act on them.
 * `start` brings them up (once, in a `beforeAll`) and answers the ones a test reaches into; `close`
 * takes them down. The helpers are bound to what `start` makes, so they may be taken before it runs.
 */
export function createReplyHarness() {
  let h: IngestHarness;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let llm: FakeLlm;
  let githubConnectionId: string;
  let azure: FakeAzureDevOps;
  let azureConnectionId: string;
  /** The identity of each person on Azure DevOps (`AZURE_ROLES`), and of each colleague by number. */
  const azurePeople = new Map<Person, string>();
  const azureColleagues = new Map<number, string>();
  let nextGitLabProject = 900;
  let nextRepository = 9_900;
  let day = 1;
  const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });

  /** The branch of the project's merge request. */
  const mergeRequestBranch = async (projectId: string) =>
    first(
      await h.ctx.db
        .select({ id: branches.id })
        .from(branches)
        .where(and(eq(branches.projectId, projectId), eq(branches.kind, 'merge_request'))),
    ).id;
  /** The review of HEAD that is done, and the snapshot it read. */
  const seedReview = async (
    project: IngestProject,
    branchId: string,
    analysisId: string,
    mergeRequestId: string,
  ) => {
    await h.ctx.db.insert(reviewRuns).values({
      projectId: project.id,
      branchId,
      analysisId,
      status: 'done',
      deadlineAt: new Date(),
      headSha: HEAD,
      summary: { verdict: 'The cart has problems.', walkthrough: [], notes: [] },
    });
    await storeSnapshot(analysisId, mergeRequestId);
  };
  /** The analysis' snapshot of HEAD, which adds PATH as LINES, unpacked and ready. */
  const storeSnapshot = async (analysisId: string, mergeRequestId: string) => {
    await storeTestSnapshot(
      h.ctx.db,
      analysisId,
      [
        {
          type: 'change',
          path: PATH,
          oldPath: null,
          status: 'added',
          patch: addedPatch(LINES),
          since: null,
        },
        { type: 'file', path: PATH, text: `${LINES.join('\n')}\n` },
      ],
      {
        headSha: HEAD,
        mergeRequest: { id: mergeRequestId, title: 'Add the cart', description: null },
      },
    );
  };

  const gitlabDriver: Driver = {
    async setup(key, findings = []) {
      // Analysed with AI review off: the test seeds the review that is done.
      await reviewOff(h);
      const gitlabId = nextGitLabProject++;
      gitlab.addProject({ id: gitlabId, path: `acme/${key.replace(/\W/g, '-')}` });
      gitlab.addMergeRequest(gitlabId, {
        iid: 12,
        title: 'Add the cart',
        state: 'opened',
        sourceBranch: 'feature/cart',
        targetBranch: 'main',
        headSha: HEAD,
        baseSha: BASE,
        startSha: BASE,
        diffs: [{ oldPath: PATH, newPath: PATH, diff: addedPatch(LINES), newFile: true }],
      });
      for (const who of Object.keys(GITLAB_USERS) as Person[]) {
        gitlab.setMember(gitlabId, GITLAB_USERS[who], GITLAB_LEVELS[who]);
      }
      const project = await mappedProject(h, gitlab, key, gitlabId);
      const analysisId = await project.ingestOk(
        mergeRequestReport(12, HEAD, {
          projectKey: project.key,
          gitlab: { projectId: String(gitlabId), mergeRequestEventType: 'detached' },
          files: [file(PATH, { lines: LINES.length, newLines: [[1, LINES.length]] })],
          findings,
        }),
      );
      const branchId = await mergeRequestBranch(project.id);
      await seedReview(project, branchId, analysisId, '12');
      const discussion = (threadId: string) => {
        const found = gitlab.discussions(gitlabId, 12).find((d) => d.id === threadId);
        if (found === undefined) throw new Error(`no discussion ${threadId}`);
        return found;
      };
      const notesPath = new RegExp(
        `^/projects/${gitlabId}/merge_requests/12/discussions/([0-9a-f]+)/notes$`,
      );
      const discussionPath = new RegExp(
        `^/projects/${gitlabId}/merge_requests/12/discussions/[0-9a-f]+$`,
      );
      return {
        project,
        branchId,
        connectionId: project.connectionId,
        analysisId,
        analyseNewer: async () => {
          await reviewOff(h);
          return project.ingestOk(
            mergeRequestReport(12, NEWER, {
              projectKey: project.key,
              // A day after the first analysis' (the reports' default date).
              analysisDate: '2026-09-23T10:15:00Z',
              gitlab: { projectId: String(gitlabId), mergeRequestEventType: 'detached' },
              files: [file(PATH, { lines: LINES.length, newLines: [[1, LINES.length]] })],
              findings,
            }),
          );
        },
        snapshotOf: (id) => storeSnapshot(id, '12'),
        decorate: async () => {
          await enqueueDecoration(h.ctx.db, { analysisId, branchId, gitlab: null });
          await runDecorations(h, decorationDeps(h));
        },
        threadOf: (issueId) => {
          const found = gitlab
            .discussions(gitlabId, 12)
            .find((d) => marksIssue(d.notes[0]?.body ?? '', issueId));
          if (found === undefined) throw new Error(`no thread for ${issueId}`);
          return found.id;
        },
        reply: (threadId, body, who = 'member') =>
          gitlab.reply(gitlabId, 12, threadId, { body, authorId: GITLAB_USERS[who] }).id,
        colleague: (threadId, body, n) => {
          gitlab.setMember(gitlabId, 100 + n, 40);
          gitlab.reply(gitlabId, 12, threadId, { body, authorId: 100 + n });
        },
        command: (body, who = 'member') => {
          const opened = gitlab.addNote(gitlabId, 12, { body, authorId: GITLAB_USERS[who] });
          return { noteId: opened.notes[0]!.id, threadId: opened.id };
        },
        writeBeside: ({ threadId }, body) =>
          void gitlab.reply(gitlabId, 12, threadId!, { body, authorId: GITLAB_USERS.member }),
        commandAnswers: () =>
          gitlab
            .discussions(gitlabId, 12)
            .filter((d) => d.notes[0]?.authorId !== gitlab.botUserId)
            .flatMap((d) =>
              d.notes
                .slice(1)
                .filter((n) => n.authorId === gitlab.botUserId)
                .map((n) => ({ id: n.id, body: n.body, threadId: d.id })),
            ),
        summaries: () =>
          gitlab
            .discussions(gitlabId, 12)
            .flatMap((d) => d.notes)
            .filter((n) => n.authorId === gitlab.botUserId && markerOf(n.body)?.kind === 'summary')
            .map((n) => ({ id: n.id, body: n.body })),
        deleteSummaries: () => {
          const list = gitlab.discussions(gitlabId, 12);
          const summarised = list.filter((d) =>
            d.notes.some(
              (n) => n.authorId === gitlab.botUserId && markerOf(n.body)?.kind === 'summary',
            ),
          );
          for (const found of summarised) list.splice(list.indexOf(found), 1);
        },
        setDraft: (draft) => gitlab.updateMergeRequest(gitlabId, 12, { draft }),
        decorateQueued: async () => void (await runDecorations(h, decorationDeps(h))),
        answers: (threadId) =>
          discussion(threadId)
            .notes.slice(1)
            .filter((n) => n.authorId === gitlab.botUserId)
            .map((n) => ({ id: n.id, body: n.body })),
        resolved: (threadId) => {
          const resolvable = discussion(threadId).notes.filter((n) => n.resolvable);
          return resolvable.length > 0 && resolvable.every((n) => n.resolved);
        },
        resolveAsPerson: (threadId) =>
          gitlab.resolveAs(gitlabId, 12, threadId, GITLAB_USERS.member, true),
        deleteThread: (threadId) => {
          const list = gitlab.discussions(gitlabId, 12);
          list.splice(list.indexOf(discussion(threadId)), 1);
        },
        deleteCommand: ({ threadId }) => {
          const list = gitlab.discussions(gitlabId, 12);
          list.splice(list.indexOf(discussion(threadId!)), 1);
        },
        deleteNote: (threadId, noteId) => {
          const { notes } = discussion(threadId);
          notes.splice(
            notes.findIndex((n) => n.id === noteId),
            1,
          );
        },
        close: () => gitlab.updateMergeRequest(gitlabId, 12, { state: 'closed' }),
        failNextPost: (stored) =>
          gitlab.inject('POST', notesPath, {
            status: 502,
            ...(stored
              ? {
                  // GitLab made the note, and the answer never came back.
                  before: () => {
                    const sent = gitlab.requests.at(-1)!;
                    const threadId = notesPath.exec(sent.path)?.[1] ?? '';
                    const { body } = JSON.parse(sent.body) as { body: string };
                    gitlab.reply(gitlabId, 12, threadId, { body, authorId: gitlab.botUserId });
                    return Promise.resolve();
                  },
                }
              : {}),
          }),
        failNextResolve: () => gitlab.inject('PUT', discussionPath, { status: 500 }),
        goneOnNextPost: () =>
          gitlab.inject('POST', notesPath, {
            status: 404,
            body: { message: '404 Discussion Not Found' },
          }),
        goneOnNextResolve: () =>
          gitlab.inject('PUT', discussionPath, {
            status: 404,
            body: { message: '404 Discussion Not Found' },
          }),
        failNextMergeRequestRead: () =>
          gitlab.inject('GET', new RegExp(`^/projects/${gitlabId}/merge_requests/12$`), {
            status: 502,
          }),
        failNextThreadRead: () =>
          gitlab.inject(
            'GET',
            new RegExp(`^/projects/${gitlabId}/merge_requests/12/discussions$`),
            { status: 502 },
          ),
        goneOnNextListing: () =>
          gitlab.inject(
            'GET',
            new RegExp(`^/projects/${gitlabId}/merge_requests/12/discussions$`),
            { status: 404, body: { message: '404 Not found' } },
          ),
        username: (who) => `user${GITLAB_USERS[who]}`,
      };
    },
    requests: () => gitlab.requests.map((r) => `${r.method} ${r.path}`),
    clearRequests: () => gitlab.clearRequests(),
  };

  const githubDriver: Driver = {
    async setup(key, findings = [], options = {}) {
      // Analysed with AI review off: the test seeds the review that is done.
      await reviewOff(h);
      const repo = { id: nextRepository++, name: key.replace(/\W/g, '-') };
      const permissions = options.githubPermissions;
      // An installation grants the same to all its repositories: one of its own grants its own.
      github.addRepository({
        id: repo.id,
        owner: 'acme',
        name: repo.name,
        installationId: permissions === undefined ? 990 : repo.id,
        ...(permissions === undefined ? {} : { permissions }),
      });
      github.addPull(repo.id, {
        number: 7,
        title: 'Add the cart',
        state: 'open',
        headSha: HEAD,
        baseSha: BASE,
        files: [{ filename: PATH, status: 'added', patch: addedPatch(LINES) }],
      });
      for (const { login, permission } of Object.values(GITHUB_USERS)) {
        github.setPermission(repo.id, login, permission);
      }
      const project = await mappedGitHubProject(h, github, key, `acme/${repo.name}`, {
        connectionId: githubConnectionId,
      });
      const context = { repositoryId: String(repo.id), checkout: 'head' as const };
      const analysisId = await project.ingestOk(
        pullRequestReport(7, HEAD, {
          projectKey: project.key,
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          engines: [engine('eslint')],
          files: [file(PATH, { lines: LINES.length, newLines: [[1, LINES.length]] })],
          findings,
          github: context,
        }),
      );
      const branchId = await mergeRequestBranch(project.id);
      await seedReview(project, branchId, analysisId, '7');
      const threadOf = (threadId: string) => {
        const found = github.reviewThreads.find((t) => t.commentIds[0] === Number(threadId));
        if (found === undefined) throw new Error(`no thread of comment ${threadId}`);
        return found;
      };
      const replies = new RegExp(`^/repos/acme/${repo.name}/pulls/7/comments/(\\d+)/replies$`);
      const issueComments = new RegExp(`^/repos/acme/${repo.name}/issues/7/comments$`);
      return {
        project,
        branchId,
        connectionId: project.connectionId,
        analysisId,
        analyseNewer: async () => {
          await reviewOff(h);
          return project.ingestOk(
            pullRequestReport(7, NEWER, {
              projectKey: project.key,
              analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
              engines: [engine('eslint')],
              files: [file(PATH, { lines: LINES.length, newLines: [[1, LINES.length]] })],
              findings,
              github: context,
            }),
          );
        },
        snapshotOf: (id) => storeSnapshot(id, '7'),
        decorate: async () => {
          await enqueueDecoration(h.ctx.db, {
            analysisId,
            branchId,
            gitlab: null,
            github: context,
          });
          await runDecorations(h, githubDeps(h));
        },
        threadOf: (issueId) => {
          const found = github.reviewComments.find(
            (c) => c.repoId === repo.id && c.inReplyToId === null && marksIssue(c.body, issueId),
          );
          if (found === undefined) throw new Error(`no thread for ${issueId}`);
          return String(found.id);
        },
        reply: (threadId, body, who = 'member') =>
          github.replyToReviewComment(repo.id, 7, Number(threadId), {
            body,
            login: GITHUB_USERS[who].login,
          }).id,
        colleague: (threadId, body, n) => {
          github.setPermission(repo.id, `dev-${n}`, { permission: 'write', roleName: 'write' });
          github.replyToReviewComment(repo.id, 7, Number(threadId), { body, login: `dev-${n}` });
        },
        command: (body, who = 'member') => {
          const written = github.addComment(repo.id, 7, { body, login: GITHUB_USERS[who].login });
          return { noteId: written.id, threadId: null };
        },
        writeBeside: (_command, body) =>
          void github.addComment(repo.id, 7, { body, login: GITHUB_USERS.member.login }),
        commandAnswers: () =>
          github.comments
            .filter(
              (c) =>
                c.repoId === repo.id &&
                c.issue === 7 &&
                c.user.type === 'Bot' &&
                firstLineOf(c.body).startsWith('<!-- qualor:reply '),
            )
            .map((c) => ({ id: c.id, body: c.body, threadId: null })),
        summaries: () =>
          github.comments
            .filter(
              (c) => c.repoId === repo.id && c.issue === 7 && markerOf(c.body)?.kind === 'summary',
            )
            .map((c) => ({ id: c.id, body: c.body })),
        deleteSummaries: () => {
          const summarised = github.comments.filter(
            (c) => c.repoId === repo.id && c.issue === 7 && markerOf(c.body)?.kind === 'summary',
          );
          for (const found of summarised) github.comments.splice(github.comments.indexOf(found), 1);
        },
        setDraft: (draft) => github.updatePull(repo.id, 7, { draft }),
        decorateQueued: async () => void (await runDecorations(h, githubDeps(h))),
        answers: (threadId) =>
          github.reviewComments
            .filter((c) => c.inReplyToId === Number(threadId) && c.user.type === 'Bot')
            .map((c) => ({ id: c.id, body: c.body })),
        resolved: (threadId) => threadOf(threadId).resolved,
        resolveAsPerson: (threadId) => github.resolveThreadAs(threadOf(threadId).id, 'octocat'),
        deleteCommand: ({ noteId }) => {
          github.comments.splice(
            github.comments.findIndex((c) => c.repoId === repo.id && c.id === noteId),
            1,
          );
        },
        deleteThread: (threadId) => {
          const thread = threadOf(threadId);
          github.reviewThreads.splice(github.reviewThreads.indexOf(thread), 1);
          for (const id of thread.commentIds) {
            github.reviewComments.splice(
              github.reviewComments.findIndex((c) => c.id === id),
              1,
            );
          }
        },
        deleteNote: (threadId, noteId) => {
          const thread = threadOf(threadId);
          thread.commentIds.splice(thread.commentIds.indexOf(noteId), 1);
          github.reviewComments.splice(
            github.reviewComments.findIndex((c) => c.id === noteId),
            1,
          );
        },
        close: () => github.updatePull(repo.id, 7, { state: 'closed' }),
        failNextPost: (stored, to = 'reply') =>
          github.inject('POST', to === 'reply' ? replies : issueComments, {
            status: 502,
            body: { message: 'Bad Gateway' },
            ...(stored
              ? {
                  // GitHub made the comment, and the answer never came back.
                  before: () => {
                    const sent = github.requests.at(-1)!;
                    const { body } = JSON.parse(sent.body) as { body: string };
                    const bot = { body, login: `${github.slug}[bot]`, type: 'Bot' } as const;
                    if (to === 'command') {
                      github.addComment(repo.id, 7, bot);
                      return;
                    }
                    const firstId = Number(replies.exec(sent.path.split('?')[0] ?? '')?.[1]);
                    github.replyToReviewComment(repo.id, 7, firstId, bot);
                  },
                }
              : {}),
          }),
        failNextResolve: () =>
          github.inject('POST', replies, {
            status: 0,
            passThrough: true,
            before: () =>
              github.inject('POST', /^\/api\/graphql$/, {
                status: 502,
                body: { message: 'Bad Gateway' },
              }),
          }),
        goneOnNextPost: () =>
          github.inject('POST', replies, { status: 404, body: { message: 'Not Found' } }),
        goneOnNextResolve: () =>
          github.inject('POST', replies, {
            status: 0,
            passThrough: true,
            // GraphQL's answer for a thread whose comments were deleted meanwhile.
            before: () =>
              github.inject('POST', /^\/api\/graphql$/, {
                status: 200,
                body: {
                  data: { resolveReviewThread: null },
                  errors: [
                    {
                      type: 'NOT_FOUND',
                      path: ['resolveReviewThread'],
                      message: 'Could not resolve to a node.',
                    },
                  ],
                },
              }),
          }),
        failNextMergeRequestRead: () =>
          github.inject('GET', new RegExp(`^/repos/acme/${repo.name}/pulls/7$`), {
            status: 502,
            body: { message: 'Bad Gateway' },
          }),
        failNextThreadRead: () =>
          github.inject('GET', new RegExp(`^/repos/acme/${repo.name}/pulls/7/comments$`), {
            status: 502,
            body: { message: 'Bad Gateway' },
          }),
        goneOnNextListing: () =>
          github.inject('GET', new RegExp(`^/repos/acme/${repo.name}/pulls/7/comments$`), {
            status: 404,
            body: { message: 'Not Found' },
          }),
        username: (who) => GITHUB_USERS[who].login,
      };
    },
    requests: () => github.requests.map((r) => `${r.method} ${r.path}`),
    clearRequests: () => github.clearRequests(),
  };

  /** The `scm` deps of the jobs and decorations: a Services organisation is sent to the fake. */
  const scmDeps = () => ({
    ...decorationDeps(h).scm,
    azureTestOrigin: h.ctx.config.azureTestOrigin,
  });
  /** The identity of a person on Azure DevOps. */
  const azureIdentityOf = (who: Person): string => {
    const id = azurePeople.get(who);
    if (id === undefined) throw new Error(`no Azure DevOps identity for ${who}`);
    return id;
  };

  const azureDriver: AzureDriver = {
    async setup(key, findings = []) {
      // Analysed with AI review off: the test seeds the review that is done.
      await reviewOff(h);
      const { id: repositoryId } = azure.addRepository({
        name: key.replace(/\W/g, '-'),
        projectName: 'Shop',
      });
      const { pullRequest } = seedAzurePullRequest(azure, repositoryId, {
        pullRequest: { id: 7, title: 'Add the cart', sourceRefName: 'refs/heads/feature/cart' },
        sourceCommit: HEAD,
        baseCommit: BASE,
        changes: [{ path: PATH, changeType: 'add' }],
        files: { [PATH]: `${LINES.join('\n')}\n` },
      });
      const project = await h.project(key);
      await h.ctx.db
        .update(projects)
        .set({ scmConnectionId: azureConnectionId, scmProjectRef: repositoryId })
        .where(eq(projects.id, project.id));
      const context = { repositoryId, checkout: 'head' as const };
      const ingest = (revision: string) => {
        const report = reportWith({
          projectKey: project.key,
          branch: 'feature/cart',
          mergeRequest: { id: '7', targetBranch: 'main', sourceBranch: 'feature/cart' },
          revision,
          baseline: { revision: BASE, kind: 'merge_base', status: 'ok' },
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          engines: [engine('eslint')],
          files: [file(PATH, { lines: LINES.length, newLines: [[1, LINES.length]] })],
          findings,
        });
        return project.ingestOk({
          ...report,
          scm: { ...report.scm, provider: 'azure', azure: context },
        });
      };
      const analysisId = await ingest(HEAD);
      const branchId = await mergeRequestBranch(project.id);
      await seedReview(project, branchId, analysisId, '7');
      const qualor = azure.patUser.id;
      const own = (authorId: string | undefined) =>
        authorId !== undefined && authorId.toLowerCase() === qualor.toLowerCase();
      const thread = (threadId: string) => {
        const found = pullRequest.threads.find((t) => t.id === Number(threadId));
        if (found === undefined) throw new Error(`no thread ${threadId}`);
        return found;
      };
      const issueThread = (issueId: string) =>
        pullRequest.threads.find(
          (t) => own(t.comments[0]?.authorId) && marksIssue(t.comments[0]?.content ?? '', issueId),
        );
      const commentOf = (threadId: string, noteId: number) => {
        const found = thread(threadId).comments.find(
          (c) => azureNote(Number(threadId), c.id) === noteId,
        );
        if (found === undefined) throw new Error(`no note ${noteId} in thread ${threadId}`);
        return found;
      };
      /** Qualor's comments in the thread after its first one. */
      const qualorsAfterFirst = (t: FakeAzureThread) =>
        t.comments
          .slice(1)
          .filter((c) => own(c.authorId))
          .map((c) => ({ id: azureNote(t.id, c.id), body: c.content }));
      /**
       * Qualor's thread of each open AI finding that has none, as Qualor's identity writes it: on
       * its line, with the issue's marker. The decoration does not post the AI review's threads on
       * Azure DevOps yet (sub-plan 5, Task 5); once it does, it finds them here already.
       */
      const postAiThreads = async () => {
        const open = await h.ctx.db
          .select({ id: issues.id, line: issues.startLine, message: issues.message })
          .from(issues)
          .innerJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
          .where(and(eq(issues.branchId, branchId), eq(issues.status, 'open')));
        for (const issue of open) {
          if (issueThread(issue.id) !== undefined) continue;
          azure.addThread(repositoryId, 7, {
            filePath: PATH,
            line: issue.line ?? 1,
            comments: [
              {
                content: `${issueMarker(issue.id)}\n**Medium** · ${issue.message}`,
                authorId: qualor,
              },
            ],
          });
        }
      };
      const decorateQueued = async () => {
        await runDecorations(h, decorationDeps(h, { scm: scmDeps() }));
        await postAiThreads();
      };
      const pullRequestPath = `/repositories/${repositoryId}/pullrequests/7`;
      const commentsPath = new RegExp(`${pullRequestPath}/threads/(\\d+)/comments$`);
      const threadPath = new RegExp(`${pullRequestPath}/threads/\\d+$`);
      const json = { 'content-type': 'application/json; charset=utf-8; api-version=7.0' };
      const notFound = {
        status: 404,
        headers: json,
        body: { message: 'TF401152: The thread does not exist.', typeKey: 'NotFound' },
      };
      const badGateway = { status: 502, headers: json, body: { message: 'Bad Gateway' } };
      return {
        project,
        branchId,
        connectionId: azureConnectionId,
        analysisId,
        repositoryId,
        analyseNewer: async () => {
          await reviewOff(h);
          return ingest(NEWER);
        },
        snapshotOf: (id) => storeSnapshot(id, '7'),
        decorate: async () => {
          await enqueueDecoration(h.ctx.db, { analysisId, branchId, gitlab: null, azure: context });
          await decorateQueued();
        },
        threadOf: (issueId) => {
          const found = issueThread(issueId);
          if (found === undefined) throw new Error(`no thread for ${issueId}`);
          return String(found.id);
        },
        reply: (threadId, body, who = 'member') =>
          azureNote(
            Number(threadId),
            azure.addComment(repositoryId, 7, Number(threadId), {
              content: body,
              authorId: azureIdentityOf(who),
              parentCommentId: 1,
            }).id,
          ),
        colleague: (threadId, body, n) => {
          let id = azureColleagues.get(n);
          if (id === undefined) {
            id = azure.addUser({ role: 'contributor', displayName: `Azure dev ${n}` }).id;
            azureColleagues.set(n, id);
          }
          azure.addComment(repositoryId, 7, Number(threadId), {
            content: body,
            authorId: id,
            parentCommentId: 1,
          });
        },
        command: (body, who = 'member') => {
          const opened = azure.addThread(repositoryId, 7, {
            comments: [{ content: body, authorId: azureIdentityOf(who) }],
          });
          return { noteId: azureNote(opened.id, 1), threadId: String(opened.id) };
        },
        writeBeside: ({ threadId }, body) =>
          void azure.addComment(repositoryId, 7, Number(threadId), {
            content: body,
            authorId: azureIdentityOf('member'),
            parentCommentId: 1,
          }),
        commandAnswers: () =>
          pullRequest.threads
            .filter((t) => t.status !== null && !own(t.comments[0]?.authorId))
            .flatMap((t) => qualorsAfterFirst(t).map((a) => ({ ...a, threadId: String(t.id) }))),
        summaries: () =>
          pullRequest.threads.flatMap((t) =>
            t.comments
              .filter((c) => own(c.authorId) && markerOf(c.content)?.kind === 'summary')
              .map((c) => ({ id: azureNote(t.id, c.id), body: c.content })),
          ),
        deleteSummaries: () => {
          const summarised = pullRequest.threads.filter(
            (t) =>
              own(t.comments[0]?.authorId) && markerOf(t.comments[0]!.content)?.kind === 'summary',
          );
          for (const found of summarised) {
            pullRequest.threads.splice(pullRequest.threads.indexOf(found), 1);
          }
        },
        setDraft: (draft) => {
          pullRequest.isDraft = draft;
        },
        decorateQueued,
        answers: (threadId) => qualorsAfterFirst(thread(threadId)),
        resolved: (threadId) => thread(threadId).status !== 'active',
        resolveAsPerson: (threadId) => {
          thread(threadId).status = 'fixed';
        },
        deleteThread: (threadId) => {
          pullRequest.threads.splice(pullRequest.threads.indexOf(thread(threadId)), 1);
        },
        // Azure DevOps keeps a deleted comment in its thread, without its author or its text.
        deleteCommand: ({ threadId }) => {
          thread(threadId!).comments[0]!.isDeleted = true;
        },
        deleteNote: (threadId, noteId) => {
          commentOf(threadId, noteId).isDeleted = true;
        },
        close: () => {
          pullRequest.status = 'abandoned';
        },
        failNextPost: (stored) =>
          azure.inject('POST', commentsPath, {
            ...badGateway,
            ...(stored
              ? {
                  // Azure DevOps made the comment, and the answer never came back.
                  before: () => {
                    const sent = azure.requests.at(-1)!;
                    const threadId = Number(commentsPath.exec(sent.path)?.[1]);
                    const { content, parentCommentId } = JSON.parse(sent.body) as {
                      content: string;
                      parentCommentId: number;
                    };
                    azure.addComment(repositoryId, 7, threadId, {
                      content,
                      authorId: qualor,
                      parentCommentId,
                    });
                    return Promise.resolve();
                  },
                }
              : {}),
          }),
        failNextResolve: () => azure.inject('PATCH', threadPath, { ...badGateway, status: 500 }),
        goneOnNextPost: () => azure.inject('POST', commentsPath, notFound),
        goneOnNextResolve: () => azure.inject('PATCH', threadPath, notFound),
        failNextMergeRequestRead: () =>
          azure.inject('GET', new RegExp(`${pullRequestPath}$`), badGateway),
        failNextThreadRead: () =>
          azure.inject('GET', new RegExp(`${pullRequestPath}/threads(?:/\\d+)?$`), badGateway),
        goneOnNextListing: () =>
          azure.inject('GET', new RegExp(`${pullRequestPath}/threads$`), {
            ...notFound,
            body: { message: 'TF401180: The requested pull request was not found.' },
          }),
        username: (who) =>
          azure.users.find((u) => u.id === azureIdentityOf(who))?.displayName ??
          azureIdentityOf(who),
        thread,
        identityOf: azureIdentityOf,
      };
    },
    requests: () => azure.requests.map((r) => `${r.method} ${r.path}`),
    clearRequests: () => azure.clearRequests(),
  };

  /** An open finding of the AI review on `line`, as the review of HEAD left it. */
  const aiFinding = async (branchId: string, line: number) => {
    const id = await seedAiIssue(h.ctx.db, {
      branchId,
      category: 'logic',
      path: PATH,
      line,
      severity: 'medium',
    });
    await h.ctx.db
      .update(issues)
      .set({ message: `Line ${line} is wrong` })
      .where(eq(issues.id, id));
    await h.ctx.db.insert(reviewFindings).values({
      issueId: id,
      category: 'logic',
      body: `Why line ${line} is wrong, and how to fix it.`,
      anchorLine: line,
      reviewedHeadSha: HEAD,
    });
    return id;
  };
  const rowOfNote = async (branchId: string, noteId: number) =>
    first(
      await h.ctx.db
        .select()
        .from(reviewReplies)
        .where(and(eq(reviewReplies.branchId, branchId), eq(reviewReplies.noteId, noteId))),
    );
  const rowById = async (id: string) =>
    first(await h.ctx.db.select().from(reviewReplies).where(eq(reviewReplies.id, id)));
  const issueById = async (id: string) =>
    first(await h.ctx.db.select().from(issues).where(eq(issues.id, id)));
  const changesOf = (issueId: string) =>
    h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issueId))
      .orderBy(issueChanges.id);
  /** The `ai-reply` jobs of the row, oldest first. */
  const jobsOf = (replyId: string) =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, AI_REPLY_QUEUE), sql`${jobs.payload} ->> 'replyId' = ${replyId}`))
      .orderBy(asc(jobs.createdAt), asc(jobs.id));
  /** The calls to the provider since `from`. */
  const callsSince = (from: number): RecordedLlmRequest[] => llm.requests.slice(from);
  const systemOf = (request: RecordedLlmRequest) =>
    String(
      (request.json as { messages: { role: string; content: string }[] }).messages.find(
        (message) => message.role === 'system',
      )?.content,
    );

  /** The review worker's deps, with the GitHub pacer on a fake clock. */
  const jobDeps = (over: Partial<ReviewJobDeps> = {}): ReviewJobDeps => ({
    db: h.ctx.db,
    config: h.ctx.config,
    logger: silentLogger,
    llmCircuit: createLlmRuntime().circuit,
    scm: scmDeps(),
    scmRuntime: githubDeps(h).runtime,
    shutdown: new AbortController().signal,
    audit: recorder,
    ...over,
  });
  /** Runs the `ai-reply` jobs that are due, as the review worker does. */
  const answer = (over: Partial<ReviewJobDeps> = {}) =>
    runUntilIdle(h.ctx.db, replyHandlers(jobDeps(over)), silentLogger);
  /** Runs `during` while the connection's token cannot be decrypted (the server's key changed). */
  const withUnreadableToken = async (connectionId: string, during: () => Promise<void>) => {
    const [saved] = await h.ctx.db
      .select({ tokenEnc: scmConnections.tokenEnc })
      .from(scmConnections)
      .where(eq(scmConnections.id, connectionId));
    await h.ctx.db
      .update(scmConnections)
      .set({ tokenEnc: encryptSecret(encryptionKey('z'.repeat(32)), 'x', SCM_TOKEN_AAD) })
      .where(eq(scmConnections.id, connectionId));
    try {
      await during();
    } finally {
      await h.ctx.db
        .update(scmConnections)
        .set({ tokenEnc: saved!.tokenEnc })
        .where(eq(scmConnections.id, connectionId));
    }
  };
  /**
   * A scan job as the review worker hands it to its handler, run alone: what the scan queues stays
   * queued. `attempts` is the try it is (the last one is the second).
   */
  const scan = (branchId: string, over: Partial<ReviewJobDeps> = {}, attempts = 1) =>
    replyHandlers(jobDeps(over))[AI_REPLY_QUEUE]!({
      id: uuidv7(),
      queue: AI_REPLY_QUEUE,
      concurrencyKey: replyKey(branchId),
      payload: { kind: 'scan', branchId },
      attempts,
      maxAttempts: AI_REPLY_MAX_ATTEMPTS,
    });
  /** The jobs that failed are due again at once: their retry. */
  const retryNow = () =>
    h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(and(eq(jobs.queue, AI_REPLY_QUEUE), eq(jobs.status, 'queued')));
  /**
   * The row's queued job is due at once, or in an hour: whether a test's worker may take it now. A
   * branch's jobs run in the order they were queued in any case, a job waiting for an earlier one.
   */
  const dueAt = (replyId: string, when: 'now' | 'later') =>
    h.ctx.db
      .update(jobs)
      .set({ runAt: when === 'now' ? sql`now()` : sql`now() + interval '1 hour'` })
      .where(
        and(
          eq(jobs.queue, AI_REPLY_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'replyId' = ${replyId}`,
        ),
      );
  /** Runs the `ai-review` jobs that are due, as the review worker does. */
  const reviews = (over: Partial<ReviewJobDeps> = {}) =>
    runUntilIdle(h.ctx.db, reviewHandlers(jobDeps(over)), silentLogger);
  const runOf = async (analysisId: string) =>
    first(await h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.analysisId, analysisId)));
  const runsOfBranch = (branchId: string) =>
    h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.branchId, branchId));
  /** The `ai-review` jobs queued for the run, each with whether it is due now. */
  const reviewJobsOf = (runId: string) =>
    h.ctx.db
      .select({ due: sql<boolean>`${jobs.runAt} <= now()` })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AI_REVIEW_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'runId' = ${runId}`,
        ),
      );
  /** The review of HEAD that `seedReview` made (it is done) ended otherwise: as `state` says. */
  const endRun = (analysisId: string, state: Partial<typeof reviewRuns.$inferInsert>) =>
    h.ctx.db.update(reviewRuns).set(state).where(eq(reviewRuns.analysisId, analysisId));
  /** The ledger's rows of the commands of the merge request, the oldest note first. */
  const commandRows = (branchId: string) =>
    h.ctx.db
      .select()
      .from(reviewReplies)
      .where(and(eq(reviewReplies.branchId, branchId), eq(reviewReplies.kind, 'command')))
      .orderBy(asc(reviewReplies.noteId));
  const commandRow = async (branchId: string, noteId: number) =>
    first((await commandRows(branchId)).filter((row) => row.noteId === noteId));
  /** The decorations queued for the analysis. */
  const queuedDecorations = (analysisId: string) =>
    h.ctx.db
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, SCM_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'analysisId' = ${analysisId}`,
        ),
      );

  /**
   * Brings up the model's, GitLab's, GitHub's and Azure DevOps' fakes and the app, with a GitHub
   * connection and an Azure DevOps one (a Services organisation, by PAT, whose user is Qualor's
   * identity), and the Azure DevOps people of `AZURE_ROLES`.
   */
  async function start() {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    azure = await createFakeAzureDevOps({ deployment: 'services' });
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          [gitlab.url, github.url, azure.url].map((url) => new URL(url).host).join(','),
        ),
        // A Services organisation's requests go to the fake (test/azure.ts, ruling 5).
        azureTestOrigin: new URL(azure.url).origin,
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
    githubConnectionId = await githubConnection(h, github);
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: servicesUrlOf(azure),
        azureAuth: 'pat',
        token: azure.pat,
      },
    });
    if (created.statusCode !== 201) throw new Error(`Azure DevOps connection: ${created.body}`);
    azureConnectionId = (created.json() as { id: string }).id;
    for (const [who, role] of Object.entries(AZURE_ROLES)) {
      azurePeople.set(who as Person, azure.addUser({ role, displayName: `Azure ${who}` }).id);
    }
    azurePeople.set('refused', AZURE_STRANGER);
    return { h, gitlab, github, llm, azure };
  }
  async function close() {
    await h.close();
    await gitlab.close();
    await github.close();
    await azure.close();
    await llm.close();
  }

  return {
    start,
    close,
    gitlabDriver,
    githubDriver,
    azureDriver,
    aiFinding,
    rowOfNote,
    rowById,
    issueById,
    changesOf,
    jobsOf,
    callsSince,
    systemOf,
    answer,
    withUnreadableToken,
    scan,
    retryNow,
    dueAt,
    reviews,
    runOf,
    runsOfBranch,
    reviewJobsOf,
    endRun,
    commandRows,
    commandRow,
    queuedDecorations,
  };
}
