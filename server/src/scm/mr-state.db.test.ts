import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { azureCommitId, seedAzurePullRequest } from '../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { mappedGitHubProject } from '../../test/github';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { decorationDeps, mappedProject, PUBLIC_URL } from '../../test/scm';
import { projects } from '../db/schema';
import { readMergeRequestState } from './mr-state';
import {
  createScmRuntime,
  MAX_DECORATIONS_PER_ORGANIZATION,
  SCM_CIRCUIT_FAILURES,
  type ScmRuntime,
} from './runtime';
import { parseInternalHosts } from './url';

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const GITLAB_PROJECT = 701;
const REPOSITORY = 9_701;

describe('readMergeRequestState (6I-3)', () => {
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let h: IngestHarness;
  let gitlabProject: string;
  let gitlabConnection: string;
  let githubProject: string;
  let unmapped: string;

  const stateOf = (projectId: string, mergeRequestId: string) =>
    readMergeRequestState({ db: h.ctx.db, scm: decorationDeps(h).scm }, projectId, mergeRequestId);

  beforeAll(async () => {
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(gitlab.url).host},${new URL(github.url).host}`,
        ),
      },
    });
    gitlab.addProject({ id: GITLAB_PROJECT, path: 'acme/mrs' });
    const mergeRequest = {
      title: 'A change',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [],
    };
    gitlab.addMergeRequest(GITLAB_PROJECT, { ...mergeRequest, iid: 1, state: 'opened' });
    gitlab.addMergeRequest(GITLAB_PROJECT, { ...mergeRequest, iid: 2, state: 'merged' });
    gitlab.addMergeRequest(GITLAB_PROJECT, { ...mergeRequest, iid: 3, state: 'closed' });
    gitlab.addMergeRequest(GITLAB_PROJECT, {
      ...mergeRequest,
      iid: 4,
      state: 'opened',
      draft: true,
    });
    // As a GitLab before 14 answers: no `draft`, only `work_in_progress`.
    gitlab.addMergeRequest(GITLAB_PROJECT, {
      ...mergeRequest,
      iid: 5,
      state: 'opened',
      legacyDraft: true,
    });
    gitlab.addMergeRequest(GITLAB_PROJECT, {
      ...mergeRequest,
      iid: 6,
      state: 'opened',
      legacyDraft: false,
    });
    const mapped = await mappedProject(h, gitlab, 'mrs/gitlab', GITLAB_PROJECT);
    gitlabProject = mapped.id;
    gitlabConnection = mapped.connectionId;

    github.addRepository({ id: REPOSITORY, owner: 'acme', name: 'prs', installationId: 701 });
    const pull = { title: 'A change', headSha: HEAD, baseSha: BASE, files: [] };
    github.addPull(REPOSITORY, { ...pull, number: 1, state: 'open' });
    github.addPull(REPOSITORY, { ...pull, number: 2, state: 'closed', merged: true });
    github.addPull(REPOSITORY, { ...pull, number: 3, state: 'closed' });
    github.addPull(REPOSITORY, { ...pull, number: 4, state: 'open', draft: true });
    githubProject = (await mappedGitHubProject(h, github, 'mrs/github', 'acme/prs')).id;
    unmapped = (await h.project('mrs/unmapped')).id;
  });
  afterAll(async () => {
    await h.close();
    await gitlab.close();
    await github.close();
  });

  it('GitLab and GitHub open, merged, closed and draft', async () => {
    for (const projectId of [gitlabProject, githubProject]) {
      const states = await Promise.all(['1', '2', '3', '4'].map((id) => stateOf(projectId, id)));
      expect(states).toEqual([
        { state: 'open', draft: false, headSha: HEAD },
        { state: 'merged', draft: false, headSha: HEAD },
        { state: 'closed', draft: false, headSha: HEAD },
        { state: 'open', draft: true, headSha: HEAD },
      ]);
    }
  });

  it('a GitLab before 14 says a draft by work_in_progress', async () => {
    expect(await stateOf(gitlabProject, '5')).toEqual({
      state: 'open',
      draft: true,
      headSha: HEAD,
    });
    expect(await stateOf(gitlabProject, '6')).toEqual({
      state: 'open',
      draft: false,
      headSha: HEAD,
    });
  });

  it('a GitLab state named like a property of every object is one it does not know, never closed', async () => {
    // Read as "not open", such a state would delete the merge request's snapshots; unknown, the
    // hourly check only comes again.
    for (const [iid, state] of [
      [21, 'constructor'],
      [22, 'toString'],
      [23, '__proto__'],
      [24, 'hasOwnProperty'],
    ] as const) {
      gitlab.addMergeRequest(GITLAB_PROJECT, {
        iid,
        title: 'A change',
        state: state as never,
        sourceBranch: 'feature/x',
        targetBranch: 'main',
        headSha: HEAD,
        baseSha: BASE,
        startSha: BASE,
        diffs: [],
      });
      expect(await stateOf(gitlabProject, String(iid)), state).toBeNull();
    }
  });

  it('an SCM error answers null', async () => {
    // A merge request the provider does not know, an answer that is an error, a project that is
    // not mapped, a repository the App is not installed on, and an id that is no merge request's.
    expect(await stateOf(gitlabProject, '99')).toBeNull();
    gitlab.inject('GET', /\/merge_requests\/1$/, { status: 500 });
    expect(await stateOf(gitlabProject, '1')).toBeNull();
    expect(await stateOf(githubProject, '99')).toBeNull();
    expect(await stateOf(unmapped, '1')).toBeNull();
    github.addRepository({ id: 9_702, owner: 'acme', name: 'gone', installationId: null });
    const notInstalled = (await mappedGitHubProject(h, github, 'mrs/gone', 'acme/gone')).id;
    expect(await stateOf(notInstalled, '1')).toBeNull();
    expect(await stateOf(gitlabProject, 'feature/x')).toBeNull();
    // A provider that answers again is read again.
    expect(await stateOf(gitlabProject, '1')).toEqual({
      state: 'open',
      draft: false,
      headSha: HEAD,
    });
  });

  describe("through the scm worker's runtime (the hourly check of 6I-3)", () => {
    const through = (runtime: ScmRuntime, projectId: string, mergeRequestId: string) =>
      readMergeRequestState(
        { db: h.ctx.db, scm: decorationDeps(h).scm, runtime },
        projectId,
        mergeRequestId,
      );
    /** The requests the fake GitLab got for merge request `iid`. */
    const asked = (iid: number) =>
      gitlab.requests.filter((r) => r.path.endsWith(`/merge_requests/${iid}`)).length;
    const takeSlots = (runtime: ScmRuntime) => {
      for (let i = 0; i < MAX_DECORATIONS_PER_ORGANIZATION; i += 1) {
        expect(runtime.slots.tryTake(h.organizationId)).toBe(true);
      }
    };

    it("takes a slot of the project's organisation and gives it back, and finds none: no answer, no request", async () => {
      const runtime = createScmRuntime();
      takeSlots(runtime);
      const before = asked(1);
      expect(await through(runtime, gitlabProject, '1')).toBeNull();
      expect(asked(1)).toBe(before);
      for (let i = 0; i < MAX_DECORATIONS_PER_ORGANIZATION; i += 1) {
        runtime.slots.release(h.organizationId);
      }
      expect(await through(runtime, gitlabProject, '1')).toMatchObject({ state: 'open' });
      // The slot is free again after an answer, and after a failure.
      gitlab.inject('GET', /\/merge_requests\/1$/, { status: 500 });
      expect(await through(runtime, gitlabProject, '1')).toBeNull();
      takeSlots(runtime);
    });

    it('stops asking a provider that keeps failing, and does not count its refusals', async () => {
      const runtime = createScmRuntime();
      // A merge request the provider does not know is an answer: the provider is up.
      for (let i = 0; i < 2 * SCM_CIRCUIT_FAILURES; i += 1) {
        expect(await through(runtime, gitlabProject, '99')).toBeNull();
      }
      expect(await through(runtime, gitlabProject, '1')).toMatchObject({ state: 'open' });
      // Consecutive server errors open the connection's circuit, which then answers without asking.
      gitlab.inject(
        'GET',
        /\/merge_requests\/1$/,
        ...Array.from({ length: SCM_CIRCUIT_FAILURES }, () => ({ status: 500 })),
      );
      for (let i = 0; i < SCM_CIRCUIT_FAILURES; i += 1) {
        expect(await through(runtime, gitlabProject, '1')).toBeNull();
      }
      const before = asked(1);
      expect(await through(runtime, gitlabProject, '1')).toBeNull();
      expect(asked(1)).toBe(before);
      expect(runtime.circuit.inspect(gitlabConnection).state).toBe('open');
      // The circuit belongs to the connection: another one is asked as usual.
      expect(await through(runtime, githubProject, '1')).toMatchObject({ state: 'open' });
    });

    it('takes a state it does not know as an answer, and an id it never sends as none', async () => {
      const runtime = createScmRuntime();
      const failures = () => runtime.circuit.inspect(gitlabConnection).failures;
      gitlab.addMergeRequest(GITLAB_PROJECT, {
        iid: 8,
        title: 'A change',
        state: 'weird' as never,
        sourceBranch: 'feature/x',
        targetBranch: 'main',
        headSha: HEAD,
        baseSha: BASE,
        startSha: BASE,
        diffs: [],
      });
      // The provider answers with a state Qualor has no word for: the request succeeded, so the
      // circuit hears the provider is up and its count of failures starts again.
      runtime.circuit.failure(gitlabConnection);
      runtime.circuit.failure(gitlabConnection);
      expect(await through(runtime, gitlabProject, '8')).toBeNull();
      expect(failures()).toBe(0);
      // An id that is no merge request's is never sent: the circuit hears nothing.
      runtime.circuit.failure(gitlabConnection);
      expect(await through(runtime, gitlabProject, 'feature/x')).toBeNull();
      expect(failures()).toBe(1);
    });

    it("shares the worker's installation tokens with the decorations", async () => {
      const minted = () => github.requests.filter((r) => r.path.endsWith('/access_tokens')).length;
      const runtime = createScmRuntime();
      const start = minted();
      expect(await through(runtime, githubProject, '1')).toMatchObject({ state: 'open' });
      expect(await through(runtime, githubProject, '2')).toMatchObject({ state: 'merged' });
      expect(minted() - start).toBe(1);
      // Without a runtime every read gets a token of its own, as the review job's does.
      await stateOf(githubProject, '1');
      await stateOf(githubProject, '2');
      expect(minted() - start).toBe(3);
    });
  });
});

describe('readMergeRequestState on Azure DevOps (Azure sub-plan 4)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let projectId: string;
  let connectionId: string;

  const stateOf = (id: string, runtime?: ScmRuntime) =>
    readMergeRequestState({ db: h.ctx.db, scm: decorationDeps(h).scm, runtime }, projectId, id);

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({
      deployment: 'server',
      repositories: [{ name: 'prs', projectName: 'Payments' }],
    });
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(new URL(fake.url).host),
      },
    });
    const repositoryId = fake.repositories[0]!.id;
    seedAzurePullRequest(fake, repositoryId, {
      pullRequest: { id: 1 },
      sourceCommit: azureCommitId('one'),
    });
    seedAzurePullRequest(fake, repositoryId, { pullRequest: { id: 2, status: 'completed' } });
    seedAzurePullRequest(fake, repositoryId, { pullRequest: { id: 3, status: 'abandoned' } });
    seedAzurePullRequest(fake, repositoryId, { pullRequest: { id: 4, isDraft: true } });
    const project = await h.project('mrs/azure');
    projectId = project.id;
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: fake.url,
        azureAuth: 'pat',
        token: fake.pat,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    connectionId = (created.json() as { id: string }).id;
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: repositoryId })
      .where(eq(projects.id, projectId));
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('answers open, merged, closed and draft', async () => {
    const states = await Promise.all(['1', '2', '3', '4'].map((id) => stateOf(id)));
    expect(states).toEqual([
      { state: 'open', draft: false, headSha: azureCommitId('one') },
      { state: 'merged', draft: false, headSha: azureCommitId('source') },
      { state: 'closed', draft: false, headSha: azureCommitId('source') },
      { state: 'open', draft: true, headSha: azureCommitId('source') },
    ]);
  });

  it('is null for a branch name that is no pull request id, and asks nothing', async () => {
    fake.clearRequests();
    for (const id of ['feature/x', '', '12345678901', '1a', '-1']) {
      expect(await stateOf(id)).toBeNull();
    }
    expect(fake.requests).toEqual([]);
  });

  it('is null for a pull request Azure DevOps does not know', async () => {
    expect(await stateOf('99')).toBeNull();
  });

  it('shares the worker runtime: no slot is kept, the circuit hears an answer', async () => {
    const runtime = createScmRuntime();
    expect(await stateOf('1', runtime)).toMatchObject({ state: 'open' });
    for (let i = 0; i < MAX_DECORATIONS_PER_ORGANIZATION; i += 1) {
      expect(runtime.slots.tryTake(h.organizationId)).toBe(true);
    }
    expect(runtime.circuit.inspect(connectionId).failures).toBe(0);
  });
});
