import { and, asc, eq, like, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { servicesUrlOf } from '../../test/azure';
import {
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
  type FakeAzureRepository,
  type FakeAzureRepositoryInput,
} from '../../test/fake-azure-devops';
import {
  createFakeGitHub,
  githubWrites,
  type FakeGitHub,
  type FakeRepository,
} from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { PUBLIC_URL } from '../../test/scm';
import type { AuditRecorder } from '../audit/recorder';
import { hashToken } from '../auth/tokens';
import {
  analyses,
  apiTokens,
  auditEvents,
  jobs,
  organizations,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  reviewSnapshots,
  scmConnections,
  users,
} from '../db/schema';
import { VERSION } from '../index';
import { runUntilIdle } from '../queue/worker';
import { REVIEW_SNAPSHOT_QUEUE } from '../review/snapshot-store';
import { InstallationTokenCache, MutationPacer } from '../scm/github/app-auth';
import { minorOf } from './ci-setup';
import {
  azureProjectKey,
  ciHostOf,
  reconcileStuckSetupRuns,
  REPOSITORY_SETUP_QUEUE,
  repositorySetupHandlers,
  setupErrorStage,
  setupKeyOf,
  type SetupRunDeps,
} from './setup-run';

interface Item {
  ref: string;
  name: string;
  project: { id: string; key: string } | null;
  projectOutcome: string;
  ciOutcome: string;
  ciUrl: string | null;
  ciReason: string | null;
  snippet: string | null;
  token: string | null;
  error: { code: string; message: string; stage: 'read' | 'change' | null } | null;
  azure: {
    pipelineUrl: string | null;
    queue: string | null;
    policy: string | null;
    policyError: string | null;
  } | null;
}
interface Run {
  id: string;
  status: string;
  ciSetup: boolean;
  items: Item[];
}

/** What CI setup needs of a GitHub App installation, besides what the guide's App has. */
const ALL = {
  checks: 'write',
  contents: 'write',
  issues: 'read',
  metadata: 'read',
  pull_requests: 'write',
  workflows: 'write',
  secrets: 'write',
} as const;
const WORKFLOW = '.github/workflows/qualor.yml';
const BRANCH = 'qualor/setup';
/** The Azure DevOps pipeline's CI trigger: its settings are the YAML's own `trigger:` block. */
const YAML_CI_TRIGGER = [
  {
    triggerType: 'continuousIntegration',
    settingsSourceType: 2,
    branchFilters: [],
    pathFilters: [],
    batchChanges: false,
    maxConcurrentBuildsPerBranch: 1,
  },
];

describe('the repository-setup run', () => {
  let h: IngestHarness;
  let recorder: AuditRecorder;
  let adminId: string;
  let otherAdmin: Session;
  let member: Session;
  let outsider: Session;
  const hosts = new Set<string>();
  const closers: (() => Promise<void>)[] = [];

  /** Mutations a second apart, without the wait: the pacer's clock moves when it sleeps. */
  const runtime = () => {
    let clock = Date.now();
    return {
      githubTokens: new InstallationTokenCache(),
      azureTokens: new InstallationTokenCache(),
      githubPacer: new MutationPacer(
        () => clock,
        async (ms) => {
          clock += ms;
        },
      ),
    };
  };
  const deps = (overrides: Partial<SetupRunDeps> = {}): SetupRunDeps => ({
    db: h.ctx.db,
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      azureTokenOrigin: null,
      azureTestOrigin: null,
      clientOptions: { timeoutMs: 2_000 },
      githubClientOptions: { timeoutMs: 2_000 },
    },
    runtime: runtime(),
    publicUrl: PUBLIC_URL,
    audit: recorder,
    logger: h.ctx.app.log,
    ...overrides,
  });
  const runSetups = (overrides: Partial<SetupRunDeps> = {}) =>
    runUntilIdle(h.ctx.db, repositorySetupHandlers(deps(overrides)), h.ctx.app.log);

  const github = async (repos: Omit<FakeRepository, 'id'>[]): Promise<FakeGitHub> => {
    const fake = await createFakeGitHub();
    closers.push(() => fake.close());
    hosts.add(new URL(fake.url).host);
    repos.forEach((repo, i) => fake.addRepository({ ...repo, id: 1000 + i }));
    return fake;
  };
  const gitlab = async (): Promise<FakeGitLab> => {
    const fake = await createFakeGitLab();
    closers.push(() => fake.close());
    hosts.add(new URL(fake.url).host);
    fake.accessLevel = 40;
    return fake;
  };
  const connect = async (body: Record<string, unknown>): Promise<string> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: { organizationId: h.organizationId, ...body },
    });
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const connectGitHub = (fake: FakeGitHub) =>
    connect({
      provider: 'github',
      baseUrl: fake.url,
      appId: String(fake.appId),
      privateKey: fake.privateKeyPem,
    });
  const connectGitLab = (fake: FakeGitLab, ciSetupAllowed = true) =>
    connect({ provider: 'gitlab', baseUrl: fake.url, token: fake.token, ciSetupAllowed });

  const post = (body: Record<string, unknown>, session: Session = h.orgAdmin) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/repository-setups',
      headers: session.headers,
      payload: { organizationId: h.organizationId, ...body },
    });
  const start = async (
    body: { connectionId: string; repositories: string[]; ciSetup: boolean; azurePool?: string },
    session: Session = h.orgAdmin,
  ): Promise<string> => {
    const res = await post(body, session);
    expect(res.statusCode, res.body).toBe(202);
    return (res.json() as { id: string }).id;
  };
  const get = (id: string, session: Session = h.orgAdmin) =>
    h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/repository-setups/${id}`,
      headers: session.headers,
    });
  const read = async (id: string, session: Session = h.orgAdmin): Promise<Run> => {
    const res = await get(id, session);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as Run;
  };
  const tokensOf = (projectId: string) =>
    h.ctx.db.select().from(apiTokens).where(eq(apiTokens.projectId, projectId));
  const projectByKey = async (key: string) => {
    const [row] = await h.ctx.db.select().from(projects).where(eq(projects.key, key));
    return row!;
  };

  beforeAll(async () => {
    const config = { scmInternalHosts: hosts as ReadonlySet<string>, publicUrl: PUBLIC_URL };
    const plugins = rbacPlugins({ now: () => new Date() });
    h = await createIngestHarness({
      config,
      // audit-log on: the events are part of what is checked.
      pluginsFor: async (db, cfg, logger) => {
        const loaded = await plugins(db, cfg, logger);
        recorder = loaded.audit!;
        return loaded;
      },
    });
    const [admin] = await h.ctx.db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.username, 'ingest-admin'));
    adminId = admin!.id;
    const a = await createUser(h.ctx, { username: 'setup-other-admin' });
    await addMember(h.ctx, h.organizationId, a.id, 'admin');
    otherAdmin = await login(h.ctx, a.username, a.password);
    const m = await createUser(h.ctx, { username: 'setup-run-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'setup-run-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
  });
  afterEach(async () => {
    await h.ctx.db.delete(repositorySetupRuns);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, REPOSITORY_SETUP_QUEUE));
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, REVIEW_SNAPSHOT_QUEUE));
    await h.ctx.db.delete(scmConnections);
    await h.ctx.db.delete(projects);
    for (const close of closers.splice(0)) await close();
  });
  afterAll(async () => {
    await h.close();
  });

  describe('GitHub', () => {
    it('creates the project, opens the pull request and keeps the token only in the Actions secret', async () => {
      const fake = await github([
        {
          owner: 'acme',
          name: 'api',
          installationId: 1,
          permissions: ALL,
          defaultBranch: 'trunk',
          languages: { TypeScript: 900, Shell: 10 },
        },
      ]);
      const connectionId = await connectGitHub(fake);

      const runId = await start({ connectionId, repositories: ['acme/api'], ciSetup: true });
      expect((await read(runId)).status).toBe('queued');
      await runSetups();

      const run = await read(runId);
      expect(run).toMatchObject({ id: runId, status: 'done', ciSetup: true });
      const project = await projectByKey('acme/api');
      expect(run.items).toEqual([
        {
          ref: 'acme/api',
          name: 'acme/api',
          project: { id: project.id, key: 'acme/api' },
          projectOutcome: 'created',
          ciOutcome: 'merge_request',
          ciUrl: `${fake.url.slice(0, -'/api/v3'.length)}/acme/api/pull/${fake.openedPulls[0]!.number}`,
          ciReason: null,
          snippet: null,
          token: null,
          error: null,
          azure: null,
        },
      ]);
      expect(project).toMatchObject({
        organizationId: h.organizationId,
        name: 'acme/api',
        mainBranchName: 'trunk',
        scmConnectionId: connectionId,
        scmProjectRef: 'acme/api',
      });
      expect(fake.openedPulls).toEqual([
        expect.objectContaining({
          head: BRANCH,
          base: 'trunk',
          title: 'Add Qualor code analysis',
          state: 'open',
        }),
      ]);
      expect(fake.openedPulls[0]!.body).toContain('QUALOR_TOKEN');
      // GitHub Enterprise Server (the fake's address): the plain job on the scanner image.
      const workflow = fake.fileText(1000, WORKFLOW, BRANCH)!;
      expect(workflow).toContain(`qualor/scanner:${VERSION}`);
      expect(workflow).toContain(PUBLIC_URL);
      expect(fake.fileText(1000, WORKFLOW)).toBeNull();

      // The token is the project's CI setup token, and lives only in the secret.
      const secret = fake.actionsSecrets.get('1000|QUALOR_TOKEN')!;
      expect(secret).toMatch(/^qlr_prj_/);
      const tokens = await tokensOf(project.id);
      expect(tokens).toEqual([
        expect.objectContaining({
          kind: 'project',
          name: 'CI setup',
          scopes: ['analysis:write'],
          expiresAt: null,
          revokedAt: null,
          createdBy: adminId,
          prefix: secret.slice(0, 12),
        }),
      ]);
      expect(tokens[0]!.secretHash.equals(hashToken(secret))).toBe(true);
      const stored = await h.ctx.db
        .select({ tokenEnc: repositorySetupItems.tokenEnc })
        .from(repositorySetupItems)
        .where(eq(repositorySetupItems.runId, runId));
      expect(stored).toEqual([{ tokenEnc: null }]);
      expect(h.ctx.logs.join('\n')).not.toContain(secret);
      const events = await h.ctx.db.select().from(auditEvents).orderBy(asc(auditEvents.seq));
      expect(JSON.stringify(events)).not.toContain(secret);
      expect(
        events
          .filter((e) => e.projectId === project.id)
          .map((e) => [e.action, e.actorUserId, e.details]),
      ).toEqual([
        [
          'project.created',
          adminId,
          { key: 'acme/api', name: 'acme/api', mainBranchName: 'trunk' },
        ],
        [
          'project.updated',
          adminId,
          {
            changes: [
              { field: 'scmConnectionId', from: null, to: connectionId },
              { field: 'scmProjectRef', from: null, to: 'acme/api' },
            ],
          },
        ],
        [
          'project_token.created',
          adminId,
          { name: 'CI setup', prefix: secret.slice(0, 12), expiresAt: null },
        ],
      ]);
    });

    it('adopts an unmapped project with the repository’s name and shows its token once, to the run’s creator only', async () => {
      const fake = await github([
        { owner: 'beta', name: 'web', installationId: 2, languages: { 'C#': 500 } },
      ]);
      const connectionId = await connectGitHub(fake);
      const existing = await h.project('beta/web');
      const before = (await tokensOf(existing.id)).length;

      const runId = await start({ connectionId, repositories: ['beta/web'], ciSetup: false });
      await runSetups();

      // Another admin of the organisation sees the run, never the token.
      const seen = await read(runId, otherAdmin);
      expect(seen.items[0]).toMatchObject({
        name: 'beta/web',
        project: { id: existing.id, key: 'beta/web' },
        projectOutcome: 'adopted',
        ciOutcome: 'skipped',
        ciUrl: null,
        ciReason: null,
        token: null,
        error: null,
      });
      // The snippet a fresh repository would get: C#, so the dotnet layout.
      expect(seen.items[0]!.snippet).toContain('qualor/scanner-dotnet');
      expect(seen.items[0]!.snippet).toContain(PUBLIC_URL);

      const shown = (await read(runId)).items[0]!.token!;
      expect(shown).toMatch(/^qlr_prj_/);
      expect((await read(runId)).items[0]!.token).toBeNull();
      expect((await read(runId, otherAdmin)).items[0]!.token).toBeNull();
      const [item] = await h.ctx.db
        .select({ tokenEnc: repositorySetupItems.tokenEnc })
        .from(repositorySetupItems)
        .where(eq(repositorySetupItems.runId, runId));
      expect(item!.tokenEnc).toBeNull();

      const mapped = await projectByKey('beta/web');
      expect(mapped).toMatchObject({ id: existing.id, scmConnectionId: connectionId });
      expect(mapped.scmProjectRef).toBe('beta/web');
      const tokens = await tokensOf(existing.id);
      expect(tokens).toHaveLength(before + 1);
      const ci = tokens.find((t) => t.name === 'CI setup')!;
      expect(ci.secretHash.equals(hashToken(shown))).toBe(true);
      // Never in a log line or an audit event.
      expect(h.ctx.logs.join('\n')).not.toContain(shown);
      const events = await h.ctx.db.select().from(auditEvents);
      expect(JSON.stringify(events)).not.toContain(shown);
      expect(
        events
          .filter((e) => e.projectId === existing.id && e.actorUserId === adminId)
          .map((e) => e.action),
      ).toEqual(expect.arrayContaining(['project.updated', 'project_token.created']));
      // Nothing was written to the repository.
      expect(githubWrites(fake.requests)).toEqual([]);
    });

    it('gives the project the next free key when the name is taken in another organisation', async () => {
      const fake = await github([{ owner: 'gamma', name: 'lib', installationId: 3 }]);
      const connectionId = await connectGitHub(fake);
      const [org] = await h.ctx.db
        .insert(organizations)
        .values({ key: 'setup-elsewhere', name: 'Elsewhere' })
        .returning();
      await h.ctx.db.insert(projects).values([
        { organizationId: org!.id, key: 'gamma/lib', name: 'theirs' },
        { organizationId: org!.id, key: 'gamma/lib-2', name: 'theirs too' },
      ]);
      try {
        const runId = await start({ connectionId, repositories: ['gamma/lib'], ciSetup: false });
        await runSetups();
        const [item] = (await read(runId)).items;
        expect(item).toMatchObject({
          projectOutcome: 'created',
          project: { key: 'gamma/lib-3' },
          ciOutcome: 'skipped',
        });
        expect(await projectByKey('gamma/lib-3')).toMatchObject({
          organizationId: h.organizationId,
          name: 'gamma/lib',
          scmProjectRef: 'gamma/lib',
        });
        // The snippet uploads to that key, not to the repository's path.
        expect(item!.snippet).toContain('QUALOR_PROJECT_KEY: gamma/lib-3');
      } finally {
        await h.ctx.db.delete(organizations).where(eq(organizations.id, org!.id));
      }
    });

    it('writes the suffixed key into the pull request’s workflow', async () => {
      const fake = await github([
        { owner: 'gamma', name: 'app', installationId: 3, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      const [org] = await h.ctx.db
        .insert(organizations)
        .values({ key: 'setup-elsewhere', name: 'Elsewhere' })
        .returning();
      await h.ctx.db
        .insert(projects)
        .values({ organizationId: org!.id, key: 'gamma/app', name: 'theirs' });
      try {
        const runId = await start({ connectionId, repositories: ['gamma/app'], ciSetup: true });
        await runSetups();
        expect((await read(runId)).items[0]).toMatchObject({
          project: { key: 'gamma/app-2' },
          ciOutcome: 'merge_request',
        });
        const workflow = fake.fileText(1000, WORKFLOW, BRANCH)!;
        expect(workflow).toContain('QUALOR_PROJECT_KEY: gamma/app-2');
        expect(fake.openedPulls[0]!.body).toContain('`gamma/app-2`');
      } finally {
        await h.ctx.db.delete(organizations).where(eq(organizations.id, org!.id));
      }
    });

    it('adds the same repositories twice without a second project, token, branch or pull request', async () => {
      const fake = await github([
        { owner: 'delta', name: 'svc', installationId: 4, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      // Two admins at once: both runs are queued before the worker takes the first.
      const first = await start({ connectionId, repositories: ['delta/svc'], ciSetup: true });
      const second = await start(
        { connectionId, repositories: ['delta/svc'], ciSetup: true },
        otherAdmin,
      );
      await runSetups();

      const a = (await read(first)).items[0]!;
      const b = (await read(second, otherAdmin)).items[0]!;
      expect(a).toMatchObject({ projectOutcome: 'created', ciOutcome: 'merge_request' });
      expect(b).toMatchObject({
        projectOutcome: 'adopted',
        project: a.project,
        ciOutcome: 'merge_request',
        ciUrl: a.ciUrl,
        token: null,
        error: null,
      });
      const keys = await h.ctx.db
        .select({ id: projects.id })
        .from(projects)
        .where(like(projects.key, 'delta/svc%'));
      expect(keys).toHaveLength(1);
      expect(await tokensOf(a.project!.id)).toHaveLength(1);
      expect(fake.openedPulls).toHaveLength(1);
      expect(githubWrites(fake.requests).filter((w) => w.endsWith('/git/refs'))).toHaveLength(1);

      // Without CI setup the mapped project gets the snippet, but no second token.
      const third = await start({ connectionId, repositories: ['delta/svc'], ciSetup: false });
      await runSetups();
      expect((await read(third)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'skipped',
        token: null,
      });
      expect(await tokensOf(a.project!.id)).toHaveLength(1);

      // Merged: the workflow is on the default branch and the pull request is closed.
      fake.addFile(1000, WORKFLOW, fake.fileText(1000, WORKFLOW, BRANCH)!);
      fake.openedPulls[0]!.state = 'closed';
      fake.clearRequests();
      const fourth = await start({ connectionId, repositories: ['delta/svc'], ciSetup: true });
      await runSetups();
      expect((await read(fourth)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'already',
        ciReason: 'already_set_up',
        ciUrl: null,
        token: null,
      });
      expect(githubWrites(fake.requests)).toEqual([]);
      expect(await tokensOf(a.project!.id)).toHaveLength(1);
    });

    it('fails a repository whose commit is refused, goes on with the others, and a later run reuses the branch', async () => {
      const fake = await github([
        { owner: 'eps', name: 'one', installationId: 5, permissions: ALL },
        { owner: 'eps', name: 'two', installationId: 5 },
      ]);
      const connectionId = await connectGitHub(fake);
      fake.inject('PUT', /^\/repos\/eps\/one\/contents\//, {
        status: 409,
        body: { message: 'is at 0000 but expected 1111 ghp_secretlooking' },
      });

      const runId = await start({
        connectionId,
        repositories: ['eps/one', 'eps/two'],
        ciSetup: true,
      });
      await runSetups();

      const [one, two] = (await read(runId)).items;
      expect(one).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        ciUrl: null,
        token: null,
        error: { code: 'refused', message: 'The provider refused the change' },
      });
      expect(JSON.stringify(one)).not.toContain('ghp_');
      // The job logs through the captured logger, with the error's kind and never its words: the
      // step and the request that failed, as fixed texts without the repository's names.
      const lines = h.ctx.logs.filter((l) => l.includes('repository setup could not set up CI'));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('"kind":"refused"');
      expect(lines[0]).toContain('"step":"files"');
      expect(lines[0]).toContain('"request":"PUT /repos/{owner}/{repo}/contents/{path}"');
      expect(lines[0]).not.toContain('ghp_');
      expect(lines[0]).not.toContain('eps/one');
      expect(two).toMatchObject({ projectOutcome: 'created', ciOutcome: 'merge_request' });
      expect(fake.branchSha(1000, BRANCH)).not.toBeNull();
      expect(fake.openedPulls.map((p) => p.repoId)).toEqual([1001]);
      expect(fake.actionsSecrets.has('1000|QUALOR_TOKEN')).toBe(false);
      // The project stays, without a live CI setup token.
      const project = await projectByKey('eps/one');
      expect(project.scmProjectRef).toBe('eps/one');
      expect(
        (await tokensOf(project.id)).filter((t) => t.name === 'CI setup' && t.revokedAt === null),
      ).toEqual([]);

      fake.clearRequests();
      const again = await start({ connectionId, repositories: ['eps/one'], ciSetup: true });
      await runSetups();
      expect((await read(again)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        project: { id: project.id },
        ciOutcome: 'merge_request',
        error: null,
      });
      const writes = githubWrites(fake.requests);
      expect(writes).not.toContain('POST /repos/eps/one/git/refs');
      expect(writes).toContain(`PUT /repos/eps/one/contents/${WORKFLOW}`);
      expect(fake.openedPulls.map((p) => p.repoId).sort()).toEqual([1000, 1001]);
      const secret = fake.actionsSecrets.get('1000|QUALOR_TOKEN')!;
      const live = (await tokensOf(project.id)).filter((t) => t.revokedAt === null);
      expect(live).toHaveLength(1);
      expect(live[0]!.secretHash.equals(hashToken(secret))).toBe(true);
    });

    it('revokes the token when the secret is refused, and names the permissions it needs', async () => {
      const fake = await github([
        { owner: 'eta', name: 'svc', installationId: 6, permissions: ALL },
      ]);
      fake.addFile(1000, 'Eta.sln', 'Microsoft Visual Studio Solution File');
      const connectionId = await connectGitHub(fake);
      fake.inject('PUT', /\/actions\/secrets\/QUALOR_TOKEN$/, {
        status: 403,
        body: { message: 'Resource not accessible by integration' },
      });

      const runId = await start({ connectionId, repositories: ['eta/svc'], ciSetup: true });
      await runSetups();

      expect((await read(runId)).items[0]).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        token: null,
        error: {
          code: 'permission',
          message: 'The GitHub App needs Contents, Workflows and Secrets write',
        },
      });
      // A .sln at the root: the dotnet layout.
      expect(fake.fileText(1000, WORKFLOW, BRANCH)).toContain('qualor/scanner-dotnet');
      const project = await projectByKey('eta/svc');
      const [token] = await tokensOf(project.id);
      expect(token).toMatchObject({ name: 'CI setup' });
      expect(token!.revokedAt).not.toBeNull();
      const revoked = await h.ctx.db
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.projectId, project.id),
            eq(auditEvents.action, 'project_token.revoked'),
          ),
        );
      expect(revoked).toHaveLength(1);
    });

    it('keeps the token stored in the secret when the pull request fails, and opens it on a later run', async () => {
      const fake = await github([
        { owner: 'zeta', name: 'app', installationId: 7, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      fake.inject('POST', /^\/repos\/zeta\/app\/pulls$/, { status: 502 });

      const runId = await start({ connectionId, repositories: ['zeta/app'], ciSetup: true });
      await runSetups();
      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'failed',
        error: {
          code: 'unavailable',
          message: 'The provider could not be reached; try again later',
        },
      });
      const secret = fake.actionsSecrets.get('1000|QUALOR_TOKEN')!;
      const project = await projectByKey('zeta/app');
      expect((await tokensOf(project.id)).map((t) => t.revokedAt)).toEqual([null]);

      const again = await start({ connectionId, repositories: ['zeta/app'], ciSetup: true });
      await runSetups();
      expect((await read(again)).items[0]).toMatchObject({ ciOutcome: 'merge_request' });
      expect(fake.openedPulls).toHaveLength(1);
      expect(fake.actionsSecrets.get('1000|QUALOR_TOKEN')).toBe(secret);
      expect(await tokensOf(project.id)).toHaveLength(1);
    });

    it('gives the snippet and the token when the repository’s installation lacks Workflows and Secrets', async () => {
      const fake = await github([
        { owner: 'theta', name: 'ok', installationId: 8, permissions: ALL },
        { owner: 'iota', name: 'bare', installationId: 9 },
      ]);
      const connectionId = await connectGitHub(fake);
      const runId = await start({ connectionId, repositories: ['iota/bare'], ciSetup: true });
      await runSetups();
      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'snippet',
        ciReason: 'missing_permissions',
        error: null,
      });
      expect(item!.snippet).toContain('QUALOR_TOKEN');
      expect(item!.token).toMatch(/^qlr_prj_/);
      expect(githubWrites(fake.requests)).toEqual([]);
    });

    it('changes nothing where an organisation secret or another workflow already runs Qualor', async () => {
      const fake = await github([
        { owner: 'org', name: 'shared', installationId: 30, permissions: ALL },
        { owner: 'org', name: 'custom', installationId: 30, permissions: ALL },
        { owner: 'org', name: 'fresh', installationId: 30, permissions: ALL },
      ]);
      fake.organizationSecrets.set(1000, ['NPM_TOKEN', 'QUALOR_TOKEN']);
      fake.organizationSecrets.set(1002, ['NPM_TOKEN']);
      fake.addFile(1001, '.github/workflows/build.yml', 'name: build\n');
      fake.addFile(
        1001,
        '.github/workflows/ci.yml',
        'name: ci\non: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: qualor scan\n',
      );
      fake.addFile(1002, '.github/workflows/build.yml', 'name: build\n');
      const connectionId = await connectGitHub(fake);
      const runId = await start({
        connectionId,
        repositories: ['org/shared', 'org/custom', 'org/fresh'],
        ciSetup: true,
      });
      await runSetups();
      const items = (await read(runId)).items;
      for (const item of items.slice(0, 2)) {
        expect(item).toMatchObject({
          projectOutcome: 'created',
          ciOutcome: 'already',
          ciReason: 'already_set_up',
          ciUrl: null,
        });
      }
      expect(items[2]).toMatchObject({ ciOutcome: 'merge_request' });
      expect(fake.openedPulls.map((p) => p.repoId)).toEqual([1002]);
      expect([...fake.actionsSecrets.keys()]).toEqual(['1002|QUALOR_TOKEN']);
    });

    it('opens the pull request in a user’s repository, which has no organisation secrets (issue #34)', async () => {
      const fake = await github([
        { owner: 'jane', ownerType: 'User', name: 'site', installationId: 31, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      const existing = await h.project('jane/site');
      const runId = await start({ connectionId, repositories: ['jane/site'], ciSetup: true });
      await runSetups();
      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        project: { id: existing.id, key: 'jane/site' },
        projectOutcome: 'adopted',
        ciOutcome: 'merge_request',
        error: null,
      });
      expect(fake.openedPulls.map((p) => p.repoId)).toEqual([1000]);
      expect([...fake.actionsSecrets.keys()]).toEqual(['1000|QUALOR_TOKEN']);
    });

    it('says a read was refused when GitHub refuses one before the change, and logs which', async () => {
      const fake = await github([
        { owner: 'zeta', name: 'read', installationId: 32, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      fake.inject('GET', /^\/repos\/zeta\/read\/actions\/secrets\/QUALOR_TOKEN$/, {
        status: 422,
        body: { message: 'Validation Failed' },
      });
      const runId = await start({ connectionId, repositories: ['zeta/read'], ciSetup: true });
      await runSetups();
      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        error: {
          code: 'refused',
          message: 'The provider refused a request to read the repository',
        },
      });
      const lines = h.ctx.logs.filter(
        (l) => l.includes('repository setup could not set up CI') && l.includes('"status":422'),
      );
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('"step":"read"');
      expect(lines[0]).toContain('"request":"GET /repos/{owner}/{repo}/actions/secrets/{name}"');
      expect(lines[0]).not.toContain('Validation Failed');
      expect(githubWrites(fake.requests)).toEqual([]);
    });

    it('fails a repository the App cannot see, and goes on with the others', async () => {
      const fake = await github([{ owner: 'kappa', name: 'here', installationId: 10 }]);
      const connectionId = await connectGitHub(fake);
      const runId = await start({
        connectionId,
        repositories: ['kappa/gone', 'kappa/here'],
        ciSetup: false,
      });
      await runSetups();
      const [gone, here] = (await read(runId)).items;
      expect(gone).toMatchObject({
        ref: 'kappa/gone',
        project: null,
        projectOutcome: 'failed',
        ciOutcome: 'failed',
        token: null,
        error: {
          code: 'not_found',
          message: 'The repository was not found, or the connection cannot reach it',
        },
      });
      expect(here).toMatchObject({ projectOutcome: 'created', ciOutcome: 'skipped' });
      expect(here!.token).toMatch(/^qlr_prj_/);
    });

    it('queues the purge of the review copies an adopted project still holds, and none for a fresh one', async () => {
      const fake = await github([
        { owner: 'nu', name: 'held', installationId: 18 },
        { owner: 'nu', name: 'fresh', installationId: 18 },
      ]);
      const connectionId = await connectGitHub(fake);
      // Copies of an earlier mapping, unmapped since, whose purge has not run.
      const held = await h.project('nu/held');
      const fresh = await h.project('nu/fresh');
      const [analysis] = await h.ctx.db.insert(analyses).values({ projectId: held.id }).returning();
      await h.ctx.db.insert(reviewSnapshots).values({
        analysisId: analysis!.id,
        projectId: held.id,
        compressedBytes: 4,
        body: Buffer.from('gzip'),
      });

      const runId = await start({
        connectionId,
        repositories: ['nu/held', 'nu/fresh'],
        ciSetup: false,
      });
      await runSetups();

      expect((await read(runId)).items.map((i) => [i.project?.id, i.projectOutcome])).toEqual([
        [held.id, 'adopted'],
        [fresh.id, 'adopted'],
      ]);
      const purged = (
        await h.ctx.db
          .select({ payload: jobs.payload })
          .from(jobs)
          .where(eq(jobs.queue, REVIEW_SNAPSHOT_QUEUE))
      ).map((j) => (j.payload as { purgeProjectId?: string }).purgeProjectId);
      expect(purged.filter((id) => id === held.id)).toHaveLength(1);
      expect(purged).not.toContain(fresh.id);
    });

    it('takes C# for the main language only', async () => {
      const hub = await github([
        {
          owner: 'xi',
          name: 'mostly-ts',
          installationId: 20,
          languages: { TypeScript: 900, 'C#': 10 },
        },
        {
          owner: 'xi',
          name: 'mostly-cs',
          installationId: 20,
          languages: { 'C#': 900, TypeScript: 10 },
        },
      ]);
      const lab = await gitlab();
      lab.addProject({ id: 16, path: 'yi/mostly-ts', languages: { TypeScript: 90, 'C#': 10 } });
      lab.addProject({ id: 17, path: 'yi/mostly-cs', languages: { 'C#': 90, TypeScript: 10 } });
      const hubRun = await start({
        connectionId: await connectGitHub(hub),
        repositories: ['xi/mostly-ts', 'xi/mostly-cs'],
        ciSetup: false,
      });
      const labRun = await start({
        connectionId: await connectGitLab(lab),
        repositories: ['16', '17'],
        ciSetup: false,
      });
      await runSetups();
      for (const id of [hubRun, labRun]) {
        const [ts, cs] = (await read(id)).items;
        expect(ts!.snippet).toContain(`qualor/scanner:${VERSION}`);
        expect(ts!.snippet).not.toContain('scanner-dotnet');
        expect(cs!.snippet).toContain(`qualor/scanner-dotnet:${VERSION}`);
      }
    });

    it('pauses a CI-setup run whose status cannot be read, and sets up CI when it reads again', async () => {
      const fake = await github([
        { owner: 'omicron', name: 'svc', installationId: 21, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      const runId = await start({ connectionId, repositories: ['omicron/svc'], ciSetup: true });
      // A blip at the run's start: no answer is not "not available".
      fake.inject('GET', /^\/app\/installations$/, { status: 500 });
      await runSetups();

      const paused = await read(runId);
      expect(paused.status).toBe('running');
      expect(paused.items[0]).toMatchObject({ projectOutcome: 'pending', ciOutcome: 'pending' });
      const [job] = await h.ctx.db
        .select()
        .from(jobs)
        .where(and(eq(jobs.queue, REPOSITORY_SETUP_QUEUE), eq(jobs.status, 'queued')));
      expect(job).toMatchObject({ concurrencyKey: connectionId, payload: { runId, pauses: 1 } });
      expect(githubWrites(fake.requests)).toEqual([]);

      await h.ctx.db
        .update(jobs)
        .set({ runAt: sql`now()` })
        .where(eq(jobs.id, job!.id));
      await runSetups();
      expect((await read(runId)).items[0]).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'merge_request',
        ciReason: null,
        token: null,
      });
      expect(fake.openedPulls).toHaveLength(1);
    });

    it('uses the Action on github.com', async () => {
      const fake = await github([
        { owner: 'lambda', name: 'ui', installationId: 11, permissions: ALL },
      ]);
      const connectionId = await connectGitHub(fake);
      const runId = await start({ connectionId, repositories: ['lambda/ui'], ciSetup: true });
      await runSetups({ host: () => 'cloud' });
      expect((await read(runId)).items[0]).toMatchObject({ ciOutcome: 'merge_request' });
      const workflow = fake.fileText(1000, WORKFLOW, BRANCH)!;
      expect(workflow).toContain(`qualor-dev/scan-action@v${minorOf(VERSION)}`);
      expect(workflow).toContain(PUBLIC_URL);
    });
  });

  describe('GitLab', () => {
    const CI =
      '# Build first.\nstages: [build, test]\n\nbuild:\n  stage: build\n  script: [make] # all of it\n';

    it('commits the job on qualor/setup, sets the variables masked and not protected, and opens the merge request once', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 7, path: 'acme/payments/api', languages: { Go: 100 } });
      fake.addFile(7, 'main', '.gitlab-ci.yml', CI);
      const connectionId = await connectGitLab(fake);

      const runId = await start({ connectionId, repositories: ['7'], ciSetup: true });
      await runSetups();

      const project = await projectByKey('acme/payments/api');
      expect((await read(runId)).items).toEqual([
        {
          ref: '7',
          name: 'acme/payments/api',
          project: { id: project.id, key: 'acme/payments/api' },
          projectOutcome: 'created',
          ciOutcome: 'merge_request',
          ciUrl: `${fake.url}/acme/payments/api/-/merge_requests/1`,
          ciReason: null,
          snippet: null,
          token: null,
          error: null,
          azure: null,
        },
      ]);
      expect(project).toMatchObject({ scmConnectionId: connectionId, scmProjectRef: '7' });
      const variables = fake.variables(7);
      expect(variables['QUALOR_TOKEN']).toEqual({
        value: expect.stringMatching(/^qlr_prj_/),
        masked: true,
        protected: false,
      });
      expect(variables['QUALOR_URL']).toEqual({
        value: PUBLIC_URL,
        masked: false,
        protected: false,
      });
      // Self-managed (the fake's address): the plain job, the file's comments kept.
      const edited = fake.file(7, BRANCH, '.gitlab-ci.yml')!;
      expect(edited.startsWith(CI)).toBe(true);
      expect(edited).toContain(`qualor/scanner:${VERSION}`);
      expect(fake.file(7, 'main', '.gitlab-ci.yml')).toBe(CI);
      const [token] = await tokensOf(project.id);
      expect(token!.secretHash.equals(hashToken(variables['QUALOR_TOKEN']!.value))).toBe(true);
      expect(h.ctx.logs.join('\n')).not.toContain(variables['QUALOR_TOKEN']!.value);

      // A second run links the open merge request and changes nothing.
      const again = await start({ connectionId, repositories: ['7'], ciSetup: true });
      await runSetups();
      expect((await read(again)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        project: { id: project.id },
        ciOutcome: 'merge_request',
        ciUrl: `${fake.url}/acme/payments/api/-/merge_requests/1`,
      });
      expect(fake.variables(7)['QUALOR_TOKEN']!.value).toBe(variables['QUALOR_TOKEN']!.value);
      expect(fake.branches(7).sort()).toEqual(['main', BRANCH]);
      expect(await tokensOf(project.id)).toHaveLength(1);
    });

    it('sets QUALOR_URL on a later run when an earlier one stored the token and stopped there', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 15, path: 'acme/halfway' });
      const connectionId = await connectGitLab(fake);
      // QUALOR_TOKEN is created; the QUALOR_URL write then fails.
      fake.inject(
        'POST',
        /^\/projects\/15\/variables$/,
        { status: 0, passThrough: true },
        { status: 500 },
      );
      const runId = await start({ connectionId, repositories: ['15'], ciSetup: true });
      await runSetups();

      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'failed',
        error: { code: 'unavailable' },
      });
      expect(Object.keys(fake.variables(15))).toEqual(['QUALOR_TOKEN']);
      const stored = fake.variables(15)['QUALOR_TOKEN']!.value;
      const project = await projectByKey('acme/halfway');
      expect((await tokensOf(project.id)).map((t) => t.revokedAt)).toEqual([null]);

      const again = await start({ connectionId, repositories: ['15'], ciSetup: true });
      await runSetups();
      expect((await read(again)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        ciUrl: `${fake.url}/acme/halfway/-/merge_requests/1`,
        error: null,
      });
      expect(fake.variables(15)['QUALOR_URL']).toEqual({
        value: PUBLIC_URL,
        masked: false,
        protected: false,
      });
      expect(fake.variables(15)['QUALOR_TOKEN']!.value).toBe(stored);
      expect(await tokensOf(project.id)).toHaveLength(1);
    });

    it('includes the component on gitlab.com', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 8, path: 'acme/web' });
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['8'], ciSetup: true });
      await runSetups({ host: () => 'cloud' });
      expect((await read(runId)).items[0]).toMatchObject({ ciOutcome: 'merge_request' });
      expect(fake.file(8, BRANCH, '.gitlab-ci.yml')).toContain(
        `component: gitlab.com/qualor/qualor/qualor@${minorOf(VERSION)}`,
      );
    });

    it('passes the suffixed key to the component', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 16, path: 'acme/taken' });
      const connectionId = await connectGitLab(fake);
      // Another project of the instance holds the repository's path as its key.
      const [org] = await h.ctx.db
        .insert(organizations)
        .values({ key: 'setup-elsewhere', name: 'Elsewhere' })
        .returning();
      await h.ctx.db
        .insert(projects)
        .values({ organizationId: org!.id, key: 'acme/taken', name: 'theirs' });
      try {
        const runId = await start({ connectionId, repositories: ['16'], ciSetup: true });
        await runSetups({ host: () => 'cloud' });
        expect((await read(runId)).items[0]).toMatchObject({
          project: { key: 'acme/taken-2' },
          ciOutcome: 'merge_request',
        });
        expect(fake.file(16, BRANCH, '.gitlab-ci.yml')).toContain(
          "args: '--project-key acme/taken-2'",
        );
      } finally {
        await h.ctx.db.delete(organizations).where(eq(organizations.id, org!.id));
      }
    });

    it('changes nothing where .gitlab-ci.yml already runs the scanner under another name', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 17, path: 'acme/scanned' });
      fake.addFile(
        17,
        'main',
        '.gitlab-ci.yml',
        'code-scan:\n  image: qualor/scanner:0.13\n  script: [qualor scan]\n',
      );
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['17'], ciSetup: true });
      await runSetups();
      expect((await read(runId)).items[0]).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'already',
        ciReason: 'already_set_up',
      });
      expect(fake.branches(17)).toEqual(['main']);
      expect(fake.variables(17)).toEqual({});
    });

    it('gives the snippet and the token for a CI configuration at a custom path', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 9, path: 'acme/custom', ciConfigPath: 'ci/pipeline.yml' });
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['9'], ciSetup: true });
      await runSetups();
      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'snippet',
        ciReason: 'custom_ci_path',
      });
      expect(item!.snippet).toContain(`qualor/scanner:${VERSION}`);
      expect(item!.token).toMatch(/^qlr_prj_/);
      expect(fake.branches(9)).toEqual(['main']);
      expect(fake.variables(9)).toEqual({});
    });

    it('gives snippets when the worker has no public URL', async () => {
      const lab = await gitlab();
      lab.addProject({ id: 10, path: 'acme/nourl' });
      const hub = await github([
        { owner: 'mu', name: 'nourl', installationId: 12, permissions: ALL },
      ]);
      const labRun = await start({
        connectionId: await connectGitLab(lab),
        repositories: ['10'],
        ciSetup: true,
      });
      const hubRun = await start({
        connectionId: await connectGitHub(hub),
        repositories: ['mu/nourl'],
        ciSetup: true,
      });
      await runSetups({ publicUrl: null });
      for (const id of [labRun, hubRun]) {
        const [item] = (await read(id)).items;
        expect(item).toMatchObject({
          projectOutcome: 'created',
          ciOutcome: 'snippet',
          ciReason: 'no_public_url',
        });
        expect(item!.snippet).toBeTruthy();
        expect(item!.token).toMatch(/^qlr_prj_/);
      }
      expect(lab.branches(10)).toEqual(['main']);
      expect(githubWrites(hub.requests)).toEqual([]);
    });
  });

  describe('Azure DevOps', () => {
    const FILE = '.azure-pipelines/qualor.yml';
    const STEPS = `# Save this as ${FILE}, then:`;
    const azure = async (deployment: 'services' | 'server' = 'services') => {
      const fake = await createFakeAzureDevOps({ deployment });
      closers.push(() => fake.close());
      hosts.add(new URL(fake.url).host);
      return fake;
    };
    /** A repository with one commit on its default branch, or an empty one. */
    const repository = (
      fake: FakeAzureDevOps,
      input: FakeAzureRepositoryInput,
      files: Record<string, string> = { 'README.md': '# app\n' },
    ): FakeAzureRepository => {
      const repo = fake.addRepository(input);
      if (repo.defaultBranch !== null) {
        fake.setBranch(repo.id, repo.defaultBranch, fake.addCommit(repo.id, { files }));
      }
      return repo;
    };
    /** A Services organisation is stored as `https://dev.azure.com/<org>` (ruling 5). */
    const connectAzure = (fake: FakeAzureDevOps, ciSetupAllowed = true) =>
      connect({
        provider: 'azure',
        baseUrl: fake.deployment === 'services' ? servicesUrlOf(fake) : fake.url,
        azureAuth: 'pat',
        token: fake.pat,
        ciSetupAllowed,
      });
    /** The worker reaches a Services fake through the test origin; a Server fake at its address. */
    const runAzure = (fake: FakeAzureDevOps, overrides: Partial<SetupRunDeps> = {}) =>
      runSetups({
        scm: { ...deps().scm, azureTestOrigin: new URL(fake.url).origin },
        ...overrides,
      });
    const writes = (fake: FakeAzureDevOps) =>
      fake.requests.filter((r) => r.method !== 'GET').map((r) => `${r.method} ${r.path}`);
    const pushes = (fake: FakeAzureDevOps) =>
      fake.requests.filter((r) => r.method === 'POST' && r.path.endsWith('/pushes'));
    const queueOf = (fake: FakeAzureDevOps, repo: FakeAzureRepository, name: string) =>
      fake.queues(repo.projectId).find((q) => q.name === name)!;
    const itemRow = async (runId: string, position = 0) => {
      const [row] = await h.ctx.db
        .select()
        .from(repositorySetupItems)
        .where(
          and(eq(repositorySetupItems.runId, runId), eq(repositorySetupItems.position, position)),
        );
      return row!;
    };

    it('creates the project, pushes the file, creates the pipeline with its secret, authorises it on the pool and opens the pull request', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'api', projectName: 'Payments' });
      const connectionId = await connectAzure(fake);
      const main = fake.branches(repo.id)['main']!;

      const runId = await start({
        connectionId,
        repositories: [repo.id.toUpperCase()],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      const project = await projectByKey('Payments/api');
      expect(fake.definitions).toHaveLength(1);
      const definition = fake.definitions[0]!;
      const pulls = fake.pullRequests(repo.id);
      expect(pulls).toHaveLength(1);
      expect((await read(runId)).items).toEqual([
        {
          ref: repo.id,
          name: 'Payments/api',
          project: { id: project.id, key: 'Payments/api' },
          projectOutcome: 'created',
          ciOutcome: 'merge_request',
          ciUrl: `${fake.url}/Payments/_git/api/pullrequest/${pulls[0]!.id}`,
          ciReason: null,
          snippet: null,
          token: null,
          error: null,
          azure: {
            pipelineUrl: `${servicesUrlOf(fake)}/Payments/_build?definitionId=${definition.id}`,
            queue: 'authorized',
            policy: 'pending',
            policyError: null,
          },
        },
      ]);
      expect(project).toMatchObject({
        name: 'Payments/api',
        mainBranchName: 'main',
        scmConnectionId: connectionId,
        scmProjectRef: repo.id,
      });

      // One push: the branch made from main's head, the file added.
      expect(pushes(fake)).toHaveLength(1);
      const push = JSON.parse(pushes(fake)[0]!.body) as {
        refUpdates: unknown[];
        commits: { parents: string[]; changes: { changeType: string; item: { path: string } }[] }[];
      };
      expect(push.refUpdates).toEqual([
        { name: 'refs/heads/qualor/setup', oldObjectId: '0'.repeat(40) },
      ]);
      expect(push.commits[0]!.parents).toEqual([main]);
      expect(push.commits[0]!.changes.map((c) => [c.changeType, c.item.path])).toEqual([
        ['add', `/${FILE}`],
      ]);
      const file = fake.fileAt(repo.id, BRANCH, FILE)!;
      expect(file).toContain('QUALOR_PROJECT_KEY: Payments/api');
      expect(file).toContain(`qualor/scanner:${VERSION}`);
      expect(file).toContain('pool:\n  name: Default\n');
      expect(fake.fileAt(repo.id, 'main', FILE)).toBeNull();

      // The pipeline: its file on the default branch, the pool's queue, QUALOR_URL and the secret.
      expect(definition.body).toMatchObject({
        name: 'Qualor',
        path: '\\',
        process: { yamlFilename: FILE },
        repository: { id: repo.id, defaultBranch: 'refs/heads/main' },
        queue: { name: 'Default' },
        variables: {
          QUALOR_URL: { value: PUBLIC_URL, allowOverride: false },
          QUALOR_TOKEN: { value: null, isSecret: true },
        },
        // Runs on pushes: a CI trigger whose settings are the YAML's own `trigger:` block.
        triggers: YAML_CI_TRIGGER,
      });
      const secret = definition.secrets['QUALOR_TOKEN']!;
      expect(secret).toMatch(/^qlr_prj_/);
      // `Default` is not open to every pipeline: this one is authorised on it.
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([definition.id]);

      // The pull request comes last: its description names the pipeline and the secret.
      expect(pulls[0]).toMatchObject({
        sourceRefName: 'refs/heads/qualor/setup',
        targetRefName: 'refs/heads/main',
        title: 'Add Qualor code analysis',
        status: 'active',
      });
      expect(pulls[0]!.description).toContain('`Qualor`');
      expect(pulls[0]!.description).toContain('`QUALOR_TOKEN`');
      expect(pulls[0]!.description).toContain('` Default `');
      expect(await itemRow(runId)).toMatchObject({
        azurePipelineId: definition.id,
        azureQueue: 'authorized',
        azurePolicy: 'pending',
        azurePolicyError: null,
        tokenEnc: null,
      });

      // The token is the project's CI setup token, and lives only in the pipeline's secret.
      const tokens = await tokensOf(project.id);
      expect(tokens).toEqual([
        expect.objectContaining({
          name: 'CI setup',
          scopes: ['analysis:write'],
          expiresAt: null,
          revokedAt: null,
          createdBy: adminId,
          prefix: secret.slice(0, 12),
        }),
      ]);
      expect(tokens[0]!.secretHash.equals(hashToken(secret))).toBe(true);
      // Sent once, in the pipeline's create; in no log line, answer or audit event.
      expect(
        fake.requests
          .filter((r) => `${r.path}?${r.query} ${r.body}`.includes(secret))
          .map((r) => `${r.method} ${r.path}`),
      ).toEqual([`POST /${repo.projectId}/_apis/build/definitions`]);
      // The new pipeline is re-saved once at once (the YAML trigger would else idle for minutes):
      // POST, then GET and PUT of that id; the PUT keeps the trigger and the secret.
      const definitionsBase = `/${repo.projectId}/_apis/build/definitions`;
      expect(
        fake.requests
          .filter((r) => r.path.startsWith(definitionsBase) && r.method !== 'DELETE')
          .filter((r) => r.path !== definitionsBase || r.method === 'POST')
          .map((r) => `${r.method} ${r.path}`),
      ).toEqual([
        `POST ${definitionsBase}`,
        `GET ${definitionsBase}/${definition.id}`,
        `PUT ${definitionsBase}/${definition.id}`,
      ]);
      expect(definition.secrets['QUALOR_TOKEN']).toBe(secret);
      expect(definition.body).toMatchObject({
        variables: { QUALOR_TOKEN: { value: null, isSecret: true } },
        triggers: YAML_CI_TRIGGER,
      });
      expect(h.ctx.logs.join('\n')).not.toContain(secret);
      expect(JSON.stringify(await read(runId))).not.toContain(secret);
      const events = await h.ctx.db.select().from(auditEvents);
      expect(JSON.stringify(events)).not.toContain(secret);
      expect(
        events.filter((e) => e.projectId === project.id).map((e) => [e.action, e.actorUserId]),
      ).toEqual([
        ['project.created', adminId],
        ['project.updated', adminId],
        ['project_token.created', adminId],
      ]);
    });

    it('uses the hosted pool on Services and the named pool on Server', async () => {
      const services = await azure();
      const server = await azure('server');
      const hosted = repository(services, { name: 'web', projectName: 'Shop' });
      const named = repository(server, { name: 'web', projectName: 'Shop' });
      server.addQueue(named.projectId, { name: 'Build agents' });
      const cloud = await start({
        connectionId: await connectAzure(services),
        repositories: [hosted.id],
        ciSetup: true,
      });
      const own = await start({
        connectionId: await connectAzure(server),
        repositories: [named.id],
        ciSetup: true,
        azurePool: 'Build agents',
      });
      await runAzure(services);

      expect((await read(cloud)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
        azure: { queue: 'open', policy: 'pending' },
      });
      expect((await read(own)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        ciUrl: `${server.url}/Shop/_git/web/pullrequest/1`,
        error: null,
        azure: {
          pipelineUrl: `${server.url}/Shop/_build?definitionId=${server.definitions[0]!.id}`,
          queue: 'authorized',
          policy: 'pending',
        },
      });
      // Services: Microsoft-hosted agents, the hosted queue, which every pipeline may use.
      expect(services.fileAt(hosted.id, BRANCH, FILE)).toContain(
        'pool:\n  vmImage: ubuntu-latest\n',
      );
      expect(services.definitions[0]!.body).toMatchObject({ queue: { name: 'Azure Pipelines' } });
      expect(writes(services).filter((w) => w.startsWith('PATCH'))).toEqual([]);
      expect(services.pullRequests(hosted.id)[0]!.description).not.toContain('must be authorised');
      // Server: the pool named, its queue, the pipeline authorised on it.
      expect(server.fileAt(named.id, BRANCH, FILE)).toContain("pool:\n  name: 'Build agents'\n");
      expect(server.definitions[0]!.body).toMatchObject({ queue: { name: 'Build agents' } });
      expect(queueOf(server, named, 'Build agents').pipelineIds).toEqual([
        server.definitions[0]!.id,
      ]);
      expect(server.pullRequests(named.id)[0]!.description).toContain('must be authorised');
    });

    it('adds the same repositories twice without a second project, token, definition or pull request', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'svc', projectName: 'Delta' });
      const connectionId = await connectAzure(fake);
      // Two admins at once: both runs are queued before the worker takes the first. `Default` is
      // not open to every pipeline: the first authorises the pipeline on it.
      const pooled = { connectionId, repositories: [repo.id], ciSetup: true, azurePool: 'Default' };
      const first = await start(pooled);
      const second = await start(pooled, otherAdmin);
      await runAzure(fake);

      const a = (await read(first)).items[0]!;
      const b = (await read(second, otherAdmin)).items[0]!;
      expect(a).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'merge_request',
        azure: { queue: 'authorized', policy: 'pending' },
      });
      // The second finds the pull request open: it records the pipeline and the pending policy too,
      // and the pipeline already authorised on the pool (not a pool open to every pipeline).
      expect(b).toMatchObject({
        projectOutcome: 'adopted',
        project: a.project,
        ciOutcome: 'merge_request',
        ciUrl: a.ciUrl,
        token: null,
        error: null,
        azure: { pipelineUrl: a.azure!.pipelineUrl, queue: 'authorized', policy: 'pending' },
      });
      expect(
        await h.ctx.db.select().from(projects).where(like(projects.key, 'Delta/svc%')),
      ).toHaveLength(1);
      expect(await tokensOf(a.project!.id)).toHaveLength(1);
      expect(fake.definitions).toHaveLength(1);
      expect(fake.pullRequests(repo.id)).toHaveLength(1);
      expect(pushes(fake)).toHaveLength(1);

      // Without CI setup the mapped project gets the snippet, but no second token.
      const third = await start({ connectionId, repositories: [repo.id], ciSetup: false });
      await runAzure(fake);
      expect((await read(third)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'skipped',
        token: null,
      });
      expect(await tokensOf(a.project!.id)).toHaveLength(1);

      // Merged: the file is on the default branch and the pull request is completed.
      const merged = fake.addCommit(repo.id, {
        parents: [fake.branches(repo.id)['main']!],
        files: { [FILE]: fake.fileAt(repo.id, BRANCH, FILE)! },
      });
      fake.setBranch(repo.id, 'main', merged);
      fake.completePullRequest(repo.id, fake.pullRequests(repo.id)[0]!.id);
      fake.clearRequests();
      const fourth = await start(pooled);
      await runAzure(fake);
      const done = (await read(fourth)).items[0]!;
      expect(done).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'already',
        ciReason: 'already_set_up',
        ciUrl: null,
        token: null,
        azure: null,
      });
      expect(done.snippet).toContain(STEPS);
      expect(writes(fake)).toEqual([]);
      expect(fake.definitions).toHaveLength(1);
      expect(await tokensOf(a.project!.id)).toHaveLength(1);
    });

    it('resumes a run stopped after the pipeline was created', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'halfway', projectName: 'Eps' });
      const connectionId = await connectAzure(fake);
      // The pipeline is created, then Azure DevOps rate limits the read of the pool's permissions.
      fake.inject('GET', /\/_apis\/pipelines\/pipelinePermissions\/queue\/\d+$/, {
        status: 429,
        headers: { 'retry-after': '30' },
      });
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      const paused = await read(runId);
      expect(paused.status).toBe('running');
      expect(paused.items[0]).toMatchObject({ projectOutcome: 'created', ciOutcome: 'pending' });
      expect(fake.definitions).toHaveLength(1);
      const secret = fake.definitions[0]!.secrets['QUALOR_TOKEN']!;
      const project = await projectByKey('Eps/halfway');
      // Stored in the pipeline: the token stays.
      expect((await tokensOf(project.id)).map((t) => t.revokedAt)).toEqual([null]);
      expect(fake.pullRequests(repo.id)).toEqual([]);

      await h.ctx.db
        .update(jobs)
        .set({ runAt: sql`now()` })
        .where(and(eq(jobs.queue, REPOSITORY_SETUP_QUEUE), eq(jobs.status, 'queued')));
      fake.clearRequests();
      await runAzure(fake);

      const done = await read(runId);
      expect(done.status).toBe('done');
      expect(done.items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
        azure: { queue: 'authorized', policy: 'pending' },
      });
      // The pipeline found by its repository and file: no second pipeline, secret, push or token.
      expect(fake.definitions).toHaveLength(1);
      expect(fake.definitions[0]!.secrets['QUALOR_TOKEN']).toBe(secret);
      expect(fake.definitions[0]!.body).toMatchObject({
        variables: { QUALOR_URL: { value: PUBLIC_URL } },
        // The PUT keeps the CI trigger the create sent.
        triggers: YAML_CI_TRIGGER,
      });
      expect(
        writes(fake).filter((w) => w.startsWith('POST') && w.endsWith('/definitions')),
      ).toEqual([]);
      expect(pushes(fake)).toEqual([]);
      expect(fake.pullRequests(repo.id)).toHaveLength(1);
      expect(await tokensOf(project.id)).toHaveLength(1);
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([fake.definitions[0]!.id]);
      expect(await itemRow(runId)).toMatchObject({
        azurePipelineId: fake.definitions[0]!.id,
        azureQueue: 'authorized',
        azurePolicy: 'pending',
      });
    });

    it('revokes the token when the pipeline write is refused', async () => {
      const fake = await azure();
      const denied = repository(fake, { name: 'denied', projectName: 'Eta' });
      const taken = repository(fake, { name: 'taken', projectName: 'Theta' });
      const connectionId = await connectAzure(fake);
      // As Services refused a Project Contributor without the User role on the queue (2026-11-25).
      fake.inject('POST', new RegExp(`^/${denied.projectId}/_apis/build/definitions$`), {
        status: 403,
        body: {
          message:
            'Access denied. Qualor needs Use permissions for pool Default to perform the action.',
          typeKey: 'AccessDeniedException',
        },
      });
      // Qualor, then `Qualor (taken)`: both names are taken in the project, answered as Services
      // answered a taken name (probe item 29: a 400 with typeKey DefinitionExistsException).
      const exists = recordedAnswer('services', '29-definition-name-taken');
      fake.inject(
        'POST',
        new RegExp(`^/${taken.projectId}/_apis/build/definitions$`),
        exists,
        exists,
      );

      const runId = await start({
        connectionId,
        repositories: [denied.id, taken.id],
        ciSetup: true,
      });
      await runAzure(fake);

      const [one, two] = (await read(runId)).items;
      expect(one).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        token: null,
        error: {
          code: 'permission',
          message:
            "The Azure DevOps identity needs Edit build pipeline in the project and the User role on the agent pool's queue",
          stage: 'change',
        },
        azure: null,
      });
      expect(two).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        token: null,
        error: {
          code: 'pipeline_name_taken',
          message: 'Pipelines named Qualor and Qualor (taken) already exist in this project',
          stage: null,
        },
        azure: null,
      });
      expect(JSON.stringify([one, two])).not.toMatch(
        /Access denied|Use permissions|DefinitionExists/,
      );
      expect(
        fake.requests
          .filter(
            (r) => r.method === 'POST' && r.path === `/${taken.projectId}/_apis/build/definitions`,
          )
          .map((r) => (JSON.parse(r.body) as { name: string }).name),
      ).toEqual(['Qualor', 'Qualor (taken)']);
      expect(fake.definitions).toEqual([]);
      expect(fake.pullRequests(denied.id)).toEqual([]);
      expect(fake.pullRequests(taken.id)).toEqual([]);
      for (const key of ['Eta/denied', 'Theta/taken']) {
        const project = await projectByKey(key);
        const [token, ...more] = await tokensOf(project.id);
        expect(more).toEqual([]);
        expect(token).toMatchObject({ name: 'CI setup' });
        expect(token!.revokedAt).not.toBeNull();
        const revoked = await h.ctx.db
          .select({ action: auditEvents.action })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.projectId, project.id),
              eq(auditEvents.action, 'project_token.revoked'),
            ),
          );
        expect(revoked).toHaveLength(1);
      }
      const lines = h.ctx.logs.filter((l) => l.includes('repository setup could not set up CI'));
      expect(lines.some((l) => l.includes('"step":"secret"') && l.includes('"status":403'))).toBe(
        true,
      );
      expect(lines.join('\n')).not.toMatch(/TF400813|Eta\/denied/);
    });

    it('a 400 that does not name a taken pipeline is a refusal: no second name is tried', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'bad', projectName: 'Zeta' });
      const connectionId = await connectAzure(fake);
      fake.inject('POST', new RegExp(`^/${repo.projectId}/_apis/build/definitions$`), {
        status: 400,
        body: { message: 'The pipeline is not valid.', typeKey: 'ArgumentException' },
      });
      const runId = await start({ connectionId, repositories: [repo.id], ciSetup: true });
      await runAzure(fake);

      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'failed',
        error: { code: 'refused', stage: 'change' },
      });
      expect(
        fake.requests.filter(
          (r) => r.method === 'POST' && r.path === `/${repo.projectId}/_apis/build/definitions`,
        ),
      ).toHaveLength(1);
      const project = await projectByKey('Zeta/bad');
      expect((await tokensOf(project.id))[0]!.revokedAt).not.toBeNull();
    });

    it('keeps the token when the re-save after the create fails: the pipeline holds it', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'resave', projectName: 'Omicron' });
      const connectionId = await connectAzure(fake);
      // The create stored the pipeline and its secret; the re-save's GET is rate limited.
      fake.inject('GET', new RegExp(`^/${repo.projectId}/_apis/build/definitions/\\d+$`), {
        status: 429,
        headers: { 'retry-after': '30' },
      });
      const runId = await start({ connectionId, repositories: [repo.id], ciSetup: true });
      await runAzure(fake);

      const done = await read(runId);
      expect(done.status).toBe('done');
      expect(done.items[0]).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'merge_request',
        token: null,
        error: null,
        azure: { policy: 'pending' },
      });
      expect(fake.definitions).toHaveLength(1);
      const secret = fake.definitions[0]!.secrets['QUALOR_TOKEN']!;
      const project = await projectByKey('Omicron/resave');
      const tokens = await tokensOf(project.id);
      expect(tokens.map((t) => t.revokedAt)).toEqual([null]);
      expect(tokens[0]!.secretHash.equals(hashToken(secret))).toBe(true);
      expect(fake.pullRequests(repo.id)).toHaveLength(1);
      // Noted with its kind, status and route only.
      const warned = h.ctx.logs.filter((l) => l.includes('could not re-save the new Azure DevOps'));
      expect(warned).toHaveLength(1);
      expect(warned[0]).toContain('"kind":"rate_limited"');
      expect(warned[0]).toContain('"status":429');
      expect(warned[0]).toContain(
        `"route":"GET /{id}/_apis/build/definitions/${fake.definitions[0]!.id}"`,
      );
      expect(h.ctx.logs.join('\n')).not.toContain(secret);

      // A rerun adopts the pipeline: still one, with the same live token.
      const again = await start({ connectionId, repositories: [repo.id], ciSetup: true });
      await runAzure(fake);
      expect((await read(again)).items[0]).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'merge_request',
        error: null,
      });
      expect(fake.definitions).toHaveLength(1);
      expect(fake.definitions[0]!.secrets['QUALOR_TOKEN']).toBe(secret);
      expect((await tokensOf(project.id)).map((t) => t.revokedAt)).toEqual([null]);
    });

    it('a queue that is open to all pipelines needs no authorisation; a refused authorisation is the manual step', async () => {
      const fake = await azure('server');
      const open = repository(fake, { name: 'open', projectName: 'Iota' });
      const shut = repository(fake, { name: 'shut', projectName: 'Kappa' });
      fake.queues(open.projectId);
      fake.addQueue(open.projectId, { name: 'Shared', open: true });
      const connectionId = await connectAzure(fake);
      fake.inject('PATCH', /\/_apis\/pipelines\/pipelinePermissions\/queue\/\d+$/, {
        status: 403,
        body: { message: 'TF400813: no Administer permission on the queue' },
      });
      const a = await start({
        connectionId,
        repositories: [open.id],
        ciSetup: true,
        azurePool: 'Shared',
      });
      const b = await start({
        connectionId,
        repositories: [shut.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      expect((await read(a)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
        azure: { queue: 'open', policy: 'pending' },
      });
      expect((await read(b)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
        azure: { queue: 'manual', policy: 'pending' },
      });
      // Only the queue that is not open was asked, and it refused.
      expect(writes(fake).filter((w) => w.startsWith('PATCH'))).toEqual([
        `PATCH /${shut.projectId}/_apis/pipelines/pipelinePermissions/queue/${queueOf(fake, shut, 'Default').id}`,
      ]);
      expect(queueOf(fake, shut, 'Default').pipelineIds).toEqual([]);
      expect(fake.pullRequests(open.id)).toHaveLength(1);
      expect(fake.pullRequests(shut.id)).toHaveLength(1);
      const project = await projectByKey('Kappa/shut');
      expect((await tokensOf(project.id)).map((t) => t.revokedAt)).toEqual([null]);
    });

    it('names Contribute and Create branch, or Edit build pipeline and the queue role, when Azure refuses that step', async () => {
      const fake = await azure();
      const branch = repository(fake, { name: 'branch', projectName: 'Lambda' });
      const pipeline = repository(fake, { name: 'pipeline', projectName: 'Mu' });
      const pull = repository(fake, { name: 'pull', projectName: 'Nu' });
      const read403 = repository(fake, { name: 'read', projectName: 'Xi' });
      const pools = repository(fake, { name: 'pools', projectName: 'Omega' });
      const forbidden = { status: 403, body: { message: 'TF401027: You need the Git permission' } };
      fake.inject(
        'GET',
        new RegExp(`^/${pools.projectId}/_apis/distributedtask/queues$`),
        forbidden,
      );
      fake.inject('POST', new RegExp(`/repositories/${branch.id}/pushes$`), forbidden);
      fake.inject(
        'POST',
        new RegExp(`^/${pipeline.projectId}/_apis/build/definitions$`),
        forbidden,
      );
      fake.inject('POST', new RegExp(`/repositories/${pull.id}/pullrequests$`), forbidden);
      fake.inject('GET', new RegExp(`^/${read403.projectId}/_apis/build/definitions$`), forbidden);
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [branch.id, pipeline.id, pull.id, read403.id, pools.id],
        ciSetup: true,
      });
      await runAzure(fake);

      const items = (await read(runId)).items;
      // The agent pools are read before anything is written: that refusal names its own right.
      expect([items[4]!.ciOutcome, items[4]!.error]).toEqual([
        'failed',
        {
          code: 'permission',
          message: "The Azure DevOps identity needs to read the project's agent pools",
          stage: 'change',
        },
      ]);
      expect(Object.keys(fake.branches(pools.id))).toEqual(['main']);
      items.pop();
      expect(items.map((i) => [i.projectOutcome, i.ciOutcome, i.error])).toEqual([
        [
          'created',
          'failed',
          {
            code: 'permission',
            message:
              'The Azure DevOps identity needs Contribute and Create branch on the repository',
            stage: 'change',
          },
        ],
        [
          'created',
          'failed',
          {
            code: 'permission',
            message:
              "The Azure DevOps identity needs Edit build pipeline in the project and the User role on the agent pool's queue",
            stage: 'change',
          },
        ],
        [
          'created',
          'failed',
          {
            code: 'permission',
            message: 'The Azure DevOps identity needs Contribute to pull requests',
            stage: 'change',
          },
        ],
        [
          'created',
          'failed',
          {
            code: 'permission',
            message: 'The connection was refused access to the repository',
            stage: 'read',
          },
        ],
      ]);
      expect(JSON.stringify(items)).not.toMatch(/GitHub|GitLab|TF401027/);
      // Refused before the token, refused at the secret (revoked), stored before the pull request.
      const live = async (key: string) =>
        (await tokensOf((await projectByKey(key)).id)).filter((t) => t.revokedAt === null);
      expect(await live('Lambda/branch')).toEqual([]);
      expect(await live('Mu/pipeline')).toEqual([]);
      expect(await live('Nu/pull')).toHaveLength(1);
      expect(await live('Xi/read')).toEqual([]);
      expect(await live('Omega/pools')).toEqual([]);
      // The pipeline of the refused pull request is there, open to it on the hosted queue.
      expect(fake.definitions.map((d) => (d.body.repository as { id: string }).id)).toEqual([
        pull.id,
      ]);
      expect(items[2]!.azure).toMatchObject({ queue: 'open', policy: null });
    });

    it('leaves a pipeline Qualor did not create on the file alone: no write, a foreign_pipeline snippet, no token', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'planted', projectName: 'Sigma' });
      // Planted by a contributor, named like Qualor's, on the pool the run names, with a secret.
      const mallory = fake.addUser({ role: 'contributor', displayName: 'Mallory' });
      const planted = fake.addDefinition(repo.id, {
        name: 'Qualor',
        author: mallory,
        secrets: { QUALOR_TOKEN: 'theirs' },
      });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'snippet',
        ciReason: 'foreign_pipeline',
        token: null,
        error: null,
        azure: null,
      });
      expect(item!.snippet).toContain(
        '# A pipeline Qualor did not create already uses .azure-pipelines/qualor.yml.',
      );
      expect(item!.snippet).toContain(STEPS);
      // No PUT of the planted pipeline, no PATCH of the pool, no branch; no token made.
      expect(writes(fake)).toEqual([]);
      expect(planted.secrets).toEqual({ QUALOR_TOKEN: 'theirs' });
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([]);
      expect(await tokensOf((await projectByKey('Sigma/planted')).id)).toEqual([]);
    });

    it('adopts the pipeline an earlier setup of the repository recorded, and writes the token into it', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'kept', projectName: 'Tau' });
      // Qualor's pipeline, renamed by a person since: neither its name nor its author is Qualor's.
      const someone = fake.addUser({ role: 'owner', displayName: 'Someone' });
      const kept = fake.addDefinition(repo.id, { name: 'Code analysis', author: someone });
      const connectionId = await connectAzure(fake);
      const earlier = await start({ connectionId, repositories: [repo.id], ciSetup: false });
      await runAzure(fake);
      await h.ctx.db
        .update(repositorySetupItems)
        .set({ azurePipelineId: kept.id })
        .where(eq(repositorySetupItems.runId, earlier));
      fake.clearRequests();

      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      const [item] = (await read(runId)).items;
      expect(item).toMatchObject({
        projectOutcome: 'adopted',
        ciOutcome: 'merge_request',
        error: null,
        azure: {
          pipelineUrl: `${servicesUrlOf(fake)}/Tau/_build?definitionId=${kept.id}`,
          queue: 'authorized',
          policy: 'pending',
        },
      });
      // GET+PUT of that pipeline with the secret and the address: no second pipeline.
      expect(fake.definitions).toHaveLength(1);
      expect(writes(fake).filter((w) => w.includes('/build/definitions'))).toEqual([
        `PUT /${repo.projectId}/_apis/build/definitions/${kept.id}`,
      ]);
      expect(kept.body).toMatchObject({
        name: 'Code analysis',
        variables: { QUALOR_URL: { value: PUBLIC_URL }, QUALOR_TOKEN: { isSecret: true } },
      });
      const secret = kept.secrets['QUALOR_TOKEN']!;
      const live = (await tokensOf(item!.project!.id)).filter((t) => t.revokedAt === null);
      expect(live.filter((t) => t.secretHash.equals(hashToken(secret)))).toHaveLength(1);
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([kept.id]);
      expect(fake.pullRequests(repo.id)[0]!.description).toContain(
        'the pipeline ` Code analysis `',
      );
    });

    it('adopts the Qualor pipeline its own identity made when the create answer was lost', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'lost', projectName: 'Upsilon' });
      // The first job pushed the branch and created the pipeline with the secret; its answer was
      // lost before the pipeline was recorded.
      const pushed = fake.addCommit(repo.id, {
        parents: [fake.branches(repo.id)['main']!],
        files: { [FILE]: 'steps: []\n' },
      });
      fake.setBranch(repo.id, BRANCH, pushed);
      const lost = fake.addDefinition(repo.id, {
        name: 'Qualor',
        author: fake.patUser,
        secrets: { QUALOR_TOKEN: 'stored-before' },
      });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
        azure: { queue: 'authorized', policy: 'pending' },
      });
      expect(await itemRow(runId)).toMatchObject({ azurePipelineId: lost.id });
      expect(fake.requests.some((r) => r.path === '/_apis/connectionData')).toBe(true);
      expect(fake.definitions).toHaveLength(1);
      expect(writes(fake).filter((w) => w.includes('/build/definitions'))).toEqual([
        `PUT /${repo.projectId}/_apis/build/definitions/${lost.id}`,
      ]);
      expect(lost.secrets).toEqual({ QUALOR_TOKEN: 'stored-before' });
      expect(pushes(fake)).toEqual([]);
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([lost.id]);
    });

    it('never adopts a pipeline its own identity made under another name: it is foreign', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'renamed', projectName: 'Rho' });
      // On the setup's file, written by Qualor's identity, but not named as Qualor names its
      // pipelines and recorded by no setup: someone may use that identity for their own pipeline.
      const other = fake.addDefinition(repo.id, {
        name: 'Code analysis',
        author: fake.patUser,
        secrets: { QUALOR_TOKEN: 'theirs' },
      });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'snippet',
        ciReason: 'foreign_pipeline',
        token: null,
        error: null,
        azure: null,
      });
      expect(writes(fake)).toEqual([]);
      expect(other.secrets).toEqual({ QUALOR_TOKEN: 'theirs' });
      expect(await tokensOf((await projectByKey('Rho/renamed')).id)).toEqual([]);
    });

    it('never adopts a Qualor-named pipeline of its own identity on another file', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'elsewhere', projectName: 'Nu' });
      const other = fake.addDefinition(repo.id, {
        name: 'Qualor',
        yamlPath: 'azure-pipelines.yml',
        author: fake.patUser,
        secrets: { QUALOR_TOKEN: 'theirs' },
      });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);

      // Not on the setup's file: left alone. The setup makes its own pipeline, under the second
      // name, as `Qualor` is taken in the project.
      expect((await read(runId)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        error: null,
      });
      expect(fake.definitions.map((d) => d.body.name)).toEqual(['Qualor', 'Qualor (elsewhere)']);
      const made = fake.definitions[1]!;
      expect(made.body).toMatchObject({ process: { yamlFilename: FILE } });
      expect(await itemRow(runId)).toMatchObject({ azurePipelineId: made.id });
      expect(writes(fake).filter((w) => w.includes(`/build/definitions/${other.id}`))).toEqual([]);
      expect(other.secrets).toEqual({ QUALOR_TOKEN: 'theirs' });
      expect(queueOf(fake, repo, 'Default').pipelineIds).toEqual([made.id]);
    });

    it('authorises only the run’s pool: a pipeline on another queue, or no queue for the pool, is the manual step', async () => {
      const fake = await azure();
      const moved = repository(fake, { name: 'moved', projectName: 'Phi' });
      const gone = repository(fake, { name: 'gone', projectName: 'Psi' });
      fake.addQueue(moved.projectId, { name: 'Protected' });
      // Both resumed: the branch pushed, Qualor's pipeline made with the secret.
      for (const [repo, queueName] of [
        [moved, 'Protected'],
        [gone, 'Default'],
      ] as const) {
        fake.setBranch(
          repo.id,
          BRANCH,
          fake.addCommit(repo.id, {
            parents: [fake.branches(repo.id)['main']!],
            files: { [FILE]: 'steps: []\n' },
          }),
        );
        fake.addDefinition(repo.id, {
          name: 'Qualor',
          author: fake.patUser,
          queueName,
          secrets: { QUALOR_TOKEN: 'stored' },
        });
      }
      const connectionId = await connectAzure(fake);
      const a = await start({
        connectionId,
        repositories: [moved.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      const b = await start({
        connectionId,
        repositories: [gone.id],
        ciSetup: true,
        azurePool: 'Nowhere',
      });
      await runAzure(fake);

      for (const runId of [a, b]) {
        expect((await read(runId)).items[0]).toMatchObject({
          ciOutcome: 'merge_request',
          error: null,
          azure: { queue: 'manual', policy: 'pending' },
        });
      }
      expect(writes(fake).filter((w) => w.startsWith('PATCH'))).toEqual([]);
      expect(queueOf(fake, moved, 'Protected').pipelineIds).toEqual([]);
      expect(queueOf(fake, moved, 'Default').pipelineIds).toEqual([]);
      expect(queueOf(fake, gone, 'Default').pipelineIds).toEqual([]);
    });

    it('records the pipeline and the pending policy when it finds the pull request open, as after a lost answer', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'found', projectName: 'Chi' });
      const connectionId = await connectAzure(fake);
      // Azure DevOps opens the pull request, and its answer is lost.
      fake.inject('POST', new RegExp(`/repositories/${repo.id}/pullrequests$`), {
        status: 503,
        before: async () => {
          fake.addPullRequest(repo.id, {
            sourceRefName: 'refs/heads/qualor/setup',
            targetRefName: 'refs/heads/main',
            title: 'Add Qualor code analysis',
          });
        },
      });
      const first = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);
      expect((await read(first)).items[0]).toMatchObject({
        ciOutcome: 'failed',
        error: { code: 'unavailable' },
        azure: { queue: 'authorized', policy: null },
      });

      const again = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Default',
      });
      await runAzure(fake);
      const definition = fake.definitions[0]!;
      expect((await read(again)).items[0]).toMatchObject({
        ciOutcome: 'merge_request',
        ciUrl: `${fake.url}/Chi/_git/found/pullrequest/1`,
        error: null,
        azure: {
          pipelineUrl: `${servicesUrlOf(fake)}/Chi/_build?definitionId=${definition.id}`,
          // Authorised by the first run; `Default` is still not open to every pipeline.
          queue: 'authorized',
          policy: 'pending',
        },
      });
      expect(await itemRow(again)).toMatchObject({
        azurePipelineId: definition.id,
        azurePolicy: 'pending',
      });
      expect(fake.pullRequests(repo.id)).toHaveLength(1);
      expect(fake.definitions).toHaveLength(1);
    });

    it('no pool of that name: fails before writing', async () => {
      const fake = await azure();
      const repo = repository(fake, { name: 'api', projectName: 'Omicron' });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Linux pool',
      });
      await runAzure(fake);

      expect((await read(runId)).items[0]).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'failed',
        token: null,
        error: {
          code: 'no_agent_pool',
          message: 'No agent pool named "Linux pool" in this project',
          stage: null,
        },
        azure: null,
      });
      expect(writes(fake)).toEqual([]);
      expect(Object.keys(fake.branches(repo.id))).toEqual(['main']);
      expect(await tokensOf((await projectByKey('Omicron/api')).id)).toEqual([]);
    });

    it('keys `My Project/Repo é` as `My-Project/Repo` and suffixes a taken key', async () => {
      const fake = await azure();
      const first = repository(fake, { name: 'Repo é', projectName: 'My Project' });
      const second = repository(fake, { name: 'Repo è', projectName: 'My Project' });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [first.id, second.id],
        ciSetup: true,
      });
      await runAzure(fake);

      const [a, b] = (await read(runId)).items;
      expect(a).toMatchObject({
        name: 'My Project/Repo é',
        project: { key: 'My-Project/Repo' },
        projectOutcome: 'created',
        ciOutcome: 'merge_request',
      });
      expect(b).toMatchObject({
        name: 'My Project/Repo è',
        project: { key: 'My-Project/Repo-2' },
        projectOutcome: 'created',
        ciOutcome: 'merge_request',
      });
      // The name keeps the original; the mapping is the repository's id.
      expect(await projectByKey('My-Project/Repo')).toMatchObject({
        name: 'My Project/Repo é',
        scmProjectRef: first.id,
      });
      expect(await projectByKey('My-Project/Repo-2')).toMatchObject({
        name: 'My Project/Repo è',
        scmProjectRef: second.id,
      });
      expect(fake.fileAt(first.id, BRANCH, FILE)).toContain(
        'QUALOR_PROJECT_KEY: My-Project/Repo\n',
      );
      expect(fake.fileAt(second.id, BRANCH, FILE)).toContain(
        'QUALOR_PROJECT_KEY: My-Project/Repo-2\n',
      );
      // One Azure project, two pipelines: the second takes a name of its own, which its pull
      // request names.
      expect(fake.definitions.map((d) => d.body.name)).toEqual(['Qualor', 'Qualor (Repo è)']);
      const description = fake.pullRequests(second.id)[0]!.description;
      expect(description).toContain('` Qualor (Repo è) `');
      expect(description).not.toContain('`Qualor`');
      expect(a!.azure!.pipelineUrl).toBe(
        `${servicesUrlOf(fake)}/My%20Project/_build?definitionId=${fake.definitions[0]!.id}`,
      );
    });

    it('an empty repository and an existing `.azure-pipelines/qualor.yml` give their snippets', async () => {
      const fake = await azure();
      const empty = repository(fake, { name: 'empty', projectName: 'Pi', defaultBranch: null });
      const done = repository(fake, { name: 'done', projectName: 'Pi' }, { [FILE]: 'steps: []\n' });
      const connectionId = await connectAzure(fake);
      const runId = await start({
        connectionId,
        repositories: [empty.id, done.id],
        ciSetup: true,
      });
      await runAzure(fake);

      const [a, b] = (await read(runId)).items;
      expect(a).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'snippet',
        ciReason: 'empty_repository',
        error: null,
        azure: null,
      });
      expect(a!.token).toMatch(/^qlr_prj_/);
      expect(b).toMatchObject({
        projectOutcome: 'created',
        ciOutcome: 'already',
        ciReason: 'already_set_up',
        token: null,
        azure: null,
      });
      for (const item of [a!, b!]) {
        expect(item.snippet).toContain(`QUALOR_PROJECT_KEY: ${item.project!.key}`);
        expect(item.snippet).toContain('vmImage: ubuntu-latest');
        expect(item.snippet).toContain(STEPS);
        expect(item.snippet).toContain(`QUALOR_URL = ${PUBLIC_URL}`);
        // The person creates the pipeline, the variable and the secret: the header says so.
        expect(item.snippet).toContain(
          '# Qualor in Azure Pipelines. Create a pipeline from this file',
        );
        expect(item.snippet).not.toContain('created by Qualor');
      }
      expect(writes(fake)).toEqual([]);
    });

    it('gives the file with the pipeline and secret steps without a public URL, and without CI setup', async () => {
      const fake = await azure('server');
      const repo = repository(fake, { name: 'manual', projectName: 'Rho' });
      const connectionId = await connectAzure(fake);
      const nourl = await start({
        connectionId,
        repositories: [repo.id],
        ciSetup: true,
        azurePool: 'Linux',
      });
      await runAzure(fake, { publicUrl: null });
      const skipped = await start({ connectionId, repositories: [repo.id], ciSetup: false });
      await runAzure(fake);

      const first = (await read(nourl)).items[0]!;
      expect(first).toMatchObject({ ciOutcome: 'snippet', ciReason: 'no_public_url' });
      expect(first.snippet).toContain('pool:\n  name: Linux\n');
      expect(first.snippet).toContain(STEPS);
      expect(first.snippet).toContain('QUALOR_URL = https://qualor.example.com');
      expect(first.snippet).toContain('QUALOR_TOKEN');
      const second = (await read(skipped)).items[0]!;
      expect(second).toMatchObject({ ciOutcome: 'skipped', ciReason: null });
      // A Server without a pool named: the pool most Servers have.
      expect(second.snippet).toContain('pool:\n  name: Default\n');
      expect(second.snippet).toContain(STEPS);
      expect(second.snippet).toContain(`QUALOR_URL = ${PUBLIC_URL}`);
      expect(writes(fake)).toEqual([]);
    });
  });

  describe('a job that stopped half way', () => {
    it('pauses the run while the provider rate limits, and goes on when it is due', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 13, path: 'acme/busy' });
      fake.addProject({ id: 14, path: 'acme/calm' });
      const connectionId = await connectGitLab(fake);
      fake.inject('GET', /^\/projects\/14$/, { status: 429, headers: { 'retry-after': '30' } });
      const runId = await start({ connectionId, repositories: ['13', '14'], ciSetup: false });
      await runSetups();

      const paused = await read(runId);
      expect(paused.status).toBe('running');
      expect(paused.items.map((i) => [i.projectOutcome, i.ciOutcome])).toEqual([
        ['created', 'skipped'],
        ['pending', 'pending'],
      ]);
      const [job] = await h.ctx.db
        .select()
        .from(jobs)
        .where(and(eq(jobs.queue, REPOSITORY_SETUP_QUEUE), eq(jobs.status, 'queued')));
      expect(job).toMatchObject({ concurrencyKey: connectionId, payload: { runId, pauses: 1 } });
      expect(job!.runAt.getTime()).toBeGreaterThan(Date.now() + 20_000);

      await h.ctx.db
        .update(jobs)
        .set({ runAt: sql`now()` })
        .where(eq(jobs.id, job!.id));
      await runSetups();
      const done = await read(runId);
      expect(done.status).toBe('done');
      expect(done.items[1]).toMatchObject({
        project: { key: 'acme/calm' },
        projectOutcome: 'created',
        ciOutcome: 'skipped',
        error: null,
      });
    });

    it('goes on with the CI of an item whose project was saved, without a second project', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 12, path: 'acme/resume' });
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['12'], ciSetup: true });
      // The first attempt saved the project (created and mapped) and stopped before its CI.
      const project = await h.project('acme/resume');
      const mapped = await h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/projects/${project.id}`,
        headers: h.orgAdmin.headers,
        payload: { scmConnectionId: connectionId, scmProjectRef: '12' },
      });
      expect(mapped.statusCode, mapped.body).toBe(200);
      await h.ctx.db
        .update(repositorySetupItems)
        .set({ projectOutcome: 'created', projectId: project.id, repositoryName: 'acme/resume' })
        .where(eq(repositorySetupItems.runId, runId));
      await h.ctx.db
        .update(repositorySetupRuns)
        .set({ status: 'running' })
        .where(eq(repositorySetupRuns.id, runId));

      await runSetups();
      expect((await read(runId)).items[0]).toMatchObject({
        projectOutcome: 'created',
        project: { id: project.id, key: 'acme/resume' },
        ciOutcome: 'merge_request',
      });
      expect(
        await h.ctx.db.select().from(projects).where(like(projects.key, 'acme/resume%')),
      ).toHaveLength(1);
      expect(fake.variables(12)['QUALOR_TOKEN']).toMatchObject({ masked: true, protected: false });
    });
  });

  describe('starting and reading a run', () => {
    it('checks the body, the connection and the CI-setup option', async () => {
      const fake = await gitlab();
      const connectionId = await connectGitLab(fake, false);
      const problem = async (body: Record<string, unknown>) => {
        const res = await post({ connectionId, repositories: ['1'], ciSetup: false, ...body });
        expect(res.statusCode, res.body).toBe(422);
        return (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path);
      };
      expect(await problem({ repositories: [] })).toContain('body.repositories');
      const many = Array.from({ length: 51 }, (_, i) => String(i + 1));
      expect(await problem({ repositories: many })).toContain('body.repositories');
      expect(await problem({ repositories: ['5', '5'] })).toContain('body.repositories');
      expect(await problem({ repositories: ['not a ref'] })).toEqual(['body.repositories.0']);
      expect(await problem({ connectionId: '00000000-0000-4000-8000-000000000000' })).toEqual([
        'body.connectionId',
      ]);
      // The connection does not allow CI setup: the option is refused, as the page hides it.
      expect(await problem({ ciSetup: true })).toEqual(['body.ciSetup']);

      const ok = await post({ connectionId, repositories: ['1', '2'], ciSetup: false });
      expect(ok.statusCode, ok.body).toBe(202);
      const id = (ok.json() as { id: string }).id;
      const [job] = await h.ctx.db
        .select()
        .from(jobs)
        .where(eq(jobs.queue, REPOSITORY_SETUP_QUEUE));
      expect(job).toMatchObject({ concurrencyKey: connectionId, payload: { runId: id } });
      expect((await read(id)).items.map((i) => [i.ref, i.projectOutcome, i.ciOutcome])).toEqual([
        ['1', 'pending', 'pending'],
        ['2', 'pending', 'pending'],
      ]);
    });

    it('is never stored by a cache, while running or with a token to show', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 18, path: 'acme/cached' });
      const connectionId = await connectGitLab(fake, false);
      const id = await start({ connectionId, repositories: ['18'], ciSetup: false });
      const queued = await get(id);
      expect(queued.headers['cache-control']).toBe('no-store');
      await runSetups();
      const done = await get(id);
      expect(done.statusCode, done.body).toBe(200);
      expect((done.json() as Run).items[0]!.token).toMatch(/^qlr_prj_/);
      expect(done.headers['cache-control']).toBe('no-store');
    });

    it('is for the organisation’s admins only', async () => {
      const fake = await gitlab();
      const connectionId = await connectGitLab(fake, false);
      const body = { connectionId, repositories: ['1'], ciSetup: false };
      expect((await post(body, member)).statusCode).toBe(403);
      expect((await post(body, outsider)).statusCode).toBe(404);
      const id = await start(body);
      expect((await get(id, member)).statusCode).toBe(403);
      expect((await get(id, outsider)).statusCode).toBe(404);
      expect((await get('00000000-0000-4000-8000-000000000000')).statusCode).toBe(404);
    });

    it('fails the repositories of a run whose connection was deleted', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 11, path: 'acme/orphan' });
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['11'], ciSetup: true });
      await h.ctx.db.delete(scmConnections).where(eq(scmConnections.id, connectionId));
      await runSetups();
      const run = await read(runId);
      expect(run.status).toBe('done');
      expect(run.items[0]).toMatchObject({
        projectOutcome: 'failed',
        ciOutcome: 'failed',
        error: { code: 'connection_gone' },
      });
    });

    it('finishes a run whose job died', async () => {
      const fake = await gitlab();
      const connectionId = await connectGitLab(fake);
      const runId = await start({ connectionId, repositories: ['1', '2'], ciSetup: false });
      await h.ctx.db
        .update(repositorySetupItems)
        .set({ projectOutcome: 'created', ciOutcome: 'skipped' })
        .where(and(eq(repositorySetupItems.runId, runId), eq(repositorySetupItems.position, 0)));
      await h.ctx.db
        .update(jobs)
        .set({ status: 'dead' })
        .where(eq(jobs.queue, REPOSITORY_SETUP_QUEUE));
      expect(await reconcileStuckSetupRuns(h.ctx.db)).toBe(1);
      const run = await read(runId);
      expect(run.status).toBe('done');
      expect(run.items.map((i) => [i.projectOutcome, i.ciOutcome, i.error?.code ?? null])).toEqual([
        ['created', 'skipped', null],
        ['failed', 'failed', 'abandoned'],
      ]);
      const [row] = await h.ctx.db
        .select({ finishedAt: repositorySetupRuns.finishedAt })
        .from(repositorySetupRuns)
        .where(eq(repositorySetupRuns.id, runId));
      expect(row!.finishedAt).not.toBeNull();
      expect(await reconcileStuckSetupRuns(h.ctx.db)).toBe(0);
    });
  });

  it('names the CI host: github.com, GHE.com and gitlab.com are cloud', () => {
    expect(ciHostOf({ provider: 'github', baseUrl: 'https://api.github.com' })).toBe('cloud');
    expect(ciHostOf({ provider: 'github', baseUrl: 'https://api.acme.ghe.com' })).toBe('cloud');
    expect(ciHostOf({ provider: 'github', baseUrl: 'https://git.acme.test/api/v3' })).toBe(
      'self-hosted',
    );
    expect(ciHostOf({ provider: 'gitlab', baseUrl: 'https://gitlab.com' })).toBe('cloud');
    expect(ciHostOf({ provider: 'gitlab', baseUrl: 'https://gitlab.acme.test' })).toBe(
      'self-hosted',
    );
    expect(ciHostOf({ provider: 'azure', baseUrl: 'https://dev.azure.com/acme' })).toBe('cloud');
    expect(ciHostOf({ provider: 'azure', baseUrl: 'https://acme.visualstudio.com' })).toBe('cloud');
    expect(
      ciHostOf({ provider: 'azure', baseUrl: 'https://tfs.acme.test/DefaultCollection' }),
    ).toBe('self-hosted');
  });

  it('tells where a refusal happened from its fixed text, so the page never reads it', () => {
    const stage = setupErrorStage;
    expect(stage('permission', 'The connection was refused access to the repository')).toBe('read');
    expect(stage('permission', 'The GitHub App needs Contents, Workflows and Secrets write')).toBe(
      'change',
    );
    expect(
      stage('permission', 'The GitLab token needs the api scope and the Maintainer role'),
    ).toBe('change');
    expect(stage('permission', 'The Azure DevOps identity needs Contribute to pull requests')).toBe(
      'change',
    );
    expect(stage('refused', 'The provider refused a request to read the repository')).toBe('read');
    expect(stage('refused', 'The provider refused the change')).toBe('change');
    expect(
      stage('not_found', 'The repository was not found, or the connection cannot reach it'),
    ).toBe(null);
    expect(stage('no_agent_pool', 'No agent pool named "x" in this project')).toBeNull();
  });

  it('makes an Azure DevOps <project>/<repository> a project key', () => {
    const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
    expect(azureProjectKey('My Project/Repo é', id)).toBe('My-Project/Repo');
    expect(azureProjectKey('a  -- b/c', id)).toBe('a-b/c');
    expect(azureProjectKey('Web.App/api_v2:x', id)).toBe('Web.App/api_v2:x');
    expect(azureProjectKey(' Team 🚀/app ', id)).toBe('Team-/app');
    // Nothing of the name is left: the repository's id.
    expect(azureProjectKey('Проект/Репо', id.toUpperCase())).toBe(id);
    expect(setupKeyOf('azure', 'My Project/Repo é', id)).toBe('My-Project/Repo');
    expect(setupKeyOf('github', 'acme/My Repo', 'acme/My Repo')).toBe('acme/My Repo');
    expect(setupKeyOf('gitlab', 'g/sub/p', '7')).toBe('g/sub/p');
  });
});
