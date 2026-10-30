import { and, asc, eq, like, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
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
  apiTokens,
  auditEvents,
  jobs,
  organizations,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  users,
} from '../db/schema';
import { VERSION } from '../index';
import { runUntilIdle } from '../queue/worker';
import { InstallationTokenCache, MutationPacer } from '../scm/github/app-auth';
import { minorOf } from './ci-setup';
import {
  ciHostOf,
  reconcileStuckSetupRuns,
  REPOSITORY_SETUP_QUEUE,
  repositorySetupHandlers,
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
  error: { code: string; message: string } | null;
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
    body: { connectionId: string; repositories: string[]; ciSetup: boolean },
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
      // The job logs through the captured logger, with the error's kind and never its words.
      const lines = h.ctx.logs.filter((l) => l.includes('repository setup could not set up CI'));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('"kind":"refused"');
      expect(lines[0]).not.toContain('ghp_');
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
        error: { code: 'permission', message: 'The GitHub App needs Workflows and Secrets write' },
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
  });
});
