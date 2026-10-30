import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  analyses,
  branches,
  memberships,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  setupChecklistClosures,
  users,
} from '../db/schema';
import {
  DEFAULT_AUTO_FIX,
  DEFAULT_LLM_SETTINGS,
  writeLlmSettings,
  type OrgLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import { DEFAULT_REVIEW } from '../review/settings';
import { SCM_TOKEN_AAD } from '../scm/connections';

type StepId = 'connect' | 'repositories' | 'analysis' | 'ai_review' | 'team';
interface Checklist {
  steps: {
    id: StepId;
    done: boolean;
    hint: 'merge_request' | 'ask_server_admin' | null;
    blocking: boolean;
  }[];
  closed: boolean;
  allDone: boolean;
}

const PROVIDER: StoredProvider = {
  kind: 'openai',
  baseUrl: 'https://llm.example/v1',
  model: 'fake-model',
  strongModel: null,
  fastModel: null,
  auth: 'bearer',
  jsonMode: 'json_object',
  maxTokensField: 'max_tokens',
  temperature: null,
  api: 'chat_completions',
  workspaceId: null,
  timeoutSeconds: 5,
  contextWindowTokens: null,
  apiKeyEnc: null,
};

describe('The setup checklist', () => {
  let ctx: TestContext;
  let org: string;
  let other: string;
  let admin: Session;
  let adminId: string;
  let instanceAdmin: Session;
  let member: Session;
  let memberId: string;
  let otherAdmin: Session;
  let seq = 0;

  const url = (id = org) => `/api/v0/organizations/${id}/setup-checklist`;
  const get = (session = admin, id = org) =>
    ctx.app.inject({ method: 'GET', url: url(id), headers: session.headers });
  const put = (closed: boolean, session = admin, id = org) =>
    ctx.app.inject({ method: 'PUT', url: url(id), headers: session.headers, payload: { closed } });
  const checklist = async (session = admin): Promise<Checklist> => {
    const res = await get(session);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as Checklist;
  };
  const step = (c: Checklist, id: StepId) => c.steps.find((s) => s.id === id)!;

  const connection = async (organization = org) => {
    const [row] = await ctx.db
      .insert(scmConnections)
      .values({
        organizationId: organization,
        provider: 'gitlab',
        baseUrl: 'https://gitlab.example.com',
        tokenEnc: encryptSecret(encryptionKey(ctx.config.secretKey), 'x', SCM_TOKEN_AAD),
      })
      .returning();
    return row!.id;
  };
  const newProject = (organization = org) =>
    createProject(ctx, instanceAdmin, { organizationId: organization, key: `sc/p${++seq}` });
  const analysis = async (projectId: string, status: 'succeeded' | 'queued' = 'succeeded') => {
    const [branch] = await ctx.db.select().from(branches).where(eq(branches.projectId, projectId));
    await ctx.db.insert(analyses).values(
      status === 'queued'
        ? { projectId, status }
        : {
            projectId,
            status,
            branchId: branch!.id,
            revision: 'a'.repeat(40),
            analysisDate: new Date(),
            baselineStatus: 'first_analysis',
            scannerVersion: '0.0.0',
          },
    );
  };
  const mergeRequestItem = async (projectId: string, organization = org) => {
    const [run] = await ctx.db
      .insert(repositorySetupRuns)
      .values({ organizationId: organization })
      .returning();
    await ctx.db.insert(repositorySetupItems).values({
      runId: run!.id,
      position: 0,
      repositoryRef: 'r',
      repositoryName: 'o/r',
      projectId,
      ciOutcome: 'merge_request',
    });
  };
  const aiOn = (provider: boolean, enabled: boolean) =>
    writeLlmSettings(ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      provider: provider ? PROVIDER : null,
      organizations: {
        [org]: {
          enabled: true,
          features: { explain: true, triage: false, fix: false },
          excludedProjectIds: [],
          autoFix: { ...DEFAULT_AUTO_FIX },
          autoFixDisabledProjectIds: [],
          review: { ...DEFAULT_REVIEW, projectIds: [], enabled },
        } satisfies OrgLlmSettings,
      },
    });
  const mapped = async (projectId: string, connectionId: string) => {
    await ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: '7' })
      .where(eq(projects.id, projectId));
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    org = await organizationId(ctx, 'default');
    const root = await createUser(ctx, { username: 'sc-root', isInstanceAdmin: true });
    instanceAdmin = await login(ctx, root.username, root.password);
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: instanceAdmin.headers,
      payload: { key: 'sc-other', name: 'Other' },
    });
    expect(created.statusCode, created.body).toBe(201);
    other = (created.json() as { id: string }).id;
    const make = async (name: string, organization: string, role: 'admin' | 'member') => {
      const user = await createUser(ctx, { username: name });
      await addMember(ctx, organization, user.id, role);
      return { user, session: await login(ctx, name, user.password) };
    };
    const a = await make('sc-admin', org, 'admin');
    admin = a.session;
    adminId = a.user.id;
    const m = await createUser(ctx, { username: 'sc-member' });
    memberId = m.id;
    member = await login(ctx, m.username, m.password);
    otherAdmin = (await make('sc-other-admin', other, 'admin')).session;
  });

  beforeEach(async () => {
    await ctx.db.delete(repositorySetupRuns);
    await ctx.db.delete(analyses);
    await ctx.db.delete(projects);
    await ctx.db.delete(scmConnections);
    await ctx.db.delete(setupChecklistClosures);
    await writeLlmSettings(ctx.db, DEFAULT_LLM_SETTINGS);
    // The organization starts with the one admin as its only member .
    await ctx.db.delete(memberships).where(eq(memberships.organizationId, org));
    await addMember(ctx, org, adminId, 'admin');
  });

  afterAll(async () => {
    await ctx.close();
  });

  it('lists the five steps, none done, in a fresh organization', async () => {
    const c = await checklist();
    expect(c.steps.map((s) => s.id)).toEqual([
      'connect',
      'repositories',
      'analysis',
      'ai_review',
      'team',
    ]);
    expect(c.steps.every((s) => !s.done)).toBe(true);
    expect(c).toMatchObject({ closed: false, allDone: false });
  });

  it('ticks connect with a connection of the organization only', async () => {
    await connection(other);
    expect(step(await checklist(), 'connect').done).toBe(false);
    await connection();
    expect(step(await checklist(), 'connect').done).toBe(true);
  });

  it('ticks repositories with a project mapped to a connection', async () => {
    const id = await connection();
    const p = await newProject();
    expect(step(await checklist(), 'repositories').done).toBe(false);
    await mapped(p.id, id);
    expect(step(await checklist(), 'repositories').done).toBe(true);
  });

  it('ticks analysis with a succeeded analysis of a project of the organization', async () => {
    const p = await newProject();
    const o = await newProject(other);
    await analysis(o.id);
    await analysis(p.id, 'queued');
    expect(step(await checklist(), 'analysis').done).toBe(false);
    await analysis(p.id);
    expect(step(await checklist(), 'analysis')).toMatchObject({ done: true, hint: null });
  });

  it('hints at the merge request while one is open and the project has no analysis', async () => {
    const p = await newProject();
    expect(step(await checklist(), 'analysis').hint).toBeNull();
    await mergeRequestItem(p.id);
    expect(step(await checklist(), 'analysis')).toMatchObject({
      done: false,
      hint: 'merge_request',
      blocking: true,
    });
    await analysis(p.id);
    expect(step(await checklist(), 'analysis')).toMatchObject({ done: true, hint: null });
  });

  it('ignores a merge request of another organization', async () => {
    const o = await newProject(other);
    await mergeRequestItem(o.id, other);
    expect(step(await checklist(), 'analysis').hint).toBeNull();
  });

  it('ticks ai_review with the organization switch on', async () => {
    await aiOn(true, false);
    expect(step(await checklist(), 'ai_review')).toMatchObject({ done: false, blocking: true });
    await aiOn(true, true);
    expect(step(await checklist(), 'ai_review')).toMatchObject({ done: true, hint: null });
  });

  it('makes ai_review non-blocking for an admin who cannot set the provider', async () => {
    expect(step(await checklist(), 'ai_review')).toMatchObject({
      done: false,
      hint: 'ask_server_admin',
      blocking: false,
    });
  });

  it('keeps ai_review blocking for an instance admin without a provider', async () => {
    expect(step(await checklist(instanceAdmin), 'ai_review')).toMatchObject({
      done: false,
      hint: null,
      blocking: true,
    });
  });

  it('ticks team with more than one active member', async () => {
    expect(step(await checklist(), 'team').done).toBe(false);
    const u = await createUser(ctx, { username: `sc-inactive-${++seq}`, active: false });
    await addMember(ctx, org, u.id, 'member');
    expect(step(await checklist(), 'team').done).toBe(false);
    const v = await createUser(ctx, { username: `sc-active-${++seq}` });
    await addMember(ctx, org, v.id, 'viewer');
    expect(step(await checklist(), 'team').done).toBe(true);
    await ctx.db.update(users).set({ active: true }).where(eq(users.id, u.id));
  });

  it('is all done when every blocking step is, ignoring the non-blocking one', async () => {
    const id = await connection();
    const p = await newProject();
    await mapped(p.id, id);
    await analysis(p.id);
    const v = await createUser(ctx, { username: `sc-mate-${++seq}` });
    await addMember(ctx, org, v.id, 'viewer');
    const c = await checklist();
    expect(step(c, 'ai_review').done).toBe(false);
    expect(c.allDone).toBe(true);
    // An instance admin still has to turn AI review on.
    expect((await checklist(instanceAdmin)).allDone).toBe(false);
  });

  it('closes and reopens per user and organization', async () => {
    const closed = await put(true);
    expect(closed.statusCode, closed.body).toBe(200);
    expect((closed.json() as Checklist).closed).toBe(true);
    expect((await put(true)).statusCode).toBe(200);
    expect((await checklist()).closed).toBe(true);
    expect((await checklist(instanceAdmin)).closed).toBe(false);
    const reopened = await put(false);
    expect((reopened.json() as Checklist).closed).toBe(false);
    expect((await checklist()).closed).toBe(false);
  });

  it('answers 422 to a body with an unknown field', async () => {
    const res = await ctx.app.inject({
      method: 'PUT',
      url: url(),
      headers: admin.headers,
      payload: { closed: true, extra: 1 },
    });
    expect(res.statusCode, res.body).toBe(422);
    expect(res.json()).toMatchObject({ code: 'VALIDATION_FAILED' });
    expect((await checklist()).closed).toBe(false);
  });

  it('refuses a member who is not an admin, and an unknown or foreign organization', async () => {
    await addMember(ctx, org, memberId, 'member');
    expect((await get(member)).statusCode).toBe(403);
    expect((await put(true, member)).statusCode).toBe(403);
    expect((await get(otherAdmin)).statusCode).toBe(404);
    expect((await put(true, otherAdmin)).statusCode).toBe(404);
    expect((await get(admin, '00000000-0000-4000-8000-000000000000')).statusCode).toBe(404);
  });
});
