import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { gzipJson, sampleReport, uploadReport } from '../../test/reports';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  analyses,
  analysisReports,
  apiTokens,
  branches,
  projects,
  scmConnections,
} from '../db/schema';
import { SCM_TOKEN_AAD } from '../scm/connections';

describe('projects', () => {
  let ctx: TestContext;
  let admin: Session;
  let orgAdmin: Session;
  let member: Session;
  let outsider: Session;
  let defaultOrg: string;
  let otherOrg: string;

  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    headers: Record<string, string>,
    payload?: object,
  ) => ctx.app.inject({ method, url: `/api/v0${url}`, headers, ...(payload ? { payload } : {}) });
  const paths = (res: { json(): { errors?: { path: string }[] } }) =>
    (res.json().errors ?? []).map((e) => e.path);

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    defaultOrg = await organizationId(ctx, 'default');
    otherOrg = (
      await call('POST', '/organizations', admin.headers, { key: 'other', name: 'Other' })
    ).json().id;
    const a = await createUser(ctx, { username: 'p-admin' });
    const m = await createUser(ctx, { username: 'p-member' });
    const o = await createUser(ctx, { username: 'p-outsider' });
    await addMember(ctx, defaultOrg, a.id, 'admin');
    await addMember(ctx, defaultOrg, m.id, 'member');
    await addMember(ctx, otherOrg, o.id, 'member');
    orgAdmin = await login(ctx, a.username, a.password);
    member = await login(ctx, m.username, m.password);
    outsider = await login(ctx, o.username, o.password);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('creates a project with its main branch', async () => {
    const res = await call('POST', '/projects', orgAdmin.headers, {
      organizationId: defaultOrg,
      key: 'acme/api',
      name: 'API',
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({
      key: 'acme/api',
      name: 'API',
      mainBranchName: 'main',
      qualityGateId: null,
      newCodeDefinition: null,
      mainBranch: {
        name: 'main',
        gateStatus: null,
        lastAnalysisId: null,
        lastAnalyzedAt: null,
        measures: {},
      },
    });
    const trunk = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'acme/trunk',
      mainBranchName: 'trunk',
    });
    const got = await call('GET', `/projects/${trunk.id}`, member.headers);
    expect(got.json().mainBranch.name).toBe('trunk');
  });

  it('validates POST (422), rejects duplicate keys (409) and enforces roles (401/403/404)', async () => {
    expect(
      paths(
        await call('POST', '/projects', orgAdmin.headers, {
          organizationId: defaultOrg,
          key: 'has space',
          name: 'x',
        }),
      ),
    ).toEqual(['body.key']);
    expect(
      paths(
        await call('POST', '/projects', orgAdmin.headers, {
          organizationId: defaultOrg,
          key: 'k1',
          name: 'x',
          extra: 1,
        }),
      ),
    ).toEqual(['body']);
    await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'dup/key' });
    const dup = await call('POST', '/projects', admin.headers, {
      organizationId: otherOrg,
      key: 'dup/key',
      name: 'x',
    });
    expect([dup.statusCode, dup.json().code]).toEqual([409, 'PROJECT_KEY_TAKEN']);
    const body = { organizationId: defaultOrg, key: 'nope/nope', name: 'x' };
    expect((await call('POST', '/projects', {}, body)).statusCode).toBe(401);
    expect((await call('POST', '/projects', member.headers, body)).statusCode).toBe(403);
    expect((await call('POST', '/projects', outsider.headers, body)).statusCode).toBe(404);
  });

  it('lists visible projects with search (LIKE wildcards are literal) and pagination', async () => {
    await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'search/pct',
      name: '100% coverage',
    });
    await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'search/plain',
      name: '1000 coverage',
    });
    await createProject(ctx, admin, { organizationId: otherOrg, key: 'other/one' });
    const keys = async (s: Session, query = '') =>
      (await call('GET', `/projects?limit=500${query}`, s.headers))
        .json()
        .items.map((p: { key: string }) => p.key);
    expect(await keys(member)).not.toContain('other/one');
    expect(await keys(outsider)).toEqual(['other/one']);
    expect(await keys(member, `&q=${encodeURIComponent('%')}`)).toEqual(['search/pct']);
    expect(await keys(admin, `&organizationId=${otherOrg}`)).toEqual(['other/one']);
    const page1 = await call('GET', '/projects?limit=1', member.headers);
    const page2 = await call(
      'GET',
      `/projects?limit=1&cursor=${page1.json().nextCursor}`,
      member.headers,
    );
    expect(page2.json().items[0].id > page1.json().items[0].id).toBe(true);
    expect((await call('GET', '/projects', {})).statusCode).toBe(401);
    expect(paths(await call('GET', '/projects?organizationId=nope', member.headers))).toEqual([
      'query.organizationId',
    ]);
  });

  it('reads a project by id and by key; 404 when not visible', async () => {
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'read/me' });
    expect((await call('GET', `/projects/${p.id}`, member.headers)).statusCode).toBe(200);
    expect((await call('GET', `/projects/${p.id}`, outsider.headers)).statusCode).toBe(404);
    expect((await call('GET', `/projects/${p.id}`, {})).statusCode).toBe(401);
    expect(paths(await call('GET', '/projects/nope', member.headers))).toEqual(['params.id']);
    const byKey = await call(
      'GET',
      `/projects/by-key?key=${encodeURIComponent('read/me')}`,
      member.headers,
    );
    expect([byKey.statusCode, byKey.json().id]).toEqual([200, p.id]);
    expect((await call('GET', '/projects/by-key?key=absent', member.headers)).statusCode).toBe(404);
    expect(
      (await call('GET', `/projects/by-key?key=${encodeURIComponent('read/me')}`, outsider.headers))
        .statusCode,
    ).toBe(404);
    expect(paths(await call('GET', '/projects/by-key?key=bad%20key', member.headers))).toEqual([
      'query.key',
    ]);
  });

  it('PATCH renames, switches the main branch and sets the new-code definition', async () => {
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'patch/me' });
    const res = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      name: 'Renamed',
      mainBranchName: 'develop',
      newCodeDefinition: { type: 'days', value: 30 },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      name: 'Renamed',
      mainBranchName: 'develop',
      newCodeDefinition: { type: 'days', value: 30 },
      mainBranch: { name: 'develop' },
    });
    const mains = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    expect(mains.map((b) => b.name)).toEqual(['develop']);
    const all = await ctx.db.select().from(branches).where(eq(branches.projectId, p.id));
    expect(all.map((b) => b.name).sort()).toEqual(['develop', 'main']);
    const back = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      mainBranchName: 'main',
      newCodeDefinition: null,
    });
    expect(back.json()).toMatchObject({ mainBranch: { name: 'main' }, newCodeDefinition: null });
  });

  it('PATCH validates input and enforces roles', async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'patch/validate',
    });
    const url = `/projects/${p.id}`;
    expect(paths(await call('PATCH', url, orgAdmin.headers, {}))).toEqual(['body']);
    expect(
      paths(
        await call('PATCH', url, orgAdmin.headers, {
          newCodeDefinition: { type: 'days', value: 0 },
        }),
      ),
    ).toEqual(['body.newCodeDefinition.value']);
    expect(
      paths(
        await call('PATCH', url, orgAdmin.headers, {
          qualityGateId: '0190a0b0-0000-7000-8000-000000000000',
        }),
      ),
    ).toEqual(['body.qualityGateId']);
    expect(
      paths(
        await call('PATCH', url, orgAdmin.headers, {
          newCodeDefinition: {
            type: 'analysis',
            analysisId: '0190a0b0-0000-7000-8000-000000000000',
          },
        }),
      ),
    ).toEqual(['body.newCodeDefinition.analysisId']);
    expect((await call('PATCH', url, member.headers, { name: 'x' })).statusCode).toBe(403);
    expect((await call('PATCH', url, outsider.headers, { name: 'x' })).statusCode).toBe(404);
    expect((await call('PATCH', url, {}, { name: 'x' })).statusCode).toBe(401);
  });

  it("an org admin's token without the admin scope gets 403 INSUFFICIENT_SCOPE on admin routes", async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'patch/scope',
    });
    const pat = (
      await call('POST', '/tokens', orgAdmin.headers, { name: 'write-only', scopes: ['write'] })
    ).json().token as string;
    const patch = await call('PATCH', `/projects/${p.id}`, bearer(pat), { name: 'x' });
    expect([patch.statusCode, patch.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const create = await call('POST', '/projects', bearer(pat), {
      organizationId: defaultOrg,
      key: 'scope/denied',
      name: 'x',
    });
    expect([create.statusCode, create.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const member403 = await call('PATCH', `/projects/${p.id}`, member.headers, { name: 'x' });
    expect(member403.json().code).toBe('FORBIDDEN');
  });

  it('newCodeDefinition of type analysis must reference a succeeded analysis on the main branch (ruling S10)', async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'patch/analysis-main',
    });
    const mainBranchId = (await call('GET', `/projects/${p.id}`, orgAdmin.headers)).json()
      .mainBranch.id;
    const [feature] = await ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'feature' })
      .returning();
    const complete = {
      projectId: p.id,
      revision: 'a'.repeat(40),
      analysisDate: new Date(),
      baselineStatus: 'first_analysis' as const,
      scannerVersion: '1.0.0',
      status: 'succeeded' as const,
    };
    const [onFeature] = await ctx.db
      .insert(analyses)
      .values({ ...complete, branchId: feature!.id })
      .returning();
    const [onMain] = await ctx.db
      .insert(analyses)
      .values({ ...complete, branchId: mainBranchId })
      .returning();
    const rejected = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      newCodeDefinition: { type: 'analysis', analysisId: onFeature!.id },
    });
    expect(paths(rejected)).toEqual(['body.newCodeDefinition.analysisId']);
    const accepted = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      newCodeDefinition: { type: 'analysis', analysisId: onMain!.id },
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json().newCodeDefinition).toEqual({
      type: 'analysis',
      analysisId: onMain!.id,
    });
  });

  it('a combined mainBranchName switch + newCodeDefinition analysis is checked against the post-switch main (fix round 1, finding 1)', async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'patch/analysis-switch',
    });
    const oldMainId = (await call('GET', `/projects/${p.id}`, orgAdmin.headers)).json().mainBranch
      .id;
    const [release] = await ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'release' })
      .returning();
    const complete = {
      projectId: p.id,
      revision: 'b'.repeat(40),
      analysisDate: new Date(),
      baselineStatus: 'first_analysis' as const,
      scannerVersion: '1.0.0',
      status: 'succeeded' as const,
    };
    const [onOldMain] = await ctx.db
      .insert(analyses)
      .values({ ...complete, branchId: oldMainId })
      .returning();
    // The analysis is on the pre-switch main; once this PATCH also promotes 'release' to main,
    // it must be rejected, and the whole request (including the switch) must roll back.
    const rejected = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      mainBranchName: 'release',
      newCodeDefinition: { type: 'analysis', analysisId: onOldMain!.id },
    });
    expect(paths(rejected)).toEqual(['body.newCodeDefinition.analysisId']);
    const afterReject = await call('GET', `/projects/${p.id}`, orgAdmin.headers);
    expect(afterReject.json().mainBranchName).toBe('main');
    const mainsAfterReject = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    expect(mainsAfterReject.map((b) => b.name)).toEqual(['main']);
    // The same switch, but pointed at a succeeded analysis on the branch being promoted, must
    // succeed and leave newCodeDefinition referencing it.
    const [onRelease] = await ctx.db
      .insert(analyses)
      .values({ ...complete, branchId: release!.id })
      .returning();
    const accepted = await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, {
      mainBranchName: 'release',
      newCodeDefinition: { type: 'analysis', analysisId: onRelease!.id },
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toMatchObject({
      mainBranchName: 'release',
      newCodeDefinition: { type: 'analysis', analysisId: onRelease!.id },
    });
  });

  it('concurrent main-branch switches to different branches never 500 (controller ruling S10)', async () => {
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'patch/race' });
    // A single pair of requests rarely overlaps at the row-lock level (each does two selects
    // before its transaction even starts); 8 distinct targets make the race land reliably.
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        call('PATCH', `/projects/${p.id}`, orgAdmin.headers, { mainBranchName: `race-${i}` }),
      ),
    );
    for (const res of results) expect([200, 409]).toContain(res.statusCode);
    const mains = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    expect(mains).toHaveLength(1);
    const [row] = await ctx.db.select().from(projects).where(eq(projects.id, p.id));
    expect(mains[0]!.name).toBe(row!.mainBranchName);
  });

  it('DELETE needs ?confirm=<key>', async () => {
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'delete/me' });
    expect(paths(await call('DELETE', `/projects/${p.id}`, orgAdmin.headers))).toEqual([
      'query.confirm',
    ]);
    expect(
      paths(await call('DELETE', `/projects/${p.id}?confirm=wrong`, orgAdmin.headers)),
    ).toEqual(['query.confirm']);
    const confirm = `?confirm=${encodeURIComponent('delete/me')}`;
    expect((await call('DELETE', `/projects/${p.id}${confirm}`, member.headers)).statusCode).toBe(
      403,
    );
    expect((await call('DELETE', `/projects/${p.id}${confirm}`, outsider.headers)).statusCode).toBe(
      404,
    );
    expect((await call('DELETE', `/projects/${p.id}${confirm}`, orgAdmin.headers)).statusCode).toBe(
      204,
    );
    expect((await call('GET', `/projects/${p.id}`, orgAdmin.headers)).statusCode).toBe(404);
  });

  it('DELETE cascades to tokens, branches, analyses and stored reports; the token then gets 401', async () => {
    const key = 'delete/cascade';
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key });
    const token = await createProjectToken(ctx, orgAdmin, p.id);
    const analysisId = await uploadReport(
      ctx,
      bearer(token),
      key,
      gzipJson(sampleReport({ projectKey: key })),
    );
    const count = async () => ({
      tokens: (await ctx.db.select().from(apiTokens).where(eq(apiTokens.projectId, p.id))).length,
      branches: (await ctx.db.select().from(branches).where(eq(branches.projectId, p.id))).length,
      analyses: (await ctx.db.select().from(analyses).where(eq(analyses.projectId, p.id))).length,
      reports: (
        await ctx.db
          .select()
          .from(analysisReports)
          .where(eq(analysisReports.analysisId, analysisId))
      ).length,
    });
    expect(await count()).toEqual({ tokens: 1, branches: 1, analyses: 1, reports: 1 });
    const confirm = `?confirm=${encodeURIComponent(key)}`;
    expect((await call('DELETE', `/projects/${p.id}${confirm}`, orgAdmin.headers)).statusCode).toBe(
      204,
    );
    expect(await count()).toEqual({ tokens: 0, branches: 0, analyses: 0, reports: 0 });
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/analyses/${analysisId}`,
      headers: bearer(token),
    });
    expect([res.statusCode, res.json().code]).toEqual([401, 'UNAUTHENTICATED']);
  });

  it('issues project tokens that can do nothing but analyses (api.md §6.3), and revokes them', async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'tokens/proj',
    });
    const created = await call('POST', `/projects/${p.id}/tokens`, orgAdmin.headers, {
      name: 'ci',
      expiresInDays: 90,
    });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({ name: 'ci', scopes: ['analysis:write'] });
    const token: string = created.json().token;
    expect(token).toMatch(/^qlr_prj_[0-9A-Za-z]{32}$/);
    for (const url of [
      '/auth/me',
      '/projects',
      `/projects/${p.id}`,
      '/system/info',
      '/organizations',
      '/tokens',
    ]) {
      const res = await call('GET', url, bearer(token));
      expect([res.statusCode, res.json().code], url).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    }
    const listed = await call('GET', `/projects/${p.id}/tokens`, orgAdmin.headers);
    expect(listed.json().items.map((t: { id: string }) => t.id)).toContain(created.json().id);
    expect(listed.json().items[0]).not.toHaveProperty('token');
    expect(
      (await call('DELETE', `/projects/${p.id}/tokens/${created.json().id}`, orgAdmin.headers))
        .statusCode,
    ).toBe(204);
    expect((await call('GET', '/auth/me', bearer(token))).statusCode).toBe(401);
    expect(
      (await call('DELETE', `/projects/${p.id}/tokens/${created.json().id}`, orgAdmin.headers))
        .statusCode,
    ).toBe(404);
  });

  it('rejects U+0000 in free text with 422 on the field, never a 500', async () => {
    const nul = 'a\u0000b';
    expect(
      paths(
        await call('POST', '/projects', orgAdmin.headers, {
          organizationId: defaultOrg,
          key: 'nul/create',
          name: nul,
        }),
      ),
    ).toEqual(['body.name']);
    expect(
      paths(
        await call('POST', '/projects', orgAdmin.headers, {
          organizationId: defaultOrg,
          key: 'nul/create',
          name: 'ok',
          mainBranchName: nul,
        }),
      ),
    ).toEqual(['body.mainBranchName']);
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'nul/patch' });
    expect(
      paths(await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, { name: nul })),
    ).toEqual(['body.name']);
    expect(
      paths(await call('PATCH', `/projects/${p.id}`, orgAdmin.headers, { mainBranchName: nul })),
    ).toEqual(['body.mainBranchName']);
    expect(paths(await call('GET', '/projects?q=a%00b', orgAdmin.headers))).toEqual(['query.q']);
    expect(
      paths(await call('POST', `/projects/${p.id}/tokens`, orgAdmin.headers, { name: nul })),
    ).toEqual(['body.name']);
  });

  it('project token endpoints validate input and enforce roles', async () => {
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'tokens/roles',
    });
    await createProjectToken(ctx, orgAdmin, p.id);
    expect(
      paths(await call('POST', `/projects/${p.id}/tokens`, orgAdmin.headers, { name: '' })),
    ).toEqual(['body.name']);
    expect(paths(await call('DELETE', `/projects/${p.id}/tokens/nope`, orgAdmin.headers))).toEqual([
      'params.tokenId',
    ]);
    for (const [method, url] of [
      ['GET', `/projects/${p.id}/tokens`],
      ['POST', `/projects/${p.id}/tokens`],
    ] as const) {
      const payload = method === 'POST' ? { name: 'x' } : undefined;
      expect((await call(method, url, {}, payload)).statusCode).toBe(401);
      expect((await call(method, url, member.headers, payload)).statusCode).toBe(403);
      expect((await call(method, url, outsider.headers, payload)).statusCode).toBe(404);
    }
  });

  it("checks the SCM reference against the mapped connection's provider (github.md §2.3)", async () => {
    const tokenEnc = encryptSecret(encryptionKey(ctx.config.secretKey), 'x', SCM_TOKEN_AAD);
    const [gitlab, github] = await ctx.db
      .insert(scmConnections)
      .values([
        {
          organizationId: defaultOrg,
          provider: 'gitlab',
          baseUrl: 'https://gitlab.example.com',
          tokenEnc,
        },
        {
          organizationId: defaultOrg,
          provider: 'github',
          baseUrl: 'https://api.github.com',
          appId: '1',
          tokenEnc,
        },
      ])
      .returning();
    const p = await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'scm/kinds' });
    const map = (payload: object) => call('PATCH', `/projects/${p.id}`, orgAdmin.headers, payload);
    expect((await map({ scmConnectionId: gitlab!.id, scmProjectRef: '7' })).statusCode).toBe(200);
    // A new GitHub connection with the GitLab project id kept: not an owner/repo.
    const kept = await map({ scmConnectionId: github!.id });
    expect([kept.statusCode, paths(kept)]).toEqual([422, ['body.scmProjectRef']]);
    expect(
      (await map({ scmConnectionId: github!.id, scmProjectRef: 'acme/api' })).json(),
    ).toMatchObject({ scmConnectionId: github!.id, scmProjectRef: 'acme/api' });
    // Only the reference changes: checked against the connection already mapped.
    for (const bad of ['42', 'acme/api/x', 'acme/..']) {
      const res = await map({ scmProjectRef: bad });
      expect([res.statusCode, paths(res)], bad).toEqual([422, ['body.scmProjectRef']]);
    }
    expect((await map({ scmProjectRef: 'acme/web' })).statusCode).toBe(200);
    expect((await map({ scmProjectRef: null })).statusCode).toBe(200);
    // Back on GitLab, a GitLab path or id again.
    expect(
      (await map({ scmConnectionId: gitlab!.id, scmProjectRef: 'group/sub/project' })).statusCode,
    ).toBe(200);
    await ctx.db.delete(scmConnections).where(eq(scmConnections.organizationId, defaultOrg));
  });
});
