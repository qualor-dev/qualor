import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { CliError, EXIT } from '../errors';
import { httpQualorApi, QualorApiError } from './qualor-api';

const serve = useTestServers();
const TOKEN = 'qlr_usr_supersecret_token_value';
const ORG = '00000000-0000-7000-8000-000000000001';
const PROFILE = '00000000-0000-7000-8000-000000000002';
const PROJECT = '00000000-0000-7000-8000-000000000003';
const ep = (url: string) => ({ url, token: TOKEN, timeoutMs: 5_000 });
const profile = (id: string, name: string) => ({
  id,
  organizationId: ORG,
  name,
  language: 'java',
  parentId: null,
  isDefault: false,
  isBuiltin: false,
  unknownRules: 'activate',
});
const noSleep = () => Promise.resolve();

describe('httpQualorApi (import-sonarqube.md §11.1)', () => {
  it('reads every page of a list with the bearer token, and validates each item', async () => {
    const s = await serve((req, res) => {
      const url = new URL(req.url ?? '', 'http://x');
      if (url.searchParams.get('cursor') === null) {
        json(res, 200, { items: [profile(PROFILE, 'A')], nextCursor: 'next' });
      } else {
        json(res, 200, { items: [profile(PROJECT, 'B')], nextCursor: null });
      }
    });
    const list = await httpQualorApi(ep(s.url)).profiles(ORG);
    expect(list.map((p) => [p.name, p.unknownRules])).toEqual([
      ['A', 'activate'],
      ['B', 'activate'],
    ]);
    expect(s.requests.map((r) => r.url)).toEqual([
      `/api/v0/quality-profiles?organizationId=${ORG}&limit=500`,
      `/api/v0/quality-profiles?organizationId=${ORG}&limit=500&cursor=next`,
    ]);
    expect(s.requests[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('reads the enterprise roles of /auth/me, and a grant-only organisation (rbac-audit.md §16)', async () => {
    const s = await serve((_req, res) =>
      json(res, 200, {
        user: { isInstanceAdmin: false },
        memberships: [
          { organizationId: ORG, organizationKey: 'a', role: 'viewer', permissions: ['org.read'] },
          { organizationId: PROFILE, organizationKey: 'b', role: null, permissions: ['org.read'] },
          { organizationId: PROJECT, organizationKey: 'c', role: 'project_admin', permissions: [] },
        ],
        projectGrants: [],
        csrfToken: null,
      }),
    );
    const me = await httpQualorApi(ep(s.url)).me();
    expect(me.memberships.map((m) => m.role)).toEqual(['viewer', null, 'project_admin']);
  });

  it('refuses an answer that does not match the schema', async () => {
    const s = await serve((_req, res) =>
      json(res, 200, { items: [{ id: 'nope' }], nextCursor: null }),
    );
    await expect(httpQualorApi(ep(s.url)).gates(ORG)).rejects.toMatchObject({
      exitCode: EXIT.SERVER,
      message: 'the server sent an invalid gate list',
    });
  });

  it('percent-encodes rule keys and languages as one path segment each', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    const api = httpQualorApi(ep(s.url));
    await api.setProfileRule(PROFILE, {
      ruleKey: 'typescript:@typescript-eslint/no-empty-function',
      active: true,
      severityOverride: 'high',
    });
    await api.deleteProfileRule(PROFILE, "java:it's(x)*");
    await api.setProjectProfile(PROJECT, 'java', PROFILE);
    await api.setProfileUnknownRules(PROFILE, 'activate');
    expect(s.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      `PUT /api/v0/quality-profiles/${PROFILE}/rules/typescript%3A%40typescript-eslint%2Fno-empty-function`,
      `DELETE /api/v0/quality-profiles/${PROFILE}/rules/java%3Ait%27s%28x%29%2A`,
      `PUT /api/v0/projects/${PROJECT}/quality-profiles/java`,
      `PATCH /api/v0/quality-profiles/${PROFILE}`,
    ]);
    expect(JSON.parse(s.requests[0]!.body.toString('utf8'))).toEqual({
      active: true,
      severityOverride: 'high',
    });
    expect(JSON.parse(s.requests[3]!.body.toString('utf8'))).toEqual({ unknownRules: 'activate' });
  });

  it('refuses a rule key with a dot segment before any request', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    const api = httpQualorApi(ep(s.url));
    for (const ruleKey of ['..', 'a/../b', 'a\\..\\b']) {
      await expect(
        api.setProfileRule(PROFILE, { ruleKey, active: true, severityOverride: null }),
      ).rejects.toBeInstanceOf(CliError);
    }
    await expect(api.setProjectGate('../x', PROFILE)).rejects.toBeInstanceOf(CliError);
    expect(s.requests).toEqual([]);
  });

  it('retries a busy lock (503 CONCURRENCY_CONFLICT), then succeeds', async () => {
    let n = 0;
    const s = await serve((_req, res) => {
      n += 1;
      if (n < 3) problem(res, 503, 'CONCURRENCY_CONFLICT');
      else json(res, 200, {});
    });
    const waits: number[] = [];
    await httpQualorApi(ep(s.url), (ms) => {
      waits.push(ms);
      return Promise.resolve();
    }).setDefaultGate(PROFILE);
    expect(s.requests).toHaveLength(3);
    expect(waits).toEqual([2000, 2000]);
  });

  it('fails with exit 5 on 401 and 403, never showing the token the server echoed', async () => {
    const s = await serve((req, res) =>
      problem(res, req.method === 'GET' ? 401 : 403, 'FORBIDDEN', `bad token ${TOKEN}`),
    );
    const api = httpQualorApi(ep(s.url), noSleep);
    for (const p of [api.me(), api.createGate(ORG, 'G')]) {
      const err = await p.catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode).toBe(EXIT.AUTH);
      expect((err as Error).message).not.toContain(TOKEN);
      expect((err as Error).message).not.toContain('supersecret');
    }
  });

  it('fails with exit 5 on 403 PASSWORD_CHANGE_REQUIRED too: no later request can succeed', async () => {
    const s = await serve((_req, res) => problem(res, 403, 'PASSWORD_CHANGE_REQUIRED'));
    const err = await httpQualorApi(ep(s.url), noSleep)
      .createGate(ORG, 'G')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err).not.toBeInstanceOf(QualorApiError);
    expect((err as CliError).exitCode).toBe(EXIT.AUTH);
    expect((err as Error).message).toContain('PASSWORD_CHANGE_REQUIRED');
  });

  it('reads whether a profile inherits', async () => {
    const s = await serve((_req, res) =>
      json(res, 200, {
        items: [profile(PROFILE, 'A'), { ...profile(PROJECT, 'B'), parentId: PROFILE }],
        nextCursor: null,
      }),
    );
    expect((await httpQualorApi(ep(s.url)).profiles(ORG)).map((p) => p.parentId)).toEqual([
      null,
      PROFILE,
    ]);
  });

  it('answers null for an unknown project key and a QualorApiError for other failures', async () => {
    const s = await serve((req, res) => {
      if (req.url?.startsWith('/api/v0/projects/by-key')) problem(res, 404, 'NOT_FOUND');
      else problem(res, 500, 'INTERNAL_ERROR', `oops ${TOKEN}`);
    });
    const api = httpQualorApi(ep(s.url), noSleep);
    expect(await api.projectByKey('acme:shop')).toBeNull();
    expect(s.requests[0]?.url).toBe('/api/v0/projects/by-key?key=acme%3Ashop');
    const err = await api.createProject(ORG, 'acme:shop', 'Shop', 'main').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QualorApiError);
    expect(err).toMatchObject({ status: 500, code: 'INTERNAL_ERROR', exitCode: EXIT.SERVER });
    expect((err as Error).message).not.toContain(TOKEN);
  });

  it('reads the status import answer, a project not analysed, and a request too large', async () => {
    let answer: 'ok' | 409 | 413 | 'body' = 'ok';
    const s = await serve((_req, res) => {
      if (answer === 409) problem(res, 409, 'PROJECT_NOT_ANALYSED');
      else if (answer === 413) problem(res, 413, 'IMPORT_TOO_LARGE');
      else if (answer === 'body') problem(res, 413, 'BODY_TOO_LARGE');
      else
        json(res, 200, {
          branchId: PROJECT,
          analysisId: PROJECT,
          results: [{ ref: 'r1', outcome: 'unmatched', issueId: null, status: null }],
          competitors: 2,
        });
    });
    const api = httpQualorApi(ep(s.url), noSleep);
    expect(await api.importStatuses(PROJECT, [], true)).toEqual({
      kind: 'ok',
      results: [{ ref: 'r1', outcome: 'unmatched', issueId: null, status: null }],
      competitors: 2,
    });
    expect(s.requests[0]?.url).toBe(`/api/v0/projects/${PROJECT}/issue-status-import`);
    expect(JSON.parse(s.requests[0]!.body.toString('utf8'))).toEqual({ dryRun: true, items: [] });
    answer = 409;
    expect(await api.importStatuses(PROJECT, [], false)).toEqual({ kind: 'not_analysed' });
    answer = 413;
    expect(await api.importStatuses(PROJECT, [], false)).toEqual({ kind: 'too_large' });
    answer = 'body';
    expect(await api.importStatuses(PROJECT, [], false)).toEqual({ kind: 'too_large' });
  });

  it('reads only the profile’s own rows', async () => {
    const rule = (key: string) => ({
      key,
      name: 'n',
      engine: 'pmd',
      languages: ['java'],
      defaultSeverity: 'medium',
      quality: 'maintainability',
      kind: 'code_smell',
    });
    const s = await serve((_req, res) =>
      json(res, 200, {
        items: [
          {
            rule: rule('pmd:A'),
            active: true,
            severityOverride: 'high',
            source: 'profile',
            sourceProfileId: PROFILE,
          },
          {
            rule: rule('pmd:B'),
            active: true,
            severityOverride: null,
            source: 'default',
            sourceProfileId: null,
          },
          {
            rule: rule('pmd:C'),
            active: false,
            severityOverride: null,
            source: 'inherited',
            sourceProfileId: ORG,
          },
        ],
        nextCursor: null,
      }),
    );
    expect(await httpQualorApi(ep(s.url)).profileRows(PROFILE)).toEqual([
      { ruleKey: 'pmd:A', active: true, severityOverride: 'high' },
    ]);
    expect(s.requests[0]?.url).toBe(
      `/api/v0/quality-profiles/${PROFILE}/rules?scope=all&limit=500`,
    );
  });
});
