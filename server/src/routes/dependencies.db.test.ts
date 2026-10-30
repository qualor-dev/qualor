import { and, eq } from 'drizzle-orm';
import type { DependencyEntry, LicensePolicy, Report } from '@qualor/shared';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, reportWith, type ReportParts } from '../../test/reports';
import { branches, instanceSettings, projectVersions } from '../db/schema';
import { fixedEdition } from '../license/edition';
import { LICENSE_POLICY_SETTINGS_KEY, writeLicensePolicy } from '../licenses/settings';

/** A URL's query part: `?` and the query, or nothing for none. */
function queryPart(query: string): string {
  return query === '' ? '' : `?${query}`;
}

/** 6M §8: the community dependency inventory API, `GET /projects/{id}/dependencies`. */
describe('GET /projects/{id}/dependencies (6M)', () => {
  let h: IngestHarness;
  let p: IngestProject;
  let minute = 0;
  const report = (project: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: project.key,
      analysisDate: new Date(Date.UTC(2026, 9, 14, 11, minute++)).toISOString(),
      ...parts,
    });
  const dep = (name: string, overrides: Partial<DependencyEntry> = {}): DependencyEntry => ({
    ecosystem: 'npm',
    path: 'package-lock.json',
    name,
    version: '1.0.0',
    licenses: ['MIT'],
    ...overrides,
  });
  const get = (url: string, session: Session | null = h.orgAdmin) =>
    h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0${url}`,
      ...(session === null ? {} : { headers: session.headers }),
    });
  const url = (project: IngestProject, query = '') =>
    `/projects/${project.id}/dependencies${queryPart(query)}`;
  const names = async (query: string) => {
    const res = await get(url(p, query));
    expect(res.statusCode, res.body).toBe(200);
    return (res.json() as { rows: { name: string }[] }).rows.map((r) => r.name);
  };

  const MAIN = [
    dep('lodash', { version: '4.17.21', line: 10, direct: true }),
    dep('gpl-lib', { licenses: ['GPL-3.0-only'], direct: false }),
    dep('agpl-db', { version: '2.0.0', licenses: ['AGPL-3.0-only'] }),
    dep('dual', { licenses: ['MIT OR Apache-2.0'] }),
    dep('mystery', { version: '0.1.0', ecosystem: 'gomod', path: 'go.sum', licenses: [] }),
    dep('classpath', {
      ecosystem: 'maven',
      path: 'pom.xml',
      licenses: ['GPL-2.0-only WITH Classpath-exception-2.0'],
    }),
    dep('apache-lib', {
      version: '3.0.0',
      ecosystem: 'maven',
      path: 'pom.xml',
      licenses: ['Apache-2.0', 'MIT'],
    }),
  ];

  beforeAll(async () => {
    h = await createIngestHarness();
    p = await h.project('deps/route');
    await p.ingestOk(report(p, { dependencies: MAIN }));
    await p.ingestOk(
      report(p, {
        branch: 'feature',
        mergeRequest: { id: '7', sourceBranch: 'feature', targetBranch: 'main' },
        dependencies: [dep('only-in-mr', { licenses: ['BSD-3-Clause'] })],
      }),
    );
  });
  afterAll(async () => {
    await h.close();
  });

  it('lists the main branch inventory in name order with its summary', async () => {
    const res = await get(url(p));
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({
      page: 1,
      pageSize: 50,
      total: 7,
      inventory: true,
      verdicts: false,
    });
    expect(body.rows.map((r: { name: string }) => r.name)).toEqual([
      'agpl-db',
      'apache-lib',
      'classpath',
      'dual',
      'gpl-lib',
      'lodash',
      'mystery',
    ]);
    expect(body.rows[5]).toEqual({
      ecosystem: 'npm',
      path: 'package-lock.json',
      line: 10,
      name: 'lodash',
      version: '4.17.21',
      licenses: ['MIT'],
      direct: true,
    });
    expect(body.rows[0]).toMatchObject({ name: 'agpl-db', line: null, direct: null });
    expect(body.summary).toEqual({
      total: 7,
      known: 6,
      unknown: 1,
      byLicense: [
        { license: 'MIT', count: 2 },
        { license: 'AGPL-3.0-only', count: 1 },
        { license: 'Apache-2.0', count: 1 },
        { license: 'GPL-2.0-only WITH Classpath-exception-2.0', count: 1 },
        { license: 'GPL-3.0-only', count: 1 },
        { license: 'MIT OR Apache-2.0', count: 1 },
      ],
    });
    expect((await get(url(p, 'branch=main'))).json()).toEqual(body);
  });

  it('filters by licence, group, ecosystem, unknown, direct and text', async () => {
    expect(await names('license=MIT')).toEqual(['apache-lib', 'lodash']);
    expect(await names('group=strong-copyleft')).toEqual(['gpl-lib']);
    expect(await names('group=weak-copyleft')).toEqual(['classpath']);
    expect(await names('group=network-copyleft')).toEqual(['agpl-db']);
    expect(await names('group=non-commercial-or-source-available')).toEqual([]);
    expect(await names('ecosystem=maven')).toEqual(['apache-lib', 'classpath']);
    expect(await names('unknown=true')).toEqual(['mystery']);
    expect(await names('unknown=false')).toHaveLength(6);
    expect(await names('direct=true')).toEqual(['lodash']);
    expect(await names('direct=false')).toHaveLength(6);
    expect(await names('q=LIB')).toEqual(['apache-lib', 'gpl-lib']);
    // LIKE wildcards are literal: unescaped, `%` and `_` would match every name.
    expect(await names('q=%25')).toEqual([]);
    expect(await names('q=_')).toEqual([]);
    expect(await names('ecosystem=npm&direct=false&license=MIT')).toEqual([]);

    const filtered = (await get(url(p, 'ecosystem=maven'))).json();
    expect(filtered.total).toBe(2);
    // The summary describes the whole inventory, whatever the filters.
    expect(filtered.summary).toMatchObject({ total: 7, known: 6, unknown: 1 });
  });

  it('pages with page and pageSize', async () => {
    const second = (await get(url(p, 'page=2&pageSize=2'))).json();
    expect(second).toMatchObject({ page: 2, pageSize: 2, total: 7 });
    expect(second.rows.map((r: { name: string }) => r.name)).toEqual(['classpath', 'dual']);
    expect(await names('page=4&pageSize=2')).toEqual(['mystery']);
    expect(await names('page=5&pageSize=2')).toEqual([]);
  });

  it('answers a merge request’s own snapshot', async () => {
    const res = (await get(url(p, 'mr=7'))).json();
    expect(res.rows.map((r: { name: string }) => r.name)).toEqual(['only-in-mr']);
    expect(res.summary).toEqual({
      total: 1,
      known: 1,
      unknown: 0,
      byLicense: [{ license: 'BSD-3-Clause', count: 1 }],
    });
  });

  it('validates the query (422)', async () => {
    for (const query of [
      'branch=main&mr=7',
      'group=permissive',
      'pageSize=501',
      'page=0',
      'unknown=yes',
      'ecosystem=NPM',
      'mr=abc',
      'license=a%00b',
      'extra=1',
    ]) {
      expect((await get(url(p, query))).statusCode, query).toBe(422);
    }
  });

  it('answers 404 for an unknown project, branch or merge request', async () => {
    expect(
      (await get('/projects/00000000-0000-7000-8000-000000000000/dependencies')).statusCode,
    ).toBe(404);
    expect((await get('/projects/not-a-uuid/dependencies')).statusCode).toBe(422);
    expect((await get(url(p, 'branch=nope'))).statusCode).toBe(404);
    expect((await get(url(p, 'mr=99'))).statusCode).toBe(404);
    // A merge request is not found by its name as a branch.
    expect((await get(url(p, 'branch=7'))).statusCode).toBe(404);
  });

  it('says inventory: false until a report carried one, and true for an empty one', async () => {
    const fresh = await h.project('deps/fresh');
    const empty = {
      rows: [],
      page: 1,
      pageSize: 50,
      total: 0,
      summary: { total: 0, known: 0, unknown: 0, byLicense: [] },
      inventory: false,
      verdicts: false,
    };
    // No analysis yet: there is no main branch row.
    expect((await get(url(fresh))).json()).toEqual(empty);
    // An analysis without the field (an older CLI, a disabled pass).
    await fresh.ingestOk(report(fresh, {}));
    expect((await get(url(fresh))).json()).toEqual(empty);

    // The licence pass ran and found no dependencies.
    const sampleEngines = report(fresh, {}).engines;
    await fresh.ingestOk(
      report(fresh, {
        engines: [...sampleEngines, engine('trivy-licenses')],
        dependencies: [],
      }),
    );
    expect((await get(url(fresh))).json()).toEqual({ ...empty, inventory: true });
  });

  it('needs project.read: 401 without a session, 404 outside the organisation, 200 for a viewer', async () => {
    expect((await get(url(p), null)).statusCode).toBe(401);

    const outsider = await createUser(h.ctx, { username: 'deps-outsider' });
    const outsiderSession = await login(h.ctx, outsider.username, outsider.password);
    expect((await get(url(p), outsiderSession)).statusCode).toBe(404);

    const viewer = await createUser(h.ctx, { username: 'deps-viewer' });
    await addMember(h.ctx, h.organizationId, viewer.id, 'viewer');
    const viewerSession = await login(h.ctx, viewer.username, viewer.password);
    expect((await get(url(p), viewerSession)).statusCode).toBe(200);
  });

  it('answers the inventory of a version with ?version, not combined with branch or mr', async () => {
    const q = await h.project('deps/by-version');
    await q.ingestOk(report(q, { dependencies: [dep('on-main')] }));
    await q.ingestOk(
      report(q, {
        branch: null,
        tag: 'v1.2.3',
        version: '1.2.3',
        findings: [],
        files: [],
        dependencies: [dep('in-version', { licenses: ['GPL-3.0-only'] }), dep('second')],
      }),
    );
    const [version] = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, q.id));
    const res = await get(`/projects/${q.id}/dependencies?version=${version!.id}`);
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json();
    expect(body.rows.map((r: { name: string }) => r.name)).toEqual(['in-version', 'second']);
    expect(body).toMatchObject({ total: 2, inventory: true, summary: { total: 2 } });
    const filtered = await get(`/projects/${q.id}/dependencies?version=${version!.id}&q=sec`);
    expect(filtered.json().rows.map((r: { name: string }) => r.name)).toEqual(['second']);
    // The branch inventory is untouched.
    expect((await get(url(q))).json().rows.map((r: { name: string }) => r.name)).toEqual([
      'on-main',
    ]);

    for (const extra of ['branch=main', 'mr=1']) {
      const both = await get(`/projects/${q.id}/dependencies?version=${version!.id}&${extra}`);
      expect(both.statusCode, extra).toBe(422);
    }
    expect((await get(`/projects/${q.id}/dependencies?version=not-a-uuid`)).statusCode).toBe(422);
    const unknown = await get(
      `/projects/${q.id}/dependencies?version=00000000-0000-4000-8000-000000000000`,
    );
    expect(unknown.statusCode).toBe(404);
    // A version of another project is not found either.
    expect((await get(`/projects/${p.id}/dependencies?version=${version!.id}`)).statusCode).toBe(
      404,
    );
  });
});

/**
 * 6M: the `licensing` quality is accepted by the rules and issues CHECKs and the issue filters.
 * Only the server makes licensing issues: a report cannot declare the quality (final review I3).
 */
describe('the licensing quality (6M)', () => {
  let h: IngestHarness;

  beforeAll(async () => {
    const base = fixedEdition();
    h = await createIngestHarness({
      edition: { ...base, limits: () => ({ ...base.limits(), licenses: { policy: true } }) },
    });
    await h.ctx.db.transaction((tx) =>
      writeLicensePolicy(tx, h.organizationId, {
        mode: 'denylist',
        forbiddenGroups: ['strong-copyleft'],
        forbidden: [],
        allowed: [],
        warnUnknown: false,
      }),
    );
  });
  afterAll(async () => {
    await h.close();
  });

  it('stores a licensing issue and filters and facets by quality=licensing', async () => {
    const p = await h.project('deps/quality');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('trivy-licenses')],
        files: [file('package-lock.json', { language: 'other', lines: 20 })],
        findings: [],
        dependencies: [
          {
            ecosystem: 'npm',
            path: 'package-lock.json',
            name: 'gpl-pkg',
            version: '1.0.0',
            licenses: ['GPL-3.0-only'],
            line: 5,
          },
        ],
      }),
    );
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/issues?branchId=${main!.id}&quality=licensing&facets=quality`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json();
    expect(body.items.map((i: { quality: string }) => i.quality)).toEqual(['licensing']);
    expect(body.facets.quality).toEqual([{ value: 'licensing', count: 1 }]);

    const rules = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/rules?organizationId=${h.organizationId}&quality=licensing`,
      headers: h.orgAdmin.headers,
    });
    expect(rules.statusCode, rules.body).toBe(200);
    expect(
      rules
        .json()
        .items.map((r: { key: string }) => r.key)
        .sort(),
    ).toEqual(['license:forbidden', 'license:unknown']);
  });
});

/**
 * 6M §8: with `limits.licenses.policy` on and a policy for the project's organisation, every row
 * carries the policy's verdict, and `verdict` filters by it.
 */
describe('GET /projects/{id}/dependencies with a licence policy (6M)', () => {
  let h: IngestHarness;
  let p: IngestProject;
  let licensed = true;
  const STRONG: LicensePolicy = {
    mode: 'denylist',
    forbiddenGroups: ['strong-copyleft'],
    forbidden: [],
    allowed: [],
    warnUnknown: false,
  };
  const dep = (name: string, licenses: string[], ecosystem = 'npm'): DependencyEntry => ({
    ecosystem,
    path: ecosystem === 'npm' ? 'package-lock.json' : 'pom.xml',
    name,
    version: '1.0.0',
    licenses,
  });
  const get = async (query = '') => {
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${p.id}/dependencies${queryPart(query)}`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as {
      rows: { name: string; verdict?: string }[];
      total: number;
      verdicts: boolean;
    };
  };
  const verdicts = async (query = '') =>
    Object.fromEntries((await get(query)).rows.map((r) => [r.name, r.verdict]));
  const setPolicy = (policy: LicensePolicy | null) =>
    h.ctx.db.transaction((tx) => writeLicensePolicy(tx, h.organizationId, policy));

  beforeAll(async () => {
    const base = fixedEdition();
    h = await createIngestHarness({
      edition: {
        ...base,
        limits: () => ({ ...base.limits(), licenses: { policy: licensed } }),
      },
    });
    p = await h.project('deps/policy');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        dependencies: [
          dep('a-gpl', ['GPL-3.0-only']),
          dep('b-dual', ['MIT OR GPL-3.0-only']),
          dep('c-mit', ['MIT']),
          dep('d-none', []),
          dep('e-lgpl', ['LGPL-2.1-only', 'MIT'], 'maven'),
          dep('f-gpl2', ['GPL-2.0+'], 'maven'),
          dep('g-custom', ['Some custom licence']),
        ],
      }),
    );
  });
  afterAll(async () => {
    await h.close();
  });
  beforeEach(async () => {
    licensed = true;
    await h.ctx.db
      .delete(instanceSettings)
      .where(eq(instanceSettings.key, LICENSE_POLICY_SETTINGS_KEY));
  });

  it('carries no verdict without a policy, and ignores the verdict filter', async () => {
    const all = await get();
    expect(all.verdicts).toBe(false);
    expect(all.rows.every((r) => !('verdict' in r))).toBe(true);
    expect((await get('verdict=forbidden')).total).toBe(7);
  });

  it('carries no verdict without the seam, even with a stored policy', async () => {
    await setPolicy(STRONG);
    licensed = false;
    const all = await get('verdict=forbidden');
    expect(all).toMatchObject({ total: 7, verdicts: false });
    expect(all.rows.every((r) => !('verdict' in r))).toBe(true);
  });

  it('ignores the policy of another organisation', async () => {
    await h.ctx.db.insert(instanceSettings).values({
      key: LICENSE_POLICY_SETTINGS_KEY,
      value: { organizations: { '0190a6c2-0000-7000-8000-00000000beef': STRONG } },
    });
    expect((await get()).verdicts).toBe(false);
  });

  it('judges every row by the organisation policy', async () => {
    await setPolicy(STRONG);
    expect((await get()).verdicts).toBe(true);
    expect(await verdicts()).toEqual({
      'a-gpl': 'forbidden',
      'b-dual': 'allowed',
      'c-mit': 'allowed',
      'd-none': 'unknown',
      'e-lgpl': 'allowed',
      'f-gpl2': 'forbidden',
      'g-custom': 'unknown',
    });
    await setPolicy({ ...STRONG, forbiddenGroups: ['weak-copyleft'] });
    expect(await verdicts('ecosystem=maven')).toEqual({
      'e-lgpl': 'forbidden',
      'f-gpl2': 'allowed',
    });
  });

  it('filters by verdict before paging, with the other filters', async () => {
    await setPolicy(STRONG);
    const forbidden = await get('verdict=forbidden');
    expect(forbidden).toMatchObject({ total: 2, verdicts: true });
    expect(forbidden.rows.map((r) => r.name)).toEqual(['a-gpl', 'f-gpl2']);
    expect(Object.keys(await verdicts('verdict=unknown'))).toEqual(['d-none', 'g-custom']);

    const allowed = await get('verdict=allowed&pageSize=2&page=2');
    expect(allowed.total).toBe(3);
    expect(allowed.rows.map((r) => [r.name, r.verdict])).toEqual([['e-lgpl', 'allowed']]);
    expect((await get('verdict=allowed&pageSize=2&page=3')).rows).toEqual([]);
    expect((await get('verdict=allowed&pageSize=2')).rows.map((r) => r.name)).toEqual([
      'b-dual',
      'c-mit',
    ]);

    const maven = await get('verdict=forbidden&ecosystem=maven');
    expect(maven.rows.map((r) => r.name)).toEqual(['f-gpl2']);
    expect(maven.total).toBe(1);
  });

  it('validates the verdict (422)', async () => {
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${p.id}/dependencies?verdict=bad`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode).toBe(422);
  });
});
