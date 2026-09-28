import { METRICS } from '@qualor/shared';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { file, reportWith } from '../../test/reports';
import { analyses, projects, qualityGates } from '../db/schema';

describe('quality gates API (api.md, server step 11)', () => {
  let h: IngestHarness;
  let member: Session;
  let outsider: Session;
  let builtinId: string;
  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    session: Session | Record<string, string> = h.orgAdmin,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: 'headers' in session ? (session as Session).headers : session,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const createGate = async (name: string) => {
    const res = await call('POST', '/quality-gates', h.orgAdmin, {
      organizationId: h.organizationId,
      name,
    });
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string };
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    const m = await createUser(h.ctx, { username: 'gate-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'gate-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
    const [builtin] = await h.ctx.db
      .select()
      .from(qualityGates)
      .where(
        and(eq(qualityGates.organizationId, h.organizationId), eq(qualityGates.isBuiltin, true)),
      );
    builtinId = builtin!.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('GET /metrics returns the catalog', async () => {
    const res = await call('GET', '/metrics', member);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveLength(METRICS.length);
    expect(res.json()).toContainEqual({
      key: 'coverage',
      name: 'Coverage',
      type: 'percent',
      direction: 'higher_is_better',
      scopes: ['overall', 'new'],
      domain: 'coverage',
    });
    expect((await call('GET', '/metrics', {})).statusCode).toBe(401);
  });

  it('lists and reads gates for members, and hides them from outsiders (404)', async () => {
    const list = await call('GET', `/quality-gates?organizationId=${h.organizationId}`, member);
    expect(list.json().items).toContainEqual(
      expect.objectContaining({
        id: builtinId,
        name: 'Qualor way',
        isBuiltin: true,
        isDefault: true,
        conditions: [
          expect.objectContaining({ metric: 'new_coverage', operator: 'lt', threshold: 80 }),
          expect.objectContaining({
            metric: 'new_duplicated_lines_density',
            operator: 'gt',
            threshold: 3,
          }),
          expect.objectContaining({ metric: 'new_issues', operator: 'gt', threshold: 0 }),
        ],
      }),
    );
    expect((await call('GET', `/quality-gates/${builtinId}`, member)).statusCode).toBe(200);
    expect((await call('GET', `/quality-gates/${builtinId}`, outsider)).json()).toMatchObject({
      status: 404,
      code: 'NOT_FOUND',
    });
    expect(
      (await call('GET', `/quality-gates?organizationId=${h.organizationId}`, outsider)).statusCode,
    ).toBe(404);
  });

  it('lets only org admins with the admin scope change gates (403 FORBIDDEN / INSUFFICIENT_SCOPE)', async () => {
    const res = await call('POST', '/quality-gates', member, {
      organizationId: h.organizationId,
      name: 'Mine',
    });
    expect([res.statusCode, res.json().code]).toEqual([403, 'FORBIDDEN']);
    const writePat = (
      await call('POST', '/tokens', h.orgAdmin, { name: 'write', scopes: ['write'] })
    ).json().token as string;
    const scoped = await call('POST', '/quality-gates', bearer(writePat), {
      organizationId: h.organizationId,
      name: 'Mine',
    });
    expect([scoped.statusCode, scoped.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
  });

  it("answers 404 to every change of another organisation's gate, never 403 or 409", async () => {
    const gate = await createGate('Private');
    const cond = (
      await call('POST', `/quality-gates/${gate.id}/conditions`, h.orgAdmin, {
        metric: 'issues',
        operator: 'gt',
        threshold: 0,
      })
    ).json() as { id: string };
    for (const id of [gate.id, builtinId, '01900000-0000-7000-8000-000000000000']) {
      for (const [method, url, payload] of [
        ['PATCH', `/quality-gates/${id}`, { name: 'Taken' }],
        ['DELETE', `/quality-gates/${id}`, undefined],
        ['POST', `/quality-gates/${id}/copy`, { name: 'Stolen' }],
        ['POST', `/quality-gates/${id}/set-default`, undefined],
        [
          'POST',
          `/quality-gates/${id}/conditions`,
          { metric: 'issues', operator: 'gt', threshold: 1 },
        ],
        ['PATCH', `/quality-gates/${id}/conditions/${cond.id}`, { threshold: 1 }],
        ['DELETE', `/quality-gates/${id}/conditions/${cond.id}`, undefined],
      ] as const) {
        const res = await call(method, url, outsider, payload);
        expect([res.statusCode, res.json().code], `${method} ${url}`).toEqual([404, 'NOT_FOUND']);
      }
    }
    const create = await call('POST', '/quality-gates', outsider, {
      organizationId: h.organizationId,
      name: 'Intruder',
    });
    expect(create.statusCode).toBe(404);
    // Members see gates but cannot change them.
    const setDefault = await call('POST', `/quality-gates/${gate.id}/set-default`, member);
    expect([setDefault.statusCode, setDefault.json().code]).toEqual([403, 'FORBIDDEN']);
    // A condition is only reachable through its own gate.
    const other = await createGate('Other');
    expect(
      (
        await call('PATCH', `/quality-gates/${other.id}/conditions/${cond.id}`, h.orgAdmin, {
          threshold: 5,
        })
      ).statusCode,
    ).toBe(404);
  });

  it('bounds names, thresholds and bodies (422)', async () => {
    const gate = await createGate('Bounds');
    const add = (body: unknown) =>
      call('POST', `/quality-gates/${gate.id}/conditions`, h.orgAdmin, body);
    for (const body of [
      { metric: 'new_coverage', operator: 'lt', threshold: 101 },
      { metric: 'new_coverage', operator: 'lt', threshold: -1 },
      { metric: 'issues', operator: 'gt', threshold: -1 },
      { metric: 'issues', operator: 'gt', threshold: 2 ** 60 },
      { metric: 'issues', operator: 'gte', threshold: 0 },
      { metric: 'issues', operator: 'gt', threshold: '0' },
      { metric: 'issues', operator: 'gt', threshold: 0, extra: true },
      { metric: 'x'.repeat(65), operator: 'gt', threshold: 0 },
    ]) {
      expect((await add(body)).statusCode, JSON.stringify(body).slice(0, 80)).toBe(422);
    }
    for (const name of ['', '   ', 'x'.repeat(101)]) {
      const res = await call('POST', '/quality-gates', h.orgAdmin, {
        organizationId: h.organizationId,
        name,
      });
      expect(res.statusCode).toBe(422);
    }
    expect((await call('GET', `/quality-gates/${gate.id}`)).json().conditions).toEqual([]);
  });

  it('keeps the built-in gate read-only: 409 BUILTIN_READ_ONLY', async () => {
    for (const [method, url, payload] of [
      ['PATCH', `/quality-gates/${builtinId}`, { name: 'Renamed' }],
      ['DELETE', `/quality-gates/${builtinId}`, undefined],
      [
        'POST',
        `/quality-gates/${builtinId}/conditions`,
        { metric: 'issues', operator: 'gt', threshold: 0 },
      ],
    ] as const) {
      const res = await call(method, url, h.orgAdmin, payload);
      expect([res.statusCode, res.json().code], `${method} ${url}`).toEqual([
        409,
        'BUILTIN_READ_ONLY',
      ]);
    }
  });

  it('rejects U+0000 in a gate name with 422 on body.name (create, rename, copy)', async () => {
    const gate = await createGate('Nul target');
    for (const [method, url, payload] of [
      ['POST', '/quality-gates', { organizationId: h.organizationId, name: 'a\u0000b' }],
      ['PATCH', `/quality-gates/${gate.id}`, { name: 'a\u0000b' }],
      ['POST', `/quality-gates/${gate.id}/copy`, { name: 'a\u0000b' }],
    ] as const) {
      const res = await call(method, url, h.orgAdmin, payload);
      expect(res.statusCode, `${method} ${url}`).toBe(422);
      expect(res.json().errors.map((e: { path: string }) => e.path)).toEqual(['body.name']);
    }
  });

  it('copies a gate with its conditions and edits the copy', async () => {
    const res = await call('POST', `/quality-gates/${builtinId}/copy`, h.orgAdmin, {
      name: 'Qualor way (strict)',
    });
    expect(res.statusCode).toBe(201);
    const copy = res.json();
    expect(copy).toMatchObject({ isBuiltin: false, isDefault: false });
    expect(copy.conditions).toHaveLength(3);
    const coverage = copy.conditions.find((c: { metric: string }) => c.metric === 'new_coverage');
    const patched = await call(
      'PATCH',
      `/quality-gates/${copy.id}/conditions/${coverage.id}`,
      h.orgAdmin,
      { threshold: 90 },
    );
    expect(patched.json()).toEqual({ ...coverage, threshold: 90 });
    const renamed = await call('PATCH', `/quality-gates/${copy.id}`, h.orgAdmin, {
      name: 'Strict',
    });
    expect(renamed.json()).toMatchObject({ name: 'Strict' });
  });

  it('validates conditions against the catalog: 422 unknown metric or out-of-range threshold, 409 duplicate', async () => {
    const gate = await createGate('Validation');
    const add = (body: unknown) =>
      call('POST', `/quality-gates/${gate.id}/conditions`, h.orgAdmin, body);
    const unknown = await add({ metric: 'new_bugs', operator: 'gt', threshold: 0 });
    expect(unknown.json()).toMatchObject({
      status: 422,
      errors: [{ path: 'body.metric', message: 'Unknown metric: new_bugs' }],
    });
    const rating = await add({ metric: 'security_rating', operator: 'gt', threshold: 7 });
    expect(rating.json().errors).toEqual([
      { path: 'body.threshold', message: 'Must be between 1 and 5 for security_rating' },
    ]);
    // An overall-only metric has no new_ version.
    expect((await add({ metric: 'new_ncloc', operator: 'gt', threshold: 1 })).statusCode).toBe(422);
    const ok = await add({ metric: 'new_issues', operator: 'gt', threshold: 0 });
    expect(ok.statusCode).toBe(201);
    const duplicate = await add({ metric: 'new_issues', operator: 'gt', threshold: 5 });
    expect([duplicate.statusCode, duplicate.json().code]).toEqual([409, 'CONDITION_EXISTS']);
    const removed = await call(
      'DELETE',
      `/quality-gates/${gate.id}/conditions/${ok.json().id}`,
      h.orgAdmin,
    );
    expect(removed.statusCode).toBe(204);
    expect(
      (await call('DELETE', `/quality-gates/${gate.id}/conditions/${ok.json().id}`)).statusCode,
    ).toBe(404);
  });

  it('set-default moves the default, and the next analysis is evaluated with it', async () => {
    const gate = await createGate('Nothing new');
    await call('POST', `/quality-gates/${gate.id}/conditions`, h.orgAdmin, {
      metric: 'new_lines',
      operator: 'gt',
      threshold: 1_000_000,
    });
    const res = await call('POST', `/quality-gates/${gate.id}/set-default`);
    expect(res.json()).toMatchObject({ id: gate.id, isDefault: true });
    const defaults = await h.ctx.db
      .select()
      .from(qualityGates)
      .where(
        and(eq(qualityGates.organizationId, h.organizationId), eq(qualityGates.isDefault, true)),
      );
    expect(defaults.map((g) => g.id)).toEqual([gate.id]);
    try {
      const p = await h.project('gates/api-default');
      const id = await p.ingestOk(reportWith({ projectKey: p.key, files: [file('src/a.ts')] }));
      const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, id));
      expect(row!.gateResult).toMatchObject({ gate: { id: gate.id, name: 'Nothing new' } });
    } finally {
      await call('POST', `/quality-gates/${builtinId}/set-default`);
    }
  });

  it('deleting the default gate leaves the organisation without one: the next analysis is none (G2)', async () => {
    const gate = await createGate('Short-lived default');
    await call('POST', `/quality-gates/${gate.id}/set-default`);
    try {
      expect((await call('DELETE', `/quality-gates/${gate.id}`)).statusCode).toBe(204);
      const list = await call('GET', `/quality-gates?organizationId=${h.organizationId}`);
      expect(list.json().items.filter((g: { isDefault: boolean }) => g.isDefault)).toEqual([]);
      const p = await h.project('gates/api-no-default');
      const id = await p.ingestOk(reportWith({ projectKey: p.key, files: [file('src/a.ts')] }));
      const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, id));
      expect(row).toMatchObject({ gateStatus: 'none', gateResult: { status: 'none', gate: null } });
    } finally {
      await call('POST', `/quality-gates/${builtinId}/set-default`);
    }
  });

  it('asks for a threshold when a new metric does not fit the stored one (422)', async () => {
    const gate = await createGate('Metric swap');
    const cond = (
      await call('POST', `/quality-gates/${gate.id}/conditions`, h.orgAdmin, {
        metric: 'issues',
        operator: 'gt',
        threshold: 50,
      })
    ).json() as { id: string };
    const url = `/quality-gates/${gate.id}/conditions/${cond.id}`;
    expect(
      (await call('PATCH', url, h.orgAdmin, { metric: 'security_rating' })).json(),
    ).toMatchObject({
      status: 422,
      errors: [
        {
          path: 'body.threshold',
          message:
            'The current threshold 50 is not between 1 and 5 for security_rating; send a threshold with the new metric',
        },
      ],
    });
    const swapped = await call('PATCH', url, h.orgAdmin, {
      metric: 'security_rating',
      threshold: 3,
    });
    expect(swapped.json()).toMatchObject({
      metric: 'security_rating',
      operator: 'gt',
      threshold: 3,
    });
  });

  it('deleting a gate returns its projects to the organisation default', async () => {
    const gate = await createGate('Temporary');
    const p = await h.project('gates/api-delete');
    await call('PATCH', `/projects/${p.id}`, h.orgAdmin, { qualityGateId: gate.id });
    expect((await call('DELETE', `/quality-gates/${gate.id}`)).statusCode).toBe(204);
    const [project] = await h.ctx.db.select().from(projects).where(eq(projects.id, p.id));
    expect(project!.qualityGateId).toBeNull();
    expect((await call('GET', `/quality-gates/${gate.id}`)).statusCode).toBe(404);
  });
});
