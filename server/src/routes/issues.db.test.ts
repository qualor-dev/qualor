import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';

interface Item {
  id: string;
  status: string;
  severity: string;
  path: string | null;
  startLine: number | null;
  rule: { key: string; engine: string };
}
interface ListBody {
  items: Item[];
  nextCursor: string | null;
  facets?: Record<string, { value: string; count: number }[]>;
}

describe('issues API: list, filters, facets, keyset pages (api.md §3, server step 12)', () => {
  let h: IngestHarness;
  let member: Session;
  let outsider: Session;
  let projectId: string;
  let branchId: string;
  let otherBranchId: string;
  let ownProjectToken: string;
  const ids: Record<string, string> = {};
  const get = (url: string, session: Session | Record<string, string> = member) =>
    h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0${url}`,
      headers: 'headers' in session ? (session as Session).headers : session,
    });
  const list = async (query: string, session: Session = member): Promise<ListBody> => {
    const res = await get(`/issues?branchId=${branchId}${query}`, session);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as ListBody;
  };
  /** Follows nextCursor to the end; returns every id in page order. */
  const walk = async (query: string, limit: number): Promise<string[]> => {
    const seen: string[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < 100; page++) {
      const body = await list(
        `${query}&limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
      );
      seen.push(...body.items.map((i) => i.id));
      cursor = body.nextCursor;
      if (!cursor) return seen;
    }
    throw new Error('pagination did not end');
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    const m = await createUser(h.ctx, { username: 'issue-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'issue-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
    const project = await h.project('acme/issues');
    projectId = project.id;
    ownProjectToken = project.token;
    branchId = await mainBranchId(h.ctx.db, projectId);
    const other = await h.project('acme/other');
    otherBranchId = await mainBranchId(h.ctx.db, other.id);

    const db = h.ctx.db;
    const eslint = await seedRule(db, { key: 'eslint:no-console' });
    const pmd = await seedRule(db, { key: 'pmd:UnusedLocalVariable' });
    const gitleaks = await seedRule(db, { key: 'gitleaks:generic-api-key', quality: 'security' });
    const semgrep = await seedRule(db, { key: 'semgrep:hardcoded-secret', quality: 'security' });
    const base = { projectId, branchId };
    ids.blocker = await seedIssue(db, {
      ...base,
      ruleId: gitleaks,
      severity: 'blocker',
      quality: 'security',
      path: 'src/config.ts',
      startLine: 3,
      message: 'Secret found: API key',
      inNewCode: true,
      snippet: { startLine: 1, lines: ['a', 'b', 'c'] },
    });
    ids.duplicate = await seedIssue(db, {
      ...base,
      ruleId: semgrep,
      severity: 'high',
      quality: 'security',
      path: 'src/config.ts',
      startLine: 3,
      message: 'Hard-coded secret',
      duplicateOfIssueId: ids.blocker,
    });
    ids.high = await seedIssue(db, {
      ...base,
      ruleId: pmd,
      severity: 'high',
      path: 'src/main/java/A.java',
      startLine: 10,
      message: 'Avoid unused local variables such as x',
    });
    ids.medium1 = await seedIssue(db, {
      ...base,
      ruleId: eslint,
      path: 'src/a.ts',
      startLine: 5,
      message: 'Unexpected console statement: 100%_done',
    });
    ids.medium2 = await seedIssue(db, {
      ...base,
      ruleId: eslint,
      path: 'src/a.ts',
      startLine: 5,
      message: 'Unexpected console statement.',
    });
    ids.nullLine = await seedIssue(db, {
      ...base,
      ruleId: eslint,
      path: 'src/a.ts',
      startLine: null,
    });
    ids.fileless = await seedIssue(db, { ...base, ruleId: eslint, path: null, severity: 'low' });
    ids.hotspot = await seedIssue(db, {
      ...base,
      ruleId: semgrep,
      kind: 'hotspot',
      severity: 'info',
      quality: 'security',
      path: 'src/b%_x.ts',
    });
    ids.resolved = await seedIssue(db, { ...base, ruleId: eslint, status: 'resolved' });
    ids.wontFix = await seedIssue(db, { ...base, ruleId: eslint, status: 'wont_fix' });
    ids.closed = await seedIssue(db, { ...base, ruleId: eslint, status: 'closed' });
    ids.otherProject = await seedIssue(db, {
      projectId: other.id,
      branchId: otherBranchId,
      ruleId: eslint,
    });
  });
  afterAll(async () => {
    await h.close();
  });

  it('lists the open, non-duplicate issues by severity (then id) by default', async () => {
    const body = await list('');
    expect(body.items.map((i) => i.id)).toEqual([
      ids.blocker,
      ids.high,
      ids.medium1,
      ids.medium2,
      ids.nullLine,
      ids.fileless,
      ids.hotspot,
    ]);
    expect(body.nextCursor).toBeNull();
    expect(body.facets).toBeUndefined();
    expect(body.items[0]).toMatchObject({
      rule: {
        key: 'gitleaks:generic-api-key',
        engine: 'gitleaks',
        name: 'gitleaks:generic-api-key',
      },
      severity: 'blocker',
      quality: 'security',
      kind: 'issue',
      status: 'open',
      path: 'src/config.ts',
      startLine: 3,
      inNewCode: true,
      duplicateOfIssueId: null,
      severityOverridden: false,
    });
  });

  it('applies each filter: OR within one, AND across them', async () => {
    const idsOf = async (query: string) => (await list(query)).items.map((i) => i.id).sort();
    const sorted = (...xs: (string | undefined)[]) => xs.map(String).sort();
    expect(await idsOf('&status=resolved&status=wont_fix')).toEqual(
      sorted(ids.resolved, ids.wontFix),
    );
    expect(await idsOf('&status=closed')).toEqual(sorted(ids.closed));
    expect(await idsOf('&severity=blocker&severity=high')).toEqual(sorted(ids.blocker, ids.high));
    expect(await idsOf('&quality=security')).toEqual(sorted(ids.blocker, ids.hotspot));
    expect(await idsOf('&kind=hotspot')).toEqual(sorted(ids.hotspot));
    expect(await idsOf('&rule=pmd:UnusedLocalVariable')).toEqual(sorted(ids.high));
    expect(await idsOf('&rule=eslint%3Ano-console&severity=low')).toEqual(sorted(ids.fileless));
    expect(await idsOf('&engine=gitleaks&engine=pmd')).toEqual(sorted(ids.blocker, ids.high));
    expect(await idsOf('&path=src/main/')).toEqual(sorted(ids.high));
    // A path prefix is literal: `%` and `_` are not wildcards.
    expect(await idsOf(`&path=${encodeURIComponent('src/b%_')}`)).toEqual(sorted(ids.hotspot));
    expect(await idsOf('&path=src/a.ts&path=src/config')).toEqual(
      sorted(ids.medium1, ids.medium2, ids.nullLine, ids.blocker),
    );
    expect(await idsOf('&inNewCode=true')).toEqual(sorted(ids.blocker));
    expect(await idsOf('&q=CONSOLE')).toEqual(sorted(ids.medium1, ids.medium2));
    expect(await idsOf(`&q=${encodeURIComponent('100%_')}`)).toEqual(sorted(ids.medium1));
    expect(await idsOf('&q=nothing-matches')).toEqual([]);
    expect(await idsOf('&includeDuplicates=true&path=src/config.ts')).toEqual(
      sorted(ids.blocker, ids.duplicate),
    );
  });

  it('pages every sort order with keyset cursors, NULL paths and lines included', async () => {
    const all = (await list('&limit=500&status=open')).items.map((i) => i.id);
    for (const sort of ['severity', 'createdAt', 'path'] as const) {
      const full = (await list(`&sort=${sort}&limit=500`)).items.map((i) => i.id);
      expect(full.slice().sort()).toEqual(all.slice().sort());
      for (const limit of [1, 2, 3]) {
        expect(await walk(`&sort=${sort}`, limit), `${sort} limit ${limit}`).toEqual(full);
      }
    }
    const byCreated = (await list('&sort=createdAt&limit=500')).items.map((i) => i.id);
    expect(byCreated).toEqual(all.slice().sort().reverse());
    const byPath = (await list('&sort=path&limit=500')).items;
    expect(byPath.map((i) => [i.path, i.startLine])).toEqual([
      ['src/a.ts', 5],
      ['src/a.ts', 5],
      ['src/a.ts', null],
      ['src/b%_x.ts', 1],
      ['src/config.ts', 3],
      ['src/main/java/A.java', 10],
      [null, null],
    ]);
  });

  it('pages by path across every NULL combination (file-less issues with and without lines)', async () => {
    const rule = await seedRule(h.ctx.db, { key: 'eslint:no-debugger' });
    const p = await h.project('acme/path-nulls');
    const branch = await mainBranchId(h.ctx.db, p.id);
    const layout: [string | null, number | null][] = [
      [null, 2],
      ['b.ts', null],
      [null, null],
      ['a.ts', 1],
      [null, 1],
      ['b.ts', 7],
      ['a.ts', null],
      [null, null],
      ['b.ts', 7],
      [null, 2],
      ['a.ts', 1],
    ];
    for (const [path, startLine] of layout) {
      await seedIssue(h.ctx.db, {
        projectId: p.id,
        branchId: branch,
        ruleId: rule,
        path,
        startLine,
      });
    }
    const page = async (query: string) => {
      const res = await get(`/issues?branchId=${branch}&sort=path${query}`, h.orgAdmin);
      expect(res.statusCode, res.body).toBe(200);
      return res.json() as ListBody;
    };
    const full = (await page('&limit=500')).items;
    expect(full.map((i) => [i.path, i.startLine])).toEqual([
      ['a.ts', 1],
      ['a.ts', 1],
      ['a.ts', null],
      ['b.ts', 7],
      ['b.ts', 7],
      ['b.ts', null],
      [null, 1],
      [null, 2],
      [null, 2],
      [null, null],
      [null, null],
    ]);
    for (const limit of [1, 2, 3, 4]) {
      const seen: string[] = [];
      let cursor: string | null = null;
      do {
        const body = await page(
          `&limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
        );
        seen.push(...body.items.map((i) => i.id));
        cursor = body.nextCursor;
      } while (cursor && seen.length <= layout.length);
      expect(seen, `limit ${limit}`).toEqual(full.map((i) => i.id));
    }
  });

  it('rejects a cursor of another sort order, or a forged one (422 query.cursor)', async () => {
    const first = await list('&sort=severity&limit=1');
    const res = await get(
      `/issues?branchId=${branchId}&sort=path&cursor=${encodeURIComponent(first.nextCursor!)}`,
    );
    expect(res.statusCode).toBe(422);
    expect(res.json().errors).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
    const forged = Buffer.from('{"s":"severity","r":"x"}').toString('base64url');
    expect((await get(`/issues?branchId=${branchId}&cursor=${forged}`)).statusCode).toBe(422);
    // Values the database would reject (out of int4 range, NUL in text) are 422, never a 500.
    const id = '019a0000-0000-7000-8000-000000000000';
    for (const crafted of [
      { s: 'path', p: 'src/a.ts', l: 9_007_199_254_740_991, id },
      { s: 'path', p: 'src/a.ts', l: -1, id },
      { s: 'path', p: 'src/\u0000a.ts', l: 1, id },
      { s: 'path', p: "x' OR 1=1 --", l: 1, id: "x' OR 1=1 --" },
      { s: 'severity', r: 0, id, extra: 1 },
    ]) {
      const cursor = Buffer.from(JSON.stringify(crafted)).toString('base64url');
      const sort = crafted.s;
      const res = await get(`/issues?branchId=${branchId}&sort=${sort}&cursor=${cursor}`);
      expect(res.statusCode, JSON.stringify(crafted)).toBe(422);
      expect(res.json().errors).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
    }
  });

  it('returns facets over the filtered set, most frequent first', async () => {
    const body = await list('&facets=severity,rule,engine,status,path,quality');
    expect(body.facets).toEqual({
      severity: [
        { value: 'medium', count: 3 },
        { value: 'blocker', count: 1 },
        { value: 'high', count: 1 },
        { value: 'info', count: 1 },
        { value: 'low', count: 1 },
      ],
      rule: [
        { value: 'eslint:no-console', count: 4 },
        { value: 'gitleaks:generic-api-key', count: 1 },
        { value: 'pmd:UnusedLocalVariable', count: 1 },
        { value: 'semgrep:hardcoded-secret', count: 1 },
      ],
      engine: [
        { value: 'eslint', count: 4 },
        { value: 'gitleaks', count: 1 },
        { value: 'pmd', count: 1 },
        { value: 'semgrep', count: 1 },
      ],
      status: [{ value: 'open', count: 7 }],
      path: [
        { value: 'src/a.ts', count: 3 },
        { value: 'src/b%_x.ts', count: 1 },
        { value: 'src/config.ts', count: 1 },
        { value: 'src/main/java/A.java', count: 1 },
      ],
      quality: [
        { value: 'maintainability', count: 5 },
        { value: 'security', count: 2 },
      ],
    });
    const filtered = await list('&status=open&status=resolved&facets=status');
    expect(filtered.facets).toEqual({
      status: [
        { value: 'open', count: 7 },
        { value: 'resolved', count: 1 },
      ],
    });
  });

  it('caps each facet at 100 values', async () => {
    const rule = await seedRule(h.ctx.db, { key: 'eslint:no-alert' });
    const cap = await h.project('acme/facet-cap');
    const capBranch = await mainBranchId(h.ctx.db, cap.id);
    for (let i = 0; i < 101; i++) {
      await seedIssue(h.ctx.db, {
        projectId: cap.id,
        branchId: capBranch,
        ruleId: rule,
        path: `src/f${String(i).padStart(3, '0')}.ts`,
      });
    }
    const res = await get(`/issues?branchId=${capBranch}&facets=path&limit=1`, h.orgAdmin);
    const body = res.json() as ListBody;
    expect(body.facets!.path).toHaveLength(100);
    expect(body.facets!.path![0]).toEqual({ value: 'src/f000.ts', count: 1 });
  });

  it('validates the query (422 with errors[].path)', async () => {
    const cases: [string, string][] = [
      ['', 'query.branchId'],
      [`branchId=${branchId}&status=bogus`, 'query.status'],
      [`branchId=${branchId}&sort=name`, 'query.sort'],
      [`branchId=${branchId}&limit=501`, 'query.limit'],
      [`branchId=${branchId}&inNewCode=yes`, 'query.inNewCode'],
      [`branchId=${branchId}&facets=severity,bogus`, 'query.facets'],
      [`branchId=${branchId}&q=${'x'.repeat(201)}`, 'query.q'],
      [`branchId=${branchId}&unknown=1`, 'query'],
      [`branchId=${branchId}${'&rule=a'.repeat(51)}`, 'query.rule'],
      [`branchId=${branchId}${'&path=a'.repeat(21)}`, 'query.path'],
      [`branchId=${branchId}&path=a%00b`, 'query.path'],
      [`branchId=${branchId}&q=a%00b`, 'query.q'],
      [`branchId=${branchId}&rule=a%00b`, 'query.rule'],
      [`branchId=${branchId}&engine=a%00b`, 'query.engine'],
      [`branchId=${branchId}&cursor=${'x'.repeat(8_193)}`, 'query.cursor'],
    ];
    for (const [query, path] of cases) {
      const res = await get(`/issues?${query}`);
      expect(res.statusCode, query).toBe(422);
      expect(
        (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path),
        query,
      ).toContainEqual(expect.stringMatching(new RegExp(`^${path.replace('.', '\\.')}`)));
    }
  });

  it('hides branches the caller cannot see (404), and rejects anonymous and project tokens', async () => {
    expect((await get(`/issues?branchId=${branchId}`, outsider)).statusCode).toBe(404);
    expect((await get(`/issues?branchId=019a0000-0000-7000-8000-000000000000`)).statusCode).toBe(
      404,
    );
    expect((await get(`/issues?branchId=${branchId}`, {})).statusCode).toBe(401);
    const project = await h.project('acme/token-only');
    const res = await get(`/issues?branchId=${branchId}`, bearer(project.token));
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe('TOKEN_NOT_ALLOWED');
    // Not even the analysis token of the branch's own project may read its issues.
    const own = await get(`/issues?branchId=${branchId}`, bearer(ownProjectToken));
    expect([own.statusCode, own.json().code]).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    for (const token of [project.token, ownProjectToken]) {
      const detail = await get(`/issues/${ids.blocker}`, bearer(token));
      expect([detail.statusCode, detail.json().code]).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    }
  });

  it('rejects an invalid cursor with 422 even when facets are asked for', async () => {
    const res = await get(`/issues?branchId=${branchId}&facets=severity,path&cursor=bogus`);
    expect(res.statusCode).toBe(422);
    expect(res.json().errors).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
  });

  it('GET /issues/{id} returns the full issue; invisible and unknown ids are 404', async () => {
    const res = await get(`/issues/${ids.blocker}`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      id: ids.blocker,
      rule: {
        key: 'gitleaks:generic-api-key',
        engine: 'gitleaks',
        quality: 'security',
        defaultSeverity: 'medium',
        tags: [],
        cwe: [],
        descriptionMd: null,
        helpUri: null,
      },
      snippet: { startLine: 1, lines: ['a', 'b', 'c'] },
      secondaryLocations: [],
      resolvedBy: null,
      fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/),
    });
    expect((await get(`/issues/${ids.blocker}`, outsider)).statusCode).toBe(404);
    expect((await get(`/issues/${ids.otherProject}`, outsider)).statusCode).toBe(404);
    expect((await get('/issues/019a0000-0000-7000-8000-000000000000')).statusCode).toBe(404);
    expect((await get('/issues/not-a-uuid')).statusCode).toBe(422);
    expect((await get(`/issues/${ids.blocker}`, {})).statusCode).toBe(401);
  });
});
