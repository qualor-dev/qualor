import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { file, finding, reportWith } from '../../test/reports';
import { analyses, branches, measures } from '../db/schema';
import { downsample, measureHistory } from '../measures/read';
import { MAX_FILE_DUPLICATIONS } from '../measures/store';

describe('measures and files API (api.md, server step 10)', () => {
  let h: IngestHarness;
  let p: IngestProject;
  let mainId: string;
  let first: string;
  let second: string;
  const get = (url: string, session: Session = h.orgAdmin) =>
    h.ctx.app.inject({ method: 'GET', url: `/api/v0${url}`, headers: session.headers });

  const files = [
    file('src/a.ts', {
      lines: 20,
      newLines: [[1, 4]],
      coverage: { covered: [[1, 3]], uncovered: [[4, 4]], branches: [] },
    }),
    file('src/a.test.ts', { kind: 'test', lines: 10 }),
    file('src/lib/b.ts', {
      lines: 30,
      coverage: { covered: [[1, 1]], uncovered: [[2, 4]], branches: [] },
    }),
    file('docs/guide.md', { language: 'other', lines: 5 }),
  ];

  beforeAll(async () => {
    h = await createIngestHarness();
    p = await h.project('measures/api');
    first = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-20T10:00:00Z',
        files,
        findings: [finding({ path: 'src/a.ts', line: 2 })],
      }),
    );
    second = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-21T10:00:00Z',
        files,
        findings: [
          finding({ path: 'src/a.ts', line: 2 }),
          finding({ path: 'src/lib/b.ts', line: 9, ruleId: 'eqeqeq' }),
        ],
      }),
    );
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    mainId = main!.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('GET /branches/{id}/measures returns the latest overall and new values', async () => {
    const res = await get(`/branches/${mainId}/measures?metrics=issues,coverage,files`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual([
      { metric: 'issues', overall: 2, new: 1 },
      { metric: 'coverage', overall: 50, new: 75 },
      { metric: 'files', overall: 3, new: null },
    ]);
    const all = (await get(`/branches/${mainId}/measures`)).json();
    expect(all.map((m: { metric: string }) => m.metric)).toContain('cognitive_complexity');
  });

  it('rejects unknown metrics with 422 and answers [] for a branch without analyses', async () => {
    const bad = await get(`/branches/${mainId}/measures?metrics=coverage,new_coverage`);
    expect(bad.statusCode).toBe(422);
    expect(bad.json().errors).toEqual([
      { path: 'query.metrics', message: 'Unknown metric: new_coverage' },
    ]);
    const empty = await h.project('measures/empty');
    const [branch] = await h.ctx.db.select().from(branches).where(eq(branches.projectId, empty.id));
    expect((await get(`/branches/${branch!.id}/measures`)).json()).toEqual([]);
  });

  it('GET /branches/{id}/measures/history returns points by analysis date, within from/to', async () => {
    const res = await get(`/branches/${mainId}/measures/history?metrics=issues,new_issues`);
    expect(res.json()).toEqual([
      {
        metric: 'issues',
        points: [
          { analysisId: first, date: '2026-09-20T10:00:00.000Z', value: 1 },
          { analysisId: second, date: '2026-09-21T10:00:00.000Z', value: 2 },
        ],
      },
      {
        metric: 'new_issues',
        points: [
          { analysisId: first, date: '2026-09-20T10:00:00.000Z', value: 1 },
          { analysisId: second, date: '2026-09-21T10:00:00.000Z', value: 1 },
        ],
      },
    ]);
    const later = await get(
      `/branches/${mainId}/measures/history?metrics=issues&from=2026-09-21T00:00:00Z`,
    );
    expect(later.json()[0].points.map((pt: { analysisId: string }) => pt.analysisId)).toEqual([
      second,
    ]);
    expect((await get(`/branches/${mainId}/measures/history`)).statusCode).toBe(422);
    expect((await get(`/branches/${mainId}/measures/history?metrics=nope`)).statusCode).toBe(422);
  });

  it('GET /branches/{id}/files aggregates directories over their main files', async () => {
    const root = (await get(`/branches/${mainId}/files`)).json();
    expect(root).toMatchObject({
      items: [
        { type: 'dir', name: 'docs', path: 'docs', measures: { files: 1, lines: 5, issues: 0 } },
        {
          type: 'dir',
          name: 'src',
          path: 'src',
          language: null,
          measures: {
            files: 2,
            lines: 50,
            lines_to_cover: 8,
            uncovered_lines: 4,
            coverage: 50,
            issues: 2,
          },
        },
      ],
      nextCursor: null,
    });
    const src = (await get(`/branches/${mainId}/files?dir=src`)).json();
    expect(
      src.items.map((i: { type: string; name: string; kind: string | null }) => [
        i.type,
        i.name,
        i.kind,
      ]),
    ).toEqual([
      ['file', 'a.test.ts', 'test'],
      ['file', 'a.ts', 'main'],
      ['dir', 'lib', null],
    ]);
    expect(src.items[1].measures).toMatchObject({ lines: 20, coverage: 75, issues: 1 });
    expect(src.items[0].measures).toMatchObject({ files: 1, lines: 10, coverage: null });
  });

  it('paginates the tree by name and validates dir and cursor', async () => {
    const page1 = (await get(`/branches/${mainId}/files?dir=src&limit=2`)).json();
    expect(page1.items.map((i: { name: string }) => i.name)).toEqual(['a.test.ts', 'a.ts']);
    const page2 = (
      await get(`/branches/${mainId}/files?dir=src&limit=2&cursor=${page1.nextCursor}`)
    ).json();
    expect(page2).toMatchObject({ items: [{ name: 'lib' }], nextCursor: null });
    expect((await get(`/branches/${mainId}/files?dir=../etc`)).statusCode).toBe(422);
    expect((await get(`/branches/${mainId}/files?cursor=bogus`)).statusCode).toBe(422);
    expect((await get(`/branches/${mainId}/files?sort=ncloc`)).statusCode).toBe(422);
  });

  it('GET /branches/{id}/file returns measures, coverage, and the issues of the file', async () => {
    const res = await get(`/branches/${mainId}/file?path=src/a.ts`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      path: 'src/a.ts',
      language: 'typescript',
      kind: 'main',
      analysisId: second,
      measures: { lines: 20, lines_to_cover: 4, coverage: 75, issues: 1 },
      coverage: { covered: [[1, 3]], uncovered: [[4, 4]], branches: [] },
      newLines: [[1, 4]],
      duplications: [],
      duplicationsTruncated: false,
      issues: [{ ruleKey: 'eslint:no-console', status: 'open', startLine: 2, inNewCode: true }],
      issuesTruncated: false,
    });
    expect((await get(`/branches/${mainId}/file?path=src/missing.ts`)).statusCode).toBe(404);
  });

  it('puts headline measures on project and branch list items', async () => {
    const projects = (await get(`/projects?q=${encodeURIComponent('measures/api')}`)).json();
    expect(projects.items[0].mainBranch.measures).toMatchObject({
      issues: 2,
      coverage: 50,
      new_issues: 1,
      security_rating: 1,
    });
    // The UI loads the main branch's gate from its last succeeded analysis, not the newest listed.
    expect(projects.items[0].mainBranch).toMatchObject({ id: mainId, lastAnalysisId: second });
    const one = (await get(`/projects/${p.id}`)).json();
    expect(one.mainBranch).toMatchObject({ id: mainId, lastAnalysisId: second });
    const list = (await get(`/projects/${p.id}/branches`)).json();
    expect(list.items[0].measures).toMatchObject({ issues: 2, new_coverage: 75 });
  });

  it('hides branches of other organisations (404) and needs authentication (401)', async () => {
    const outsider = await createUser(h.ctx, { username: 'measures-outsider' });
    const session = await login(h.ctx, outsider.username, outsider.password);
    for (const url of [
      `/branches/${mainId}/measures`,
      `/branches/${mainId}/measures/history?metrics=issues`,
      `/branches/${mainId}/files`,
      `/branches/${mainId}/file?path=src/a.ts`,
    ]) {
      expect((await get(url, session)).statusCode, url).toBe(404);
      const anonymous = await h.ctx.app.inject({ method: 'GET', url: `/api/v0${url}` });
      expect(anonymous.statusCode, url).toBe(401);
    }
  });
  it('answers an invisible branch exactly like a missing one', async () => {
    const outsider = await createUser(h.ctx, { username: 'measures-outsider-2' });
    const session = await login(h.ctx, outsider.username, outsider.password);
    const missing = '0190a0a0-0000-7000-8000-000000000000';
    for (const suffix of ['/measures', '/files', '/file?path=src/a.ts']) {
      const hidden = await get(`/branches/${mainId}${suffix}`, session);
      const absent = await get(`/branches/${missing}${suffix}`, session);
      expect(hidden.statusCode, suffix).toBe(404);
      expect(absent.statusCode, suffix).toBe(404);
      expect(hidden.json(), suffix).toEqual(absent.json());
    }
  });

  it('refuses project analysis tokens, whichever project they belong to', async () => {
    const other = await h.project('measures/other');
    for (const token of [p.token, other.token]) {
      const res = await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/branches/${mainId}/measures`,
        headers: bearer(token),
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().code).toBe('TOKEN_NOT_ALLOWED');
    }
  });

  it('validates the file path, the metric list and the page size', async () => {
    for (const url of [
      `/branches/${mainId}/file?path=../etc/passwd`,
      `/branches/${mainId}/file?path=/etc/passwd`,
      `/branches/${mainId}/file`,
      `/branches/${mainId}/measures?metrics=`,
      `/branches/${mainId}/measures?metrics=${'coverage,'.repeat(300)}`,
      `/branches/${mainId}/measures/history?metrics=${[
        'issues',
        'new_issues',
        'coverage',
        'new_coverage',
        'lines',
        'new_lines',
        'ncloc',
        'files',
        'complexity',
        'cognitive_complexity',
        'functions',
        'classes',
        'statements',
        'comment_lines',
        'high_issues',
        'new_high_issues',
        'low_issues',
        'new_low_issues',
        'info_issues',
        'new_info_issues',
        'medium_issues',
      ].join(',')}`,
      `/branches/${mainId}/measures/history?metrics=issues&from=yesterday`,
      `/branches/${mainId}/files?limit=0`,
      `/branches/${mainId}/files?limit=501`,
      `/branches/not-a-uuid/files`,
    ]) {
      expect((await get(url)).statusCode, url).toBe(422);
    }
  });

  it('downsamples history over analyses, keeping the first and the last', async () => {
    const q = await h.project('measures/history');
    const ids: string[] = [];
    for (const day of [1, 2, 3, 4, 5]) {
      ids.push(
        await q.ingestOk(
          reportWith({
            projectKey: q.key,
            analysisDate: `2026-09-0${day}T10:00:00Z`,
            files: [file('src/a.ts')],
            findings: [],
          }),
        ),
      );
    }
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, q.id), eq(branches.isMain, true)));
    const [series] = await measureHistory(h.ctx.db, branch!.id, ['issues'], {}, 3);
    expect(series!.points.map((pt) => pt.analysisId)).toEqual([ids[0], ids[2], ids[4]]);
    const [ranged] = await measureHistory(
      h.ctx.db,
      branch!.id,
      ['issues'],
      { from: new Date('2026-09-02T00:00:00Z'), to: new Date('2026-09-04T23:00:00Z') },
      2,
    );
    expect(ranged!.points.map((pt) => pt.analysisId)).toEqual([ids[1], ids[3]]);
  });

  it('downsamples in SQL to exactly the points downsample() keeps', async () => {
    const q = await h.project('measures/long-history');
    const last = await q.ingestOk(
      reportWith({ projectKey: q.key, files: [file('src/a.ts')], findings: [] }),
    );
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, q.id), eq(branches.isMain, true)));
    const N = 1_500;
    // Pairs of analyses share a date, so the (date, id) tie-break is exercised too.
    const rows = Array.from({ length: N }, (_, i) => ({
      projectId: q.id,
      branchId: branch!.id,
      status: 'succeeded' as const,
      revision: 'a'.repeat(40),
      baselineStatus: 'ok' as const,
      scannerVersion: '0.1.0',
      analysisDate: new Date(Date.UTC(2026, 0, 1, 0, Math.floor(i / 2))),
    }));
    const inserted = await h.ctx.db
      .insert(analyses)
      .values(rows)
      .returning({ id: analyses.id, date: analyses.analysisDate });
    inserted.sort((a, b) => a.date!.getTime() - b.date!.getTime() || (a.id < b.id ? -1 : 1));
    await h.ctx.db.insert(measures).values(
      inserted.map((r) => ({
        analysisId: r.id,
        metricKey: 'issues',
        scope: 'overall' as const,
        value: 1,
      })),
    );
    const all = [...inserted.map((r) => r.id), last];
    for (const max of [1, 2, 3, 7, 10, 999, 1_000, 1_001, 1_500, 1_501, 1_502]) {
      const [series] = await measureHistory(h.ctx.db, branch!.id, ['issues'], {}, max);
      expect(
        series!.points.map((pt) => pt.analysisId),
        `max ${max}`,
      ).toEqual(downsample(all, max));
    }
  });

  it('lists directories and files whose names are outside the BMP', async () => {
    const q = await h.project('measures/emoji');
    await q.ingestOk(
      reportWith({
        projectKey: q.key,
        files: [
          file('📁docs/a.ts', { lines: 10 }),
          file('📁docs/sub/b.ts', { lines: 20 }),
          file('z.ts', { lines: 5 }),
        ],
        findings: [finding({ path: '📁docs/a.ts', line: 2 })],
      }),
    );
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, q.id), eq(branches.isMain, true)));
    const root = (await get(`/branches/${branch!.id}/files`)).json();
    expect(root.items.map((i: { name: string }) => i.name)).toEqual(['z.ts', '📁docs']);
    const res = await get(`/branches/${branch!.id}/files?dir=${encodeURIComponent('📁docs')}`);
    expect(res.statusCode).toBe(200);
    expect(res.json().items).toMatchObject([
      { type: 'file', name: 'a.ts', path: '📁docs/a.ts', measures: { lines: 10, issues: 1 } },
      { type: 'dir', name: 'sub', path: '📁docs/sub', measures: { lines: 20, issues: 0 } },
    ]);
  });

  it('says when the stored duplication detail of a file was cut', async () => {
    const q = await h.project('measures/dup-truncated');
    const groups = Array.from({ length: MAX_FILE_DUPLICATIONS + 1 }, (_, i) => ({
      blocks: [
        { path: 'src/a.ts', startLine: i + 1, endLine: i + 1 },
        { path: 'src/b.ts', startLine: i + 1, endLine: i + 1 },
      ],
    }));
    await q.ingestOk(
      reportWith({
        projectKey: q.key,
        files: [file('src/a.ts', { lines: 2_000 }), file('src/b.ts', { lines: 2_000 })],
        findings: [],
        duplications: groups,
      }),
    );
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, q.id), eq(branches.isMain, true)));
    const body = (await get(`/branches/${branch!.id}/file?path=src/a.ts`)).json();
    expect(body.duplications).toHaveLength(MAX_FILE_DUPLICATIONS);
    expect(body.duplications[0]).toEqual({
      startLine: 1,
      endLine: 1,
      others: [{ path: 'src/b.ts', startLine: 1, endLine: 1 }],
      othersTotal: 1,
    });
    expect(body).toMatchObject({
      duplicationsTruncated: true,
      measures: { duplicated_lines: MAX_FILE_DUPLICATIONS + 1 },
    });
  });
});
