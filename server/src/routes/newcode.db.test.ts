import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith } from '../../test/reports';
import { analyses, projects, type NewCodeDefinition } from '../db/schema';

const DAY = 86_400_000;

describe('GET /projects/new-code-baseline (gates.md §5, server step 9)', () => {
  let h: IngestHarness;
  let dbNow: number;
  let n = 0;
  const revision = () => (++n).toString(16).padStart(40, 'a');
  /** Ingests a main-branch analysis dated `daysAgo` before the database's now(). */
  const analyse = (p: IngestProject, daysAgo: number, version?: string) => {
    const rev = revision();
    return p
      .ingestOk(
        reportWith({
          projectKey: p.key,
          revision: rev,
          analysisDate: new Date(dbNow - daysAgo * DAY).toISOString(),
          ...(version === undefined ? {} : { version }),
        }),
      )
      .then((id) => ({ id, revision: rev }));
  };
  /** Like analyse, for an untagged commit: the analysis has no version label (sampleReport sets one). */
  const analyseUnlabelled = async (p: IngestProject, daysAgo: number) => {
    const done = await analyse(p, daysAgo);
    await h.ctx.db.update(analyses).set({ versionLabel: null }).where(eq(analyses.id, done.id));
    return done;
  };
  const get = (p: IngestProject, query: string, headers = bearer(p.token)) =>
    h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/new-code-baseline?${query}`,
      headers,
    });
  const baseline = async (p: IngestProject, extra = '') => {
    const res = await get(p, `projectKey=${encodeURIComponent(p.key)}&branch=main${extra}`);
    expect(res.statusCode).toBe(200);
    return res.json();
  };
  const define = (p: IngestProject, definition: NewCodeDefinition) =>
    h.ctx.db.update(projects).set({ newCodeDefinition: definition }).where(eq(projects.id, p.id));

  beforeAll(async () => {
    h = await createIngestHarness();
    const result = await h.ctx.db.execute<{ now: Date }>(sql`SELECT now() AS now`);
    dbNow = new Date(result.rows[0]!.now).getTime();
  });
  afterAll(async () => {
    await h.close();
  });

  it('returns no revision before the first analysis, with the default definition', async () => {
    const p = await h.project('baseline/first');
    expect(await baseline(p)).toEqual({
      revision: null,
      analysisId: null,
      analysisDate: null,
      definition: { type: 'days', value: 30 },
      warnings: [],
    });
  });

  it('days: 30 with analyses on days -40, -31, -29 and -1 picks day -29 (gates.md §9.3)', async () => {
    const p = await h.project('baseline/days');
    await analyse(p, 40);
    await analyse(p, 31);
    const expected = await analyse(p, 29);
    await analyse(p, 1);
    expect(await baseline(p)).toMatchObject({
      revision: expected.revision,
      analysisId: expected.id,
      definition: { type: 'days', value: 30 },
    });
  });

  it('days: N with every analysis older than N days picks the most recent one (ruling N1)', async () => {
    const p = await h.project('baseline/old');
    await analyse(p, 90);
    const latest = await analyse(p, 60);
    expect((await baseline(p)).analysisId).toBe(latest.id);
  });

  it('previous_version picks the most recent analysis of another version', async () => {
    const p = await h.project('baseline/version');
    await define(p, { type: 'previous_version' });
    await analyse(p, 20, '1.0');
    const last10 = await analyse(p, 10, '1.0');
    const v11 = await analyse(p, 5, '1.1');
    expect((await baseline(p)).analysisId).toBe(last10.id);
    expect((await baseline(p, '&version=1.1')).analysisId).toBe(last10.id);
    expect((await baseline(p, '&version=1.2')).analysisId).toBe(v11.id);
  });

  it('previous_version without any version falls back to days: 30 with a warning (gates.md §9.4)', async () => {
    const p = await h.project('baseline/no-version');
    await define(p, { type: 'previous_version' });
    await analyse(p, 40);
    const within = await analyse(p, 20);
    await h.ctx.db.execute(
      sql`UPDATE analyses SET version_label = NULL WHERE project_id = ${p.id}`,
    );
    expect(await baseline(p)).toMatchObject({
      analysisId: within.id,
      definition: { type: 'previous_version' },
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
  });

  it('analysis returns that fixed analysis', async () => {
    const p = await h.project('baseline/fixed');
    const fixed = await analyse(p, 50);
    await analyse(p, 2);
    await define(p, { type: 'analysis', analysisId: fixed.id });
    expect(await baseline(p)).toMatchObject({ revision: fixed.revision, warnings: [] });
  });

  it('previous_version ignores unlabelled analyses: current is the latest label (ruling U8)', async () => {
    const p = await h.project('baseline/unlabelled');
    await define(p, { type: 'previous_version' });
    const v10 = await analyse(p, 20, '1.0');
    await analyseUnlabelled(p, 15);
    const v11 = await analyse(p, 5, '1.1');
    await analyseUnlabelled(p, 2);
    // No ?version: current is 1.1 (the latest label), so the baseline is the latest 1.0.
    expect(await baseline(p)).toMatchObject({ analysisId: v10.id, warnings: [] });
    expect(await baseline(p, '&version=1.2')).toMatchObject({ analysisId: v11.id, warnings: [] });
  });

  it('previous_version with ?version on a history without labels falls back with a warning (ruling U8)', async () => {
    const p = await h.project('baseline/unlabelled-only');
    await define(p, { type: 'previous_version' });
    await analyseUnlabelled(p, 40);
    const within = await analyseUnlabelled(p, 20);
    expect(await baseline(p, '&version=1.0')).toMatchObject({
      analysisId: within.id,
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
  });

  it('previous_version where the only label is the current one falls back with a warning (ruling U8)', async () => {
    const p = await h.project('baseline/same-version');
    await define(p, { type: 'previous_version' });
    await analyse(p, 40, '2.0');
    const within = await analyse(p, 20, '2.0');
    await analyseUnlabelled(p, 10);
    expect(await baseline(p)).toMatchObject({
      analysisId: within.id,
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
    expect((await baseline(p, '&version=2.0')).warnings).toEqual(['NEW_CODE_DEFINITION_FALLBACK']);
  });

  it('previous_version treats an empty version as no version (stored as NULL at ingest)', async () => {
    const p = await h.project('baseline/empty-version');
    await define(p, { type: 'previous_version' });
    const v10 = await analyse(p, 20, '1.0');
    const empty = await analyse(p, 10, '');
    const [row] = await h.ctx.db
      .select({ versionLabel: analyses.versionLabel })
      .from(analyses)
      .where(eq(analyses.id, empty.id));
    expect(row?.versionLabel).toBeNull();
    expect((await baseline(p, '&version=1.1')).analysisId).toBe(v10.id);
  });

  it('previous_version ignores a stored empty label like a missing one (D-M3)', async () => {
    // Ingestion stores '' as NULL, but a row written otherwise (a restore, by hand) may hold ''.
    const p = await h.project('baseline/stored-empty');
    await define(p, { type: 'previous_version' });
    await analyse(p, 40, '1.0');
    const within = await analyse(p, 20, '1.0');
    const empty = await analyse(p, 10, '1.0');
    await h.ctx.db.update(analyses).set({ versionLabel: '' }).where(eq(analyses.id, empty.id));
    // Current is 1.0 (the latest non-empty label), and '' is not "another version".
    expect(await baseline(p)).toMatchObject({
      analysisId: within.id,
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
    expect(await baseline(p, '&version=1.0')).toMatchObject({
      analysisId: within.id,
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
  });

  it('previous_version ignores failed and queued labelled analyses (D-M3)', async () => {
    const p = await h.project('baseline/not-succeeded');
    await define(p, { type: 'previous_version' });
    const failed = await analyse(p, 30, '0.9');
    const v10 = await analyse(p, 20, '1.0');
    const queued = await analyse(p, 5, '1.1');
    await h.ctx.db.update(analyses).set({ status: 'failed' }).where(eq(analyses.id, failed.id));
    await h.ctx.db.update(analyses).set({ status: 'queued' }).where(eq(analyses.id, queued.id));
    // Current is 1.0, not the queued 1.1; the failed 0.9 is no baseline.
    expect(await baseline(p)).toMatchObject({
      analysisId: v10.id,
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
    // A new version's baseline is the succeeded 1.0, not the queued 1.1.
    expect(await baseline(p, '&version=1.2')).toMatchObject({ analysisId: v10.id, warnings: [] });
  });

  it('analysis whose baseline no longer exists falls back to days: 30 with a warning (ruling N1/N2)', async () => {
    const p = await h.project('baseline/missing');
    await analyse(p, 40);
    const within = await analyse(p, 20);
    await define(p, { type: 'analysis', analysisId: '01900000-0000-7000-8000-000000000000' });
    expect(await baseline(p)).toMatchObject({
      analysisId: within.id,
      definition: { type: 'analysis' },
      warnings: ['NEW_CODE_BASELINE_MISSING'],
    });
  });

  it("ignores a fixed baseline of another project, and answers 404 to another project's token", async () => {
    const p = await h.project('baseline/scoped');
    const other = await h.project('baseline/scoped-other');
    const foreignAnalysis = await analyse(other, 5);
    await analyse(p, 3);
    await define(p, { type: 'analysis', analysisId: foreignAnalysis.id });
    // The fixed baseline must be an analysis of this project's main branch.
    expect((await baseline(p)).warnings).toEqual(['NEW_CODE_BASELINE_MISSING']);
    const res = await get(p, `projectKey=${encodeURIComponent(other.key)}&branch=main`);
    expect([res.statusCode, res.json().code]).toEqual([404, 'PROJECT_NOT_FOUND']);
  });

  it('tells an unknown project (PROJECT_NOT_FOUND) apart from a missing endpoint (NOT_FOUND)', async () => {
    const p = await h.project('baseline/codes');
    const unknown = await get(p, 'projectKey=nope&branch=main');
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json().code).toBe('PROJECT_NOT_FOUND');
    const other = await h.project('baseline/other');
    const foreign = await get(other, `projectKey=${encodeURIComponent(p.key)}&branch=main`);
    expect(foreign.json().code).toBe('PROJECT_NOT_FOUND');
    // What an older server without this route answers: the generic 404 of an unknown route.
    const missing = await h.ctx.app.inject({
      method: 'GET',
      url: '/api/v0/projects/new-code-baseline/unknown?projectKey=x&branch=main',
      headers: bearer(p.token),
    });
    expect([missing.statusCode, missing.json().code]).toEqual([404, 'NOT_FOUND']);
  });

  it('answers 404 PROJECT_NOT_FOUND, not 403, to a user outside the organisation', async () => {
    const p = await h.project('baseline/outsider');
    const outsider = await createUser(h.ctx, { username: 'baseline-outsider' });
    const session = await login(h.ctx, outsider.username, outsider.password);
    const res = await get(
      p,
      `projectKey=${encodeURIComponent(p.key)}&branch=main`,
      session.headers,
    );
    expect([res.statusCode, res.json().code]).toEqual([404, 'PROJECT_NOT_FOUND']);
  });

  it('refuses a branch other than the main branch with 409 NOT_MAIN_BRANCH', async () => {
    const p = await h.project('baseline/branch');
    const res = await get(p, `projectKey=${encodeURIComponent(p.key)}&branch=develop`);
    expect([res.statusCode, res.json().code]).toEqual([409, 'NOT_MAIN_BRANCH']);
  });

  it('needs analysis:write: 401 anonymous, 403 for a read-only token, 200 for a member session', async () => {
    const p = await h.project('baseline/auth');
    const query = `projectKey=${encodeURIComponent(p.key)}&branch=main`;
    expect((await get(p, query, {})).statusCode).toBe(401);
    const member = await createUser(h.ctx, { username: 'baseline-member' });
    await addMember(h.ctx, h.organizationId, member.id, 'member');
    const session = await login(h.ctx, member.username, member.password);
    expect((await get(p, query, session.headers)).statusCode).toBe(200);
    const pat = (
      await h.ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: { name: 'read', scopes: ['read'] },
      })
    ).json().token as string;
    const res = await get(p, query, bearer(pat));
    expect([res.statusCode, res.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
  });

  it('validates the query: 422 with errors[].path', async () => {
    const p = await h.project('baseline/validation');
    const res = await get(p, 'branch=main');
    expect(res.statusCode).toBe(422);
    expect(res.json().errors).toContainEqual(expect.objectContaining({ path: 'query.projectKey' }));
  });
});
