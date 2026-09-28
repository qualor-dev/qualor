import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { qualityProfiles, rules } from '../db/schema';
import { MAX_PROFILES_PER_ORGANIZATION, MAX_RULES_PER_PROFILE } from './profiles';

/** E1 wave: resource bounds on profiles and on the rules ruling X5 lets a PUT create. */
describe('profile and profile-rule bounds', () => {
  let h: IngestHarness;
  const call = (method: 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const createProfile = (name: string) =>
    call('POST', '/quality-profiles', {
      organizationId: h.organizationId,
      name,
      language: '*',
    });
  const created = async (name: string) => {
    const res = await createProfile(name);
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const setRule = (profileId: string, key: string, active = true) =>
    call('PUT', `/quality-profiles/${profileId}/rules/${encodeURIComponent(key)}`, { active });
  const unsetRule = (profileId: string, key: string) =>
    call('DELETE', `/quality-profiles/${profileId}/rules/${encodeURIComponent(key)}`);
  const ruleExists = async (key: string) =>
    (await h.ctx.db.select({ id: rules.id }).from(rules).where(eq(rules.key, key))).length === 1;
  const profileCount = async () =>
    (
      await h.ctx.db
        .select({ id: qualityProfiles.id })
        .from(qualityProfiles)
        .where(eq(qualityProfiles.organizationId, h.organizationId))
    ).length;

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('removes a rule a PUT created once no profile sets it and nothing else refers to it', async () => {
    const a = await created('Bounds A');
    const b = await created('Bounds B');
    expect((await setRule(a, 'semgrep:made-by-put')).statusCode).toBe(200);
    expect((await setRule(b, 'semgrep:made-by-put', false)).statusCode).toBe(200);
    expect(await ruleExists('semgrep:made-by-put')).toBe(true);
    // Still set in B: kept.
    expect((await unsetRule(a, 'semgrep:made-by-put')).statusCode).toBe(204);
    expect(await ruleExists('semgrep:made-by-put')).toBe(true);
    // The last setting goes: the bare rule goes with it.
    expect((await unsetRule(b, 'semgrep:made-by-put')).statusCode).toBe(204);
    expect(await ruleExists('semgrep:made-by-put')).toBe(false);

    // A rule with issues, or with metadata from a report, stays.
    const project = await h.project('acme/bounds');
    const branchId = await mainBranchId(h.ctx.db, project.id);
    const withIssue = await seedRule(h.ctx.db, { key: 'semgrep:has-issue', name: 'has-issue' });
    await seedIssue(h.ctx.db, { projectId: project.id, branchId, ruleId: withIssue });
    await seedRule(h.ctx.db, { key: 'semgrep:has-metadata', cwe: [79] });
    for (const key of ['semgrep:has-issue', 'semgrep:has-metadata']) {
      expect((await setRule(a, key)).statusCode).toBe(200);
      expect((await unsetRule(a, key)).statusCode).toBe(204);
      expect(await ruleExists(key), key).toBe(true);
    }

    // Deleting a profile removes the bare rules only it set.
    expect((await setRule(a, 'semgrep:only-in-a')).statusCode).toBe(200);
    expect((await setRule(a, 'semgrep:also-in-b')).statusCode).toBe(200);
    expect((await setRule(b, 'semgrep:also-in-b')).statusCode).toBe(200);
    expect((await call('DELETE', `/quality-profiles/${a}`)).statusCode).toBe(204);
    expect(await ruleExists('semgrep:only-in-a')).toBe(false);
    expect(await ruleExists('semgrep:also-in-b')).toBe(true);
    expect(await ruleExists('semgrep:has-issue')).toBe(true);
  });

  it(`sets at most ${MAX_RULES_PER_PROFILE} rules per profile (409 PROFILE_RULE_LIMIT_REACHED)`, async () => {
    const full = await created('Bounds full');
    // Fill the profile to the bound directly (bulk SQL, not 10 000 requests).
    await h.ctx.db.execute(sql`
      WITH made AS (
        INSERT INTO rules (id, key, engine_id, engine_rule_id, name, default_severity, quality, kind, origin)
        SELECT gen_random_uuid(), 'semgrep:bulk-' || n, 'semgrep', 'bulk-' || n, 'bulk-' || n,
               'medium', 'maintainability', 'issue', 'reported'
          FROM generate_series(1, ${MAX_RULES_PER_PROFILE}) AS n
        RETURNING id)
      INSERT INTO profile_rules (profile_id, rule_id, active)
      SELECT ${full}::uuid, id, true FROM made`);
    const refused = await setRule(full, 'semgrep:one-too-many');
    expect(refused.statusCode, refused.body).toBe(409);
    expect(refused.json()).toMatchObject({ code: 'PROFILE_RULE_LIMIT_REACHED' });
    // Refused before anything was created.
    expect(await ruleExists('semgrep:one-too-many')).toBe(false);
    // A rule already set can still be changed.
    expect((await setRule(full, 'semgrep:bulk-1', false)).statusCode).toBe(200);
  });

  it(`keeps at most ${MAX_PROFILES_PER_ORGANIZATION} profiles per organisation (409 PROFILE_LIMIT_REACHED), under concurrency too`, async () => {
    const existing = await profileCount();
    for (let i = existing; i < MAX_PROFILES_PER_ORGANIZATION - 1; i++) {
      await h.ctx.db
        .insert(qualityProfiles)
        .values({ organizationId: h.organizationId, name: `Filler ${i}`, language: '*' });
    }
    // One place left, two requests at once: exactly one gets it.
    const racing = await Promise.all([createProfile('Race 1'), createProfile('Race 2')]);
    expect(racing.map((r) => r.statusCode).sort()).toEqual([201, 409]);
    const loser = racing.find((r) => r.statusCode === 409)!;
    expect(loser.json()).toMatchObject({ code: 'PROFILE_LIMIT_REACHED' });
    expect(await profileCount()).toBe(MAX_PROFILES_PER_ORGANIZATION);
    // A copy is a new profile too.
    const [any] = await h.ctx.db
      .select({ id: qualityProfiles.id })
      .from(qualityProfiles)
      .where(eq(qualityProfiles.organizationId, h.organizationId))
      .limit(1);
    const copy = await call('POST', `/quality-profiles/${any!.id}/copy`, { name: 'One more' });
    expect(copy.statusCode, copy.body).toBe(409);
    expect(copy.json()).toMatchObject({ code: 'PROFILE_LIMIT_REACHED' });
  });
});
