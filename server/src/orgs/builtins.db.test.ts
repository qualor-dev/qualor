import { and, asc, eq } from 'drizzle-orm';
import { QUALOR_WAY_GATE } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { bootstrap } from '../auth/bootstrap';
import { gateConditions, organizations, qualityGates, qualityProfiles, users } from '../db/schema';
import { BUILTIN_NAME, ensureBuiltins, PROFILE_LANGUAGES } from './builtins';
import { createOrganization } from './service';

const admin = { username: 'admin', password: 'correct horse battery staple' };

describe('built-in profiles and gate (data-model.md §4.4, gates.md §7)', () => {
  let t: TestDatabase;
  let adminId: string;
  const orgId = async (key: string) =>
    (await t.db.select().from(organizations).where(eq(organizations.key, key)))[0]!.id;
  const profilesOf = (organizationId: string) =>
    t.db
      .select()
      .from(qualityProfiles)
      .where(eq(qualityProfiles.organizationId, organizationId))
      .orderBy(asc(qualityProfiles.language), asc(qualityProfiles.name));
  const gatesOf = (organizationId: string) =>
    t.db
      .select()
      .from(qualityGates)
      .where(eq(qualityGates.organizationId, organizationId))
      .orderBy(asc(qualityGates.name));

  beforeAll(async () => {
    t = await createTestDatabase();
    await bootstrap(t.db, admin);
    adminId = (await t.db.select().from(users))[0]!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('bootstrap gives the default organisation a default built-in profile per language and the Qualor way gate', async () => {
    const org = await orgId('default');
    const profiles = await profilesOf(org);
    expect(profiles.map((p) => p.language).sort()).toEqual([...PROFILE_LANGUAGES].sort());
    for (const p of profiles) {
      expect(p).toMatchObject({
        name: BUILTIN_NAME,
        isBuiltin: true,
        isDefault: true,
        unknownRules: 'activate',
        parentId: null,
      });
    }
    const [gate, ...others] = await gatesOf(org);
    expect(others).toEqual([]);
    expect(gate).toMatchObject({ name: BUILTIN_NAME, isBuiltin: true, isDefault: true });
    const conditions = await t.db
      .select()
      .from(gateConditions)
      .where(eq(gateConditions.gateId, gate!.id))
      .orderBy(asc(gateConditions.metricKey));
    expect(
      conditions.map((c) => ({
        metric: c.metricKey,
        operator: c.operator,
        threshold: c.threshold,
      })),
    ).toEqual([...QUALOR_WAY_GATE.conditions].sort((a, b) => a.metric.localeCompare(b.metric)));
  });

  it('is idempotent: another boot creates nothing new', async () => {
    const org = await orgId('default');
    const before = [(await profilesOf(org)).length, (await gatesOf(org)).length];
    await bootstrap(t.db, admin);
    expect(await ensureBuiltins(t.db, org)).toEqual({ createdProfiles: 0, createdGate: false });
    expect([(await profilesOf(org)).length, (await gatesOf(org)).length]).toEqual(before);
  });

  it('seeds a new organisation in the same transaction that creates it', async () => {
    const org = await createOrganization(t.db, {
      key: 'second',
      name: 'Second',
      creatorId: adminId,
    });
    expect((await profilesOf(org.id)).filter((p) => p.isBuiltin && p.isDefault)).toHaveLength(
      PROFILE_LANGUAGES.length,
    );
    expect(await gatesOf(org.id)).toMatchObject([{ isBuiltin: true, isDefault: true }]);
  });

  it('never takes the default back from a gate or profile an admin chose', async () => {
    const org = await orgId('second');
    await t.db
      .update(qualityGates)
      .set({ isDefault: false })
      .where(eq(qualityGates.organizationId, org));
    await t.db
      .insert(qualityGates)
      .values({ organizationId: org, name: 'Strict', isDefault: true });
    await t.db
      .update(qualityProfiles)
      .set({ isDefault: false })
      .where(and(eq(qualityProfiles.organizationId, org), eq(qualityProfiles.language, 'java')));
    await t.db
      .insert(qualityProfiles)
      .values({ organizationId: org, name: 'Team Java', language: 'java', isDefault: true });
    await bootstrap(t.db, admin);
    expect((await gatesOf(org)).map((g) => [g.name, g.isDefault])).toEqual([
      [BUILTIN_NAME, false],
      ['Strict', true],
    ]);
    const java = (await profilesOf(org)).filter((p) => p.language === 'java');
    expect(java.map((p) => [p.name, p.isDefault])).toEqual([
      [BUILTIN_NAME, false],
      ['Team Java', true],
    ]);
  });

  it('back-fills organisations that predate the built-ins on the next boot', async () => {
    const [legacy] = await t.db
      .insert(organizations)
      .values({ key: 'legacy', name: 'Legacy' })
      .returning();
    expect(await profilesOf(legacy!.id)).toEqual([]);
    await bootstrap(t.db, admin);
    expect(await profilesOf(legacy!.id)).toHaveLength(PROFILE_LANGUAGES.length);
    expect(await gatesOf(legacy!.id)).toMatchObject([{ isBuiltin: true, isDefault: true }]);
  });

  it('adds the csharp built-in to an organisation that has every other built-in (plan 2D, no migration)', async () => {
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'pre-csharp', name: 'Before C#' })
      .returning();
    for (const language of ['typescript', 'javascript', 'java', '*']) {
      await t.db.insert(qualityProfiles).values({
        organizationId: org!.id,
        name: BUILTIN_NAME,
        language,
        isBuiltin: true,
        isDefault: true,
        unknownRules: 'activate',
      });
    }
    await bootstrap(t.db, admin);
    const csharp = (await profilesOf(org!.id)).filter((p) => p.language === 'csharp');
    expect(csharp).toMatchObject([{ name: BUILTIN_NAME, isBuiltin: true, isDefault: true }]);
  });
});
