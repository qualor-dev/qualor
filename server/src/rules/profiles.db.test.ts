import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { seedRule } from '../../test/issues';
import * as schema from '../db/schema';
import { profileRules, projectProfiles, qualityProfiles } from '../db/schema';
import { loadProfileSet, ruleSetting } from './profiles';

describe('loadProfileSet reads one snapshot (E1 wave)', () => {
  let h: IngestHarness;
  let project: { id: string; organizationId: string };
  let ruleId: string;
  let otherRuleId: string;
  let childId: string;

  beforeAll(async () => {
    h = await createIngestHarness();
    const created = await h.project('acme/profiles-snapshot');
    project = { id: created.id, organizationId: h.organizationId };
    const db = h.ctx.db;
    ruleId = await seedRule(db, { key: 'semgrep:snapshot-rule' });
    otherRuleId = await seedRule(db, { key: 'semgrep:snapshot-other' });
    const [builtin] = await db
      .select()
      .from(qualityProfiles)
      .where(
        and(
          eq(qualityProfiles.organizationId, h.organizationId),
          eq(qualityProfiles.language, '*'),
          eq(qualityProfiles.isDefault, true),
        ),
      );
    // The project uses a child of the default `*` profile that silences one rule, and the
    // parent raises another's severity.
    const [child] = await db
      .insert(qualityProfiles)
      .values({
        organizationId: h.organizationId,
        name: 'Snapshot child',
        language: '*',
        parentId: builtin!.id,
        unknownRules: 'activate',
      })
      .returning();
    childId = child!.id;
    await db.insert(profileRules).values([
      { profileId: childId, ruleId, active: false },
      { profileId: builtin!.id, ruleId: otherRuleId, active: true, severityOverride: 'high' },
    ]);
    await db
      .insert(projectProfiles)
      .values({ projectId: project.id, language: '*', profileId: childId });
  });
  afterAll(async () => {
    await h.close();
  });

  it('is a single statement with the same result', async () => {
    const statements: string[] = [];
    const logged = drizzle({
      client: h.ctx.database.pool,
      schema,
      logger: { logQuery: (query) => void statements.push(query) },
    });
    const set = await loadProfileSet(logged, project, [ruleId, otherRuleId]);
    expect(statements).toHaveLength(1);
    expect(set.chains.get('*')!.profileIds[0]).toBe(childId);
    expect(set.chains.get('*')!.profileIds).toHaveLength(2);
    expect(ruleSetting(set, '*', ruleId)).toEqual({ active: false, severityOverride: null });
    expect(ruleSetting(set, '*', otherRuleId)).toEqual({ active: true, severityOverride: 'high' });
    // Without rules to ask about, still one statement and no settings.
    statements.length = 0;
    const bare = await loadProfileSet(logged, project, []);
    expect(statements).toHaveLength(1);
    expect(bare.settings.size).toBe(0);
    expect(bare.chains.get('*')!.profileIds[0]).toBe(childId);
  });
});
