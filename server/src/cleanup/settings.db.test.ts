import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { checkViolation, PG_NOT_NULL_VIOLATION, refusal } from '../../test/refusals';
import { instanceSettings, projects } from '../db/schema';
import { CLEANUP_SETTINGS_KEY, readCleanupDefaults, writeCleanupDefaults } from './settings';

describe('the cleanup columns of projects (migration 0038_branch_cleanup)', () => {
  let t: TestDatabase;
  let org: string;
  let n = 0;

  /** A new project's id, its cleanup columns set to `values` (raw SQL: what the column types allow). */
  const insert = (values: { branches?: unknown; mergeRequests?: unknown; keep?: unknown } = {}) => {
    const id = randomUUID();
    const columns = ['id', 'organization_id', 'key', 'name'];
    const params: unknown[] = [id, org, `cleanup/schema-${++n}`, 'P'];
    if ('branches' in values) {
      columns.push('cleanup_branches_days');
      params.push(values.branches);
    }
    if ('mergeRequests' in values) {
      columns.push('cleanup_merge_requests_days');
      params.push(values.mergeRequests);
    }
    if ('keep' in values) {
      columns.push('cleanup_keep_branches');
      params.push(values.keep);
    }
    const placeholders = params.map((_, i) => `$${i + 1}`).join(', ');
    return t.pool
      .query(`INSERT INTO projects (${columns.join(', ')}) VALUES (${placeholders})`, params)
      .then(() => id);
  };

  beforeAll(async () => {
    t = await createTestDatabase();
    org = randomUUID();
    await t.pool.query(
      `INSERT INTO organizations (id, key, name) VALUES ($1, 'cleanup-schema', 'C')`,
      [org],
    );
  });
  afterAll(async () => {
    await t.close();
  });

  it('gives a new project no rule of its own and no keep patterns', async () => {
    const id = await insert();
    const [row] = await t.db.select().from(projects).where(eq(projects.id, id));
    expect(row).toMatchObject({
      cleanupBranchesDays: null,
      cleanupMergeRequestsDays: null,
      cleanupKeepBranches: [],
    });
  });

  it('takes NULL (the server default), 0 (off) and 1 to 3650 days in either column', async () => {
    for (const days of [null, 0, 1, 30, 3650]) {
      expect(await refusal(insert({ branches: days })), String(days)).toBeNull();
      expect(await refusal(insert({ mergeRequests: days })), String(days)).toBeNull();
    }
  });

  it('refuses a negative day count and more than 3650 days', async () => {
    for (const days of [-1, 3651]) {
      expect(await refusal(insert({ branches: days })), String(days)).toEqual(
        checkViolation('projects_cleanup_branches_days_check'),
      );
      expect(await refusal(insert({ mergeRequests: days })), String(days)).toEqual(
        checkViolation('projects_cleanup_merge_requests_days_check'),
      );
    }
  });

  it('takes 20 keep patterns and refuses 21', async () => {
    const patterns = (count: number) => Array.from({ length: count }, (_, i) => `keep/${i}`);
    expect(await refusal(insert({ keep: patterns(20) }))).toBeNull();
    expect(await refusal(insert({ keep: patterns(21) }))).toEqual(
      checkViolation('projects_cleanup_keep_branches_check'),
    );
  });

  it('refuses NULL keep patterns', async () => {
    expect((await refusal(insert({ keep: null })))?.code).toBe(PG_NOT_NULL_VIOLATION);
  });
});

describe('the server defaults of the cleanup (instance_settings `cleanup`)', () => {
  let t: TestDatabase;

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  afterEach(async () => {
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, CLEANUP_SETTINGS_KEY));
  });
  afterAll(async () => {
    await t.close();
  });

  const store = (value: unknown) =>
    t.db.insert(instanceSettings).values({ key: CLEANUP_SETTINGS_KEY, value });

  it('is off for both rules while the row is absent', async () => {
    expect(await readCleanupDefaults(t.db)).toEqual({
      branchesDays: null,
      mergeRequestsDays: null,
    });
  });

  it('reads what was written, and a second write replaces it', async () => {
    await writeCleanupDefaults(t.db, { branchesDays: 30, mergeRequestsDays: null });
    expect(await readCleanupDefaults(t.db)).toEqual({ branchesDays: 30, mergeRequestsDays: null });
    await writeCleanupDefaults(t.db, { branchesDays: null, mergeRequestsDays: 3650 });
    expect(await readCleanupDefaults(t.db)).toEqual({
      branchesDays: null,
      mergeRequestsDays: 3650,
    });
  });

  it.each([
    ['a day count of 0', { branchesDays: 0, mergeRequestsDays: null }],
    ['more than 3650 days', { branchesDays: 30, mergeRequestsDays: 3651 }],
    ['days as text', { branchesDays: '30', mergeRequestsDays: null }],
    ['a field missing', { branchesDays: 30 }],
    ['not an object', [30, 60]],
  ])('is off for both rules when the stored row holds %s', async (_name, value) => {
    await store(value);
    expect(await readCleanupDefaults(t.db)).toEqual({
      branchesDays: null,
      mergeRequestsDays: null,
    });
  });
});
