import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';
import { MIGRATIONS_DIR } from '../../test/paths';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION } from './errors';
import { pendingMigrations } from './migrate';
import {
  analyses,
  apiTokens,
  branches,
  issues,
  jobs,
  organizations,
  projects,
  rules,
  users,
} from './schema';

const TABLES = [
  'analyses',
  'analysis_reports',
  'api_tokens',
  'audit_events',
  'branch_files',
  'branches',
  'gate_conditions',
  'identities',
  'instance_settings',
  'issue_changes',
  'issues',
  'jobs',
  'llm_requests',
  'measures',
  'memberships',
  'organizations',
  'profile_rules',
  'project_memberships',
  'project_profiles',
  'projects',
  'quality_gates',
  'quality_profiles',
  'rules',
  'scim_group_members',
  'scim_groups',
  'scim_tokens',
  'scm_connections',
  'sessions',
  'sso_connections',
  'sso_group_mappings',
  'sso_states',
  'users',
  'webhook_deliveries',
  'webhook_subscriptions',
];

describe('first migration (data-model.md §4)', () => {
  let t: TestDatabase;
  let projectId: string;

  beforeAll(async () => {
    t = await createTestDatabase();
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: org!.id, key: 'acme/api', name: 'API' })
      .returning();
    projectId = project!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('leaves no pending migrations', async () => {
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
  });

  it('creates exactly the tables of the data model', async () => {
    const result = await t.db.execute<{ table_name: string }>(
      sql`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    expect(result.rows.map((r) => r.table_name).sort()).toEqual([...TABLES].sort());
  });

  it('enables citext and pg_trgm', async () => {
    const result = await t.db.execute<{ extname: string }>(
      sql`SELECT extname FROM pg_extension WHERE extname IN ('citext','pg_trgm')`,
    );
    expect(result.rows.map((r) => r.extname).sort()).toEqual(['citext', 'pg_trgm']);
  });

  it('backs every foreign key with an index whose leading columns are the FK columns', async () => {
    // Without one, every DELETE/UPDATE of a referenced row (cascade, SET NULL, RESTRICT check)
    // scans the referencing table. A partial index counts only when its predicate is
    // `<fk column> IS NOT NULL` (any other predicate, e.g. `WHERE is_default`, misses rows).
    const result = await t.db.execute<{ fk: string }>(sql`
      SELECT c.conrelid::regclass::text || '(' || c.conname || ')' AS fk
      FROM pg_constraint c
      WHERE c.contype = 'f'
        AND c.connamespace = 'public'::regnamespace
        AND NOT EXISTS (
          SELECT 1 FROM pg_index i
          WHERE i.indrelid = c.conrelid
            AND (string_to_array(i.indkey::text, ' ')::int2[])[1:cardinality(c.conkey)] @> c.conkey
            AND (string_to_array(i.indkey::text, ' ')::int2[])[1:cardinality(c.conkey)] <@ c.conkey
            AND (
              i.indpred IS NULL
              OR pg_get_expr(i.indpred, i.indrelid) = format(
                '(%s IS NOT NULL)',
                (SELECT a.attname FROM pg_attribute a
                 WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[1])
              )
            )
        )
      ORDER BY 1`);
    expect(result.rows.map((r) => r.fk)).toEqual([]);
  });

  it('gives the mutable tables analyses and api_tokens an updated_at column (§2)', async () => {
    const result = await t.db.execute<{ table_name: string }>(sql`
      SELECT table_name FROM information_schema.columns
      WHERE table_schema = 'public' AND column_name = 'updated_at'
        AND table_name IN ('analyses', 'api_tokens')`);
    expect(result.rows.map((r) => r.table_name).sort()).toEqual(['analyses', 'api_tokens']);
  });

  it('compares usernames case-insensitively', async () => {
    await t.db.insert(users).values({ username: 'Alice' });
    await expectPgError(t.db.insert(users).values({ username: 'alice' }), PG_UNIQUE_VIOLATION);
    const [found] = await t.db.select().from(users).where(eq(users.username, 'ALICE'));
    expect(found?.username).toBe('Alice');
  });

  it('allows one main branch per project and unique (project, kind, name)', async () => {
    await t.db.insert(branches).values({ projectId, kind: 'branch', name: 'main', isMain: true });
    await expectPgError(
      t.db.insert(branches).values({ projectId, kind: 'branch', name: 'trunk', isMain: true }),
      PG_UNIQUE_VIOLATION,
    );
    await expectPgError(
      t.db.insert(branches).values({ projectId, kind: 'branch', name: 'main' }),
      PG_UNIQUE_VIOLATION,
    );
    await expectPgError(
      t.db.insert(branches).values({ projectId, kind: 'merge_request', name: '7', isMain: true }),
      PG_CHECK_VIOLATION,
    );
  });

  it('enforces the api_tokens kind and scope invariants', async () => {
    const [user] = await t.db.insert(users).values({ username: 'token-owner' }).returning();
    const base = { name: 'x', secretHash: Buffer.alloc(32) };
    await expectPgError(
      t.db.insert(apiTokens).values({
        ...base,
        kind: 'project',
        projectId,
        userId: user!.id,
        prefix: 'qlr_prj_abcd',
        scopes: ['analysis:write'],
      }),
      PG_CHECK_VIOLATION,
    );
    await expectPgError(
      t.db
        .insert(apiTokens)
        .values({ ...base, kind: 'project', projectId, prefix: 'qlr_prj_abcd', scopes: ['read'] }),
      PG_CHECK_VIOLATION,
    );
    await expectPgError(
      t.db
        .insert(apiTokens)
        .values({ ...base, kind: 'personal', prefix: 'qlr_pat_abcd', scopes: ['read'] }),
      PG_CHECK_VIOLATION,
    );
  });

  it('rejects unknown enumeration values and incomplete succeeded analyses', async () => {
    await expectPgError(
      t.db.execute(
        sql`INSERT INTO analyses (id, project_id, status) VALUES (gen_random_uuid(), ${projectId}, 'bogus')`,
      ),
      PG_CHECK_VIOLATION,
    );
    await expectPgError(
      t.db.execute(
        sql`INSERT INTO analyses (id, project_id, status) VALUES (gen_random_uuid(), ${projectId}, 'succeeded')`,
      ),
      PG_CHECK_VIOLATION,
    );
    await expectPgError(
      t.db.execute(
        sql`INSERT INTO analyses (id, project_id, revision) VALUES (gen_random_uuid(), ${projectId}, 'HEAD')`,
      ),
      PG_CHECK_VIOLATION,
    );
  });

  it('requires scanner_version for a succeeded analysis (ruling R4)', async () => {
    const [branch] = await t.db
      .insert(branches)
      .values({ projectId, kind: 'branch', name: 'scanner-version-test' })
      .returning();
    const complete = {
      projectId,
      branchId: branch!.id,
      revision: 'a'.repeat(40),
      analysisDate: new Date(),
      baselineStatus: 'first_analysis' as const,
      status: 'succeeded' as const,
    };
    await expectPgError(
      t.db.insert(analyses).values({ ...complete, scannerVersion: null }),
      PG_CHECK_VIOLATION,
    );
    const [analysis] = await t.db
      .insert(analyses)
      .values({ ...complete, scannerVersion: '1.2.3' })
      .returning();
    expect(analysis?.scannerVersion).toBe('1.2.3');
  });

  it('allows at most one running job per concurrency key', async () => {
    await t.db
      .insert(jobs)
      .values({ queue: 'q', payload: {}, concurrencyKey: 'k', status: 'running' });
    await t.db
      .insert(jobs)
      .values({ queue: 'q', payload: {}, concurrencyKey: 'k', status: 'queued' });
    await expectPgError(
      t.db.insert(jobs).values({ queue: 'q', payload: {}, concurrencyKey: 'k', status: 'running' }),
      PG_UNIQUE_VIOLATION,
    );
  });

  it('derives issues.severity_rank from severity (ruling R6)', async () => {
    const [branch] = await t.db
      .insert(branches)
      .values({ projectId, kind: 'branch', name: 'rank-test' })
      .returning();
    const [rule] = await t.db
      .insert(rules)
      .values({
        key: 'eslint:no-console',
        engineId: 'eslint',
        engineRuleId: 'no-console',
        name: 'no-console',
        defaultSeverity: 'medium',
        quality: 'maintainability',
        kind: 'issue',
        origin: 'reported',
      })
      .returning();
    const [issue] = await t.db
      .insert(issues)
      .values({
        projectId,
        branchId: branch!.id,
        ruleId: rule!.id,
        fingerprint: 'f'.repeat(32),
        lineHash: 'a'.repeat(32),
        contextHash: 'b'.repeat(32),
        message: 'm',
        severity: 'high',
        quality: 'maintainability',
        kind: 'issue',
        firstSeenAt: new Date(),
      })
      .returning();
    expect(issue!.severityRank).toBe(1);
  });
});
