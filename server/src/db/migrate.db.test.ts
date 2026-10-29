import { randomUUID } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { MIGRATIONS_DIR } from '../../test/paths';
import { pendingMigrations, readinessCheck, runMigrations } from './migrate';

/** How many migrations the journal lists (what an empty database has pending). */
function journalLength(): number {
  const journalPath = path.join(MIGRATIONS_DIR, 'meta', '_journal.json');
  return (JSON.parse(readFileSync(journalPath, 'utf8')) as { entries: unknown[] }).entries.length;
}

/** A copy of the migrations folder whose journal stops after the first `count` migrations. */
function migrationsUpTo(count: number): { dir: string; remove: () => void } {
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-migrations-'));
  cpSync(MIGRATIONS_DIR, dir, { recursive: true });
  const journalPath = path.join(dir, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as { entries: unknown[] };
  writeFileSync(
    journalPath,
    JSON.stringify({ ...journal, entries: journal.entries.slice(0, count) }),
  );
  return { dir, remove: () => rmSync(dir, { recursive: true, force: true }) };
}

/** An `llm_requests` row of the given feature (the 0016 and 0017 tests insert them before and after). */
function insertLlmRequest(db: TestDatabase, org: string, project: string, feature: string) {
  return db.pool.query(
    `INSERT INTO llm_requests (id, organization_id, project_id, feature, cache_key, provider,
       provider_host, model, prompt_version, input_sha256, input_bytes, fields)
     VALUES ($1, $2, $3, $4, $5, 'openai', 'api.example.com', 'm', $6, $7, 10, '{rule}')`,
    [randomUUID(), org, project, feature, 'a'.repeat(64), `${feature}.v1`, 'b'.repeat(64)],
  );
}

describe('runMigrations / pendingMigrations', () => {
  let t: TestDatabase | undefined;
  afterEach(async () => {
    await t?.close();
    t = undefined;
  });

  it('counts every migration as pending on an empty database, then none', async () => {
    t = await createTestDatabase({ migrated: false });
    // 0000_extensions, 0001_init, 0002_analyses_scm_context (scm.md §7),
    // 0003_scm_connections_github_app (github.md §2.5), 0004_llm_requests (llm.md §11.1, DM-1),
    // 0005_rbac_audit (rbac-audit.md §7, approved 2026-09-27),
    // 0006_sso_scim (sso-scim.md §13, approved 2026-09-28),
    // 0007_compliance_reports (4E-1 §1), 0008_branch_dependencies (6M §4), 0009_mail (E1 spec,
    // approved 2026-10-13), 0010_account_tokens (mail E2 A1, 2026-10-13), 0011_notifications
    // (mail E3 N8, 2026-10-13), 0012_issues_confidence (6B-C# engine spec R-9, approved
    // 2026-10-15), 0013_oauth (phase 6N, OAuth clients, requests, grants and tokens),
    // 0014_chat_webhooks (phase 6G, Slack and Teams webhooks), 0015_review_snapshots (phase 6I-2,
    // the repository snapshots of the AI review), 0016_review_runs (phase 6I-3, the review runs
    // and the AI findings), 0017_review_replies (phase 6I-4, the replies ledger), 0018_rule_scope
    // (0.13, a rule's scope and its profile override).
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(19);
    expect(await readinessCheck(t.db, MIGRATIONS_DIR)()).toBe(false);
    await runMigrations(t.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
    expect(await readinessCheck(t.db, MIGRATIONS_DIR)()).toBe(true);
  });

  it('is safe when several replicas migrate at once', async () => {
    t = await createTestDatabase({ migrated: false });
    const pool = t.pool;
    await Promise.all([1, 2, 3].map(() => runMigrations(pool, MIGRATIONS_DIR)));
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
  });

  it('adds the GitHub App columns to a database that holds plan 2A rows (0003, github.md §2.5)', async () => {
    t = await createTestDatabase({ migrated: false });
    const upTo2A = migrationsUpTo(3); // 0000_extensions, 0001_init, 0002_analyses_scm_context
    try {
      await runMigrations(t.pool, upTo2A.dir);
    } finally {
      upTo2A.remove();
    }
    // 0003 and every later migration: independent of how many come after.
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(journalLength() - 3);
    const org = randomUUID();
    const connection = randomUUID();
    const envelope = { v: 1, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-2a', 'Mig')`, [
      org,
    ]);
    await t.pool.query(
      `INSERT INTO scm_connections (id, organization_id, provider, base_url, token_enc)
       VALUES ($1, $2, 'gitlab', 'https://gitlab.example.com', $3)`,
      [connection, org, JSON.stringify(envelope)],
    );
    await runMigrations(t.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
    const { rows } = await t.pool.query(
      'SELECT provider, base_url, token_enc, app_id, webhook_secret_enc FROM scm_connections WHERE id = $1',
      [connection],
    );
    expect(rows).toEqual([
      {
        provider: 'gitlab',
        base_url: 'https://gitlab.example.com',
        token_enc: envelope,
        app_id: null,
        webhook_secret_enc: null,
      },
    ]);
  });

  it('adds llm_requests to a database that holds plan 2C rows (0004, llm.md §11.1, DM-1)', async () => {
    t = await createTestDatabase({ migrated: false });
    const upTo2C = migrationsUpTo(4); // 0000–0003
    try {
      await runMigrations(t.pool, upTo2C.dir);
    } finally {
      upTo2C.remove();
    }
    // 0004 and every later migration.
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(journalLength() - 4);
    const org = randomUUID();
    const project = randomUUID();
    const user = randomUUID();
    const connection = randomUUID();
    const envelope = { v: 1, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-2c', 'Mig')`, [
      org,
    ]);
    await t.pool.query(
      `INSERT INTO scm_connections (id, organization_id, provider, base_url, token_enc, app_id)
       VALUES ($1, $2, 'github', 'https://api.github.com', $3, '12345')`,
      [connection, org, JSON.stringify(envelope)],
    );
    await t.pool.query(
      `INSERT INTO projects (id, organization_id, key, name, scm_connection_id)
       VALUES ($1, $2, 'mig/2c', 'P', $3)`,
      [project, org, connection],
    );
    await t.pool.query(`INSERT INTO users (id, username) VALUES ($1, 'mig-2c-user')`, [user]);
    await runMigrations(t.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
    // The existing rows are untouched, and the new table is empty and usable.
    const { rows: before } = await t.pool.query(
      `SELECT p.key, c.app_id, c.token_enc FROM projects p
         JOIN scm_connections c ON c.id = p.scm_connection_id WHERE p.id = $1`,
      [project],
    );
    expect(before).toEqual([{ key: 'mig/2c', app_id: '12345', token_enc: envelope }]);
    const { rows: empty } = await t.pool.query('SELECT count(*)::int AS n FROM llm_requests');
    expect(empty).toEqual([{ n: 0 }]);
    await t.pool.query(
      `INSERT INTO llm_requests (id, organization_id, project_id, user_id, feature, cache_key,
         provider, provider_host, model, prompt_version, input_sha256, input_bytes, fields)
       VALUES ($1, $2, $3, $4, 'explain', $5, 'openai', 'api.example.com', 'm', 'explain.v1',
               $6, 10, '{rule,message}')`,
      [randomUUID(), org, project, user, 'a'.repeat(64), 'b'.repeat(64)],
    );
    const { rows } = await t.pool.query(
      'SELECT status, attempts, redactions, issue_id, result, prompt, post FROM llm_requests',
    );
    expect(rows).toEqual([
      {
        status: 'queued',
        attempts: 0,
        redactions: 0,
        issue_id: null,
        result: null,
        prompt: null,
        post: null,
      },
    ]);
    // Tenancy: deleting the organisation leaves no orphan.
    await t.pool.query('DELETE FROM organizations WHERE id = $1', [org]);
    const { rows: gone } = await t.pool.query('SELECT count(*)::int AS n FROM llm_requests');
    expect(gone).toEqual([{ n: 0 }]);
  });

  it('adds project grants and audit events to a database already at 0004 (0005, rbac-audit.md §7)', async () => {
    t = await createTestDatabase({ migrated: false });
    const upTo4 = migrationsUpTo(5); // 0000_extensions … 0004_llm_requests
    try {
      await runMigrations(t.pool, upTo4.dir);
    } finally {
      upTo4.remove();
    }
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(journalLength() - 5);
    const org = randomUUID();
    const project = randomUUID();
    const user = randomUUID();
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-4c', 'Mig')`, [
      org,
    ]);
    await t.pool.query(`INSERT INTO users (id, username) VALUES ($1, 'mig-4c-user')`, [user]);
    await t.pool.query(
      `INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')`,
      [org, user],
    );
    await t.pool.query(
      `INSERT INTO projects (id, organization_id, key, name) VALUES ($1, $2, 'mig/4c', 'P')`,
      [project, org],
    );
    await runMigrations(t.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(t.db, MIGRATIONS_DIR)).toBe(0);
    // The existing membership row (a pre-4C community role) is untouched by the widened CHECK.
    const { rows: membershipRows } = await t.pool.query(
      'SELECT organization_id, user_id, role FROM memberships WHERE organization_id = $1',
      [org],
    );
    expect(membershipRows).toEqual([{ organization_id: org, user_id: user, role: 'admin' }]);
    // The new project_memberships table is empty and usable.
    const { rows: empty } = await t.pool.query(
      'SELECT count(*)::int AS n FROM project_memberships',
    );
    expect(empty).toEqual([{ n: 0 }]);
    await t.pool.query(
      `INSERT INTO project_memberships (project_id, user_id, role) VALUES ($1, $2, 'viewer')`,
      [project, user],
    );
    const { rows: grant } = await t.pool.query(
      'SELECT project_id, user_id, role FROM project_memberships WHERE project_id = $1',
      [project],
    );
    expect(grant).toEqual([{ project_id: project, user_id: user, role: 'viewer' }]);
    // A project grant is removed with the project (cascade), never orphaned.
    await t.pool.query('DELETE FROM projects WHERE id = $1', [project]);
    const { rows: gone } = await t.pool.query(
      'SELECT count(*)::int AS n FROM project_memberships WHERE project_id = $1',
      [project],
    );
    expect(gone).toEqual([{ n: 0 }]);
    // audit_events is empty and its immutability trigger already guards it.
    const { rows: auditEmpty } = await t.pool.query('SELECT count(*)::int AS n FROM audit_events');
    expect(auditEmpty).toEqual([{ n: 0 }]);
  });

  it('adds the SSO and SCIM tables to a database already at 0005 without changing a row (0006, sso-scim.md §13)', async () => {
    const db = await createTestDatabase({ migrated: false });
    t = db;
    const upTo5 = migrationsUpTo(6); // 0000_extensions … 0005_rbac_audit
    try {
      await runMigrations(db.pool, upTo5.dir);
    } finally {
      upTo5.remove();
    }
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(journalLength() - 6);
    const org = randomUUID();
    const project = randomUUID();
    const admin = randomUUID();
    const viewer = randomUUID();
    await db.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-4d', 'Mig')`, [
      org,
    ]);
    await db.pool.query(
      `INSERT INTO users (id, username, email, password_hash, is_instance_admin)
       VALUES ($1, 'mig-4d-admin', 'a@example.com', 'x', true), ($2, 'mig-4d-viewer', NULL, NULL, false)`,
      [admin, viewer],
    );
    await db.pool.query(
      `INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin'), ($1, $3, 'viewer')`,
      [org, admin, viewer],
    );
    await db.pool.query(
      `INSERT INTO projects (id, organization_id, key, name) VALUES ($1, $2, 'mig/4d', 'P')`,
      [project, org],
    );
    await db.pool.query(
      `INSERT INTO project_memberships (project_id, user_id, role) VALUES ($1, $2, 'project_admin')`,
      [project, viewer],
    );
    await db.pool.query(
      `INSERT INTO sessions (id, user_id, expires_at) VALUES ('\\x0102', $1, now() + interval '1 day')`,
      [admin],
    );
    await db.pool.query(
      `INSERT INTO api_tokens (id, kind, user_id, name, prefix, secret_hash, scopes)
       VALUES ($1, 'personal', $2, 't', 'qlr_abcdefgh', '\\x00', '{read}')`,
      [randomUUID(), admin],
    );

    // Every row of every table, as JSON, before and after (the new column aside).
    const snapshot = async (): Promise<Record<string, string[]>> => {
      const { rows: tables } = await db.pool.query<{ name: string }>(
        `SELECT table_name AS name FROM information_schema.tables
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`,
      );
      const out: Record<string, string[]> = {};
      for (const { name } of tables) {
        const { rows } = await db.pool.query<{ r: string }>(
          `SELECT (to_jsonb(x) - 'managed_by_connection_id')::text AS r FROM "${name}" x ORDER BY 1`,
        );
        out[name] = rows.map((row) => row.r);
      }
      return out;
    };
    const before = await snapshot();
    expect(before.memberships).toHaveLength(2);
    await runMigrations(db.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(0);
    const after = await snapshot();

    // 0006 adds the SSO and SCIM tables; the run to the latest migration adds the later tables too.
    const added0006 = [
      'identities',
      'scim_group_members',
      'scim_groups',
      'scim_tokens',
      'sso_connections',
      'sso_group_mappings',
      'sso_states',
    ];
    const added = [
      ...added0006,
      'compliance_reports', // 0007_compliance_reports
      'branch_dependencies', // 0008_branch_dependencies
      'mail_messages', // 0009_mail
      'account_tokens', // 0010_account_tokens
      'notification_preferences', // 0011_notifications
      'oauth_clients', // 0013_oauth
      'oauth_grants', // 0013_oauth
      'oauth_requests', // 0013_oauth
      'oauth_tokens', // 0013_oauth
      'project_watches',
      'review_findings', // 0016_review_runs
      'review_replies', // 0017_review_replies
      'review_runs', // 0016_review_runs
      'review_snapshot_files', // 0015_review_snapshots
      'review_snapshots', // 0015_review_snapshots
    ].sort();
    expect(Object.keys(after).filter((name) => !(name in before))).toEqual(added);
    for (const name of added) expect(after[name], name).toEqual([]);
    for (const name of Object.keys(before)) expect(after[name], name).toEqual(before[name]);
    // The existing memberships and project grants are all manual.
    const { rows: managed } = await db.pool.query(
      `SELECT (SELECT count(*)::int FROM memberships WHERE managed_by_connection_id IS NULL) AS m,
              (SELECT count(*)::int FROM project_memberships WHERE managed_by_connection_id IS NULL) AS p`,
    );
    expect(managed).toEqual([{ m: 2, p: 1 }]);
  });

  it('adds the review tables to a database that holds AI requests and keeps every request (0016, phase 6I-3)', async () => {
    const db = await createTestDatabase({ migrated: false });
    t = db;
    const upTo15 = migrationsUpTo(16); // 0000_extensions … 0015_review_snapshots
    try {
      await runMigrations(db.pool, upTo15.dir);
    } finally {
      upTo15.remove();
    }
    // 0016 and every later migration.
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(journalLength() - 16);
    const org = randomUUID();
    const project = randomUUID();
    await db.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-6i3', 'Mig')`, [
      org,
    ]);
    await db.pool.query(
      `INSERT INTO projects (id, organization_id, key, name) VALUES ($1, $2, 'mig/6i3', 'P')`,
      [project, org],
    );
    for (const feature of ['explain', 'triage', 'fix']) {
      await insertLlmRequest(db, org, project, feature);
    }
    const requests = async () =>
      (
        await db.pool.query(
          'SELECT id, feature, status, prompt_version, cache_key FROM llm_requests ORDER BY feature',
        )
      ).rows;
    const before = await requests();
    expect(before).toHaveLength(3);

    await runMigrations(db.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(0);
    // Dropping and adding the feature check changed no request, and the new tables are empty.
    expect(await requests()).toEqual(before);
    for (const table of ['review_runs', 'review_findings']) {
      const { rows } = await db.pool.query(`SELECT count(*)::int AS n FROM ${table}`);
      expect(rows, table).toEqual([{ n: 0 }]);
    }
    // The widened check lists review, and still refuses any other value.
    await insertLlmRequest(db, org, project, 'review');
    await expect(insertLlmRequest(db, org, project, 'poem')).rejects.toMatchObject({
      code: '23514',
      constraint: 'llm_requests_feature_check',
    });
  });

  it('adds the replies ledger to a database that holds connections, runs and AI requests, and keeps every row (0017, phase 6I-4)', async () => {
    const db = await createTestDatabase({ migrated: false });
    t = db;
    const upTo16 = migrationsUpTo(17); // 0000_extensions … 0016_review_runs
    try {
      await runMigrations(db.pool, upTo16.dir);
    } finally {
      upTo16.remove();
    }
    // 0017 and every later migration.
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(journalLength() - 17);
    const org = randomUUID();
    const project = randomUUID();
    const branch = randomUUID();
    const analysis = randomUUID();
    const envelope = JSON.stringify({ v: 1, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' });
    await db.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-6i4', 'Mig')`, [
      org,
    ]);
    await db.pool.query(
      `INSERT INTO projects (id, organization_id, key, name) VALUES ($1, $2, 'mig/6i4', 'P')`,
      [project, org],
    );
    await db.pool.query(
      `INSERT INTO branches (id, project_id, kind, name) VALUES ($1, $2, 'merge_request', '7')`,
      [branch, project],
    );
    await db.pool.query(`INSERT INTO analyses (id, project_id) VALUES ($1, $2)`, [
      analysis,
      project,
    ]);
    await db.pool.query(
      `INSERT INTO review_runs (id, project_id, branch_id, analysis_id, deadline_at)
       VALUES ($1, $2, $3, $4, now())`,
      [randomUUID(), project, branch, analysis],
    );
    await db.pool.query(
      `INSERT INTO scm_connections (id, organization_id, provider, base_url, token_enc, app_id, webhook_secret_enc)
       VALUES ($1, $2, 'gitlab', 'https://gitlab.example.com', $3, NULL, NULL),
              ($4, $2, 'github', 'https://api.github.com', $3, '12345', $3)`,
      [randomUUID(), org, envelope, randomUUID()],
    );
    await insertLlmRequest(db, org, project, 'review');
    const rowsOf = async (table: string) =>
      (
        await db.pool.query<{ row: Record<string, unknown> }>(
          `SELECT to_jsonb(x) AS row FROM ${table} x ORDER BY x.id`,
        )
      ).rows.map((r) => r.row);
    const before = {
      connections: await rowsOf('scm_connections'),
      runs: await rowsOf('review_runs'),
      requests: await rowsOf('llm_requests'),
    };
    expect(before.connections).toHaveLength(2);
    expect(before.runs).toHaveLength(1);
    expect(before.requests).toHaveLength(1);

    await runMigrations(db.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(0);
    // Dropping and adding two checks changed no row, and the runs only gained their empty column.
    expect(await rowsOf('scm_connections')).toEqual(before.connections);
    expect(await rowsOf('llm_requests')).toEqual(before.requests);
    expect(await rowsOf('review_runs')).toEqual(
      before.runs.map((run) => ({ ...run, requested_by: null })),
    );
    const { rows: ledger } = await db.pool.query('SELECT count(*)::int AS n FROM review_replies');
    expect(ledger).toEqual([{ n: 0 }]);

    // The relaxed check lets a GitLab connection hold a webhook secret and still refuses an App id
    // on it, and a GitHub connection without one.
    const insertConnection = (provider: string, appId: string | null, secret: string | null) =>
      db.pool.query(
        `INSERT INTO scm_connections (id, organization_id, provider, base_url, token_enc, app_id, webhook_secret_enc)
         VALUES ($1, $2, $3, 'https://x.example', $4, $5, $6)`,
        [randomUUID(), org, provider, envelope, appId, secret],
      );
    await insertConnection('gitlab', null, envelope);
    for (const [provider, appId] of [
      ['gitlab', '1'],
      ['github', null],
    ] as const) {
      await expect(insertConnection(provider, appId, envelope)).rejects.toMatchObject({
        code: '23514',
        constraint: 'scm_connections_github_app_check',
      });
    }
    // The widened check lists review-reply, and still refuses any other value.
    await insertLlmRequest(db, org, project, 'review-reply');
    await expect(insertLlmRequest(db, org, project, 'poem')).rejects.toMatchObject({
      code: '23514',
      constraint: 'llm_requests_feature_check',
    });
  });

  it('gives every existing rule the scope all and every profile row no override (0018, 0.13)', async () => {
    const db = await createTestDatabase({ migrated: false });
    t = db;
    const upTo17 = migrationsUpTo(18); // 0000_extensions … 0017_review_replies
    try {
      await runMigrations(db.pool, upTo17.dir);
    } finally {
      upTo17.remove();
    }
    // 0018 and every later migration.
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(journalLength() - 18);
    const org = randomUUID();
    const profile = randomUUID();
    const rule = randomUUID();
    await db.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'mig-013', 'Mig')`, [
      org,
    ]);
    await db.pool.query(
      `INSERT INTO rules (id, key, engine_id, engine_rule_id, name, default_severity, quality, kind, origin)
       VALUES ($1, 'sonarjs:S2004', 'sonarjs', 'S2004', 'S2004', 'medium', 'maintainability', 'issue', 'reported')`,
      [rule],
    );
    await db.pool.query(
      `INSERT INTO quality_profiles (id, organization_id, name, language) VALUES ($1, $2, 'P', 'typescript')`,
      [profile, org],
    );
    await db.pool.query(
      `INSERT INTO profile_rules (profile_id, rule_id, active, severity_override) VALUES ($1, $2, false, 'high')`,
      [profile, rule],
    );

    await runMigrations(db.pool, MIGRATIONS_DIR);
    expect(await pendingMigrations(db.db, MIGRATIONS_DIR)).toBe(0);
    const { rows: scoped } = await db.pool.query(
      `SELECT r.scope, pr.active, pr.severity_override, pr.scope_override
         FROM profile_rules pr JOIN rules r ON r.id = pr.rule_id`,
    );
    expect(scoped).toEqual([
      { scope: 'all', active: false, severity_override: 'high', scope_override: null },
    ]);
    // The checks take the three scopes and nothing else.
    await db.pool.query(`UPDATE rules SET scope = 'main' WHERE id = $1`, [rule]);
    await db.pool.query(`UPDATE profile_rules SET scope_override = 'test'`);
    await expect(
      db.pool.query(`UPDATE rules SET scope = 'Main' WHERE id = $1`, [rule]),
    ).rejects.toMatchObject({ code: '23514', constraint: 'rules_scope_check' });
    await expect(
      db.pool.query(`UPDATE profile_rules SET scope_override = 'tests'`),
    ).rejects.toMatchObject({ code: '23514', constraint: 'profile_rules_scope_check' });
  });
});
