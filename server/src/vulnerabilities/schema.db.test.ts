import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';

describe('vulnerability decisions and target checks (schema)', () => {
  let t: TestDatabase;
  let org: string;
  let n = 0;

  beforeAll(async () => {
    t = await createTestDatabase();
    org = randomUUID();
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'vd-schema', 'S')`, [
      org,
    ]);
  });
  afterAll(async () => {
    await t.close();
  });

  const project = async (): Promise<{ id: string; branch: string; version: string }> => {
    const id = randomUUID();
    const branch = randomUUID();
    const version = randomUUID();
    await t.pool.query(
      `INSERT INTO projects (id, organization_id, key, name) VALUES ($1, $2, $3, 'P')`,
      [id, org, `vd/schema-${++n}`],
    );
    await t.pool.query(
      `INSERT INTO branches (id, project_id, kind, name) VALUES ($1, $2, 'branch', 'main')`,
      [branch, id],
    );
    await t.pool.query(
      `INSERT INTO project_versions (id, project_id, label, source, analyzed_at)
       VALUES ($1, $2, '1.0.0', 'tag', now())`,
      [version, id],
    );
    return { id, branch, version };
  };
  const decide = (
    p: { id: string },
    set: {
      branch?: string | null;
      version?: string | null;
      status?: string;
      reason?: string | null;
      comment?: string | null;
      pkg?: string;
    } = {},
  ) =>
    t.pool.query(
      `INSERT INTO vulnerability_decisions (id, project_id, package_name, vulnerability_id,
         branch_id, version_id, status, reason, comment)
       VALUES ($1, $2, $3, 'CVE-2026-0001', $4, $5, $6, $7, $8)`,
      [
        randomUUID(),
        p.id,
        set.pkg ?? 'lodash',
        set.branch ?? null,
        set.version ?? null,
        set.status ?? 'wont_fix',
        set.reason ?? null,
        set.comment ?? null,
      ],
    );

  it('stores a decision and a check and reads them back', async () => {
    const p = await project();
    await decide(p, {
      status: 'false_positive',
      reason: 'component_not_present',
      comment: 'Dev only',
    });
    await t.pool.query(
      `INSERT INTO vulnerability_target_checks (project_id, branch_id, basis, baseline_at, checked_at)
       VALUES ($1, $2, 'a', now(), now())`,
      [p.id, p.branch],
    );
    const { rows } = await t.pool.query(
      `SELECT status, reason, comment, decided_at IS NOT NULL AS dated
         FROM vulnerability_decisions WHERE project_id = $1`,
      [p.id],
    );
    expect(rows).toEqual([
      {
        status: 'false_positive',
        reason: 'component_not_present',
        comment: 'Dev only',
        dated: true,
      },
    ]);
    const { rows: checks } = await t.pool.query(
      `SELECT basis FROM vulnerability_target_checks WHERE project_id = $1`,
      [p.id],
    );
    expect(checks).toEqual([{ basis: 'a' }]);
  });

  it('refuses a decision with two scopes, a reason on wont_fix, a bad status and a long comment', async () => {
    const p = await project();
    await expect(decide(p, { branch: p.branch, version: p.version })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_one_scope',
    });
    await expect(
      decide(p, { status: 'wont_fix', reason: 'component_not_present' }),
    ).rejects.toMatchObject({ constraint: 'vulnerability_decisions_reason_status' });
    await expect(decide(p, { status: 'false_positive', reason: 'because' })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_reason_check',
    });
    await expect(decide(p, { status: 'resolved' })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_status_check',
    });
    await expect(decide(p, { comment: 'x'.repeat(2001) })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_comment_length',
    });
    await decide(p, { comment: 'x'.repeat(2000) });
  });

  it('allows one decision per pair and scope', async () => {
    const p = await project();
    await decide(p);
    await expect(decide(p)).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_project_uq',
    });
    // The same pair on a branch and on a version is another decision; so is another package.
    await decide(p, { branch: p.branch });
    await decide(p, { version: p.version });
    await decide(p, { pkg: 'minimist' });
    await expect(decide(p, { branch: p.branch })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_branch_uq',
    });
    await expect(decide(p, { version: p.version })).rejects.toMatchObject({
      constraint: 'vulnerability_decisions_version_uq',
    });
  });

  it('keeps one check per target, for exactly one target', async () => {
    const p = await project();
    const check = (branch: string | null, version: string | null) =>
      t.pool.query(
        `INSERT INTO vulnerability_target_checks (project_id, branch_id, version_id, basis, baseline_at, checked_at)
         VALUES ($1, $2, $3, 'a', now(), now())`,
        [p.id, branch, version],
      );
    await check(p.branch, null);
    await expect(check(p.branch, null)).rejects.toMatchObject({
      constraint: 'vulnerability_target_checks_branch_uq',
    });
    await check(null, p.version);
    await expect(check(null, p.version)).rejects.toMatchObject({
      constraint: 'vulnerability_target_checks_version_uq',
    });
    await expect(check(null, null)).rejects.toMatchObject({
      constraint: 'vulnerability_target_checks_one_target',
    });
    await expect(check(p.branch, p.version)).rejects.toMatchObject({
      constraint: 'vulnerability_target_checks_one_target',
    });
  });

  it('deletes the decisions and the check of a branch with it', async () => {
    const p = await project();
    await decide(p, { branch: p.branch });
    await decide(p);
    await t.pool.query(
      `INSERT INTO vulnerability_target_checks (project_id, branch_id, basis, baseline_at, checked_at)
       VALUES ($1, $2, 'a', now(), now())`,
      [p.id, p.branch],
    );
    await t.pool.query('DELETE FROM branches WHERE id = $1', [p.branch]);
    const { rows } = await t.pool.query(
      `SELECT branch_id FROM vulnerability_decisions WHERE project_id = $1`,
      [p.id],
    );
    expect(rows).toEqual([{ branch_id: null }]);
    const { rows: checks } = await t.pool.query(
      `SELECT 1 FROM vulnerability_target_checks WHERE project_id = $1`,
      [p.id],
    );
    expect(checks).toEqual([]);
  });
});
