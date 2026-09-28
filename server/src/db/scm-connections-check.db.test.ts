import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';

/** github.md §2.5: GitLab rows keep both GitHub columns NULL; GitHub rows have a digits App id. */
describe('scm_connections_github_app_check (migration 0003)', () => {
  let t: TestDatabase;
  let org: string;
  const envelope = JSON.stringify({ v: 1, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' });
  const insert = (provider: string, appId: string | null, webhookSecretEnc: string | null) =>
    t.pool.query(
      `INSERT INTO scm_connections (id, organization_id, provider, base_url, token_enc, app_id, webhook_secret_enc)
       VALUES ($1, $2, $3, 'https://x.example', $4, $5, $6)`,
      [randomUUID(), org, provider, envelope, appId, webhookSecretEnc],
    );

  beforeAll(async () => {
    t = await createTestDatabase();
    org = randomUUID();
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'check-org', 'C')`, [
      org,
    ]);
  });
  afterAll(() => t.close());

  it('accepts a GitLab row without, and a GitHub row with, an App id', async () => {
    await insert('gitlab', null, null);
    await insert('github', '123456', null);
    await insert('github', '123456', envelope);
    const { rows } = await t.pool.query('SELECT count(*)::int AS n FROM scm_connections');
    expect(rows[0]?.n).toBe(3);
  });

  it('refuses a GitLab row with an App id or a webhook secret', async () => {
    await expectPgError(insert('gitlab', '1', null), '23514');
    await expectPgError(insert('gitlab', null, envelope), '23514');
  });

  it('refuses a GitHub row without an App id, or with one that is not digits', async () => {
    await expectPgError(insert('github', null, null), '23514');
    await expectPgError(insert('github', '12a', null), '23514');
    await expectPgError(insert('github', '1'.repeat(21), null), '23514');
  });
});
