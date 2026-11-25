import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';

/**
 * github.md §2.5: GitLab rows keep the App id NULL, and since migration 0017 may hold a webhook
 * secret (the GitLab note webhook); GitHub rows have a digits App id.
 */
describe('scm_connections_github_app_check (migrations 0003 and 0017)', () => {
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

  it('accepts a GitLab row with a webhook secret', async () => {
    await insert('gitlab', null, envelope);
    const { rows } = await t.pool.query(
      `SELECT count(*)::int AS n FROM scm_connections
        WHERE provider = 'gitlab' AND webhook_secret_enc IS NOT NULL`,
    );
    expect(rows[0]?.n).toBe(1);
  });

  it('refuses a GitLab row with an App id, with or without a webhook secret', async () => {
    await expectPgError(insert('gitlab', '1', null), '23514');
    await expectPgError(insert('gitlab', '1', envelope), '23514');
    await expectPgError(insert('gitlab', '', null), '23514');
  });

  it('refuses a GitHub row without an App id, or with one that is not digits', async () => {
    await expectPgError(insert('github', null, null), '23514');
    // A webhook secret does not stand in for the App id.
    await expectPgError(insert('github', null, envelope), '23514');
    await expectPgError(insert('github', '12a', null), '23514');
    await expectPgError(insert('github', '1'.repeat(21), null), '23514');
  });
});

/** Migration 0034: Azure DevOps rows carry how they authenticate, and a service principal its ids. */
describe('scm_connections azure checks (migration 0034)', () => {
  let t: TestDatabase;
  let org: string;
  const envelope = JSON.stringify({ v: 1, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' });
  const GUID = '0f8fad5b-d9cb-469f-a165-70867728950e';
  const insert = (
    provider: string,
    appId: string | null,
    azureAuth: string | null,
    tenantId: string | null = null,
    clientId: string | null = null,
  ) =>
    t.pool.query(
      `INSERT INTO scm_connections
         (id, organization_id, provider, base_url, token_enc, app_id, azure_auth, azure_tenant_id, azure_client_id)
       VALUES ($1, $2, $3, 'https://dev.azure.com/acme', $4, $5, $6, $7, $8)`,
      [randomUUID(), org, provider, envelope, appId, azureAuth, tenantId, clientId],
    );

  beforeAll(async () => {
    t = await createTestDatabase();
    org = randomUUID();
    await t.pool.query(`INSERT INTO organizations (id, key, name) VALUES ($1, 'azure-org', 'A')`, [
      org,
    ]);
  });
  afterAll(() => t.close());

  it('an azure row with azure_auth pat and no ids is accepted', async () => {
    await insert('azure', null, 'pat');
    const { rows } = await t.pool.query(
      `SELECT count(*)::int AS n FROM scm_connections WHERE provider = 'azure'`,
    );
    expect(rows[0]?.n).toBe(1);
  });

  it('an azure row with a service principal accepts both GUIDs', async () => {
    await insert('azure', null, 'service_principal_secret', GUID, GUID);
    await insert('azure', null, 'service_principal_certificate', GUID, GUID);
    const { rows } = await t.pool.query(
      `SELECT count(*)::int AS n FROM scm_connections
        WHERE provider = 'azure' AND azure_auth LIKE 'service_principal_%'`,
    );
    expect(rows[0]?.n).toBe(2);
  });

  it('an azure row with a service principal kind needs both ids', async () => {
    for (const kind of ['service_principal_secret', 'service_principal_certificate']) {
      await expectPgError(insert('azure', null, kind, null, GUID), '23514');
      await expectPgError(insert('azure', null, kind, GUID, null), '23514');
      await expectPgError(insert('azure', null, kind), '23514');
      await expectPgError(insert('azure', null, kind, 'not-a-guid', GUID), '23514');
      await expectPgError(insert('azure', null, kind, GUID, GUID.toUpperCase()), '23514');
    }
  });

  it('an azure pat row carries no ids, and an azure row needs a known kind', async () => {
    await expectPgError(insert('azure', null, 'pat', GUID, GUID), '23514');
    await expectPgError(insert('azure', null, null), '23514');
    await expectPgError(insert('azure', null, 'basic'), '23514');
  });

  it('a gitlab or github row with azure_auth set is refused', async () => {
    await expectPgError(insert('gitlab', null, 'pat'), '23514');
    await expectPgError(insert('github', '123456', 'pat'), '23514');
    await expectPgError(insert('gitlab', null, null, GUID, GUID), '23514');
  });

  it('an azure row with app_id is refused', async () => {
    await expectPgError(insert('azure', '123456', 'pat'), '23514');
  });
});
