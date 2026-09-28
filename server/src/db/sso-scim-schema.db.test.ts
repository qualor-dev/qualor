import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { uuidv7 } from './ids';

/**
 * drizzle-orm 0.45 wraps the driver's error in a `DrizzleQueryError` whose `.message` is only
 * "Failed query: …"; the constraint name is on `.cause`. Walks the chain (as the 0005 test does).
 */
async function expectRejection(action: PromiseLike<unknown>, pattern: RegExp): Promise<void> {
  const error: unknown = await Promise.resolve(action).then(
    () => null,
    (err: unknown) => err,
  );
  expect(error, 'expected the query to be rejected').not.toBeNull();
  const messages: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const message = (current as { message?: unknown }).message;
    if (typeof message === 'string') messages.push(message);
    current = (current as { cause?: unknown }).cause;
  }
  expect(messages.join(' | ')).toMatch(pattern);
}

const NEW_TABLES = [
  'sso_connections',
  'identities',
  'scim_tokens',
  'scim_groups',
  'scim_group_members',
  'sso_group_mappings',
  'sso_states',
];

describe('migration 0006: SSO and SCIM (sso-scim.md §13)', () => {
  let database: TestDatabase;
  let orgId: string;
  let userId: string;
  let projectId: string;
  let oidcId: string;

  const exec = (q: ReturnType<typeof sql>) => database.db.execute(q);

  beforeAll(async () => {
    database = await createTestDatabase();
    orgId = uuidv7();
    userId = uuidv7();
    projectId = uuidv7();
    oidcId = uuidv7();
    await exec(sql`INSERT INTO organizations (id, key, name) VALUES (${orgId}, 'o6', 'O6')`);
    await exec(sql`INSERT INTO users (id, username) VALUES (${userId}, 'u6')`);
    await exec(
      sql`INSERT INTO projects (id, organization_id, key, name) VALUES (${projectId}, ${orgId}, 'p6', 'P6')`,
    );
    await exec(
      sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${oidcId}, 'Acme', 'oidc', '{}'::jsonb)`,
    );
  });
  afterAll(async () => database.close());

  it('refuses a second connection of the same name in another case', async () => {
    await expectRejection(
      exec(
        sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${uuidv7()}, 'ACME', 'saml', '{}'::jsonb)`,
      ),
      /sso_connections_name_key/,
    );
  });

  it('refuses an unknown protocol and a config over 64 KiB', async () => {
    await expectRejection(
      exec(
        sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${uuidv7()}, 'x0', 'ldap', '{}')`,
      ),
      /sso_connections_protocol_check/,
    );
    await expectRejection(
      exec(sql`INSERT INTO sso_connections (id, name, protocol, config)
               VALUES (${uuidv7()}, 'x0', 'oidc', jsonb_build_object('x', repeat('a', 65600)))`),
      /sso_connections_config_size/,
    );
  });

  it('keeps an OIDC row without an SP key and a SAML row without a client secret', async () => {
    const env = sql`'{"v":1,"iv":"a","ct":"b","tag":"c"}'::jsonb`;
    await expectRejection(
      exec(
        sql`INSERT INTO sso_connections (id, name, protocol, config, sp_key_enc) VALUES (${uuidv7()}, 'x1', 'oidc', '{}', ${env})`,
      ),
      /sso_connections_secret_check/,
    );
    await expectRejection(
      exec(
        sql`INSERT INTO sso_connections (id, name, protocol, config, secret_enc) VALUES (${uuidv7()}, 'x2', 'saml', '{}', ${env})`,
      ),
      /sso_connections_secret_check/,
    );
    // The matching pairs are accepted, and a new connection starts disabled.
    const oidc = uuidv7();
    const saml = uuidv7();
    await exec(
      sql`INSERT INTO sso_connections (id, name, protocol, config, secret_enc) VALUES (${oidc}, 'x3', 'oidc', '{}', ${env})`,
    );
    await exec(
      sql`INSERT INTO sso_connections (id, name, protocol, config, sp_key_enc) VALUES (${saml}, 'x4', 'saml', '{}', ${env})`,
    );
    const rows = await exec(
      sql`SELECT enabled FROM sso_connections WHERE id IN (${oidc}, ${saml})`,
    );
    expect(rows.rows).toEqual([{ enabled: false }, { enabled: false }]);
    await exec(sql`DELETE FROM sso_connections WHERE id IN (${oidc}, ${saml})`);
  });

  it('makes (connection, subject) and (connection, user) unique', async () => {
    await exec(
      sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by) VALUES (${uuidv7()}, ${oidcId}, ${userId}, 'sub-1', 'jit')`,
    );
    const other = uuidv7();
    await exec(sql`INSERT INTO users (id, username) VALUES (${other}, 'u6b')`);
    await expectRejection(
      exec(
        sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by) VALUES (${uuidv7()}, ${oidcId}, ${other}, 'sub-1', 'jit')`,
      ),
      /identities_connection_subject_key/,
    );
    await expectRejection(
      exec(
        sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by) VALUES (${uuidv7()}, ${oidcId}, ${userId}, 'sub-2', 'jit')`,
      ),
      /identities_connection_user_key/,
    );
  });

  it('refuses an identity with neither a subject nor a SCIM userName', async () => {
    const u = uuidv7();
    await exec(sql`INSERT INTO users (id, username) VALUES (${u}, 'u6c')`);
    await expectRejection(
      exec(
        sql`INSERT INTO identities (id, connection_id, user_id, linked_by) VALUES (${uuidv7()}, ${oidcId}, ${u}, 'scim')`,
      ),
      /identities_subject_or_scim_check/,
    );
  });

  it('bounds the subject, checks linked_by, and keeps SCIM userNames unique ignoring case', async () => {
    const [a, b, c] = [uuidv7(), uuidv7(), uuidv7()];
    await exec(
      sql`INSERT INTO users (id, username) VALUES (${a}, 'u6d'), (${b}, 'u6e'), (${c}, 'u6f')`,
    );
    await expectRejection(
      exec(sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by)
               VALUES (${uuidv7()}, ${oidcId}, ${a}, repeat('s', 256), 'jit')`),
      /identities_subject_length/,
    );
    await expectRejection(
      exec(sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by)
               VALUES (${uuidv7()}, ${oidcId}, ${a}, 's-a', 'username')`),
      /identities_linked_by_check/,
    );
    // A SCIM record not yet signed in: no subject, a userName.
    await exec(sql`INSERT INTO identities (id, connection_id, user_id, linked_by, scim_user_name, scim_external_id)
                   VALUES (${uuidv7()}, ${oidcId}, ${a}, 'scim', 'Ann@Example.com', 'ext-1')`);
    await expectRejection(
      exec(sql`INSERT INTO identities (id, connection_id, user_id, linked_by, scim_user_name)
               VALUES (${uuidv7()}, ${oidcId}, ${b}, 'scim', 'ann@example.COM')`),
      /identities_connection_scim_user_name_key/,
    );
    await expectRejection(
      exec(sql`INSERT INTO identities (id, connection_id, user_id, linked_by, scim_user_name, scim_external_id)
               VALUES (${uuidv7()}, ${oidcId}, ${c}, 'scim', 'cat@example.com', 'ext-1')`),
      /identities_connection_scim_external_id_key/,
    );
  });

  it('keeps SCIM group names unique per connection ignoring case', async () => {
    await exec(
      sql`INSERT INTO scim_groups (id, connection_id, display_name, external_id) VALUES (${uuidv7()}, ${oidcId}, 'Devs', 'g-1')`,
    );
    await expectRejection(
      exec(
        sql`INSERT INTO scim_groups (id, connection_id, display_name) VALUES (${uuidv7()}, ${oidcId}, 'DEVS')`,
      ),
      /scim_groups_display_name_key/,
    );
    await expectRejection(
      exec(
        sql`INSERT INTO scim_groups (id, connection_id, display_name, external_id) VALUES (${uuidv7()}, ${oidcId}, 'Ops', 'g-1')`,
      ),
      /scim_groups_external_id_key/,
    );
  });

  it('refuses admin on a project mapping, and a duplicate mapping even with a null project', async () => {
    await expectRejection(
      exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, project_id, role)
               VALUES (${uuidv7()}, ${oidcId}, 'g', ${orgId}, ${projectId}, 'admin')`),
      /sso_group_mappings_project_role_check/,
    );
    await exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, role)
                   VALUES (${uuidv7()}, ${oidcId}, 'g', ${orgId}, 'member')`);
    await expectRejection(
      exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, role)
               VALUES (${uuidv7()}, ${oidcId}, 'g', ${orgId}, 'viewer')`),
      /sso_group_mappings_unique/,
    );
    // The same group on a project is another mapping.
    await exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, project_id, role)
                   VALUES (${uuidv7()}, ${oidcId}, 'g', ${orgId}, ${projectId}, 'viewer')`);
    await expectRejection(
      exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, role)
               VALUES (${uuidv7()}, ${oidcId}, '', ${orgId}, 'viewer')`),
      /sso_group_mappings_group_length/,
    );
    await expectRejection(
      exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, role)
               VALUES (${uuidv7()}, ${oidcId}, 'h', ${orgId}, 'owner')`),
      /sso_group_mappings_role_check/,
    );
  });

  it('turns managed memberships into manual ones when the connection is deleted, and cascades the rest', async () => {
    const conn = uuidv7();
    const identity = uuidv7();
    const group = uuidv7();
    await exec(
      sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${conn}, 'Temp', 'saml', '{}')`,
    );
    await exec(sql`DELETE FROM memberships WHERE user_id = ${userId}`);
    await exec(
      sql`INSERT INTO memberships (organization_id, user_id, role, managed_by_connection_id) VALUES (${orgId}, ${userId}, 'member', ${conn})`,
    );
    await exec(
      sql`INSERT INTO project_memberships (project_id, user_id, role, managed_by_connection_id) VALUES (${projectId}, ${userId}, 'viewer', ${conn})`,
    );
    await exec(
      sql`INSERT INTO sso_states (key, kind, connection_id, expires_at) VALUES ('oidc:x', 'oidc', ${conn}, now() + interval '10 minutes')`,
    );
    await exec(
      sql`INSERT INTO identities (id, connection_id, user_id, subject, linked_by) VALUES (${identity}, ${conn}, ${userId}, 'nameid', 'jit')`,
    );
    await exec(
      sql`INSERT INTO scim_groups (id, connection_id, display_name) VALUES (${group}, ${conn}, 'G')`,
    );
    await exec(
      sql`INSERT INTO scim_group_members (group_id, identity_id) VALUES (${group}, ${identity})`,
    );
    await exec(sql`INSERT INTO scim_tokens (id, connection_id, name, prefix, secret_hash)
                   VALUES (${uuidv7()}, ${conn}, 't', 'qlr_scim_abc', decode(repeat('00', 32), 'hex'))`);
    await exec(sql`INSERT INTO sso_group_mappings (id, connection_id, group_value, organization_id, role)
                   VALUES (${uuidv7()}, ${conn}, '*', ${orgId}, 'viewer')`);
    await exec(sql`DELETE FROM sso_connections WHERE id = ${conn}`);
    const m = await exec(
      sql`SELECT role, managed_by_connection_id FROM memberships WHERE user_id = ${userId} AND organization_id = ${orgId}`,
    );
    expect(m.rows).toEqual([{ role: 'member', managed_by_connection_id: null }]);
    const pm = await exec(
      sql`SELECT role, managed_by_connection_id FROM project_memberships WHERE user_id = ${userId} AND project_id = ${projectId}`,
    );
    expect(pm.rows).toEqual([{ role: 'viewer', managed_by_connection_id: null }]);
    const left = await exec(sql`SELECT
        (SELECT count(*)::int FROM sso_states WHERE connection_id = ${conn}) AS states,
        (SELECT count(*)::int FROM identities WHERE connection_id = ${conn}) AS identities,
        (SELECT count(*)::int FROM scim_groups WHERE connection_id = ${conn}) AS groups,
        (SELECT count(*)::int FROM scim_group_members WHERE group_id = ${group}) AS members,
        (SELECT count(*)::int FROM scim_tokens WHERE connection_id = ${conn}) AS tokens,
        (SELECT count(*)::int FROM sso_group_mappings WHERE connection_id = ${conn}) AS mappings,
        (SELECT count(*)::int FROM users WHERE id = ${userId}) AS users`);
    expect(left.rows[0]).toEqual({
      states: 0,
      identities: 0,
      groups: 0,
      members: 0,
      tokens: 0,
      mappings: 0,
      users: 1,
    });
  });

  it('bounds a state payload to 16 KiB and checks its kind', async () => {
    await expectRejection(
      exec(sql`INSERT INTO sso_states (key, kind, connection_id, payload, expires_at)
               VALUES ('finish:y', 'finish', ${oidcId}, jsonb_build_object('x', repeat('a', 17000)), now())`),
      /sso_states_payload_size/,
    );
    await expectRejection(
      exec(sql`INSERT INTO sso_states (key, kind, connection_id, expires_at)
               VALUES ('other:y', 'other', ${oidcId}, now())`),
      /sso_states_kind_check/,
    );
    await exec(sql`INSERT INTO sso_states (key, kind, connection_id, expires_at)
                   VALUES ('finish:z', 'finish', ${oidcId}, now())`);
    const r = await exec(sql`SELECT payload FROM sso_states WHERE key = 'finish:z'`);
    expect(r.rows).toEqual([{ payload: {} }]);
  });

  it('stores secrets only as encrypted envelopes (jsonb) and SHA-256 hashes (bytea)', async () => {
    const r = await exec(sql`SELECT table_name, column_name, data_type, is_nullable
                             FROM information_schema.columns
                             WHERE table_schema = 'public' AND table_name IN ${sql.raw(
                               `(${NEW_TABLES.map((t) => `'${t}'`).join(',')})`,
                             )}
                               AND column_name ~ '(secret|key|token|password|hash|enc)'
                             ORDER BY table_name, column_name`);
    expect(r.rows).toEqual([
      {
        table_name: 'scim_tokens',
        column_name: 'secret_hash',
        data_type: 'bytea',
        is_nullable: 'NO',
      },
      {
        table_name: 'sso_connections',
        column_name: 'secret_enc',
        data_type: 'jsonb',
        is_nullable: 'YES',
      },
      {
        table_name: 'sso_connections',
        column_name: 'sp_key_enc',
        data_type: 'jsonb',
        is_nullable: 'YES',
      },
      { table_name: 'sso_states', column_name: 'key', data_type: 'text', is_nullable: 'NO' },
    ]);
  });

  it('has exactly the indexes of sso-scim.md §13', async () => {
    const r = await exec(sql`SELECT tablename, indexname, indexdef FROM pg_indexes
                             WHERE schemaname = 'public'
                               AND (tablename IN ${sql.raw(
                                 `(${NEW_TABLES.map((t) => `'${t}'`).join(',')})`,
                               )} OR indexname LIKE '%managed_by%')
                             ORDER BY indexname`);
    const defs = Object.fromEntries(
      (r.rows as { indexname: string; indexdef: string }[]).map((row) => [
        row.indexname,
        row.indexdef.replace(/ USING btree/, '').replace(/public\./g, ''),
      ]),
    );
    expect(defs).toEqual({
      identities_connection_scim_external_id_key:
        'CREATE UNIQUE INDEX identities_connection_scim_external_id_key ON identities (connection_id, scim_external_id) WHERE (scim_external_id IS NOT NULL)',
      identities_connection_scim_user_name_key:
        'CREATE UNIQUE INDEX identities_connection_scim_user_name_key ON identities (connection_id, scim_user_name) WHERE (scim_user_name IS NOT NULL)',
      identities_connection_subject_key:
        'CREATE UNIQUE INDEX identities_connection_subject_key ON identities (connection_id, subject) WHERE (subject IS NOT NULL)',
      identities_connection_user_key:
        'CREATE UNIQUE INDEX identities_connection_user_key ON identities (connection_id, user_id)',
      identities_pkey: 'CREATE UNIQUE INDEX identities_pkey ON identities (id)',
      identities_user_idx: 'CREATE INDEX identities_user_idx ON identities (user_id)',
      memberships_managed_by_idx:
        'CREATE INDEX memberships_managed_by_idx ON memberships (managed_by_connection_id) WHERE (managed_by_connection_id IS NOT NULL)',
      project_memberships_managed_by_idx:
        'CREATE INDEX project_memberships_managed_by_idx ON project_memberships (managed_by_connection_id) WHERE (managed_by_connection_id IS NOT NULL)',
      scim_group_members_identity_idx:
        'CREATE INDEX scim_group_members_identity_idx ON scim_group_members (identity_id)',
      scim_group_members_group_id_identity_id_pk:
        'CREATE UNIQUE INDEX scim_group_members_group_id_identity_id_pk ON scim_group_members (group_id, identity_id)',
      scim_groups_display_name_key:
        'CREATE UNIQUE INDEX scim_groups_display_name_key ON scim_groups (connection_id, lower(display_name))',
      scim_groups_external_id_key:
        'CREATE UNIQUE INDEX scim_groups_external_id_key ON scim_groups (connection_id, external_id) WHERE (external_id IS NOT NULL)',
      scim_groups_pkey: 'CREATE UNIQUE INDEX scim_groups_pkey ON scim_groups (id)',
      scim_tokens_connection_idx:
        'CREATE INDEX scim_tokens_connection_idx ON scim_tokens (connection_id)',
      scim_tokens_created_by_idx:
        'CREATE INDEX scim_tokens_created_by_idx ON scim_tokens (created_by) WHERE (created_by IS NOT NULL)',
      scim_tokens_pkey: 'CREATE UNIQUE INDEX scim_tokens_pkey ON scim_tokens (id)',
      scim_tokens_prefix_idx: 'CREATE INDEX scim_tokens_prefix_idx ON scim_tokens (prefix)',
      sso_connections_created_by_idx:
        'CREATE INDEX sso_connections_created_by_idx ON sso_connections (created_by) WHERE (created_by IS NOT NULL)',
      sso_connections_name_key:
        'CREATE UNIQUE INDEX sso_connections_name_key ON sso_connections (lower(name))',
      sso_connections_pkey: 'CREATE UNIQUE INDEX sso_connections_pkey ON sso_connections (id)',
      sso_group_mappings_organization_idx:
        'CREATE INDEX sso_group_mappings_organization_idx ON sso_group_mappings (organization_id)',
      sso_group_mappings_pkey:
        'CREATE UNIQUE INDEX sso_group_mappings_pkey ON sso_group_mappings (id)',
      sso_group_mappings_project_idx:
        'CREATE INDEX sso_group_mappings_project_idx ON sso_group_mappings (project_id) WHERE (project_id IS NOT NULL)',
      sso_group_mappings_unique:
        'CREATE UNIQUE INDEX sso_group_mappings_unique ON sso_group_mappings (connection_id, group_value, organization_id, project_id) NULLS NOT DISTINCT',
      sso_states_connection_idx:
        'CREATE INDEX sso_states_connection_idx ON sso_states (connection_id)',
      sso_states_expires_idx: 'CREATE INDEX sso_states_expires_idx ON sso_states (expires_at)',
      sso_states_pkey: 'CREATE UNIQUE INDEX sso_states_pkey ON sso_states (key)',
    });
  });

  it('has the foreign keys of sso-scim.md §13 with their delete rules', async () => {
    const r = await exec(sql`SELECT c.conrelid::regclass::text AS tbl, a.attname AS col,
                                    c.confrelid::regclass::text AS ref, c.confdeltype AS del
                             FROM pg_constraint c
                             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
                             WHERE c.contype = 'f'
                               AND (c.conrelid::regclass::text IN ${sql.raw(
                                 `(${NEW_TABLES.map((t) => `'${t}'`).join(',')})`,
                               )} OR a.attname = 'managed_by_connection_id')
                             ORDER BY 1, 2`);
    // a = no action, c = cascade, n = set null
    expect(r.rows).toEqual([
      { tbl: 'identities', col: 'connection_id', ref: 'sso_connections', del: 'c' },
      { tbl: 'identities', col: 'user_id', ref: 'users', del: 'c' },
      { tbl: 'memberships', col: 'managed_by_connection_id', ref: 'sso_connections', del: 'n' },
      {
        tbl: 'project_memberships',
        col: 'managed_by_connection_id',
        ref: 'sso_connections',
        del: 'n',
      },
      { tbl: 'scim_group_members', col: 'group_id', ref: 'scim_groups', del: 'c' },
      { tbl: 'scim_group_members', col: 'identity_id', ref: 'identities', del: 'c' },
      { tbl: 'scim_groups', col: 'connection_id', ref: 'sso_connections', del: 'c' },
      { tbl: 'scim_tokens', col: 'connection_id', ref: 'sso_connections', del: 'c' },
      { tbl: 'scim_tokens', col: 'created_by', ref: 'users', del: 'n' },
      { tbl: 'sso_connections', col: 'created_by', ref: 'users', del: 'n' },
      { tbl: 'sso_group_mappings', col: 'connection_id', ref: 'sso_connections', del: 'c' },
      { tbl: 'sso_group_mappings', col: 'organization_id', ref: 'organizations', del: 'c' },
      { tbl: 'sso_group_mappings', col: 'project_id', ref: 'projects', del: 'c' },
      { tbl: 'sso_states', col: 'connection_id', ref: 'sso_connections', del: 'c' },
    ]);
  });
});
