import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { databaseUrl } from '../../test/urls';
import { sweepE2eDatabases } from './sweep';

const e2eName = () => `qualor_e2e_${randomBytes(6).toString('hex')}`;

describe('sweepE2eDatabases', () => {
  const adminUrl = inject('databaseAdminUrl');
  const admin = new pg.Client({ connectionString: adminUrl });
  const idle = e2eName();
  const busy = e2eName();
  const other = `qualor_sweep_other_${randomBytes(4).toString('hex')}`;
  let holder: pg.Client;

  beforeAll(async () => {
    await admin.connect();
    for (const name of [idle, busy, other]) await admin.query(`CREATE DATABASE ${name}`);
    holder = new pg.Client({ connectionString: databaseUrl(adminUrl, busy) });
    await holder.connect();
  });
  afterAll(async () => {
    await holder.end();
    for (const name of [idle, busy, other]) await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    await admin.end();
  });

  it('drops leftover e2e databases nobody is connected to, and nothing else', async () => {
    const dropped = await sweepE2eDatabases(admin);
    expect(dropped).toContain(idle);
    expect(dropped).not.toContain(busy);
    const { rows } = await admin.query<{ datname: string }>(
      'SELECT datname FROM pg_database WHERE datname = ANY($1)',
      [[idle, busy, other]],
    );
    expect(rows.map((r) => r.datname).sort()).toEqual([busy, other].sort());
  });
});
