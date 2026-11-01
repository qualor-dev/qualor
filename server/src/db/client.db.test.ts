import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { createDatabase, type Database } from './client';

/**
 * The URL with a startup `options` parameter, the way a database or role setting would set the
 * session default. The SQL `SET` in `createDatabase` must still win over it.
 */
function withOptions(url: string, options: string): string {
  const separator = new URL(url).search === '' ? '?' : '&';
  return `${url}${separator}options=${encodeURIComponent(options)}`;
}

describe('createDatabase: every pooled connection', () => {
  let t: TestDatabase;
  const opened: Database[] = [];
  const open = (url: string, options: Parameters<typeof createDatabase>[1]) => {
    const database = createDatabase(url, options);
    opened.push(database);
    return database;
  };

  beforeAll(async () => {
    t = await createTestDatabase({ migrated: false });
  });
  afterAll(async () => {
    await Promise.all(opened.map((database) => database.close()));
    await t.close();
  });

  it('uses ISO DateStyle whatever the server default is', async () => {
    const database = open(withOptions(t.url, '-c DateStyle=SQL,DMY'), { max: 1 });
    const show = await database.pool.query<{ DateStyle: string }>('SHOW DateStyle');
    expect(show.rows[0]!.DateStyle).toBe('ISO, MDY');
    const date = await database.db.execute<{ d: string }>(sql`SELECT DATE '2026-10-21'::text AS d`);
    expect(date.rows[0]!.d).toBe('2026-10-21');
  });

  it('keeps DateStyle ISO and the session read-only when readOnly is set', async () => {
    const database = open(withOptions(t.url, '-c DateStyle=SQL,DMY'), {
      max: 1,
      readOnly: true,
    });
    const show = await database.pool.query<{ DateStyle: string }>('SHOW DateStyle');
    expect(show.rows[0]!.DateStyle).toBe('ISO, MDY');
    await expect(
      database.pool.query('CREATE TABLE client_db_read_only_probe (id int)'),
    ).rejects.toThrow(/read-only/);
  });
});
