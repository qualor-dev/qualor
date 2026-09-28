import { describe, expect, it } from 'vitest';
import { ADMIN_PASSWORD, createTestContext, login } from '../../test/app';
import { testConfig } from '../../test/config';
import { createTestDatabase } from '../../test/db';
import { T0, testPayload } from '../../test/license';
import { MIGRATIONS_DIR } from '../../test/paths';
import { buildApp } from '../app';
import { createDatabase, type Database } from '../db/client';
import { readinessCheck } from '../db/migrate';
import { createLogger } from '../http/logger';
import { VERSION } from '../index';
import { createEdition, NO_PLUGINS } from '../license/edition';

async function readyz({ db }: Database): Promise<number> {
  const app = await buildApp({
    config: testConfig(),
    db,
    logger: createLogger('silent'),
    checkReady: readinessCheck(db, MIGRATIONS_DIR),
  });
  try {
    return (await app.inject({ method: 'GET', url: '/readyz' })).statusCode;
  } finally {
    await app.close();
  }
}

describe('/readyz against PostgreSQL', () => {
  it('is 200 when migrations are current and 503 when they are pending', async () => {
    const migrated = await createTestDatabase();
    const empty = await createTestDatabase({ migrated: false });
    try {
      expect(await readyz(migrated)).toBe(200);
      expect(await readyz(empty)).toBe(503);
    } finally {
      await migrated.close();
      await empty.close();
    }
  });

  it('is 503 when the database is unreachable', async () => {
    const unreachable = createDatabase('postgres://nobody:nothing@127.0.0.1:1/none', { max: 1 });
    try {
      expect(await readyz(unreachable)).toBe(503);
    } finally {
      await unreachable.close();
    }
  });
});

describe('GET /system/info with a licence (enterprise.md §7.3)', () => {
  it('reports the enterprise edition, its active features and extensions, and no limits', async () => {
    const license = testPayload({ features: ['llm.fix-quota'] });
    const edition = createEdition({
      boot: {
        source: 'environment',
        keyHash: 'boot-key-hash',
        verification: { ok: true, kid: 'test-a', license },
      },
      plugins: {
        ...NO_PLUGINS,
        features: new Set(['llm.fix-quota']),
        extensions: [
          {
            feature: 'llm.fix-quota',
            extension: {
              point: 'settings.nav',
              id: 'quota',
              label: 'Quota',
              path: '/settings/ee/quota',
            },
          },
        ],
      },
      now: () => T0,
    });
    const ctx = await createTestContext({ edition });
    try {
      const session = await login(ctx, 'admin', ADMIN_PASSWORD);
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/system/info',
        headers: session.headers,
      });
      expect(res.json()).toMatchObject({
        edition: 'enterprise',
        features: ['llm.fix-quota'],
        extensions: [{ id: 'quota', path: '/settings/ee/quota' }],
      });
      // enterprise.md §7.3: no organisation limit, so no `limits` member.
      expect(Object.keys(res.json() as object).sort()).toEqual([
        'edition',
        'extensions',
        'features',
        'version',
      ]);
      // Only the fields of the spec: no customer, licence id, key id or key hash (§7.3).
      expect(res.json()).toEqual({
        version: VERSION,
        edition: 'enterprise',
        features: ['llm.fix-quota'],
        extensions: [
          { point: 'settings.nav', id: 'quota', label: 'Quota', path: '/settings/ee/quota' },
        ],
      });
      for (const secret of [license.customer, license.id, 'test-a', 'boot-key-hash']) {
        expect(res.body).not.toContain(secret);
      }
    } finally {
      await ctx.close();
    }
  });
});
