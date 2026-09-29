import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Config } from '../config';
import { RESTORE_DATABASE, restoreEmbedded, restoreSwapping } from './restore';

// embedded-postgres.md §6: `main.js restore` reports why the embedded start failed, in words.

let root: string;
beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), 'qualor-restore-'));
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(root, { recursive: true, force: true });
});

const logger = { info: () => undefined, warn: () => undefined };

describe('restoreSwapping', () => {
  const recorder = (pgRestoreCode: number) => {
    const calls: string[] = [];
    return {
      calls,
      steps: {
        query: async (sql: string) => {
          calls.push(sql);
        },
        pgRestore: async (database: string) => {
          calls.push(`pg_restore -d ${database}`);
          return pgRestoreCode;
        },
      },
    };
  };

  it('keeps the existing database when the dump does not load (a truncated or wrong file)', async () => {
    const { calls, steps } = recorder(1);
    await expect(restoreSwapping(steps)).resolves.toBe(1);
    expect(calls).toEqual([
      `DROP DATABASE IF EXISTS ${RESTORE_DATABASE} WITH (FORCE)`,
      `CREATE DATABASE ${RESTORE_DATABASE}`,
      `pg_restore -d ${RESTORE_DATABASE}`,
      `DROP DATABASE IF EXISTS ${RESTORE_DATABASE} WITH (FORCE)`,
    ]);
    expect(calls.some((c) => /DROP DATABASE IF EXISTS qualor WITH/.test(c))).toBe(false);
  });

  it('loads beside the existing database, then replaces it', async () => {
    const { calls, steps } = recorder(0);
    await expect(restoreSwapping(steps)).resolves.toBe(0);
    expect(calls).toEqual([
      `DROP DATABASE IF EXISTS ${RESTORE_DATABASE} WITH (FORCE)`,
      `CREATE DATABASE ${RESTORE_DATABASE}`,
      `pg_restore -d ${RESTORE_DATABASE}`,
      'DROP DATABASE IF EXISTS qualor WITH (FORCE)',
      `ALTER DATABASE ${RESTORE_DATABASE} RENAME TO qualor`,
    ]);
  });
});

describe('restoreEmbedded', () => {
  it('prints the embedded start failure with its message and exits 1, instead of throwing', async () => {
    const postgresDir = path.join(root, 'pg');
    mkdirSync(postgresDir, { recursive: true });
    const config = {
      databaseUrl: null,
      embedded: { dataDir: path.join(root, 'data'), postgresDir },
    } as unknown as Config;
    const stderr: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    const isTTY = process.stdin.isTTY;
    process.stdin.isTTY = false;
    try {
      await expect(restoreEmbedded(config, logger)).resolves.toBe(1);
    } finally {
      process.stdin.isTTY = isTTY;
    }
    expect(stderr.join('')).toContain(
      `qualor-server: DATABASE_URL is not set and no embedded PostgreSQL was found in ${postgresDir}; set DATABASE_URL`,
    );
  });
});
