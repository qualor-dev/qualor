import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(import.meta.dirname, '..', '..', '..');
/** The code that runs in production (tests set the flag to clean up, and are left out). */
const PRODUCTION_DIRS = [
  'server/src',
  'server/drizzle',
  'server/scripts',
  'enterprise/src',
  'enterprise/scripts',
  'cli/src',
  'cli/scripts',
  'packages/shared/src',
  'ui/src',
  'tools',
];
const SKIPPED = new Set(['node_modules', 'dist', '.angular']);

function productionFiles(dir: string): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries.flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return SKIPPED.has(entry.name) ? [] : productionFiles(path);
    return /\.(test|spec)\.[cm]?[jt]s$/.test(entry.name) ? [] : [path];
  });
}

describe('the prune flag (rbac-audit.md §7.3, §11.1; ruling AU2)', () => {
  it('is set only by pruneAuditEvents; the migration only reads it', () => {
    const mentions = PRODUCTION_DIRS.flatMap((dir) => productionFiles(join(ROOT, dir)))
      .filter((file) => readFileSync(file).toString('utf8').includes('audit_prune'))
      .map((file) => relative(ROOT, file).replaceAll('\\', '/'))
      .sort();
    expect(mentions).toEqual([
      'server/drizzle/0005_rbac_audit.sql',
      'server/src/audit/retention.ts',
    ]);

    const migration = readFileSync(join(ROOT, 'server/drizzle/0005_rbac_audit.sql'), 'utf8');
    const lines = migration.split('\n').filter((line) => line.includes('audit_prune'));
    for (const line of lines) {
      const code = line.replace(/--.*$/, '');
      if (!code.includes('audit_prune')) continue;
      // Bound to the transaction that set it (§7.3): a session value never matches.
      expect(code).toMatch(
        /current_setting\('qualor\.audit_prune', true\) = txid_current\(\)::text/,
      );
      expect(code).not.toMatch(/set_config|\bSET\b/i);
    }

    // Only the transaction-local form (is_local = true), set to this transaction's id and cleared.
    const retention = readFileSync(join(ROOT, 'server/src/audit/retention.ts'), 'utf8');
    const sets = retention.split('\n').filter((line) => line.includes('set_config('));
    expect(sets.map((line) => line.trim())).toEqual([
      "await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);",
      "await tx.execute(sql`SELECT set_config('qualor.audit_prune', '', true)`);",
    ]);
    expect(retention).not.toMatch(/SET LOCAL|SET SESSION|SET qualor/);
  });
});
