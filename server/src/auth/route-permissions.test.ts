import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { isOrganizationPermission, isProjectPermission } from './policy';
import { ROUTE_PERMISSIONS } from './route-permissions';

// The design specs are kept outside the public repository; their parity checks run where they exist.
const SPEC = new URL('../../../docs/spec/rbac-audit.md', import.meta.url);

/** rbac-audit.md §3.4: `| \`METHOD /path\` | \`rule\` |` rows. */
function specRows(): Record<string, string> {
  const text = readFileSync(SPEC, 'utf8');
  const start = text.indexOf('### 3.4 The route matrix');
  const end = text.indexOf('\n### ', start + 1);
  if (start < 0 || end < 0) throw new Error('rbac-audit.md: §3.4 The route matrix not found');
  const rows: Record<string, string> = {};
  for (const m of text
    .slice(start, end)
    .matchAll(/^\|\s*`((?:GET|POST|PUT|PATCH|DELETE) [^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*$/gm)) {
    if (m[1]! in rows) throw new Error(`rbac-audit.md §3.4 lists ${m[1]!} twice`);
    rows[m[1]!] = m[2]!;
  }
  return rows;
}

describe('the route rules (rbac-audit.md §3.4)', () => {
  it.runIf(existsSync(SPEC))('equals the spec table', () => {
    expect(ROUTE_PERMISSIONS).toEqual(specRows());
  });

  it('names only real permissions', () => {
    for (const [id, rule] of Object.entries(ROUTE_PERMISSIONS)) {
      const p = rule.startsWith('list:') ? rule.slice(5) : rule;
      if (['public', 'authenticated', 'self', 'instance-admin'].includes(p)) continue;
      expect(isOrganizationPermission(p) || isProjectPermission(p), `${id}: ${rule}`).toBe(true);
    }
  });
});
