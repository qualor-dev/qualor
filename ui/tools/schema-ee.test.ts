import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const CLI = fileURLToPath(
  new URL('../node_modules/openapi-typescript/bin/cli.js', import.meta.url),
);
/** Written by `pnpm --filter @qualor/enterprise openapi` (its own staleness test checks it). */
const SPEC = fileURLToPath(new URL('../../enterprise/openapi.json', import.meta.url));
const SCHEMA = fileURLToPath(new URL('../src/app/api/schema-ee.ts', import.meta.url));

/**
 * rbac-audit.md §17: the UI's types for the enterprise API (`/api/v0/ee/*`) must match
 * the plugin's OpenAPI document. After `pnpm --filter @qualor/enterprise openapi`, run
 * `pnpm --filter @qualor/ui api:ee` and commit `ui/src/app/api/schema-ee.ts`.
 */
describe('generated enterprise API types (rbac-audit.md §17)', () => {
  it('ui/src/app/api/schema-ee.ts is current with the enterprise OpenAPI document', () => {
    const generated = execFileSync(process.execPath, [CLI, SPEC], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    expect(generated).toContain('"/api/v0/ee/audit/events"');
    // rbac-audit.md §16: the grant routes are core routes since 5B (schema.ts), not the plugin's.
    expect(generated).not.toContain('/api/v0/ee/rbac/');
    expect(readFileSync(SCHEMA, 'utf8') === generated, 'run: pnpm --filter @qualor/ui api:ee').toBe(
      true,
    );
  });

  it('names no enterprise path in the generated source (ui/src never does)', () => {
    expect(readFileSync(SCHEMA, 'utf8').toLowerCase()).not.toContain('enterprise/');
  });
});
