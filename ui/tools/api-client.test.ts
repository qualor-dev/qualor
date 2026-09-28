import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const CLI = fileURLToPath(
  new URL('../node_modules/openapi-typescript/bin/cli.js', import.meta.url),
);
const SPEC = fileURLToPath(new URL('../../server/openapi.json', import.meta.url));
const SCHEMA = fileURLToPath(new URL('../src/app/api/schema.ts', import.meta.url));

/**
 * api.md §6.1: the UI's generated client must match server/openapi.json. After `pnpm openapi`,
 * run `pnpm --filter @qualor/ui api` and commit `ui/src/app/api/schema.ts`.
 */
describe('generated API client (api.md §6)', () => {
  it('ui/src/app/api/schema.ts is current with server/openapi.json', () => {
    const generated = execFileSync(process.execPath, [CLI, SPEC], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    expect(generated.length).toBeGreaterThan(1000);
    expect(readFileSync(SCHEMA, 'utf8') === generated, 'run: pnpm --filter @qualor/ui api').toBe(
      true,
    );
  });
});
