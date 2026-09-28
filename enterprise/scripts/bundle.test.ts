// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertEnterpriseInputs, buildEnterprise } from './bundle';

/**
 * enterprise.md §12: a structural allowlist of the bundle's *inputs* (every file esbuild read is
 * one of enterprise/src). It is not a list of allowed packages: a runtime dependency of
 * package.json (zod, since 4C) is marked external, so esbuild never reads it and it is no input;
 * any other package the source imports as a value would be read from node_modules, and refused.
 * That the dependencies are the server's, at the same ranges, is plugin.test.ts's check.
 */
describe('the enterprise bundle (enterprise.md §12)', () => {
  it('holds only enterprise/src: core and npm packages reach it by type or stay external', async () => {
    const outfile = fileURLToPath(new URL('../.tmp/bundle-test/plugin.js', import.meta.url));
    const { inputs } = await buildEnterprise({ outfile });
    expect(inputs).toContain('src/plugin.ts');
    expect(inputs.filter((i) => !i.startsWith('src/'))).toEqual([]);
    // zod, the one runtime dependency, is imported from node_modules at run time, not copied in.
    const bundle = readFileSync(outfile, 'utf8');
    expect(bundle).toMatch(/^import \{[^}]*\} from "zod";$/m);
    expect(inputs.some((i) => i.includes('zod'))).toBe(false);
  }, 60_000);

  it.each([
    ['../server/src/license/verify.ts'],
    ['../packages/shared/src/index.ts'],
    ['../node_modules/.pnpm/drizzle-orm@0.45.3/node_modules/drizzle-orm/index.js'],
    ['../node_modules/.pnpm/zod@4.6.5/node_modules/zod/index.js'],
    ['node_modules/some-package/index.js'],
    ['scripts/bundle.ts'],
    ['src/../../server/src/main.ts'],
    ['src\\..\\..\\server\\src\\main.ts'],
  ])('refuses a bundle with the input %s, naming it', (input) => {
    expect(() => assertEnterpriseInputs(['src/plugin.ts', input])).toThrow(input);
  });

  it('accepts a bundle of enterprise/src only', () => {
    expect(() =>
      assertEnterpriseInputs(['src/plugin.ts', 'src/audit-routes.ts', 'src/sso-routes.ts']),
    ).not.toThrow();
  });
});
