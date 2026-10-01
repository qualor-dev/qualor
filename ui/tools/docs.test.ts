import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The built-in guide (`ui/src/app/docs/guide.ts`) imports every page of `docs/guide/` by name: a
 * page added to the guide and not to that list would be missing from every server's /docs.
 */
const GUIDE = fileURLToPath(new URL('../../docs/guide', import.meta.url));
const REGISTRY = fileURLToPath(new URL('../src/app/docs/guide.ts', import.meta.url));

describe('the built-in user guide', () => {
  it('bundles every page of docs/guide, each under its own name', () => {
    const pages = readdirSync(GUIDE)
      .filter((n) => n.endsWith('.md'))
      .map((n) => n.slice(0, -3))
      .sort();
    const source = readFileSync(REGISTRY, 'utf8');
    const entries = [
      ...source.matchAll(
        /^ {2}'?([\w-]+)'?: \(\) => import\('\.\.\/\.\.\/\.\.\/\.\.\/docs\/guide\/([\w-]+)\.md'\),$/gm,
      ),
    ];
    expect(entries.map((m) => m[1])).toEqual(entries.map((m) => m[2]));
    expect(entries.map((m) => m[2]).sort()).toEqual(pages);
  });
});
