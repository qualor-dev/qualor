import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/** sso-scim.md §3.4: a bump of any of these is a reviewed change that reruns the §19.3 corpus. */
const PINNED: Record<string, string> = {
  'openid-client': '6.8.8',
  oauth4webapi: '3.8.8',
  jose: '6.2.12',
  '@node-saml/node-saml': '5.1.0',
  'xml-crypto': '6.3.2',
  '@xmldom/xmldom': '0.8.15',
};

const root = resolve(import.meta.dirname, '../../..');
const lock = readFileSync(resolve(root, 'pnpm-lock.yaml'), 'utf8');
const serverPkg = JSON.parse(readFileSync(resolve(root, 'server/package.json'), 'utf8')) as {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};
const rootPkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as {
  pnpm?: { overrides?: Record<string, string> };
};

/** Every `name@version` key of the lockfile's `packages:` section for one package. */
function lockedVersions(name: string): string[] {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const pattern = new RegExp(`^  '?${escaped}@(\\d+\\.\\d+\\.\\d+)'?:`, 'gm');
  return [...new Set([...lock.matchAll(pattern)].map((m) => m[1]!))];
}

describe('SSO library pins (sso-scim.md §3.1)', () => {
  it.each(Object.entries(PINNED))('%s resolves to exactly %s', (name, version) => {
    expect(lockedVersions(name)).toEqual([version]);
  });

  it('lists the two libraries without a range, and the test-only ones as dev dependencies', () => {
    expect(serverPkg.dependencies['openid-client']).toBe('6.8.8');
    expect(serverPkg.dependencies['@node-saml/node-saml']).toBe('5.1.0');
    expect(serverPkg.devDependencies.jose).toBe('6.2.12');
    expect(serverPkg.devDependencies['xml-crypto']).toBe('6.3.2');
  });

  it('overrides @xmldom/xmldom to the release that fixes the September 2026 advisories', () => {
    expect(rootPkg.pnpm?.overrides?.['@xmldom/xmldom']).toBe('0.8.15');
  });
});
