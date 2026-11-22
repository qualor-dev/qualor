import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { bundledPackages, noticesText } from './notices';

describe('bundled package notices', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const pkg = (name: string, files: Record<string, string>): string => {
    const at = path.join(dir, 'node_modules', name);
    mkdirSync(at, { recursive: true });
    writeFileSync(
      path.join(at, 'package.json'),
      JSON.stringify({ name, version: '1.0.0', license: 'MIT' }),
    );
    for (const [f, text] of Object.entries(files)) writeFileSync(path.join(at, f), text);
    return `node_modules/${name}/index.js`;
  };

  it('finds LICENSE-MIT, LICENSE.md, COPYING and LICENCE style files', () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-notices-'));
    const inputs = [
      pkg('a', { 'LICENSE-MIT': 'text of a' }),
      pkg('b', { 'LICENSE.md': 'text of b' }),
      pkg('c', { COPYING: 'text of c' }),
      pkg('d', { LICENCE: 'text of d' }),
    ];
    const text = noticesText(bundledPackages(inputs, dir));
    for (const t of ['text of a', 'text of b', 'text of c', 'text of d']) expect(text).toContain(t);
  });

  it('fails the build for a package without a licence file', () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-notices-'));
    const inputs = [pkg('nolicence', { 'README.md': 'x' })];
    expect(() => bundledPackages(inputs, dir)).toThrow(/nolicence .*no licence file/);
  });
});
