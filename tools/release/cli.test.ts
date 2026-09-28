import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { copyCliSources } from './cli';

/** A fake repository whose sources.json has two bun entries and one other. */
function fakeRoot(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(tmpdir(), 'qualor-cli-sources-'));
  mkdirSync(path.join(root, 'deploy', 'scanner'), { recursive: true });
  mkdirSync(path.join(root, '.tmp', 'scanner-sources'), { recursive: true });
  const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
  const entry = (file: string, component: string, content: string) => ({
    file,
    component,
    sha256: sha(content),
  });
  writeFileSync(
    path.join(root, 'deploy', 'scanner', 'sources.json'),
    JSON.stringify({
      entries: [
        entry('bun.tar.gz', 'bun', 'BUN'),
        entry('webkit.tar', 'bun', 'WEBKIT'),
        entry('pmd.zip', 'pmd', 'PMD'),
      ],
    }),
  );
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(path.join(root, '.tmp', 'scanner-sources', name), content);
  }
  return root;
}

let root = '';
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('cli-sources (release.md §4, ruling L1)', () => {
  it('copies every bun entry, checked, with its own SHA256SUMS, and nothing else', async () => {
    root = fakeRoot({ 'bun.tar.gz': 'BUN', 'webkit.tar': 'WEBKIT', 'pmd.zip': 'PMD' });
    const release = path.join(root, 'release');
    const written = await copyCliSources(
      release,
      root,
      (r) => JSON.parse(readFileSync(path.join(r, 'deploy/scanner/sources.json'), 'utf8')).entries,
    );
    expect(written).toEqual([
      'cli-sources/SHA256SUMS',
      'cli-sources/bun.tar.gz',
      'cli-sources/webkit.tar',
    ]);
    expect(readFileSync(path.join(release, 'cli-sources', 'SHA256SUMS'), 'utf8')).toMatch(
      /^[0-9a-f]{64} {2}bun\.tar\.gz\n[0-9a-f]{64} {2}webkit\.tar\n$/,
    );
  });

  it('lists the sources in byte order, not locale order', async () => {
    root = fakeRoot({ 'alpha.tar': 'A', 'Zeta.tar': 'Z' });
    const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
    const written = await copyCliSources(path.join(root, 'release'), root, () => [
      { file: 'alpha.tar', component: 'bun', sha256: sha('A') },
      { file: 'Zeta.tar', component: 'bun', sha256: sha('Z') },
    ]);
    expect(written).toEqual([
      'cli-sources/SHA256SUMS',
      'cli-sources/Zeta.tar',
      'cli-sources/alpha.tar',
    ]);
  });

  it('names pnpm deploy:sources when a Bun source is missing or wrong', async () => {
    root = fakeRoot({ 'bun.tar.gz': 'BUN' });
    const load = (r: string) =>
      JSON.parse(readFileSync(path.join(r, 'deploy/scanner/sources.json'), 'utf8')).entries;
    await expect(copyCliSources(path.join(root, 'r1'), root, load)).rejects.toThrow(
      '.tmp/scanner-sources/webkit.tar is missing or wrong: run pnpm deploy:sources',
    );
    writeFileSync(path.join(root, '.tmp', 'scanner-sources', 'webkit.tar'), 'CHANGED');
    await expect(copyCliSources(path.join(root, 'r2'), root, load)).rejects.toThrow(
      /webkit\.tar is missing or wrong/,
    );
  });
});
