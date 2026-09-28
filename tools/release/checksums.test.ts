import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parseSums, releaseFiles, sha256sums, sumsProblems } from './checksums';

let dir = '';
afterEach(() => rmSync(dir, { recursive: true, force: true }));
function release(files: Record<string, string>): string {
  dir = mkdtempSync(path.join(tmpdir(), 'qualor-sums-'));
  for (const [f, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    writeFileSync(path.join(dir, f), content);
  }
  return dir;
}

describe('SHA256SUMS (release.md §3, §12)', () => {
  it('lists every file but SHA256SUMS and its bundle, sorted, in sha256sum format', async () => {
    release({ 'cli/b': 'B', 'a.json': 'A', SHA256SUMS: 'old', 'SHA256SUMS.bundle': '{}' });
    expect(releaseFiles(dir)).toEqual(['a.json', 'cli/b']);
    // The SHA-256 of the strings "A" and "B".
    expect(await sha256sums(dir)).toBe(
      '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd  a.json\n' +
        'df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c  cli/b\n',
    );
  });

  it('names a changed, a missing and an unlisted file', async () => {
    release({ 'a.json': 'A', 'cli/b': 'B' });
    const sums = await sha256sums(dir);
    writeFileSync(path.join(dir, 'a.json'), 'A!');
    rmSync(path.join(dir, 'cli/b'));
    writeFileSync(path.join(dir, 'extra.txt'), 'X');
    expect(await sumsProblems(dir, sums)).toEqual([
      'a.json: the SHA-256 does not match SHA256SUMS',
      'cli/b: listed in SHA256SUMS but missing',
      'extra.txt: not listed in SHA256SUMS',
    ]);
  });

  it('refuses a malformed line, a path that leaves the directory, and a symbolic link', () => {
    expect(() => parseSums('abc  file\n')).toThrow(/line 1/);
    expect(() => parseSums(`${'0'.repeat(64)}  ../etc/passwd\n`)).toThrow(
      /leaves the release directory/,
    );
    release({ 'a.json': 'A' });
    try {
      symlinkSync(path.join(dir, 'a.json'), path.join(dir, 'link'));
    } catch {
      return; // Windows without the symlink privilege: nothing to check here.
    }
    expect(() => releaseFiles(dir)).toThrow('link: not a regular file');
  });

  it('names a listed directory instead of crashing with EISDIR', async () => {
    release({ 'a.json': 'A', 'cli/b': 'B' });
    const sums = `${await sha256sums(dir)}${'0'.repeat(64)}  cli\n`;
    expect(await sumsProblems(dir, sums)).toEqual([
      'cli: listed in SHA256SUMS but not a regular file',
    ]);
  });
});
