import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import { sha256sums } from './checksums';
import { parseVerifyArgs, resolveVerifyKey, VERIFY_USAGE, verifyRelease } from './verify';

let dir = '';
afterEach(() => rmSync(dir, { recursive: true, force: true }));
function tempRelease(): string {
  mkdirSync(path.join(REPO_ROOT, '.tmp'), { recursive: true });
  dir = mkdtempSync(path.join(REPO_ROOT, '.tmp', 'verify-'));
  return dir;
}

describe('verifyRelease (release.md §12)', () => {
  it('checks the signature, then every hash, and reports both', async () => {
    tempRelease();
    writeFileSync(path.join(dir, 'a.txt'), 'A');
    writeFileSync(path.join(dir, 'SHA256SUMS'), await sha256sums(dir));
    writeFileSync(path.join(dir, 'SHA256SUMS.bundle'), '{}');
    const calls: string[] = [];
    const good = {
      verifyBlob: (pub: string, file: string) => {
        calls.push(`${pub} ${file}`);
        return true;
      },
    };
    expect(await verifyRelease(dir, path.join(dir, 'cosign.pub'), good)).toEqual([]);
    expect(calls[0]).toMatch(/cosign\.pub \/work\/\.tmp\/verify-.*\/SHA256SUMS$/);
    writeFileSync(path.join(dir, 'a.txt'), 'changed');
    expect(
      await verifyRelease(dir, path.join(dir, 'cosign.pub'), { verifyBlob: () => false }),
    ).toEqual([
      'SHA256SUMS: the signature does not verify with cosign.pub',
      'a.txt: the SHA-256 does not match SHA256SUMS',
    ]);
  });

  it('names a listed directory instead of crashing (EISDIR)', async () => {
    tempRelease();
    mkdirSync(path.join(dir, 'cli'));
    writeFileSync(path.join(dir, 'cli', 'b'), 'B');
    writeFileSync(path.join(dir, 'SHA256SUMS'), `${await sha256sums(dir)}${'0'.repeat(64)}  cli\n`);
    writeFileSync(path.join(dir, 'SHA256SUMS.bundle'), '{}');
    expect(
      await verifyRelease(dir, path.join(dir, 'cosign.pub'), { verifyBlob: () => true }),
    ).toEqual(['cli: listed in SHA256SUMS but not a regular file']);
  });

  it('names a missing SHA256SUMS or bundle', async () => {
    tempRelease();
    expect(
      await verifyRelease(dir, path.join(dir, 'cosign.pub'), { verifyBlob: () => true }),
    ).toEqual(['SHA256SUMS is missing', 'SHA256SUMS.bundle is missing']);
  });
});

describe('the key of pnpm release:verify (release.md §12, ruling R-VERIFYKEY)', () => {
  it('takes one directory and --key or --self-check, and refuses everything else', () => {
    expect(parseVerifyArgs(['d'])).toEqual({ dir: 'd', key: undefined, selfCheck: false });
    expect(parseVerifyArgs(['--', 'd', '--key', 'k.pub'])).toEqual({
      dir: 'd',
      key: 'k.pub',
      selfCheck: false,
    });
    expect(parseVerifyArgs(['--self-check', 'd'])).toEqual({
      dir: 'd',
      key: undefined,
      selfCheck: true,
    });
    for (const bad of [
      [],
      ['--key', 'k'],
      ['d', '--key'],
      ['d', '--key', '--self-check'],
      ['d', '--key', 'k', '--self-check'],
      ['d', 'e'],
      ['d', '--kye', 'k'],
      ['d', '--insecure'],
      ['d', '--self-check', '--self-check'],
      ['d', '--key', 'a', '--key', 'b'],
    ]) {
      expect(() => parseVerifyArgs(bad), bad.join(' ')).toThrow(VERIFY_USAGE);
    }
  });

  it('uses --key, else only the git-tracked root cosign.pub, never the directory’s by default', () => {
    const root = tempRelease();
    const release = path.join(root, 'release');
    mkdirSync(release);
    writeFileSync(path.join(release, 'cosign.pub'), 'dir key');
    writeFileSync(path.join(root, 'given.pub'), 'given');
    expect(
      resolveVerifyKey({ dir: release, key: path.join(root, 'given.pub'), selfCheck: false }, root),
    ).toEqual({ pub: path.join(root, 'given.pub'), source: '--key' });
    // No committed key: refused, even though the directory carries one.
    expect(() => resolveVerifyKey({ dir: release, selfCheck: false }, root, () => true)).toThrow(
      /--key <cosign\.pub>/,
    );
    writeFileSync(path.join(root, 'cosign.pub'), 'root key');
    expect(() => resolveVerifyKey({ dir: release, selfCheck: false }, root, () => false)).toThrow(
      /git tracks no cosign\.pub/,
    );
    expect(resolveVerifyKey({ dir: release, selfCheck: false }, root, () => true)).toMatchObject({
      pub: path.join(root, 'cosign.pub'),
      source: expect.stringMatching(/git-tracked/) as unknown,
    });
    const self = resolveVerifyKey({ dir: release, selfCheck: true }, root, () => true);
    expect(self.pub).toBe(path.join(release, 'cosign.pub'));
    expect(self.warning).toMatch(/WARNING/);
  });

  it('names a --key that is missing or a directory', () => {
    const root = tempRelease();
    expect(() =>
      resolveVerifyKey({ dir: root, key: path.join(root, 'nope.pub'), selfCheck: false }),
    ).toThrow(/no such key file/);
    expect(() => resolveVerifyKey({ dir: root, key: root, selfCheck: false })).toThrow(
      /not a regular file/,
    );
  });

  it('the CLI prints the key it used and refuses unknown arguments', () => {
    const source = readFileSync('tools/release/verify-cli.ts', 'utf8');
    expect(source).toContain('parseVerifyArgs(process.argv.slice(2))');
    expect(source).toMatch(/process\.stdout\.write\(`key: \$\{k\.pub\} \(\$\{k\.source\}\)\\n`\)/);
  });
});
