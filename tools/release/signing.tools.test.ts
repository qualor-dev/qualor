import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import { sha256sums, SUMS, SUMS_BUNDLE } from './checksums';
import { signBlobArgs, verifyBlobArgs } from './cosign';
import { generateKeys, removeKeys, type Keys } from './keys';
import { runTool, toWork } from './toolbox';
import { cosignVerifier, verifyRelease } from './verify';

const dir = path.join(REPO_ROOT, '.tmp', 'release-test', randomBytes(4).toString('hex'));
const rel = path.join(dir, 'release');
const binary = path.join(rel, 'cli', 'qualor-0.0.0-linux-x64');
let keys: Keys | undefined;
let other: Keys | undefined;
const pubOf = (k: Keys | undefined) => path.join(k!.hostDir, 'cosign.pub');

beforeAll(async () => {
  mkdirSync(path.dirname(binary), { recursive: true });
  writeFileSync(binary, 'binary');
  writeFileSync(path.join(rel, 'release-manifest.json'), '{}\n');
  keys = generateKeys(path.join(dir, 'keys'));
  other = generateKeys(path.join(dir, 'other'));
  writeFileSync(path.join(rel, SUMS), await sha256sums(rel));
  const args = signBlobArgs(
    keys.key,
    toWork(path.join(rel, SUMS)),
    toWork(path.join(rel, SUMS_BUNDLE)),
    { offline: true },
  );
  const r = runTool('cosign', args, { env: { COSIGN_PASSWORD: keys.password } });
  expect(r.code, r.stderr).toBe(0);
});
afterAll(() => {
  if (keys) removeKeys(keys);
  if (other) removeKeys(other);
  rmSync(dir, { recursive: true, force: true });
  // release.md §7.3: the throwaway private keys are gone when the test ends.
  expect(existsSync(dir)).toBe(false);
});

describe('cosign with no network (release.md §7.2, §15 item 5)', () => {
  it('verifies the signed SHA256SUMS with the right key', async () => {
    expect(await verifyRelease(rel, pubOf(keys), cosignVerifier)).toEqual([]);
  });

  it('fails with another key', () => {
    const args = verifyBlobArgs(
      other!.pub,
      toWork(path.join(rel, SUMS)),
      toWork(path.join(rel, SUMS_BUNDLE)),
    );
    expect(runTool('cosign', args).code).not.toBe(0);
  });

  it('names a changed file, and fails the signature when SHA256SUMS changes', async () => {
    writeFileSync(binary, 'binarY');
    expect(await verifyRelease(rel, pubOf(keys), cosignVerifier)).toEqual([
      'cli/qualor-0.0.0-linux-x64: the SHA-256 does not match SHA256SUMS',
    ]);
    writeFileSync(path.join(rel, SUMS), await sha256sums(rel));
    const problems = await verifyRelease(rel, pubOf(keys), cosignVerifier);
    expect(problems).toEqual(['SHA256SUMS: the signature does not verify with cosign.pub']);
  });
});
