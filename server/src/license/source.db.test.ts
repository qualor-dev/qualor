import { sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { testConfig } from '../../test/config';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { signTest, testPayload, testSigner, verifyWith } from '../../test/license';
import { instanceSettings } from '../db/schema';
import { LicenseFileError, readBootLicense } from './source';
import { keyHash } from './token';

describe('readBootLicense (enterprise.md §6)', () => {
  let database: TestDatabase;
  const signer = testSigner();
  const key = signTest(signer);
  const dir = mkdtempSync(path.join(tmpdir(), 'qualor-license-'));

  beforeAll(async () => {
    database = await createTestDatabase();
  });
  afterEach(async () => {
    await database.db.delete(instanceSettings);
  });
  afterAll(async () => {
    await database.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const read = (license: { text?: string; file?: string }) =>
    readBootLicense(
      testConfig({ license: { text: license.text ?? null, file: license.file ?? null } }),
      database.db,
      verifyWith(signer),
    );

  it('is none without any source', async () => {
    expect(await read({})).toEqual({ source: null, keyHash: null, verification: null });
  });

  it('boots a pre-5A key from QUALOR_LICENSE with a licence that has no organizations (enterprise.md §17 item 9)', async () => {
    const payload = testPayload();
    const input = `QLK1.${signer.kid}.${Buffer.from(JSON.stringify({ ...payload, organizations: 10 })).toString('base64url')}`;
    const old = `${input}.${sign(null, Buffer.from(input), signer.privateKey).toString('base64url')}`;
    const boot = await read({ text: old });
    expect(boot.verification).toEqual({ ok: true, kid: signer.kid, license: payload });
  });

  it('prefers QUALOR_LICENSE over a stored key', async () => {
    await database.db.insert(instanceSettings).values({
      key: 'license',
      value: { key: 'QLK1.other.x.y', savedAt: new Date().toISOString(), savedBy: 'u' },
    });
    const boot = await read({ text: key });
    expect(boot.source).toBe('environment');
    expect(boot.keyHash).toBe(keyHash(key));
    expect(boot.verification).toMatchObject({ ok: true });
  });

  it('reads a licence file that ends with a newline', async () => {
    const file = path.join(dir, 'license');
    writeFileSync(file, `${key}\n`);
    const boot = await read({ file });
    expect(boot.source).toBe('file');
    expect(boot.keyHash).toBe(keyHash(key));
    expect(boot.verification).toMatchObject({ ok: true });
  });

  it.each([
    ['missing', () => path.join(dir, 'missing')],
    [
      'a directory',
      () => {
        const d = path.join(dir, 'a-dir');
        mkdirSync(d, { recursive: true });
        return d;
      },
    ],
    [
      'over 16 KiB',
      () => {
        const f = path.join(dir, 'big');
        writeFileSync(f, 'A'.repeat(16 * 1024 + 1));
        return f;
      },
    ],
  ])('stops the boot when the file is %s, naming QUALOR_LICENSE_FILE', async (_what, make) => {
    await expect(read({ file: make() })).rejects.toThrow(LicenseFileError);
    await expect(read({ file: make() })).rejects.toThrow(/QUALOR_LICENSE_FILE/);
  });

  it('uses the stored row when no variable is set', async () => {
    await database.db.insert(instanceSettings).values({
      key: 'license',
      value: {
        key,
        savedAt: new Date().toISOString(),
        savedBy: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f',
      },
    });
    expect(await read({})).toMatchObject({ source: 'uploaded', verification: { ok: true } });
  });

  it('a rejected key does not stop the boot and is reported with its reason', async () => {
    const boot = await read({ text: 'QLK1.test-a.not-a-key' });
    expect(boot.source).toBe('environment');
    expect(boot.verification).toEqual({ ok: false, reason: 'malformed' });
  });

  it('ignores a stored row of the wrong shape (an operator edit) as no key', async () => {
    await database.db.insert(instanceSettings).values({ key: 'license', value: { nope: true } });
    expect(await read({})).toEqual({ source: null, keyHash: null, verification: null });
  });
});
