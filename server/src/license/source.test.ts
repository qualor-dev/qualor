import { describe, expect, it } from 'vitest';
import { signTest, testSigner, verifyWith } from '../../test/license';
import { decodeLicenseText, LicenseFileError } from './source';
import { verifyLicenseKey } from './verify';

/** UTF-16 big-endian bytes of a string (Node has no 'utf16be' encoding). */
function utf16be(text: string): Buffer {
  const le = Buffer.from(text, 'utf16le');
  const be = Buffer.alloc(le.length);
  for (let i = 0; i < le.length; i += 2) {
    be[i] = le[i + 1]!;
    be[i + 1] = le[i]!;
  }
  return be;
}

describe('decodeLicenseText (enterprise.md §6: files saved by Notepad or PowerShell 5.1)', () => {
  const signer = testSigner();
  const key = signTest(signer);
  const decode = (bytes: Buffer) => decodeLicenseText(bytes, 'QUALOR_LICENSE_FILE: /run/licence');

  it.each([
    ['UTF-8', Buffer.from(`${key}\n`, 'utf8')],
    ['UTF-8 with a byte-order mark', Buffer.from(`\uFEFF${key}\r\n`, 'utf8')],
    ['UTF-16 little-endian with a byte-order mark', Buffer.from(`\uFEFF${key}\r\n`, 'utf16le')],
    ['UTF-16 big-endian with a byte-order mark', utf16be(`\uFEFF${key}\r\n`)],
  ])('reads %s to a key that verifies', (_what, bytes) => {
    const text = decode(bytes);
    expect(verifyLicenseKey(text, verifyWith(signer))).toMatchObject({ ok: true });
  });

  it('refuses UTF-16 without a byte-order mark with a clear message and no content', () => {
    let error: unknown;
    try {
      decode(Buffer.from(key, 'utf16le'));
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(LicenseFileError);
    const message = (error as Error).message;
    expect(message).toMatch(/^QUALOR_LICENSE_FILE: \/run\/licence .*UTF-8/);
    expect(message).not.toContain(key.split('.')[2]!.slice(0, 16));
  });
});
