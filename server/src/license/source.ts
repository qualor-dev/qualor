import { readFile, stat } from 'node:fs/promises';
import { z } from 'zod';
import type { Config } from '../config';
import type { Executor } from '../db/client';
import { instanceSetting } from '../settings';
import { keyHash } from './token';
import { verifyLicenseKey, type Verification, type VerifyOptions } from './verify';

/** The `instance_settings` row of an uploaded key (data-model.md). */
export const LICENSE_SETTING_KEY = 'license';
/** QUALOR_LICENSE_FILE and a stored key are at most 16 KiB (enterprise.md §6). */
export const MAX_LICENSE_FILE_BYTES = 16 * 1024;

export const storedLicenseSchema = z.object({
  key: z.string().min(1).max(MAX_LICENSE_FILE_BYTES),
  savedAt: z.string(),
  savedBy: z.string(),
});
export type StoredLicense = z.infer<typeof storedLicenseSchema>;

export type LicenseSource = 'environment' | 'file' | 'uploaded';

/** The key the process booted with; fixed for its life (enterprise.md §6, ruling EE3). */
export interface BootLicense {
  source: LicenseSource | null;
  /** SHA-256 of the whitespace-free key text, never the text itself. */
  keyHash: string | null;
  verification: Verification | null;
}

/** A licence file that is not there stops the boot, as a wrong QUALOR_UI_DIR does (enterprise.md §6). */
export class LicenseFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LicenseFileError';
  }
}

/** The uploaded key, or null when the row is missing or of the wrong shape (an operator edit). */
export async function readStoredLicense(db: Executor): Promise<StoredLicense | null> {
  return instanceSetting(db, LICENSE_SETTING_KEY, storedLicenseSchema.nullable(), null);
}

/**
 * enterprise.md §6: the text of a licence file or of `license:inspect -`. UTF-8, with or without a
 * byte-order mark, or UTF-16 with one (Notepad's "Unicode", PowerShell 5.1's `>`); the mark itself
 * is dropped later by `normaliseKey`. NUL bytes without a UTF-16 mark are refused with a clear
 * message, naming `what` and never the content.
 */
export function decodeLicenseText(content: Buffer, what: string): string {
  if (content.length >= 2 && content[0] === 0xff && content[1] === 0xfe) {
    return content.subarray(2).toString('utf16le');
  }
  if (content.length >= 2 && content[0] === 0xfe && content[1] === 0xff) {
    // Node has no UTF-16BE decoder: swap each pair of bytes, then read it as UTF-16LE.
    const le = Buffer.from(content.subarray(2, content.length - (content.length % 2)));
    le.swap16();
    return le.toString('utf16le');
  }
  if (content.includes(0)) {
    throw new LicenseFileError(
      `${what} is not a text file in UTF-8 (or UTF-16 with a byte-order mark); save it as UTF-8`,
    );
  }
  return content.toString('utf8');
}

const tooLarge = (file: string) =>
  new LicenseFileError(`QUALOR_LICENSE_FILE: ${file} is larger than 16 KiB`);

async function readLicenseFile(file: string): Promise<string> {
  let size: number;
  try {
    const info = await stat(file);
    if (!info.isFile()) throw new LicenseFileError(`QUALOR_LICENSE_FILE: ${file} is not a file`);
    size = info.size;
  } catch (err) {
    if (err instanceof LicenseFileError) throw err;
    throw new LicenseFileError(`QUALOR_LICENSE_FILE: cannot read ${file}`);
  }
  if (size > MAX_LICENSE_FILE_BYTES) throw tooLarge(file);
  let content: Buffer;
  try {
    content = await readFile(file);
  } catch {
    throw new LicenseFileError(`QUALOR_LICENSE_FILE: cannot read ${file}`);
  }
  // The file may have grown between stat and read.
  if (content.length > MAX_LICENSE_FILE_BYTES) throw tooLarge(file);
  return decodeLicenseText(content, `QUALOR_LICENSE_FILE: ${file}`);
}

/**
 * enterprise.md §6: the first of QUALOR_LICENSE, QUALOR_LICENSE_FILE, the stored row. A key that
 * fails verification is returned with its reason and never stops the boot; only a licence file
 * that cannot be read does (LicenseFileError).
 */
export async function readBootLicense(
  config: Config,
  db: Executor,
  verifyOptions: VerifyOptions,
): Promise<BootLicense> {
  let source: LicenseSource | null = null;
  let text: string | null = null;
  if (config.license.text !== null) {
    source = 'environment';
    text = config.license.text;
  } else if (config.license.file !== null) {
    source = 'file';
    text = await readLicenseFile(config.license.file);
  } else {
    const stored = await readStoredLicense(db);
    if (stored) {
      source = 'uploaded';
      text = stored.key;
    }
  }
  if (source === null || text === null) return { source: null, keyHash: null, verification: null };
  return { source, keyHash: keyHash(text), verification: verifyLicenseKey(text, verifyOptions) };
}
