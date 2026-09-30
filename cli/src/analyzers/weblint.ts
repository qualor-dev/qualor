import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, statSync } from 'node:fs';
import path from 'node:path';
import { staysInside } from './binary';

/** A repository configuration Qualor's HTML and CSS passes cannot use (config.md §6): a skip reason. */
export class WeblintConfigError extends Error {}

/** True when `file` exists as any kind of entry (a dangling link included). */
export function repoEntryExists(file: string): boolean {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * A repository configuration file's text: a regular file (never a FIFO or a directory) that stays
 * inside the repository as written and after symlinks, of at most `maxBytes`. `rel` is the path as
 * the user wrote it or as Qualor looked it up, for the message.
 *
 * The file is opened once (non-blocking, so a FIFO swapped in cannot hang the scan) and its type and
 * size are taken from that descriptor; at most `maxBytes + 1` bytes are ever read.
 */
export function readRepoConfig(root: string, rel: string, maxBytes: number): string {
  const file = path.resolve(root, rel);
  if (!repoEntryExists(file)) throw new WeblintConfigError(`${rel} cannot be read`);
  if (!staysInside(root, file)) throw new WeblintConfigError(`${rel} is outside the repository`);
  const notRegular = () => new WeblintConfigError(`${rel} is not a regular file`);
  try {
    if (!statSync(file).isFile()) throw notRegular();
  } catch (err) {
    if (err instanceof WeblintConfigError) throw err;
    throw new WeblintConfigError(`${rel} cannot be read`);
  }
  let fd: number;
  try {
    fd = openSync(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    throw new WeblintConfigError(`${rel} cannot be read`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw notRegular();
    const tooLarge = () =>
      new WeblintConfigError(`${rel} is larger than ${maxBytes / 1024 / 1024} MiB`);
    if (stat.size > maxBytes) throw tooLarge();
    const buf = Buffer.alloc(maxBytes + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buf, length, buf.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > maxBytes) throw tooLarge();
    }
    return buf.toString('utf8', 0, length);
  } catch (err) {
    if (err instanceof WeblintConfigError) throw err;
    throw new WeblintConfigError(`${rel} cannot be read`);
  } finally {
    closeSync(fd);
  }
}
