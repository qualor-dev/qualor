import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { within } from './binary';

/**
 * The file's bytes when it is a regular file inside the root, reached without a symbolic link or
 * junction on the way, of at most 1 MiB (ruling E15); else null. Opened once, without following a
 * link at the last step and without blocking on a FIFO, and judged by that descriptor. `realRoot`
 * is `realpathSync(root)`, computed once per run.
 */
export function readPlainFile(root: string, realRoot: string, abs: string): Buffer | null {
  try {
    if (!lstatSync(abs).isFile()) return null;
    if (realpathSync(abs) !== path.join(realRoot, path.relative(root, abs))) return null;
    const fd = openSync(
      abs,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_ANALYZED_BYTES) return null;
      const bytes = readFileSync(fd);
      return bytes.length > MAX_ANALYZED_BYTES ? null : bytes;
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** Where `copyCheckedFiles` puts a scope file below `input`: its repository path. */
export function copyTarget(input: string, f: ScopeFile): string {
  return path.join(input, ...f.path.split('/'));
}

/**
 * The bytes with every CR LF replaced by LF; a lone CR stays, as it is no line end to Qualor
 * (`splitSourceLines`). Byte for byte (latin1 maps each byte to one code unit), so text that is not
 * UTF-8 is kept, and each line keeps the columns Qualor counts up to its end (ruling F27).
 */
export function crlfToLf(bytes: Buffer): Buffer {
  if (!bytes.includes(0x0d)) return bytes;
  return Buffer.from(bytes.toString('latin1').replaceAll('\r\n', '\n'), 'latin1');
}

/**
 * Copies scope files into `input`, at their repository paths, through `readPlainFile` (the checked
 * copy of rulings E20 and F10). The tool reads the copy, never the checkout: nothing can change
 * between this check and the tool's read, no link or FIFO is ever followed, and the relative paths
 * it reports are the repository's own. `transform` changes the copied bytes only (SwiftLint's
 * `crlfToLf`, ruling F27); without it the bytes are copied as they are. Returns the files copied;
 * the others were left out (a link, a file larger than 1 MiB, one that cannot be read, or two
 * paths one file system folds together).
 */
export function copyCheckedFiles(
  root: string,
  files: readonly ScopeFile[],
  input: string,
  transform: (bytes: Buffer) => Buffer = (bytes) => bytes,
): ScopeFile[] {
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return [];
  }
  return files.filter((f) => copyOne(root, realRoot, f, input, transform));
}

function copyOne(
  root: string,
  realRoot: string,
  f: ScopeFile,
  input: string,
  transform: (bytes: Buffer) => Buffer,
): boolean {
  const target = copyTarget(input, f);
  if (!within(input, target) || target === input) return false;
  const bytes = readPlainFile(root, realRoot, f.absPath);
  if (bytes === null) return false;
  try {
    mkdirSync(path.dirname(target), { recursive: true });
    // `wx`: two paths that one file system folds together are never merged silently.
    writeFileSync(target, transform(bytes), { flag: 'wx' });
    return true;
  } catch {
    return false;
  }
}
