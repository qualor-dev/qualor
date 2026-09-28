import { existsSync, lstatSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { sha256File } from '../deploy/sources';

/** release.md §3, §12: SHA256SUMS lists every file of the release directory but itself and its bundle. */
export const SUMS = 'SHA256SUMS';
export const SUMS_BUNDLE = 'SHA256SUMS.bundle';
const UNLISTED = new Set([SUMS, SUMS_BUNDLE]);

/** Every regular file, as sorted posix paths. A link or anything else is refused. */
export function releaseFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (rel: string): void => {
    for (const e of readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const p = rel === '' ? e.name : `${rel}/${e.name}`;
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        if (!UNLISTED.has(p)) out.push(p);
      } else throw new Error(`${p}: not a regular file`);
    }
  };
  walk('');
  return out.sort();
}

export async function sha256sums(dir: string): Promise<string> {
  const lines: string[] = [];
  for (const f of releaseFiles(dir)) lines.push(`${await sha256File(path.join(dir, f))}  ${f}`);
  return `${lines.join('\n')}\n`;
}

const LINE = /^([0-9a-f]{64}) {2}(\S(?:.*\S)?)$/;

export function parseSums(text: string): { sha256: string; file: string }[] {
  return text
    .split('\n')
    .filter((l) => l !== '')
    .map((l, i) => {
      const m = LINE.exec(l);
      if (!m?.[1] || !m[2]) throw new Error(`SHA256SUMS line ${i + 1} is not "<sha256>  <path>"`);
      const file = m[2];
      if (file.startsWith('/') || file.includes('\\') || file.split('/').includes('..')) {
        throw new Error(`SHA256SUMS line ${i + 1}: ${file} leaves the release directory`);
      }
      return { sha256: m[1], file };
    });
}

export async function sumsProblems(dir: string, text: string): Promise<string[]> {
  const listed = parseSums(text);
  const problems: string[] = [];
  for (const { sha256, file } of listed) {
    const full = path.join(dir, file);
    if (!existsSync(full)) problems.push(`${file}: listed in SHA256SUMS but missing`);
    else if (!lstatSync(full).isFile()) {
      // A directory (EISDIR) or a link is named, never hashed.
      problems.push(`${file}: listed in SHA256SUMS but not a regular file`);
    } else if ((await sha256File(full)) !== sha256) {
      problems.push(`${file}: the SHA-256 does not match SHA256SUMS`);
    }
  }
  const names = new Set(listed.map((l) => l.file));
  for (const f of releaseFiles(dir)) {
    if (!names.has(f)) problems.push(`${f}: not listed in SHA256SUMS`);
  }
  return problems.sort();
}
