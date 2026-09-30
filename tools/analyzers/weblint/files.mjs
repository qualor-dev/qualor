// files.mjs — shared by stylelint.mjs and htmlhint.mjs (plan 8D): the command line, the file
// list the CLI writes, and SARIF pieces. MIT.
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

const NEVER_DIRS = new Set(['node_modules', '.git']);

export const stderr = (line) => process.stderr.write(line);

export function option(args, name) {
  const i = args.indexOf(name);
  return i < 0 ? undefined : args[i + 1];
}

export function required(args, name) {
  const value = option(args, name);
  if (value === undefined) throw new Error(`missing ${name}`);
  return value;
}

/** A JSON file the CLI wrote into its work directory. */
export function readJson(file) {
  return JSON.parse(readFileSync(path.resolve(file), 'utf8'));
}

/**
 * Whether `full` is a regular file inside `root` (whose real path is `realRoot`), reached without
 * a symbolic link or junction in any component, and never under node_modules or .git.
 */
export function isRepoFile(root, realRoot, full) {
  const rel = path.relative(root, full);
  if (rel === '' || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    return false;
  }
  if (rel.split(path.sep).some((part) => NEVER_DIRS.has(part))) return false;
  try {
    // lstat: the file itself is no link; realpath: no directory on the way is one either.
    return lstatSync(full).isFile() && realpathSync(full) === path.join(realRoot, rel);
  } catch {
    return false;
  }
}

/**
 * The entries of a --files list that may be linted: regular files whose name matches `pattern`,
 * inside `root`, reached without a symbolic link or junction in any component, never under
 * node_modules or .git. The CLI already applied Qualor's scope; each entry is checked again here.
 */
export function listedFiles(root, entries, pattern, warn = stderr) {
  if (!Array.isArray(entries)) throw new Error('--files must name a JSON array of paths');
  const realRoot = realpathSync(root);
  const out = new Set();
  let dropped = 0;
  for (const entry of entries) {
    const full = typeof entry === 'string' ? path.resolve(root, entry) : undefined;
    if (full !== undefined && pattern.test(full) && isRepoFile(root, realRoot, full)) out.add(full);
    else dropped += 1;
  }
  if (dropped > 0) {
    warn(`${dropped} listed file(s) not linted (not a regular source file inside the root)\n`);
  }
  return [...out].sort();
}

export const uriOf = (root, file) => path.relative(root, file).split(path.sep).join('/');

/** A SARIF region (1-based; the end column is exclusive in both SARIF and stylelint). */
export function region(line, column, endLine, endColumn) {
  return {
    startLine: line ?? 1,
    ...(column && { startColumn: column }),
    ...(endLine && { endLine }),
    ...(endColumn && { endColumn }),
  };
}

export const https = (url) =>
  typeof url === 'string' && url.startsWith('https://') ? url : undefined;

/** Runs `main` and exits 2 with the error on stderr when it throws. */
export async function run(tool, main) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    stderr(`${tool}: ${err?.stack ?? err}\n`);
    process.exit(2);
  }
}
