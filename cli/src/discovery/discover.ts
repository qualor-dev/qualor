import { closeSync, openSync, readdirSync, readSync, statSync, type Dirent } from 'node:fs';
import path from 'node:path';
import {
  BUILTIN_EXCLUDES,
  normalizeRepoPath,
  type Language,
  type QualorConfig,
} from '@qualor/shared';
import picomatch from 'picomatch';
import type { Logger } from '../log';
import type { GrammarId } from '../parse/grammars';
import type { Warnings } from '../warnings';
import { isIgnored, readIgnoreLayer, rootIgnoreLayers, type IgnoreLayer } from './gitignore';
import { detectLanguage, resolveCHeaders } from './languages';

export interface ScopeFile {
  /** Repo-relative, `/`-separated, NFC (report-format §2). */
  path: string;
  /** Absolute path as found on disk (may be NFD). */
  absPath: string;
  language: Language;
  grammar: GrammarId | null;
  kind: 'main' | 'test';
  size: number;
}

export interface DiscoverOptions {
  root: string;
  config: QualorConfig;
  warnings: Warnings;
  log: Logger;
  /**
   * Directories (repo-relative, `/`-separated) left out entirely and silently: the scanner's
   * vulnerability database cache inside the checkout (vuln plan 3).
   */
  leaveOut?: readonly string[];
}

/** config.md §3.1: larger files are skipped for metrics and duplication, with a warning. */
export const MAX_ANALYZED_BYTES = 1024 * 1024;
const BINARY_SNIFF_BYTES = 8 * 1024;

export function globMatcher(globs: readonly string[], dot: boolean): (p: string) => boolean {
  if (globs.length === 0) return () => false;
  return picomatch([...globs], { dot });
}

/** config.md §3.1: a NUL byte in the first 8 KiB marks a binary file. */
export function isBinaryFile(absPath: string): boolean {
  const fd = openSync(absPath, 'r');
  try {
    const buffer = Buffer.alloc(BINARY_SNIFF_BYTES);
    const read = readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.subarray(0, read).includes(0);
  } finally {
    closeSync(fd);
  }
}

interface PendingDir {
  abs: string;
  rel: string;
  layers: readonly IgnoreLayer[];
}

/** The line breaks a directory name may not hold (ruling F6's set). */
const DIRECTORY_LINE_BREAK = /[\r\n\u0085\u2028\u2029]/;

/** Code-unit order (not the locale's), for directory entries and the scope's paths alike. */
function compareText(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

const byName = (a: Dirent, b: Dirent) => compareText(a.name, b.name);

/** One discovery's walk: its options, the matchers built from them, and what it found so far. */
interface Walk {
  o: DiscoverOptions;
  leaveOut: ReadonlySet<string>;
  include: (p: string) => boolean;
  excluded: (p: string) => boolean;
  testInclude: (p: string) => boolean;
  testExclude: (p: string) => boolean;
  useGitignore: boolean;
  files: ScopeFile[];
  pending: PendingDir[];
}

export function discoverFiles(o: DiscoverOptions): ScopeFile[] {
  const { root, config, warnings, log } = o;
  const useGitignore = config.sources.useGitignore;
  const walk: Walk = {
    o,
    leaveOut: new Set(o.leaveOut ?? []),
    include: globMatcher(config.sources.include, false), // ruling C16: no dotfiles by default
    excluded: globMatcher([...BUILTIN_EXCLUDES, ...config.sources.exclude], true),
    testInclude: globMatcher(config.tests.include, true),
    testExclude: globMatcher(config.tests.exclude, true),
    useGitignore,
    files: [],
    pending: [{ abs: root, rel: '', layers: useGitignore ? rootIgnoreLayers(root, warnings) : [] }],
  };
  for (let dir = walk.pending.pop(); dir !== undefined; dir = walk.pending.pop()) {
    const entries = readEntries(dir, warnings, log);
    if (entries === null) continue;
    const layers = layersBelow(walk, dir);
    for (const entry of entries.sort(byName)) visitEntry(walk, dir, layers, entry);
  }
  return resolveCHeaders(withoutDuplicates(walk.files, warnings), config.languages);
}

/** A directory's entries; null, with a warning, when it cannot be read or is another repository. */
function readEntries(dir: PendingDir, warnings: Warnings, log: Logger): Dirent[] | null {
  let entries: Dirent[];
  try {
    entries = readdirSync(dir.abs, { withFileTypes: true });
  } catch (err) {
    warnings.add('DIRECTORY_UNREADABLE', 'a directory could not be read and was skipped');
    log.debug(`cannot read ${dir.abs}: ${String(err)}`);
    return null;
  }
  // A `.git` directory (nested clone) or file (submodule, worktree) below the root marks another
  // repository: its files are not this repository's history, so they are left out entirely.
  if (dir.rel !== '' && entries.some((e) => e.name === '.git')) {
    warnings.add(
      'NESTED_REPOSITORY_SKIPPED',
      'nested git repositories and submodules were left out of the scan',
    );
    log.info(`skipping ${dir.rel}: it is a nested git repository or submodule`);
    return null;
  }
  return entries;
}

/** The ignore layers inside `dir`: its `.gitignore` over its parent's (the root's come first). */
function layersBelow(walk: Walk, dir: PendingDir): readonly IgnoreLayer[] {
  if (!walk.useGitignore || dir.rel === '') return dir.layers;
  const layer = readIgnoreLayer(path.join(dir.abs, '.gitignore'), dir.rel, walk.o.warnings);
  return layer === null ? dir.layers : [...dir.layers, layer];
}

/** One directory entry: a directory to walk is queued, a file in scope is added. */
function visitEntry(
  walk: Walk,
  dir: PendingDir,
  layers: readonly IgnoreLayer[],
  entry: Dirent,
): void {
  const { warnings } = walk.o;
  const rel = dir.rel === '' ? entry.name : `${dir.rel}/${entry.name}`;
  if (walk.excluded(rel)) return;
  if (entry.isSymbolicLink()) {
    warnings.add('SYMLINK_SKIPPED', 'symbolic links and junctions are not followed');
    return;
  }
  // Applies to directories too: a backslash would otherwise be misread as a path separator
  // once this name is joined into a repo-relative path, on either platform.
  if (process.platform !== 'win32' && entry.name.includes('\\')) {
    warnings.add('PATH_UNSUPPORTED', 'paths whose name contains a backslash were skipped');
    return;
  }
  const abs = path.join(dir.abs, entry.name);
  if (entry.isDirectory()) queueDirectory(walk, { abs, rel, layers }, entry.name);
  else if (entry.isFile()) addFile(walk, abs, rel, layers);
}

/** Queues a directory unless it is left out, ignored, or has a line break in its name. */
function queueDirectory(walk: Walk, next: PendingDir, name: string): void {
  if (walk.leaveOut.has(next.rel)) return;
  if (walk.useGitignore && isIgnored(next.layers, next.rel, true)) return;
  // picomatch's `**` does not cross a line break, so every file below would be dropped
  // silently; U+0085 too, as SwiftLint's file list would split on it (final review minor 1).
  if (DIRECTORY_LINE_BREAK.test(name)) {
    walk.o.warnings.add(
      'PATH_UNSUPPORTED',
      'directories whose name contains a line break were skipped',
    );
    return;
  }
  walk.pending.push(next);
}

/** Adds a file when it is in scope: reportable, included, not excluded or ignored, not binary. */
function addFile(walk: Walk, abs: string, rel: string, layers: readonly IgnoreLayer[]): void {
  const { config, warnings, log } = walk.o;
  let repoPath: string;
  try {
    repoPath = normalizeRepoPath(rel);
  } catch {
    warnings.add('PATH_UNSUPPORTED', 'files whose path cannot be reported were skipped');
    return;
  }
  if (!walk.include(repoPath) || walk.excluded(repoPath)) return;
  if (walk.useGitignore && isIgnored(layers, rel, false)) return;
  let size: number;
  try {
    size = statSync(abs).size;
    if (isBinaryFile(abs)) return;
  } catch (err) {
    warnings.add('FILE_UNREADABLE', 'a file could not be read and was skipped');
    log.debug(`cannot read ${abs}: ${String(err)}`);
    return;
  }
  const { language, grammar } = detectLanguage(repoPath, config.languages);
  const kind = walk.testInclude(repoPath) && !walk.testExclude(repoPath) ? 'test' : 'main';
  walk.files.push({ path: repoPath, absPath: abs, language, grammar, kind, size });
}

/** The files in path order, without a later file that maps to the same NFC path (warned). */
function withoutDuplicates(files: ScopeFile[], warnings: Warnings): ScopeFile[] {
  files.sort((a, b) => compareText(a.path, b.path));
  return files.filter((f, i) => {
    const duplicate = i > 0 && files[i - 1]?.path === f.path;
    if (duplicate) {
      warnings.add('PATH_DUPLICATE', 'two files map to the same NFC path; the first was kept');
    }
    return !duplicate;
  });
}
