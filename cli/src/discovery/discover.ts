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
import { detectLanguage } from './languages';

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

const byName = (a: Dirent, b: Dirent) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

export function discoverFiles(o: DiscoverOptions): ScopeFile[] {
  const { root, config, warnings, log } = o;
  const include = globMatcher(config.sources.include, false); // ruling C16: no dotfiles by default
  const excluded = globMatcher([...BUILTIN_EXCLUDES, ...config.sources.exclude], true);
  const testInclude = globMatcher(config.tests.include, true);
  const testExclude = globMatcher(config.tests.exclude, true);
  const useGitignore = config.sources.useGitignore;

  const files: ScopeFile[] = [];
  const pending: PendingDir[] = [
    { abs: root, rel: '', layers: useGitignore ? rootIgnoreLayers(root, warnings) : [] },
  ];
  for (let dir = pending.pop(); dir !== undefined; dir = pending.pop()) {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir.abs, { withFileTypes: true });
    } catch (err) {
      warnings.add('DIRECTORY_UNREADABLE', 'a directory could not be read and was skipped');
      log.debug(`cannot read ${dir.abs}: ${String(err)}`);
      continue;
    }
    // A `.git` directory (nested clone) or file (submodule, worktree) below the root marks another
    // repository: its files are not this repository's history, so they are left out entirely.
    if (dir.rel !== '' && entries.some((e) => e.name === '.git')) {
      warnings.add(
        'NESTED_REPOSITORY_SKIPPED',
        'nested git repositories and submodules were left out of the scan',
      );
      log.info(`skipping ${dir.rel}: it is a nested git repository or submodule`);
      continue;
    }
    let layers = dir.layers;
    if (useGitignore && dir.rel !== '') {
      const layer = readIgnoreLayer(path.join(dir.abs, '.gitignore'), dir.rel, warnings);
      if (layer !== null) layers = [...layers, layer];
    }
    for (const entry of entries.sort(byName)) {
      const rel = dir.rel === '' ? entry.name : `${dir.rel}/${entry.name}`;
      if (excluded(rel)) continue;
      if (entry.isSymbolicLink()) {
        warnings.add('SYMLINK_SKIPPED', 'symbolic links and junctions are not followed');
        continue;
      }
      // Applies to directories too: a backslash would otherwise be misread as a path separator
      // once this name is joined into a repo-relative path, on either platform.
      if (process.platform !== 'win32' && entry.name.includes('\\')) {
        warnings.add('PATH_UNSUPPORTED', 'paths whose name contains a backslash were skipped');
        continue;
      }
      const abs = path.join(dir.abs, entry.name);
      if (entry.isDirectory()) {
        if (useGitignore && isIgnored(layers, rel, true)) continue;
        // picomatch's `**` does not cross a line break, so every file below would be dropped
        // silently; U+0085 too, as SwiftLint's file list would split on it (final review minor 1).
        if (DIRECTORY_LINE_BREAK.test(entry.name)) {
          warnings.add(
            'PATH_UNSUPPORTED',
            'directories whose name contains a line break were skipped',
          );
          continue;
        }
        pending.push({ abs, rel, layers });
        continue;
      }
      if (!entry.isFile()) continue;
      let repoPath: string;
      try {
        repoPath = normalizeRepoPath(rel);
      } catch {
        warnings.add('PATH_UNSUPPORTED', 'files whose path cannot be reported were skipped');
        continue;
      }
      if (!include(repoPath) || excluded(repoPath)) continue;
      if (useGitignore && isIgnored(layers, rel, false)) continue;
      let size: number;
      try {
        size = statSync(abs).size;
        if (isBinaryFile(abs)) continue;
      } catch (err) {
        warnings.add('FILE_UNREADABLE', 'a file could not be read and was skipped');
        log.debug(`cannot read ${abs}: ${String(err)}`);
        continue;
      }
      const { language, grammar } = detectLanguage(repoPath, config.languages);
      const kind = testInclude(repoPath) && !testExclude(repoPath) ? 'test' : 'main';
      files.push({ path: repoPath, absPath: abs, language, grammar, kind, size });
    }
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return files.filter((f, i) => {
    const duplicate = i > 0 && files[i - 1]?.path === f.path;
    if (duplicate) {
      warnings.add('PATH_DUPLICATE', 'two files map to the same NFC path; the first was kept');
    }
    return !duplicate;
  });
}
