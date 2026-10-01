import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { ScopeFile } from '../discovery/discover';
import { within } from './binary';
import { checkRepoFileSetting, realRootOf } from './cfamily-common';
import { shown } from './reason';
import { readRepoConfigBytes, repoEntryExists, WeblintConfigError } from './weblint';

/** config.md §6.2: a compile database larger than this is not read. */
export const MAX_COMPILE_COMMANDS_BYTES = 64 * 1024 * 1024;
/** Where `compileCommands: null` looks, in order (config.md §6.2). */
export const COMPILE_COMMANDS_LOOKUP = [
  'compile_commands.json',
  'build/compile_commands.json',
] as const;

export function findCompileCommands(
  root: string,
  setting: string | false | null,
): { rel: string } | { none: string } | { skip: string } {
  if (setting === false) return { none: 'compileCommands is false' };
  if (setting !== null) {
    return repoEntryExists(path.resolve(root, setting))
      ? { rel: setting }
      : { skip: `compileCommands ${shown(setting)} does not exist` };
  }
  for (const rel of COMPILE_COMMANDS_LOOKUP) {
    if (repoEntryExists(path.join(root, rel))) return { rel };
  }
  return { none: 'no compile_commands.json at the repository root or in build/' };
}

/** config.md §6.2 (exit 2): only a URL, or a path outside the repository as written (ruling F3). */
export function checkCompileCommandsSetting(
  setting: string | false | null,
  key: string,
): string | null {
  return typeof setting === 'string' ? checkRepoFileSetting(key, 'compileCommands', setting) : null;
}

/** POSIX shell word splitting without any expansion (CMake writes `command` this way). */
export function splitCommand(command: string): string[] {
  const words: string[] = [];
  let word = '';
  let inWord = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command.charAt(i);
    if (quote === "'") {
      if (c === "'") quote = null;
      else word += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === '\\' && i + 1 < command.length && '"\\$`\n'.includes(command.charAt(i + 1)))
        word += command[++i];
      else word += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      inWord = true;
    } else if (c === '\\' && i + 1 < command.length) {
      word += command[++i];
      inWord = true;
    } else if (/\s/.test(c)) {
      if (inWord) words.push(word);
      word = '';
      inWord = false;
    } else {
      word += c;
      inWord = true;
    }
  }
  if (inWord) words.push(word);
  return words;
}

/** Options whose value is the next argument when it is not attached. */
const KEPT_WITH_VALUE = new Set([
  '-I',
  '-isystem',
  '-iquote',
  '-idirafter',
  '-include',
  '-isysroot',
  '-D',
  '-U',
  '-x',
  '-target',
]);
const DROPPED_WITH_VALUE = new Set([
  '-Xclang',
  '-mllvm',
  '-Xpreprocessor',
  '-Xlinker',
  '-Xassembler',
  '-imacros',
  '-iprefix',
  '-iwithprefix',
  '-iwithprefixbefore',
  '-resource-dir',
  '-L',
  '-l',
  '--param',
  '-arch',
  '-main-file-name',
]);
/** Build options every entry has: dropped (with their value) but not counted. */
const ROUTINE_WITH_VALUE = new Set(['-o', '-MF', '-MT', '-MQ']);
const ROUTINE = /^(-c|-MD|-MMD|-MP|-M|-MM|-pipe|-O\w*|-g\w*)$/;
const KEPT_ATTACHED = /^(-I|-isystem|-iquote|-idirafter|-D|-U)./;
const KEPT_EXACT = new Set(['-m32', '-m64', '-pthread', '-ansi', '-nostdinc', '-nostdinc++', '-w']);
const KEPT_PREFIX =
  /^(-std=|--target=|--sysroot=|--gcc-toolchain=|--gcc-install-dir=|-march=|-mtune=|-mcpu=)/;
const DRIVER_MODE = /^--driver-mode=(gcc|g\+\+|cpp)$/;
const WARNING = /^-W(no-)?[A-Za-z0-9][A-Za-z0-9+=_-]*$/;
const F_FLAGS = new Set([
  'exceptions',
  'cxx-exceptions',
  'rtti',
  'ms-extensions',
  'ms-compatibility',
  'delayed-template-parsing',
  'char8_t',
  'signed-char',
  'unsigned-char',
  'openmp',
  'threadsafe-statics',
  'gnu-keywords',
  'coroutines',
  'concepts',
  'pic',
  'PIC',
  'pie',
  'PIE',
  'strict-aliasing',
  'wrapv',
  'short-enums',
  'short-wchar',
  'builtin',
  'freestanding',
  'hosted',
  'common',
  'asm',
  'gnu89-inline',
  'blocks',
]);
const LAUNCHERS = new Set(['ccache', 'sccache', 'distcc']);
/**
 * A gcc or clang driver name, with an optional target prefix and version suffix. Clang takes its
 * driver mode from argv[0]: `cl`, `clang-cl`, `clang-dxc` or `flang` would switch it to a mode
 * that reads `/`-options (`/clang:<any option>`), so any other name becomes `c++` or `cc`.
 */
const COMPILER_NAME = /^([A-Za-z0-9_.]+-)*(cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(-[0-9.]+)?$/;
/** A cl-style option (`/clang:-fplugin=…`, `/Fo:x`) as a separate value: dropped with its option. */
const CL_OPTION = /^\/[A-Za-z][A-Za-z0-9_-]*:/;
/** `-march=native` and the like: clang may run a helper found on PATH to detect the host. */
const NATIVE = /^-m(arch|cpu|tune)=native$/;
const SOURCE = /\.(c|cc|cpp|cxx|c\+\+|C|m|mm)$/;

/**
 * A line break or NUL: no argument line of a response file, nor an argv entry, can carry it, and a
 * line break could start a new option there. The argument (with its value) is dropped.
 */
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT = /[\r\n\u0000\x85\u2028\u2029]/;

/**
 * A separate value of a kept option: clang expands every argument that starts with `@` as a
 * response file (wherever it stands, values included), and a value that looks like an option could
 * be read as one by a tool that parses differently, so both are dropped with their option.
 */
function safeValue(v: string): boolean {
  return (
    v !== '' &&
    !v.startsWith('@') &&
    !v.startsWith('-') &&
    !CL_OPTION.test(v) &&
    !UNSAFE_TEXT.test(v)
  );
}

function keptFlag(a: string): boolean {
  if (NATIVE.test(a)) return false;
  if (KEPT_EXACT.has(a) || KEPT_PREFIX.test(a) || KEPT_ATTACHED.test(a) || DRIVER_MODE.test(a))
    return true;
  if (WARNING.test(a)) return !a.startsWith('-Werror') && a !== '-Wfatal-errors';
  const f = /^-f(no-)?([A-Za-z0-9_+-]+)$/.exec(a);
  return f !== null && F_FLAGS.has(f[2] ?? '');
}

/**
 * config.md §6.2: the compiler's gcc or clang driver name (else `c++`, or `cc` for C), and the
 * arguments of the allowlist. A dropped option
 * that takes a value drops its value; the input files (sources) are left out without being
 * counted, as the writer adds the entry's file itself.
 */
export function sanitizeArguments(
  args: readonly string[],
  language: 'c' | 'cpp' = 'cpp',
): {
  compiler: string;
  kept: string[];
  dropped: number;
} {
  let i = 0;
  while (
    i < args.length &&
    LAUNCHERS.has(path.posix.basename((args[i] ?? '').replaceAll('\\', '/')))
  )
    i++;
  const first = args[i] ?? '';
  const base = path.posix.basename(first.replaceAll('\\', '/'));
  const compiler = COMPILER_NAME.test(base) ? base : language === 'c' ? 'cc' : 'c++';
  const kept: string[] = [];
  let dropped = 0;
  for (i += 1; i < args.length; i++) {
    const a = args[i] ?? '';
    if (KEPT_WITH_VALUE.has(a) && i + 1 < args.length) {
      const value = args[++i] ?? '';
      if (safeValue(value)) kept.push(a, value);
      else dropped++;
    } else if (UNSAFE_TEXT.test(a)) {
      dropped++;
    } else if (ROUTINE_WITH_VALUE.has(a)) {
      i++;
    } else if (DROPPED_WITH_VALUE.has(a)) {
      i++;
      dropped++;
    } else if (keptFlag(a)) {
      kept.push(a);
    } else if (ROUTINE.test(a) || (!a.startsWith('-') && !a.startsWith('@') && SOURCE.test(a))) {
      // a routine build option, or the input file (also absolute, as CMake writes it)
    } else {
      dropped++;
    }
  }
  return { compiler, kept, dropped };
}

export interface CompileEntry {
  repoPath: string;
  directory: string;
  file: string;
  compiler: string;
  args: string[];
}

type RawEntry = { directory?: unknown; file?: unknown; arguments?: unknown; command?: unknown };

export function readCompileCommands(
  root: string,
  rel: string,
  scope: ReadonlyMap<string, ScopeFile>,
): { entries: CompileEntry[]; droppedArgs: number; ignoredEntries: number } | { skip: string } {
  const name = shown(rel);
  let bytes: Buffer;
  try {
    bytes = readRepoConfigBytes(root, rel, MAX_COMPILE_COMMANDS_BYTES, rel);
  } catch (err) {
    if (err instanceof WeblintConfigError) return { skip: shown(err.message) };
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    return { skip: `${name} is not valid JSON` };
  }
  if (!Array.isArray(parsed)) return { skip: `${name} is not a JSON array of entries` };
  const realRoot = realRootOf(root);
  const dbDir = path.dirname(path.resolve(root, rel));
  const entries: CompileEntry[] = [];
  const seen = new Set<string>();
  let droppedArgs = 0;
  let ignoredEntries = 0;
  for (const [index, raw] of (parsed as RawEntry[]).entries()) {
    const ok =
      raw !== null &&
      typeof raw === 'object' &&
      typeof raw.directory === 'string' &&
      typeof raw.file === 'string' &&
      ((Array.isArray(raw.arguments) && raw.arguments.every((a) => typeof a === 'string')) ||
        typeof raw.command === 'string');
    if (!ok)
      return {
        skip: `${name}: entry ${index + 1} needs "directory", "file", and "arguments" or "command"`,
      };
    const directory = path.resolve(dbDir, raw.directory as string);
    const file = path.resolve(directory, raw.file as string);
    const repoPath = repoPathOf(root, realRoot, file);
    const scoped = repoPath === null ? undefined : scope.get(repoPath);
    if (
      repoPath === null ||
      scoped === undefined ||
      seen.has(repoPath) ||
      !plainFile(file, realRoot)
    ) {
      ignoredEntries++;
      continue;
    }
    seen.add(repoPath);
    const argv = Array.isArray(raw.arguments)
      ? (raw.arguments as string[])
      : splitCommand(raw.command as string);
    const { compiler, kept, dropped } = sanitizeArguments(
      argv,
      scoped.language === 'c' ? 'c' : 'cpp',
    );
    droppedArgs += dropped;
    entries.push({ repoPath, directory, file, compiler, args: kept });
  }
  return { entries, droppedArgs, ignoredEntries };
}

/** The repository path of an absolute file, through the root as written or as resolved; else null. */
function repoPathOf(root: string, realRoot: string, file: string): string | null {
  for (const base of [path.resolve(root), realRoot]) {
    if (within(base, file) && file !== base)
      return path.relative(base, file).split(path.sep).join('/');
  }
  return null;
}

/**
 * A regular file reached without a link at its last step (discovery skips links; checked again),
 * whose resolved path stays in the repository (no directory on the way links out).
 */
function plainFile(file: string, realRoot: string): boolean {
  try {
    return lstatSync(file).isFile() && within(realRoot, realpathSync(file));
  } catch {
    return false;
  }
}
