import { mkdirSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import {
  CPPCHECK_VERSION,
  cppcheckSuppressed,
  cppcheckVersionSupported,
  type QualorConfig,
} from '@qualor/shared';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { isCHeader } from '../discovery/languages';
import { within } from './binary';
import {
  C_LANGUAGES,
  cFamilyDropEnv,
  cFamilyEnv,
  hasLineBreak,
  realRootOf,
} from './cfamily-common';
import { copyCheckedFiles, copyTarget } from './checked-copy';
import {
  checkCompileCommandsSetting,
  findCompileCommands,
  readCompileCommands,
  type CompileEntry,
} from './compile-commands';
import { cppcheckXmlToSarif } from './cppcheck-xml';
import { detailLine, shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

const NOT_INSTALLED = 'cppcheck is not installed (cppcheck on PATH or in the qualor/scanner image)';
const INPUT_DIR = 'src';

/** `cppcheck --version` prints `Cppcheck 2.22.0` (the Premium edition is another product). */
export function parseCppcheckVersion(stdout: string): string | null {
  return /^Cppcheck (\d+\.\d+(?:\.\d+)?)$/.exec(stdout.trim())?.[1] ?? null;
}

/** One warn line for the results that are no finding (decision 6). */
function logNotAnalysed(ctx: AnalyzerContext, counts: ReadonlyMap<string, number>): void {
  if (counts.size === 0) return;
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  const ids = [...counts].map(([id, n]) => `${shown(id)} ${n}`).join(', ');
  const detail = detailLine(
    `${total} result(s) say it could not fully analyse the code (${ids}); they are not issues`,
  );
  ctx.log.warn(`cppcheck: ${detail}`);
}

/** The cppcheck to run and its version, or why there is none (never the checkout's own). */
async function findCppcheck(
  ctx: AnalyzerContext,
): Promise<{ cppcheck: string; version: string } | { skip: string } | { unavailable: string }> {
  const cppcheck = ctx.resolveBinary('cppcheck');
  if (cppcheck === null) {
    const own =
      ctx.repoBinary('cppcheck') === null ? '' : "; the repository's own cppcheck is never run";
    return { skip: `${NOT_INSTALLED}${own}` };
  }
  const probe = await ctx.exec(cppcheck, ['--version'], { timeoutMs: 30_000, cwd: ctx.workDir });
  const version = probe.exitCode === 0 ? parseCppcheckVersion(probe.stdout) : null;
  if (version === null) return { unavailable: '`cppcheck --version` printed no version' };
  if (!cppcheckVersionSupported(version)) {
    const minor = CPPCHECK_VERSION.split('.').slice(0, 2).join('.');
    return {
      skip: `cppcheck ${shown(version)} is not supported: this Qualor runs cppcheck ${minor}.x (the qualor/scanner image's ${CPPCHECK_VERSION})`,
    };
  }
  return { cppcheck, version };
}

/** The scope's C/C++ files copied into `<work>/src`, the directory cppcheck runs in. */
function copyInput(
  ctx: AnalyzerContext,
): { copied: ScopeFile[]; input: string } | { skip: string } {
  const cFiles = ctx.files.filter((f) => C_LANGUAGES.has(f.language));
  const lineBreaks = cFiles.filter((f) => hasLineBreak(f.path)).length;
  if (lineBreaks > 0)
    ctx.log.warn(`cppcheck: ${lineBreaks} file(s) whose path has a line break were left out`);
  const large = cFiles.filter((f) => f.size > MAX_ANALYZED_BYTES).length;
  if (large > 0) ctx.log.warn(`cppcheck: ${large} C/C++ file(s) larger than 1 MiB were left out`);
  const candidates = cFiles.filter((f) => !hasLineBreak(f.path) && f.size <= MAX_ANALYZED_BYTES);
  const input = path.join(ctx.workDir, INPUT_DIR);
  if (hasLineBreak(input)) return { skip: 'the work directory path has a line break' };
  mkdirSync(input, { recursive: true });
  // The copy holds the scope's C/C++ files only: no cppcheck.cfg, *.cppcheck project, addon or
  // rule file of the checkout is ever in cppcheck's working directory (config.md §6.2).
  const copied = copyCheckedFiles(ctx.root, candidates, input);
  if (copied.length < candidates.length) {
    ctx.log.warn(
      `cppcheck: ${candidates.length - copied.length} C/C++ file(s) not analysed (a link, or a file that cannot be read)`,
    );
  }
  if (copied.length === 0) return { skip: 'no C or C++ file in scope that cppcheck can be given' };
  return { copied, input };
}

/** cppcheck's input arguments: Qualor's rewritten database, or a file list with the settings. */
function inputArgs(
  ctx: AnalyzerContext,
  db: { rel: string } | { none: string },
  copy: { copied: ScopeFile[]; input: string },
): string[] | { skip: string } {
  const { copied, input } = copy;
  if ('rel' in db) {
    const project = writeProject(ctx, db.rel, copied, input);
    if ('skip' in project) return project;
    return [`--project=${project.file}`];
  }
  const settings = ctx.config.analyzers.cppcheck;
  // cppcheck reads a lone .h as C: a C++ header is analysed where a source includes it.
  const listed = copied.filter((f) => !(f.language === 'cpp' && isCHeader(f.path)));
  if (listed.length === 0) return { skip: 'no C or C++ source file in scope for cppcheck' };
  const list = path.join(ctx.workDir, 'cppcheck-files.txt');
  writeFileSync(list, listed.map((f) => `${f.path}\n`).join(''));
  return [
    `--file-list=${list}`,
    ...settings.includePaths.map((dir) => `-I${path.join(input, ...dir.split('/'))}`),
    ...settings.defines.map((d) => `-D${d}`),
  ];
}

/** The run's transform: cppcheck's xmlv2 as SARIF, with one log line per kind of dropped result. */
function cppcheckTransform(
  ctx: AnalyzerContext,
  version: string,
  input: string,
): (output: unknown) => unknown {
  return (output) => {
    const { log, notAnalysed, outside } = cppcheckXmlToSarif(String(output), {
      version,
      base: input,
    });
    logNotAnalysed(ctx, notAnalysed);
    // Ruling D9-9: a count only, never the foreign path.
    if (outside > 0) {
      ctx.log.warn(
        `cppcheck: ${outside} result(s) or note(s) located outside the repository were dropped`,
      );
    }
    return log;
  };
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.cppcheck;
  const db = findCompileCommands(ctx.root, settings.compileCommands);
  if ('skip' in db) return db;
  const found = await findCppcheck(ctx);
  if (!('cppcheck' in found)) return found;
  const { cppcheck, version } = found;
  const copy = copyInput(ctx);
  if ('skip' in copy) return copy;
  const input = copy.input;
  const out = path.join(ctx.workDir, 'cppcheck.xml');
  const jobs = Math.max(1, Math.min(4, availableParallelism()));
  const files = inputArgs(ctx, db, copy);
  if (!Array.isArray(files)) return files;
  const args = [
    '-q',
    `-j${jobs}`,
    `--enable=${settings.enable.join(',')}`,
    '--inline-suppr',
    // Ruling D9-14: the default-off ids, unless `select` names them.
    ...cppcheckSuppressed(settings.select).map((id) => `--suppress=${id}`),
    '--output-format=xmlv2',
    `--output-file=${out}`,
    `--relative-paths=${input}`,
    ...files,
  ];
  const own = cFamilyEnv(ctx.workDir);
  return {
    run: {
      command: cppcheck,
      args,
      cwd: input,
      env: own,
      dropEnv: cFamilyDropEnv(own),
      sarifPath: out,
      outputFormat: 'text',
      okExitCodes: [0],
      version,
      transform: cppcheckTransform(ctx, version, input),
    },
  };
}

/**
 * cppcheck joins a database entry's `arguments` into one command line and splits it again, so a
 * kept argument with a quote, a backslash or white space could become other arguments: dropped.
 */
const UNSAFE_ARGUMENT = /["\\\s]/;
/**
 * Ruling D9-18 (revising D9-17): a file whose repository path has a quote or a control character
 * is left out of cppcheck's database (its `-c <file>` argument). White space is kept: cppcheck
 * 2.22 quotes such an argument and does not split it (cppcheck-real.test.ts guards this).
 */
// eslint-disable-next-line no-control-regex
const UNSAFE_FILE_PATH = /["\u0000-\u001f\u007f]/;
/** Options of the sanitised arguments whose separate value cppcheck's rewrite leaves out. */
const DROPPED_VALUE_OPTIONS = new Set(['-include', '-idirafter', '-isysroot', '-x', '-target']);
const INCLUDE_OPTION = /^(-I|-isystem|-iquote)(.*)$/;

/** The state of one rewrite of database arguments for cppcheck (writeProject). */
interface Rewrite {
  /** A directory as its place in the checked copy; null outside the repository or unsafe. */
  toCopy: (dir: string) => string | null;
  droppedIncludes: number;
  droppedUnsafe: number;
}

/** A kept argument, unless cppcheck's re-splitting could turn it into others. */
function keepArg(r: Rewrite, args: string[], a: string): void {
  if (UNSAFE_ARGUMENT.test(a)) r.droppedUnsafe++;
  else args.push(a);
}

/** An include directory of the entry, mapped into the copy (or dropped and counted). */
function addInclude(r: Rewrite, args: string[], dir: { directory: string; value: string }): void {
  if (/["\s]/.test(dir.value)) {
    r.droppedUnsafe++;
    return;
  }
  const mapped = dir.value === '' ? null : r.toCopy(path.resolve(dir.directory, dir.value));
  if (mapped === null) r.droppedIncludes++;
  else args.push(`-I${mapped}`);
}

/** One argument of an entry (with its value), rewritten into `args`; returns how many it used. */
function rewriteStep(r: Rewrite, e: CompileEntry, at: { i: number; args: string[] }): number {
  const { i, args } = at;
  const a = e.args[i] ?? '';
  const flag = INCLUDE_OPTION.exec(a);
  if (flag !== null) {
    const attached = flag[2] ?? '';
    const value = attached === '' ? (e.args[i + 1] ?? '') : attached;
    addInclude(r, args, { directory: e.directory, value });
    return attached === '' ? 2 : 1;
  }
  if (/^-[DU]./.test(a) || a.startsWith('-std=')) {
    keepArg(r, args, a);
    return 1;
  }
  if ((a === '-D' || a === '-U') && i + 1 < e.args.length) {
    keepArg(r, args, `${a}${e.args[i + 1] ?? ''}`);
    return 2;
  }
  return DROPPED_VALUE_OPTIONS.has(a) ? 2 : 1;
}

/** An entry's arguments for cppcheck: includes mapped into the copy, `-D`, `-U` and `-std=`. */
function rewriteArgs(r: Rewrite, e: CompileEntry): string[] {
  const args: string[] = [];
  let i = 0;
  while (i < e.args.length) i += rewriteStep(r, e, { i, args });
  return args;
}

/** The directory `dir` as its place in the checked copy `input`; null outside the repository. */
function copyMapper(ctx: AnalyzerContext, input: string): (dir: string) => string | null {
  const roots = [path.resolve(ctx.root), realRootOf(ctx.root)];
  return (dir) => {
    const root = roots.find((r) => within(r, dir));
    if (root === undefined) return null;
    const rel = path.relative(root, dir);
    // The part of the path the database chose (separators aside) must also be one argument.
    return UNSAFE_ARGUMENT.test(rel.split(path.sep).join('/')) ? null : path.join(input, rel);
  };
}

/** The info lines of a rewrite: the arguments left out of cppcheck's database, as counts. */
function logRewrite(ctx: AnalyzerContext, r: Rewrite): void {
  if (r.droppedUnsafe > 0) {
    ctx.log.info(
      `cppcheck: ${r.droppedUnsafe} argument(s) with a quote, backslash or space left out (cppcheck splits the database's arguments again)`,
    );
  }
  if (r.droppedIncludes > 0) {
    ctx.log.info(
      `cppcheck: ${r.droppedIncludes} include director(ies) outside the repository left out (cppcheck uses its own library for system headers)`,
    );
  }
}

/**
 * Decision 7: Qualor's rewrite of the compile database for cppcheck, in the checked copy: the
 * copied files only, and only `-I`/`-isystem`/`-iquote` inside the repository (mapped into the
 * copy), `-D`, `-U` and `-std=`. The arguments are Task 7's sanitised ones; the compiler is named
 * by the file's language (`cc` or `c++`), never taken from the database.
 */
function writeProject(
  ctx: AnalyzerContext,
  rel: string,
  copied: readonly ScopeFile[],
  input: string,
): { file: string } | { skip: string } {
  const scope = new Map(copied.map((f) => [f.path, f]));
  const read = readCompileCommands(ctx.root, rel, scope);
  if ('skip' in read) return read;
  if (read.entries.length === 0)
    return { skip: `${shown(rel)} names no C or C++ file of the scan` };
  if (read.droppedArgs > 0 || read.ignoredEntries > 0) {
    ctx.log.info(
      `cppcheck: ${shown(rel)}: ${read.droppedArgs} argument(s) outside Qualor's allowlist dropped, ${read.ignoredEntries} entr(ies) for no file of the scan ignored`,
    );
  }
  const r: Rewrite = { toCopy: copyMapper(ctx, input), droppedIncludes: 0, droppedUnsafe: 0 };
  let unsafeFiles = 0;
  const entries = read.entries.flatMap((e) => {
    // readCompileCommands keeps entries of scope files only.
    const f = scope.get(e.repoPath);
    if (f === undefined) return [];
    if (UNSAFE_FILE_PATH.test(f.path)) {
      unsafeFiles++;
      return [];
    }
    const args = rewriteArgs(r, e);
    const file = copyTarget(input, f);
    return [
      {
        directory: r.toCopy(e.directory) ?? input,
        file,
        arguments: [f.language === 'c' ? 'cc' : 'c++', ...args, '-c', file],
      },
    ];
  });
  if (unsafeFiles > 0) {
    ctx.log.warn(
      `cppcheck: ${unsafeFiles} file(s) whose path has a quote or a control character left out of the compile database`,
    );
  }
  if (entries.length === 0)
    return { skip: `${shown(rel)} names no C or C++ file of the scan that cppcheck can take` };
  logRewrite(ctx, r);
  const file = path.join(ctx.workDir, 'cppcheck-compile-commands.json');
  writeFileSync(file, JSON.stringify(entries));
  return { file };
}

function checkConfig(_root: string, config: QualorConfig): string | null {
  return checkCompileCommandsSetting(
    config.analyzers.cppcheck.compileCommands,
    'analyzers.cppcheck',
  );
}

export const cppcheckAnalyzer: Analyzer = {
  id: 'cppcheck',
  languages: ['c', 'cpp'],
  ruleLanguages: ['c', 'cpp'],
  prepare,
  checkConfig,
};
