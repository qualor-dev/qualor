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
  ctx.log.warn(
    `cppcheck: ${detailLine(`${total} result(s) say it could not fully analyse the code (${ids}); they are not issues`)}`,
  );
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.cppcheck;
  const db = findCompileCommands(ctx.root, settings.compileCommands);
  if ('skip' in db) return db;
  const cppcheck = ctx.resolveBinary('cppcheck');
  if (cppcheck === null) {
    return {
      skip:
        ctx.repoBinary('cppcheck') === null
          ? NOT_INSTALLED
          : `${NOT_INSTALLED}; the repository's own cppcheck is never run`,
    };
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

  const out = path.join(ctx.workDir, 'cppcheck.xml');
  const jobs = Math.max(1, Math.min(4, availableParallelism()));
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
  ];
  if ('rel' in db) {
    const project = writeProject(ctx, db.rel, copied, input);
    if ('skip' in project) return project;
    args.push(`--project=${project.file}`);
  } else {
    // cppcheck reads a lone .h as C: a C++ header is analysed where a source includes it.
    const listed = copied.filter((f) => !(f.language === 'cpp' && isCHeader(f.path)));
    if (listed.length === 0) return { skip: 'no C or C++ source file in scope for cppcheck' };
    const list = path.join(ctx.workDir, 'cppcheck-files.txt');
    writeFileSync(list, listed.map((f) => `${f.path}\n`).join(''));
    args.push(`--file-list=${list}`);
    for (const dir of settings.includePaths) args.push(`-I${path.join(input, ...dir.split('/'))}`);
    for (const d of settings.defines) args.push(`-D${d}`);
  }
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
      transform: (output) => {
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
      },
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
  const roots = [path.resolve(ctx.root), realRootOf(ctx.root)];
  const toCopy = (dir: string): string | null => {
    for (const root of roots) {
      if (within(root, dir)) {
        const rel = path.relative(root, dir);
        // The part of the path the database chose (separators aside) must also be one argument.
        if (UNSAFE_ARGUMENT.test(rel.split(path.sep).join('/'))) return null;
        return path.join(input, rel);
      }
    }
    return null;
  };
  let droppedIncludes = 0;
  let droppedUnsafe = 0;
  let unsafeFiles = 0;
  const keep = (args: string[], a: string) => {
    if (UNSAFE_ARGUMENT.test(a)) droppedUnsafe++;
    else args.push(a);
  };
  const entries = read.entries.flatMap((e) => {
    // readCompileCommands keeps entries of scope files only.
    const f = scope.get(e.repoPath);
    if (f === undefined) return [];
    if (UNSAFE_FILE_PATH.test(f.path)) {
      unsafeFiles++;
      return [];
    }
    const args: string[] = [];
    for (let i = 0; i < e.args.length; i++) {
      const a = e.args[i] ?? '';
      const flag = INCLUDE_OPTION.exec(a);
      if (flag !== null) {
        const value = flag[2] !== '' ? (flag[2] ?? '') : (e.args[++i] ?? '');
        if (/["\s]/.test(value)) {
          droppedUnsafe++;
          continue;
        }
        const mapped = value === '' ? null : toCopy(path.resolve(e.directory, value));
        if (mapped !== null) args.push(`-I${mapped}`);
        else droppedIncludes++;
      } else if (/^-[DU]./.test(a) || a.startsWith('-std=')) {
        keep(args, a);
      } else if ((a === '-D' || a === '-U') && i + 1 < e.args.length) {
        keep(args, `${a}${e.args[++i] ?? ''}`);
      } else if (DROPPED_VALUE_OPTIONS.has(a)) {
        i++;
      }
    }
    const file = copyTarget(input, f);
    return [
      {
        directory: toCopy(e.directory) ?? input,
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
  if (droppedUnsafe > 0) {
    ctx.log.info(
      `cppcheck: ${droppedUnsafe} argument(s) with a quote, backslash or space left out (cppcheck splits the database's arguments again)`,
    );
  }
  if (droppedIncludes > 0) {
    ctx.log.info(
      `cppcheck: ${droppedIncludes} include director(ies) outside the repository left out (cppcheck uses its own library for system headers)`,
    );
  }
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
