import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { CLANG_TIDY_MIN_MAJOR, clangTidyVersionSupported } from '@qualor/shared';
import {
  C_LANGUAGES,
  cFamilyDropEnv,
  cFamilyEnv,
  hasLineBreak,
  realRootOf,
} from './cfamily-common';
import { checkClangTidyConfig, loadClangTidyConfig } from './clang-tidy-config';
import { clangTidyFixesToSarif } from './clang-tidy-fixes';
import { findCompileCommands, readCompileCommands } from './compile-commands';
import { detailLine, shown, stderrLines } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

const NOT_INSTALLED =
  'clang-tidy is not installed (no clang-tidy on PATH; no Qualor image bundles it, config.md §6.2)';
/** clang 16 added `--no-default-config`; an older clang rejects it as an unknown argument. */
const NO_DEFAULT_CONFIG_MAJOR = 16;

/** `clang-tidy --version`: `LLVM version 22.1.8` (Debian: `Debian LLVM version 14.0.6`). */
export function parseClangTidyVersion(stdout: string): string | null {
  return /LLVM version (\d+\.\d+\.\d+)/.exec(stdout)?.[1] ?? null;
}

const REGEX_META = /[.*+?^${}()|[\]\\]/g;
/** `--header-filter`: diagnostics in headers of the repository only, through either root spelling. */
export function headerFilter(root: string, realRoot: string): string {
  const esc = (p: string) => p.split(path.sep).join('/').replace(REGEX_META, '\\$&');
  return `^(${esc(root)}|${esc(realRoot)})/`;
}

/** LLVM's GNU response-file syntax: one double-quoted path per line, `\` and `"` escaped. */
const quoted = (p: string) => `"${p.replace(/["\\]/g, '\\$&')}"`;

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers['clang-tidy'];
  const db = findCompileCommands(ctx.root, settings.compileCommands);
  if ('skip' in db) return db;
  if ('none' in db) {
    return {
      skip: `no compile database (${db.none}); clang-tidy needs the project's compile_commands.json (config.md §6.2)`,
    };
  }
  const plan = loadClangTidyConfig(ctx.root, settings.configFile);
  if ('error' in plan) return { skip: plan.error };
  if ('skip' in plan) return plan;
  // Never the checkout's own clang-tidy (ruling V3).
  const bin = ctx.resolveBinary('clang-tidy');
  if (bin === null) {
    return {
      skip:
        ctx.repoBinary('clang-tidy') === null
          ? NOT_INSTALLED
          : `${NOT_INSTALLED}; the repository's own clang-tidy is never run`,
    };
  }
  const probe = await ctx.exec(bin, ['--version'], { timeoutMs: 30_000, cwd: ctx.workDir });
  const version = probe.exitCode === 0 ? parseClangTidyVersion(probe.stdout) : null;
  if (version === null) return { unavailable: '`clang-tidy --version` printed no version' };
  if (!clangTidyVersionSupported(version)) {
    return {
      skip: `clang-tidy ${version} is too old: Qualor runs clang-tidy ${CLANG_TIDY_MIN_MAJOR} or newer`,
    };
  }
  const cFiles = ctx.files.filter((f) => C_LANGUAGES.has(f.language));
  const lineBreaks = cFiles.filter((f) => hasLineBreak(f.path)).length;
  if (lineBreaks > 0) {
    ctx.log.warn(`clang-tidy: ${lineBreaks} file(s) whose path has a line break were left out`);
  }
  const scope = new Map(cFiles.filter((f) => !hasLineBreak(f.path)).map((f) => [f.path, f]));
  const read = readCompileCommands(ctx.root, db.rel, scope);
  if ('skip' in read) return read;
  if (read.entries.length === 0)
    return { skip: `${shown(db.rel)} names no C or C++ file of the scan` };
  if (read.droppedArgs > 0) {
    ctx.log.info(
      `clang-tidy: ${shown(db.rel)}: ${read.droppedArgs} compiler argument(s) left out (config.md §6.2)`,
    );
  }
  if (plan.dropped.length > 0) {
    ctx.log.info(
      `clang-tidy: ${shown(plan.source)}: left out ${plan.dropped.join(', ')} (config.md §6.2)`,
    );
  }
  // Ruling D9-11: static analyzer settings that read or write files; key names only.
  if (plan.droppedOptions.length > 0) {
    ctx.log.warn(
      `clang-tidy: ${shown(plan.source)}: left out CheckOptions ${plan.droppedOptions.join(', ')} (config.md §6.2)`,
    );
  }
  const work = ctx.workDir;
  // Qualor's own database (Task 7's sanitised arguments). The compiler is named by the file's
  // language, never taken from the checkout's database: clang reads a driver mode and a target
  // from argv[0], and nothing of the database is ever executed (clang-tidy runs no compiler).
  writeFileSync(
    path.join(work, 'compile_commands.json'),
    JSON.stringify(
      read.entries.map((e) => ({
        directory: e.directory,
        file: e.file,
        arguments: [
          scope.get(e.repoPath)?.language === 'c' ? 'cc' : 'c++',
          ...e.args,
          '-c',
          e.file,
        ],
      })),
    ),
  );
  const configPath = path.join(work, 'clang-tidy.json');
  writeFileSync(configPath, plan.json);
  const rsp = path.join(work, 'clang-tidy-files.rsp');
  writeFileSync(rsp, read.entries.map((e) => `${quoted(e.file)}\n`).join(''));
  const out = path.join(work, 'clang-tidy-fixes.yaml');
  // clang-tidy writes no file when it finds nothing (fact F8).
  writeFileSync(out, '');
  const realRoot = realRootOf(ctx.root);
  const own = cFamilyEnv(work);
  const major = Number(version.split('.')[0]);
  const inScope = new Set(ctx.files.map((f) => f.path));
  return {
    run: {
      command: bin,
      args: [
        '-p',
        work,
        // With --config-file, clang-tidy reads no .clang-tidy of the checkout, its parents or HOME.
        `--config-file=${configPath}`,
        '--quiet',
        '--use-color=false',
        `--header-filter=${headerFilter(path.resolve(ctx.root), realRoot)}`,
        // No clang configuration file (<driver>.cfg) adds compile arguments Qualor did not allow.
        ...(major >= NO_DEFAULT_CONFIG_MAJOR ? ['--extra-arg=--no-default-config'] : []),
        `--export-fixes=${out}`,
        `@${rsp}`,
      ],
      cwd: work,
      env: own,
      dropEnv: cFamilyDropEnv(own),
      sarifPath: out,
      outputFormat: 'text',
      // 1: a translation unit did not compile; the others were analysed (fact F8).
      okExitCodes: [0, 1],
      version,
      transform: (output) => {
        const r = clangTidyFixesToSarif(String(output), {
          root: ctx.root,
          version,
          scope: inScope,
        });
        if (r.compileErrors > 0) {
          ctx.log.warn(
            `clang-tidy: ${r.compileErrors} compile error(s): clang-tidy could not compile every translation unit (a missing header or flag); those diagnostics are not issues`,
          );
        }
        // Rulings D9-9/D9-11: a count only, never the path (outside the repository, a repository
        // file outside the scan, an offset past the end, a malformed entry; notes included).
        if (r.unplaced > 0) {
          ctx.log.warn(
            `clang-tidy: ${r.unplaced} diagnostic(s) could not be placed on a file of the scan`,
          );
        }
        return r.log;
      },
      failureDetail: (_code, stderr) => {
        const lines = stderrLines(stderr);
        const line = lines.find((l) => l.startsWith('Error: ')) ?? lines.at(-1);
        return line === undefined ? null : detailLine(line.split(work).join('<work>'));
      },
      configWarnings: (stderr) =>
        stderrLines(stderr)
          .filter((l) => l.startsWith('Error: '))
          .slice(0, 1)
          .map((l) => detailLine(l.split(work).join('<work>'))),
    },
  };
}

export const clangTidyAnalyzer: Analyzer = {
  id: 'clang-tidy',
  languages: ['c', 'cpp'],
  ruleLanguages: ['c', 'cpp'],
  prepare,
  // configFile and compileCommands (checkClangTidyConfig checks both).
  checkConfig: (root, config) => checkClangTidyConfig(root, config),
};
