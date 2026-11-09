import { statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { CppcheckEnableGroup, QualorConfig } from '@qualor/shared';
import type { ScopeFile } from '../discovery/discover';
import { checkRepoFileSetting } from './cfamily-common';
import { shown } from './reason';
import type { AnalyzerContext } from './types';
import { readRepoConfigBytes, WeblintConfigError } from './weblint';

type Settings = QualorConfig['analyzers']['cppcheck'];

const MAX_RULE_TEXTS_BYTES = 1024 * 1024;
const SETTINGS_KEY = 'analyzers.cppcheck';

/**
 * Issue #33: cppcheck starts an addon through a shell (`popen`), with the path of the source file's
 * dump on its command line, so a file named `$(cmd).c` would run `cmd`. Only these characters may
 * reach that command line. Quoting cannot help: cppcheck builds the command itself.
 */
const SHELL_INERT_PATH = /^[\p{L}\p{N}_+./ -]+$/u;

/** A path a shell leaves alone; a leading `-` would be an option of the addon. */
export function addonSafePath(p: string): boolean {
  return SHELL_INERT_PATH.test(p) && !p.startsWith('-');
}

/** An absolute path of this machine, with a Windows drive and separators read as POSIX ones. */
function addonSafeAbsolute(p: string): boolean {
  return addonSafePath(
    process.platform === 'win32' ? p.replace(/^[A-Za-z]:/, '').replaceAll('\\', '/') : p,
  );
}

/** With addons on, the files whose path can reach the addon's shell; the others get a warning. */
export function withAddonSafePaths(ctx: AnalyzerContext, files: ScopeFile[]): ScopeFile[] {
  if (ctx.config.analyzers.cppcheck.addons.length === 0) return files;
  const safe = files.filter((f) => addonSafePath(f.path));
  const left = files.length - safe.length;
  if (left > 0) {
    ctx.log.warn(
      `cppcheck: ${left} C/C++ file(s) left out: with addons, a path may hold only letters, digits, spaces and _ + . / -`,
    );
  }
  return safe;
}

/** cppcheck drops an addon's result unless the result's severity is enabled. */
export function enabledGroups(settings: Settings): readonly CppcheckEnableGroup[] {
  if (settings.addons.length === 0) return settings.enable;
  return [...new Set<CppcheckEnableGroup>([...settings.enable, 'warning', 'style'])];
}

/** The groups cppcheck's own results are limited to, when addons widened `enabledGroups`. */
export function projectGroups(settings: Settings): ReadonlySet<string> | undefined {
  return settings.addons.length === 0 ? undefined : new Set(settings.enable);
}

function isFile(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
}

/** The misra addon with `--rule-texts`: an addon file of Qualor's, and a copy of the texts. */
function misraWithRuleTexts(
  ctx: AnalyzerContext,
  script: string,
  rel: string,
): { addon: string } | { skip: string } {
  let texts: Buffer;
  try {
    texts = readRepoConfigBytes(
      ctx.root,
      rel,
      MAX_RULE_TEXTS_BYTES,
      `misraRuleTexts ${shown(rel)}`,
    );
  } catch (err) {
    if (err instanceof WeblintConfigError) return { skip: err.message };
    throw err;
  }
  const copy = path.join(ctx.workDir, 'misra-rule-texts.txt');
  writeFileSync(copy, texts);
  const addon = path.join(ctx.workDir, 'cppcheck-addon-misra.json');
  writeFileSync(addon, JSON.stringify({ script, args: [`--rule-texts=${copy}`] }));
  return { addon };
}

export interface AddonRun {
  args: string[];
  env: Record<string, string>;
}

/** Why the addons cannot run in this environment, or null. */
function environmentProblem(ctx: AnalyzerContext, python: string, dir: string): string | null {
  if (!addonSafeAbsolute(python) || !addonSafeAbsolute(dir)) {
    return "the path of python3 or of cppcheck's addons has a character a shell would interpret";
  }
  // Its path also goes into an addon's arguments, which cppcheck splits at spaces.
  if (!addonSafeAbsolute(ctx.workDir) || ctx.workDir.includes(' ')) {
    return 'the work directory path has a character a shell would interpret';
  }
  return null;
}

/**
 * The options that run the chosen addons, always by absolute path from cppcheck's own install: the
 * checkout never names a script. `cppcheck` is `<prefix>/bin/cppcheck`, as install-cppcheck.sh
 * lays it out.
 */
export function addonCommand(ctx: AnalyzerContext, cppcheck: string): AddonRun | { skip: string } {
  const { addons, misraRuleTexts } = ctx.config.analyzers.cppcheck;
  if (addons.length === 0) return { args: [], env: {} };
  const python = ctx.resolveBinary('python3');
  if (python === null) {
    return { skip: 'cppcheck addons need python3 (on PATH or in the qualor/scanner image)' };
  }
  const dir = path.join(path.dirname(path.dirname(cppcheck)), 'share', 'cppcheck', 'addons');
  const missing = addons.find((a) => !isFile(path.join(dir, `${a}.py`)));
  if (missing !== undefined) {
    return { skip: `cppcheck addon ${missing} is not installed (use the qualor/scanner image)` };
  }
  const problem = environmentProblem(ctx, python, dir);
  if (problem !== null) return { skip: problem };
  const args = [`--addon-python=${python}`];
  for (const a of addons) {
    const script = path.join(dir, `${a}.py`);
    if (a === 'misra' && misraRuleTexts !== null) {
      const misra = misraWithRuleTexts(ctx, script, misraRuleTexts);
      if ('skip' in misra) return misra;
      args.push(`--addon=${misra.addon}`);
    } else {
      args.push(`--addon=${script}`);
    }
  }
  return { args, env: { PYTHONDONTWRITEBYTECODE: '1' } };
}

/** Exit 2 for a `misraRuleTexts` that is no repository file, or has no misra addon to read it. */
export function checkAddonSettings(config: QualorConfig): string | null {
  const { addons, misraRuleTexts } = config.analyzers.cppcheck;
  if (misraRuleTexts === null) return null;
  const bad = checkRepoFileSetting(SETTINGS_KEY, 'misraRuleTexts', misraRuleTexts);
  if (bad !== null) return bad;
  return addons.includes('misra')
    ? null
    : `${SETTINGS_KEY}.misraRuleTexts needs misra in ${SETTINGS_KEY}.addons`;
}
