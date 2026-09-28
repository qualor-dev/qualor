import path from 'node:path';
import { isSecretVarName } from '../config/settings';
import { isInside } from './binary';

/**
 * Variable names stripped from every analyzer's child process environment, on top of the
 * generic secret-suffix rule reused from `qualor.yml` interpolation (`isSecretVarName`).
 * `QUALOR_TOKEN_FILE` does not end in one of that rule's suffixes, so it needs listing here.
 */
const EXTRA_STRIPPED = new Set(['QUALOR_TOKEN', 'QUALOR_TOKEN_FILE']);

/**
 * Fix-round finding 3: analyzers run repo-controlled code (ESLint plugins, PMD rulesets, Semgrep
 * rules), so the server token must never be visible to their process environment. Strips
 * `QUALOR_TOKEN`, `QUALOR_TOKEN_FILE`, and any other `QUALOR_`-prefixed variable that looks like a
 * secret by the same name rule `qualor.yml` interpolation uses; every other variable (`PATH`,
 * `HOME`, etc.) passes through unchanged.
 *
 * Fix-round-2 finding 6: Windows environment variable names are case-insensitive (`Path` and
 * `PATH` name the same variable), so the match is case-insensitive there; POSIX names are matched
 * as given, since a lower-case `qualor_token` is simply a different, unrelated variable there.
 */
export function sanitizeAnalyzerEnv(
  env: Readonly<Record<string, string | undefined>>,
  o: { platform?: NodeJS.Platform } = {},
): Record<string, string> {
  const platform = o.platform ?? process.platform;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const compareKey = platform === 'win32' ? key.toUpperCase() : key;
    if (EXTRA_STRIPPED.has(compareKey)) continue;
    if (compareKey.startsWith('QUALOR_') && isSecretVarName(compareKey)) continue;
    out[key] = value;
  }
  return out;
}

interface SearchPathVar {
  split: RegExp;
  join: string;
  /**
   * `LD_PRELOAD`: a bare library name (no `/`) is looked up in the library path (confined too)
   * and the system directories, never in the working directory, so it is kept.
   */
  bareNames?: boolean;
}

/**
 * Search paths a launcher script, the JVM or the dynamic loader resolves programs, classes and
 * libraries from, with the separator of their entries. glibc splits `LD_LIBRARY_PATH` on `:` and
 * `;`, and `LD_PRELOAD` on `:` and spaces.
 */
const SEARCH_PATH_VARS: ReadonlyMap<string, SearchPathVar> = new Map([
  ['PATH', { split: new RegExp(`[${path.delimiter}]`), join: path.delimiter }],
  ['CLASSPATH', { split: new RegExp(`[${path.delimiter}]`), join: path.delimiter }],
  ['LD_LIBRARY_PATH', { split: /[:;]/, join: ':' }],
  ['DYLD_LIBRARY_PATH', { split: /:/, join: ':' }],
  ['DYLD_FALLBACK_LIBRARY_PATH', { split: /:/, join: ':' }],
  ['LD_PRELOAD', { split: /[:\s]/, join: ':', bareNames: true }],
  ['LD_AUDIT', { split: /:/, join: ':' }],
  // Python's import path (Semgrep is a Python program): an empty or relative entry is the
  // working directory, so a repository `requests/` or `sitecustomize.py` would run.
  ['PYTHONPATH', { split: new RegExp(`[${path.delimiter}]`), join: path.delimiter }],
]);

/**
 * Variables that name one location code is loaded from: `JAVA_HOME` (the JDK a launcher runs)
 * and Python's (the standard library, a startup script, the user site-packages with its `.pth`
 * files, compiled `.pyc` files, the interpreter). `PYTHONHOME` may be `prefix${path.delimiter}exec_prefix`, so each is split on the
 * delimiter and kept only when every part is absolute and outside the repository.
 */
const SINGLE_PATH_VARS: ReadonlySet<string> = new Set([
  // The PMD launcher runs `$JAVA_HOME/bin/java` when it is set (SpotBugs checks it itself too).
  'JAVA_HOME',
  'PYTHONHOME',
  'PYTHONSTARTUP',
  'PYTHONUSERBASE',
  'PYTHONPYCACHEPREFIX',
  'PYTHONEXECUTABLE',
]);

/**
 * Ruling V3 applied to the child environment: the PMD and SpotBugs launchers run `java` from
 * `PATH` and put `CLASSPATH` on the JVM class path, both with the repository as the working
 * directory, and the dynamic loader of every child reads `LD_LIBRARY_PATH`, `LD_PRELOAD`,
 * `LD_AUDIT` (and their macOS `DYLD_*` counterparts). A relative or empty entry (the working
 * directory), or one inside the checkout, would let the repository supply a program, a class (a
 * ruleset's `class=`) or a shared library that runs. Only absolute entries outside `root` (also
 * after resolving symlinks) are kept, plus bare library names in `LD_PRELOAD` (the loader never
 * looks for those in the working directory); a variable with none left is removed, because an empty
 * entry means the working directory. Python's variables (Semgrep) get the same treatment:
 * `PYTHONPATH` entry by entry, the single-location ones (`SINGLE_PATH_VARS`) as a whole. On
 * Windows the names match case-insensitively.
 */
export function confineAnalyzerEnv(
  env: Readonly<Record<string, string>>,
  root: string,
): Record<string, string> {
  const out: Record<string, string> = {};
  const outsideRepo = (entry: string) =>
    entry !== '' && path.isAbsolute(entry) && !isInside(root, entry);
  for (const [key, value] of Object.entries(env)) {
    const name = process.platform === 'win32' ? key.toUpperCase() : key;
    if (SINGLE_PATH_VARS.has(name)) {
      if (value.split(path.delimiter).every(outsideRepo)) out[key] = value;
      continue;
    }
    const list = SEARCH_PATH_VARS.get(name);
    if (list === undefined) {
      out[key] = value;
      continue;
    }
    const kept = value
      .split(list.split)
      .filter((e) => outsideRepo(e) || (list.bareNames === true && e !== '' && !e.includes('/')));
    if (kept.length > 0) out[key] = kept.join(list.join);
  }
  return out;
}

/**
 * The parent environment with an adapter's own variables on top. Windows variable names are
 * case-insensitive, so there a parent `Http_Proxy` is removed before `HTTP_PROXY` is added;
 * otherwise the child would receive both spellings and either could win.
 */
export function mergeAnalyzerEnv(
  parent: Readonly<Record<string, string | undefined>>,
  extra: Readonly<Record<string, string>> | undefined,
  platform: NodeJS.Platform = process.platform,
): Record<string, string | undefined> {
  if (extra === undefined) return { ...parent };
  const replaced = new Set(
    Object.keys(extra).map((k) => (platform === 'win32' ? k.toUpperCase() : k)),
  );
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(parent)) {
    if (!replaced.has(platform === 'win32' ? key.toUpperCase() : key)) out[key] = value;
  }
  return { ...out, ...extra };
}
