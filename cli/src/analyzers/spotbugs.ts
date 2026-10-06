import { lstatSync, opendirSync, readdirSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import type { ScopeFile } from '../discovery/discover';
import { staysInside } from './binary';
import { DEAD_PROXY_PROPERTIES, javaBinary } from './jvm';
import { shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Entries examined while checking a class directory for links out of the repository. */
const MAX_ENTRIES_CHECKED = 1_000_000;

/** True when `dir` (not a symlink) holds at least one `.class` file somewhere below it. */
export function hasClassFiles(dir: string): boolean {
  return inspectClassDir(dir, dir).hasClasses;
}

interface ClassDirInspection {
  /** At least one `.class` file, or a link to one inside the repository, somewhere below. */
  hasClasses: boolean;
  problem: 'links outside the repository' | 'too large' | null;
}

/**
 * One walk of a class directory. SpotBugs 4.10 does not descend into a linked directory (neither
 * does this walk), but it does read a linked file, so a link to a file outside the repository
 * (a class or an archive from elsewhere) is refused. A tree too large to check completely is
 * refused rather than trusted.
 */
function inspectClassDir(root: string, dir: string): ClassDirInspection {
  const result: ClassDirInspection = { hasClasses: false, problem: null };
  try {
    if (!lstatSync(dir).isDirectory()) return result;
  } catch {
    return result;
  }
  const stack = [dir];
  let entries = 0;
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let handle;
    try {
      handle = opendirSync(current);
    } catch {
      continue;
    }
    try {
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        entries += 1;
        if (entries > MAX_ENTRIES_CHECKED) return { ...result, problem: 'too large' };
        const full = path.join(current, entry.name);
        if (entry.isSymbolicLink()) {
          let isFile = false;
          try {
            isFile = statSync(full).isFile();
          } catch {
            continue;
          }
          if (!isFile) continue;
          if (!staysInside(root, full)) {
            return { ...result, problem: 'links outside the repository' };
          }
          if (entry.name.endsWith('.class')) result.hasClasses = true;
        } else if (entry.isDirectory()) {
          stack.push(full);
        } else if (entry.isFile() && entry.name.endsWith('.class')) {
          result.hasClasses = true;
        }
      }
    } finally {
      handle.closeSync();
    }
  }
  return result;
}

const SOURCE_ROOT = /^((?:.*\/)?src\/(?:main|test)\/java)\//;

/**
 * Maven/Gradle source roots of the in-scope Java files (`…/src/main/java`, `…/src/test/java`),
 * repo-relative. SpotBugs reports paths relative to a source root (`com/acme/A.java`), so the
 * normaliser tries these prefixes, and `-sourcepath` lets SpotBugs name the root itself.
 */
export function javaSourceRoots(files: readonly ScopeFile[]): string[] {
  const roots = new Set<string>();
  for (const f of files) {
    if (f.language !== 'java') continue;
    const m = SOURCE_ROOT.exec(f.path);
    if (m?.[1] !== undefined) roots.add(m[1]);
  }
  return [...roots].sort();
}

/** `-sourcepath` longer than this is cut to the roots that fit (it only helps name paths). */
const MAX_SOURCEPATH_CHARS = 32 * 1024;
/** All class directories together: more does not fit on one command line everywhere. */
const MAX_CLASS_DIR_CHARS = 128 * 1024;

/** A list of user-supplied names in a reason: the first few, then how many more. */
function listed(names: readonly string[], max = 5): string {
  const head = names
    .slice(0, max)
    .map((n) => shown(n))
    .join(', ');
  return names.length > max ? `${head} and ${names.length - max} more` : head;
}

/**
 * The SpotBugs installation behind a resolved `spotbugs` launcher: its home (the parent of the
 * launcher's real directory, or `share/spotbugs` below it in an FHS layout) and its
 * `lib/spotbugs.jar`.
 */
export function spotbugsHome(launcher: string): { home: string; jar: string } | null {
  let home: string;
  try {
    home = path.dirname(path.dirname(realpathSync(launcher)));
  } catch {
    return null;
  }
  const fhs = path.join(home, 'share', 'spotbugs');
  try {
    if (statSync(fhs).isDirectory()) home = fhs;
  } catch {
    // not an FHS layout
  }
  const jar = path.join(home, 'lib', 'spotbugs.jar');
  try {
    return statSync(jar).isFile() ? { home, jar } : null;
  } catch {
    return null;
  }
}

/** The SARIF tool extension SpotBugs writes for the FindSecBugs plugin (plan 6A). */
export const FINDSECBUGS_EXTENSION = 'com.h3xstream.findsecbugs';

const FINDSECBUGS_JAR = /^findsecbugs-plugin-(\d+\.\d+\.\d+)\.jar$/;

/**
 * The FindSecBugs jar in a SpotBugs home's plugin/ directory, where SpotBugs loads every jar from
 * (the qualor/scanner image installs it there, tools/analyzers/install.sh), with the version its
 * file name carries; the first in name order when there are several. Null without one.
 */
export function findsecbugsPlugin(home: string): { jar: string; version: string } | null {
  let names: string[];
  try {
    names = readdirSync(path.join(home, 'plugin')).sort();
  } catch {
    return null;
  }
  for (const name of names) {
    const m = FINDSECBUGS_JAR.exec(name);
    if (m?.[1] !== undefined) return { jar: path.join(home, 'plugin', name), version: m[1] };
  }
  return null;
}

/**
 * config.md §6 (plan 6A): FindSecBugs reads its settings from `findsecbugs.*` environment
 * variables (and the same names with `_`), some naming files it opens relative to the working
 * directory (the checkout) or writes there. The CLI drops them, so nothing from the checkout or a
 * stray CI variable configures the plugin. A `-Dfindsecbugs.*` option in `JAVA_TOOL_OPTIONS`,
 * `_JAVA_OPTIONS` or `JDK_JAVA_OPTIONS` still reaches it: like `-javaagent`, those variables
 * belong to the CI and are passed through.
 */
export function isFindsecbugsVariable(name: string): boolean {
  return name.toLowerCase().startsWith('findsecbugs');
}

/**
 * config.md §6 (plan 6A): when the log lists the FindSecBugs extension (whose own version field
 * SpotBugs leaves empty), the driver version becomes `<SpotBugs> + FindSecBugs <version>`, so the
 * report says the plugin ran. Mutates `output` in place; anything that is not a SARIF log is left
 * as it is.
 */
export function withFindsecbugsVersion(output: unknown, pluginVersion: string | null): void {
  if (typeof output !== 'object' || output === null) return;
  const runs = (output as { runs?: unknown }).runs;
  if (!Array.isArray(runs)) return;
  const suffix = pluginVersion === null ? '' : ` ${pluginVersion}`;
  for (const run of runs) {
    if (typeof run !== 'object' || run === null) continue;
    const tool = (run as { tool?: unknown }).tool;
    if (typeof tool !== 'object' || tool === null) continue;
    const { driver, extensions } = tool as { driver?: unknown; extensions?: unknown };
    const loaded =
      Array.isArray(extensions) &&
      extensions.some(
        (e) =>
          typeof e === 'object' &&
          e !== null &&
          (e as { name?: unknown }).name === FINDSECBUGS_EXTENSION,
      );
    if (!loaded || typeof driver !== 'object' || driver === null) continue;
    const d = driver as { version?: unknown };
    if (typeof d.version !== 'string') continue;
    d.version = `${d.version} + FindSecBugs${suffix}`;
  }
}

function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  return Promise.resolve(prepareSync(ctx));
}

function prepareSync(ctx: AnalyzerContext): Preparation {
  const settings = ctx.config.analyzers.spotbugs;
  const dirs: { entry: string; abs: string }[] = [];
  for (const entry of settings.classDirs) {
    const abs = path.resolve(ctx.root, entry);
    // SpotBugs reads everything below a class directory: it must be the repository's own.
    if (!staysInside(ctx.root, abs)) {
      return { skip: `classDirs entry ${shown(entry)} is outside the repository` };
    }
    dirs.push({ entry, abs });
  }
  const withClasses: string[] = [];
  for (const d of dirs) {
    const inspected = inspectClassDir(ctx.root, d.abs);
    if (inspected.problem === 'links outside the repository') {
      return { skip: `classDirs entry ${shown(d.entry)} links outside the repository` };
    }
    if (inspected.problem === 'too large') {
      return {
        skip: `classDirs entry ${shown(d.entry)} has more than ${MAX_ENTRIES_CHECKED} entries`,
      };
    }
    if (inspected.hasClasses) withClasses.push(d.abs);
  }
  if (withClasses.length === 0) {
    return {
      skip: `no compiled classes in ${listed(settings.classDirs)} (build the project before qualor scan)`,
    };
  }
  if (withClasses.reduce((n, d) => n + d.length + 1, 0) > MAX_CLASS_DIR_CHARS) {
    return { skip: 'the classDirs paths are too long for one command line' };
  }
  const aux: string[] = [];
  if (settings.auxClasspathFile !== null) {
    const name = `auxClasspathFile ${shown(settings.auxClasspathFile)}`;
    const file = path.resolve(ctx.root, settings.auxClasspathFile);
    if (!staysInside(ctx.root, file)) return { skip: `${name} is outside the repository` };
    try {
      if (!lstatSync(file).isFile()) throw new Error('not a file');
    } catch {
      return { skip: `${name} does not exist` };
    }
    aux.push('-auxclasspathFromFile', file);
  }
  const launcher = ctx.resolveBinary('spotbugs');
  if (launcher === null) {
    return { unavailable: 'SpotBugs is not installed (spotbugs on PATH or in the scanner image)' };
  }
  const install = spotbugsHome(launcher);
  if (install === null) {
    return {
      unavailable: 'SpotBugs is not installed (no lib/spotbugs.jar next to the spotbugs launcher)',
    };
  }
  const plugin = findsecbugsPlugin(install.home);
  // The jar runs directly on a system java (ruling V3): the launcher script re-splits its
  // arguments on whitespace, so a path with a space would break, and a line break in a directory
  // name would become options of their own (such as `-pluginList <jar>`, which loads code).
  const java = javaBinary(ctx);
  if (java === null) return { unavailable: 'SpotBugs needs java (JAVA_HOME or PATH)' };
  const sourceRoots: string[] = [];
  let sourceChars = 0;
  for (const r of javaSourceRoots(ctx.files)) {
    const abs = path.join(ctx.root, ...r.split('/'));
    // Only for source lookup: a root SpotBugs would split is left out, not a reason to skip.
    if (abs.includes(path.delimiter)) continue;
    sourceChars += abs.length + 1;
    if (sourceChars > MAX_SOURCEPATH_CHARS) break;
    sourceRoots.push(abs);
  }
  const sourcepath =
    sourceRoots.length === 0 ? [] : ['-sourcepath', sourceRoots.join(path.delimiter)];
  const out = path.join(ctx.workDir, 'spotbugs.sarif');
  // SpotBugs reads an argument starting with `@` as an options file and one starting with `-` as
  // an option; every path here is absolute, so this only guards that invariant.
  const paths = [...sourceRoots, ...aux.slice(1), ...withClasses];
  if (paths.some((p) => p.startsWith('-') || p.startsWith('@'))) {
    return { skip: 'SpotBugs cannot be given a path that starts with - or @' };
  }
  return {
    run: {
      command: java,
      args: [
        // At most half the memory the JVM sees (the container limit in a CI job), so SpotBugs on a
        // large codebase cannot starve the analyzers running beside it.
        '-XX:MaxRAMPercentage=50',
        ...DEAD_PROXY_PROPERTIES,
        `-Dspotbugs.home=${install.home}`,
        '-cp',
        install.jar,
        'edu.umd.cs.findbugs.FindBugs2',
        '-quiet',
        // Everything SpotBugs can find; the quality profile decides what becomes an issue.
        '-effort:max',
        '-low',
        `-sarif=${out}`,
        ...sourcepath,
        ...aux,
        ...withClasses,
      ],
      cwd: ctx.root,
      sarifPath: out,
      // Without -exitcode, SpotBugs exits 0 whether or not it found bugs; anything else failed.
      okExitCodes: [0],
      // Plan 6A: `findsecbugs*` variables are dropped (config.md §6); the CI's own JVM option
      // variables (JAVA_TOOL_OPTIONS, …) are kept.
      dropEnv: isFindsecbugsVariable,
      transform: (output: unknown) => {
        withFindsecbugsVersion(output, plugin?.version ?? null);
        return output;
      },
      version: null,
    },
  };
}

export const spotbugsAnalyzer: Analyzer = {
  id: 'spotbugs',
  languages: ['java'],
  ruleLanguages: ['java'],
  prepare,
  sourceRoots: (ctx) => javaSourceRoots(ctx.files),
};
