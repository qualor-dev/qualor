import { mkdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isInside } from './binary';
import { copyCheckedFiles } from './checked-copy';
import {
  checkDetektConfig,
  detektConfig,
  QUALOR_DETEKT_DEFAULTS,
  QUALOR_DETEKT_OVERLAY,
} from './detekt-config';
import { detektSarif } from './detekt-sarif';
import { DEAD_PROXY_PROPERTIES, javaBinary } from './jvm';
import { detailLine, shown, stderrLines } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where tools/analyzers/install.sh puts detekt's CLI jar (config.md §4). */
export const DEFAULT_DETEKT_JAR = '/opt/qualor/lib/detekt/detekt-cli.jar';

/** detekt splits `--config` on commas and semicolons. */
const SPLIT = /[,;]/;

/** The copy of the in-scope Kotlin files detekt reads, below the work directory. */
const INPUT_DIR = 'detekt-input';

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Copies the in-scope Kotlin files into `input`, at their repository paths (`copyCheckedFiles`).
 * detekt reads the copy, never the checkout: no path of the checkout reaches its command line
 * (JCommander would split one with a space, detekt one with a comma or semicolon), nothing can
 * change between this check and detekt's read, and the relative paths it reports are the
 * repository's own.
 */
function copyKotlinFiles(ctx: AnalyzerContext, input: string): { copied: number; leftOut: number } {
  const kotlin = ctx.files.filter((f) => f.language === 'kotlin');
  const copied = copyCheckedFiles(ctx.root, kotlin, input).length;
  return { copied, leftOut: kotlin.length - copied };
}

/** detekt's line with the cause of a crash, in the head of its stderr. */
const ORIGINAL_MESSAGE = 'The original exception message was: ';
/** detekt's first stderr line when analysing one file threw. */
const ANALYZING = /^java\.lang\.IllegalStateException: Analyzing (.+) led to an exception\.$/;

/** The work-directory paths in detekt's stderr, and what the user knows them as. */
export interface DetektPaths {
  /** The copy detekt reads (`--input`). */
  input: string;
  /** The checked copy of the project config, or null. */
  projectConfig: string | null;
  /** That config's repository path, or null. */
  projectConfigRel: string | null;
}

/**
 * Why detekt failed, from its stderr (final review, minor 3): the `The original exception message
 * was: …` line, after the file detekt was analysing when there is one, else the first non-empty
 * line; the JVM's `Picked up JAVA_TOOL_OPTIONS: …` echo is never chosen (`stderrLines`), since
 * the CI's options may hold secrets. The copy's paths become repository paths, so the line names the checkout file; then it is
 * one bounded line (`detailLine`). For the log only, never a report `reason`.
 */
export function detektFailureDetail(stderr: string, paths: DetektPaths): string | null {
  const shownPath = (text: string): string => {
    let out = text;
    if (paths.projectConfig !== null && paths.projectConfigRel !== null) {
      out = out.split(paths.projectConfig).join(paths.projectConfigRel);
    }
    for (const prefix of new Set([`${paths.input}/`, `${paths.input}${path.sep}`])) {
      out = out.split(prefix).join('');
    }
    return out;
  };
  const lines = stderrLines(stderr);
  const message = lines.find((l) => l.startsWith(ORIGINAL_MESSAGE));
  if (message !== undefined) {
    const file = lines.map((l) => l.match(ANALYZING)?.[1]).find((f) => f !== undefined);
    return detailLine(shownPath(file === undefined ? message : `${file}: ${message}`));
  }
  const first = lines[0];
  return first === undefined ? null : detailLine(shownPath(first));
}

function prepareWith(defaultJar: string) {
  return (ctx: AnalyzerContext): Promise<Preparation> =>
    Promise.resolve(prepareSync(ctx, defaultJar));
}

function prepareSync(ctx: AnalyzerContext, defaultJar: string): Preparation {
  const config = detektConfig(ctx.root, ctx.config);
  // `error` (a configFile outside the repository) already stopped `qualor scan` with exit 2.
  if (config.kind === 'error' || config.kind === 'skip') return { skip: config.reason };
  let jar = defaultJar;
  const override = ctx.env['QUALOR_DETEKT_JAR'];
  if (override !== undefined && override !== '') {
    if (!path.isAbsolute(override) || isInside(ctx.root, override)) {
      return { unavailable: 'QUALOR_DETEKT_JAR must be an absolute path outside the repository' };
    }
    if (!isFile(override)) {
      return { unavailable: `QUALOR_DETEKT_JAR ${shown(override)} is not a file` };
    }
    jar = override;
  } else if (!isFile(defaultJar)) {
    // An image-bundled resource missing on a plain host, like the sonarjs pass or Trivy's
    // database: a skip, so ruling G6 keeps the scan complete.
    return { skip: 'detekt is not installed (qualor/scanner image)' };
  }
  const java = javaBinary(ctx);
  if (java === null) return { unavailable: 'detekt needs java (JAVA_HOME or PATH)' };
  if (SPLIT.test(ctx.workDir)) {
    return {
      skip: 'the work directory path has a comma or semicolon, which detekt would split',
    };
  }
  const input = path.join(ctx.workDir, INPUT_DIR);
  mkdirSync(input, { recursive: true });
  const { copied, leftOut } = copyKotlinFiles(ctx, input);
  if (leftOut > 0) {
    ctx.log.warn(
      `detekt: ${leftOut} Kotlin file(s) not analysed (a link, a file larger than 1 MiB or one that cannot be read)`,
    );
  }
  if (copied === 0) return { skip: 'no Kotlin file in scope that detekt can be given' };
  const configs: string[] = [];
  let projectConfig: string | null = null;
  if (config.kind === 'project') {
    // The checked text, not the file: nothing can change between the check and detekt's read.
    projectConfig = path.join(ctx.workDir, 'project-detekt.yml');
    writeFileSync(projectConfig, config.text);
    configs.push(projectConfig);
  } else {
    // No project config: detekt's defaults with its Jetpack Compose settings (Important 1).
    const defaults = path.join(ctx.workDir, 'qualor-detekt-defaults.yml');
    writeFileSync(defaults, QUALOR_DETEKT_DEFAULTS);
    configs.push(defaults);
  }
  const paths: DetektPaths = {
    input,
    projectConfig,
    projectConfigRel: config.kind === 'project' ? config.rel : null,
  };
  const overlay = path.join(ctx.workDir, 'qualor-detekt.yml');
  writeFileSync(overlay, QUALOR_DETEKT_OVERLAY);
  configs.push(overlay);
  const out = path.join(ctx.workDir, 'detekt.sarif');
  return {
    run: {
      command: java,
      // Every path is the work directory's or the jar's, so no JCommander `@file` is needed and the
      // command line stays short on any repository size. Never --classpath (type resolution stays
      // out), --plugins, --baseline, --jdk-home or --all-rules.
      args: [
        // At most half the memory the JVM sees, like SpotBugs.
        '-XX:MaxRAMPercentage=50',
        ...DEAD_PROXY_PROPERTIES,
        // Non-ASCII file names and sources survive whatever the host's locale (ruling E16).
        '-Dfile.encoding=UTF-8',
        '-Dsun.jnu.encoding=UTF-8',
        '-jar',
        jar,
        '--input',
        input,
        '--base-path',
        input,
        '--config',
        configs.join(','),
        '--build-upon-default-config',
        '--report',
        `sarif:${out}`,
      ],
      env: { LC_ALL: 'C.UTF-8' },
      // Not the checkout: nothing detekt resolves against its working directory is the checkout's.
      cwd: ctx.workDir,
      sarifPath: out,
      // 0: ran; 2: ran and found more issues than build.maxIssues; 1 and 3 are failures.
      okExitCodes: [0, 2],
      // The SARIF driver carries detekt's own version.
      version: null,
      transform: (output) => detektSarif(output, ctx.root),
      failureDetail: (_code, stderr) => detektFailureDetail(stderr, paths),
    },
  };
}

export function createDetektAnalyzer(o: { defaultJar?: string } = {}): Analyzer {
  return {
    id: 'detekt',
    languages: ['kotlin'],
    ruleLanguages: ['kotlin'],
    prepare: prepareWith(o.defaultJar ?? DEFAULT_DETEKT_JAR),
    checkConfig: checkDetektConfig,
  };
}

export const detektAnalyzer: Analyzer = createDetektAnalyzer();
