import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { isInside, within } from './binary';
import { checkDetektConfig, detektConfig, QUALOR_DETEKT_OVERLAY } from './detekt-config';
import { detektSarif } from './detekt-sarif';
import { DEAD_PROXY_PROPERTIES, javaBinary } from './jvm';
import { shown } from './reason';
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
 * The file's bytes when it is a regular file inside the root, reached without a symbolic link or
 * junction on the way, of at most 1 MiB (ruling E15); else null. Opened once, without following a
 * link at the last step and without blocking on a FIFO, and judged by that descriptor.
 */
function readPlainFile(root: string, abs: string): Buffer | null {
  try {
    if (!lstatSync(abs).isFile()) return null;
    if (realpathSync(abs) !== path.join(realpathSync(root), path.relative(root, abs))) return null;
    const fd = openSync(
      abs,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > MAX_ANALYZED_BYTES) return null;
      const bytes = readFileSync(fd);
      return bytes.length > MAX_ANALYZED_BYTES ? null : bytes;
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}

/**
 * Copies the in-scope Kotlin files into `input`, at their repository paths. detekt reads the copy,
 * never the checkout: no path of the checkout reaches its command line (JCommander would split one
 * with a space, detekt one with a comma or semicolon), nothing can change between this check and
 * detekt's read, and the relative paths it reports are the repository's own.
 */
function copyKotlinFiles(ctx: AnalyzerContext, input: string): { copied: number; leftOut: number } {
  let copied = 0;
  let leftOut = 0;
  for (const f of ctx.files) {
    if (f.language !== 'kotlin') continue;
    if (copyOne(ctx.root, f, input)) copied++;
    else leftOut++;
  }
  return { copied, leftOut };
}

function copyOne(root: string, f: ScopeFile, input: string): boolean {
  const target = path.join(input, ...f.path.split('/'));
  if (!within(input, target) || target === input) return false;
  const bytes = readPlainFile(root, f.absPath);
  if (bytes === null) return false;
  try {
    mkdirSync(path.dirname(target), { recursive: true });
    // `wx`: two paths that one file system folds together are never merged silently.
    writeFileSync(target, bytes, { flag: 'wx' });
    return true;
  } catch {
    return false;
  }
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
  if (config.kind === 'project') {
    // The checked text, not the file: nothing can change between the check and detekt's read.
    const copy = path.join(ctx.workDir, 'project-detekt.yml');
    writeFileSync(copy, config.text);
    configs.push(copy);
  }
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
