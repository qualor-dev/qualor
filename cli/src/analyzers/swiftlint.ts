import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { SWIFTLINT_VERSION, swiftlintVersionSupported } from '@qualor/shared';
import picomatch from 'picomatch';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { copyCheckedFiles, copyTarget } from './checked-copy';
import { deadProxyEnv } from './offline';
import { detailLine, stderrLines } from './reason';
import { checkSwiftlintConfig, loadSwiftlintConfig } from './swiftlint-config';
import { swiftlintSarif } from './swiftlint-sarif';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

const NOT_INSTALLED =
  'SwiftLint is not installed (swiftlint on PATH or in the qualor/scanner image)';

/** The checked copy of the files SwiftLint lints, below the work directory (ruling F10). */
const INPUT_DIR = 'src';

/**
 * config.md §6: the only inherited variables SwiftLint sees (matched without case). SwiftLint
 * replaces `${VAR}` in its configuration from its environment, so nothing else may reach it.
 */
export const SWIFTLINT_KEPT_ENV: ReadonlySet<string> = new Set([
  'PATH',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'SYSTEMROOT',
  'WINDIR',
]);

/**
 * The line breaks Foundation's `enumerateLines` splits SwiftLint's `.xcfilelist` on: a path
 * holding one would be read as two (ruling F6).
 */
const LINE_BREAK = /[\r\n\x85\u2028\u2029]/;

/** `swiftlint version` prints the bare version (`0.65.1`). */
export function parseSwiftlintVersion(stdout: string): string | null {
  return /^(\d+\.\d+\.\d+)$/.exec(stdout.trim())?.[1] ?? null;
}

/**
 * SwiftLint lints a listed file only when its extension is exactly `swift` (`URL.isSwiftFile`,
 * case-sensitive): `Package.SWIFT` is Swift to Qualor, but not to SwiftLint (ruling F6).
 */
function swiftName(repoPath: string): boolean {
  const base = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  return base.length > '.swift'.length && base.endsWith('.swift');
}

/** SwiftLint's stderr lines that say why it stopped (`error: …`, `Fatal error: …`). */
const ERROR_LINE = /^(fatal error|error):/i;

/**
 * Why SwiftLint failed (ruling F8), for the log only: the first `error:` line of its stderr (the
 * YAML error, `No lintable files found`), else its last meaningful line, with the work directory
 * shown as `<work>`, as one bounded line. Its environment is an allowlist, so its stderr cannot
 * echo a CI secret.
 */
export function swiftlintFailureDetail(stderr: string, workDir: string): string | null {
  const lines = stderrLines(stderr);
  const line = lines.find((l) => ERROR_LINE.test(l.trim())) ?? lines.at(-1);
  if (line === undefined) return null;
  return detailLine(line.split(workDir).join('<work>'));
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.swiftlint;
  // `qualor scan` stops with exit 2 on a configFile that is a URL or outside the repository
  // (checkConfig) before any analyzer runs; this is the same check for any other caller.
  const plan = loadSwiftlintConfig(ctx.root, settings.configFile);
  if ('error' in plan) return { skip: plan.error };
  if ('skip' in plan) return plan;
  const swiftlint = ctx.resolveBinary('swiftlint');
  if (swiftlint === null) {
    return {
      skip:
        ctx.repoBinary('swiftlint') === null
          ? NOT_INSTALLED
          : `${NOT_INSTALLED}; the repository's own swiftlint is never run`,
    };
  }
  const probe = await ctx.exec(swiftlint, ['version'], { timeoutMs: 30_000, cwd: ctx.workDir });
  const version = probe.exitCode === 0 ? parseSwiftlintVersion(probe.stdout) : null;
  if (version === null) return { unavailable: '`swiftlint version` printed no version' };
  if (!swiftlintVersionSupported(version)) {
    const minor = SWIFTLINT_VERSION.split('.').slice(0, 2).join('.');
    return {
      skip: `SwiftLint ${version} is not supported: this Qualor runs SwiftLint ${minor}.x (the qualor/scanner image's ${SWIFTLINT_VERSION})`,
    };
  }
  if (plan.notRun.length > 0) {
    ctx.log.warn(
      `swiftlint: ${plan.notRun.join(', ')} need SourceKit, which the bundled SwiftLint does not have; they do not run`,
    );
  }
  if (plan.dropped.length > 0) {
    ctx.log.info(`swiftlint: ${plan.source}: left out ${plan.dropped.join(', ')} (config.md §6)`);
  }
  const input = path.join(ctx.workDir, INPUT_DIR);
  if (LINE_BREAK.test(input)) {
    return { skip: 'the work directory path has a line break, which SwiftLint would split' };
  }

  // Rulings F6 and F26: a file the scan detects as Swift (a `languages:` override away from swift
  // is respected) whose name ends in exactly `.swift`.
  const otherCase = ctx.files.filter((f) => f.language === 'swift' && !swiftName(f.path)).length;
  if (otherCase > 0) {
    ctx.log.warn(
      `swiftlint: ${otherCase} Swift file(s) whose name does not end in .swift were left out (SwiftLint lints only *.swift)`,
    );
  }
  const named = ctx.files.filter((f) => f.language === 'swift' && swiftName(f.path));
  const lineBreaks = named.filter((f) => LINE_BREAK.test(f.path)).length;
  if (lineBreaks > 0) {
    ctx.log.warn(`swiftlint: ${lineBreaks} file(s) whose path has a line break were left out`);
  }
  if (named.length === lineBreaks) {
    return {
      skip: 'no Swift file left to lint: names SwiftLint cannot read (case or line break)',
    };
  }
  const inScope = plan.included.length > 0 ? picomatch(plan.included, { dot: true }) : () => true;
  const excluded = plan.excluded.length > 0 ? picomatch(plan.excluded, { dot: true }) : () => false;
  const kept = named.filter(
    (f) => !LINE_BREAK.test(f.path) && inScope(f.path) && !excluded(f.path),
  );
  if (kept.length === 0) {
    return { skip: `no Swift file left to lint (${plan.source}: included/excluded)` };
  }
  // Ruling F7: the analysis bound of config.md §3.1.
  const large = kept.filter((f) => f.size > MAX_ANALYZED_BYTES).length;
  if (large > 0) {
    ctx.log.warn(`swiftlint: ${large} Swift file(s) larger than 1 MiB were left out`);
  }
  // No `.swiftlint.yml` can exist in the copy: not even a directory of that name.
  const candidates = kept.filter(
    (f) =>
      f.size <= MAX_ANALYZED_BYTES && !f.path.split('/').slice(0, -1).includes('.swiftlint.yml'),
  );
  mkdirSync(input, { recursive: true });
  const files = copyCheckedFiles(ctx.root, candidates, input);
  const leftOut = kept.length - large - files.length;
  if (leftOut > 0) {
    ctx.log.warn(
      `swiftlint: ${leftOut} Swift file(s) not analysed (a link, a file that cannot be read, or one below a directory named .swiftlint.yml)`,
    );
  }
  if (files.length === 0) return { skip: 'no Swift file in scope that SwiftLint can be given' };

  const configPath = path.join(ctx.workDir, 'swiftlint.yml');
  const list = path.join(ctx.workDir, 'swiftlint-files.xcfilelist');
  const out = path.join(ctx.workDir, 'swiftlint.sarif');
  writeFileSync(configPath, plan.yaml);
  writeFileSync(list, files.map((f) => `${copyTarget(input, f)}\n`).join(''));
  const own: Record<string, string> = {
    ...deadProxyEnv(),
    HOME: ctx.workDir,
    // Non-ASCII file names and sources whatever the host's locale (ruling E16 parity).
    LC_ALL: 'C.UTF-8',
    SWIFTLINT_DISABLE_SOURCEKIT: '1',
    SCRIPT_INPUT_FILE_LIST_COUNT: '1',
    SCRIPT_INPUT_FILE_LIST_0: list,
  };
  return {
    run: {
      command: swiftlint,
      args: [
        'lint',
        '--quiet',
        '--no-cache',
        '--config',
        configPath,
        '--use-script-input-file-lists',
        '--reporter',
        'sarif',
        '--output',
        out,
      ],
      // The copy (ruling F10): SARIF URIs are relative to the working directory (fact F4), so
      // they are the repository paths, and no configuration of the checkout is next to them.
      cwd: input,
      env: own,
      dropEnv: (name) => !Object.hasOwn(own, name) && !SWIFTLINT_KEPT_ENV.has(name.toUpperCase()),
      sarifPath: out,
      // 0: no violation or warnings only; 2: a violation at error severity (fact F4).
      okExitCodes: [0, 2],
      version,
      // Relative URIs are written raw: percent-encoded so the normaliser decodes the same name.
      transform: (output) => swiftlintSarif(output),
      failureDetail: (_code, stderr) => swiftlintFailureDetail(stderr, ctx.workDir),
    },
  };
}

export const swiftlintAnalyzer: Analyzer = {
  id: 'swiftlint',
  languages: ['swift'],
  ruleLanguages: ['swift'],
  prepare,
  checkConfig: (root, config) => checkSwiftlintConfig(root, config),
};
