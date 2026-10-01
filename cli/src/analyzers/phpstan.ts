import { mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { PHPSTAN_PHP_VERSION, PHPSTAN_VERSION, phpstanVersionSupported } from '@qualor/shared';
import { isInside } from './binary';
import { copyCheckedFiles } from './checked-copy';
import { isFile } from './detekt';
import { deadProxyEnv } from './offline';
import {
  copyDependencies,
  DEPENDENCIES_NOT_INSTALLED,
  DEPENDENCIES_TOO_LARGE,
  MAX_DEPENDENCY_BYTES,
  MAX_DEPENDENCY_FILES,
  phpDependencies,
} from './phpstan-deps';
import type { Logger } from '../log';
import { phpstanSarif } from './phpstan-output';
import { detailLine, shown, stderrLines } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where tools/analyzers/install.sh puts PHPStan's phar (config.md §4). */
export const DEFAULT_PHPSTAN_PHAR = '/opt/qualor/lib/phpstan/phpstan.phar';
const NOT_INSTALLED = 'PHPStan is not installed (qualor/scanner image)';

/** `php phpstan.phar --version` prints `PHPStan - PHP Static Analysis Tool 2.2.16` (fact P1). */
export function parsePhpstanVersion(stdout: string): string | null {
  return /^PHPStan - PHP Static Analysis Tool (\d+\.\d+\.\d+)\s*$/m.exec(stdout)?.[1] ?? null;
}

/**
 * config.md §6: variables that configure PHP or PHPStan behind the command line's back. PHPRC and
 * PHP_INI_SCAN_DIR name ini files (`auto_prepend_file` runs PHP before PHPStan, fact P4); COMPOSER
 * renames the composer.json PHPStan's start-up reads.
 */
export const isPhpVariable = (name: string): boolean =>
  /^(PHPRC|PHP_INI_SCAN_DIR|COMPOSER(_.*)?|PHPSTAN_.*|XDEBUG_(CONFIG|MODE|SESSION))$/i.test(name);

/**
 * Ruling A9-18: the options of every php Qualor starts for PHPStan (the version probe, the wrapper
 * and the PHPStan it runs). `-n`: no php.ini and no scan directory at all, so neither PHPRC nor a
 * php.ini of the checkout can make php run a file first (`auto_prepend_file`). Only the extensions
 * the phar cannot run without are loaded, from php's own extension directory; a php that has them
 * built in warns on stderr and goes on. Warnings go to stderr, never into the report on stdout.
 */
export const PHP_OPTIONS: readonly string[] = [
  '-n',
  '-d',
  'display_errors=stderr',
  '-d',
  'extension=phar',
  '-d',
  'extension=tokenizer',
];
const phpArray = (values: readonly string[]) => `[${values.map((v) => "'" + v + "'").join(', ')}]`;

/** A NEON double-quoted string: JSON's escapes, and `%%` for `%` (Nette expands `%name%`). */
export function neonString(value: string): string {
  return JSON.stringify(value).replaceAll('%', '%%');
}

/** The whole PHPStan configuration of a scan (config.md §6): nothing else is ever loaded. */
export function phpstanNeon(o: {
  level: number | 'max';
  input: string;
  deps: string | null;
  tmpDir: string;
}): string {
  return [
    '# Written by Qualor (config.md §6, plan 9A): the whole PHPStan configuration of this scan.',
    'parameters:',
    `    level: ${o.level}`,
    `    phpVersion: ${PHPSTAN_PHP_VERSION}`,
    `    tmpDir: ${neonString(o.tmpDir)}`,
    '    reportUnmatchedIgnoredErrors: false',
    `    paths: [${neonString(o.input)}]`,
    ...(o.deps === null ? [] : [`    scanDirectories: [${neonString(o.deps)}]`]),
    '',
  ].join('\n');
}

/**
 * config.md §6, fact P5: `<work>/qualor-phpstan.php`. PHPStan has no output-file option and
 * exits 1 for findings and failures alike; this runs it with stdout going to the report file and
 * decides from the report itself.
 */
export const PHPSTAN_WRAPPER = `<?php
// Written by Qualor (config.md §6, plan 9A). Runs \`php <phar> <args>\` with its standard output
// written to <out> (PHPStan has no output-file option), then checks that output:
// exit 0: <out> is PHPStan's JSON report and lists no general error;
// exit 3: the report lists general errors (printed on stderr);
// exit 4: there is no report (PHPStan's output printed on stderr).
// A file below <input> that PHPStan cannot parse makes it report nothing else (its "severe
// errors"): those copies are deleted, listed in <out>.left-out.json (with the count of such files
// that could not be deleted), and PHPStan runs once more (ruling A9-19).
declare(strict_types=1);
if ($argc < 4) {
    fwrite(STDERR, "qualor-phpstan: usage: qualor-phpstan.php <phar> <out> <input> <args...>\\n");
    exit(4);
}
$phar = $argv[1];
$out = $argv[2];
$input = realpath($argv[3]);
if ($input === false) {
    fwrite(STDERR, "qualor-phpstan: the input directory does not exist\\n");
    exit(4);
}
// Ruling A9-18: PHPStan's php reads no php.ini either.
$php = array_merge([PHP_BINARY], ${phpArray(PHP_OPTIONS)});
$command = array_merge($php, [$phar], array_slice($argv, 4));

/** Runs PHPStan with its standard output in $out; returns its report, or exits 4 without one. */
function qualor_phpstan_run(array $command, string $out): array
{
    $fh = fopen($out, 'xb');
    if ($fh === false) {
        fwrite(STDERR, "qualor-phpstan: cannot create the report file\\n");
        exit(4);
    }
    $proc = proc_open($command, [0 => ['pipe', 'r'], 1 => $fh, 2 => STDERR], $pipes);
    if ($proc === false) {
        fwrite(STDERR, "qualor-phpstan: cannot start PHPStan\\n");
        exit(4);
    }
    fclose($pipes[0]);
    $code = proc_close($proc);
    fclose($fh);
    $text = (string) file_get_contents($out);
    // PHPStan exits 0 (no finding) or 1 (findings or general errors); any other code is a crash
    // whose output, even if it looks like a report, is not trusted.
    if ($code !== 0 && $code !== 1) {
        fwrite(STDERR, "qualor-phpstan: PHPStan wrote no report (exit code $code)\\n" . substr($text, 0, 4000) . "\\n");
        exit(4);
    }
    $report = json_decode($text, true);
    if (!is_array($report) || !isset($report['totals'], $report['files']) || !is_array($report['errors'] ?? null)) {
        fwrite(STDERR, "qualor-phpstan: PHPStan wrote no report (exit code $code)\\n" . substr($text, 0, 4000) . "\\n");
        exit(4);
    }
    return $report;
}

$report = qualor_phpstan_run($command, $out);
$leftOut = [];
$notLeftOut = 0;
foreach (is_array($report['files']) ? $report['files'] : [] as $file => $result) {
    foreach (is_array($result['messages'] ?? null) ? $result['messages'] : [] as $message) {
        if (!is_array($message) || ($message['identifier'] ?? null) !== 'phpstan.parse') {
            continue;
        }
        $real = realpath((string) $file);
        if ($real !== false && strpos($real, $input . DIRECTORY_SEPARATOR) === 0 && is_file($real) && unlink($real)) {
            $leftOut[] = $real;
        } else {
            $notLeftOut++;
        }
        break;
    }
}
if ($leftOut !== [] || $notLeftOut > 0) {
    $leftOutJson = json_encode(['leftOut' => $leftOut, 'notLeftOut' => $notLeftOut], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    file_put_contents($out . '.left-out.json', $leftOutJson);
}
if ($leftOut !== []) {
    unlink($out);
    $left = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($input, FilesystemIterator::SKIP_DOTS)) as $entry) {
        if ($entry->isFile()) {
            $left++;
            break;
        }
    }
    if ($left === 0) {
        // Nothing is left to analyse: PHPStan would refuse an empty path, and there is no finding.
        file_put_contents($out, '{"totals":{"errors":0,"file_errors":0},"files":[],"errors":[]}');
        exit(0);
    }
    $report = qualor_phpstan_run($command, $out);
}
if ($report['errors'] !== []) {
    foreach (array_slice($report['errors'], 0, 20) as $error) {
        fwrite(STDERR, 'PHPStan error: ' . (is_string($error) ? $error : json_encode($error)) . "\\n");
    }
    exit(3);
}
exit(0);
`;

const NO_REPORT = 'qualor-phpstan: PHPStan wrote no report';
const WRAPPER_LINE = /^(PHPStan error: |qualor-phpstan: )/;

/**
 * Why PHPStan failed, for the warn log only (config.md §6): the wrapper's first line, with
 * PHPStan's own first line after a "no report", the work directory shown as `<work>`.
 */
export function phpstanFailureDetail(stderr: string, workDir: string): string | null {
  const lines = stderrLines(stderr);
  const i = lines.findIndex((l) => WRAPPER_LINE.test(l));
  const first = i === -1 ? lines.at(-1) : lines[i];
  if (first === undefined) return null;
  const next = i !== -1 && first.startsWith(NO_REPORT) ? lines[i + 1] : undefined;
  const line = next === undefined ? first : `${first}: ${next.trim()}`;
  return detailLine(line.split(workDir).join('<work>'));
}

/** The environment PHPStan's php gets over the analyzer environment (config.md §6). */
const phpEnv = () => ({ ...deadProxyEnv(), LC_ALL: 'C.UTF-8' });

/**
 * Ruling A9-19: the files the wrapper left out because PHPStan cannot parse them, named by their
 * repository paths in a warning, and a warning when some could not be left out (the result may then
 * be incomplete). `<out>.left-out.json` holds the copies' real paths (`realpath()`), so they are
 * compared with the input directory as given and as resolved (a work directory reached through a
 * link, macOS's /var, a Windows short name). Logged once, whether PHPStan's second run succeeds or
 * fails.
 */
export function warnLeftOut(file: string, input: string, log: Logger): void {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(file, 'utf8'));
    rmSync(file, { force: true });
  } catch {
    return;
  }
  if (typeof data !== 'object' || data === null) return;
  const { leftOut, notLeftOut } = data as { leftOut?: unknown; notLeftOut?: unknown };
  const slashes = (p: string) => p.replaceAll('\\', '/');
  const prefixes = new Set([input]);
  try {
    prefixes.add(realpathSync.native(input));
  } catch {
    // The input directory is gone: only the path as given is compared.
  }
  const bases = [...prefixes].map((p) => `${slashes(p).replace(/\/+$/, '')}/`);
  const repo: string[] = [];
  for (const entry of Array.isArray(leftOut) ? leftOut : []) {
    if (typeof entry !== 'string') continue;
    const p = slashes(entry);
    const base = bases.find((b) => p.startsWith(b));
    if (base !== undefined) repo.push(shown(p.slice(base.length)));
  }
  if (repo.length > 0) {
    const listed = repo.slice(0, MAX_LEFT_OUT_LISTED).join(', ');
    const more =
      repo.length > MAX_LEFT_OUT_LISTED ? `, and ${repo.length - MAX_LEFT_OUT_LISTED} more` : '';
    log.warn(
      `phpstan: ${repo.length} PHP file(s) PHPStan cannot parse were left out: ${listed}${more}`,
    );
  }
  if (typeof notLeftOut === 'number' && notLeftOut > 0) {
    log.warn(
      `phpstan: ${notLeftOut} file(s) PHPStan cannot parse could not be left out; its result may be incomplete`,
    );
  }
}
const MAX_LEFT_OUT_LISTED = 20;

/** PHPStan reads only names ending in exactly `.php` (its default fileExtensions). */
const phpName = (repoPath: string) => {
  const base = repoPath.slice(repoPath.lastIndexOf('/') + 1);
  return base.length > '.php'.length && base.endsWith('.php');
};

interface DependencyLimits {
  files: number;
  bytes: number;
}

/** The phar to run: `QUALOR_PHPSTAN_PHAR` or the image's; otherwise why PHPStan does not run. */
function pharOf(ctx: AnalyzerContext, defaultPhar: string): string | Preparation {
  const override = ctx.env['QUALOR_PHPSTAN_PHAR'];
  if (override === undefined || override === '') {
    // Ruling G6: a tool that comes with the qualor/scanner image is a skip on a plain host.
    return isFile(defaultPhar) ? defaultPhar : { skip: NOT_INSTALLED };
  }
  if (!path.isAbsolute(override) || isInside(ctx.root, override)) {
    return { unavailable: 'QUALOR_PHPSTAN_PHAR must be an absolute path outside the repository' };
  }
  if (!isFile(override))
    return { unavailable: `QUALOR_PHPSTAN_PHAR ${shown(override)} is not a file` };
  return override;
}

/**
 * The installed dependencies copied for PHPStan's `scanDirectories`: the copy's directory, `null`
 * to run without them, or why PHPStan does not run.
 */
function dependencyCopy(
  ctx: AnalyzerContext,
  deps: { vendorDir: string; requiresPackages: boolean },
  limits: DependencyLimits,
): string | null | Preparation {
  const target = path.join(ctx.workDir, 'deps');
  const c = copyDependencies(ctx.root, deps.vendorDir, target, limits.files, limits.bytes);
  ctx.log.debug(
    `phpstan: ${c.files} dependency file(s) read from ${shown(deps.vendorDir)}/, ${c.skipped} left out`,
  );
  // Rulings A9-14, A9-15: PHPStan with part of the symbols would report what it cannot see as
  // false positives, so past either cap it does not run at all.
  if (c.tooLarge || c.truncated) {
    if (c.truncated) {
      ctx.log.debug(
        `phpstan: ${shown(deps.vendorDir)}/ has more than ${limits.files} PHP files; PHPStan is skipped`,
      );
    }
    rmSync(target, { recursive: true, force: true });
    return { skip: DEPENDENCIES_TOO_LARGE };
  }
  if (c.skipped > 0) {
    ctx.log.warn(
      `phpstan: ${c.skipped} dependency file(s) below ${shown(deps.vendorDir)}/ not read (a link, a file larger than 1 MiB or one that cannot be read)`,
    );
  }
  if (c.files > 0) return target;
  // Rulings A9-15, A9-17: installed.json is there but no dependency file could be read (vendor/
  // is a link, or holds only Composer's own files) while packages are required: the same as
  // dependencies not installed. Without such a require PHPStan runs without them.
  return deps.requiresPackages ? { skip: DEPENDENCIES_NOT_INSTALLED } : null;
}

async function prepare(
  ctx: AnalyzerContext,
  defaultPhar: string,
  limits: DependencyLimits,
): Promise<Preparation> {
  const settings = ctx.config.analyzers.phpstan;
  const php = ctx.files.filter((f) => f.language === 'php');
  if (php.length === 0) return { skip: 'no PHP files in scope' };

  const phar = pharOf(ctx, defaultPhar);
  if (typeof phar !== 'string') return phar;
  const phpBinary = ctx.resolveBinary('php');
  if (phpBinary === null) {
    return { unavailable: 'PHPStan needs php 7.4 or later (PATH or the qualor/scanner image)' };
  }

  const deps = phpDependencies(ctx.root);
  if (deps.kind === 'skip') return { skip: deps.reason };
  // Compared case-insensitively (review fix round 1): `Vendor/` is vendor/ on a case-insensitive
  // file system.
  const vendorPrefix = deps.kind === 'installed' ? `${deps.vendorDir.toLowerCase()}/` : null;
  const own = php.filter(
    (f) => vendorPrefix === null || !f.path.toLowerCase().startsWith(vendorPrefix),
  );
  const otherCase = own.filter((f) => !phpName(f.path)).length;
  if (otherCase > 0) {
    ctx.log.warn(`phpstan: ${otherCase} PHP file(s) whose name does not end in .php were left out`);
  }
  const named = own.filter((f) => phpName(f.path));
  if (named.length === 0) {
    return { skip: 'no PHP file left to analyse (PHPStan reads only names ending in .php)' };
  }

  // The work directory is the probe's working directory too: PHPStan's start-up would load a
  // composer.json, vendor/autoload.php or phpstan.neon from it (fact P4), and it holds none.
  // Ruling A9-18: the probe is php with PHPStan too, under the run's own php options and
  // environment rules.
  const probe = await ctx.exec(phpBinary, [...PHP_OPTIONS, phar, '--version'], {
    timeoutMs: 60_000,
    cwd: ctx.workDir,
    env: phpEnv(),
    dropEnv: isPhpVariable,
  });
  const version = probe.exitCode === 0 ? parsePhpstanVersion(probe.stdout) : null;
  if (version === null) return { unavailable: 'php <phar> --version printed no PHPStan version' };
  if (!phpstanVersionSupported(version)) {
    const [major, minor] = PHPSTAN_VERSION.split('.');
    return {
      skip: `PHPStan ${version} is not supported (Qualor runs PHPStan ${major}.${minor}.x; the qualor/scanner image has ${PHPSTAN_VERSION})`,
    };
  }

  const input = path.join(ctx.workDir, 'src');
  mkdirSync(input, { recursive: true });
  const copied = copyCheckedFiles(ctx.root, named, input);
  const leftOut = named.length - copied.length;
  if (leftOut > 0) {
    ctx.log.warn(
      `phpstan: ${leftOut} PHP file(s) not analysed (a link, a file larger than 1 MiB or one that cannot be read)`,
    );
  }
  if (copied.length === 0) return { skip: 'no PHP file in scope that PHPStan can be given' };

  const depsDir = deps.kind === 'installed' ? dependencyCopy(ctx, deps, limits) : null;
  if (depsDir !== null && typeof depsDir !== 'string') return depsDir;

  const neon = path.join(ctx.workDir, 'phpstan.neon');
  const wrapper = path.join(ctx.workDir, 'qualor-phpstan.php');
  const out = path.join(ctx.workDir, 'phpstan.json');
  writeFileSync(
    neon,
    phpstanNeon({
      level: settings.level,
      input,
      deps: depsDir,
      tmpDir: path.join(ctx.workDir, 'phpstan-tmp'),
    }),
  );
  writeFileSync(wrapper, PHPSTAN_WRAPPER);
  const withDependencies = depsDir !== null;
  return {
    run: {
      command: phpBinary,
      // Never --pro, --fix, --autoload-file, --generate-baseline or --xdebug (config.md §6).
      args: [
        ...PHP_OPTIONS,
        wrapper,
        phar,
        out,
        input,
        'analyse',
        '--configuration',
        neon,
        '--error-format=json',
        '--no-progress',
        '--no-interaction',
        `--memory-limit=${settings.memoryLimit}`,
      ],
      cwd: ctx.workDir,
      env: phpEnv(),
      dropEnv: isPhpVariable,
      sarifPath: out,
      // The wrapper's verdict (exit 0: a report without general errors), never PHPStan's own code.
      okExitCodes: [0],
      version,
      transform: (output) => {
        warnLeftOut(`${out}.left-out.json`, input, ctx.log);
        return phpstanSarif(output, {
          input,
          workDir: ctx.workDir,
          version,
          withDependencies,
          log: ctx.log,
        });
      },
      failureDetail: (_code, stderr) => {
        warnLeftOut(`${out}.left-out.json`, input, ctx.log);
        return phpstanFailureDetail(stderr, ctx.workDir);
      },
    },
  };
}

/**
 * The phpstan engine. Tests point `defaultPhar` at a temporary file and may lower the dependency
 * caps (`MAX_DEPENDENCY_FILES`, `MAX_DEPENDENCY_BYTES` by default).
 */
export function createPhpstanAnalyzer(
  o: { defaultPhar?: string; maxDependencyFiles?: number; maxDependencyBytes?: number } = {},
): Analyzer {
  const defaultPhar = o.defaultPhar ?? DEFAULT_PHPSTAN_PHAR;
  const limits: DependencyLimits = {
    files: o.maxDependencyFiles ?? MAX_DEPENDENCY_FILES,
    bytes: o.maxDependencyBytes ?? MAX_DEPENDENCY_BYTES,
  };
  return {
    id: 'phpstan',
    languages: ['php'],
    ruleLanguages: ['php'],
    prepare: (ctx) => prepare(ctx, defaultPhar, limits),
  };
}

export const phpstanAnalyzer: Analyzer = createPhpstanAnalyzer();
