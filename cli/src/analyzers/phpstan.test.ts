import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PHPSTAN_DEFAULT_LEVEL, PHPSTAN_PHP_VERSION, PHPSTAN_VERSION } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger } from '../log';
import {
  createPhpstanAnalyzer,
  dropPhpVariable,
  isPhpVariable,
  neonString,
  parsePhpstanVersion,
  PHP_INI,
  PHPSTAN_WRAPPER,
  phpstanFailureDetail,
  phpstanNeon,
  warnLeftOut,
} from './phpstan';
import { execEnv } from './runner';
import type { ExecOptions } from './types';
import { DEPENDENCIES_NOT_INSTALLED, DEPENDENCIES_TOO_LARGE } from './phpstan-deps';

const tmp = useTempDirs();
/** A directory link: a junction on Windows (no privilege needed), a symlink elsewhere. */
const CAN_LINK_DIRS = (() => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-link-check-'));
  try {
    symlinkSync(dir, path.join(dir, 'link'), 'junction');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
})();
const PHP = '/usr/bin/php';
const [MAJOR, MINOR] = PHPSTAN_VERSION.split('.').map(Number) as [number, number];

/** A repository with the given files, the PHP ones as discovery lists them. */
function repo(tree: Record<string, string>): { root: string; files: ScopeFile[] } {
  const root = tmp();
  writeTree(root, tree);
  const files = Object.keys(tree)
    .filter((p) => p.toLowerCase().endsWith('.php'))
    .map((p) => ({
      path: p,
      absPath: path.join(root, ...p.split('/')),
      language: 'php' as const,
      grammar: 'php' as const,
      kind: 'main' as const,
      size: Buffer.byteLength(tree[p] ?? ''),
    }));
  return { root, files };
}

/** An analyzer whose default phar exists, and a context whose `php --version` probe is recorded. */
function setup(
  tree: Record<string, string>,
  o: {
    version?: string;
    config?: object;
    php?: string | null;
    limits?: { maxDependencyFiles?: number; maxDependencyBytes?: number };
  } = {},
) {
  const { root, files } = repo(tree);
  const phar = path.join(tmp(), 'phpstan.phar');
  writeFileSync(phar, 'phar');
  const workDir = tmp();
  const probes: { command: string; args: readonly string[]; cwd?: string }[] = [];
  const probeOptions: ExecOptions[] = [];
  const lines: string[] = [];
  const ctx = {
    ...fakeContext(root, {
      binaries: o.php === null ? {} : { php: o.php ?? PHP },
      workDir,
      config: o.config ?? {},
      exec: (command: string, args: readonly string[], options: ExecOptions) => {
        probes.push({ command, args, cwd: options.cwd });
        probeOptions.push(options);
        return {
          exitCode: 0,
          timedOut: false,
          durationMs: 1,
          stdout: `PHPStan - PHP Static Analysis Tool ${o.version ?? PHPSTAN_VERSION}\n`,
          stderr: '',
        };
      },
    }),
    log: createLogger('debug', (t) => lines.push(t)),
    files,
  };
  return {
    root,
    phar,
    workDir,
    ctx,
    probes,
    probeOptions,
    lines,
    analyzer: createPhpstanAnalyzer({ defaultPhar: phar, ...o.limits }),
  };
}

describe('phpstanAnalyzer.prepare (config.md §6, plan 9A)', () => {
  it('runs the wrapper on a checked copy, from the work directory, with Qualor’s own configuration', async () => {
    const s = setup({
      'src/Cart.php': '<?php\n',
      'README.md': 'x',
      'phpstan.neon': 'includes: [evil.neon]\n',
      'composer.json': '{}',
    });
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const w = (name: string) => path.join(s.workDir, name);
    expect(p.run.command).toBe(PHP);
    expect(p.run.args).toEqual([
      '-c',
      w('qualor-php.ini'),
      '-d',
      'memory_limit=-1',
      w('qualor-phpstan.php'),
      s.phar,
      w('phpstan.json'),
      w('src'),
      'analyse',
      '--configuration',
      w('phpstan.neon'),
      '--error-format=json',
      '--no-progress',
      '--no-interaction',
      '--memory-limit=2G',
    ]);
    expect(p.run).toMatchObject({
      cwd: s.workDir,
      sarifPath: w('phpstan.json'),
      okExitCodes: [0],
      version: PHPSTAN_VERSION,
    });
    expect(readFileSync(w('qualor-phpstan.php'), 'utf8')).toBe(PHPSTAN_WRAPPER);
    expect(readFileSync(w('phpstan.neon'), 'utf8')).toBe(
      phpstanNeon({
        level: PHPSTAN_DEFAULT_LEVEL,
        input: w('src'),
        deps: null,
        tmpDir: w('phpstan-tmp'),
      }),
    );
    expect(readFileSync(path.join(s.workDir, 'src', 'src', 'Cart.php'), 'utf8')).toBe('<?php\n');
    // Nothing PHPStan's start-up looks for is in its working directory (fact P4).
    expect(readdirSync(s.workDir).sort()).toEqual([
      'phpstan.neon',
      'qualor-php.ini',
      'qualor-phpstan.php',
      'src',
    ]);
    expect(p.run.env).toMatchObject({
      LC_ALL: 'C.UTF-8',
      HTTPS_PROXY: 'http://127.0.0.1:9',
      PHP_INI_SCAN_DIR: '',
    });
    for (const name of [
      'PHPRC',
      'php_ini_scan_dir',
      'COMPOSER',
      'COMPOSER_HOME',
      'phpstan_arena',
    ]) {
      expect(p.run.dropEnv?.(name), name).toBe(true);
    }
    expect(p.run.dropEnv?.('PATH')).toBe(false);
    // The version probe runs in the work directory too.
    expect(s.probes).toEqual([
      { command: PHP, args: ['-c', w('qualor-php.ini'), s.phar, '--version'], cwd: s.workDir },
    ]);
  });

  it('starts every php with Qualor’s php.ini only and without the variables that configure php (rulings A9-18, A9-23)', async () => {
    const s = setup({ 'src/Cart.php': '<?php\n' });
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const ini = path.join(s.workDir, 'qualor-php.ini');
    // The whole configuration: only the extensions PHPStan's phar needs, from php's own extension
    // directory; warnings never on stdout (the report); no PCRE JIT (ruling A9-22).
    expect(readFileSync(ini, 'utf8')).toBe(PHP_INI);
    expect(PHP_INI.split('\n').filter((l) => l !== '' && !l.startsWith(';'))).toEqual([
      'display_errors = stderr',
      'extension = phar',
      'extension = tokenizer',
      'pcre.jit = 0',
    ]);
    expect(p.run.args.slice(0, 4)).toEqual(['-c', ini, '-d', 'memory_limit=-1']);
    expect(s.probes[0]!.args.slice(0, 2)).toEqual(['-c', ini]);
    // The wrapper starts PHPStan with the php.ini it was started with (PHPStan passes it on to its
    // workers), and refuses to run under any other.
    expect(PHPSTAN_WRAPPER).toContain('$ini = php_ini_loaded_file();');
    expect(PHPSTAN_WRAPPER).toContain("ini_get('pcre.jit') !== '0'");
    expect(PHPSTAN_WRAPPER).toContain("$php = [PHP_BINARY, '-c', $ini];");
    expect(PHPSTAN_WRAPPER).not.toContain('memory_limit');
    // The version probe: the run's environment rules too.
    const probe = s.probeOptions[0]!;
    expect(probe.env).toMatchObject({
      LC_ALL: 'C.UTF-8',
      HTTPS_PROXY: 'http://127.0.0.1:9',
      PHP_INI_SCAN_DIR: '',
    });
    for (const name of ['PHPRC', 'COMPOSER_HOME', 'PHPSTAN_X', 'XDEBUG_MODE', 'XDEBUG_TRIGGER']) {
      expect(probe.dropEnv?.(name), name).toBe(true);
      expect(p.run.dropEnv?.(name), name).toBe(true);
    }
    expect(probe.dropEnv?.('PATH')).toBe(false);
    // The process environment: the job's PHPRC, PHP_INI_SCAN_DIR (any spelling) and XDEBUG_* are
    // gone, and PHP_INI_SCAN_DIR is the empty one (no scan directory at all).
    for (const options of [probe, p.run]) {
      const env = execEnv(
        {
          PATH: '/usr/bin',
          PHPRC: s.root,
          PHP_INI_SCAN_DIR: path.join(s.root, 'php.d'),
          php_ini_scan_dir: path.join(s.root, 'php.d'),
          XDEBUG_TRIGGER: '1',
        },
        { env: options.env!, dropEnv: options.dropEnv! },
        s.root,
      );
      expect(env['PHP_INI_SCAN_DIR']).toBe('');
      expect(Object.keys(env).filter((k) => isPhpVariable(k))).toEqual(['PHP_INI_SCAN_DIR']);
      expect(env['PATH']).toBe('/usr/bin');
    }
  });

  it('passes the level and memory limit, and copies installed dependencies to deps/, never to vendor/', async () => {
    const s = setup(
      {
        'composer.json': JSON.stringify({ require: { 'acme/lib': '^1' } }),
        'vendor/composer/installed.json': '{}',
        'vendor/autoload.php': '<?php',
        'vendor/acme/lib/src/Thing.php': '<?php class Thing {}',
        'src/App.php': '<?php\n',
        // Review fix round 1: the vendor directory is left out whatever the case of its name.
        'Vendor/other/lib/Other.php': '<?php class Other {}',
      },
      { config: { analyzers: { phpstan: { level: 'max', memoryLimit: '512M' } } } },
    );
    // Discovery never lists vendor/ (a built-in exclude); here the test lists it to prove the
    // adapter leaves dependency files out of the analysis anyway.
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(p.run.args).toContain('--memory-limit=512M');
    const neon = readFileSync(path.join(s.workDir, 'phpstan.neon'), 'utf8');
    expect(neon).toContain('    level: max\n');
    expect(neon).toContain(`    scanDirectories: [${neonString(path.join(s.workDir, 'deps'))}]\n`);
    expect(
      existsSync(path.join(s.workDir, 'deps', 'vendor', 'acme', 'lib', 'src', 'Thing.php')),
    ).toBe(true);
    expect(existsSync(path.join(s.workDir, 'deps', 'vendor', 'autoload.php'))).toBe(false);
    expect(existsSync(path.join(s.workDir, 'vendor'))).toBe(false);
    expect(existsSync(path.join(s.workDir, 'src', 'vendor'))).toBe(false);
    expect(existsSync(path.join(s.workDir, 'src', 'Vendor'))).toBe(false);
    expect(existsSync(path.join(s.workDir, 'src', 'src', 'App.php'))).toBe(true);
    // Ruling A9-15: PHPStan's working directory holds no vendor/ and no composer.json (fact P4).
    const cwd = readdirSync(p.run.cwd);
    expect(cwd).not.toContain('vendor');
    expect(cwd).not.toContain('composer.json');
    expect(cwd.sort()).toEqual([
      'deps',
      'phpstan.neon',
      'qualor-php.ini',
      'qualor-phpstan.php',
      'src',
    ]);
  });

  const installed = {
    'composer.json': JSON.stringify({ require: { 'acme/lib': '^1' } }),
    'vendor/composer/installed.json': '{}',
    'vendor/acme/lib/src/A.php': '<?php class A {}',
    'vendor/acme/lib/src/B.php': '<?php class B {}',
    'src/App.php': '<?php\n',
  };

  it('is skipped, never run with part of the symbols, past the file-count or size cap (rulings A9-14, A9-15)', async () => {
    const many = setup(installed, { limits: { maxDependencyFiles: 1 } });
    expect(await many.analyzer.prepare(many.ctx)).toEqual({ skip: DEPENDENCIES_TOO_LARGE });
    const big = setup(installed, { limits: { maxDependencyBytes: 10 } });
    expect(await big.analyzer.prepare(big.ctx)).toEqual({ skip: DEPENDENCIES_TOO_LARGE });
    for (const s of [many, big]) {
      expect(existsSync(path.join(s.workDir, 'phpstan.neon'))).toBe(false);
    }
  });

  it('is skipped as not installed when vendor/ gives no dependency file (ruling A9-15)', async () => {
    const s = setup({
      'composer.json': JSON.stringify({ require: { 'acme/lib': '^1' } }),
      'vendor/composer/installed.json': '{}',
      'vendor/autoload.php': '<?php',
      'src/App.php': '<?php\n',
    });
    expect(await s.analyzer.prepare(s.ctx)).toEqual({ skip: DEPENDENCIES_NOT_INSTALLED });
  });

  it('runs without dependencies when vendor/ gives no file and no package is required (ruling A9-17)', async () => {
    for (const composer of [{}, { require: { php: '>=8.1', 'ext-json': '*' } }]) {
      const s = setup({
        'composer.json': JSON.stringify(composer),
        'vendor/composer/installed.json': '{}',
        'vendor/autoload.php': '<?php',
        'src/App.php': '<?php\n',
      });
      const p = await s.analyzer.prepare(s.ctx);
      if (!('run' in p)) throw new Error(JSON.stringify(p));
      const neon = readFileSync(path.join(s.workDir, 'phpstan.neon'), 'utf8');
      expect(neon).not.toContain('scanDirectories');
      expect(existsSync(path.join(s.workDir, 'deps'))).toBe(false);
    }
  });

  it('warns about dependency files it left out (ruling A9-15)', async () => {
    const s = setup({
      ...installed,
      'vendor/acme/lib/src/Huge.php': `<?php // ${'x'.repeat(1024 * 1024)}`,
    });
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(s.lines.join('')).toContain(
      'phpstan: 1 dependency file(s) below vendor/ not read (a link, a file larger than 1 MiB or one that cannot be read)',
    );
    expect(existsSync(path.join(s.workDir, 'deps', 'vendor', 'acme', 'lib', 'src', 'A.php'))).toBe(
      true,
    );
  });

  it('is skipped when dependencies are required but not installed', async () => {
    const s = setup({
      'composer.json': JSON.stringify({ require: { 'acme/lib': '^1' } }),
      'a.php': '<?php\n',
    });
    expect(await s.analyzer.prepare(s.ctx)).toEqual({ skip: DEPENDENCIES_NOT_INSTALLED });
  });

  it('is skipped without PHP files, and leaves out a name not ending in exactly .php with a warning', async () => {
    const none = setup({ 'README.md': 'x' });
    expect(await none.analyzer.prepare(none.ctx)).toEqual({ skip: 'no PHP files in scope' });
    const upper = setup({ 'LEGACY.PHP': '<?php\n' });
    expect(await upper.analyzer.prepare(upper.ctx)).toEqual({
      skip: 'no PHP file left to analyse (PHPStan reads only names ending in .php)',
    });
    expect(upper.lines.join('')).toContain(
      'phpstan: 1 PHP file(s) whose name does not end in .php were left out',
    );
  });

  it('is skipped without the phar, unavailable with a bad override or without php', async () => {
    const s = setup({ 'a.php': '<?php\n' });
    const missing = createPhpstanAnalyzer({ defaultPhar: path.join(tmp(), 'none.phar') });
    expect(await missing.prepare(s.ctx)).toEqual({
      skip: 'PHPStan is not installed (qualor/scanner image)',
    });
    const env = (value: string) => ({ ...s.ctx, env: { QUALOR_PHPSTAN_PHAR: value } });
    expect(await s.analyzer.prepare(env('lib/phpstan.phar'))).toEqual({
      unavailable: 'QUALOR_PHPSTAN_PHAR must be an absolute path outside the repository',
    });
    expect(await s.analyzer.prepare(env(path.join(s.root, 'phpstan.phar')))).toEqual({
      unavailable: 'QUALOR_PHPSTAN_PHAR must be an absolute path outside the repository',
    });
    const absent = path.join(tmp(), 'absent.phar');
    expect(await s.analyzer.prepare(env(absent))).toEqual({
      unavailable: `QUALOR_PHPSTAN_PHAR ${absent} is not a file`,
    });
    const noPhp = setup({ 'a.php': '<?php\n' }, { php: null });
    expect(await noPhp.analyzer.prepare(noPhp.ctx)).toEqual({
      unavailable: 'PHPStan needs php 7.4 or later (PATH or the qualor/scanner image)',
    });
  });

  it('skips another minor of PHPStan by name, and is unavailable when the probe prints no version', async () => {
    for (const other of [`${MAJOR}.${MINOR + 1}.0`, `${MAJOR}.${MINOR - 1}.4`]) {
      const s = setup({ 'a.php': '<?php\n' }, { version: other });
      expect(await s.analyzer.prepare(s.ctx)).toEqual({
        skip: `PHPStan ${other} is not supported (Qualor runs PHPStan ${MAJOR}.${MINOR}.x; the qualor/scanner image has ${PHPSTAN_VERSION})`,
      });
    }
    const s = setup({ 'a.php': '<?php\n' }, { version: 'garbage' });
    expect(await s.analyzer.prepare(s.ctx)).toEqual({
      unavailable: 'php <phar> --version printed no PHPStan version',
    });
  });
});

describe('phpstan helpers', () => {
  it('reads the version the phar prints', () => {
    expect(parsePhpstanVersion('PHPStan - PHP Static Analysis Tool 2.2.16\n')).toBe('2.2.16');
    expect(
      parsePhpstanVersion('Note: something\nPHPStan - PHP Static Analysis Tool 2.2.17\n'),
    ).toBe('2.2.17');
    expect(parsePhpstanVersion('PHP Fatal error: …')).toBeNull();
  });

  it('knows the variables that configure PHP or PHPStan behind the command line', () => {
    for (const n of [
      'PHPRC',
      'phprc',
      'PHP_INI_SCAN_DIR',
      'COMPOSER',
      'COMPOSER_VENDOR_DIR',
      'PHPSTAN_ARENA',
      'XDEBUG_CONFIG',
      'XDEBUG_MODE',
      'xdebug_session',
      'XDEBUG_TRIGGER',
      'XDEBUG_OTHER',
    ]) {
      expect(isPhpVariable(n), n).toBe(true);
    }
    for (const n of ['PATH', 'PHP_BINARY_X', 'MYCOMPOSER', 'HOME', 'XDEBUG'])
      expect(isPhpVariable(n), n).toBe(false);
    // Ruling A9-23: phpEnv's own empty PHP_INI_SCAN_DIR stays; every other spelling goes.
    expect(dropPhpVariable('PHP_INI_SCAN_DIR')).toBe(false);
    expect(dropPhpVariable('php_ini_scan_dir')).toBe(true);
    expect(dropPhpVariable('PHPRC')).toBe(true);
  });

  it('writes NEON strings PHPStan reads back exactly (fact P3)', () => {
    expect(neonString(`/tmp/a %b c#d"e'f ü`)).toBe(`"/tmp/a %%b c#d\\"e'f ü"`);
    expect(neonString('C:\\w\\src')).toBe('"C:\\\\w\\\\src"');
    expect(phpstanNeon({ level: 2, input: '/w/src', deps: '/w/deps', tmpDir: '/w/t' })).toBe(
      [
        '# Written by Qualor (config.md §6, plan 9A): the whole PHPStan configuration of this scan.',
        'parameters:',
        '    level: 2',
        `    phpVersion: ${PHPSTAN_PHP_VERSION}`,
        '    tmpDir: "/w/t"',
        '    reportUnmatchedIgnoredErrors: false',
        '    paths: ["/w/src"]',
        '    scanDirectories: ["/w/deps"]',
        '',
      ].join('\n'),
    );
  });

  it('names the files the wrapper left out because PHPStan cannot parse them, as repository paths (ruling A9-19)', async () => {
    const s = setup({ 'src/Cart.php': '<?php\n' });
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const input = path.join(s.workDir, 'src');
    writeFileSync(
      path.join(s.workDir, 'phpstan.json.left-out.json'),
      JSON.stringify({
        leftOut: [
          path.join(input, 'src', 'Broken.php'),
          path.join(input, 'x\u0007.php'),
          // Never a path outside the copy.
          path.join(s.workDir, 'phpstan.neon'),
        ],
        notLeftOut: 0,
      }),
    );
    p.run.transform?.({ totals: {}, files: [], errors: [] }, '');
    // Once only, though the failure hook would read it too.
    p.run.failureDetail?.(4, '');
    expect(s.lines.filter((l) => l.includes('cannot parse'))).toEqual([
      'warn: phpstan: 2 PHP file(s) PHPStan cannot parse were left out: src/Broken.php, x?.php\n',
    ]);
  });

  it('names them when PHPStan’s second run fails too, and says when some could not be left out (ruling A9-19)', async () => {
    const s = setup({ 'src/Cart.php': '<?php\n' });
    const p = await s.analyzer.prepare(s.ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    writeFileSync(
      path.join(s.workDir, 'phpstan.json.left-out.json'),
      JSON.stringify({ leftOut: [path.join(s.workDir, 'src', 'a.php')], notLeftOut: 2 }),
    );
    p.run.failureDetail?.(4, 'qualor-phpstan: PHPStan wrote no report (exit code 255)\n');
    expect(s.lines.join('')).toContain(
      'warn: phpstan: 1 PHP file(s) PHPStan cannot parse were left out: a.php\n',
    );
    expect(s.lines.join('')).toContain(
      'warn: phpstan: 2 file(s) PHPStan cannot parse could not be left out; its result may be incomplete\n',
    );
  });

  // Review fix round 1: the wrapper writes realpath()s; a work directory reached through a link
  // (macOS /var -> /private/var, a Windows short name) must still give repository paths.
  it.skipIf(!CAN_LINK_DIRS)(
    'names them by repository path when the work directory is reached through a link',
    () => {
      const real = tmp();
      const linked = path.join(tmp(), 'linked-work');
      symlinkSync(real, linked, 'junction');
      mkdirSync(path.join(real, 'src', 'src'), { recursive: true });
      const sidecar = path.join(linked, 'phpstan.json.left-out.json');
      writeFileSync(
        sidecar,
        JSON.stringify({ leftOut: [path.join(real, 'src', 'src', 'Broken.php')], notLeftOut: 0 }),
      );
      const lines: string[] = [];
      warnLeftOut(
        sidecar,
        path.join(linked, 'src'),
        createLogger('debug', (t) => lines.push(t)),
      );
      expect(lines).toEqual([
        'warn: phpstan: 1 PHP file(s) PHPStan cannot parse were left out: src/Broken.php\n',
      ]);
    },
  );

  it('pins how the wrapper leaves out files PHPStan cannot parse (ruling A9-19)', () => {
    expect(PHPSTAN_WRAPPER).toContain("($message['identifier'] ?? null) !== 'phpstan.parse'");
    // Only a copy below <input>, the wrapper's third argument, is ever deleted.
    expect(PHPSTAN_WRAPPER).toContain('$input = realpath($argv[3]);');
    expect(PHPSTAN_WRAPPER).toContain('strpos($real, $input . DIRECTORY_SEPARATOR) === 0');
    expect(PHPSTAN_WRAPPER).toContain("$out . '.left-out.json'");
    expect(PHPSTAN_WRAPPER).toContain("['leftOut' => $leftOut, 'notLeftOut' => $notLeftOut]");
  });

  it('pins what the wrapper does (fact P5)', () => {
    expect(PHPSTAN_WRAPPER.startsWith('<?php\n')).toBe(true);
    expect(PHPSTAN_WRAPPER).toContain("fopen($out, 'xb')");
    expect(PHPSTAN_WRAPPER).toContain(
      '$command = array_merge($php, [$phar], array_slice($argv, 4));',
    );
    expect(PHPSTAN_WRAPPER).toContain('exit(3);');
    expect(PHPSTAN_WRAPPER).toContain('exit(4);');
    // Review fix round 1: a report is trusted only after PHPStan's own exit code 0 or 1.
    expect(PHPSTAN_WRAPPER).toContain('if ($code !== 0 && $code !== 1) {');
    expect(PHPSTAN_WRAPPER).not.toMatch(
      /shell_exec|passthru|system\(|exec\(|eval\(|include|require/,
    );
  });

  it('logs why PHPStan failed, with the work directory as <work>', () => {
    expect(
      phpstanFailureDetail(
        'noise\nPHPStan error: Child process error (exit code 255): PHP Fatal error: Allowed memory size in /w/x/src/a.php\n',
        '/w/x',
      ),
    ).toBe(
      'PHPStan error: Child process error (exit code 255): PHP Fatal error: Allowed memory size in <work>/src/a.php',
    );
    expect(
      phpstanFailureDetail(
        'qualor-phpstan: PHPStan wrote no report (exit code 1)\n\n Memory limit "1M" cannot be set.\n',
        '/w/x',
      ),
    ).toBe(
      'qualor-phpstan: PHPStan wrote no report (exit code 1): Memory limit "1M" cannot be set.',
    );
    expect(phpstanFailureDetail('', '/w/x')).toBeNull();
  });
});
