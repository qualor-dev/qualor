import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, readdirSync, readFileSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { expect, it } from 'vitest';
import { describeWithPhpstan } from '../../test/analyzers';
import { canCreateFileSymlinks } from '../../test/symlinks';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { Warnings } from '../warnings';
import { resolveBinary } from './binary';
import { fileLines, normalizeCaptures } from './normalize';
import { DEFAULT_PHPSTAN_PHAR, phpstanAnalyzer } from './phpstan';
import { DEPENDENCIES_NOT_INSTALLED } from './phpstan-deps';
import { execEnv, runAnalyzers } from './runner';
import type { Analyzer } from './types';

const tmp = useTempDirs();
const CAN_SYMLINK_FILES = canCreateFileSymlinks();
/** Real PHPStan runs take seconds each, minutes on a loaded CI runner. */
const TIMEOUT = { timeout: 600_000 };
/** Files beyond the hostile layout's own in the A9-16 checkout: 6 of PHPStan's 20-file jobs. */
const GENERATED_FILES = 120;

/** A PHP single-quoted string literal. */
const phpString = (s: string) => `'${s.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`;
/** A top-level statement that leaves `ran-<who>` in `markers` if PHP ever runs it. */
const marker = (markers: string, who: string) =>
  `file_put_contents(${phpString(path.join(markers, 'ran-' + who))}, 'x');\n`;

async function scanPhp(
  root: string,
  o: { env?: NodeJS.ProcessEnv; config?: object; tempRoot?: string; analyzer?: Analyzer } = {},
) {
  const config = parseConfig({ version: 1, ...o.config });
  const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
  const lines: string[] = [];
  const [capture] = await runAnalyzers([o.analyzer ?? phpstanAnalyzer], {
    root,
    config,
    files,
    log: createLogger('debug', (t) => lines.push(t)),
    env: o.env ?? process.env,
    ...(o.tempRoot !== undefined && { tempRoot: o.tempRoot }),
  });
  if (capture === undefined) throw new Error('no capture');
  const out = normalizeCaptures([capture], {
    repoRoot: root,
    readLines: fileLines(root),
    knownPaths: new Set(files.map((f) => f.path)),
    log: silentLogger,
  });
  return {
    capture,
    lines,
    keys: out.findings
      .map((f) => `${f.ruleId} ${f.location?.path}:${f.location?.startLine}`)
      .sort(),
  };
}

/** Every file below `dir` with its bytes, to prove a scan wrote and changed nothing. */
function snapshot(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.set(path.relative(dir, p), readFileSync(p, 'latin1'));
    }
  };
  walk(dir);
  return out;
}

/** Every path below `dir`, `/`-separated, sorted. */
function tree(dir: string): string[] {
  return [...snapshot(dir).keys()].map((p) => p.split(path.sep).join('/')).sort();
}

/**
 * Ruling A9-16: a checkout whose every PHP file that PHP could be made to run leaves a marker.
 * Composer's layout below `vendorDir` (its autoloader, the files it loads, the bin proxies, a
 * files-autoload function file, a class, the extension installer's GeneratedConfig), the root
 * composer.json's `autoload.files`, project PHPStan configurations with `bootstrapFiles` and
 * `includes`, a php.ini (`PHPRC`) and an ini of a scan directory (`PHP_INI_SCAN_DIR`) with
 * `auto_prepend_file`. The autoloader chain is the hostile
 * checkout's own: it requires every one of them, the way the positive control shows PHPStan would
 * run it. `src/App.php` uses the dependencies: a by-reference argument of the vendor function and
 * a method inherited from the vendor class.
 */
function hostileCheckout(
  root: string,
  markers: string,
  o: { vendorDir: string; neons: readonly string[] },
): void {
  const m = (who: string) => marker(markers, who);
  const v = o.vendorDir;
  const neons = Object.fromEntries(
    o.neons.flatMap((name) => [
      [
        name,
        `parameters:\n  level: 9\n  paths: [src]\n  bootstrapFiles: [boot-${name}.php]\nincludes: [extra.neon]\nrules: [App\\EvilRule]\n`,
      ],
      [`boot-${name}.php`, `<?php\n${m('bootstrap-' + name)}`],
    ]),
  );
  writeTree(root, {
    'composer.json': JSON.stringify({
      require: { php: '>=8.2', 'acme/lib': '^1' },
      autoload: { files: ['app/helpers.php'], 'psr-4': { 'App\\': 'src/' } },
      ...(v !== 'vendor' && { config: { 'vendor-dir': v } }),
    }),
    [`${v}/autoload.php`]: `<?php\n${m('autoload')}return require __DIR__ . '/composer/autoload_real.php';\n`,
    [`${v}/composer/autoload_real.php`]: String.raw`<?php
${m('autoload-real')}require __DIR__ . '/platform_check.php';
require __DIR__ . '/ClassLoader.php';
require __DIR__ . '/InstalledVersions.php';
require __DIR__ . '/autoload_static.php';
require __DIR__ . '/installed.php';
require __DIR__ . '/../bin/acme';
require __DIR__ . '/../bin/acme-tool.php';
foreach (require __DIR__ . '/autoload_files.php' as $file) {
    require_once $file;
}
spl_autoload_register(static function (string $class): void {
    $map = [
        'Acme\Lib\Base' => __DIR__ . '/../acme/lib/src/Base.php',
        'PHPStan\ExtensionInstaller\GeneratedConfig' => __DIR__ . '/../phpstan/extension-installer/src/GeneratedConfig.php',
        'App\EvilRule' => dirname(__DIR__, 2) . '/src/EvilRule.php',
    ];
    if (isset($map[$class])) {
        require $map[$class];
    }
});
return null;
`,
    [`${v}/composer/platform_check.php`]: `<?php\n${m('platform-check')}`,
    [`${v}/composer/autoload_static.php`]: `<?php\n${m('autoload-static')}`,
    [`${v}/composer/installed.php`]: `<?php\n${m('installed-php')}return [];\n`,
    // Composer's runtime classes, declared only when not loaded yet (PHPStan's phar has its own).
    [`${v}/composer/ClassLoader.php`]: `<?php\nnamespace Composer\\Autoload;\n\n${m('class-loader')}if (!\\class_exists(ClassLoader::class, false)) {\n    class ClassLoader\n    {\n    }\n}\n`,
    [`${v}/composer/InstalledVersions.php`]: `<?php\nnamespace Composer;\n\n${m('installed-versions')}if (!\\class_exists(InstalledVersions::class, false)) {\n    class InstalledVersions\n    {\n    }\n}\n`,
    // A package of the composer vendor (composer/semver): an ordinary dependency (ruling A9-21).
    [`${v}/composer/semver/src/functions.php`]: `<?php\nnamespace Composer\\Semver;\n\n${m('composer-package')}function semver_gt(string $a, string $b): bool\n{\n    return $a > $b;\n}\n`,
    [`${v}/composer/installed.json`]: '{"packages":[{"name":"acme/lib","version":"1.0.0"}]}',
    [`${v}/composer/autoload_files.php`]: `<?php\n${m('autoload-files')}$vendorDir = dirname(__DIR__);\n$baseDir = dirname($vendorDir);\nreturn ['a1' => $vendorDir . '/acme/lib/src/functions.php', 'a2' => $baseDir . '/app/helpers.php', 'c1' => $vendorDir . '/composer/semver/src/functions.php'];\n`,
    [`${v}/bin/acme`]: `<?php\n${m('bin-proxy')}`,
    [`${v}/bin/acme-tool.php`]: `<?php\n${m('bin-php')}`,
    [`${v}/acme/lib/src/functions.php`]: `<?php\n${m('vendor-function-file')}function acme_parse(string $s, ?array &$out = null): bool\n{\n    $out = [$s];\n    return true;\n}\n`,
    [`${v}/acme/lib/src/Base.php`]: `<?php\nnamespace Acme\\Lib;\n\n${m('vendor-class')}class Base\n{\n    public function hello(): int\n    {\n        return 1;\n    }\n}\n`,
    [`${v}/phpstan/extension-installer/src/GeneratedConfig.php`]: `<?php\nnamespace PHPStan\\ExtensionInstaller;\n\n${m('extension-installer')}final class GeneratedConfig\n{\n    public const EXTENSIONS = [];\n    public const NOT_INSTALLED = [];\n}\n`,
    // With a custom vendor-dir, a vendor/autoload.php is Composer's no longer, but still PHP.
    ...(v !== 'vendor' && { 'vendor/autoload.php': `<?php\n${m('default-vendor-autoload')}` }),
    'app/helpers.php': `<?php\n${m('root-autoload-files')}`,
    // Review fix round 1: enough files for several of PHPStan's jobs (20 files each), so it
    // analyses them in worker processes, which inherit the hostile environment of the run.
    ...Object.fromEntries(
      Array.from({ length: GENERATED_FILES }, (_, i) => [
        `src/gen/G${i}.php`,
        `<?php\nnamespace App\\Gen;\n\nfunction g${i}(): int\n{\n    return ${i};\n}\n`,
      ]),
    ),
    ...neons,
    'extra.neon': 'parameters:\n  bootstrapFiles: [boot-included.php]\n',
    'boot-included.php': `<?php\n${m('neon-includes')}`,
    'php.ini': `auto_prepend_file=${path.join(root, 'prepend.php')}\n`,
    'prepend.php': `<?php\n${m('php-ini')}`,
    'php.d/zz-checkout.ini': `auto_prepend_file=${path.join(root, 'prepend-scan.php')}\n`,
    'prepend-scan.php': `<?php\n${m('php-ini-scan-dir')}`,
    // A working custom rule: PHPStan in the checkout loads it and goes on to the bootstrap files.
    'src/EvilRule.php': `<?php\nnamespace App;\n\nuse PhpParser\\Node;\nuse PHPStan\\Analyser\\Scope;\nuse PHPStan\\Rules\\Rule;\n\n${m('rule-class')}final class EvilRule implements Rule\n{\n    public function getNodeType(): string\n    {\n        return Node::class;\n    }\n\n    public function processNode(Node $node, Scope $scope): array\n    {\n        return [];\n    }\n}\n`,
    // Line 18: an inherited method called with an argument too many (a finding only when PHPStan
    // knows Base::hello() from the dependency). Line 23: the one undefined variable; line 13's $m
    // is defined by the vendor function's by-reference parameter. Line 28: a function of the
    // composer/semver package called with an argument too many (known only from vendor/composer/).
    'src/App.php': [
      '<?php',
      'namespace App;',
      '',
      m('analysed-file').trimEnd(),
      '',
      'use Acme\\Lib\\Base;',
      '',
      'final class Child extends Base',
      '{',
      '    public function parse(string $s): array',
      '    {',
      '        \\acme_parse($s, $m);',
      '        return $m;',
      '    }',
      '',
      '    public function twice(): int',
      '    {',
      '        return $this->hello() + $this->hello(1);',
      '    }',
      '',
      '    public function broken(): int',
      '    {',
      '        return $missing;',
      '    }',
      '',
      '    public function newer(): bool',
      '    {',
      "        return \\Composer\\Semver\\semver_gt('2', '1', '0');",
      '    }',
      '}',
      '',
    ].join('\n'),
  });
  writeTree(root, {
    'bin/php': `#!/bin/sh\ntouch ${JSON.stringify(path.join(markers, 'ran-repository-php'))}\n`,
  });
  chmodSync(path.join(root, 'bin', 'php'), 0o755);
}

/**
 * The environment of Qualor's run: the checkout's php.ini through PHPRC and its ini directory
 * through PHP_INI_SCAN_DIR (ruling A9-18), its bin/ first on PATH.
 */
const hostileEnv = (root: string): NodeJS.ProcessEnv => ({
  ...process.env,
  PHPRC: root,
  PHP_INI_SCAN_DIR: path.join(root, 'php.d'),
  PATH: `${path.join(root, 'bin')}${path.delimiter}${process.env['PATH'] ?? ''}`,
});

/**
 * The positive control: PHPStan the way a developer runs it in the checkout (its directory, its
 * configuration found there, its php.ini through PHPRC), with the image's php and phar.
 */
function phpstanInCheckout(root: string): void {
  const php = resolveBinary('php', { root: process.cwd(), env: process.env });
  if (php === null) throw new Error('no php');
  spawnSync(
    php,
    [DEFAULT_PHPSTAN_PHAR, 'analyse', '--no-progress', '--error-format=json', '--memory-limit=1G'],
    { cwd: root, env: { ...process.env, PHPRC: root }, encoding: 'utf8', timeout: 300_000 },
  );
  // A scan directory's ini is read after php.ini (its auto_prepend_file wins), so it gets its own
  // run; php fails without the system's extension inis, after the prepended file has run.
  spawnSync(php, [DEFAULT_PHPSTAN_PHAR, '--version'], {
    cwd: root,
    env: { ...process.env, PHP_INI_SCAN_DIR: path.join(root, 'php.d') },
    encoding: 'utf8',
    timeout: 300_000,
  });
}

/** What php says about its own configuration, asked with the run's php.ini and environment. */
interface IniProbe {
  /** The run's `-c` argument. */
  given: string;
  jit: string;
  loaded: string | false;
  scanned: string | false;
  extensions: string[];
}

/**
 * The real runner's phpstan, recording its work directory (PHPStan's cwd) as PHPStan starts, and
 * asking php, started the way the run starts it (its php.ini, its environment over the hostile
 * one), how it is configured (ruling A9-23).
 */
function observed(): { analyzer: Analyzer; cwd: string[][]; deps: string[][]; ini: IniProbe[] } {
  const cwd: string[][] = [];
  const deps: string[][] = [];
  const ini: IniProbe[] = [];
  const analyzer: Analyzer = {
    ...phpstanAnalyzer,
    prepare: async (ctx) => {
      const prep = await phpstanAnalyzer.prepare(ctx);
      if ('run' in prep) {
        cwd.push(readdirSync(prep.run.cwd).sort());
        deps.push(tree(path.join(prep.run.cwd, 'deps')));
        const code =
          "echo json_encode(['jit' => ini_get('pcre.jit'), 'loaded' => php_ini_loaded_file(), 'scanned' => php_ini_scanned_files(), 'extensions' => get_loaded_extensions()]);";
        // The run's php options: everything before the wrapper.
        const options = prep.run.args.slice(
          0,
          prep.run.args.findIndex((a) => a.endsWith('qualor-phpstan.php')),
        );
        const probe = spawnSync(prep.run.command, [...options, '-r', code], {
          cwd: prep.run.cwd,
          env: execEnv(ctx.env, { env: prep.run.env, dropEnv: prep.run.dropEnv }, ctx.root),
          encoding: 'utf8',
        });
        const said = JSON.parse(probe.stdout) as Omit<IniProbe, 'given'>;
        ini.push({ given: options[options.indexOf('-c') + 1] ?? '', ...said });
      }
      return prep;
    },
  };
  return { analyzer, cwd, deps, ini };
}

/** The variable that marks the processes of one scan (it passes the analyzer environment). */
const PROCESS_TAG = 'QA_PHP_PROCESS_TAG';

interface PhpProcess {
  argv: string[];
  env: Map<string, string>;
  /** The php extension modules (`*.so` of php's extension directory) mapped into the process. */
  modules: Set<string>;
}

/** The NUL-separated entries of /proc/<pid>/<what>. */
const procEntries = (pid: string, what: string) =>
  readFileSync(`/proc/${pid}/${what}`, 'utf8').split('\0').slice(0, -1);

/**
 * Ruling A9-23: every php process carrying `tag` in its environment while the scan runs (the
 * probe, the wrapper, PHPStan and its worker processes), from /proc: its command line, its
 * environment and the extension modules it has loaded. Linux only (the toolbox).
 */
function watchPhpProcesses(tag: string): { seen: Map<number, PhpProcess>; stop(): void } {
  const seen = new Map<number, PhpProcess>();
  const visit = (pid: string) => {
    let p = seen.get(Number(pid));
    if (p === undefined) {
      const argv = procEntries(pid, 'cmdline');
      if (!path.basename(argv[0] ?? '').startsWith('php')) return;
      const env = new Map(
        procEntries(pid, 'environ').map((kv) => {
          const eq = kv.indexOf('=');
          return [kv.slice(0, eq), kv.slice(eq + 1)] as const;
        }),
      );
      if (env.get(PROCESS_TAG) !== tag) return;
      p = { argv, env, modules: new Set() };
      seen.set(Number(pid), p);
    }
    for (const line of readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n')) {
      const file = line.split(/\s+/)[5] ?? '';
      if (/^\/usr\/lib\/php\/\d+\/[^/]+\.so$/.test(file)) p.modules.add(path.basename(file));
    }
  };
  const poll = () => {
    for (const pid of readdirSync('/proc')) {
      if (!/^\d+$/.test(pid)) continue;
      try {
        visit(pid);
      } catch {
        // The process has gone.
      }
    }
  };
  const timer = setInterval(poll, 5);
  return {
    seen,
    stop: () => {
      clearInterval(timer);
      poll();
    },
  };
}

const QUALOR_MODULES = ['phar.so', 'tokenizer.so'];

/**
 * Ruling A9-23: php under Qualor's php.ini has pcre.jit=0, reads no scan directory and loads the
 * two extensions of that ini only; and every php process of the scan, PHPStan's worker processes
 * included, was started with that php.ini, an empty PHP_INI_SCAN_DIR and no PHPRC, and loaded no
 * extension module but those two.
 */
function expectQualorPhpOnly(ini: IniProbe[], processes: Map<number, PhpProcess>): void {
  expect(ini).toHaveLength(1);
  const probe = ini[0]!;
  const all = [...processes.values()];
  const shown = JSON.stringify(all.map((p) => p.argv));
  const workers = all.filter((p) => p.argv.includes('worker'));
  // Enough files for several of PHPStan's jobs: it analysed them in worker processes.
  expect(workers.length, shown).toBeGreaterThan(0);
  expect(
    all.some((p) => p.argv.some((a) => a.endsWith('qualor-phpstan.php'))),
    shown,
  ).toBe(true);
  for (const w of workers) {
    const argv = w.argv.join(' ');
    expect({ argv: w.argv.slice(1, 3), modules: [...w.modules].sort() }, argv).toEqual({
      argv: ['-c', probe.given],
      modules: QUALOR_MODULES,
    });
  }
  for (const p of all) {
    const argv = p.argv.join(' ');
    expect(p.argv.slice(1, 3), argv).toEqual(['-c', probe.given]);
    expect(p.argv, argv).not.toContain('-n');
    expect(p.env.get('PHP_INI_SCAN_DIR'), argv).toBe('');
    expect(p.env.has('PHPRC'), argv).toBe(false);
    for (const m of p.modules) expect(QUALOR_MODULES, argv).toContain(m);
  }

  expect(path.basename(probe.given)).toBe('qualor-php.ini');
  expect(probe).toMatchObject({ jit: '0', loaded: probe.given, scanned: false });
  expect(probe.extensions).toEqual(expect.arrayContaining(['Phar', 'tokenizer']));
  for (const ext of ['ctype', 'posix', 'Zend OPcache', 'iconv'])
    expect(probe.extensions).not.toContain(ext);
}

const DEPENDENCY_COPY = (v: string) => [
  `${v}/acme/lib/src/Base.php`,
  `${v}/acme/lib/src/functions.php`,
  `${v}/composer/semver/src/functions.php`,
  `${v}/phpstan/extension-installer/src/GeneratedConfig.php`,
];

describeWithPhpstan()('PHPStan on untrusted checkouts (real PHPStan, Review Focus 1, 2)', () => {
  for (const layout of [
    {
      vendorDir: 'vendor',
      neons: ['phpstan.neon', 'phpstan.neon.dist', 'phpstan.dist.neon'],
      // PHPStan reads the first of its configurations it finds: phpstan.neon.
      bootstrap: 'phpstan.neon',
    },
    { vendorDir: 'lib', neons: ['phpstan.neon.dist'], bootstrap: 'phpstan.neon.dist' },
  ]) {
    it(
      `never runs a line of the checkout (${layout.vendorDir}/, ${layout.bootstrap}): autoloaders, Composer's files, bin, bootstrap files, includes, extensions, php.ini, its php (ruling A9-16)`,
      TIMEOUT,
      async () => {
        // The positive control: PHPStan run in the checkout itself runs every one of them (with a
        // custom vendor-dir, it loads <vendor-dir>/autoload.php and leaves vendor/autoload.php).
        const control = tmp();
        const controlMarkers = tmp();
        hostileCheckout(control, controlMarkers, layout);
        phpstanInCheckout(control);
        expect(readdirSync(controlMarkers).sort()).toEqual(
          [
            'autoload',
            'autoload-files',
            'autoload-real',
            'autoload-static',
            'bin-php',
            'bin-proxy',
            `bootstrap-${layout.bootstrap}`,
            'class-loader',
            'composer-package',
            'extension-installer',
            'installed-php',
            'installed-versions',
            'neon-includes',
            'php-ini',
            'php-ini-scan-dir',
            'platform-check',
            'root-autoload-files',
            'rule-class',
            'vendor-class',
            'vendor-function-file',
          ].map((w) => `ran-${w}`),
        );

        // Qualor's scan of the same checkout: no marker at all, nothing written in the checkout.
        const root = tmp();
        const markers = tmp();
        hostileCheckout(root, markers, layout);
        const before = snapshot(root);
        const seen = observed();
        const tag = `9a-${process.pid}-${Date.now()}`;
        const processes = watchPhpProcesses(tag);
        const { capture, keys, lines } = await scanPhp(root, {
          env: { ...hostileEnv(root), [PROCESS_TAG]: tag },
          analyzer: seen.analyzer,
        }).finally(() => processes.stop());
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(readdirSync(markers)).toEqual([]);
        expect(snapshot(root)).toEqual(before);
        // PHPStan's cwd holds Qualor's files only: no vendor/, composer.json or project .neon.
        expect(seen.cwd).toEqual([
          ['deps', 'phpstan.neon', 'qualor-php.ini', 'qualor-phpstan.php', 'src'],
        ]);
        // The dependencies are copied as symbols, without Composer's own files and bin/.
        expect(seen.deps).toEqual([DEPENDENCY_COPY(layout.vendorDir)]);
        // The vendor symbols resolve: the by-reference argument defines $m (no variable.undefined
        // on line 13), Base::hello() is known (its argument count is checked on line 18), and no
        // unknown-symbol message (method.notFound, class.notFound, function.notFound) was dropped.
        expect(keys).toEqual([
          'arguments.count src/App.php:18',
          'arguments.count src/App.php:28',
          'variable.undefined src/App.php:23',
        ]);
        expect(lines.join('\n')).not.toMatch(/unknown-symbol message/);
        expectQualorPhpOnly(seen.ini, processes.seen);
      },
    );
  }

  it(
    'fires every curated SonarQube target at the default level (import-sonarqube.md §6.1)',
    TIMEOUT,
    async () => {
      // One snippet per target, each in its own namespace (two snippets declaring the same class
      // would confuse PHPStan). Task 10's rows may only name identifiers listed here.
      const SNIPPETS: Record<string, string> = {
        'variable.undefined': 'function f(): int { return $x; }',
        'arguments.count':
          'function f(int $a): int { return $a; } function g(): int { return f(1, 2); }',
        'function.void': 'function v(): void {} function g(): void { $x = v(); echo $x; }',
        'method.void':
          'final class A { public function v(): void {} public function g(): void { $x = $this->v(); echo $x; } }',
        'staticMethod.void':
          'final class A { public static function s(): void {} public function g(): void { $x = self::s(); echo $x; } }',
        'catch.notThrowable':
          'final class NotEx {} function f(): void { try { echo 1; } catch (NotEx $e) { echo 2; } }',
        'constructor.unusedParameter':
          'final class A { public function __construct(int $unused) {} }',
      };
      const ids = Object.keys(SNIPPETS);
      const root = tmp();
      writeTree(
        root,
        Object.fromEntries(
          ids.map((id, i) => [`s/${id}.php`, `<?php\nnamespace S${i};\n${SNIPPETS[id]}\n`]),
        ),
      );
      const { capture, keys } = await scanPhp(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      for (const id of ids) expect(keys, id).toContain(`${id} s/${id}.php:3`);
      const sonarTable = JSON.parse(
        readFileSync('packages/shared/rules/sonarqube.json', 'utf8'),
      ) as {
        rules: { sonar: string[]; qualor: string[] }[];
      };
      const targets = sonarTable.rules
        .filter((r) => r.sonar.some((s) => s.startsWith('php:')))
        .flatMap((r) => r.qualor);
      for (const t of targets) expect(ids, t).toContain(t.slice('phpstan:'.length));
    },
  );

  it(
    'is skipped when composer.json requires packages that are not installed',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'composer.json': JSON.stringify({ require: { 'acme/lib': '^1' } }),
        'a.php': '<?php\n',
      });
      const { capture } = await scanPhp(root);
      expect(capture).toMatchObject({ status: 'skipped', reason: DEPENDENCIES_NOT_INSTALLED });
    },
  );

  it(
    'drops unknown symbols (framework magic, PHPUnit not installed) and analyses PHP 8.4 syntax',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'src/User.php': `<?php\nnamespace App;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass User extends Model\n{\n    public function posts()\n    {\n        return $this->hasMany(Post::class)->where('a', 1);\n    }\n}\n`,
        'src/Point.php': `<?php\nnamespace App;\n\nfinal class Point\n{\n    public private(set) int $x = 0;\n    public string $label { get => strtoupper($this->label); set => $value; }\n\n    public function f(): int\n    {\n        return $nope;\n    }\n}\n`,
        'tests/UserTest.php': `<?php\nnamespace Tests;\n\nuse PHPUnit\\Framework\\TestCase;\n\nfinal class UserTest extends TestCase\n{\n    public function testIt(): void\n    {\n        self::assertTrue(true);\n    }\n}\n`,
      });
      const { capture, keys } = await scanPhp(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(keys).toEqual(['variable.undefined src/Point.php:11']);
    },
  );
});

describeWithPhpstan()(
  'PHPStan on awkward paths and failures (real PHPStan, Review Focus 3, 4)',
  () => {
    it(
      'reports on the right repository path, once, whatever the names and the work directory',
      TIMEOUT,
      async () => {
        const root = tmp();
        const names = ['a b.php', 'c#d.php', 'e%f.php', "g'h.php", '-dash.php', 'ü.php', 'q"r.php'];
        writeTree(root, {
          // A function name per file: two global functions of one name would be an error of their own.
          ...Object.fromEntries(
            names.map((n, i) => [`src/${n}`, `<?php\nfunction f${i}(): int { return $x; }\n`]),
          ),
          'src/T.php':
            '<?php\nnamespace App;\n\ntrait T\n{\n    public function t(): int\n    {\n        return $y;\n    }\n}\n',
          'src/AB.php':
            '<?php\nnamespace App;\n\nfinal class A { use T; }\nfinal class B { use T; }\n',
          // PHPStan 2.2 checks a require of a constant path; `__DIR__ . '/x'` is not one without its
          // bleeding-edge feature toggle (Task 9 report), so the path is relative.
          'src/Req.php': "<?php\nrequire 'missing.php';\n",
          'LEGACY.PHP': '<?php\nfunction g(): int { return $z; }\n',
        });
        const tempRoot = path.join(tmp(), 'tmp 100% #x');
        mkdirSync(tempRoot);
        const { capture, keys, lines } = await scanPhp(root, { tempRoot });
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(keys).toEqual(
          [
            ...names.map((n) => `variable.undefined src/${n}:2`),
            'variable.undefined src/T.php:8',
            'require.fileNotFound src/Req.php:2',
          ].sort(),
        );
        expect(lines.join('\n')).toContain(
          'phpstan: 1 PHP file(s) whose name does not end in .php were left out',
        );
        const req = capture.sarif as {
          runs: { results: { ruleId: string; message: { text: string } }[] }[];
        };
        const text = req.runs[0]!.results.find((r) => r.ruleId === 'require.fileNotFound')!.message
          .text;
        expect(text).not.toContain(tempRoot);
        expect(text).toBe('Path in require() "missing.php" is not a file or it does not exist.');
      },
    );

    // Ruling A9-19: a file PHPStan cannot parse is a "severe error", after which its report lists
    // only those; the file is left out and PHPStan runs once more, so the other findings survive.
    it(
      'keeps the findings of every other file when PHPStan cannot parse one, and names the file left out',
      TIMEOUT,
      async () => {
        const root = tmp();
        writeTree(root, {
          'src/Broken.php': '<?php\nfunction (\n',
          'src/sub dir/Also #broken.php': '<?php\nclass {\n',
          'src/a.php': '<?php\nfunction f(): int { return $x; }\n',
        });
        const { capture, keys, lines } = await scanPhp(root);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(keys).toEqual(['variable.undefined src/a.php:2']);
        expect(lines.join('')).toContain(
          'warn: phpstan: 2 PHP file(s) PHPStan cannot parse were left out: src/Broken.php, src/sub dir/Also #broken.php',
        );
      },
    );

    it('is ok without findings when PHPStan can parse no file at all', TIMEOUT, async () => {
      const root = tmp();
      writeTree(root, { 'src/Broken.php': '<?php\nfunction (\n' });
      const { capture, keys, lines } = await scanPhp(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(keys).toEqual([]);
      expect(lines.join('')).toContain(
        'warn: phpstan: 1 PHP file(s) PHPStan cannot parse were left out: src/Broken.php',
      );
    });

    // Skipped (and shown as skipped) where file symlinks cannot be made; it runs in the toolbox.
    it.skipIf(!CAN_SYMLINK_FILES)(
      'never analyses a .php link out of the repository',
      TIMEOUT,
      async () => {
        const root = tmp();
        const outside = tmp();
        writeTree(outside, { 'secret.php': '<?php\nfunction s(): int { return $secret; }\n' });
        writeTree(root, { 'src/ok.php': '<?php\nfunction ok(): int { return 1; }\n' });
        symlinkSync(path.join(outside, 'secret.php'), path.join(root, 'src', 'link.php'), 'file');
        const { capture, keys } = await scanPhp(root);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        // secret.php's undefined $secret would be a finding if the link were followed.
        expect(keys).toEqual([]);
      },
    );

    it('fails, with PHPStan’s reason in the log, when it writes no report', TIMEOUT, async () => {
      const root = tmp();
      writeTree(root, { 'a.php': '<?php\n' });
      const { capture, lines } = await scanPhp(root, {
        config: { analyzers: { phpstan: { memoryLimit: '1M' } } },
      });
      expect(capture).toMatchObject({ status: 'failed', reason: 'exited with code 4' });
      // PHPStan prints its own reason on stdout or stderr; the unit test of phpstanFailureDetail pins
      // how a reason after the wrapper's line is joined to it.
      expect(lines.join('\n')).toContain(
        'phpstan: qualor-phpstan: PHPStan wrote no report (exit code 1)',
      );
    });
  },
);
