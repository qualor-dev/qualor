import {
  chmodSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import {
  engineMapping,
  parseConfig,
  SWIFTLINT_VERSION,
  type QualorConfigInput,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext, recorded, scanWithRecordedSarif } from '../../test/analyzers';
import { normalizeCaptures } from './normalize';
import { swiftlintSarif } from './swiftlint-sarif';
import { useTempDirs, writeTree } from '../../test/tmp';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { runAnalyzers } from './runner';
import {
  parseSwiftlintVersion,
  SWIFTLINT_KEPT_ENV,
  swiftlintAnalyzer,
  swiftlintFailureDetail,
} from './swiftlint';
import type { AnalyzerCommand, AnalyzerContext } from './types';

const tmp = useTempDirs();
const BIN = '/opt/qualor/bin/swiftlint';
const posix = process.platform !== 'win32';

function scope(root: string, rel: string, language: ScopeFile['language'] = 'swift'): ScopeFile {
  const absPath = path.join(root, ...rel.split('/'));
  let size = 1;
  try {
    size = statSync(absPath).size;
  } catch {
    // A path the test only lists (a line break, which Windows cannot create).
  }
  return { path: rel, absPath, language, grammar: 'swift', kind: 'main', size };
}

function context(
  files: Record<string, string>,
  o: {
    config?: Omit<QualorConfigInput, 'version'>;
    version?: string;
    exitCode?: number;
    lines?: string[];
  } = {},
): { ctx: AnalyzerContext; root: string; work: string } {
  const root = tmp();
  const work = tmp();
  writeTree(root, files);
  const base = fakeContext(root, {
    binaries: { swiftlint: BIN },
    workDir: work,
    config: o.config ?? {},
    exec: () => ({
      exitCode: o.exitCode ?? 0,
      timedOut: false,
      durationMs: 1,
      stdout: `${o.version ?? SWIFTLINT_VERSION}\n`,
      stderr: '',
    }),
  });
  const swift = Object.keys(files).filter((f) => f.endsWith('.swift'));
  const lines: string[] = o.lines ?? [];
  return {
    ctx: {
      ...base,
      files: swift.map((f) => scope(root, f)),
      log: createLogger('debug', (t) => lines.push(t)),
    },
    root,
    work,
  };
}

async function run(ctx: AnalyzerContext): Promise<AnalyzerCommand> {
  const p = await swiftlintAnalyzer.prepare(ctx);
  if (!('run' in p)) throw new Error(JSON.stringify(p));
  return p.run;
}

const listed = (work: string) =>
  readFileSync(path.join(work, 'swiftlint-files.xcfilelist'), 'utf8');

/** Every file below `dir`, `/`-separated. */
function tree(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => path.relative(dir, path.join(d.parentPath, d.name)).split(path.sep).join('/'))
    .sort();
}

describe('swiftlintAnalyzer.prepare (config.md §6, plan 8F)', () => {
  it('runs swiftlint lint on a checked copy by a list file, with its own configuration, never the checkout’s', async () => {
    const { ctx, work } = context({
      'Sources/A.swift': 'let a = 1\n',
      'Sources/.swiftlint.yml': 'disabled_rules: [colon]\n',
      'README.md': '# x\n',
      '.swiftlint.yml': 'write_baseline: /tmp/marker.json\nline_length: 90\n',
    });
    const cmd = await run(ctx);
    const config = path.join(work, 'swiftlint.yml');
    const list = path.join(work, 'swiftlint-files.xcfilelist');
    const input = path.join(work, 'src');
    expect(cmd.command).toBe(BIN);
    expect(cmd.args).toEqual([
      'lint',
      '--quiet',
      '--no-cache',
      '--config',
      config,
      '--use-script-input-file-lists',
      '--reporter',
      'sarif',
      '--output',
      path.join(work, 'swiftlint.sarif'),
    ]);
    // Ruling F10: SwiftLint reads the copy, so its SARIF URIs are the repository paths.
    expect(cmd.cwd).toBe(input);
    expect(cmd.okExitCodes).toEqual([0, 2]);
    expect(cmd.version).toBe(SWIFTLINT_VERSION);
    expect(listed(work)).toBe(`${path.join(input, 'Sources', 'A.swift')}\n`);
    // Only the Swift files are copied: no configuration of the checkout is in the copy.
    expect(tree(input)).toEqual(['Sources/A.swift']);
    expect(readFileSync(path.join(input, 'Sources', 'A.swift'), 'utf8')).toBe('let a = 1\n');
    const yaml = readFileSync(config, 'utf8');
    expect(yaml).toContain('"line_length": 90');
    expect(yaml).not.toContain('write_baseline');
    expect(cmd.env).toMatchObject({
      HOME: work,
      LC_ALL: 'C.UTF-8',
      SWIFTLINT_DISABLE_SOURCEKIT: '1',
      SCRIPT_INPUT_FILE_LIST_COUNT: '1',
      SCRIPT_INPUT_FILE_LIST_0: list,
      HTTPS_PROXY: 'http://127.0.0.1:9',
    });
  });

  it('gives a project without a configuration Qualor’s defaults layer (ruling F5)', async () => {
    const { ctx, work } = context({ 'A.swift': 'let a = 1\n' });
    await run(ctx);
    const yaml = readFileSync(path.join(work, 'swiftlint.yml'), 'utf8');
    expect(yaml).toContain('qualor-default');
    expect(yaml).toContain('"ignores_empty_lines": true');
    expect(yaml).toMatch(
      /"disabled_rules":\n {2}- "todo"\n {2}- "multiple_closures_with_trailing_closure"/,
    );
  });

  it('keeps only an allowlist of variables, so ${CI_JOB_TOKEN} in a config expands to nothing', async () => {
    const { ctx } = context({ 'A.swift': 'let a = 1\n' });
    const cmd = await run(ctx);
    const keep = (name: string) => !cmd.dropEnv!(name);
    for (const name of [
      'CI_JOB_TOKEN',
      'GITHUB_TOKEN',
      'AWS_SECRET_ACCESS_KEY',
      'HOME_EXTRA',
      'SWIFTLINT_X',
      'QUALOR_URL',
      'LD_PRELOAD',
    ]) {
      expect(keep(name), name).toBe(false);
    }
    for (const name of [
      'PATH',
      'Path',
      'TMPDIR',
      'LANG',
      'LC_ALL',
      'HOME',
      'SWIFTLINT_DISABLE_SOURCEKIT',
      'SCRIPT_INPUT_FILE_LIST_0',
    ]) {
      expect(keep(name), name).toBe(true);
    }
    expect([...SWIFTLINT_KEPT_ENV]).toEqual([
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
  });

  it.runIf(posix)(
    'never lets a CI secret reach the swiftlint process (a stand-in swiftlint records its environment)',
    async () => {
      const root = tmp();
      const bin = tmp();
      const record = path.join(tmp(), 'env.txt');
      writeTree(root, { 'A.swift': 'let a = 1\n' });
      const script = [
        '#!/bin/sh',
        `if [ "$1" = version ]; then echo ${SWIFTLINT_VERSION}; exit 0; fi`,
        `env > '${record}'`,
        'while [ $# -gt 0 ]; do if [ "$1" = --output ]; then out="$2"; fi; shift; done',
        `printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"SwiftLint"}},"results":[]}]}' > "$out"`,
        '',
      ].join('\n');
      writeFileSync(path.join(bin, 'swiftlint'), script);
      chmodSync(path.join(bin, 'swiftlint'), 0o755);
      const [capture] = await runAnalyzers([swiftlintAnalyzer], {
        root,
        config: parseConfig({ version: 1 }),
        files: [scope(root, 'A.swift')],
        log: silentLogger,
        env: {
          PATH: `${bin}:/usr/bin:/bin`,
          LANG: 'en_US.UTF-8',
          CI_JOB_TOKEN: 's3cr3t-job',
          GITHUB_TOKEN: 's3cr3t-gh',
          SWIFTLINT_SECRET: 's3cr3t-sl',
        },
      });
      expect(capture?.status, capture?.reason ?? '').toBe('ok');
      const env = readFileSync(record, 'utf8');
      expect(env).not.toContain('s3cr3t');
      expect(env).toContain('LANG=en_US.UTF-8');
      expect(env).toContain('LC_ALL=C.UTF-8');
      expect(env).toContain('SWIFTLINT_DISABLE_SOURCEKIT=1');
      const names = env
        .split('\n')
        .filter((l) => l.includes('='))
        .map((l) => l.slice(0, l.indexOf('=')));
      for (const name of names) {
        expect(
          SWIFTLINT_KEPT_ENV.has(name) ||
            /^(HOME|LC_ALL|SWIFTLINT_DISABLE_SOURCEKIT|SCRIPT_INPUT_FILE_LIST_(COUNT|0)|(HTTPS?|ALL|NO)_PROXY|(https?|all|no)_proxy|PWD|SHLVL|_)$/.test(
              name,
            ),
          name,
        ).toBe(true);
      }
    },
  );

  it("lists only the scope's Swift files the configuration keeps, never a link or a line break", async () => {
    const lines: string[] = [];
    const { ctx, root, work } = context(
      {
        '.swiftlint.yml': 'included: [Sources]\nexcluded: [Sources/Generated]\n',
        'Sources/A b#ü.swift': 'let a = 1\n',
        'Sources/Generated/G.swift': 'let g = 1\n',
        'Tools/T.swift': 'let t = 1\n',
      },
      { lines },
    );
    const withOddOnes = [
      ...ctx.files,
      scope(root, 'Sources/new\nline.swift'),
      scope(root, 'Sources/cr\rx.swift'),
      scope(root, 'Sources/nel\u0085x.swift'),
      scope(root, 'Sources/ls\u2028x.swift'),
      scope(root, 'Sources/ps\u2029x.swift'),
    ];
    if (posix) {
      symlinkSync(path.join(root, 'Tools/T.swift'), path.join(root, 'Sources/L.swift'));
      withOddOnes.push(scope(root, 'Sources/L.swift'));
    }
    await run({ ...ctx, files: withOddOnes });
    expect(listed(work)).toBe(`${path.join(work, 'src', 'Sources', 'A b#ü.swift')}\n`);
    const text = lines.join('');
    expect(text).toContain('swiftlint: 5 file(s) whose path has a line break were left out');
    if (posix) {
      expect(text).toContain(
        'swiftlint: 1 Swift file(s) not analysed (a link, a file that cannot be read, or one below a directory named .swiftlint.yml)',
      );
    }
  });

  it('lints only Swift files whose name ends in exactly .swift; a language override is respected (rulings F6, F26)', async () => {
    const lines: string[] = [];
    const { ctx, root, work } = context(
      { 'A.swift': 'let a = 1\n', 'Package.SWIFT': 'let p = 1\n', 'B.Swift': 'let b = 1\n' },
      { lines },
    );
    const files = [
      scope(root, 'A.swift'),
      scope(root, 'Package.SWIFT'),
      scope(root, 'B.Swift'),
      // A language override away from swift (`languages:` in qualor.yml): not linted.
      scope(root, 'C.swift', 'other'),
      scope(root, 'Sources/.swift'),
    ];
    writeTree(root, { 'C.swift': 'let c = 1\n' });
    await run({ ...ctx, files });
    expect(listed(work)).toBe(`${path.join(work, 'src', 'A.swift')}\n`);
    expect(lines.join('')).toContain(
      'swiftlint: 3 Swift file(s) whose name does not end in .swift were left out (SwiftLint lints only *.swift)',
    );
  });

  it('leaves out files over 1 MiB with one warning (ruling F7), and a directory named .swiftlint.yml', async () => {
    const lines: string[] = [];
    const big = `// ${'x'.repeat(MAX_ANALYZED_BYTES)}\n`;
    const { ctx, work } = context(
      {
        'A.swift': 'let a = 1\n',
        'Big.swift': big,
        'Big2.swift': big,
        'Sub/.swiftlint.yml/Hidden.swift': 'let h = 1\n',
      },
      { lines },
    );
    await run(ctx);
    expect(listed(work)).toBe(`${path.join(work, 'src', 'A.swift')}\n`);
    expect(tree(path.join(work, 'src'))).toEqual(['A.swift']);
    const text = lines.join('');
    expect(text).toContain('swiftlint: 2 Swift file(s) larger than 1 MiB were left out');
    expect(text).toContain('swiftlint: 1 Swift file(s) not analysed');
  });

  it('skips when every Swift file is left out: a line break, another case, over 1 MiB', async () => {
    const { ctx, root } = context({ 'X.SWIFT': 'let a = 1\n' });
    const files = [scope(root, 'X.SWIFT'), scope(root, 'new\nline.swift')];
    expect(await swiftlintAnalyzer.prepare({ ...ctx, files })).toEqual({
      skip: 'no Swift file left to lint: names SwiftLint cannot read (case or line break)',
    });
    const big = context({ 'Big.swift': `// ${'x'.repeat(MAX_ANALYZED_BYTES)}\n` });
    expect(await swiftlintAnalyzer.prepare(big.ctx)).toEqual({
      skip: 'no Swift file in scope that SwiftLint can be given',
    });
  });

  it('logs what the configuration asked for that does not run, and the keys left out', async () => {
    const lines: string[] = [];
    const { ctx } = context(
      {
        'A.swift': 'let a = 1\n',
        '.swiftlint.yml': 'opt_in_rules: [explicit_self]\nreporter: xcode\ncustom_rules: {}\n',
      },
      { lines },
    );
    await run(ctx);
    const text = lines.join('');
    expect(text).toContain(
      'warn: swiftlint: explicit_self, custom_rules need SourceKit, which the bundled SwiftLint does not have; they do not run',
    );
    expect(text).toContain('swiftlint: .swiftlint.yml: left out reporter (config.md §6)');
  });

  it('is skipped, not unavailable, without swiftlint (ruling G6), and says a repository copy is never run', async () => {
    const { ctx } = context({ 'A.swift': 'let a = 1\n' });
    const p = await swiftlintAnalyzer.prepare({
      ...ctx,
      resolveBinary: () => null,
      repoBinary: () => '/r/bin/swiftlint',
    });
    expect(p).toEqual({
      skip: "SwiftLint is not installed (swiftlint on PATH or in the qualor/scanner image); the repository's own swiftlint is never run",
    });
    const none = await swiftlintAnalyzer.prepare({ ...ctx, resolveBinary: () => null });
    expect(none).toEqual({
      skip: 'SwiftLint is not installed (swiftlint on PATH or in the qualor/scanner image)',
    });
  });

  it('skips another SwiftLint minor, naming both, and is unavailable when swiftlint prints no version', async () => {
    const [major, minor] = SWIFTLINT_VERSION.split('.');
    const other = `${major}.${Number(minor) + 1}.0`;
    const skip = await swiftlintAnalyzer.prepare(
      context({ 'A.swift': 'let a = 1\n' }, { version: other }).ctx,
    );
    expect(skip).toEqual({
      skip: `SwiftLint ${other} is not supported: this Qualor runs SwiftLint ${major}.${minor}.x (the qualor/scanner image's ${SWIFTLINT_VERSION})`,
    });
    const silent = await swiftlintAnalyzer.prepare(
      context({ 'A.swift': 'let a = 1\n' }, { version: 'oops' }).ctx,
    );
    expect(silent).toEqual({ unavailable: '`swiftlint version` printed no version' });
    const failed = await swiftlintAnalyzer.prepare(
      context({ 'A.swift': 'let a = 1\n' }, { exitCode: 1 }).ctx,
    );
    expect(failed).toEqual({ unavailable: '`swiftlint version` printed no version' });
  });

  it('passes on the configuration skips (parent_config, a missing configFile)', async () => {
    const parent = await swiftlintAnalyzer.prepare(
      context({ 'A.swift': 'x\n', '.swiftlint.yml': 'parent_config: p.yml\n' }).ctx,
    );
    expect(parent).toMatchObject({ skip: expect.stringContaining('configFile: qualor-default') });
    const missing = await swiftlintAnalyzer.prepare(
      context(
        { 'A.swift': 'x\n' },
        { config: { analyzers: { swiftlint: { configFile: 'no.yml' } } } },
      ).ctx,
    );
    expect(missing).toEqual({ skip: 'configFile no.yml does not exist' });
  });

  it('skips when the configuration leaves no file to lint', async () => {
    const p = await swiftlintAnalyzer.prepare(
      context({ 'A.swift': 'let a = 1\n', '.swiftlint.yml': 'excluded: [A.swift]\n' }).ctx,
    );
    expect(p).toEqual({ skip: 'no Swift file left to lint (.swiftlint.yml: included/excluded)' });
  });

  it('turns a skip into a failure under enabled: true, without marking the engine unavailable', async () => {
    // A missing configFile skips before swiftlint is even looked up, so this holds on a CI
    // runner that has /opt/qualor/bin/swiftlint too; the missing-binary skip is the test above.
    const root = tmp();
    writeTree(root, { 'A.swift': 'let a = 1\n' });
    const [capture] = await runAnalyzers([swiftlintAnalyzer], {
      root,
      config: parseConfig({
        version: 1,
        analyzers: { swiftlint: { enabled: true, configFile: 'no.yml' } },
      }),
      files: [scope(root, 'A.swift')],
      log: silentLogger,
      env: {},
    });
    expect(capture).toMatchObject({ status: 'failed', reason: 'configFile no.yml does not exist' });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it('refuses a configFile that is a URL or outside the repository (exit 2, ruling F3)', () => {
    const root = tmp();
    const cfg = (configFile: string) =>
      parseConfig({ version: 1, analyzers: { swiftlint: { configFile } } });
    expect(swiftlintAnalyzer.checkConfig!(root, cfg('https://x/y.yml'))).toContain('is a URL');
    expect(swiftlintAnalyzer.checkConfig!(root, cfg('../y.yml'))).toContain(
      'outside the repository',
    );
    expect(swiftlintAnalyzer.checkConfig!(root, cfg('missing.yml'))).toBeNull();
  });

  it('reads the version swiftlint prints', () => {
    expect(parseSwiftlintVersion('0.65.1\n')).toBe('0.65.1');
    expect(parseSwiftlintVersion('')).toBeNull();
    expect(parseSwiftlintVersion('SwiftLint 0.65.1 garbage\n')).toBeNull();
  });

  it('logs why swiftlint failed from its recorded stderr, the work directory shown as <work> (ruling F8)', async () => {
    const stderr = recorded('swiftlint/stderr.json') as Record<string, string>;
    const work = '/tmp/qualor-swiftlint-AbC123';
    expect(swiftlintFailureDetail(stderr['yaml']!, work)).toBe(
      'error: Cannot parse YAML file: 2:1: error: parser: while parsing a flow node in line 2, column 1',
    );
    expect(swiftlintFailureDetail(stderr['noFiles']!, work)).toBe(
      "Error: No lintable files found at paths: '<work>/src'",
    );
    expect(swiftlintFailureDetail(stderr['combined']!, work)).toBe(
      "error: 'disabled_rules' or 'opt_in_rules' cannot be used in combination with 'only_rules'",
    );
    expect(swiftlintFailureDetail('\n  \n', work)).toBeNull();
    expect(swiftlintFailureDetail(`Segmentation fault in ${work}/src/A.swift\n`, work)).toBe(
      'Segmentation fault in <work>/src/A.swift',
    );
    // Wired into the command.
    const { ctx, work: dir } = context({ 'A.swift': 'let a = 1\n' });
    const cmd = await run(ctx);
    expect(cmd.failureDetail!(1, `Error: No lintable files found at paths: '${dir}/src'\n`)).toBe(
      "Error: No lintable files found at paths: '<work>/src'",
    );
  });

  it('normalises the recorded fixture run into swiftlint issues with kind-based quality and severity', () => {
    const report = scanWithRecordedSarif(
      'swiftlint',
      'cli/test/analyzer-output/swiftlint/basic.sarif',
    );
    const by = (key: string) => report.issues.filter((i) => i.ruleKey === key);
    expect(by('swiftlint:duplicate_conditions').map((i) => [i.severity, i.quality])).toEqual([
      ['high', 'reliability'],
      ['high', 'reliability'],
    ]);
    expect(by('swiftlint:force_cast')[0]).toMatchObject({
      severity: 'high',
      quality: 'maintainability',
    });
    expect(by('swiftlint:force_unwrapping')[0]).toMatchObject({
      severity: 'low',
      quality: 'maintainability',
    });
    expect(by('swiftlint:line_length')[0]).toMatchObject({
      severity: 'low',
      quality: 'maintainability',
    });
    expect(report.issues.map((i) => i.location?.path)).toEqual(
      report.issues.map(() => 'Sources/App/Store.swift'),
    );
    expect(report.issues).toHaveLength(5);
    // The recorded SARIF is re-recorded on each SwiftLint bump (fixtures/README.md), so the
    // driver's semanticVersion always names the pinned SwiftLint.
    expect(report.engines[0]?.version).toBe(SWIFTLINT_VERSION);
  });

  it('keeps the repository path of a file named with %, a colon, a space, # or ü (fix round 1, Important 1)', async () => {
    // SwiftLint writes the relative path raw; the normaliser decodes a relative URI.
    const names = [
      '100%.swift',
      'p%41q.swift',
      'p%zz.swift',
      'a:b.swift',
      'Sources/a b#ü.swift',
      'Sources/x?y.swift',
    ];
    const sarif = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'SwiftLint', semanticVersion: SWIFTLINT_VERSION } },
          results: names.map((uri) => ({
            ruleId: 'colon',
            level: 'warning',
            message: { text: 'Colon spacing should be correct' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri },
                  region: { startLine: 1, startColumn: 6 },
                },
              },
            ],
          })),
        },
      ],
    };
    const { ctx } = context({ 'A.swift': 'let a = 1\n' });
    const cmd = await run(ctx);
    expect(cmd.transform).toBeDefined();
    const out = normalizeCaptures(
      [
        {
          engineId: 'swiftlint',
          kind: 'builtin',
          status: 'ok',
          reason: null,
          durationMs: 1,
          version: SWIFTLINT_VERSION,
          required: false,
          sarif: cmd.transform!(sarif, ''),
          mapping: engineMapping('swiftlint')!,
        },
      ],
      { repoRoot: '/repo', readLines: () => null, knownPaths: new Set(names), log: silentLogger },
    );
    expect(out.findings.map((f) => f.location?.path).sort()).toEqual([...names].sort());
    // An absolute file URI (never written for the copy) is left as it is.
    const uri = 'file:///w/src/A%20b.swift';
    const absolute = swiftlintSarif({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'SwiftLint' } },
          results: [
            {
              ruleId: 'colon',
              message: { text: 'x' },
              locations: [{ physicalLocation: { artifactLocation: { uri } } }],
            },
          ],
        },
      ],
    });
    const loc = absolute.runs[0]?.results?.[0]?.locations?.[0];
    expect(loc?.physicalLocation?.artifactLocation?.uri).toBe(uri);
  });
});
