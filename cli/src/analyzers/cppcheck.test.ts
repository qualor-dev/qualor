import { readFileSync } from 'node:fs';
import path from 'node:path';
import { CPPCHECK_VERSION, parseConfig, type QualorConfigInput } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { cFamilyContext, cFamilyScopeFile as scope } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { C_FAMILY_KEPT_ENV } from './cfamily-common';
import { cppcheckAnalyzer, parseCppcheckVersion } from './cppcheck';
import { runAnalyzers } from './runner';
import type { AnalyzerCommand, AnalyzerContext } from './types';

const tmp = useTempDirs();
const BIN = '/opt/qualor/bin/cppcheck';

const context = (
  files: Record<string, string>,
  {
    version = CPPCHECK_VERSION,
    ...o
  }: {
    config?: Omit<QualorConfigInput, 'version'>;
    version?: string;
    lines?: string[];
    languages?: Record<string, 'c' | 'cpp'>;
  } = {},
) =>
  cFamilyContext(tmp, files, {
    binaries: { cppcheck: BIN },
    versionStdout: `Cppcheck ${version}\n`,
    ...o,
  });

async function run(ctx: AnalyzerContext): Promise<AnalyzerCommand> {
  const p = await cppcheckAnalyzer.prepare(ctx);
  if (!('run' in p)) throw new Error(JSON.stringify(p));
  return p.run;
}

const XML = (errors: string) =>
  `<?xml version="1.0"?><results version="2"><cppcheck version="2.22.0"/><errors>${errors}</errors></results>`;

describe('cppcheckAnalyzer.prepare (config.md §6.2, plan 9D)', () => {
  it('runs on a checked copy with a file list, the default groups, and xmlv2 output', async () => {
    const { ctx, work } = context({
      'src/a.c': 'int a;\n',
      'src/a.h': 'int h;\n',
      'README.md': '# x\n',
    });
    const cmd = await run(ctx);
    const input = path.join(work, 'src');
    expect(cmd.command).toBe(BIN);
    expect(cmd.cwd).toBe(input);
    expect(cmd.args.slice(0, 1)).toEqual(['-q']);
    expect(cmd.args).toContain('--enable=warning,performance,portability');
    expect(cmd.args).toContain('--inline-suppr');
    expect(cmd.args).toContain('--output-format=xmlv2');
    expect(cmd.args).toContain(`--output-file=${path.join(work, 'cppcheck.xml')}`);
    expect(cmd.args).toContain(`--relative-paths=${input}`);
    expect(cmd.args).toContain(`--file-list=${path.join(work, 'cppcheck-files.txt')}`);
    expect(
      cmd.args.some((a) =>
        /^--(addon|clang|project=(?!.*cppcheck-compile-commands)|library=|rule|suppressions-list|cppcheck-build-dir)/.test(
          a,
        ),
      ),
    ).toBe(false);
    expect(readFileSync(path.join(work, 'cppcheck-files.txt'), 'utf8')).toBe('src/a.c\nsrc/a.h\n');
    expect(readFileSync(path.join(input, 'src/a.c'), 'utf8')).toBe('int a;\n');
    expect(cmd.outputFormat).toBe('text');
    expect(cmd.okExitCodes).toEqual([0]);
    expect(cmd.version).toBe(CPPCHECK_VERSION);
    expect(cmd.env).toMatchObject({
      HOME: work,
      LC_ALL: 'C.UTF-8',
      HTTPS_PROXY: 'http://127.0.0.1:9',
    });
  });

  it('never copies a project file, cppcheck.cfg or addon of the checkout, nor names one (config.md §6.2)', async () => {
    const { ctx, work } = context({
      'src/a.c': 'int a;\n',
      'cppcheck.cfg': '{"addons":["evil.py"]}',
      'x.cppcheck': '<project/>',
      'evil.py': 'x',
      'rules.xml': '<rule/>',
    });
    const cmd = await run(ctx);
    const input = path.join(work, 'src');
    expect(() => readFileSync(path.join(input, 'cppcheck.cfg'))).toThrow();
    expect(() => readFileSync(path.join(input, 'x.cppcheck'))).toThrow();
    expect(() => readFileSync(path.join(input, 'evil.py'))).toThrow();
    expect(cmd.args.some((a) => /cppcheck\.cfg|\.cppcheck$|\.py$|rules\.xml/.test(a))).toBe(false);
  });

  it('passes enable, includePaths (inside the copy) and defines from the settings', async () => {
    const { ctx, work } = context(
      { 'src/a.c': 'int a;\n', 'include/x.h': 'int x;\n' },
      {
        config: {
          analyzers: {
            cppcheck: {
              enable: ['warning', 'style'],
              includePaths: ['include'],
              defines: ['DEBUG', 'LEVEL=2'],
            },
          },
        },
      },
    );
    const cmd = await run(ctx);
    expect(cmd.args).toContain('--enable=warning,style');
    expect(cmd.args).toContain(`-I${path.join(work, 'src', 'include')}`);
    expect(cmd.args).toContain('-DDEBUG');
    expect(cmd.args).toContain('-DLEVEL=2');
  });

  it('leaves out .h files the scan counts as C++, which cppcheck would read as C', async () => {
    const { ctx, work } = context(
      { 'src/a.cpp': 'int a;\n', 'include/s.h': 'class S {};\n' },
      { languages: { 'include/s.h': 'cpp' } },
    );
    await run(ctx);
    expect(readFileSync(path.join(work, 'cppcheck-files.txt'), 'utf8')).toBe('src/a.cpp\n');
  });

  it('rewrites a compile database into the copy: in-repo -I, -D, -U, -std only (decision 7)', async () => {
    const { ctx, work, root } = context({
      'src/a.cpp': 'int a;\n',
      'src/b.c': 'int b;\n',
      'include/x.h': 'int x;\n',
      'compile_commands.json': '[]',
    });
    const db = [
      {
        directory: '.',
        file: 'src/a.cpp',
        arguments: [
          'g++',
          '-std=c++17',
          '-Iinclude',
          '-I/usr/include/qt',
          '-isystem',
          '../outside',
          '-include',
          '/etc/passwd',
          '-DA=1',
          '-UB',
          '-fplugin=x.so',
          '-Wall',
          '-c',
          'src/a.cpp',
        ],
      },
      { directory: '.', file: 'src/b.c', command: 'clang -D B -c src/b.c' },
    ];
    writeTree(root, { 'compile_commands.json': JSON.stringify(db) });
    const cmd = await run(ctx);
    const input = path.join(work, 'src');
    expect(cmd.args).toContain(`--project=${path.join(work, 'cppcheck-compile-commands.json')}`);
    expect(cmd.args.some((a) => a.startsWith('--file-list='))).toBe(false);
    expect(
      JSON.parse(readFileSync(path.join(work, 'cppcheck-compile-commands.json'), 'utf8')),
    ).toEqual([
      {
        directory: input,
        file: path.join(input, 'src', 'a.cpp'),
        arguments: [
          'c++',
          '-std=c++17',
          `-I${path.join(input, 'include')}`,
          '-DA=1',
          '-UB',
          '-c',
          path.join(input, 'src', 'a.cpp'),
        ],
      },
      {
        directory: input,
        file: path.join(input, 'src', 'b.c'),
        arguments: ['cc', '-DB', '-c', path.join(input, 'src', 'b.c')],
      },
    ]);
  });

  it('keeps only an allowlist of variables', async () => {
    const { ctx } = context({ 'a.c': 'int a;\n' });
    const cmd = await run(ctx);
    const keep = (name: string) => !cmd.dropEnv!(name);
    for (const n of [
      'CI_JOB_TOKEN',
      'GITHUB_TOKEN',
      'CCC_OVERRIDE_OPTIONS',
      'CPATH',
      'UNUSEDFUNCTION_ONLY',
    ])
      expect(keep(n), n).toBe(false);
    for (const n of ['PATH', 'TMPDIR', 'LANG', 'HOME']) expect(keep(n), n).toBe(true);
    expect([...C_FAMILY_KEPT_ENV]).toEqual([
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

  it('is skipped, not unavailable, without cppcheck; skips another minor; unavailable without a version', async () => {
    const { ctx } = context({ 'a.c': 'int a;\n' });
    expect(
      await cppcheckAnalyzer.prepare({
        ...ctx,
        resolveBinary: () => null,
        repoBinary: () => '/r/cppcheck',
      }),
    ).toEqual({
      skip: "cppcheck is not installed (cppcheck on PATH or in the qualor/scanner image); the repository's own cppcheck is never run",
    });
    const [major, minor] = CPPCHECK_VERSION.split('.');
    const other = `${major}.${Number(minor) - 4}`;
    expect(
      await cppcheckAnalyzer.prepare(context({ 'a.c': 'int a;\n' }, { version: other }).ctx),
    ).toEqual({
      skip: `cppcheck ${other} is not supported: this Qualor runs cppcheck ${major}.${minor}.x (the qualor/scanner image's ${CPPCHECK_VERSION})`,
    });
    expect(
      await cppcheckAnalyzer.prepare(context({ 'a.c': 'int a;\n' }, { version: 'oops' }).ctx),
    ).toEqual({
      unavailable: '`cppcheck --version` printed no version',
    });
  });

  it('skips a configured database that does not exist or cannot be read, and an empty scope', async () => {
    const missing = context(
      { 'a.c': 'int a;\n' },
      { config: { analyzers: { cppcheck: { compileCommands: 'out/cc.json' } } } },
    );
    expect(await cppcheckAnalyzer.prepare(missing.ctx)).toEqual({
      skip: 'compileCommands out/cc.json does not exist',
    });
    const broken = context({ 'a.c': 'int a;\n', 'compile_commands.json': '{' });
    expect(await cppcheckAnalyzer.prepare(broken.ctx)).toEqual({
      skip: 'compile_commands.json is not valid JSON',
    });
    const none = context({ 'a.c': 'int a;\n', 'compile_commands.json': '[]' });
    expect(await cppcheckAnalyzer.prepare(none.ctx)).toEqual({
      skip: 'compile_commands.json names no C or C++ file of the scan',
    });
  });

  it('leaves out files whose path has a line break, with one warning', async () => {
    const lines: string[] = [];
    const { ctx, root, work } = context({ 'a.c': 'int a;\n' }, { lines });
    await run({ ...ctx, files: [...ctx.files, scope(root, 'b\nc.c')] });
    expect(readFileSync(path.join(work, 'cppcheck-files.txt'), 'utf8')).toBe('a.c\n');
    expect(lines.join('')).toContain(
      'cppcheck: 1 file(s) whose path has a line break were left out',
    );
  });

  it('logs the files it could not analyse, from the transform (decision 6)', async () => {
    const lines: string[] = [];
    const { ctx } = context({ 'a.c': 'int a;\n' }, { lines });
    const cmd = await run(ctx);
    const out = cmd.transform!(
      XML(
        '<error id="syntaxError" severity="error" msg="x"><location file="a.c" line="1" column="1"/></error><error id="unknownMacro" severity="error" msg="y"><location file="a.c" line="2" column="1"/></error>',
      ),
      '',
    );
    expect((out as { runs: { results: unknown[] }[] }).runs[0]!.results).toEqual([]);
    expect(lines.join('')).toContain(
      'warn: cppcheck: 2 result(s) say it could not fully analyse the code (syntaxError 1, unknownMacro 1); they are not issues',
    );
  });

  it('drops results and notes outside the repository in the transform, logging only a count (ruling D9-9)', async () => {
    const lines: string[] = [];
    const { ctx } = context({ 'a.c': 'int a;\n' }, { lines });
    const cmd = await run(ctx);
    const out = cmd.transform!(
      XML(
        '<error id="zerodiv" severity="error" msg="Division by zero."><location file="/usr/include/host-secret.h" line="1" column="1"/></error><error id="zerodiv" severity="error" msg="Division by zero."><location file="a.c" line="1" column="1"/><location file="/usr/include/host-secret.h" line="3" column="1" info="host-secret.h:3"/></error>',
      ),
      '',
    );
    expect(JSON.stringify(out)).not.toContain('host-secret');
    expect((out as { runs: { results: unknown[] }[] }).runs[0]!.results).toHaveLength(1);
    expect(lines.join('')).toContain(
      'cppcheck: 2 result(s) or note(s) located outside the repository were dropped',
    );
    expect(lines.join('')).not.toContain('host-secret');
  });

  it('turns a skip into a failure under enabled: true, without marking the engine unavailable', async () => {
    const root = tmp();
    writeTree(root, { 'a.c': 'int a;\n' });
    const [capture] = await runAnalyzers([cppcheckAnalyzer], {
      root,
      config: parseConfig({
        version: 1,
        analyzers: { cppcheck: { enabled: true, compileCommands: 'no.json' } },
      }),
      files: [scope(root, 'a.c')],
      log: silentLogger,
      env: {},
    });
    expect(capture).toMatchObject({
      status: 'failed',
      reason: 'compileCommands no.json does not exist',
    });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it('reads the version cppcheck prints', () => {
    expect(parseCppcheckVersion('Cppcheck 2.22.0\n')).toBe('2.22.0');
    expect(parseCppcheckVersion('Cppcheck 2.18\n')).toBe('2.18');
    expect(parseCppcheckVersion('Cppcheck Premium 25.1.0\n')).toBeNull();
    expect(parseCppcheckVersion('')).toBeNull();
  });

  it('is a configuration error for a compileCommands URL or a path outside the repository (ruling F3)', () => {
    const cfg = (compileCommands: string) =>
      parseConfig({ version: 1, analyzers: { cppcheck: { compileCommands } } });
    expect(cppcheckAnalyzer.checkConfig!('/r', cfg('https://x/cc.json'))).toMatch(/is a URL/);
    expect(cppcheckAnalyzer.checkConfig!('/r', cfg('../cc.json'))).toMatch(
      /outside the repository/,
    );
    expect(cppcheckAnalyzer.checkConfig!('/r', cfg('build/cc.json'))).toBeNull();
  });
});
