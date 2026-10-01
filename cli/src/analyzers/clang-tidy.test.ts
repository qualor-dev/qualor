import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  CLANG_TIDY_DEFAULT_CHECKS,
  CLANG_TIDY_MIN_MAJOR,
  type QualorConfigInput,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { cFamilyContext } from '../../test/analyzers';
import { useTempDirs } from '../../test/tmp';
import { clangTidyAnalyzer, headerFilter, parseClangTidyVersion } from './clang-tidy';
import type { AnalyzerCommand, AnalyzerContext } from './types';

const tmp = useTempDirs();
const BIN = '/usr/bin/clang-tidy';
const VERSION_TEXT = (v: string) =>
  `LLVM (http://llvm.org/):\n  LLVM version ${v}\n  Optimized build.\n`;

// Task 8's shared helper; every source here is a .cpp file, so its scope is C++.
const context = (
  files: Record<string, string>,
  {
    version = '22.1.8',
    ...o
  }: {
    config?: Omit<QualorConfigInput, 'version'>;
    version?: string;
    lines?: string[];
    languages?: Record<string, 'c' | 'cpp'>;
  } = {},
) =>
  cFamilyContext(tmp, files, {
    binaries: { 'clang-tidy': BIN },
    versionStdout: VERSION_TEXT(version),
    ...o,
  });

const DB = (entries: object[]) => JSON.stringify(entries);

async function run(ctx: AnalyzerContext): Promise<AnalyzerCommand> {
  const p = await clangTidyAnalyzer.prepare(ctx);
  if (!('run' in p)) throw new Error(JSON.stringify(p));
  return p.run;
}

describe('clangTidyAnalyzer.prepare (config.md §6.2, plan 9D)', () => {
  it("runs with Qualor's database, configuration and response file, never the checkout's", async () => {
    const { ctx, root, work } = context({
      'src/a.cpp': 'int a;\n',
      '.clang-tidy': "Checks: '-*,bugprone-*'\nExtraArgs: ['-fplugin=./evil.so']\n",
      'compile_commands.json': DB([
        {
          directory: '.',
          file: 'src/a.cpp',
          arguments: [
            'g++',
            '-std=c++17',
            '-fplugin=./evil.so',
            '-Xclang',
            '-load',
            '-c',
            'src/a.cpp',
          ],
        },
      ]),
    });
    const cmd = await run(ctx);
    expect(cmd.command).toBe(BIN);
    expect(cmd.cwd).toBe(work);
    expect(cmd.args).toHaveLength(9);
    expect(cmd.args.slice(0, 5)).toEqual([
      '-p',
      work,
      `--config-file=${path.join(work, 'clang-tidy.json')}`,
      '--quiet',
      '--use-color=false',
    ]);
    // The temp root's real path may differ from the path as written (a symlinked TMPDIR).
    expect(cmd.args[5]).toMatch(/^--header-filter=\^\(.+\|.+\)\/$/);
    // No clang configuration file (clang 16+: <driver>.cfg beside the binary or in the system's
    // directories) changes the compile arguments Qualor allowlisted.
    expect(cmd.args.slice(6)).toEqual([
      '--extra-arg=--no-default-config',
      `--export-fixes=${path.join(work, 'clang-tidy-fixes.yaml')}`,
      `@${path.join(work, 'clang-tidy-files.rsp')}`,
    ]);
    expect(cmd.args.some((a) => a.startsWith('--load') || a === '--fix')).toBe(false);
    // argv[0] is named by the file's language (Task 7, ruling D9-9's review), never the database's.
    expect(JSON.parse(readFileSync(path.join(work, 'compile_commands.json'), 'utf8'))).toEqual([
      {
        directory: root,
        file: path.join(root, 'src/a.cpp'),
        arguments: ['c++', '-std=c++17', '-c', path.join(root, 'src/a.cpp')],
      },
    ]);
    expect(JSON.parse(readFileSync(path.join(work, 'clang-tidy.json'), 'utf8'))).toEqual({
      Checks: '-*,bugprone-*',
    });
    expect(readFileSync(path.join(work, 'clang-tidy-files.rsp'), 'utf8')).toBe(
      `"${path.join(root, 'src/a.cpp').replaceAll('\\', '\\\\')}"\n`,
    );
    expect(readFileSync(path.join(work, 'clang-tidy-fixes.yaml'), 'utf8')).toBe('');
    expect(cmd.outputFormat).toBe('text');
    expect(cmd.okExitCodes).toEqual([0, 1]);
    expect(cmd.version).toBe('22.1.8');
  });

  it('names the compiler cc for C and c++ for C++, whatever the database says', async () => {
    const { ctx, root, work } = context(
      {
        'a.c': 'int a;\n',
        'b.cpp': 'int b;\n',
        'compile_commands.json': DB([
          { directory: '.', file: 'a.c', arguments: ['clang++', '-c', 'a.c'] },
          {
            directory: '.',
            file: 'b.cpp',
            arguments: ['/opt/evil/x86_64-linux-gnu-gcc-12', '-c', 'b.cpp'],
          },
        ]),
      },
      { languages: { 'a.c': 'c' } },
    );
    await run(ctx);
    const written = JSON.parse(readFileSync(path.join(work, 'compile_commands.json'), 'utf8')) as {
      arguments: string[];
    }[];
    expect(written.map((e) => e.arguments)).toEqual([
      ['cc', '-c', path.join(root, 'a.c')],
      ['c++', '-c', path.join(root, 'b.cpp')],
    ]);
  });

  it('passes --no-default-config only to a clang-tidy that knows it (16 and newer)', async () => {
    const files = {
      'a.cpp': 'int a;\n',
      'compile_commands.json': DB([{ directory: '.', file: 'a.cpp', command: 'c++ -c a.cpp' }]),
    };
    expect((await run(context(files, { version: '15.0.7' }).ctx)).args).not.toContain(
      '--extra-arg=--no-default-config',
    );
    expect((await run(context(files, { version: '16.0.0' }).ctx)).args).toContain(
      '--extra-arg=--no-default-config',
    );
  });

  it("uses Qualor's default checks without a .clang-tidy", async () => {
    const { ctx, work } = context({
      'a.cpp': 'int a;\n',
      'build/compile_commands.json': DB([
        { directory: '..', file: 'a.cpp', command: 'c++ -c a.cpp' },
      ]),
    });
    await run(ctx);
    expect(JSON.parse(readFileSync(path.join(work, 'clang-tidy.json'), 'utf8'))).toEqual({
      Checks: CLANG_TIDY_DEFAULT_CHECKS,
    });
  });

  it('is skipped without a compile database, without clang-tidy, or with one older than 14', async () => {
    expect(await clangTidyAnalyzer.prepare(context({ 'a.cpp': 'int a;\n' }).ctx)).toEqual({
      skip: "no compile database (no compile_commands.json at the repository root or in build/); clang-tidy needs the project's compile_commands.json (config.md §6.2)",
    });
    const withDb = {
      'a.cpp': 'int a;\n',
      'compile_commands.json': DB([{ directory: '.', file: 'a.cpp', command: 'c++ -c a.cpp' }]),
    };
    const none = context(withDb).ctx;
    expect(
      await clangTidyAnalyzer.prepare({
        ...none,
        resolveBinary: () => null,
        repoBinary: () => null,
      }),
    ).toEqual({
      skip: 'clang-tidy is not installed (no clang-tidy on PATH; no Qualor image bundles it, config.md §6.2)',
    });
    expect(
      await clangTidyAnalyzer.prepare({
        ...none,
        resolveBinary: () => null,
        repoBinary: () => '/repo/bin/clang-tidy',
      }),
    ).toEqual({
      skip: "clang-tidy is not installed (no clang-tidy on PATH; no Qualor image bundles it, config.md §6.2); the repository's own clang-tidy is never run",
    });
    const old = `${CLANG_TIDY_MIN_MAJOR - 1}.0.1`;
    expect(await clangTidyAnalyzer.prepare(context(withDb, { version: old }).ctx)).toEqual({
      skip: `clang-tidy ${old} is too old: Qualor runs clang-tidy ${CLANG_TIDY_MIN_MAJOR} or newer`,
    });
    expect(await clangTidyAnalyzer.prepare(context(withDb, { version: 'garbage' }).ctx)).toEqual({
      unavailable: '`clang-tidy --version` printed no version',
    });
  });

  it('skips a database without a file of the scan, and logs the arguments it dropped', async () => {
    const lines: string[] = [];
    expect(
      await clangTidyAnalyzer.prepare(
        context({ 'a.cpp': 'int a;\n', 'compile_commands.json': DB([]) }).ctx,
      ),
    ).toEqual({
      skip: 'compile_commands.json names no C or C++ file of the scan',
    });
    const { ctx } = context(
      {
        'a.cpp': 'int a;\n',
        'compile_commands.json': DB([
          {
            directory: '.',
            file: 'a.cpp',
            arguments: ['c++', '-fplugin=x.so', '@r.rsp', '-c', 'a.cpp'],
          },
        ]),
      },
      { lines },
    );
    await run(ctx);
    expect(lines.join('')).toContain(
      'clang-tidy: compile_commands.json: 2 compiler argument(s) left out (config.md §6.2)',
    );
  });

  it('logs compile errors and dropped outside diagnostics from the transform, and the first Error: line', async () => {
    const lines: string[] = [];
    const { ctx } = context(
      {
        'a.cpp': 'int a;\n',
        'compile_commands.json': DB([{ directory: '.', file: 'a.cpp', command: 'c++ -c a.cpp' }]),
      },
      { lines },
    );
    const cmd = await run(ctx);
    cmd.transform!(
      [
        '---',
        'Diagnostics:',
        '  - DiagnosticName: clang-diagnostic-error',
        '    DiagnosticMessage: {Message: x, FilePath: a.cpp, FileOffset: 0}',
        '    Level: Error',
        "    BuildDirectory: '/nowhere'",
        '  - DiagnosticName: bugprone-x',
        "    DiagnosticMessage: {Message: x, FilePath: '/usr/include/host-secret.h', FileOffset: 0}",
        '    Level: Warning',
        "    BuildDirectory: '/nowhere'",
        '',
      ].join('\n'),
      '',
    );
    const text = lines.join('\n');
    expect(text).toContain(
      'warn: clang-tidy: 1 compile error(s): clang-tidy could not compile every translation unit (a missing header or flag); those diagnostics are not issues',
    );
    expect(text).toContain(
      'warn: clang-tidy: 1 diagnostic(s) could not be placed on a file of the scan',
    );
    expect(text).not.toContain('host-secret');
    expect(
      cmd.configWarnings!('Error while processing /x/a.cpp.\nError: no checks enabled.\n'),
    ).toEqual(['Error: no checks enabled.']);
  });

  it('runs without the static analyzer options that name files, keeping the others, with one warn line of key names (ruling D9-11)', async () => {
    const lines: string[] = [];
    const { ctx, work } = context(
      {
        'a.cpp': 'int a;\n',
        '.clang-tidy': [
          "Checks: '-*,clang-analyzer-*'",
          'CheckOptions:',
          '  clang-analyzer-ctu-invocation-list: /etc/secret.yml',
          '  clang-analyzer-alpha.security.taint.TaintPropagation:Config: /etc/taint.yml',
          '  clang-analyzer-unix.DynamicMemoryModeling:Optimistic: true',
          '  bugprone-argument-comment.StrictMode: 1',
          '',
        ].join('\n'),
        'compile_commands.json': DB([{ directory: '.', file: 'a.cpp', command: 'c++ -c a.cpp' }]),
      },
      { lines },
    );
    await run(ctx);
    expect(JSON.parse(readFileSync(path.join(work, 'clang-tidy.json'), 'utf8'))).toEqual({
      Checks: '-*,clang-analyzer-*',
      CheckOptions: {
        'clang-analyzer-unix.DynamicMemoryModeling:Optimistic': 'true',
        'bugprone-argument-comment.StrictMode': '1',
      },
    });
    const text = lines.join('\n');
    expect(text).toContain(
      'warn: clang-tidy: .clang-tidy: left out CheckOptions clang-analyzer-ctu-invocation-list (a global static analyzer setting), clang-analyzer-alpha.security.taint.TaintPropagation:Config (a static analyzer option that names a file) (config.md §6.2)',
    );
    expect(text).not.toContain('/etc/');
  });

  it('keeps only an allowlist of variables', async () => {
    const { ctx } = context({
      'a.cpp': 'int a;\n',
      'compile_commands.json': DB([{ directory: '.', file: 'a.cpp', command: 'c++ -c a.cpp' }]),
    });
    const cmd = await run(ctx);
    for (const n of [
      'CCC_OVERRIDE_OPTIONS',
      'CPATH',
      'CPLUS_INCLUDE_PATH',
      'GITHUB_TOKEN',
      'CLANG_CONFIG_FILE',
    ])
      expect(cmd.dropEnv!(n), n).toBe(true);
    expect(cmd.dropEnv!('PATH')).toBe(false);
  });

  it('reads the versions clang-tidy prints', () => {
    expect(parseClangTidyVersion(VERSION_TEXT('22.1.8'))).toBe('22.1.8');
    expect(parseClangTidyVersion('Debian LLVM version 14.0.6\n  Optimized build.\n')).toBe(
      '14.0.6',
    );
    expect(parseClangTidyVersion('clang-tidy\n')).toBeNull();
  });

  it('escapes the repository root for the header filter', () => {
    expect(headerFilter('/r/a.b+c', '/real/x')).toBe('^(/r/a\\.b\\+c|/real/x)/');
  });
});
