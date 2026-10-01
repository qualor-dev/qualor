import { existsSync, mkdirSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import {
  checkCompileCommandsSetting,
  findCompileCommands,
  MAX_COMPILE_COMMANDS_BYTES,
  readCompileCommands,
  sanitizeArguments,
  splitCommand,
} from './compile-commands';

const tmp = useTempDirs();

function scopeOf(root: string, paths: string[]): Map<string, ScopeFile> {
  return new Map(
    paths.map((p) => [
      p,
      {
        path: p,
        absPath: path.join(root, p),
        language: p.endsWith('.c') ? 'c' : 'cpp',
        grammar: p.endsWith('.c') ? 'c' : 'cpp',
        kind: 'main',
        size: 10,
      } as ScopeFile,
    ]),
  );
}

describe('splitCommand (POSIX shell words, no expansion)', () => {
  it('splits on blanks and honours quotes and backslashes, expanding nothing', () => {
    expect(splitCommand(`g++ -DNAME="a b" -I'dir with space' -DX=\\"q\\" src/a.cpp`)).toEqual([
      'g++',
      '-DNAME=a b',
      '-Idir with space',
      '-DX="q"',
      'src/a.cpp',
    ]);
    expect(splitCommand('cc  $HOME/x `id` $(id) -c a.c')).toEqual([
      'cc',
      '$HOME/x',
      '`id`',
      '$(id)',
      '-c',
      'a.c',
    ]);
  });
});

describe('sanitizeArguments (config.md §6.2)', () => {
  it('keeps includes, defines, the standard and the allowlisted flags', () => {
    const r = sanitizeArguments([
      '/usr/bin/g++',
      '-std=c++17',
      '-I',
      'include',
      '-Isrc',
      '-isystem',
      '/opt/x/include',
      '-DA=1',
      '-D',
      'B',
      '-UC',
      '-fno-exceptions',
      '-fPIC',
      '-Wall',
      '-Wno-unused',
      '-m64',
      '-march=x86-64',
      '-pthread',
      '--target=x86_64-linux-gnu',
      '-x',
      'c++',
      '-include',
      'pre.h',
      '-c',
      'src/a.cpp',
      '-o',
      'a.o',
    ]);
    expect(r.compiler).toBe('g++');
    expect(r.kept).toEqual([
      '-std=c++17',
      '-I',
      'include',
      '-Isrc',
      '-isystem',
      '/opt/x/include',
      '-DA=1',
      '-D',
      'B',
      '-UC',
      '-fno-exceptions',
      '-fPIC',
      '-Wall',
      '-Wno-unused',
      '-m64',
      '-march=x86-64',
      '-pthread',
      '--target=x86_64-linux-gnu',
      '-x',
      'c++',
      '-include',
      'pre.h',
    ]);
    expect(r.dropped).toBe(0);
  });

  it('drops every plugin, response file, pass-through and output option with its value (Review Focus 1)', () => {
    const r = sanitizeArguments([
      'ccache',
      'clang++',
      '-fplugin=./evil.so',
      '-fpass-plugin=./evil.so',
      '-Xclang',
      '-load',
      '-Xclang',
      './evil.so',
      '-mllvm',
      '-load=./evil.so',
      '@args.rsp',
      '-Xpreprocessor',
      '-x',
      '--config-file=x',
      '-Werror',
      '-Werror=format',
      '-fsanitize=address',
      '-O2',
      '-g',
      '-MD',
      '-MF',
      'a.d',
      '-o',
      'a.o',
      '-c',
      '/Iinc',
      '-Wl,-rpath,/x',
      '-Wp,-include,/etc/passwd',
      '-resource-dir',
      '/x',
      'src/a.cpp',
    ]);
    expect(r.compiler).toBe('clang++');
    expect(r.kept).toEqual([]);
    expect(r.dropped).toBe(15);
  });

  it('replaces a compiler that is no plain name, and removes a launcher', () => {
    expect(sanitizeArguments(['/x/my compiler', '-c', 'a.cpp']).compiler).toBe('c++');
    expect(sanitizeArguments(['sccache', '/usr/bin/cc', 'a.c']).compiler).toBe('cc');
    expect(sanitizeArguments(['x86_64-linux-gnu-g++-12', 'a.cpp']).compiler).toBe(
      'x86_64-linux-gnu-g++-12',
    );
  });
});

describe('findCompileCommands and checkCompileCommandsSetting', () => {
  it('looks at the root, then build/, unless set to false or to a file', () => {
    const root = tmp();
    expect(findCompileCommands(root, null)).toEqual({
      none: 'no compile_commands.json at the repository root or in build/',
    });
    writeTree(root, { 'build/compile_commands.json': '[]' });
    expect(findCompileCommands(root, null)).toEqual({ rel: 'build/compile_commands.json' });
    writeTree(root, { 'compile_commands.json': '[]' });
    expect(findCompileCommands(root, null)).toEqual({ rel: 'compile_commands.json' });
    expect(findCompileCommands(root, false)).toEqual({ none: 'compileCommands is false' });
    expect(findCompileCommands(root, 'out/cc.json')).toEqual({
      skip: 'compileCommands out/cc.json does not exist',
    });
  });

  it('is a configuration error only for a URL or a path outside the repository as written (ruling F3)', () => {
    expect(checkCompileCommandsSetting('https://x/cc.json', 'analyzers.cppcheck')).toBe(
      'analyzers.cppcheck.compileCommands https://x/cc.json is a URL (only repository files)',
    );
    expect(checkCompileCommandsSetting('../cc.json', 'analyzers.cppcheck')).toBe(
      'analyzers.cppcheck.compileCommands ../cc.json is outside the repository',
    );
    expect(checkCompileCommandsSetting('/abs/cc.json', 'analyzers.clang-tidy')).toMatch(
      /outside the repository/,
    );
    for (const ok of [null, false, 'build/compile_commands.json'] as const)
      expect(checkCompileCommandsSetting(ok, 'x')).toBeNull();
  });
});

describe('readCompileCommands (config.md §6.2)', () => {
  it('keeps in-scope files only, resolves relative directories against the file, first entry wins', () => {
    const root = tmp();
    writeTree(root, {
      'src/a.cpp': 'int a;\n',
      'src/b.c': 'int b;\n',
      'third_party/z.cpp': 'int z;\n',
      'build/compile_commands.json': JSON.stringify([
        {
          directory: '..',
          file: 'src/a.cpp',
          arguments: ['g++', '-Iinclude', '-fplugin=x.so', '-c', 'src/a.cpp'],
        },
        { directory: '..', file: 'src/a.cpp', arguments: ['g++', '-DSECOND', '-c', 'src/a.cpp'] },
        { directory: path.join(root, 'src'), file: 'b.c', command: 'cc -DB=1 -c b.c' },
        {
          directory: '..',
          file: 'third_party/z.cpp',
          arguments: ['g++', '-c', 'third_party/z.cpp'],
        },
        {
          directory: '/elsewhere',
          file: '/elsewhere/q.cpp',
          arguments: ['g++', '-c', '/elsewhere/q.cpp'],
        },
      ]),
    });
    const r = readCompileCommands(
      root,
      'build/compile_commands.json',
      scopeOf(root, ['src/a.cpp', 'src/b.c']),
    );
    if ('skip' in r) throw new Error(r.skip);
    expect(r.entries.map((e) => [e.repoPath, e.directory, e.file, e.compiler, e.args])).toEqual([
      ['src/a.cpp', root, path.join(root, 'src/a.cpp'), 'g++', ['-Iinclude']],
      ['src/b.c', path.join(root, 'src'), path.join(root, 'src/b.c'), 'cc', ['-DB=1']],
    ]);
    expect(r.droppedArgs).toBe(1);
    expect(r.ignoredEntries).toBe(3);
  });

  it('skips what it cannot read: bad JSON, not an array, a bad entry, too large, a link out', () => {
    const root = tmp();
    const scope = scopeOf(root, []);
    const write = (s: string) => writeFileSync(path.join(root, 'compile_commands.json'), s);
    write('{');
    expect(readCompileCommands(root, 'compile_commands.json', scope)).toEqual({
      skip: 'compile_commands.json is not valid JSON',
    });
    write('{}');
    expect(readCompileCommands(root, 'compile_commands.json', scope)).toEqual({
      skip: 'compile_commands.json is not a JSON array of entries',
    });
    write('[{"file": "a.c"}]');
    expect(readCompileCommands(root, 'compile_commands.json', scope)).toEqual({
      skip: 'compile_commands.json: entry 1 needs "directory", "file", and "arguments" or "command"',
    });
    write(`[${' '.repeat(MAX_COMPILE_COMMANDS_BYTES)}]`);
    expect(readCompileCommands(root, 'compile_commands.json', scope)).toEqual({
      skip: 'compile_commands.json is larger than 64 MiB',
    });
  });

  it.runIf(process.platform !== 'win32')(
    'never takes a file entry that is a symbolic link, nor a database that links out',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'o.cpp'), 'int o;\n');
      writeTree(root, { 'src/a.cpp': 'int a;\n' });
      symlinkSync(path.join(outside, 'o.cpp'), path.join(root, 'src/l.cpp'));
      writeFileSync(
        path.join(root, 'compile_commands.json'),
        JSON.stringify([
          { directory: root, file: 'src/l.cpp', arguments: ['g++', '-c', 'src/l.cpp'] },
        ]),
      );
      const r = readCompileCommands(
        root,
        'compile_commands.json',
        scopeOf(root, ['src/a.cpp', 'src/l.cpp']),
      );
      expect(r).toMatchObject({ entries: [], ignoredEntries: 1 });
      mkdirSync(path.join(root, 'build'));
      writeFileSync(path.join(outside, 'cc.json'), '[]');
      symlinkSync(path.join(outside, 'cc.json'), path.join(root, 'build/compile_commands.json'));
      expect(readCompileCommands(root, 'build/compile_commands.json', scopeOf(root, []))).toEqual({
        skip: 'build/compile_commands.json is outside the repository',
      });
    },
  );
});

describe('nothing from the database is ever run (Review Focus 1)', () => {
  it('reads a database full of commands that would plant markers, and no marker appears', () => {
    const root = tmp();
    const marker = path.join(root, 'MARKER');
    const m = marker.replaceAll('\\', '/');
    writeTree(root, {
      'src/a.cpp': 'int a;\n',
      'src/b.cpp': 'int b;\n',
      'evil.rsp': `-Xclang -load -Xclang ./evil.so\n`,
      'compile_commands.json': JSON.stringify([
        {
          directory: root,
          file: 'src/a.cpp',
          command: `sh -c "touch ${m}" $(touch ${m}) \`touch ${m}\` ; touch ${m} && -c src/a.cpp`,
        },
        {
          directory: root,
          file: 'src/b.cpp',
          arguments: [
            'ccache',
            `/bin/sh -c 'touch ${m}'`,
            '-fplugin=./evil.so',
            '@evil.rsp',
            `-DX=$(touch ${m})`,
            '-c',
            'src/b.cpp',
          ],
        },
      ]),
    });
    const before = readdirSync(root).sort();
    const r = readCompileCommands(
      root,
      'compile_commands.json',
      scopeOf(root, ['src/a.cpp', 'src/b.cpp']),
    );
    if ('skip' in r) throw new Error(r.skip);
    expect(existsSync(marker)).toBe(false);
    expect(readdirSync(root).sort()).toEqual(before);
    expect(r.entries.map((e) => e.compiler)).toEqual(['sh', 'c++']);
    expect(r.entries[0]!.args).toEqual([]);
    // the define's value is text for the preprocessor, never expanded by a shell
    expect(r.entries[1]!.args).toEqual([`-DX=$(touch ${m})`]);
  });

  it('drops a separate value that clang would read as a response file or an option', () => {
    const r = sanitizeArguments([
      'clang++',
      '-I',
      '@evil.rsp',
      '-include',
      '-fplugin=x.so',
      '-x',
      '@y',
      '-D',
      'OK',
      '-c',
      'a.cpp',
    ]);
    expect(r.kept).toEqual(['-D', 'OK']);
    expect(r.dropped).toBe(3);
  });

  it('drops an argument that carries a line break or a NUL (a response file line cannot hold it)', () => {
    const r = sanitizeArguments([
      'cc',
      '-DA=1\n-fplugin=x.so',
      '-I',
      'in\nc',
      '-DB=\u0000',
      '-DC',
      'a.c',
    ]);
    expect(r.kept).toEqual(['-DC']);
    expect(r.dropped).toBe(3);
  });

  it('a value option at the end, with no value, is dropped', () => {
    expect(sanitizeArguments(['cc', '-DA', '-I'])).toEqual({
      compiler: 'cc',
      kept: ['-DA'],
      dropped: 1,
    });
  });
});

describe('readCompileCommands keeps no file reached through a link', () => {
  it.runIf(process.platform !== 'win32')(
    'ignores an entry whose directory on the way is a link out',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'o.cpp'), 'int o;\n');
      symlinkSync(outside, path.join(root, 'lnk'));
      writeFileSync(
        path.join(root, 'compile_commands.json'),
        JSON.stringify([
          { directory: root, file: 'lnk/o.cpp', arguments: ['g++', '-c', 'lnk/o.cpp'] },
        ]),
      );
      // even if a scope wrongly listed it, the resolved file is outside the repository
      expect(
        readCompileCommands(root, 'compile_commands.json', scopeOf(root, ['lnk/o.cpp'])),
      ).toMatchObject({
        entries: [],
        ignoredEntries: 1,
      });
    },
  );
});

describe('cfamily-common', () => {
  it('keeps only the allowlisted environment, and the variables Qualor sets', async () => {
    const { cFamilyDropEnv, cFamilyEnv, hasLineBreak, C_LANGUAGES } =
      await import('./cfamily-common');
    const own = cFamilyEnv('/work');
    expect(own).toMatchObject({ HOME: '/work', LC_ALL: 'C.UTF-8' });
    const drop = cFamilyDropEnv(own);
    for (const n of [
      'CCC_OVERRIDE_OPTIONS',
      'CPATH',
      'CPLUS_INCLUDE_PATH',
      'GITHUB_TOKEN',
      'LD_PRELOAD',
    ])
      expect(drop(n)).toBe(true);
    for (const n of ['PATH', 'Path', 'TMPDIR', 'SystemRoot', 'HOME', 'LC_ALL'])
      expect(drop(n)).toBe(false);
    expect(hasLineBreak('a\nb')).toBe(true);
    expect(hasLineBreak('a b')).toBe(true);
    expect(hasLineBreak('a b#%é')).toBe(false);
    expect([...C_LANGUAGES]).toEqual(['c', 'cpp']);
  });
});
