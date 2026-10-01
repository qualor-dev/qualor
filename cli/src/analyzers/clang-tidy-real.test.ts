import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';
import {
  describeWithClangTidy,
  findingKeys,
  resultKey as key,
  sarifResults as results,
  scanRepoWith,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { resolveBinary } from './binary';
import { createLogger } from '../log';
import { clangTidyAnalyzer } from './clang-tidy';

const tmp = useTempDirs();
const TIMEOUT = { timeout: 600_000 };
const analyse = async (root: string) => (await scanRepoWith(clangTidyAnalyzer, root)).capture;
const DIVIDE = 'int f(int a) { int z = 0; if (a > 3) return a / z; return 0; }\n';

/** A shared library whose constructor creates `marker`: a planted plugin (Review Focus 1). */
function plugin(dir: string, marker: string): string {
  const src = path.join(dir, 'p.c');
  writeFileSync(
    src,
    `#include <fcntl.h>\n__attribute__((constructor)) static void f(void) { creat("${marker}", 0644); }\n`,
  );
  const so = path.join(dir, 'evil.so');
  expect(spawnSync('cc', ['-shared', '-fPIC', '-o', so, src]).status).toBe(0);
  return so;
}

describeWithClangTidy()('clang-tidy with the real binary (plan 9D)', () => {
  it("reports fact F12 on fixtures/cpp-basic with Qualor's default checks", TIMEOUT, async () => {
    const capture = await analyse(path.resolve('fixtures/cpp-basic'));
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(results(capture.sarif).map(key).sort()).toEqual([
      'src/shape.cpp:27 bugprone-use-after-move',
      'src/shape.cpp:27 clang-analyzer-cplusplus.Move',
      'src/shape.cpp:29 clang-analyzer-unix.MismatchedDeallocator',
      'src/shape.cpp:36 clang-analyzer-core.DivideZero',
    ]);
  });

  it(
    'never loads a plugin a compile database or .clang-tidy plants; ignores nested and parent configs and WarningsAsErrors',
    TIMEOUT,
    async () => {
      const parent = tmp();
      const root = path.join(parent, 'repo');
      mkdirSync(root);
      const outside = tmp();
      const marker = path.join(outside, 'MARKER');
      const so = plugin(outside, marker);
      // Control: the same clang-tidy does load the plugin from a compile argument, so the marker
      // proves something when it stays absent below.
      const bin = resolveBinary('clang-tidy', { root: process.cwd(), env: process.env });
      expect(bin).not.toBeNull();
      const probe = path.join(outside, 'probe.cpp');
      writeFileSync(probe, 'int x;\n');
      spawnSync(bin!, [
        '--quiet',
        '--checks=-*,clang-analyzer-core.DivideZero',
        probe,
        '--',
        `-fplugin=${so}`,
      ]);
      expect(existsSync(marker), 'control: -fplugin= loads the planted library').toBe(true);
      rmSync(marker);

      // A parent directory's .clang-tidy that would turn every check off if clang-tidy read it.
      writeFileSync(
        path.join(parent, '.clang-tidy'),
        "Checks: '-*,readability-braces-around-statements'\n",
      );
      writeTree(root, {
        '.clang-tidy': `Checks: '-*,clang-analyzer-core.DivideZero'\nExtraArgs: ['-fplugin=${so}']\nExtraArgsBefore: ['-Xclang', '-load', '-Xclang', '${so}']\nWarningsAsErrors: '*'\nInheritParentConfig: true\n`,
        'src/.clang-tidy': "Checks: '-*'\n",
        'src/a.cpp': DIVIDE,
        'compile_commands.json': JSON.stringify([
          {
            directory: '.',
            file: 'src/a.cpp',
            arguments: [
              so,
              `-fplugin=${so}`,
              '-Xclang',
              '-load',
              '-Xclang',
              so,
              `-fpass-plugin=${so}`,
              '-mllvm',
              `-load=${so}`,
              `--config=${path.join(outside, 'x.cfg')}`,
              '-c',
              'src/a.cpp',
            ],
          },
        ]),
      });
      const capture = await analyse(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(results(capture.sarif).map(key)).toEqual([
        'src/a.cpp:1 clang-analyzer-core.DivideZero',
      ]);
      expect(existsSync(marker)).toBe(false);
    },
  );

  it(
    'drops notes and findings in a host header an absolute include reaches, with no trace of its path (ruling D9-9)',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      const secret = path.join(outside, 'host-secret.h').split(path.sep).join('/');
      writeFileSync(
        secret,
        [
          'inline void host_set(int *&p) { p = nullptr; }',
          'inline int host_div(int a) { int z = 0; return a / z; }',
          '',
        ].join('\n'),
      );
      writeTree(root, {
        'src/a.cpp': [
          `#include "${secret}"`,
          'int f() { int x = 1; int *p = &x; host_set(p); return *p; }',
          'int g(int a) { return host_div(a); }',
          'int h(int a) { int z = 0; if (a > 3) return a / z; return 0; }',
          '',
        ].join('\n'),
        'compile_commands.json': JSON.stringify([
          {
            directory: '.',
            file: 'src/a.cpp',
            arguments: ['c++', '-std=c++17', '-c', 'src/a.cpp'],
          },
        ]),
      });
      const lines: string[] = [];
      const { capture, out } = await scanRepoWith(
        clangTidyAnalyzer,
        root,
        process.env,
        createLogger('debug', (t) => lines.push(t)),
      );
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // clang-tidy 22 exports the analyzer's DivideZero inside host_div (in the header, despite
      // --header-filter) and a note of the NullDereference path there: both are dropped, so the
      // drop is really exercised ...
      expect(lines.join('\n')).toContain(
        'clang-tidy: 2 diagnostic(s) could not be placed on a file of the scan',
      );
      // ... the in-repository findings are kept, with their in-repository notes only ...
      const found = results(capture.sarif);
      expect(found.map(key).sort()).toEqual([
        'src/a.cpp:2 clang-analyzer-core.NullDereference',
        'src/a.cpp:4 clang-analyzer-core.DivideZero',
      ]);
      const related = (
        found.find((r) => r.ruleId === 'clang-analyzer-core.NullDereference') as {
          relatedLocations?: { physicalLocation: { artifactLocation: { uri: string } } }[];
        }
      ).relatedLocations;
      // Calling 'host_set', Returning from 'host_set', the dereference; not the store in the header.
      expect(related?.map((l) => l.physicalLocation.artifactLocation.uri)).toEqual([
        'src/a.cpp',
        'src/a.cpp',
        'src/a.cpp',
      ]);
      expect(findingKeys(out.findings)).toEqual([
        'clang-tidy:clang-analyzer-core.DivideZero src/a.cpp:4 [high]',
        'clang-tidy:clang-analyzer-core.NullDereference src/a.cpp:2 [high]',
      ]);
      // ... and nothing about the header reaches the capture, the report or a non-debug log line
      // (the snippet is left out: it quotes the repository's own #include line).
      const shown = [
        JSON.stringify(capture),
        JSON.stringify(out, (k, v: unknown) => (k === 'snippet' ? undefined : v)),
        ...lines.filter((l) => !l.startsWith('debug: ')),
      ].join(' ');
      expect(shown).not.toContain('host-secret');
      expect(shown).not.toContain(outside);
    },
  );

  it(
    'analyses the other units when one does not compile, and counts the error',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'src/bad.cpp': 'int x = ;\n',
        'src/good.cpp': DIVIDE,
        'compile_commands.json': JSON.stringify([
          { directory: '.', file: 'src/bad.cpp', command: 'c++ -c src/bad.cpp' },
          { directory: '.', file: 'src/good.cpp', command: 'c++ -c src/good.cpp' },
        ]),
      });
      const lines: string[] = [];
      const { capture } = await scanRepoWith(
        clangTidyAnalyzer,
        root,
        process.env,
        createLogger('debug', (t) => lines.push(t)),
      );
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(results(capture.sarif).map(key)).toEqual([
        'src/good.cpp:1 clang-analyzer-core.DivideZero',
      ]);
      expect(lines.join('\n')).toContain('clang-tidy: 1 compile error(s)');
    },
  );

  it(
    'places findings in awkward file names, and analyses hundreds of units through the response file',
    TIMEOUT,
    async () => {
      const root = tmp();
      const files: Record<string, string> = { 'src/a b#ü.cpp': DIVIDE };
      const entries: object[] = [
        { directory: '.', file: 'src/a b#ü.cpp', arguments: ['c++', '-c', 'src/a b#ü.cpp'] },
      ];
      for (let i = 0; i < 300; i++) {
        files[`many/f${i}.cpp`] = `int v${i}() { return ${i}; }\n`;
        entries.push({ directory: '.', file: `many/f${i}.cpp`, command: `c++ -c many/f${i}.cpp` });
      }
      // The last unit of the response file has a finding too: every unit was analysed.
      files['many/f299.cpp'] = DIVIDE;
      writeTree(root, { ...files, 'compile_commands.json': JSON.stringify(entries) });
      const capture = await analyse(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(results(capture.sarif).map(key).sort()).toEqual([
        'many/f299.cpp:1 clang-analyzer-core.DivideZero',
        'src/a b#ü.cpp:1 clang-analyzer-core.DivideZero',
      ]);
    },
  );
});
