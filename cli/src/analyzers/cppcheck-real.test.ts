import { existsSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';
import {
  describeWithCppcheck,
  findingKeys,
  resultKey as key,
  sarifResults as results,
  scanRepoWith,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createLogger } from '../log';
import { cppcheckAnalyzer } from './cppcheck';

const tmp = useTempDirs();
const TIMEOUT = { timeout: 600_000 };
const analyse = async (root: string) => (await scanRepoWith(cppcheckAnalyzer, root)).capture;

describeWithCppcheck()('cppcheck with the real binary (plan 9D)', () => {
  it('reports exactly fact F12 on fixtures/c-basic', TIMEOUT, async () => {
    const capture = await analyse(path.resolve('fixtures/c-basic'));
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(results(capture.sarif).map(key).sort()).toEqual([
      'src/main.c:18 memleak',
      'src/main.c:21 memleak',
      'src/main.c:9 zerodiv',
      'src/stack.c:17 arrayIndexOutOfBounds',
      'src/stack.c:23 nullPointerOutOfMemory',
    ]);
  });

  it(
    'reports fact F12 on fixtures/cpp-basic through its rewritten compile database',
    TIMEOUT,
    async () => {
      const capture = await analyse(path.resolve('fixtures/cpp-basic'));
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(results(capture.sarif).map(key).sort()).toEqual([
        'src/shape.cpp:29 mismatchAllocDealloc',
        'src/shape.cpp:36 zerodiv',
      ]);
    },
  );

  it(
    'runs no addon named by a project file or cppcheck.cfg the checkout plants (cppcheck reads cppcheck.cfg only beside its binary)',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      writeTree(root, {
        'cppcheck.cfg': JSON.stringify({ addons: [path.join(outside, 'evil.py')] }),
        'src/cppcheck.cfg': JSON.stringify({ addons: [path.join(outside, 'evil.py')] }),
        'evil.cppcheck': `<?xml version="1.0"?><project><addons><addon>${path.join(outside, 'evil.py')}</addon></addons></project>`,
        'src/a.c': 'int f(void) { int a[2]; return a[2]; }\n',
      });
      writeFileSync(
        path.join(outside, 'evil.py'),
        `open(${JSON.stringify(path.join(outside, 'MARKER'))}, 'w').write('x')\n`,
      );
      const capture = await analyse(root);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(results(capture.sarif).map(key)).toContain('src/a.c:1 arrayIndexOutOfBounds');
      expect(existsSync(path.join(outside, 'MARKER'))).toBe(false);
    },
  );

  it(
    'drops a finding located in a host header an absolute include reaches, with no trace of its path (F5, ruling D9-9)',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      const secret = path.join(outside, 'host-secret.h').split(path.sep).join('/');
      writeFileSync(secret, 'static int leak(void) { int z = 0; return 1 / z; }\n');
      // An absolute include reaches the header from the checked copy too (a relative one would not:
      // the copy lives in the work directory), so cppcheck really reads the outside file.
      writeTree(root, {
        'src/a.c': `#include "${secret}"\nint f(void) { return leak(); }\nint g(void) { int a[2] = {0, 1}; return a[2]; }\n`,
      });
      const lines: string[] = [];
      const { capture, out } = await scanRepoWith(
        cppcheckAnalyzer,
        root,
        process.env,
        createLogger('debug', (t) => lines.push(t)),
      );
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // cppcheck did report in the outside header (the drop is really exercised) ...
      expect(lines.join('')).toMatch(
        /cppcheck: [1-9]\d* result\(s\) or note\(s\) located outside the repository were dropped/,
      );
      // ... the in-repository finding is kept ...
      expect(results(capture.sarif).map(key)).toEqual(['src/a.c:3 arrayIndexOutOfBounds']);
      expect(findingKeys(out.findings)).toEqual([
        'cppcheck:arrayIndexOutOfBounds src/a.c:3 [high]',
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

  it('analyses awkward names and a thousand files; never a link', TIMEOUT, async () => {
    const root = tmp();
    const outside = tmp();
    const files: Record<string, string> = {
      'src/a b#ü.c': 'int f(void) { int a[2] = {0, 1}; return a[2]; }\n',
      'src/-dash.c': 'int g(void) { return 1 / 0; }\n',
    };
    for (let i = 0; i < 1000; i++) files[`many/f${i}.c`] = `int v${i}(void) { return ${i}; }\n`;
    writeTree(root, files);
    writeFileSync(path.join(outside, 'o.c'), 'int o(void) { return 1 / 0; }\n');
    if (process.platform !== 'win32')
      symlinkSync(path.join(outside, 'o.c'), path.join(root, 'src/l.c'));
    const capture = await analyse(root);
    expect(capture.status, capture.reason ?? '').toBe('ok');
    const keys = results(capture.sarif).map(key).sort();
    expect(keys).toEqual(['src/-dash.c:1 zerodiv', 'src/a b#ü.c:1 arrayIndexOutOfBounds']);
  });
});
