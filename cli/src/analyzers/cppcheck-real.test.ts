import { existsSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
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

  it(
    'does not split a database file path with spaces into options: no injected -I or -D (ruling D9-18)',
    TIMEOUT,
    async () => {
      const root = tmp();
      const zerodiv = (name: string) => `static int ${name}(void) { int z = 0; return 1 / z; }\n`;
      const entry = (file: string, ...flags: string[]) => ({
        directory: '.',
        file,
        arguments: ['cc', ...flags, '-c', file],
      });
      const files: Record<string, string> = {
        // Split on blanks, `<copy>/a -Iinc /b.c` would carry -Iinc, and `a -DX /d.c` -DX.
        'a -Iinc /b.c': '#include "inj.h"\nint b(void) { return leak(); }\n',
        'inc/inj.h': zerodiv('leak'),
        'a -DX /d.c': '#ifdef X\nint d(void) { int z = 0; return 1 / z; }\n#endif\n',
        // Controls: the same through real options, so the probes above can fail.
        'ctl.c': '#include "y.h"\nint c(void) { return leak2(); }\n',
        'ctl/y.h': zerodiv('leak2'),
        'defx.c': '#ifdef X\nint e(void) { int z = 0; return 1 / z; }\n#endif\n',
      };
      const db = [
        entry('a -Iinc /b.c'),
        entry('a -DX /d.c'),
        entry('ctl.c', '-Ictl'),
        entry('defx.c', '-DX'),
      ];
      // The literal `a -I` / `etc ` layout reaches a host header in /etc, where the test may write.
      const host = `/etc/qualor-9d-probe-${process.pid}.h`;
      let hostProbe = false;
      try {
        writeFileSync(host, zerodiv('hostLeak'));
        hostProbe = true;
        files['a -I/etc /e.c'] =
          `#include "${path.basename(host)}"\nint h(void) { return hostLeak(); }\n`;
        db.push(entry('a -I/etc /e.c'));
      } catch {
        // not root: the relative probe above covers the same parsing
      }
      try {
        writeTree(root, { ...files, 'compile_commands.json': JSON.stringify(db) });
        const lines: string[] = [];
        const { capture } = await scanRepoWith(
          cppcheckAnalyzer,
          root,
          process.env,
          createLogger('debug', (t) => lines.push(t)),
        );
        expect(capture.status, capture.reason ?? '').toBe('ok');
        expect(results(capture.sarif).map(key).sort()).toEqual([
          'ctl/y.h:1 zerodiv',
          'defx.c:2 zerodiv',
        ]);
        if (hostProbe) expect(lines.join('')).not.toMatch(/located outside the repository/);
      } finally {
        if (hostProbe) rmSync(host, { force: true });
      }
    },
  );
});

describeWithCppcheck()('cppcheck addons with the real binary (issue #33)', () => {
  const VIOLATIONS =
    'int f(int x) { goto end; end: return (x + 1); }\nvoid h(void) { int a = 3; { int a = 4; (void)a; } (void)a; }\n';
  type Addon = 'misra' | 'misc' | 'threadsafety' | 'y2038';
  const settings = (addons: Addon[], misraRuleTexts?: string) => ({
    analyzers: { cppcheck: { addons, ...(misraRuleTexts !== undefined && { misraRuleTexts }) } },
  });
  const scan = async (root: string, s: ReturnType<typeof settings>) => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    const r = await scanRepoWith(cppcheckAnalyzer, root, process.env, log, s);
    expect(r.capture.status, r.capture.reason ?? '').toBe('ok');
    return { ...r, keys: results(r.capture.sarif).map(key), log: lines.join('\n') };
  };

  it(
    'reports MISRA rules with the default groups, without cppcheck style results',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, { 'src/a.c': VIOLATIONS });
      const { keys, out, log } = await scan(root, settings(['misra']));
      expect(keys).toContain('src/a.c:1 misra-c2012-15.1');
      expect(keys.filter((k) => k.includes('shadowVariable'))).toEqual([]);
      expect(findingKeys(out.findings)).toContain('cppcheck:misra-c2012-15.1 src/a.c:1 [low]');
      expect(log).not.toContain('addon failed');
    },
  );

  it('keeps cppcheck style results when the project enabled style', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, { 'src/a.c': VIOLATIONS });
    const s = {
      analyzers: { cppcheck: { addons: ['misra' as const], enable: ['style' as const] } },
    };
    const { keys } = await scan(root, s);
    expect(keys).toContain('src/a.c:1 misra-c2012-15.1');
    expect(keys.filter((k) => k.includes('shadowVariable'))).toHaveLength(1);
  });

  it('puts the rule text of a repository file in the message', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, {
      'src/a.c': VIOLATIONS,
      'misra/rules.txt':
        'Appendix A Summary of guidelines\nRule 15.1 Advisory\nThe goto statement should not be used\n',
    });
    const { capture } = await scan(root, settings(['misra'], 'misra/rules.txt'));
    const goto15 = results(capture.sarif).find((r) => r.ruleId === 'misra-c2012-15.1');
    expect(goto15?.message?.text).toBe('The goto statement should not be used');
  });

  it('names the rule when there are no rule texts', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, { 'src/a.c': VIOLATIONS });
    const { capture } = await scan(root, settings(['misra']));
    const goto15 = results(capture.sarif).find((r) => r.ruleId === 'misra-c2012-15.1');
    expect(goto15?.message?.text).toContain('MISRA C 2012 rule 15.1');
  });

  it.runIf(process.platform !== 'win32')(
    'runs no command a file name spells',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      const m1 = path.join(outside, 'M1');
      const m2 = path.join(outside, 'M2');
      writeTree(root, {
        'src/a.c': VIOLATIONS,
        [`src/$(touch ${m1}).c`]: VIOLATIONS,
        [`src/\`touch ${m2}\`.c`]: VIOLATIONS,
      });
      const { keys, log } = await scan(root, settings(['misra']));
      expect(keys).toContain('src/a.c:1 misra-c2012-15.1');
      expect(existsSync(m1)).toBe(false);
      expect(existsSync(m2)).toBe(false);
      expect(log).toContain('2 C/C++ file(s) left out');
    },
  );

  it('analyses a path with a space', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, { 'src dir/a b.c': VIOLATIONS });
    const { keys, log } = await scan(root, settings(['misra']));
    expect(keys).toContain('src dir/a b.c:1 misra-c2012-15.1');
    expect(log).not.toContain('addon failed');
  });

  it('runs through the rewritten compile database', TIMEOUT, async () => {
    const root = tmp();
    writeTree(root, {
      'src/a.c': VIOLATIONS,
      'compile_commands.json': JSON.stringify([
        { directory: '.', file: 'src/a.c', arguments: ['cc', '-c', 'src/a.c'] },
      ]),
    });
    const { keys } = await scan(root, settings(['misra']));
    expect(keys).toContain('src/a.c:1 misra-c2012-15.1');
  });

  it.each<Addon>(['misc', 'threadsafety', 'y2038'])(
    'runs %s to its end',
    TIMEOUT,
    async (addon) => {
      const root = tmp();
      writeTree(root, { 'src/a.c': VIOLATIONS });
      const { log } = await scan(root, settings([addon]));
      expect(log).not.toContain('addon failed');
      expect(log).not.toContain('internalError');
    },
  );

  it('warns when an addon fails on a rule-texts file it cannot decode', TIMEOUT, async () => {
    const root = tmp();
    // 0x81 is undefined in windows-1252, the last encoding the addon tries.
    writeTree(root, { 'src/a.c': VIOLATIONS });
    writeFileSync(path.join(root, 'rules.txt'), Buffer.from([0x81, 0x8d, 0x8f, 0x90, 0x9d, 0xff]));
    const { log } = await scan(root, settings(['misra'], 'rules.txt'));
    expect(log).toContain('addon failed');
  });
});
