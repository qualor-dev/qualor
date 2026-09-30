import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { parseConfig, RUFF_DEFAULT_IGNORE, RUFF_VERSION } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { describeWithTools, fakeContext, ROOT, WORK } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles, type ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { Warnings } from '../warnings';
import { fileLines, normalizeCaptures } from './normalize';
import { dropNonRuleResults, isRuffVariable, parseRuffVersion, ruffAnalyzer } from './ruff';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();
const RUFF = path.join(path.dirname(ROOT), 'bin', 'ruff');
const [MAJOR, MINOR] = RUFF_VERSION.split('.').map(Number) as [number, number];
const versionOut = (v: string) => () => ({
  exitCode: 0,
  timedOut: false,
  durationMs: 1,
  stdout: `ruff ${v}\n`,
  stderr: '',
});

/** A real repository root with the given .py files, as discovery would list them. */
function repo(files: string[]): { root: string; scope: ScopeFile[] } {
  const root = tmp();
  const scope = files.map((p) => {
    const abs = path.join(root, p);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, 'import os\n');
    return {
      path: p,
      absPath: abs,
      language: 'python' as const,
      grammar: 'python' as const,
      kind: 'main' as const,
      size: 10,
    };
  });
  return { root, scope };
}

describe('ruffAnalyzer.prepare', () => {
  it('runs ruff check --isolated on an argfile of the in-scope .py files, with qualor-default', async () => {
    const { root, scope } = repo(['app/a.py', 'b c/#d.py']);
    const work = tmp();
    const p = await ruffAnalyzer.prepare({
      ...fakeContext(root, {
        binaries: { ruff: RUFF },
        workDir: work,
        exec: versionOut(RUFF_VERSION),
      }),
      files: [...scope, { ...scope[0]!, path: 'README.md', language: 'other', grammar: null }],
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const list = path.join(work, 'ruff-files.txt');
    const out = path.join(work, 'ruff.sarif');
    expect(p.run.args).toEqual([
      'check',
      '--isolated',
      '--no-cache',
      '--no-fix',
      '--no-preview',
      '--quiet',
      '--output-format',
      'sarif',
      '--output-file',
      out,
      '--select',
      'E4,E7,E9,F,B,PLE,S',
      '--ignore',
      RUFF_DEFAULT_IGNORE.join(','),
      `@${list}`,
    ]);
    expect(readFileSync(list, 'utf8')).toBe(`${scope.map((f) => f.absPath).join('\n')}\n`);
    expect(p.run).toMatchObject({
      command: RUFF,
      cwd: root,
      sarifPath: out,
      okExitCodes: [0, 1],
      version: RUFF_VERSION,
    });
    expect(p.run.env?.['HTTPS_PROXY']).toBe('http://127.0.0.1:9');
    expect(p.run.dropEnv?.('RUFF_OUTPUT_FILE')).toBe(true);
    expect(p.run.dropEnv?.('ruff_cache_dir')).toBe(true);
    expect(p.run.dropEnv?.('PATH')).toBe(false);
  });

  it('passes the project selection and never ignores a code it selects by name', async () => {
    const { root, scope } = repo(['a.py']);
    const run = async (ruff: object) => {
      const p = await ruffAnalyzer.prepare({
        ...fakeContext(root, {
          binaries: { ruff: RUFF },
          workDir: tmp(),
          exec: versionOut(RUFF_VERSION),
          config: { analyzers: { ruff } },
        }),
        files: scope,
      });
      if (!('run' in p)) throw new Error(JSON.stringify(p));
      return p.run.args;
    };
    const withS311 = await run({ select: ['qualor-default', 'S311'] });
    expect(withS311[withS311.indexOf('--select') + 1]).toBe('E4,E7,E9,F,B,PLE,S,S311');
    expect(withS311[withS311.indexOf('--ignore') + 1]?.split(',')).not.toContain('S311');
    const plain = await run({ select: ['F'] });
    expect(plain).not.toContain('--ignore');
    expect(plain[plain.indexOf('--select') + 1]).toBe('F');
  });

  it('never lists a path with a line break, a symlink, or a file outside the repository', async () => {
    const { root, scope } = repo(['ok.py']);
    const lines: string[] = [];
    const extra: ScopeFile[] = [
      { ...scope[0]!, path: 'bad\nname.py', absPath: path.join(root, 'bad\nname.py') },
    ];
    try {
      const outside = path.join(tmp(), 'secret.py');
      writeFileSync(outside, 'x = 1\n');
      symlinkSync(outside, path.join(root, 'link.py'), 'file');
      extra.push({ ...scope[0]!, path: 'link.py', absPath: path.join(root, 'link.py') });
    } catch {
      // No file symlinks here (Windows without Developer Mode): the line-break case still runs.
    }
    const work = tmp();
    const p = await ruffAnalyzer.prepare({
      ...fakeContext(root, {
        binaries: { ruff: RUFF },
        workDir: work,
        exec: versionOut(RUFF_VERSION),
      }),
      log: createLogger('debug', (t) => lines.push(t)),
      files: [...scope, ...extra],
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(readFileSync(path.join(work, 'ruff-files.txt'), 'utf8')).toBe(`${scope[0]!.absPath}\n`);
    expect(lines.join('')).toContain(
      '1 Python file(s) with a line break in their path are not analysed',
    );
  });

  it('is skipped without Python files, and when only unlistable ones are in scope', async () => {
    const ctx = fakeContext(ROOT, {
      binaries: { ruff: RUFF },
      workDir: WORK,
      exec: versionOut(RUFF_VERSION),
    });
    expect(await ruffAnalyzer.prepare({ ...ctx, files: [] })).toEqual({
      skip: 'no Python files in scope',
    });
    const bad: ScopeFile = {
      path: 'a\nb.py',
      absPath: path.join(ROOT, 'a\nb.py'),
      language: 'python',
      grammar: 'python',
      kind: 'main',
      size: 1,
    };
    expect(await ruffAnalyzer.prepare({ ...ctx, files: [bad] })).toEqual({
      skip: 'no Python file in scope has a path Ruff can read from a file list (line break)',
    });
  });

  it('is skipped, not unavailable, without ruff, and says when the repository has its own', async () => {
    const { root, scope } = repo(['a.py']);
    expect(
      await ruffAnalyzer.prepare({ ...fakeContext(root, { binaries: {} }), files: scope }),
    ).toEqual({
      skip: 'Ruff is not installed (ruff on PATH or in the qualor/scanner image)',
    });
    const bin = path.join(root, '.venv', 'bin');
    mkdirSync(bin, { recursive: true });
    const own = path.join(bin, process.platform === 'win32' ? 'ruff.exe' : 'ruff');
    writeFileSync(own, '#!/bin/sh\ntouch "$0.ran"\n');
    chmodSync(own, 0o755);
    // resolveBinary is forced to null: on a CI runner /opt/qualor/bin/ruff exists and would win;
    // repoBinary still comes from this PATH (fakeContext's env mode).
    const p = await ruffAnalyzer.prepare({
      ...fakeContext(root, { env: { PATH: bin } }),
      resolveBinary: () => null,
      files: scope,
    });
    expect(p).toEqual({
      skip: 'Ruff is not installed (ruff on PATH or in the qualor/scanner image; a ruff inside the repository is not used)',
    });
  });

  it('skips another minor of Ruff by name, and is unavailable when --version fails', async () => {
    const { root, scope } = repo(['a.py']);
    for (const other of [`${MAJOR}.${MINOR + 1}.0`, `${MAJOR}.${MINOR - 1}.7`]) {
      const p = await ruffAnalyzer.prepare({
        ...fakeContext(root, { binaries: { ruff: RUFF }, exec: versionOut(other) }),
        files: scope,
      });
      expect(p).toEqual({
        skip: `Ruff ${other} is not supported (Qualor runs Ruff ${MAJOR}.${MINOR}.x; the qualor/scanner image has ${RUFF_VERSION})`,
      });
    }
    const broken = await ruffAnalyzer.prepare({
      ...fakeContext(root, {
        binaries: { ruff: RUFF },
        exec: () => ({ exitCode: 127, timedOut: false, durationMs: 1, stdout: '', stderr: 'boom' }),
      }),
      files: scope,
    });
    expect(broken).toEqual({ unavailable: 'ruff --version did not report a version' });
  });

  it('fails (not merely skips) under enabled: true without ruff', async () => {
    const { root, scope } = repo(['a.py']);
    // The runner also looks in /opt/qualor/bin, which holds a real ruff on CI runners: this copy
    // of the analyzer sees no binary at all, and the runner's own enabled: true rule decides.
    const noRuff = {
      ...ruffAnalyzer,
      prepare: (ctx: Parameters<typeof ruffAnalyzer.prepare>[0]) =>
        ruffAnalyzer.prepare({ ...ctx, resolveBinary: () => null, repoBinary: () => null }),
    };
    const [capture] = await runAnalyzers([noRuff], {
      root,
      config: parseConfig({ version: 1, analyzers: { ruff: { enabled: true } } }),
      files: scope,
      log: silentLogger,
    });
    expect(capture).toMatchObject({
      status: 'failed',
      reason: 'Ruff is not installed (ruff on PATH or in the qualor/scanner image)',
    });
    expect(capture?.unavailable ?? false).toBe(false);
  });
});

describe('ruff output helpers', () => {
  it('reads the version ruff --version prints', () => {
    expect(parseRuffVersion('ruff 0.16.9\n')).toBe('0.16.9');
    expect(parseRuffVersion('ruff 0.16.10 (abc 2026-09-24)\n')).toBe('0.16.10');
    expect(parseRuffVersion('garbage')).toBeNull();
  });

  it('knows the RUFF_ variables, in any case', () => {
    expect(isRuffVariable('RUFF_NO_CACHE')).toBe(true);
    expect(isRuffVariable('Ruff_Cache_Dir')).toBe(true);
    expect(isRuffVariable('TRUFFLE')).toBe(false);
  });

  it('drops invalid-syntax and E902 results and counts them at debug level', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    const sarif = {
      runs: [
        {
          results: [
            { ruleId: 'invalid-syntax' },
            { ruleId: 'F401' },
            { ruleId: 'E902' },
            { ruleId: 'S608' },
            {},
          ],
        },
      ],
    };
    const out = dropNonRuleResults(sarif, log) as typeof sarif;
    expect(out.runs[0]!.results.map((r) => r.ruleId)).toEqual(['F401', 'S608']);
    expect(lines.join('')).toContain('ruff: 3 result(s) that are not rule findings dropped');
    expect(dropNonRuleResults(null, log)).toBeNull();
  });
});

async function scanRuff(root: string, env: NodeJS.ProcessEnv = process.env) {
  const config = parseConfig({ version: 1 });
  const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
  const [capture] = await runAnalyzers([ruffAnalyzer], {
    root,
    config,
    files,
    log: silentLogger,
    env,
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
    keys: out.findings
      .map((f) => `${f.ruleId} ${f.location?.path}:${f.location?.startLine}`)
      .sort(),
  };
}

/** Every regular file under `dir` (relative path → bytes); symbolic links are not followed. */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!e.isFile()) continue;
    const abs = path.join(e.parentPath, e.name);
    out[path.relative(dir, abs).split(path.sep).join('/')] = readFileSync(abs).toString('base64');
  }
  return out;
}

describeWithTools(['ruff'])('Ruff on untrusted checkouts (real Ruff)', () => {
  it("reads no Ruff configuration, writes nothing, and never runs the checkout's own ruff or Python", async () => {
    const root = tmp();
    const outside = tmp();
    const source = 'import os\n\n\ndef f(x):\n    return x\n';
    const hostile =
      `fix = true\nunsafe-fixes = true\ncache-dir = "${outside.replace(/\\/g, '/')}/cache"\n` +
      // Without --isolated each of these would change the result despite the command line's
      // --select, --no-fix and --no-cache: an excluded file, a per-file ignore.
      'force-exclude = true\nextend-exclude = ["excluded.py"]\n' +
      '[lint]\nselect = ["ALL"]\n[lint.per-file-ignores]\n"app.py" = ["F401"]\n';
    // Executable markers: each writes a file named ran-<who> next to itself if anything runs
    // it. The Python ones use no path literal, so they trigger no qualor-default rule (a /tmp
    // literal would be S108).
    const pyMarker = (who: string) =>
      `import pathlib\n\npathlib.Path(__file__).with_name("ran-${who}").write_text("x")\n`;
    writeTree(root, {
      'app.py': source,
      'ruff.toml': hostile,
      '.ruff.toml': hostile,
      'pyproject.toml': `[tool.ruff]\nfix = true\nrequired-version = ">=99"\nextend = "${outside.replace(/\\/g, '/')}/extra.toml"\n`,
      'sitecustomize.py': pyMarker('sitecustomize'),
      'conftest.py': pyMarker('conftest'),
      'excluded.py': 'import os\n',
      // The nearest configuration of strict/c.py: a Ruff that reads it stops with an error.
      'strict/pyproject.toml': '[tool.ruff]\nrequired-version = ">=99"\n',
      'strict/c.py': 'import os\n',
      // A directory whose only configuration is a pyproject.toml, so its `extend` to a file
      // outside the repository is one a Ruff reading configuration would follow (at the root,
      // ruff.toml takes precedence over pyproject.toml). The extended file's per-file ignore
      // survives the command line's --select: a Ruff that followed it drops ext/d.py's F401
      // (probe of 2026-09-30, Ruff 0.16.9 without --isolated).
      'ext/pyproject.toml': `[tool.ruff]\nextend = "${outside.replace(/\\/g, '/')}/ext.toml"\n`,
      'ext/d.py': 'import os\n',
    });
    writeFileSync(path.join(outside, 'extra.toml'), '[lint]\nselect = ["ALL"]\n');
    writeFileSync(
      path.join(outside, 'ext.toml'),
      '[lint]\nselect = ["ALL"]\n[lint.per-file-ignores]\n"d.py" = ["F401"]\n',
    );
    const bin = path.join(root, '.venv', 'bin');
    mkdirSync(bin, { recursive: true });
    const own = path.join(bin, process.platform === 'win32' ? 'ruff.exe' : 'ruff');
    writeFileSync(own, '#!/bin/sh\ntouch "$0.ran"\n');
    chmodSync(own, 0o755);
    const before = snapshot(root);
    const { capture, keys } = await scanRuff(root, {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env['PATH'] ?? ''}`,
    });
    expect(capture.status, capture.reason ?? '').toBe('ok');
    // qualor-default only: F401 for `import os`, nothing of ALL (no D100, ANN001, …).
    expect(keys).toEqual([
      'F401 app.py:1',
      'F401 excluded.py:1',
      'F401 ext/d.py:1',
      'F401 strict/c.py:1',
    ]);
    // Every planted file byte-identical, and no file added (no .ruff_cache, no ran-* marker).
    expect(snapshot(root)).toEqual(before);
    expect(readFileSync(path.join(root, 'app.py'), 'utf8')).toBe(source);
    expect(existsSync(path.join(root, '.ruff_cache'))).toBe(false);
    expect(existsSync(path.join(outside, 'cache'))).toBe(false);
    expect(readdirSync(root).filter((n) => n.startsWith('ran-'))).toEqual([]);
    expect(existsSync(`${own}.ran`)).toBe(false);
  });

  it('drops syntax errors, keeps the other files, and lints awkward names (Review Focus 2, 3)', async () => {
    const root = tmp();
    const names = ['a b.py', 'c#d.py', 'e%f.py', '@at.py', '-dash.py', 'ü.py'];
    writeTree(root, {
      'py2.py': 'print "hello"\n',
      'broken.py': 'def f(:\n    pass\n',
      // A 3.12 type alias: Ruff 0.16.9 parses it without a version error (probe of 2026-09-30).
      'newer.py': 'import os\n\ntype T = int\n',
      ...Object.fromEntries(names.map((n) => [n, 'import os\n'])),
    });
    const { capture, keys } = await scanRuff(root);
    expect(capture.status, capture.reason ?? '').toBe('ok');
    // py2.py and broken.py give only invalid-syntax results, which are dropped.
    expect(keys).toEqual([...names.map((n) => `F401 ${n}:1`), 'F401 newer.py:1'].sort());
  });

  it('never passes a symlinked .py, even one pointing outside the repository', async () => {
    const root = tmp();
    const outside = path.join(tmp(), 'secret.py');
    writeFileSync(outside, 'import os\n');
    writeTree(root, { 'ok.py': 'x = 1\n' });
    try {
      symlinkSync(outside, path.join(root, 'link.py'), 'file');
    } catch {
      return; // no file symlinks on this host (Windows without Developer Mode)
    }
    const { keys } = await scanRuff(root);
    expect(keys).toEqual([]);
  });
});
