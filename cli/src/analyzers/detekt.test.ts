import { mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { engineMapping, parseConfig, splitSourceLines } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  describeWithDetekt,
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  recorded,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { createDetektAnalyzer, DEFAULT_DETEKT_JAR, detektAnalyzer } from './detekt';
import { QUALOR_DETEKT_OVERLAY } from './detekt-config';
import { detektSarif } from './detekt-sarif';
import { DEAD_PROXY_PROPERTIES } from './jvm';
import { normalizeCaptures } from './normalize';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';

function kt(root: string, p: string, language: ScopeFile['language'] = 'kotlin'): ScopeFile {
  return {
    path: p,
    absPath: path.join(root, ...p.split('/')),
    language,
    grammar: language === 'kotlin' ? 'kotlin' : null,
    kind: 'main',
    size: 10,
  };
}

/** A repository with Kotlin files, a fake jar outside it and a fake java. */
function setup(extra: Record<string, string> = {}) {
  const root = tmp();
  writeTree(root, {
    'src/A.kt': 'class A\n',
    'build.gradle.kts': 'val x = 1\n',
    'README.md': '# r\n',
    ...extra,
  });
  const tools = tmp();
  const jar = path.join(tools, 'detekt-cli.jar');
  writeFileSync(jar, 'jar');
  const workDir = tmp();
  const files = [
    kt(root, 'src/A.kt'),
    kt(root, 'build.gradle.kts'),
    kt(root, 'README.md', 'other'),
  ];
  return { root, jar, workDir, files };
}

function ctxFor(
  s: ReturnType<typeof setup>,
  o: { env?: Record<string, string>; java?: string | null } = {},
) {
  const base = fakeContext(s.root, {
    workDir: s.workDir,
    binaries: o.java === null ? {} : { java: o.java ?? '/usr/bin/java' },
  });
  return { ...base, env: { QUALOR_DETEKT_JAR: s.jar, ...o.env }, files: s.files };
}

/** The repository-relative files under the copy detekt reads. */
function copied(workDir: string): string[] {
  const input = path.join(workDir, 'detekt-input');
  return readdirSync(input, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => path.relative(input, path.join(d.parentPath, d.name)).split(path.sep).join('/'))
    .sort();
}

describe('detekt prepare (config.md §6)', () => {
  it('is skipped without the image jar, so a plain host keeps a complete scan (ruling G6)', async () => {
    const s = setup();
    const analyzer = createDetektAnalyzer({ defaultJar: path.join(tmp(), 'missing.jar') });
    const p = await analyzer.prepare({ ...ctxFor(s), env: {} });
    expect(p).toEqual({ skip: 'detekt is not installed (qualor/scanner image)' });
  });

  it('is unavailable with a relative QUALOR_DETEKT_JAR', async () => {
    const s = setup();
    expect(
      await detektAnalyzer.prepare(ctxFor(s, { env: { QUALOR_DETEKT_JAR: 'lib/detekt.jar' } })),
    ).toEqual({ unavailable: 'QUALOR_DETEKT_JAR must be an absolute path outside the repository' });
  });

  it('is unavailable with a QUALOR_DETEKT_JAR inside the repository or not naming a file', async () => {
    const s = setup({ 'tools/detekt.jar': 'evil' });
    expect(
      await detektAnalyzer.prepare(
        ctxFor(s, { env: { QUALOR_DETEKT_JAR: path.join(s.root, 'tools', 'detekt.jar') } }),
      ),
    ).toEqual({ unavailable: 'QUALOR_DETEKT_JAR must be an absolute path outside the repository' });
    const missing = path.join(tmp(), 'none.jar');
    expect(
      await detektAnalyzer.prepare(ctxFor(s, { env: { QUALOR_DETEKT_JAR: missing } })),
    ).toEqual({ unavailable: `QUALOR_DETEKT_JAR ${missing} is not a file` });
  });

  it('is unavailable without java', async () => {
    expect(await detektAnalyzer.prepare(ctxFor(setup(), { java: null }))).toEqual({
      unavailable: 'detekt needs java (JAVA_HOME or PATH)',
    });
  });

  it('runs java -jar on a checked copy of the in-scope Kotlin files, detekt defaults and the overlay last', async () => {
    const s = setup();
    const p = await detektAnalyzer.prepare(ctxFor(s));
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const input = path.join(s.workDir, 'detekt-input');
    const overlay = path.join(s.workDir, 'qualor-detekt.yml');
    expect(p.run.command).toBe('/usr/bin/java');
    expect(p.run.args).toEqual([
      '-XX:MaxRAMPercentage=50',
      ...DEAD_PROXY_PROPERTIES,
      '-Dfile.encoding=UTF-8',
      '-Dsun.jnu.encoding=UTF-8',
      '-jar',
      s.jar,
      '--input',
      input,
      '--base-path',
      input,
      '--config',
      overlay,
      '--build-upon-default-config',
      '--report',
      `sarif:${p.run.sarifPath}`,
    ]);
    // Never a path of the checkout, never anything that loads code or a baseline.
    expect(p.run.args.join(' ')).not.toContain(s.root);
    for (const flag of ['--classpath', '--plugins', '--baseline', '--jdk-home', '--all-rules']) {
      expect(p.run.args).not.toContain(flag);
    }
    expect(p.run.env).toEqual({ LC_ALL: 'C.UTF-8' });
    expect(p.run.cwd).toBe(s.workDir);
    expect(p.run.okExitCodes).toEqual([0, 2]);
    expect(p.run.version).toBeNull();
    expect(p.run.sarifPath).toBe(path.join(s.workDir, 'detekt.sarif'));
    expect(copied(s.workDir)).toEqual(['build.gradle.kts', 'src/A.kt']);
    expect(readFileSync(path.join(input, 'src', 'A.kt'), 'utf8')).toBe('class A\n');
    expect(readFileSync(overlay, 'utf8')).toBe(QUALOR_DETEKT_OVERLAY);
  });

  it('passes a checked copy of the project config before the overlay, never the checkout file (ruling E6)', async () => {
    const s = setup({ 'config/detekt/detekt.yml': 'style:\n  MagicNumber:\n    active: false\n' });
    const p = await detektAnalyzer.prepare(ctxFor(s));
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const copy = path.join(s.workDir, 'project-detekt.yml');
    expect(p.run.args[p.run.args.indexOf('--config') + 1]).toBe(
      `${copy},${path.join(s.workDir, 'qualor-detekt.yml')}`,
    );
    expect(readFileSync(copy, 'utf8')).toBe('style:\n  MagicNumber:\n    active: false\n');
  });

  it('skips on an unusable project config, never exit 2 (ruling E7)', async () => {
    const s = setup({ 'detekt.yml': '- 1\n' });
    expect(await detektAnalyzer.prepare(ctxFor(s))).toEqual({
      skip: 'detekt.yml is not a YAML mapping',
    });
    expect(detektAnalyzer.checkConfig?.(s.root, fakeContext(s.root).config)).toBeNull();
  });

  it('stops qualor scan with exit 2 only for a configFile outside the repository', () => {
    const s = setup();
    const config = parseConfig({
      version: 1,
      analyzers: { detekt: { configFile: '../x.yml' } },
    });
    expect(detektAnalyzer.checkConfig?.(s.root, config)).toBe(
      'configFile ../x.yml is outside the repository',
    );
  });

  it('copies names with spaces, non-ASCII letters, commas and semicolons as they are (ruling E16)', async () => {
    const names = ['src/Space Name.kt', 'src/Ünïcødé.kt', 'src/a,b/C;D.kt'];
    const s = setup(Object.fromEntries(names.map((n) => [n, 'class X\n'])));
    const p = await detektAnalyzer.prepare({
      ...ctxFor(s),
      files: names.map((n) => kt(s.root, n)),
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(copied(s.workDir)).toEqual([...names].sort());
  });

  it('leaves out links and files over 1 MiB with one warning, and skips when nothing is left (Review Focus 3, ruling E15)', async () => {
    const s = setup({ 'src/Big.kt': `// ${'x'.repeat(MAX_ANALYZED_BYTES)}\n` });
    const outside = path.join(tmp(), 'Out.kt');
    writeFileSync(outside, 'class Out\n');
    const outDir = tmp();
    writeTree(outDir, { 'In.kt': 'class In\n' });
    if (posix) {
      symlinkSync(outside, path.join(s.root, 'src', 'Link.kt'));
      // A linked source directory: its files are not reached without a link.
      symlinkSync(outDir, path.join(s.root, 'linked'));
    }
    const warnings: string[] = [];
    const ctx = {
      ...ctxFor(s),
      log: { ...silentLogger, warn: (m: string) => warnings.push(m) },
      files: [
        kt(s.root, 'src/A.kt'),
        kt(s.root, 'src/Big.kt'),
        kt(s.root, 'src/Missing.kt'),
        ...(posix ? [kt(s.root, 'src/Link.kt'), kt(s.root, 'linked/In.kt')] : []),
      ],
    };
    const p = await detektAnalyzer.prepare(ctx);
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(copied(s.workDir)).toEqual(['src/A.kt']);
    expect(warnings).toEqual([
      `detekt: ${posix ? 4 : 2} Kotlin file(s) not analysed (a link, a file larger than 1 MiB or one that cannot be read)`,
    ]);
    const none = await detektAnalyzer.prepare({
      ...ctx,
      workDir: tmp(),
      files: [kt(s.root, 'src/Big.kt')],
    });
    expect(none).toEqual({ skip: 'no Kotlin file in scope that detekt can be given' });
  });

  it('skips when the work directory path has a comma or semicolon, which --config would split', async () => {
    const s = setup();
    const workDir = path.join(tmp(), 'a,b');
    mkdirSync(workDir);
    expect(await detektAnalyzer.prepare({ ...ctxFor(s), workDir })).toEqual({
      skip: 'the work directory path has a comma or semicolon, which detekt would split',
    });
  });

  it('converts the SARIF with detektSarif, rebased onto the repository', async () => {
    const s = setup();
    const p = await detektAnalyzer.prepare(ctxFor(s));
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const out = p.run.transform!(
      {
        version: '2.1.0',
        runs: [
          {
            originalUriBaseIds: { '%SRCROOT%': { uri: 'file:///x/detekt-input/' } },
            tool: { driver: { name: 'detekt', rules: [{ id: 'detekt.style.MagicNumber' }] } },
            results: [],
          },
        ],
      },
      '',
    ) as {
      runs: {
        originalUriBaseIds: Record<string, { uri: string }>;
        tool: { driver: { rules: { id: string }[] } };
      }[];
    };
    expect(out.runs[0]!.tool.driver.rules[0]!.id).toBe('MagicNumber');
    expect(out.runs[0]!.originalUriBaseIds['%SRCROOT%']!.uri.endsWith('/')).toBe(true);
    expect(decodeURIComponent(out.runs[0]!.originalUriBaseIds['%SRCROOT%']!.uri)).toContain(
      path.basename(s.root),
    );
  });

  it('declares its id, languages and default jar', () => {
    expect(detektAnalyzer.id).toBe('detekt');
    expect(detektAnalyzer.languages).toEqual(['kotlin']);
    expect(detektAnalyzer.ruleLanguages).toEqual(['kotlin']);
    expect(DEFAULT_DETEKT_JAR).toBe('/opt/qualor/lib/detekt/detekt-cli.jar');
  });
});

describeWithDetekt()('detekt on awkward file names (real detekt, ruling E16)', () => {
  it(
    'reports findings in files with spaces, non-ASCII letters, a comma or a % in the name, under a spaced root',
    { timeout: 180_000 },
    async () => {
      const root = path.join(tmp(), 'repo with space');
      const names = [
        'src/main/kotlin/Space Name.kt',
        'src/main/kotlin/Ünïcødé.kt',
        'src/a,b;c.kt',
        'src/100%.kt',
      ];
      writeTree(
        root,
        Object.fromEntries(names.map((n) => [n, 'class Foo {\n    val x = 42 * 7\n}\n'])),
      );
      const [capture] = await runAnalyzers([detektAnalyzer], {
        root,
        files: names.map((n) => kt(root, n)),
        config: parseConfig({ version: 1 }),
        log: silentLogger,
        env: process.env,
      });
      expect(capture?.status, capture?.reason ?? '').toBe('ok');
      // Through the normaliser, as runScan does: every file keeps its path in the repository.
      const out = normalizeCaptures([{ ...capture!, mapping: engineMapping('detekt')! }], {
        repoRoot: root,
        readLines: (p) => splitSourceLines(readFileSync(path.join(root, p), 'utf8')),
        knownPaths: new Set(names),
        log: silentLogger,
      });
      const magic = out.findings
        .filter((f) => f.ruleId === 'MagicNumber')
        .map((f) => f.location?.path);
      expect([...new Set(magic)].sort()).toEqual([...names].sort());
    },
  );
});

describe('detekt SARIF normalisation (recorded run over kotlin-basic)', () => {
  it('gives the fixture’s expected detekt findings', () => {
    const out = normalizeRecorded(
      detektSarif(recorded('detekt/basic.sarif')),
      detektAnalyzer,
      'kotlin-basic',
    );
    expect(findingKeys(out.findings)).toEqual(expectedKeys('kotlin-basic', 'detekt'));
    expect(out.engines[0]).toMatchObject({ id: 'detekt', version: '1.23.8' });
  });
});
