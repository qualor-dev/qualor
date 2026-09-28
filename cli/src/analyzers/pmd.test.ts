import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  describeWithTools,
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  sarifSample,
  scanFixtureWith,
  startListener,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { resolveBinary } from './binary';
import { DEAD_PROXY_PROPERTIES } from './jvm';
import { checkPmdConfig, pmdAnalyzer, PMD_DEFAULT_RULESET, resolveRuleset } from './pmd';
import { checkRulesetTree, MAX_RULESET_BYTES, rulesetRefs } from './pmd-ruleset';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();

const javaFile = (root: string, p: string): ScopeFile => ({
  path: p,
  absPath: path.join(root, ...p.split('/')),
  language: 'java',
  grammar: 'java',
  kind: 'main',
  size: 1,
});

describe('resolveRuleset', () => {
  it('maps qualor-default to the PMD quickstart ruleset, keeps repo files and classpath rulesets', () => {
    const root = tmp();
    writeTree(root, { 'config/pmd.xml': '<ruleset/>' });
    expect(resolveRuleset(root, 'qualor-default')).toBe(PMD_DEFAULT_RULESET);
    expect(resolveRuleset(root, 'config/pmd.xml')).toBe(path.join(root, 'config', 'pmd.xml'));
    expect(resolveRuleset(root, 'category/java/errorprone.xml')).toBe(
      'category/java/errorprone.xml',
    );
    expect(resolveRuleset(root, 'config/missing.xml')).toEqual({
      skip: 'ruleset config/missing.xml does not exist',
    });
  });

  it('rejects rulesets outside the repository, also through a linked directory', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'pmd.xml': '<ruleset/>' });
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    const abs = path.join(outside, 'pmd.xml');
    const rel = path.relative(root, abs).split(path.sep).join('/');
    for (const entry of [abs, rel, 'linked/pmd.xml', 'category/java/../../../x.xml']) {
      expect(resolveRuleset(root, entry), entry).toEqual({
        error: `ruleset ${entry} is outside the repository`,
      });
    }
  });

  it('rejects URLs, directories, classpath names that climb, and never echoes control characters', () => {
    const root = tmp();
    mkdirSync(path.join(root, 'config'));
    for (const url of ['https://example.com/r.xml', 'jar:file:/x.jar!/r.xml']) {
      expect(resolveRuleset(root, url)).toEqual({
        error: `ruleset ${url} is a URL (PMD would download it)`,
      });
    }
    expect(resolveRuleset(root, 'config')).toEqual({ skip: 'ruleset config is not a file' });
    expect(resolveRuleset(root, 'category/../category/java/errorprone.xml')).toEqual({
      skip: 'ruleset category/../category/java/errorprone.xml does not exist',
    });
    expect(resolveRuleset(root, 'a\nb.xml')).toEqual({ skip: 'ruleset a?b.xml does not exist' });
    const long = `${'x'.repeat(300)}.xml`;
    const r = resolveRuleset(root, long);
    expect(JSON.stringify(r).length).toBeLessThan(260);
  });
});

describe('pmdAnalyzer.prepare', () => {
  it('runs pmd check on the in-scope Java files with SARIF output', async () => {
    const root = tmp();
    writeTree(root, { 'config/pmd.xml': '<ruleset/>' });
    const base = fakeContext(root, {
      config: { analyzers: { pmd: { rulesets: ['config/pmd.xml', 'qualor-default'] } } },
      binaries: { pmd: '/opt/qualor/bin/pmd' },
      workDir: tmp(),
    });
    const ctx = {
      ...base,
      files: [
        javaFile(root, 'src/main/java/A.java'),
        { ...javaFile(root, 'web/app.ts'), language: 'typescript' as const },
      ],
    };
    const prep = await pmdAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const list = path.join(ctx.workDir, 'files.txt');
    const out = path.join(ctx.workDir, 'pmd.sarif');
    expect(prep.run).toEqual({
      command: '/opt/qualor/bin/pmd',
      args: [
        'check',
        '--file-list',
        list,
        '--rulesets',
        `${path.join(root, 'config', 'pmd.xml')},${PMD_DEFAULT_RULESET}`,
        '--format',
        'sarif',
        '--report-file',
        out,
        '--no-cache',
        '--no-progress',
        '--no-fail-on-violation',
        '--no-fail-on-error',
      ],
      cwd: root,
      env: { PMD_JAVA_OPTS: DEAD_PROXY_PROPERTIES.join(' ') },
      sarifPath: out,
      okExitCodes: [0],
      version: null,
    });
    expect(readFileSync(list, 'utf8')).toBe(
      `${path.join(root, 'src', 'main', 'java', 'A.java')}\n`,
    );
  });

  it('skips a missing ruleset, a scope without Java, and a missing pmd', async () => {
    const root = tmp();
    const withJava = (o: Parameters<typeof fakeContext>[1]) => ({
      ...fakeContext(root, o),
      files: [javaFile(root, 'A.java')],
    });
    expect(
      await pmdAnalyzer.prepare(
        withJava({ config: { analyzers: { pmd: { rulesets: ['nope.xml'] } } } }),
      ),
    ).toEqual({ skip: 'ruleset nope.xml does not exist' });
    expect(await pmdAnalyzer.prepare(fakeContext(root))).toEqual({
      skip: 'no Java files in scope',
    });
    expect(await pmdAnalyzer.prepare(withJava({}))).toEqual({
      unavailable: 'PMD is not installed (pmd on PATH or in the scanner image)',
    });
  });

  it('keeps paths PMD would split (comma, line break) out of the file list', async () => {
    const root = tmp();
    const ctx = (files: ScopeFile[]) => ({
      ...fakeContext(root, { binaries: { pmd: '/opt/qualor/bin/pmd' }, workDir: tmp() }),
      files,
    });
    const good = ctx([
      javaFile(root, 'src/a,b/A.java'),
      javaFile(root, 'src/x\ny/C.java'),
      javaFile(root, 'src/x\ry/D.java'),
      javaFile(root, 'src/B.java'),
    ]);
    const prep = await pmdAnalyzer.prepare(good);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(readFileSync(path.join(good.workDir, 'files.txt'), 'utf8')).toBe(
      `${path.join(root, 'src', 'B.java')}\n`,
    );
    expect(await pmdAnalyzer.prepare(ctx([javaFile(root, 'src/a,b/A.java')]))).toEqual({
      skip: 'no Java file in scope has a path PMD can read from a file list (comma or line break)',
    });
  });

  it('appends the dead proxy to the CI PMD_JAVA_OPTS, so the last -D is ours (ruling V5)', async () => {
    const root = tmp();
    const ctx = {
      ...fakeContext(root, {
        binaries: { pmd: '/opt/qualor/bin/pmd' },
        workDir: tmp(),
        env: { PMD_JAVA_OPTS: ' -Xmx2g -Dhttp.proxyHost=proxy.corp ' },
      }),
      files: [javaFile(root, 'A.java')],
    };
    const prep = await pmdAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.env).toEqual({
      PMD_JAVA_OPTS: `-Xmx2g -Dhttp.proxyHost=proxy.corp ${DEAD_PROXY_PROPERTIES.join(' ')}`,
    });
  });

  it('skips an empty ruleset list and a ruleset path with a comma PMD would split', async () => {
    const root = path.join(tmp(), 'a,b');
    writeTree(root, { 'config/pmd.xml': '<ruleset/>' });
    const ctx = (rulesets: string[]) => ({
      ...fakeContext(root, {
        config: { analyzers: { pmd: { rulesets } } },
        binaries: { pmd: '/opt/qualor/bin/pmd' },
        workDir: tmp(),
      }),
      files: [javaFile(root, 'A.java')],
    });
    expect(await pmdAnalyzer.prepare(ctx([]))).toEqual({ skip: 'no PMD rulesets configured' });
    // A comma in the entry itself is a schema error (exit 2); here it is in the checkout's path.
    expect(await pmdAnalyzer.prepare(ctx(['config/pmd.xml']))).toEqual({
      skip: 'ruleset config/pmd.xml is in a directory whose path has a comma or line break, which PMD would split',
    });
    // A PMD built-in ruleset has no path, but every source path has the comma too.
    expect(await pmdAnalyzer.prepare(ctx(['qualor-default']))).toEqual({
      skip: 'no Java file in scope has a path PMD can read from a file list (comma or line break)',
    });
  });

  it.runIf(process.platform !== 'win32')(
    'skips a ruleset whose name has a line break PMD would split',
    async () => {
      const root = tmp();
      writeTree(root, { 'config/a\nb.xml': '<ruleset/>' });
      const ctx = {
        ...fakeContext(root, {
          config: { analyzers: { pmd: { rulesets: ['config/a\nb.xml'] } } },
          binaries: { pmd: '/opt/qualor/bin/pmd' },
          workDir: tmp(),
        }),
        files: [javaFile(root, 'A.java')],
      };
      expect(await pmdAnalyzer.prepare(ctx)).toEqual({
        skip: 'ruleset config/a?b.xml has a line break in its name, which PMD would split',
      });
    },
  );
});

const RULESET = (rules: string, head = '<?xml version="1.0"?>\n') =>
  `${head}<ruleset name="r" xmlns="http://pmd.sourceforge.net/ruleset/2.0.0">\n  <description>r</description>\n${rules}\n</ruleset>\n`;

describe('rulesetRefs (ruling V4)', () => {
  const refs = (xml: string | Buffer) =>
    rulesetRefs(typeof xml === 'string' ? Buffer.from(xml, 'utf8') : xml);

  it('reads every rule ref, decoded, with any prefix, quote style or > in an earlier value', () => {
    expect(
      refs(
        RULESET(`<rule ref="category/java/errorprone.xml/EmptyCatchBlock"/>
  <pmd:rule
     message="a > b" ref='&#104;ttp://127.0.0.1/x.xml' />
  <rule ref="a&amp;b.xml">
    <priority>1</priority>
  </rule>
  <!-- <rule ref="http://ignored.example/comment.xml"/> -->
  <description><![CDATA[<rule ref="http://ignored.example/cdata.xml"/>]]></description>`),
      ),
    ).toEqual({
      refs: ['category/java/errorprone.xml/EmptyCatchBlock', 'http://127.0.0.1/x.xml', 'a&b.xml'],
    });
  });

  it('refuses what it cannot check with certainty', () => {
    const cases: [string | Buffer, string][] = [
      [
        RULESET('<rule ref="x.xml"/>').replace(
          '<ruleset',
          '<!DOCTYPE r [<!ENTITY e SYSTEM "http://x/">]>\n<ruleset',
        ),
        'declares a DOCTYPE',
      ],
      [
        Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(RULESET(''), 'utf16le')]),
        'is not UTF-8',
      ],
      [Buffer.from(RULESET(''), 'utf16le'), 'is not UTF-8'],
      [RULESET('', '<?xml version="1.0" encoding="UTF-16"?>\n'), 'declares the encoding UTF-16'],
      [RULESET('<rule ref="&evil;"/>'), 'entity that cannot be checked'],
      [RULESET('<rule ref="a & b"/>'), 'entity that cannot be checked'],
      [RULESET('<rule ref="x.xml" ref="http://x/"/>'), 'duplicate attribute'],
      [RULESET('<rule ref=http://x/ />'), 'cannot be checked'],
      // EBCDIC `<?xml` (4C 6F A7 94 93): no zero byte, but not text this reader can check.
      [Buffer.from([0x4c, 0x6f, 0xa7, 0x94, 0x93, 0x40, 0x6e]), 'does not start with <'],
      [`x${RULESET('')}`, 'does not start with <'],
      ['', 'does not start with <'],
    ];
    for (const [xml, message] of cases) {
      const r = refs(xml);
      expect('error' in r ? r.error : r, message).toContain(message);
    }
  });

  it('accepts a byte order mark or whitespace before the first <', () => {
    const ref = RULESET('<rule ref="a.xml"/>');
    expect(refs(`\ufeff${ref}`)).toEqual({ refs: ['a.xml'] });
    expect(refs(`\n  ${RULESET('<rule ref="a.xml"/>', '')}`)).toEqual({ refs: ['a.xml'] });
  });
});

describe('checkRulesetTree and checkPmdConfig (ruling V4)', () => {
  const check = (root: string, rules: Record<string, string>, top = 'config/pmd.xml') => {
    writeTree(root, rules);
    return checkRulesetTree(root, path.join(root, ...top.split('/')));
  };

  it('allows built-in rulesets, rules of the same ruleset and repository rulesets, recursively', () => {
    const root = tmp();
    expect(
      check(root, {
        'config/pmd.xml': RULESET(`<rule ref="category/java/errorprone.xml/EmptyCatchBlock"/>
<rule ref="rulesets/java/quickstart.xml"/>
<rule ref="MyRule"/>
<rule ref="other.xml"/>
<rule ref="config/third.xml/Some"/>`),
        'config/other.xml': RULESET('<rule ref="pmd.xml"/>'),
        'config/third.xml': RULESET('<rule ref="category/java/bestpractices.xml"/>'),
      }),
    ).toBeNull();
  });

  it('rejects URL, absolute, backslash, outside and unknown refs, also through other rulesets', () => {
    const root = tmp();
    const bad: [string, string][] = [
      ['http://127.0.0.1:8123/remote.xml', 'is a URL'],
      ['HTTPS://example.com/r.xml/Rule', 'is a URL'],
      ['jar:file:/x.jar!/r.xml', 'is a URL'],
      ['file:///etc/pmd.xml', 'is a URL'],
      ['/etc/pmd.xml', 'is an absolute path'],
      ['C:\\rules\\pmd.xml', 'is an absolute path'],
      ['\\\\host\\share\\pmd.xml', 'is an absolute path'],
      ['sub\\pmd.xml', 'has a backslash'],
      ['../../outside.xml', 'is outside the repository'],
      ['category/java/../../../../x.xml', 'is outside the repository'],
      ['not/a/ruleset', 'is neither a ruleset nor a rule name'],
      ['missing.xml', 'is neither a repository file nor a PMD built-in ruleset'],
      ['', 'is empty'],
    ];
    for (const [ref, why] of bad) {
      const message = check(root, {
        'config/pmd.xml': RULESET(`<rule ref="${ref.replace(/&/g, '&amp;')}"/>`),
      });
      expect(message, ref).toContain(why);
      expect(message, ref).toContain('ruleset config/pmd.xml');
    }
    // Two levels down: the message names the ruleset that has the bad ref.
    expect(
      check(root, {
        'config/pmd.xml': RULESET('<rule ref="a.xml"/>'),
        'config/a.xml': RULESET('<rule ref="config/b.xml"/>'),
        'config/b.xml': RULESET('<rule ref="http://127.0.0.1:8123/x.xml"/>'),
      }),
    ).toBe(
      'ruleset config/b.xml: rule ref "http://127.0.0.1:8123/x.xml" is a URL (PMD would download it)',
    );
  });

  it('allows a ../ ref that stays inside from the ruleset directory, unless an outside file of that name exists', () => {
    const parent = tmp();
    const root = path.join(parent, 'repo');
    const tree = {
      'config/pmd.xml': RULESET('<rule ref="../shared.xml"/>'),
      'shared.xml': RULESET('<rule ref="category/java/errorprone.xml"/>'),
    };
    // From the repository root, ../shared.xml is outside; from config/ it is the root's file.
    expect(check(root, tree)).toBeNull();
    writeTree(parent, { 'shared.xml': RULESET('') });
    expect(check(root, tree)).toBe(
      'ruleset config/pmd.xml: rule ref "../shared.xml" is outside the repository',
    );
  });

  it('refuses a ref through a link out of the repository, and an oversized ruleset', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'r.xml': RULESET('') });
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    expect(check(root, { 'config/pmd.xml': RULESET('<rule ref="linked/r.xml"/>') })).toContain(
      'is outside the repository',
    );
    const big = `${RULESET('')}${' '.repeat(MAX_RULESET_BYTES)}`;
    expect(check(root, { 'config/pmd.xml': big })).toBe(
      'ruleset config/pmd.xml is larger than 4 MiB',
    );
  });

  it('turns a URL or outside ruleset entry into a configuration error', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'r.xml': RULESET('') });
    writeTree(root, {
      'config/pmd.xml': RULESET('<rule ref="http://127.0.0.1:8123/x.xml"/>'),
      'config/ok.xml': RULESET('<rule ref="category/java/errorprone.xml"/>'),
    });
    const config = (rulesets: string[]) =>
      parseConfig({ version: 1, analyzers: { pmd: { rulesets } } });
    expect(
      checkPmdConfig(root, config(['qualor-default', 'config/ok.xml', 'missing.xml'])),
    ).toBeNull();
    expect(checkPmdConfig(root, config([path.join(outside, 'r.xml')]))).toBe(
      `ruleset ${path.join(outside, 'r.xml')} is outside the repository`,
    );
    expect(checkPmdConfig(root, config(['config/pmd.xml']))).toContain('is a URL');
    expect(pmdAnalyzer.checkConfig?.(root, config(['config/pmd.xml']))).toContain('is a URL');
  });
});

describe('PMD SARIF (recorded PMD 7.27.0 output on java-basic)', () => {
  it('normalises to exactly the fixture findings, with java rules', () => {
    const out = normalizeRecorded(sarifSample('pmd'), pmdAnalyzer, 'java-basic');
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('java-basic', 'pmd'));
    expect(out.engines[0]?.version).toBe('7.27.0');
    expect(out.engines[0]?.rules.map((r) => r.languages)).toEqual([
      ['java'],
      ['java'],
      ['java'],
      ['java'],
    ]);
  });
});

describeWithTools(['pmd'])('PMD on the java-basic fixture (real PMD)', () => {
  it('reports exactly the fixture findings', { timeout: 180_000 }, async () => {
    const { capture, keys } = await scanFixtureWith(pmdAnalyzer, 'java-basic', tmp());
    expect(capture.status).toBe('ok');
    expect(keys).toEqual(expectedKeys('java-basic', 'pmd'));
  });

  it(
    'runs the qualor-default ruleset from the PMD distribution',
    { timeout: 180_000 },
    async () => {
      const { keys } = await scanFixtureWith(pmdAnalyzer, 'java-basic', tmp(), (root) =>
        writeFileSync(path.join(root, 'qualor.yml'), 'version: 1\n'),
      );
      expect(keys).toContain(
        'pmd:CompareObjectsWithEquals src/main/java/com/acme/Calculator.java:15 [medium]',
      );
    },
  );
});

/** A checkout that plants a `java` program and a class a ruleset names; either writes `pwned`. */
function hostileRepo(root: string): string {
  const marker = path.join(root, 'pwned');
  writeTree(root, {
    'src/main/java/A.java': 'class A { void f() { try { } catch (Exception e) { } } }\n',
    // Initialised when PMD loads the ruleset's rule class= from a class path entry in the repo.
    'evil/Evil.java': `public class Evil { static { try { java.nio.file.Files.writeString(java.nio.file.Path.of(${JSON.stringify(marker)}), "class"); } catch (Exception e) { } } }\n`,
    'config/evil.xml': `<?xml version="1.0"?>
<ruleset name="evil" xmlns="http://pmd.sourceforge.net/ruleset/2.0.0">
  <description>evil</description>
  <rule name="Evil" language="java" class="Evil" message="evil"/>
</ruleset>
`,
    'bin/java': `#!/bin/sh\necho java > ${JSON.stringify(marker)}\nexit 1\n`,
  });
  chmodSync(path.join(root, 'bin', 'java'), 0o755);
  const javac = resolveBinary('javac', { root, env: process.env });
  if (javac === null) throw new Error('javac is not installed');
  const built = spawnSync(javac, ['-d', root, path.join(root, 'evil', 'Evil.java')], {
    encoding: 'utf8',
  });
  expect(built.status, built.stderr).toBe(0);
  expect(existsSync(path.join(root, 'Evil.class'))).toBe(true);
  return marker;
}

describeWithTools(['pmd', 'javac'])('PMD never runs code from the repository (real PMD)', () => {
  const scan = (root: string, ruleset: string, env: Record<string, string>) =>
    runAnalyzers([pmdAnalyzer], {
      root,
      config: parseConfig({ version: 1, analyzers: { pmd: { rulesets: [ruleset] } } }),
      files: [javaFile(root, 'src/main/java/A.java')],
      log: silentLogger,
      env: { ...process.env, ...env },
    });

  it.runIf(process.platform !== 'win32')(
    'ignores a java on a relative or in-repository PATH entry',
    { timeout: 180_000 },
    async () => {
      const root = tmp();
      const marker = hostileRepo(root);
      const [capture] = await scan(root, 'qualor-default', {
        PATH: `bin:${path.join(root, 'bin')}:${process.env['PATH'] ?? ''}`,
      });
      expect(existsSync(marker)).toBe(false);
      expect(capture?.status).toBe('ok');
    },
  );

  it.runIf(process.platform !== 'win32')(
    'never puts the repository on the class path, so a ruleset cannot load a class from it',
    { timeout: 180_000 },
    async () => {
      const root = tmp();
      const marker = hostileRepo(root);
      const [capture] = await scan(root, 'config/evil.xml', { CLASSPATH: `.:${root}` });
      expect(existsSync(marker)).toBe(false);
      // PMD cannot load the rule class (it is not on PMD's class path), so the run fails.
      expect(capture?.status).toBe('failed');
    },
  );

  it(
    'sends no request from a ruleset XPath doc-available() (ruling V5 dead proxy)',
    { timeout: 180_000 },
    async () => {
      const listener = await startListener();
      try {
        const root = tmp();
        hostileRepo(root);
        writeTree(root, {
          'config/xpath.xml':
            RULESET(`<rule name="X" language="java" message="m" class="net.sourceforge.pmd.lang.rule.xpath.XPathRule">
    <priority>3</priority>
    <properties><property name="xpath"><value><![CDATA[ //ClassDeclaration[doc-available('${listener.url}/xpath') or unparsed-text-available('${listener.url}/text')] ]]></value></property></properties>
  </rule>`),
        });
        const [capture] = await scan(root, 'config/xpath.xml', {});
        expect(capture?.status).toBe('ok');
        expect(listener.hits).toEqual([]);
      } finally {
        await listener.close();
      }
    },
  );
});
