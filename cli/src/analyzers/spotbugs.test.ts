import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  compileJava,
  describeWithTools,
  expectedKeys,
  fakeContext,
  findingKeys,
  normalizeRecorded,
  sarifSample,
  scanFixtureWith,
  startListener,
} from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { silentLogger } from '../log';
import { runAnalyzers } from './runner';
import { DEAD_PROXY_PROPERTIES } from './jvm';
import {
  FINDSECBUGS_EXTENSION,
  findsecbugsPlugin,
  hasClassFiles,
  isFindsecbugsVariable,
  javaSourceRoots,
  spotbugsAnalyzer,
  spotbugsHome,
  withFindsecbugsVersion,
} from './spotbugs';

const tmp = useTempDirs();

/** A SpotBugs installation as the tarball lays it out: bin/spotbugs and lib/spotbugs.jar. */
function fakeInstall(o: { plugin?: string } = {}): {
  launcher: string;
  home: string;
  jar: string;
} {
  const home = tmp();
  writeTree(home, { 'bin/spotbugs': '#!/bin/sh\n', 'lib/spotbugs.jar': 'jar' });
  if (o.plugin !== undefined) writeTree(home, { [`plugin/${o.plugin}`]: 'jar' });
  return {
    launcher: path.join(home, 'bin', 'spotbugs'),
    home,
    jar: path.join(home, 'lib', 'spotbugs.jar'),
  };
}
const JAVA = path.resolve('/usr/bin/java');

function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    writeFileSync(path.join(dir, 'target.txt'), 'x');
    symlinkSync(path.join(dir, 'target.txt'), path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const CAN_SYMLINK_FILES = canCreateFileSymlinks();

const file = (p: string, language: ScopeFile['language'] = 'java'): ScopeFile => ({
  path: p,
  absPath: `/r/${p}`,
  language,
  grammar: null,
  kind: 'main',
  size: 1,
});

describe('SpotBugs inputs', () => {
  it('finds class files below a directory, and nothing in an empty or missing one', () => {
    const root = tmp();
    writeTree(root, { 'target/classes/com/acme/A.class': 'x', 'empty/.keep': '' });
    expect(hasClassFiles(path.join(root, 'target', 'classes'))).toBe(true);
    expect(hasClassFiles(path.join(root, 'empty'))).toBe(false);
    expect(hasClassFiles(path.join(root, 'missing'))).toBe(false);
    expect(hasClassFiles(path.join(root, 'empty', '.keep'))).toBe(false);
  });

  it('never follows a linked directory, at the top or below it', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'com/acme/A.class': 'x' });
    mkdirSync(path.join(root, 'classes'));
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    symlinkSync(outside, path.join(root, 'classes', 'inner'), 'junction');
    expect(hasClassFiles(path.join(root, 'linked'))).toBe(false);
    expect(hasClassFiles(path.join(root, 'classes'))).toBe(false);
  });

  it('derives Maven/Gradle source roots from the in-scope Java files', () => {
    expect(
      javaSourceRoots([
        file('src/main/java/com/acme/A.java'),
        file('api/src/main/java/com/acme/B.java'),
        file('api/src/test/java/com/acme/BTest.java'),
        file('scripts/Tool.java'),
        file('src/main/java/web/app.ts', 'typescript'),
      ]),
    ).toEqual(['api/src/main/java', 'api/src/test/java', 'src/main/java']);
  });
});

describe('FindSecBugs in the SpotBugs run (plan 6A)', () => {
  it('drops every findsecbugs* variable, which FindSecBugs would read as configuration', async () => {
    const root = tmp();
    writeTree(root, { 'target/classes/A.class': 'x' });
    const install = fakeInstall();
    const prep = await spotbugsAnalyzer.prepare(
      fakeContext(root, { binaries: { spotbugs: install.launcher, java: JAVA } }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const drop = prep.run.dropEnv!;
    for (const name of [
      'findsecbugs.taint.customconfigfile',
      'findsecbugs_taint_outputconfigs',
      'findsecbugs.injection.customconfigfile.SqlInjectionDetector',
      'FINDSECBUGS_TAINT_CUSTOMCONFIGFILE',
    ]) {
      expect(drop(name), name).toBe(true);
    }
    for (const name of ['PATH', 'JAVA_HOME', 'JAVA_TOOL_OPTIONS', 'HOME', 'myfindsecbugs']) {
      expect(drop(name), name).toBe(false);
    }
    expect(isFindsecbugsVariable('findsecbugsX')).toBe(true);
  });

  it("reads the plugin's version from its jar name in the SpotBugs home", () => {
    const withPlugin = fakeInstall({ plugin: 'findsecbugs-plugin-1.14.0.jar' });
    expect(findsecbugsPlugin(withPlugin.home)).toEqual({
      jar: path.join(withPlugin.home, 'plugin', 'findsecbugs-plugin-1.14.0.jar'),
      version: '1.14.0',
    });
    expect(findsecbugsPlugin(fakeInstall({ plugin: 'fb-contrib-7.6.4.jar' }).home)).toBeNull();
    expect(findsecbugsPlugin(fakeInstall().home)).toBeNull();
    expect(findsecbugsPlugin(path.join(tmp(), 'nowhere'))).toBeNull();
  });

  it('names FindSecBugs next to SpotBugs only when the log lists its extension', () => {
    const log = (extensions: unknown[]) => ({
      runs: [
        { tool: { driver: { name: 'SpotBugs', version: '4.10.4' }, extensions }, results: [] },
      ],
    });
    const version = (out: unknown) =>
      (out as { runs: { tool: { driver: { version: string } } }[] }).runs[0]!.tool.driver.version;
    const fsb = { name: FINDSECBUGS_EXTENSION, version: '' };
    expect(version(withFindsecbugsVersion(log([fsb]), '1.14.0'))).toBe(
      '4.10.4 + FindSecBugs 1.14.0',
    );
    expect(version(withFindsecbugsVersion(log([fsb]), null))).toBe('4.10.4 + FindSecBugs');
    expect(
      version(
        withFindsecbugsVersion(log([{ name: 'edu.umd.cs.findbugs.plugins.core' }]), '1.14.0'),
      ),
    ).toBe('4.10.4');
    expect(version(withFindsecbugsVersion(log([]), '1.14.0'))).toBe('4.10.4');
    for (const odd of [null, 'text', 42, { runs: 'x' }, { runs: [null, { tool: null }] }]) {
      expect(withFindsecbugsVersion(odd, '1.14.0')).toEqual(odd);
    }
  });

  it('sets the transform, and keeps the command line exactly as before', async () => {
    const root = tmp();
    writeTree(root, { 'target/classes/A.class': 'x' });
    const install = fakeInstall({ plugin: 'findsecbugs-plugin-1.14.0.jar' });
    const prep = await spotbugsAnalyzer.prepare(
      fakeContext(root, { binaries: { spotbugs: install.launcher, java: JAVA } }),
    );
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args).not.toContain('-pluginList');
    expect(prep.run.args.some((a) => a.includes('findsecbugs'))).toBe(false);
    const out = prep.run.transform!(
      {
        runs: [
          {
            tool: { driver: { version: '4.10.4' }, extensions: [{ name: FINDSECBUGS_EXTENSION }] },
          },
        ],
      },
      '',
    ) as { runs: { tool: { driver: { version: string } } }[] };
    expect(out.runs[0]!.tool.driver.version).toBe('4.10.4 + FindSecBugs 1.14.0');
  });
});

describe('spotbugsAnalyzer.prepare', () => {
  it('runs the SpotBugs jar on a system java for the class directories that hold classes', async () => {
    const root = tmp();
    const install = fakeInstall();
    writeTree(root, {
      'target/classes/A.class': 'x',
      'build/classes/java/main/.keep': '',
      'deps.txt': '/m2/lib.jar\n',
    });
    const ctx = {
      ...fakeContext(root, {
        config: { analyzers: { spotbugs: { auxClasspathFile: 'deps.txt' } } },
        binaries: { spotbugs: install.launcher, java: JAVA },
      }),
      files: [file('src/main/java/A.java')],
    };
    const prep = await spotbugsAnalyzer.prepare(ctx);
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    const out = path.join(ctx.workDir, 'spotbugs.sarif');
    expect(prep.run).toEqual({
      command: JAVA,
      args: [
        '-XX:MaxRAMPercentage=50',
        ...DEAD_PROXY_PROPERTIES,
        `-Dspotbugs.home=${install.home}`,
        '-cp',
        install.jar,
        'edu.umd.cs.findbugs.FindBugs2',
        '-quiet',
        '-effort:max',
        '-low',
        `-sarif=${out}`,
        '-sourcepath',
        path.join(root, 'src', 'main', 'java'),
        '-auxclasspathFromFile',
        path.join(root, 'deps.txt'),
        path.join(root, 'target', 'classes'),
      ],
      cwd: root,
      sarifPath: out,
      okExitCodes: [0],
      dropEnv: isFindsecbugsVariable,
      transform: expect.any(Function),
      version: null,
    });
    expect(spotbugsAnalyzer.sourceRoots?.(ctx)).toEqual(['src/main/java']);
  });

  it('finds the installation from the real launcher path, also in an FHS layout', async () => {
    const install = fakeInstall();
    expect(spotbugsHome(install.launcher)).toEqual({ home: install.home, jar: install.jar });
    const fhs = tmp();
    writeTree(fhs, { 'bin/spotbugs': '', 'share/spotbugs/lib/spotbugs.jar': 'jar' });
    expect(spotbugsHome(path.join(fhs, 'bin', 'spotbugs'))).toEqual({
      home: path.join(fhs, 'share', 'spotbugs'),
      jar: path.join(fhs, 'share', 'spotbugs', 'lib', 'spotbugs.jar'),
    });
    expect(spotbugsHome(path.join(tmp(), 'bin', 'spotbugs'))).toBeNull();
    const root = tmp();
    writeTree(root, { 'target/classes/A.class': 'x' });
    const prepare = (binaries: Record<string, string>) =>
      spotbugsAnalyzer.prepare(fakeContext(root, { binaries }));
    expect(await prepare({ spotbugs: path.join(tmp(), 'spotbugs'), java: JAVA })).toEqual({
      unavailable: 'SpotBugs is not installed (no lib/spotbugs.jar next to the spotbugs launcher)',
    });
    expect(await prepare({ spotbugs: install.launcher })).toEqual({
      unavailable: 'SpotBugs needs java (JAVA_HOME or PATH)',
    });
  });

  it('runs the java of an absolute JAVA_HOME outside the repository, else the one from PATH', async () => {
    const root = tmp();
    const install = fakeInstall();
    writeTree(root, { 'target/classes/A.class': 'x' });
    const jdk = (dir: string) => {
      const exe = process.platform === 'win32' ? 'java.exe' : 'java';
      writeTree(dir, { [`bin/${exe}`]: '#!/bin/sh\n' });
      chmodSync(path.join(dir, 'bin', exe), 0o755);
      return path.join(dir, 'bin', exe);
    };
    const command = async (javaHome: string) => {
      const prep = await spotbugsAnalyzer.prepare(
        fakeContext(root, {
          binaries: { spotbugs: install.launcher, java: JAVA },
          env: { JAVA_HOME: javaHome },
        }),
      );
      return 'run' in prep ? prep.run.command : JSON.stringify(prep);
    };
    const outside = tmp();
    const java = jdk(outside);
    expect(await command(outside)).toBe(java);
    // Inside the checkout, relative, or without bin/java: the java from PATH.
    jdk(path.join(root, 'jdk'));
    expect(await command(path.join(root, 'jdk'))).toBe(JAVA);
    expect(await command('jdk')).toBe(JAVA);
    expect(await command(tmp())).toBe(JAVA);
  });

  it('skips without compiled classes, with a missing aux classpath file, or without spotbugs', async () => {
    const root = tmp();
    expect(await spotbugsAnalyzer.prepare(fakeContext(root))).toEqual({
      skip: 'no compiled classes in target/classes, build/classes/java/main (build the project before qualor scan)',
    });
    writeTree(root, { 'target/classes/A.class': 'x' });
    expect(
      await spotbugsAnalyzer.prepare(
        fakeContext(root, { config: { analyzers: { spotbugs: { auxClasspathFile: 'cp.txt' } } } }),
      ),
    ).toEqual({ skip: 'auxClasspathFile cp.txt does not exist' });
    expect(await spotbugsAnalyzer.prepare(fakeContext(root))).toEqual({
      unavailable: 'SpotBugs is not installed (spotbugs on PATH or in the scanner image)',
    });
  });

  it('refuses class directories and an aux classpath file outside the repository', async () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'classes/A.class': 'x', 'cp.txt': '/m2/lib.jar\n' });
    writeTree(root, { 'target/classes/A.class': 'x' });
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    const prepare = (spotbugs: Record<string, unknown>) =>
      spotbugsAnalyzer.prepare(
        fakeContext(root, {
          config: { analyzers: { spotbugs } },
          binaries: { spotbugs: '/opt/qualor/bin/spotbugs' },
        }),
      );
    const absClasses = path.join(outside, 'classes');
    const relClasses = path.relative(root, absClasses).split(path.sep).join('/');
    for (const dir of [absClasses, relClasses, 'linked/classes']) {
      expect(await prepare({ classDirs: ['target/classes', dir] }), dir).toEqual({
        skip: `classDirs entry ${dir} is outside the repository`,
      });
    }
    for (const cp of [path.join(outside, 'cp.txt'), 'linked/cp.txt']) {
      expect(await prepare({ auxClasspathFile: cp }), cp).toEqual({
        skip: `auxClasspathFile ${cp} is outside the repository`,
      });
    }
  });

  it('ignores linked directories (SpotBugs does not follow them) but refuses a linked file from outside', async () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'com/Secret.class': 'x' });
    writeTree(root, { 'target/classes/A.class': 'x' });
    const install = fakeInstall();
    const ctx = () =>
      fakeContext(root, {
        binaries: { spotbugs: install.launcher, java: JAVA },
        workDir: tmp(),
      });
    symlinkSync(outside, path.join(root, 'target', 'classes', 'deep'), 'junction');
    expect('run' in (await spotbugsAnalyzer.prepare(ctx()))).toBe(true);
    if (!CAN_SYMLINK_FILES) return;
    symlinkSync(
      path.join(outside, 'com', 'Secret.class'),
      path.join(root, 'target', 'classes', 'Secret.class'),
      'file',
    );
    expect(await spotbugsAnalyzer.prepare(ctx())).toEqual({
      skip: 'classDirs entry target/classes links outside the repository',
    });
  });

  it('passes paths with spaces and line breaks as single arguments, and caps long lists', async () => {
    const root = tmp();
    const install = fakeInstall();
    const odd = process.platform === 'win32' ? 'odd dir' : 'a\n-pluginList\nevil dir';
    writeTree(root, { [`${odd}/classes/B.class`]: 'x' });
    const prepare = (spotbugs: Record<string, unknown>, files: ScopeFile[] = []) =>
      spotbugsAnalyzer.prepare({
        ...fakeContext(root, {
          config: { analyzers: { spotbugs } },
          binaries: { spotbugs: install.launcher, java: JAVA },
        }),
        files,
      });
    const prep = await prepare({ classDirs: [`${odd}/classes`] });
    if (!('run' in prep)) throw new Error(JSON.stringify(prep));
    expect(prep.run.args.at(-1)).toBe(path.join(root, odd, 'classes'));
    expect(prep.run.args).not.toContain('-pluginList');
    // The "no compiled classes" reason names five entries and counts the rest.
    const many = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
    expect(await prepare({ classDirs: many })).toEqual({
      skip: 'no compiled classes in a, b, c, d, e and 2 more (build the project before qualor scan)',
    });
    // -sourcepath keeps only the roots that fit in 32 KiB.
    const roots = Array.from({ length: 2000 }, (_, i) =>
      file(`module-${String(i).padStart(4, '0')}-${'x'.repeat(40)}/src/main/java/A.java`),
    );
    const capped = await prepare({ classDirs: [`${odd}/classes`] }, roots);
    if (!('run' in capped)) throw new Error(JSON.stringify(capped));
    const sourcepath = capped.run.args[capped.run.args.indexOf('-sourcepath') + 1] ?? '';
    expect(sourcepath.length).toBeLessThanOrEqual(32 * 1024);
    expect(sourcepath.split(path.delimiter).length).toBeGreaterThan(100);
  });
});

describe('SpotBugs SARIF (recorded SpotBugs 4.10.4 output on java-basic)', () => {
  it('normalises to exactly the fixture findings, with java rules and their CWEs', () => {
    const out = normalizeRecorded(sarifSample('spotbugs'), spotbugsAnalyzer, 'java-basic', [
      'src/main/java',
    ]);
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('java-basic', 'spotbugs'));
    expect(out.engines[0]?.version).toBe('4.10.4');
    expect(out.engines[0]?.rules.map((r) => [r.id, r.cwe, r.languages])).toEqual([
      ['ES_COMPARING_PARAMETER_STRING_WITH_EQ', [595], ['java']],
      ['UUF_UNUSED_FIELD', [563], ['java']],
    ]);
  });
});

describe('SpotBugs with FindSecBugs SARIF (recorded run over java-security, plan 6A)', () => {
  it('normalises to the fixture findings, with kinds from the table and the plugin in the version', () => {
    const out = normalizeRecorded(
      withFindsecbugsVersion(sarifSample('findsecbugs'), '1.14.0'),
      spotbugsAnalyzer,
      'java-security',
      ['src/main/java'],
    );
    expect(out.warnings).toEqual([]);
    expect(findingKeys(out.findings)).toEqual(expectedKeys('java-security', 'spotbugs'));
    expect(out.engines[0]?.version).toBe('4.10.4 + FindSecBugs 1.14.0');
    const kind = (id: string) => out.engines[0]?.rules.find((r) => r.id === id)?.kind;
    expect(kind('SQL_INJECTION_JDBC')).toBe('issue');
    expect(kind('PREDICTABLE_RANDOM')).toBe('hotspot');
    expect(kind('DMI_HARDCODED_ABSOLUTE_FILENAME')).toBe('issue');
  });
});

describeWithTools(['spotbugs', 'javac'])(
  'SpotBugs on the java-basic fixture (real SpotBugs)',
  () => {
    it(
      'reports exactly the fixture findings once the classes are compiled',
      { timeout: 300_000 },
      async () => {
        const { capture, keys } = await scanFixtureWith(
          spotbugsAnalyzer,
          'java-basic',
          tmp(),
          compileJava,
        );
        expect(capture.version).toBeNull();
        expect(keys).toEqual(expectedKeys('java-basic', 'spotbugs'));
      },
    );

    it.runIf(process.platform !== 'win32')(
      'runs the system java even when PATH lists a java inside the repository',
      { timeout: 300_000 },
      async () => {
        const root = tmp();
        const marker = path.join(root, 'pwned');
        cpSync(path.join(FIXTURES_DIR, 'java-basic'), root, { recursive: true });
        compileJava(root);
        writeTree(root, {
          'bin/java': `#!/bin/sh\necho java > ${JSON.stringify(marker)}\nexit 1\n`,
        });
        chmodSync(path.join(root, 'bin', 'java'), 0o755);
        // Without JAVA_HOME the launcher runs the `java` it finds on PATH.
        const env: Record<string, string | undefined> = {
          ...process.env,
          PATH: `bin:${path.join(root, 'bin')}:${process.env['PATH'] ?? ''}`,
        };
        delete env['JAVA_HOME'];
        const [capture] = await runAnalyzers([spotbugsAnalyzer], {
          root,
          config: parseConfig({ version: 1 }),
          files: [
            {
              ...file('src/main/java/com/acme/Calculator.java'),
              absPath: path.join(root, 'src', 'main', 'java', 'com', 'acme', 'Calculator.java'),
            },
          ],
          log: silentLogger,
          env,
        });
        expect(existsSync(marker)).toBe(false);
        expect(capture?.status).toBe('ok');
      },
    );

    it(
      'analyses a class directory whose path has a space (the jar runs without the launcher)',
      { timeout: 300_000 },
      async () => {
        const { keys } = await scanFixtureWith(spotbugsAnalyzer, 'java-basic', tmp(), (root) => {
          compileJava(root);
          mkdirSync(path.join(root, 'build out'));
          renameSync(path.join(root, 'target', 'classes'), path.join(root, 'build out', 'classes'));
          writeFileSync(
            path.join(root, 'qualor.yml'),
            'version: 1\nanalyzers:\n  spotbugs:\n    classDirs: [build out/classes]\n',
          );
        });
        expect(keys).toEqual(expectedKeys('java-basic', 'spotbugs'));
      },
    );

    it(
      'sends no request for an aux classpath URL (ruling V5 dead proxy)',
      { timeout: 300_000 },
      async () => {
        const listener = await startListener();
        try {
          const { capture } = await scanFixtureWith(
            spotbugsAnalyzer,
            'java-basic',
            tmp(),
            (root) => {
              compileJava(root);
              writeFileSync(path.join(root, 'deps.txt'), `${listener.url}/aux.jar\n`);
              writeFileSync(
                path.join(root, 'qualor.yml'),
                'version: 1\nanalyzers:\n  spotbugs:\n    auxClasspathFile: deps.txt\n',
              );
            },
          );
          expect(capture.status).toBe('ok');
          expect(listener.hits).toEqual([]);
        } finally {
          await listener.close();
        }
      },
    );
  },
);
