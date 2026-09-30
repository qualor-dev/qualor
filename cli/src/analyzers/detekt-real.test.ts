import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { engineMapping, parseConfig, splitSourceLines } from '@qualor/shared';
import { expect, it } from 'vitest';
import {
  describeWithDetekt,
  expectedKeys,
  REQUIRE_ANALYZERS,
  scanFixtureWith,
  toolInstalled,
} from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { resolveBinary } from './binary';
import { DEFAULT_DETEKT_JAR, detektAnalyzer } from './detekt';
import { normalizeCaptures } from './normalize';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
/** Symbolic links and `#!/bin/sh` programs: POSIX only. */
const itPosix = it.runIf(posix);
/** Also builds a rule set provider jar with the JDK's `javac` and `jar`. */
const itHostile = it.runIf(
  posix && (REQUIRE_ANALYZERS || (toolInstalled('javac') && toolInstalled('jar'))),
);
const TIMEOUT = { timeout: 180_000 };

function kt(root: string, p: string): ScopeFile {
  return {
    path: p,
    absPath: path.join(root, ...p.split('/')),
    language: 'kotlin',
    grammar: 'kotlin',
    kind: 'main',
    size: 40,
  };
}

/**
 * A class with two magic numbers on line 4: `MagicNumber` reports 42 and 7. An expression, not a
 * property declaration, which the Compose layer ignores without a project config.
 */
const MAGIC = 'package a\n\nclass A {\n    fun f() = 42 * 7\n}\n';

/**
 * A Jetpack Compose screen (no Compose on the class path: detekt runs without type resolution):
 * PascalCase composables, a private `@Preview`, a screen of 7 parameters of which 4 are defaulted,
 * and one unused parameter, a genuine finding.
 */
const COMPOSE = `package a

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(text = "Hello $name", modifier = modifier)
}

@Composable
fun ProfileScreen(
    name: String,
    email: String,
    age: Int,
    modifier: Modifier = Modifier,
    onSave: () -> Unit = {},
    onCancel: () -> Unit = {},
    onDelete: () -> Unit = {},
) {
    Greeting(name, modifier)
}

@Preview
@Composable
private fun GreetingPreview() {
    Greeting("Android")
}
`;

/** The rule ids of the findings, each once, sorted. */
function ruleIds(findings: readonly { ruleId: string }[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))].sort();
}

/** Runs the real detekt adapter over `paths` and normalises its findings as `runScan` does. */
async function scan(
  root: string,
  paths: readonly string[],
  o: { config?: Parameters<typeof parseConfig>[0]; env?: Record<string, string | undefined> } = {},
) {
  const [capture] = await runAnalyzers([detektAnalyzer], {
    root,
    config: parseConfig(o.config ?? { version: 1 }),
    files: paths.map((p) => kt(root, p)),
    log: silentLogger,
    env: o.env ?? process.env,
  });
  if (capture === undefined) throw new Error('no capture');
  const out =
    capture.status === 'ok'
      ? normalizeCaptures([{ ...capture, mapping: engineMapping('detekt')! }], {
          repoRoot: root,
          readLines: (p) => {
            try {
              return splitSourceLines(readFileSync(path.join(root, p), 'utf8'));
            } catch {
              return null;
            }
          },
          knownPaths: new Set(paths),
          log: silentLogger,
        })
      : null;
  return { capture, findings: out?.findings ?? [] };
}

function magicLines(findings: readonly { ruleId: string; location: unknown }[]): string[] {
  return findings
    .filter((f) => f.ruleId === 'MagicNumber')
    .map((f) => {
      const l = f.location as { path: string; startLine: number; startColumn?: number } | null;
      return `${l?.path}:${l?.startLine}:${l?.startColumn ?? ''}`;
    })
    .sort();
}

describeWithDetekt()('detekt on kotlin-basic (real detekt)', () => {
  it('reports the fixture’s findings with the project’s own config', TIMEOUT, async () => {
    const { keys } = await scanFixtureWith(detektAnalyzer, 'kotlin-basic', tmp());
    expect(keys).toEqual(expectedKeys('kotlin-basic', 'detekt'));
  });

  it(
    'runs a config written for another detekt version and survives a config that fights the run (Review Focus 1, 2)',
    TIMEOUT,
    async () => {
      const outside = path.join(tmp(), 'template.txt');
      writeFileSync(outside, 'SECRET-TEMPLATE-TEXT\n');
      const { out, capture } = await scanFixtureWith(
        detektAnalyzer,
        'kotlin-basic',
        tmp(),
        (root) => {
          writeFileSync(
            path.join(root, 'config', 'detekt', 'detekt.yml'),
            [
              'config:',
              '  validation: true',
              '  warningsAsErrors: true',
              'build:',
              '  maxIssues: 1000',
              'output-reports:',
              '  active: false',
              '  exclude: ["SarifOutputReport"]',
              'style:',
              '  NoSuchRuleInDetekt123:',
              '    active: true',
              // A rule set detekt 1.23.8 does not have, as a config for a later version would name.
              'no-such-rule-set-in-detekt-1:',
              '  active: true',
              '  SomeRule:',
              '    active: true',
              'comments:',
              '  AbsentOrWrongFileLicense:',
              '    active: true',
              `    licenseTemplateFile: ${JSON.stringify(outside)}`,
              '',
            ].join('\n'),
          );
        },
      );
      expect(capture.status).toBe('ok');
      expect(out.findings.some((f) => f.ruleId === 'AbsentOrWrongFileLicense')).toBe(false);
      expect(JSON.stringify(out)).not.toContain('SECRET-TEMPLATE-TEXT');
      expect(JSON.stringify(capture.sarif)).not.toContain('SECRET-TEMPLATE-TEXT');
    },
  );
});

describeWithDetekt()(
  'detekt on Jetpack Compose code (real detekt, final review Important 1)',
  () => {
    const COMPOSE_NOISE = ['FunctionNaming', 'LongParameterList', 'UnusedPrivateMember'];

    it(
      'without a project config: no Compose false positive, genuine findings stay',
      TIMEOUT,
      async () => {
        const root = tmp();
        writeTree(root, {
          'src/main/kotlin/a/Screen.kt': COMPOSE,
          'src/main/kotlin/a/A.kt': MAGIC,
        });
        const { capture, findings } = await scan(root, [
          'src/main/kotlin/a/Screen.kt',
          'src/main/kotlin/a/A.kt',
        ]);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        const ids = ruleIds(findings);
        for (const noise of COMPOSE_NOISE) expect(ids).not.toContain(noise);
        expect(ids).toContain('UnusedParameter');
        expect(magicLines(findings)).toEqual([
          'src/main/kotlin/a/A.kt:4:15',
          'src/main/kotlin/a/A.kt:4:20',
        ]);
      },
    );

    it(
      'with a project config that does not set them: detekt’s own defaults, the layer is not used',
      TIMEOUT,
      async () => {
        const root = tmp();
        writeTree(root, {
          'src/main/kotlin/a/Screen.kt': COMPOSE,
          'config/detekt/detekt.yml': 'style:\n  WildcardImport:\n    active: true\n',
        });
        const { capture, findings } = await scan(root, ['src/main/kotlin/a/Screen.kt']);
        expect(capture.status, capture.reason ?? '').toBe('ok');
        const ids = ruleIds(findings);
        for (const noise of COMPOSE_NOISE) expect(ids).toContain(noise);
        expect(ids).toContain('UnusedParameter');
      },
    );
  },
);

describeWithDetekt()('detekt failures say why (real detekt, final review minor 3)', () => {
  it(
    'a project config value of the wrong type fails detekt, with the reason in the log only',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'src/A.kt': MAGIC,
        'config/detekt/detekt.yml': 'style:\n  MaxLineLength:\n    maxLineLength: abc\n',
      });
      const lines: string[] = [];
      const [capture] = await runAnalyzers([detektAnalyzer], {
        root,
        config: parseConfig({ version: 1 }),
        files: [kt(root, 'src/A.kt')],
        log: createLogger('warn', (t) => lines.push(t)),
        env: process.env,
      });
      expect(capture).toMatchObject({ status: 'failed', reason: 'exited with code 1' });
      expect(lines.join('\n')).toContain(
        'detekt: src/A.kt: The original exception message was: Value "abc" set for config parameter "style > MaxLineLength > maxLineLength" is not of required type Int.',
      );
      expect(lines.join('\n')).not.toContain('detekt-input');
    },
  );
});

/** detekt's rule set provider interface: a jar that implements it is a detekt plugin. */
const PROVIDER = 'io.gitlab.arturbosch.detekt.api.RuleSetProvider';

/** Where the hostile checkout plants its plugin jar: nothing may load any of them. */
const PLANTED_JARS = [
  'evil.jar',
  'plugins/evil.jar',
  'config/detekt/evil.jar',
  'config/detekt/plugins/evil.jar',
  'src/main/kotlin/evil.jar',
];

/**
 * A checkout that tries every way detekt could run its code: a java on PATH and in JAVA_HOME, and
 * a real detekt rule set provider (a ServiceLoader entry whose class implements detekt's
 * interface, so loading it runs its static initialiser, which writes the marker) as loose classes
 * at the root and as a plugin jar in every place a project keeps one. None may run.
 */
function hostileKotlinRepo(root: string): string {
  const marker = path.join(root, 'pwned');
  writeTree(root, {
    'src/A.kt': 'package a\n\nclass A\n',
    'evil/Evil.java': `public class Evil implements ${PROVIDER} {
  static { try { java.nio.file.Files.writeString(java.nio.file.Path.of(${JSON.stringify(marker)}), "class"); } catch (Exception e) { } }
  public String getRuleSetId() { return "evil"; }
  public io.gitlab.arturbosch.detekt.api.RuleSet instance(io.gitlab.arturbosch.detekt.api.Config c) {
    return new io.gitlab.arturbosch.detekt.api.RuleSet("evil", java.util.List.of());
  }
}
`,
    [`META-INF/services/${PROVIDER}`]: 'Evil\n',
    'bin/java': `#!/bin/sh\necho path > ${JSON.stringify(marker)}\nexit 1\n`,
    'jdk/bin/java': `#!/bin/sh\necho home > ${JSON.stringify(marker)}\nexit 1\n`,
  });
  chmodSync(path.join(root, 'bin', 'java'), 0o755);
  chmodSync(path.join(root, 'jdk', 'bin', 'java'), 0o755);
  const javac = resolveBinary('javac', { root, env: process.env });
  if (javac === null) throw new Error('javac is not installed');
  const built = spawnSync(
    javac,
    ['-cp', DEFAULT_DETEKT_JAR, '-d', root, path.join(root, 'evil', 'Evil.java')],
    { encoding: 'utf8' },
  );
  expect(built.status, built.stderr).toBe(0);
  const jar = resolveBinary('jar', { root, env: process.env });
  if (jar === null) throw new Error('jar is not installed');
  const packed = path.join(root, 'evil.jar');
  const r = spawnSync(jar, ['cf', packed, '-C', root, 'Evil.class', '-C', root, 'META-INF'], {
    encoding: 'utf8',
  });
  expect(r.status, r.stderr).toBe(0);
  for (const rel of PLANTED_JARS.slice(1)) {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    copyFileSync(packed, path.join(root, rel));
  }
  return marker;
}

function markerText(marker: string): string {
  return existsSync(marker) ? readFileSync(marker, 'utf8') : '';
}

describeWithDetekt()('detekt never runs code from the repository (real detekt)', () => {
  itHostile(
    'the planted rule set provider is real: detekt handed the jar does run it (control)',
    TIMEOUT,
    () => {
      const root = tmp();
      const marker = hostileKotlinRepo(root);
      const java = resolveBinary('java', { root, env: process.env });
      if (java === null) throw new Error('java is not installed');
      const r = spawnSync(
        java,
        [
          '-jar',
          DEFAULT_DETEKT_JAR,
          '--input',
          path.join(root, 'src'),
          '--plugins',
          path.join(root, 'plugins', 'evil.jar'),
        ],
        { cwd: tmp(), encoding: 'utf8', timeout: 120_000 },
      );
      expect(markerText(marker), r.stderr).toBe('class');
    },
  );

  itHostile(
    'ignores a java in PATH or JAVA_HOME inside the checkout and a class path into it',
    TIMEOUT,
    async () => {
      const root = tmp();
      const marker = hostileKotlinRepo(root);
      const { capture } = await scan(root, ['src/A.kt'], {
        env: {
          ...process.env,
          PATH: `bin:${path.join(root, 'bin')}:${process.env['PATH'] ?? ''}`,
          JAVA_HOME: path.join(root, 'jdk'),
          CLASSPATH: `.:${root}:${path.join(root, 'plugins', 'evil.jar')}`,
        },
      });
      expect(existsSync(marker), markerText(marker)).toBe(false);
      expect(capture.status, capture.reason ?? '').toBe('ok');
    },
  );

  itHostile(
    'loads no detekt config, baseline or plugin jar the checkout plants, only its checked project config',
    TIMEOUT,
    async () => {
      const root = tmp();
      const marker = hostileKotlinRepo(root);
      const off = 'style:\n  MagicNumber:\n    active: false\n';
      const baseline = [
        '<?xml version="1.0" ?>',
        '<SmellBaseline>',
        '  <ManuallySuppressedIssues/>',
        '  <CurrentIssues>',
        '    <ID>MagicNumber:A.kt$A$42</ID>',
        '    <ID>MagicNumber:A.kt$A$7</ID>',
        '  </CurrentIssues>',
        '</SmellBaseline>',
        '',
      ].join('\n');
      writeTree(root, {
        'src/main/kotlin/a/A.kt': MAGIC,
        // The checked project config: 7 is not a magic number here, 42 still is.
        'config/detekt/detekt.yml':
          "style:\n  MagicNumber:\n    ignoreNumbers: ['-1', '0', '1', '2', '7']\n",
        // Every other config a project could keep: each would switch MagicNumber off.
        'detekt.yml': off,
        '.detekt.yml': off,
        'config/detekt.yml': off,
        'config/detekt/config.yml': off,
        'detekt-config.yml': off,
        'src/main/kotlin/detekt.yml': off,
        'src/main/kotlin/a/detekt.yml': off,
        // Every baseline a project could keep: each would hide both findings.
        'detekt-baseline.xml': baseline,
        'baseline.xml': baseline,
        'config/detekt/baseline.xml': baseline,
        'config/detekt/detekt-baseline.xml': baseline,
        'src/main/kotlin/a/baseline.xml': baseline,
      });
      const { capture, findings } = await scan(root, ['src/main/kotlin/a/A.kt']);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(existsSync(marker), markerText(marker)).toBe(false);
      // 42 is reported (no planted config or baseline was read), 7 is not (the project config was).
      expect(magicLines(findings)).toEqual(['src/main/kotlin/a/A.kt:4:15']);
    },
  );

  itHostile(
    'a project config with plugin or class path keys cannot load code (structural pin: detekt 1.23.8 reads none of these keys)',
    TIMEOUT,
    async () => {
      const root = tmp();
      const marker = hostileKotlinRepo(root);
      const jars = PLANTED_JARS.map((j) => JSON.stringify(path.join(root, j)));
      writeTree(root, {
        'config/detekt/detekt.yml': [
          `plugins: [${jars.join(', ')}]`,
          `classpath: ${jars[0]}`,
          `jdkHome: ${JSON.stringify(path.join(root, 'jdk'))}`,
          `baseline: ${JSON.stringify(path.join(root, 'detekt-baseline.xml'))}`,
          'config:',
          `  plugins: [${jars.join(', ')}]`,
          `  classpath: ${jars[0]}`,
          'detekt:',
          `  plugins: [${jars.join(', ')}]`,
          '  autoCorrect: true',
          'processors:',
          '  active: true',
          `  exclude: []`,
          'console-reports:',
          '  active: true',
          'evil:',
          '  active: true',
          '',
        ].join('\n'),
      });
      const { capture } = await scan(root, ['src/A.kt']);
      expect(existsSync(marker), markerText(marker)).toBe(false);
      expect(capture.status, capture.reason ?? '').toBe('ok');
    },
  );

  itPosix(
    'never copies or lints a Kotlin file reached through a symbolic link that leaves the root',
    TIMEOUT,
    async () => {
      const root = tmp();
      const outside = tmp();
      writeTree(root, { 'src/A.kt': MAGIC });
      writeTree(outside, {
        'Outside.kt': 'package o\n\nclass Outside {\n    val y = 4242\n}\n',
        'dir/B.kt': 'package o\n\nclass B {\n    val z = 4343\n}\n',
      });
      symlinkSync(path.join(outside, 'Outside.kt'), path.join(root, 'src', 'Linked.kt'));
      symlinkSync(path.join(outside, 'dir'), path.join(root, 'linked'));
      const { capture, findings } = await scan(root, ['src/A.kt', 'src/Linked.kt', 'linked/B.kt']);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(magicLines(findings)).toEqual(['src/A.kt:4:15', 'src/A.kt:4:20']);
      const sarif = JSON.stringify(capture.sarif);
      expect(sarif).not.toContain('Linked.kt');
      expect(sarif).not.toContain('B.kt');
      expect(sarif).not.toContain('4242');
      expect(sarif).not.toContain('4343');
    },
  );

  itPosix(
    'refuses a detekt config whose symbolic link leaves the root: a skip under auto, a failure under enabled: true',
    TIMEOUT,
    async () => {
      const outside = tmp();
      writeTree(outside, {
        'detekt.yml': 'style:\n  MagicNumber:\n    active: false\n',
        'dir/detekt.yml': 'style:\n  MagicNumber:\n    active: false\n',
      });
      // The file itself is a link out, and a directory on the way is a link out.
      const fileLink = tmp();
      writeTree(fileLink, { 'src/A.kt': MAGIC });
      mkdirSync(path.join(fileLink, 'config', 'detekt'), { recursive: true });
      symlinkSync(
        path.join(outside, 'detekt.yml'),
        path.join(fileLink, 'config', 'detekt', 'detekt.yml'),
      );
      const dirLink = tmp();
      writeTree(dirLink, { 'src/A.kt': MAGIC });
      mkdirSync(path.join(dirLink, 'config'));
      symlinkSync(path.join(outside, 'dir'), path.join(dirLink, 'config', 'detekt'));
      for (const root of [fileLink, dirLink]) {
        const auto = await scan(root, ['src/A.kt']);
        expect(auto.capture.status).toBe('skipped');
        expect(auto.capture.reason).toBe('config/detekt/detekt.yml is outside the repository');
        const required = await scan(root, ['src/A.kt'], {
          config: { version: 1, analyzers: { detekt: { enabled: true } } },
        });
        expect(required.capture.status).toBe('failed');
        expect(required.capture.reason).toBe('config/detekt/detekt.yml is outside the repository');
      }
    },
  );

  itPosix(
    'reads a detekt config whose symbolic link stays inside the root (ruling E6, control)',
    TIMEOUT,
    async () => {
      const root = tmp();
      writeTree(root, {
        'src/A.kt': MAGIC,
        'shared/detekt.yml': "style:\n  MagicNumber:\n    ignoreNumbers: ['7']\n",
      });
      mkdirSync(path.join(root, 'config', 'detekt'), { recursive: true });
      symlinkSync(
        path.join('..', '..', 'shared', 'detekt.yml'),
        path.join(root, 'config', 'detekt', 'detekt.yml'),
      );
      const { capture, findings } = await scan(root, ['src/A.kt']);
      expect(capture.status, capture.reason ?? '').toBe('ok');
      expect(magicLines(findings)).toEqual(['src/A.kt:4:15']);
    },
  );
});
