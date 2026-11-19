import { chmodSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { checkFixUpload, type FixClaimItem, type FixFileChange } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import type { FixWorkspace } from './adapter';
import { mavenAdapter } from './maven';
import { prepareFix, type FixOutcome } from './run';
import type { ToolResult, ToolRunner } from './runner';
import { resolveTool } from './shim';
import { familyFiles, servedFamilies } from './tools';
import { openScratch } from './workspace';

/**
 * The Maven adapter (Task 15) with a fake `mvn` (R27): every `dependency:tree` answer is output
 * recorded as `mvn -B` prints it (Maven 3.9, maven-dependency-plugin 3.8.1), `[INFO]` prefixes and
 * tree characters included. Maven and Java are not needed.
 */

const tmp = useTempDirs();
const SPRING = 'org.springframework:spring-core';
const TREE_ARGS = ['-B', 'dependency:tree', `-Dincludes=${SPRING}`, '-DoutputType=text'];
const EIGHT_MIB = 8 * 1024 * 1024;

// ─── Poms ───────────────────────────────────────────────────────────────────

/** A `<dependency>` at a 4-space indent, its children at 6; no `<version>` when `version` is null. */
function dep(ga: string, version: string | null, extra: string[] = []): string {
  const [groupId, artifactId] = ga.split(':');
  return [
    '    <dependency>',
    `      <groupId>${groupId}</groupId>`,
    `      <artifactId>${artifactId}</artifactId>`,
    ...(version === null ? [] : [`      <version>${version}</version>`]),
    ...extra.map((line) => `      ${line}`),
    '    </dependency>',
    '',
  ].join('\n');
}

/** A one-module pom `com.example:app:1.0.0` with `head` before its `<dependencies>`. */
function pom(dependencies: string, head = '', artifactId = 'app'): string {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<project>',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>com.example</groupId>',
    `  <artifactId>${artifactId}</artifactId>`,
    '  <version>1.0.0</version>',
    `${head}  <dependencies>`,
    `${dependencies}  </dependencies>`,
    '</project>',
    '',
  ].join('\n');
}

const PARENT = [
  '  <parent>',
  '    <groupId>com.example</groupId>',
  '    <artifactId>app-parent</artifactId>',
  '    <version>1.0.0</version>',
  '  </parent>',
  '',
].join('\n');

// ─── Recorded mvn output ────────────────────────────────────────────────────

/** One module of a reactor: `g:a:packaging:version`, its pom, and its filtered tree's lines. */
interface Module {
  coords: string;
  pom: string;
  tree: string[];
}

const RULE = '------------------------------------------------------------------------';

/** `-----< g:a >-----`, as Maven centres it in 72 columns. */
function banner(text: string): string {
  const left = Math.floor((72 - text.length) / 2);
  return `${'-'.repeat(left)}${text}${'-'.repeat(72 - text.length - left)}`;
}

function moduleLines(m: Module, i: number, total: number): string[] {
  const [groupId, artifactId, packaging, version] = m.coords.split(':');
  const counter = total > 1 ? `${' '.repeat(40)}[${i + 1}/${total}]` : '';
  const project = banner('< ' + groupId + ':' + artifactId + ' >');
  const kind = banner('[ ' + packaging + ' ]');
  return [
    '[INFO] ',
    `[INFO] ${project}`,
    `[INFO] Building ${artifactId} ${version}${counter}`,
    `[INFO]   from ${m.pom}`,
    `[INFO] ${kind}`,
    '[INFO] ',
    `[INFO] --- dependency:3.8.1:tree (default-cli) @ ${artifactId} ---`,
    ...(m.tree.length === 0 ? [] : [`[INFO] ${m.coords}`, ...m.tree.map((l) => `[INFO] ${l}`)]),
  ];
}

/** What `mvn -B dependency:tree -Dincludes=… -DoutputType=text` prints for a reactor. */
function mavenOutput(modules: Module[], o: { between?: string[]; end?: string[] } = {}): string {
  const order =
    modules.length > 1
      ? [
          `[INFO] ${RULE}`,
          '[INFO] Reactor Build Order:',
          '[INFO] ',
          ...modules.map(
            (m) => `[INFO] ${(m.coords.split(':')[1] ?? '').padEnd(66)}[${m.coords.split(':')[2]}]`,
          ),
        ]
      : [];
  const body = modules.flatMap((m, i) => {
    const lines = moduleLines(m, i, modules.length);
    // Downloads come after the goal's header, before the tree (the collection reads POMs).
    return i === 0 ? [...lines.slice(0, 7), ...(o.between ?? []), ...lines.slice(7)] : lines;
  });
  const end = o.end ?? [
    `[INFO] ${RULE}`,
    '[INFO] BUILD SUCCESS',
    `[INFO] ${RULE}`,
    '[INFO] Total time:  1.482 s',
    '[INFO] Finished at: 2026-11-19T10:15:42Z',
    `[INFO] ${RULE}`,
  ];
  return `${['[INFO] Scanning for projects...', ...order, ...body, ...end].join('\n')}\n`;
}

const DOWNLOADS = [
  '[INFO] Downloading from central: https://repo.maven.apache.org/maven2/org/springframework/spring-core/5.2.20.RELEASE/spring-core-5.2.20.RELEASE.pom',
  '[INFO] Downloaded from central: https://repo.maven.apache.org/maven2/org/springframework/spring-core/5.2.20.RELEASE/spring-core-5.2.20.RELEASE.pom (3.4 kB at 41 kB/s)',
];

/** A one-module app whose tree has the package directly at `version`. */
const directTree = (version: string, extra: string[] = []) =>
  mavenOutput(
    [
      {
        coords: 'com.example:app:jar:1.0.0',
        pom: 'pom.xml',
        tree: [...extra, `\\- ${SPRING}:jar:${version}:compile`],
      },
    ],
    { between: DOWNLOADS },
  );

/** A one-module app that gets the package through spring-context. */
const transitiveTree = (version: string, suffix = '') =>
  mavenOutput([
    {
      coords: 'com.example:app:jar:1.0.0',
      pom: 'pom.xml',
      tree: [
        '\\- org.springframework:spring-context:jar:5.2.20.RELEASE:compile',
        `   \\- ${SPRING}:jar:${version}:compile${suffix}`,
      ],
    },
  ]);

const ok = (stdout: string): ToolResult => ({
  exitCode: 0,
  timedOut: false,
  stdout,
  stderr: '',
  truncated: false,
});

// ─── Running a fix ──────────────────────────────────────────────────────────

function committed(files: Record<string, string>): string {
  const dir = tmp('qualor-fix-mvn-');
  initRepo(dir);
  writeTree(dir, files);
  commitAll(dir, 'base');
  return dir;
}

function claim(installed: string[], fixed: string[]): FixClaimItem {
  return {
    id: '0193a4c6-1c2e-7a3b-9f00-000000000003',
    generation: 1,
    leaseToken: 'lease-1',
    family: 'maven',
    packageName: SPRING,
    installedVersions: installed,
    vulnerabilities: [
      {
        id: 'CVE-2022-22965',
        severity: 'critical',
        title: 'Spring4Shell',
        url: null,
        installedVersions: installed,
        fixedVersions: fixed,
      },
    ],
    mainBranch: 'main',
    declinedTarget: null,
  };
}

interface Call {
  tool: string;
  args: string[];
  /** The folder it ran in, relative to the scratch copy ('' at its root). */
  cwd: string;
  outputLimitBytes: number | undefined;
}

interface Fixed {
  outcome: FixOutcome;
  calls: Call[];
  files: Map<string, FixFileChange>;
  /** `git diff --cached -U0` of each uploaded path in the scratch copy. */
  diffs: Map<string, string>;
}

/**
 * A fake `mvn` answering each call with the next recorded answer (a string is a successful run's
 * stdout), as much of its end as the call keeps (`outputLimitBytes`, else 64 KiB), as the runner does.
 */
function fakeMvn(answers: (string | ToolResult)[]): ToolRunner {
  const queue = [...answers];
  return (tool, _args, call) => {
    const next = queue.shift();
    if (tool !== 'mvn' || next === undefined) {
      return Promise.reject(new Error(`unexpected ${tool} call`));
    }
    const r = typeof next === 'string' ? ok(next) : next;
    const limit = call.outputLimitBytes ?? 64 * 1024;
    return Promise.resolve({
      ...r,
      stdout: r.stdout.slice(Math.max(0, r.stdout.length - limit)),
      truncated: r.truncated || r.stdout.length > limit,
    });
  };
}

async function fix(
  dir: string,
  item: FixClaimItem,
  answers: (string | ToolResult)[],
): Promise<Fixed> {
  const git = createGit(dir, GIT_TEST_ENV);
  const scratch = await openScratch(git, tmp('qualor-fix-temp-'));
  const calls: Call[] = [];
  const fake = fakeMvn(answers);
  const run: ToolRunner = (tool, args, call) => {
    const cwd = path.relative(scratch.root, call.cwd).replaceAll('\\', '/');
    calls.push({ tool, args: [...args], cwd, outputLimitBytes: call.outputLimitBytes });
    return fake(tool, args, call);
  };
  try {
    const ws: FixWorkspace = {
      root: scratch.root,
      files: gitSync(dir, 'ls-files').split('\n'),
      run,
      deadline: Date.now() + 60_000,
      log: silentLogger,
    };
    const outcome = await prepareFix(item, mavenAdapter, ws, git);
    const files = new Map<string, FixFileChange>();
    const diffs = new Map<string, string>();
    for (const f of 'files' in outcome ? outcome.files : []) {
      const next = Buffer.from(f.content, 'base64').toString('utf8');
      files.set(f.path, { path: f.path, base: readFileSync(path.join(dir, f.path), 'utf8'), next });
      diffs.set(f.path, gitSync(scratch.root, 'diff', '--cached', '-U0', '--', f.path));
    }
    return { outcome, calls, files, diffs };
  } finally {
    await scratch.close();
  }
}

function uploaded(r: Fixed): Extract<FixOutcome, { files: unknown }> {
  if (!('files' in r.outcome)) throw new Error(`expected files, got ${JSON.stringify(r.outcome)}`);
  return r.outcome;
}

function textOf(r: Fixed, file: string): string {
  const change = r.files.get(file);
  if (change === undefined) throw new Error(`${file} did not change`);
  return change.next;
}

/** The `+` and `-` lines of a diff, without its headers. */
const changedLines = (diff: string | undefined): string[] =>
  (diff ?? '').split('\n').filter((l) => /^[+-](?![+-]{2} )/.test(l));

/** The B1 content check the server runs, over the outcome's own files. */
function contentCheck(r: Fixed, item: FixClaimItem) {
  return checkFixUpload({
    family: 'maven',
    packageName: item.packageName,
    targets: uploaded(r).targets,
    files: [...r.files.values()],
  });
}

const DIRECT = { path: 'pom.xml', relation: 'direct', mechanism: null, dependents: [] };
const SPRING_520 = claim(['5.2.20.RELEASE'], ['5.3.18', '5.2.21']);

// ─── Direct ─────────────────────────────────────────────────────────────────

describe('the Maven adapter: direct dependencies', () => {
  it('literal (§11.4): 5.2.20.RELEASE moves to 5.2.21 on its own line; the pom diff is one line', async () => {
    const dir = committed({
      'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE') + dep('com.google.guava:guava', '31.1-jre')),
    });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), directTree('5.2.21')]);

    const up = uploaded(r);
    expect(up.targets).toEqual([
      { installed: '5.2.20.RELEASE', target: '5.2.21', lockfile: 'pom.xml' },
    ]);
    expect(up.targetVersion).toBe('5.2.21');
    expect(up.installedVersion).toBe('5.2.20.RELEASE');
    expect(up.lockfiles).toEqual([DIRECT]);
    expect(changedLines(r.diffs.get('pom.xml'))).toEqual([
      '-      <version>5.2.20.RELEASE</version>',
      '+      <version>5.2.21</version>',
    ]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('runs only mvn from PATH (R25), dependency:tree at the root with 8 MiB of stdout kept (F16)', async () => {
    const dir = committed({
      'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')),
      mvnw: '#!/bin/sh\nexec java -jar .mvn/wrapper/maven-wrapper.jar "$@"\n',
    });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), directTree('5.2.21')]);

    const call = { tool: 'mvn', args: TREE_ARGS, cwd: '', outputLimitBytes: EIGHT_MIB };
    expect(r.calls).toEqual([call, call]);
    expect(uploaded(r).lockfiles).toEqual([DIRECT]);
  });

  it('property: ${spring.version} defined in the root pom changes, the dependency does not', async () => {
    const properties = [
      '  <properties>',
      '    <java.version>17</java.version>',
      '    <spring.version>5.2.20.RELEASE</spring.version>',
      '  </properties>',
      '',
    ].join('\n');
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '${spring.version}'), properties) });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), directTree('5.2.21')]);

    expect(changedLines(r.diffs.get('pom.xml'))).toEqual([
      '-    <spring.version>5.2.20.RELEASE</spring.version>',
      '+    <spring.version>5.2.21</spring.version>',
    ]);
    expect(textOf(r, 'pom.xml')).toContain('<version>${spring.version}</version>');
    expect(uploaded(r).lockfiles).toEqual([DIRECT]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('comments kept (§11.3, Review Focus 1): comments, a property block, CRLF and a BOM; only the planned line changes', async () => {
    const base = [
      '﻿<?xml version="1.0" encoding="UTF-8"?>',
      '<!-- Built by the platform team. -->',
      '<project>',
      '    <modelVersion>4.0.0</modelVersion>',
      '    <groupId>com.example</groupId>',
      '    <artifactId>app</artifactId>',
      '    <version>1.0.0</version>',
      '',
      '    <properties>',
      '        <!-- Keep in step with the platform BOM. -->',
      '        <java.version>17</java.version>',
      '        <spring.version>5.2.20.RELEASE</spring.version> <!-- spring -->',
      '        <guava.version>31.1-jre</guava.version>',
      '    </properties>',
      '',
      '    <dependencies>',
      '        <!-- Spring -->',
      '        <dependency>',
      '            <groupId>org.springframework</groupId>',
      '            <artifactId>spring-core</artifactId>',
      '            <version>${spring.version}</version><!-- the CVE -->',
      '        </dependency>',
      '    </dependencies>',
      '</project>',
      '',
    ].join('\r\n');
    const dir = committed({ 'pom.xml': base });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), directTree('5.2.21')]);

    expect(textOf(r, 'pom.xml')).toBe(
      base.replace(
        '<spring.version>5.2.20.RELEASE</spring.version>',
        '<spring.version>5.2.21</spring.version>',
      ),
    );
    expect(changedLines(r.diffs.get('pom.xml'))).toHaveLength(2);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('group:artifact (Review Focus 3): of two dependencies sharing the artifactId, only the right group’s changes', async () => {
    const dir = committed({
      'pom.xml': pom(
        dep('com.example.fork:spring-core', '5.2.20.RELEASE') + dep(SPRING, '5.2.20.RELEASE'),
      ),
    });
    const fork = '+- com.example.fork:spring-core:jar:5.2.20.RELEASE:compile';

    const r = await fix(dir, SPRING_520, [
      directTree('5.2.20.RELEASE', [fork]),
      directTree('5.2.21', [fork]),
    ]);

    const next = textOf(r, 'pom.xml');
    expect(next).toBe(
      pom(dep('com.example.fork:spring-core', '5.2.20.RELEASE') + dep(SPRING, '5.2.21')),
    );
    expect(changedLines(r.diffs.get('pom.xml'))).toHaveLength(2);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });
});

// ─── Transitive ─────────────────────────────────────────────────────────────

const managedEntry = (indent: string, version: string) =>
  [
    `${indent}<dependency>`,
    `${indent}  <groupId>org.springframework</groupId>`,
    `${indent}  <artifactId>spring-core</artifactId>`,
    `${indent}  <version>${version}</version>`,
    `${indent}</dependency>`,
    '',
  ].join('\n');

const PINNED = {
  path: 'pom.xml',
  relation: 'transitive',
  mechanism: 'dependencyManagement',
  dependents: ['org.springframework:spring-context'],
};

describe('the Maven adapter: transitive dependencies', () => {
  it('transitive: a <dependencyManagement> entry is added in the root pom, before <dependencies>, at the sibling indentation', async () => {
    const base = pom(dep('org.springframework:spring-context', '5.2.20.RELEASE'));
    const dir = committed({ 'pom.xml': base });

    const r = await fix(dir, SPRING_520, [
      transitiveTree('5.2.20.RELEASE'),
      transitiveTree('5.2.21', ' (version managed from 5.2.20.RELEASE)'),
    ]);

    const section = [
      '  <dependencyManagement>',
      '    <dependencies>',
      managedEntry('      ', '5.2.21').trimEnd(),
      '    </dependencies>',
      '  </dependencyManagement>',
      '',
    ].join('\n');
    expect(textOf(r, 'pom.xml')).toBe(
      base.replace('  <dependencies>\n', `${section}  <dependencies>\n`),
    );
    const up = uploaded(r);
    expect(up.targets).toEqual([
      { installed: '5.2.20.RELEASE', target: '5.2.21', lockfile: 'pom.xml' },
    ]);
    expect(up.lockfiles).toEqual([PINNED]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('transitive: an existing <dependencyManagement> section is extended after its last entry', async () => {
    const bom = [
      '  <dependencyManagement>',
      '    <dependencies>',
      '      <dependency>',
      '        <groupId>com.fasterxml.jackson</groupId>',
      '        <artifactId>jackson-bom</artifactId>',
      '        <version>2.13.3</version>',
      '        <type>pom</type>',
      '        <scope>import</scope>',
      '      </dependency>',
      '    </dependencies>',
      '  </dependencyManagement>',
      '',
    ].join('\n');
    const base = pom(dep('org.springframework:spring-context', '5.2.20.RELEASE'), bom);
    const dir = committed({ 'pom.xml': base });

    const r = await fix(dir, SPRING_520, [
      transitiveTree('5.2.20.RELEASE'),
      transitiveTree('5.2.21'),
    ]);

    expect(textOf(r, 'pom.xml')).toBe(
      base.replace(
        '      </dependency>\n    </dependencies>\n  </dependencyManagement>',
        `      </dependency>\n${managedEntry('      ', '5.2.21')}    </dependencies>\n  </dependencyManagement>`,
      ),
    );
    expect(uploaded(r).lockfiles).toEqual([PINNED]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('one managed entry for modules on two release lines is no_fix several_lines (B3)', async () => {
    const dir = committed({
      'pom.xml': [
        '<project>',
        '  <modelVersion>4.0.0</modelVersion>',
        '  <groupId>com.example</groupId>',
        '  <artifactId>app-parent</artifactId>',
        '  <version>1.0.0</version>',
        '  <packaging>pom</packaging>',
        '  <modules>',
        '    <module>old</module>',
        '    <module>new</module>',
        '  </modules>',
        '</project>',
        '',
      ].join('\n'),
      'old/pom.xml': pom(
        dep('org.springframework:spring-context', '4.3.30.RELEASE'),
        PARENT,
        'old',
      ),
      'new/pom.xml': pom(
        dep('org.springframework:spring-context', '5.2.20.RELEASE'),
        PARENT,
        'new',
      ),
    });
    const through = (version: string) => [
      `\\- org.springframework:spring-context:jar:${version}:compile`,
      `   \\- ${SPRING}:jar:${version}:compile`,
    ];
    const tree = mavenOutput([
      { coords: 'com.example:app-parent:pom:1.0.0', pom: 'pom.xml', tree: [] },
      { coords: 'com.example:old:jar:1.0.0', pom: 'old/pom.xml', tree: through('4.3.30.RELEASE') },
      { coords: 'com.example:new:jar:1.0.0', pom: 'new/pom.xml', tree: through('5.2.20.RELEASE') },
    ]);
    const item = claim(['4.3.30.RELEASE', '5.2.20.RELEASE'], ['5.2.21', '4.3.31']);

    const r = await fix(dir, item, [tree]);

    expect(r.outcome).toMatchObject({ noFix: { reason: 'several_lines' } });
    if ('noFix' in r.outcome) {
      expect(r.outcome.noFix.message).toContain('release lines 4, 5');
      expect(r.outcome.noFix.message).toContain('com.example:old, com.example:new');
    }
    expect(r.calls).toHaveLength(1);
  });
});

// ─── Modules and parents ────────────────────────────────────────────────────

/** A reactor: the root pom (packaging pom, `head` inside) with modules core and web. */
function reactor(rootHead: string, core: string): Record<string, string> {
  return {
    'pom.xml': [
      '<project>',
      '  <modelVersion>4.0.0</modelVersion>',
      '  <groupId>com.example</groupId>',
      '  <artifactId>app-parent</artifactId>',
      '  <version>1.0.0</version>',
      '  <packaging>pom</packaging>',
      '  <modules>',
      '    <module>core</module>',
      '    <module>web</module>',
      '  </modules>',
      `${rootHead}</project>`,
      '',
    ].join('\n'),
    'core/pom.xml': pom(core, PARENT, 'core'),
    'web/pom.xml': pom(dep('com.example:core', '${project.version}'), PARENT, 'web'),
  };
}

const reactorTree = (version: string) =>
  mavenOutput([
    { coords: 'com.example:app-parent:pom:1.0.0', pom: 'pom.xml', tree: [] },
    {
      coords: 'com.example:core:jar:1.0.0',
      pom: 'core/pom.xml',
      tree: [`\\- ${SPRING}:jar:${version}:compile`],
    },
    {
      coords: 'com.example:web:jar:1.0.0',
      pom: 'web/pom.xml',
      tree: ['\\- com.example:core:jar:1.0.0:compile', `   \\- ${SPRING}:jar:${version}:compile`],
    },
  ]);

const SPRING_PROPERTY =
  '  <properties>\n    <spring.version>5.2.20.RELEASE</spring.version>\n  </properties>\n';

describe('the Maven adapter: modules and parents', () => {
  it('a reactor whose root manages the version through its own property: the root’s property changes', async () => {
    const managed = [
      '  <dependencyManagement>',
      '    <dependencies>',
      managedEntry('      ', '${spring.version}').trimEnd(),
      '    </dependencies>',
      '  </dependencyManagement>',
      '',
    ].join('\n');
    const dir = committed(reactor(`${SPRING_PROPERTY}${managed}`, dep(SPRING, null)));

    const r = await fix(dir, SPRING_520, [reactorTree('5.2.20.RELEASE'), reactorTree('5.2.21')]);

    const up = uploaded(r);
    expect([...r.files.keys()]).toEqual(['pom.xml']);
    expect(changedLines(r.diffs.get('pom.xml'))).toEqual([
      '-    <spring.version>5.2.20.RELEASE</spring.version>',
      '+    <spring.version>5.2.21</spring.version>',
    ]);
    expect(up.targets).toEqual([
      { installed: '5.2.20.RELEASE', target: '5.2.21', lockfile: 'pom.xml' },
    ]);
    expect(up.lockfiles).toEqual([DIRECT]);
    expect(r.calls.map((c) => c.cwd)).toEqual(['', '']);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('a version every module inherits from the root’s <dependencies>: the root’s <version> changes', async () => {
    const declared = `  <dependencies>\n${dep(SPRING, '5.2.20.RELEASE')}  </dependencies>\n`;
    const dir = committed(reactor(declared, dep('com.google.guava:guava', '31.1-jre')));
    const inherited = (version: string) =>
      mavenOutput(
        [
          'com.example:app-parent:pom:1.0.0',
          'com.example:core:jar:1.0.0',
          'com.example:web:jar:1.0.0',
        ].map((coords, i) => ({
          coords,
          pom: ['pom.xml', 'core/pom.xml', 'web/pom.xml'][i] ?? '',
          tree: [`\\- ${SPRING}:jar:${version}:compile`],
        })),
      );

    const r = await fix(dir, SPRING_520, [inherited('5.2.20.RELEASE'), inherited('5.2.21')]);

    expect([...r.files.keys()]).toEqual(['pom.xml']);
    expect(changedLines(r.diffs.get('pom.xml'))).toEqual([
      '-      <version>5.2.20.RELEASE</version>',
      '+      <version>5.2.21</version>',
    ]);
    expect(uploaded(r).lockfiles).toEqual([DIRECT]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('F13: a ${property} that only an outside parent pom defines is manifest_unsupported, nothing changed', async () => {
    const parent = [
      '  <parent>',
      '    <groupId>org.springframework.boot</groupId>',
      '    <artifactId>spring-boot-starter-parent</artifactId>',
      '    <version>2.2.13.RELEASE</version>',
      '  </parent>',
      '',
    ].join('\n');
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '${spring-framework.version}'), parent) });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE')]);

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toContain('${spring-framework.version}');
      expect(r.outcome.failure.message).toContain('pom.xml');
    }
    expect(r.calls).toHaveLength(1);
    expect(r.files.size).toBe(0);
  });

  it('F13: a module’s ${property} defined only in the root pom is manifest_unsupported (the root does not use it)', async () => {
    const dir = committed(reactor(SPRING_PROPERTY, dep(SPRING, '${spring.version}')));

    const r = await fix(dir, SPRING_520, [reactorTree('5.2.20.RELEASE')]);

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toContain(
        'core/pom.xml takes the version of org.springframework:spring-core from ${spring.version}, which it does not define',
      );
    }
    expect(r.calls).toHaveLength(1);
    expect(r.files.size).toBe(0);
  });
});

// ─── Verify, failures, limits ───────────────────────────────────────────────

const failedRun = (errors: string[]): ToolResult => ({
  exitCode: 1,
  timedOut: false,
  truncated: false,
  stdout: mavenOutput([{ coords: 'com.example:app:jar:1.0.0', pom: 'pom.xml', tree: [] }], {
    end: [
      `[INFO] ${RULE}`,
      '[INFO] BUILD FAILURE',
      `[INFO] ${RULE}`,
      ...errors.map((e) => `[ERROR] ${e}`),
      '[ERROR] ',
      '[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.',
    ],
  }),
  stderr: '',
});

describe('the Maven adapter: verify and failures', () => {
  it('verify: the tree after the edit still shows 5.2.20.RELEASE: verify_failed', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });

    const r = await fix(dir, SPRING_520, [
      directTree('5.2.20.RELEASE'),
      directTree('5.2.20.RELEASE'),
    ]);

    expect(r.outcome).toMatchObject({ failure: { code: 'verify_failed' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('5.2.20.RELEASE');
  });

  it('F36: Maven finds no POM of the target (a warning, exit 0): no_fix unresolvable', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });
    const missing = `[WARNING] The POM for ${SPRING}:jar:5.2.21 is missing, no dependency information available`;

    const r = await fix(dir, SPRING_520, [
      directTree('5.2.20.RELEASE'),
      mavenOutput(
        [
          {
            coords: 'com.example:app:jar:1.0.0',
            pom: 'pom.xml',
            tree: [`\\- ${SPRING}:jar:5.2.21:compile`],
          },
        ],
        { between: [missing] },
      ),
    ]);

    expect(r.outcome).toMatchObject({ noFix: { reason: 'unresolvable' } });
    if ('noFix' in r.outcome) expect(r.outcome.noFix.message).toContain('5.2.21 is missing');
  });

  it.each([
    [
      'the target is not found: no_fix unresolvable',
      { noFix: { reason: 'unresolvable' } },
      `Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree (default-cli) on project app: Could not resolve dependencies for project com.example:app:jar:1.0.0: The following artifacts could not be resolved: ${SPRING}:jar:5.2.21 (absent): Could not find artifact ${SPRING}:jar:5.2.21 in central (https://repo.maven.apache.org/maven2) -> [Help 1]`,
    ],
    [
      'another artifact is not found at the new version (I1): no_fix unresolvable',
      { noFix: { reason: 'unresolvable' } },
      'Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree (default-cli) on project app: Could not resolve dependencies for project com.example:app:jar:1.0.0: Could not find artifact org.springframework:spring-jcl:jar:5.2.21 in central (https://repo.maven.apache.org/maven2) -> [Help 1]',
    ],
  ])('F36: dependency:tree failing after the edit, %s', async (_what, expected, error) => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), failedRun([error])]);

    expect(r.outcome).toMatchObject(expected);
    const message = JSON.stringify(r.outcome);
    expect(message).toMatch(/Could not find artifact|Maven cannot find/);
    expect(message).not.toContain('re-run Maven with the -e switch');
  });

  it('F16: a tree cut at 8 MiB is never read: failure package_manager', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });
    const line = `${DOWNLOADS[1]}\n`;
    const noise = Array.from({ length: Math.ceil(EIGHT_MIB / line.length) + 1 }, () => line);
    const huge = mavenOutput(
      [
        {
          coords: 'com.example:app:jar:1.0.0',
          pom: 'pom.xml',
          tree: [`\\- ${SPRING}:jar:5.2.20.RELEASE:compile`],
        },
      ],
      { between: noise.map((l) => l.trimEnd()) },
    );
    expect(huge.length).toBeGreaterThan(EIGHT_MIB);

    const r = await fix(dir, SPRING_520, [huge]);

    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('8 MiB');
  });

  it('a run that prints no dependency tree (say, -q in .mvn/maven.config) is failure package_manager, not "not installed"', async () => {
    const dir = committed({
      'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')),
      '.mvn/maven.config': '-q\n',
    });

    const r = await fix(dir, SPRING_520, ['']);

    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('no dependency tree');
  });

  it('tree lines outside a module’s tree (a parallel build’s interleaved output) are never read: failure package_manager', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });
    const interleaved = [
      '[INFO] Scanning for projects...',
      '[INFO] --- dependency:3.8.1:tree (default-cli) @ core ---',
      '[INFO] --- dependency:3.8.1:tree (default-cli) @ web ---',
      '[INFO] com.example:core:jar:1.0.0',
      '[INFO] com.example:web:jar:1.0.0',
      `[INFO] \\- ${SPRING}:jar:5.2.20.RELEASE:compile`,
      `[INFO] \\- ${SPRING}:jar:5.2.20.RELEASE:compile`,
      '[INFO] BUILD SUCCESS',
      '',
    ].join('\n');

    const r = await fix(dir, SPRING_520, [interleaved]);

    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('cannot read');
  });

  it('a base tree that fails is failure package_manager with Maven’s error', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });

    const r = await fix(dir, SPRING_520, [
      failedRun([
        'Non-resolvable parent POM for com.example:app:1.0.0: Could not transfer artifact',
      ]),
    ]);

    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    if ('failure' in r.outcome)
      expect(r.outcome.failure.message).toContain('Non-resolvable parent POM');
  });
});

// ─── Fix round 1 ────────────────────────────────────────────────────────────

const DATABIND = 'com.fasterxml.jackson.core:jackson-databind';
const jackson = (databind: string, between: string[] = []) =>
  mavenOutput(
    [
      {
        coords: 'com.example:app:jar:1.0.0',
        pom: 'pom.xml',
        tree: [`\\- ${DATABIND}:jar:${databind}:compile`],
      },
    ],
    { between },
  );
const JACKSON_POM = pom(
  dep(DATABIND, '${jackson.version}') +
    dep('com.fasterxml.jackson.core:jackson-core', '${jackson.version}'),
  '  <properties>\n    <jackson.version>2.13.4</jackson.version>\n  </properties>\n',
);
const JACKSON_CLAIM: FixClaimItem = {
  ...claim(['2.13.4'], ['2.13.4.2']),
  packageName: DATABIND,
};
const missingCore = (version: string) =>
  `[WARNING] The POM for com.fasterxml.jackson.core:jackson-core:jar:${version} is missing, no dependency information available`;

describe('fix round 1: I1, an artifact that shares the property and does not exist at the new version', () => {
  it('jackson-databind and jackson-core share ${jackson.version}; the verify run misses jackson-core at the new version: no_fix unresolvable naming it and the property', async () => {
    const dir = committed({ 'pom.xml': JACKSON_POM });

    const r = await fix(dir, JACKSON_CLAIM, [
      jackson('2.13.4'),
      jackson('2.13.4.2', [missingCore('2.13.4.2')]),
    ]);

    expect(r.outcome).toMatchObject({ noFix: { reason: 'unresolvable' } });
    if ('noFix' in r.outcome) {
      expect(r.outcome.noFix.message).toContain('com.fasterxml.jackson.core:jackson-core');
      expect(r.outcome.noFix.message).toContain('2.13.4.2');
      expect(r.outcome.noFix.message).toContain('jackson.version');
    }
  });

  it('a missing artifact the base run reports too is not new: the fix goes on', async () => {
    const dir = committed({ 'pom.xml': JACKSON_POM });
    const old =
      '[WARNING] The POM for org.example:legacy:jar:1.0 is missing, no dependency information available';

    const r = await fix(dir, JACKSON_CLAIM, [jackson('2.13.4', [old]), jackson('2.13.4.2', [old])]);

    expect(uploaded(r).targetVersion).toBe('2.13.4.2');
  });

  it('a new missing artifact in a failed verify run is no_fix unresolvable too', async () => {
    const dir = committed({ 'pom.xml': JACKSON_POM });
    const error =
      'Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree (default-cli) on project app: Could not resolve dependencies for project com.example:app:jar:1.0.0: Could not find artifact com.fasterxml.jackson.core:jackson-core:jar:2.13.4.2 in central (https://repo.maven.apache.org/maven2) -> [Help 1]';

    const r = await fix(dir, JACKSON_CLAIM, [jackson('2.13.4'), failedRun([error])]);

    expect(r.outcome).toMatchObject({ noFix: { reason: 'unresolvable' } });
  });
});

describe('fix round 1: T15e, the runner’s truncated flag', () => {
  it('output the runner flags as cut is never read, whatever its size', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });

    const r = await fix(dir, SPRING_520, [
      { ...ok(directTree('5.2.20.RELEASE')), truncated: true },
    ]);

    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('8 MiB');
  });

  it('output of nearly 8 MiB that was not cut is read', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });
    const base = directTree('5.2.20.RELEASE');
    const padding = `[INFO] ${'x'.repeat(EIGHT_MIB - base.length - 10)}\n`;

    const r = await fix(dir, SPRING_520, [padding + base, directTree('5.2.21')]);

    expect(uploaded(r).targetVersion).toBe('5.2.21');
  });
});

describe('fix round 1: T15g, a base tree that times out', () => {
  it('is failure timeout, not package_manager', async () => {
    const dir = committed({ 'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')) });
    const hung: ToolResult = {
      exitCode: null,
      timedOut: true,
      truncated: false,
      stdout: '',
      stderr: '',
    };

    const r = await fix(dir, SPRING_520, [hung]);

    expect(r.outcome).toMatchObject({ failure: { code: 'timeout' } });
  });
});

describe('fix round 1: T15c, a direct dependency managed from outside', () => {
  it('has no <version> and an outside parent: the pin is a managed entry, reported as direct with its mechanism', async () => {
    const outside = [
      '  <parent>',
      '    <groupId>org.springframework.boot</groupId>',
      '    <artifactId>spring-boot-starter-parent</artifactId>',
      '    <version>2.2.13.RELEASE</version>',
      '  </parent>',
      '',
    ].join('\n');
    const dir = committed({ 'pom.xml': pom(dep(SPRING, null), outside) });

    const r = await fix(dir, SPRING_520, [directTree('5.2.20.RELEASE'), directTree('5.2.21')]);

    const up = uploaded(r);
    expect(up.lockfiles).toEqual([
      { path: 'pom.xml', relation: 'direct', mechanism: 'dependencyManagement', dependents: [] },
    ]);
    expect(up.targets).toEqual([
      { installed: '5.2.20.RELEASE', target: '5.2.21', lockfile: 'pom.xml' },
    ]);
    expect(textOf(r, 'pom.xml')).toContain('<dependencyManagement>');
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });

  it('a multi-module add: the module declares it without a version, the root manages nothing: the entry and the target name the root pom', async () => {
    const dir = committed(reactor('', dep(SPRING, null)));

    const r = await fix(dir, SPRING_520, [reactorTree('5.2.20.RELEASE'), reactorTree('5.2.21')]);

    const up = uploaded(r);
    expect([...r.files.keys()]).toEqual(['pom.xml']);
    expect(up.targets).toEqual([
      { installed: '5.2.20.RELEASE', target: '5.2.21', lockfile: 'pom.xml' },
    ]);
    expect(up.lockfiles).toEqual([
      {
        path: 'pom.xml',
        relation: 'transitive',
        mechanism: 'dependencyManagement',
        dependents: ['com.example:core'],
      },
    ]);
    expect(contentCheck(r, SPRING_520)).toEqual({ ok: true });
  });
});

describe('fix round 1: T15d, a relativePath that names the parent’s folder', () => {
  it.each(['..', '../'])(
    '<relativePath>%s</relativePath> keeps the in-repository parent',
    async (rel) => {
      const parent = PARENT.replace(
        '  </parent>',
        `    <relativePath>${rel}</relativePath>\n  </parent>`,
      );
      const managed = [
        '  <dependencyManagement>',
        '    <dependencies>',
        managedEntry('      ', '5.2.20.RELEASE').trimEnd(),
        '    </dependencies>',
        '  </dependencyManagement>',
        '',
      ].join('\n');
      const files = reactor(managed, dep(SPRING, null));
      files['core/pom.xml'] = pom(dep(SPRING, null), parent, 'core');
      const dir = committed(files);

      const r = await fix(dir, SPRING_520, [reactorTree('5.2.20.RELEASE'), reactorTree('5.2.21')]);

      expect([...r.files.keys()]).toEqual(['pom.xml']);
      expect(changedLines(r.diffs.get('pom.xml'))).toEqual([
        '-        <version>5.2.20.RELEASE</version>',
        '+        <version>5.2.21</version>',
      ]);
      expect(uploaded(r).lockfiles).toEqual([DIRECT]);
    },
  );
});

// ─── R25 ────────────────────────────────────────────────────────────────────

describe('mvnw only (R25)', () => {
  /** The job's lookup (`commands/fix.ts` `toolLookup`): `resolveTool` on `PATH`, never in the repository. */
  const lookup = (root: string, pathVar: string) => (tool: string) => {
    const found = resolveTool(tool, { root, env: { PATH: pathVar } });
    return found === null || 'problem' in found ? null : found.command;
  };

  it('a repository with only mvnw (and an mvn of its own on PATH) is not served; an mvn outside it is', () => {
    const dir = committed({
      'pom.xml': pom(dep(SPRING, '5.2.20.RELEASE')),
      mvnw: '#!/bin/sh\nexec java -jar .mvn/wrapper/maven-wrapper.jar "$@"\n',
      'mvnw.cmd': '@echo off\r\njava -jar .mvn\\wrapper\\maven-wrapper.jar %*\r\n',
      '.mvn/wrapper/maven-wrapper.properties':
        'distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n',
      'bin/mvn': '#!/bin/sh\necho planted\n',
      'bin/mvn.exe': 'planted',
      'bin/mvn.cmd': '@echo planted\r\n',
    });
    for (const file of ['mvnw', 'bin/mvn']) chmodSync(path.join(dir, file), 0o755);
    const files = gitSync(dir, 'ls-files').split('\n');
    const empty = tmp('qualor-fix-path-');

    const inRepo = lookup(dir, [dir, path.join(dir, 'bin'), empty].join(path.delimiter));
    expect(inRepo('mvn')).toBeNull();
    expect(servedFamilies(familyFiles(files), inRepo)).toEqual([]);

    const bin = tmp('qualor-fix-mvn-bin-');
    writeTree(bin, { mvn: '#!/bin/sh\n', 'mvn.exe': '' });
    chmodSync(path.join(bin, 'mvn'), 0o755);
    const outside = lookup(dir, [path.join(dir, 'bin'), bin].join(path.delimiter));
    expect(outside('mvn')).not.toBeNull();
    expect(servedFamilies(familyFiles(files), outside)).toEqual(['maven']);
  });
});
