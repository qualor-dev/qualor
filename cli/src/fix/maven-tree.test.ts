import { describe, expect, it } from 'vitest';
import {
  errorText,
  missingArtifacts,
  packageNodes,
  readTrees,
  targetMissing,
  type ModuleTree,
} from './maven-tree';

/** The tree parser of the Maven adapter (T15k), read directly: recorded `mvn -B` lines only. */

const HEADER = '[INFO] --- dependency:3.8.1:tree (default-cli) @ app ---';
const SPRING = 'org.springframework:spring-core';

const out = (...lines: string[]) => `${lines.join('\n')}\n`;

function stopOf(r: ReturnType<typeof readTrees>) {
  if (Array.isArray(r)) throw new Error('expected a stop');
  return r;
}

describe('readTrees', () => {
  it('reads each module of a reactor with its nodes, their depth and a classifier', () => {
    const r = readTrees(
      out(
        '[INFO] Scanning for projects...',
        HEADER,
        '[INFO] com.example:app:jar:1.0.0',
        '[INFO] +- org.springframework:spring-context:jar:5.2.20.RELEASE:compile',
        '[INFO] |  \\- org.springframework:spring-core:jar:5.2.20.RELEASE:compile',
        '[INFO] \\- io.netty:netty-tcnative:jar:linux-x86_64:2.0.1:compile',
        '[INFO] ',
        HEADER.replace('@ app', '@ lib'),
        '[INFO] com.example:lib:jar:1.0.0',
        '[INFO] \\- org.springframework:spring-core:jar:5.3.18:compile',
        '[INFO] BUILD SUCCESS',
      ),
    );
    expect(r).toEqual([
      {
        module: 'com.example:app',
        nodes: [
          { ga: 'org.springframework:spring-context', version: '5.2.20.RELEASE', depth: 1 },
          { ga: SPRING, version: '5.2.20.RELEASE', depth: 2 },
          { ga: 'io.netty:netty-tcnative', version: '2.0.1', depth: 1 },
        ],
      },
      { module: 'com.example:lib', nodes: [{ ga: SPRING, version: '5.3.18', depth: 1 }] },
    ]);
  });

  it('reads CRLF output and a module whose filtered tree is empty', () => {
    const r = readTrees(
      out(HEADER, '[INFO] com.example:app:jar:1.0.0', '[INFO] done').replaceAll('\n', '\r\n'),
    );
    expect(r).toEqual([{ module: 'com.example:app', nodes: [] }]);
  });

  it('stops when no goal header is printed (a -q in .mvn/maven.config)', () => {
    const stop = stopOf(readTrees(out('[INFO] BUILD SUCCESS')));
    expect(stop).toMatchObject({ kind: 'failure', code: 'package_manager' });
    expect(stop.message).toContain('no dependency tree');
  });

  it('stops on a tree line outside a module tree (interleaved output)', () => {
    const stop = stopOf(
      readTrees(
        out(HEADER, '[INFO] com.example:app:jar:1.0.0', '[INFO] ', '[INFO] \\- a:b:jar:1:compile'),
      ),
    );
    expect(stop).toMatchObject({ kind: 'failure', code: 'package_manager' });
    expect(stop.message).toContain('a tree line Qualor cannot read');
  });
});

describe('packageNodes', () => {
  const tree: ModuleTree = {
    module: 'com.example:app',
    nodes: [
      { ga: 'a:direct', version: '1', depth: 1 },
      { ga: 'a:mid', version: '1', depth: 2 },
      { ga: SPRING, version: '5.2.20.RELEASE', depth: 3 },
      { ga: SPRING, version: '5.2.20.RELEASE', depth: 1 },
    ],
  };

  it('names the node above a transitive one, and none for a direct one', () => {
    expect(packageNodes(tree, SPRING)).toEqual([
      { version: '5.2.20.RELEASE', depth: 3, parent: 'a:mid' },
      { version: '5.2.20.RELEASE', depth: 1, parent: null },
    ]);
    expect(packageNodes(tree, 'other:thing')).toEqual([]);
  });
});

describe('missing artifacts', () => {
  const output = [
    '[WARNING] The POM for com.fasterxml.jackson.core:jackson-core:jar:2.13.4.2 is missing, no dependency information available',
    '[ERROR] Could not find artifact org.springframework:spring-core:jar:5.2.99 in central (https://repo.maven.apache.org/maven2)',
    '[ERROR] Failure to find org.springframework:spring-core:pom:5.2.98 in central',
    '[INFO] The POM for is missing',
  ].join('\n');

  it('lists the artifacts of the three messages', () => {
    expect(missingArtifacts(output).toSorted()).toEqual([
      'com.fasterxml.jackson.core:jackson-core:jar:2.13.4.2',
      'org.springframework:spring-core:jar:5.2.99',
      'org.springframework:spring-core:pom:5.2.98',
    ]);
  });

  it('matches a target of the package itself, by version equality', () => {
    expect(targetMissing(output, SPRING, ['5.2.99'])).toBe(true);
    expect(targetMissing(output, SPRING, ['5.2.21'])).toBe(false);
    expect(targetMissing(output, 'com.fasterxml.jackson.core:jackson-databind', ['2.13.4.2'])).toBe(
      false,
    );
  });
});

describe('errorText', () => {
  const run = (stdout: string, stderr = '') => ({
    exitCode: 1,
    timedOut: false,
    truncated: false,
    stdout,
    stderr,
  });

  it('quotes the errors up to Maven help text, else the warnings, else the whole stdout', () => {
    expect(
      errorText(
        run('[ERROR] first\n[ERROR] second\n[ERROR] \n[ERROR] To see the full stack trace'),
      ),
    ).toBe('[ERROR] first\n[ERROR] second');
    expect(errorText(run('[INFO] x\n[WARNING] careful'))).toBe('[WARNING] careful');
    expect(errorText(run('plain'))).toBe('plain');
    expect(errorText(run('[ERROR] e', 'stderr text'))).toBe('[ERROR] e\nstderr text');
  });
});
