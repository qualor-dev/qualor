import { readFileSync } from 'node:fs';
import path from 'node:path';
import { checkFixUpload, type FixClaimItem, type FixFileChange } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import { mavenAdapter } from './maven';
import { prepareFix, type FixOutcome } from './run';
import { createToolRunner } from './runner';
import { openScratch } from './workspace';

/**
 * 0.16 fix MRs (R26, R27): the Maven adapter with the real mvn against Maven Central, run only by
 * `pnpm fix:live` (the unit project excludes `*.live.test.ts`). A one-module pom with
 * `org.springframework:spring-core` 5.2.20.RELEASE, directly and through spring-context, is fixed to
 * 5.2.22.RELEASE (CVE-2022-22970, GHSA-hh26-6xwr-ggv7: fixed in 5.2.22.RELEASE and 5.3.20).
 */

const tmp = useTempDirs();
const SPRING = 'org.springframework:spring-core';
const LIVE_MS = 600_000;

const SPRING_CORE: FixClaimItem = {
  id: '0193a4c6-1c2e-7a3b-9f00-000000000003',
  generation: 1,
  leaseToken: 'lease-1',
  family: 'maven',
  packageName: SPRING,
  installedVersions: ['5.2.20.RELEASE'],
  vulnerabilities: [
    {
      id: 'CVE-2022-22970',
      severity: 'medium',
      title: 'Spring Framework DoS via data binding to MultipartFile or javax.servlet.Part',
      url: null,
      installedVersions: ['5.2.20.RELEASE'],
      fixedVersions: ['5.2.22.RELEASE', '5.3.20'],
    },
  ],
  mainBranch: 'main',
  declinedTarget: null,
};

function pom(artifactId: string): string {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<project>',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>com.example.live</groupId>',
    '  <artifactId>app</artifactId>',
    '  <version>1.0.0</version>',
    '  <!-- One dependency of Spring Framework 5.2. -->',
    '  <dependencies>',
    '    <dependency>',
    '      <groupId>org.springframework</groupId>',
    `      <artifactId>${artifactId}</artifactId>`,
    '      <version>5.2.20.RELEASE</version>',
    '    </dependency>',
    '  </dependencies>',
    '</project>',
    '',
  ].join('\n');
}

/** The job's environment as `qualor fix` starts with it. */
const jobEnv = (): Record<string, string> =>
  Object.fromEntries(
    Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined),
  );

async function fixed(files: Record<string, string>): Promise<{
  outcome: FixOutcome;
  changes: FixFileChange[];
}> {
  const env = jobEnv();
  const dir = tmp('qualor-fix-live-mvn-');
  initRepo(dir);
  writeTree(dir, files);
  commitAll(dir, 'base');
  const git = createGit(dir, GIT_TEST_ENV);
  const scratch = await openScratch(git, tmp('qualor-fix-live-temp-'));
  try {
    const outcome = await prepareFix(
      SPRING_CORE,
      mavenAdapter,
      {
        root: scratch.root,
        files: gitSync(dir, 'ls-files').split('\n'),
        env,
        run: createToolRunner({ env, root: dir, log: silentLogger }),
        deadline: Date.now() + LIVE_MS,
        log: silentLogger,
      },
      git,
    );
    const changes = ('files' in outcome ? outcome.files : []).map((f) => ({
      path: f.path,
      base: readFileSync(path.join(dir, f.path), 'utf8'),
      next: Buffer.from(f.content, 'base64').toString('utf8'),
    }));
    return { outcome, changes };
  } finally {
    await scratch.close();
  }
}

const TARGETS = [{ installed: '5.2.20.RELEASE', target: '5.2.22.RELEASE', lockfile: 'pom.xml' }];

describe.runIf(toolInstalled('mvn'))('the Maven adapter against Maven Central (live)', () => {
  it(
    'fixes a direct spring-core 5.2.20.RELEASE to 5.2.22.RELEASE in its <version>',
    async () => {
      const base = pom('spring-core');
      const { outcome, changes } = await fixed({ 'pom.xml': base });

      if (!('files' in outcome)) throw new Error(JSON.stringify(outcome));
      expect(changes.map((c) => c.next)).toEqual([
        base.replace('5.2.20.RELEASE', '5.2.22.RELEASE'),
      ]);
      expect(outcome.targets).toEqual(TARGETS);
      expect(outcome.lockfiles).toEqual([
        { path: 'pom.xml', relation: 'direct', mechanism: null, dependents: [] },
      ]);
      expect(
        checkFixUpload({
          family: 'maven',
          packageName: SPRING,
          targets: outcome.targets,
          files: changes,
        }),
      ).toEqual({ ok: true });
    },
    LIVE_MS,
  );

  it(
    'pins spring-core 5.2.22.RELEASE in <dependencyManagement> when spring-context brings it',
    async () => {
      const { outcome, changes } = await fixed({ 'pom.xml': pom('spring-context') });

      if (!('files' in outcome)) throw new Error(JSON.stringify(outcome));
      expect(changes.map((c) => c.path)).toEqual(['pom.xml']);
      expect(changes[0]?.next).toContain('<dependencyManagement>');
      expect(outcome.targets).toEqual(TARGETS);
      expect(outcome.lockfiles).toEqual([
        {
          path: 'pom.xml',
          relation: 'transitive',
          mechanism: 'dependencyManagement',
          dependents: ['org.springframework:spring-context'],
        },
      ]);
      expect(
        checkFixUpload({
          family: 'maven',
          packageName: SPRING,
          targets: outcome.targets,
          files: changes,
        }),
      ).toEqual({ ok: true });
    },
    LIVE_MS,
  );
});
