import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { cancelComment, fixBody, fixTitle } from '../../../server/src/fixes/body';
import type { Thr } from './19-decoration.js';
import {
  benchFixYaml,
  CANCEL_TEXT,
  CLOSING_SENTENCE,
  closedThread,
  endsWithClosing,
  EXPECTED_TARGET,
  FIX_DOCKER_PATH,
  fixPackageJson,
  fixPackageLock,
  fixTitleOf,
  INSTALLED,
  judgeClosed,
  judgeFiles,
  judgeOpenPr,
  judgeTarget,
  lodashIn,
  seedChanges,
  seedFiles,
  versionCore,
  type FixPr,
} from './24-fix-pr.js';

const example = (file: string): string =>
  readFileSync(
    fileURLToPath(new URL(`../../../integrations/azure-devops/${file}`, import.meta.url)),
    'utf8',
  );

const SP = '7c429e0c-e3c7-43e0-8633-fa6e0000136d';
const OTHER = '11111111-2222-4333-8444-555555555555';
const BRANCH = 'qualor/fix/js/lodash';

describe('item 24 repository files', () => {
  it('pins lodash 4.17.20 exactly in the manifest', () => {
    const pkg = JSON.parse(fixPackageJson()) as Record<string, unknown>;
    expect(pkg['dependencies']).toEqual({ lodash: '4.17.20' });
    expect(pkg['private']).toBe(true);
    expect(fixPackageJson().endsWith('}\n')).toBe(true);
  });

  it('writes an npm v3 lockfile for exactly lodash 4.17.20', () => {
    const lock = JSON.parse(fixPackageLock()) as {
      name: string;
      version: string;
      lockfileVersion: number;
      requires: boolean;
      packages: Record<string, Record<string, unknown>>;
    };
    const pkg = JSON.parse(fixPackageJson()) as { name: string; version: string };
    expect(lock.lockfileVersion).toBe(3);
    expect(lock.requires).toBe(true);
    expect(lock.name).toBe(pkg.name);
    expect(lock.version).toBe(pkg.version);
    expect(Object.keys(lock.packages)).toEqual(['', 'node_modules/lodash']);
    expect(lock.packages['']).toEqual({
      name: pkg.name,
      version: pkg.version,
      dependencies: { lodash: '4.17.20' },
    });
    expect(lock.packages['node_modules/lodash']).toEqual({
      version: '4.17.20',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
      integrity:
        'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==',
    });
    expect(lodashIn(fixPackageJson(), fixPackageLock())).toEqual({
      manifest: INSTALLED,
      lockRoot: INSTALLED,
      locked: INSTALLED,
    });
  });

  it('runs the fix example on the bench: its pool and image, no trigger and no schedule', () => {
    const yaml = benchFixYaml(example('qualor-fix-docker.yml'));
    expect(yaml).toContain('trigger: none');
    expect(yaml).not.toContain('schedules:');
    expect(yaml).not.toContain('cron');
    expect(yaml).toContain('pool:\n  name: Default\n');
    expect(yaml).not.toContain('vmImage');
    expect(yaml).toContain('QUALOR_SCANNER_IMAGE: qualor/scanner:azure-dev');
    expect(yaml).not.toContain('--dry-run');
    expect(yaml).not.toContain('QUALOR_SCM');
    expect(yaml.trimEnd()).toMatch(
      /\$\(QUALOR_SCANNER_IMAGE\) fix\n {4}displayName: Qualor fix\n {4}env:\n {6}QUALOR_TOKEN: \$\(QUALOR_TOKEN\)$/,
    );
    const doc = parse(yaml) as Record<string, unknown>;
    expect(doc['trigger']).toBe('none');
    expect(doc['schedules']).toBeUndefined();
    expect(doc['pool']).toEqual({ name: 'Default' });
    const steps = doc['steps'] as Record<string, unknown>[];
    expect(steps[0]).toMatchObject({ checkout: 'self', fetchDepth: 0, persistCredentials: false });
    expect(String(steps.at(-1)?.['script'])).toContain(
      '-e QUALOR_URL -e QUALOR_TOKEN -e QUALOR_PROJECT_KEY',
    );
  });

  it('seeds main with the manifest, the lockfile, the scan that uploads and the fix pipeline', () => {
    const files = seedFiles(example('qualor-docker.yml'), example('qualor-fix-docker.yml'));
    expect(files.map((f) => f.path)).toEqual([
      '/package.json',
      '/package-lock.json',
      '/.azure-pipelines/qualor-docker.yml',
      `/${FIX_DOCKER_PATH}`,
    ]);
    const scan = files[2]?.content ?? '';
    expect(scan).toContain('qualor/scanner:azure-dev');
    expect(scan).not.toContain('--dry-run');
    expect(scan).toContain('trigger: none');
  });
});

describe('item 24 seedChanges', () => {
  const wanted = [
    { path: '/a', content: 'one\n' },
    { path: '/b', content: 'two\n' },
    { path: '/c', content: 'three\n' },
  ];

  it('adds what is missing, edits what differs, skips what is already there', () => {
    const current = new Map<string, string | null>([
      ['/a', null],
      ['/b', 'two\r\n'],
      ['/c', 'other\n'],
    ]);
    expect(seedChanges(wanted, current)).toEqual([
      { path: '/a', content: 'one\n', changeType: 'add' },
      { path: '/c', content: 'three\n', changeType: 'edit' },
    ]);
  });

  it('changes nothing on a main already seeded, and adds everything to an empty one', () => {
    const same = new Map(wanted.map((f) => [f.path, f.content] as const));
    expect(seedChanges(wanted, same)).toEqual([]);
    expect(seedChanges(wanted, new Map()).map((c) => c.changeType)).toEqual(['add', 'add', 'add']);
  });
});

describe('item 24 judges', () => {
  it('reads the version a spec pins', () => {
    expect(versionCore('^4.17.21')).toBe('4.17.21');
    expect(versionCore('~4.17.21')).toBe('4.17.21');
    expect(versionCore('4.17.21')).toBe('4.17.21');
    expect(versionCore('>=4.0.0 <5')).toBe('>=4.0.0 <5');
    expect(versionCore(null)).toBeNull();
  });

  it('wants the target in the manifest, the lockfile root and its entry', () => {
    const fixed = (spec: string, locked: string) =>
      lodashIn(
        fixPackageJson().replace('"4.17.20"', JSON.stringify(spec)),
        fixPackageLock().replace(/"4\.17\.20"/g, JSON.stringify(locked)),
      );
    expect(judgeFiles(fixed('4.17.21', '4.17.21'), '4.17.21').pass).toBe(true);
    expect(judgeFiles(fixed('^4.17.21', '4.17.21'), '4.17.21').pass).toBe(true);
    expect(judgeFiles(fixed('4.17.20', '4.17.21'), '4.17.21').pass).toBe(false);
    expect(judgeFiles(lodashIn(fixPackageJson(), fixPackageLock()), '4.17.21').pass).toBe(false);
    expect(judgeFiles(lodashIn('not json', null), '4.17.21')).toMatchObject({
      pass: false,
      got: 'package.json absent; package-lock.json root absent, node_modules/lodash absent',
    });
  });

  it('takes 4.17.21 or a later 4.17.x as the target, and says why a later one', () => {
    expect(judgeTarget(EXPECTED_TARGET)).toMatchObject({ pass: true, got: '4.17.21' });
    const later = judgeTarget('4.17.23');
    expect(later.pass).toBe(true);
    expect(later.got).toContain('not 4.17.21');
    expect(judgeTarget('4.17.20').pass).toBe(false);
    expect(judgeTarget('5.0.0').pass).toBe(false);
    expect(judgeTarget(null).pass).toBe(false);
  });

  it('titles the pull request as the server does on Azure DevOps', () => {
    expect(fixTitleOf('4.17.21')).toBe('Bump lodash from 4.17.20 to 4.17.21');
    expect(fixTitleOf('4.17.21')).toBe(fixTitle('lodash', '4.17.20', '4.17.21', 'azure'));
  });

  it("keeps the server's closing sentence and cancel comment", () => {
    const body = fixBody({
      provider: 'azure',
      targets: [],
      vulnerabilities: [],
      unfixable: [],
      lockfiles: [],
      additions: [],
      majorJumps: [],
      vulnerabilitiesUrl: null,
    });
    expect(body).toBe(CLOSING_SENTENCE);
    expect(cancelComment('azure')).toBe(CANCEL_TEXT);
  });

  it('finds the closing sentence at the end only', () => {
    expect(endsWithClosing(`table\r\n\r\n${CLOSING_SENTENCE}\r\n`)).toBe(true);
    expect(endsWithClosing(`${CLOSING_SENTENCE}\n\nmore`)).toBe(false);
    expect(endsWithClosing(null)).toBe(false);
  });

  const pr = (over: Partial<FixPr> = {}): FixPr => ({
    pullRequestId: 7,
    status: 'active',
    title: 'Bump lodash from 4.17.20 to 4.17.21',
    description: `| a | b |\n\n${CLOSING_SENTENCE}`,
    sourceRefName: `refs/heads/${BRANCH}`,
    targetRefName: 'refs/heads/main',
    createdBy: { id: SP.toUpperCase() },
    ...over,
  });
  const want = { branch: BRANCH, target: '4.17.21', spId: SP };

  it('passes the open pull request the brief describes', () => {
    expect(judgeOpenPr(pr(), want).map((c) => c.pass)).toEqual([true, true, true, true]);
  });

  it('fails each part of the open pull request on its own', () => {
    const failed = (over: Partial<FixPr>) =>
      judgeOpenPr(pr(over), want)
        .map((c, i) => (c.pass ? -1 : i))
        .filter((i) => i >= 0);
    expect(failed({ status: 'abandoned' })).toEqual([0]);
    expect(failed({ targetRefName: 'refs/heads/other' })).toEqual([0]);
    expect(failed({ title: 'Bump lodash from 4.17.20 to 4.17.22' })).toEqual([1]);
    expect(
      failed({ description: `${'d'.repeat(4001 - CLOSING_SENTENCE.length)}${CLOSING_SENTENCE}` }),
    ).toEqual([2]);
    expect(
      failed({ description: `${'d'.repeat(4000 - CLOSING_SENTENCE.length)}${CLOSING_SENTENCE}` }),
    ).toEqual([]);
    expect(failed({ description: null })).toEqual([2]);
    expect(failed({ createdBy: { id: OTHER } })).toEqual([3]);
  });

  const thread = (over: Partial<Thr> & { content?: string; author?: string } = {}): Thr => {
    const { content = CANCEL_TEXT, author = SP, ...rest } = over;
    return {
      id: 3,
      status: 'closed',
      comments: [{ id: 1, content, author: { id: author } }],
      ...rest,
    };
  };

  it("finds Qualor's closed thread on the pull request as a whole", () => {
    expect(closedThread([thread()], SP)?.id).toBe(3);
    expect(closedThread([thread({ author: OTHER })], SP)).toBeUndefined();
    expect(closedThread([thread({ content: 'something else' })], SP)).toBeUndefined();
    expect(
      closedThread([thread({ threadContext: { filePath: '/package.json' } })], SP),
    ).toBeUndefined();
  });

  it('passes the cancelled pull request: abandoned, the closed thread, the branch gone', () => {
    const closed = pr({ status: 'abandoned' });
    expect(judgeClosed(closed, [thread()], undefined, SP).map((c) => c.pass)).toEqual([
      true,
      true,
      true,
    ]);
    expect(judgeClosed(pr(), [thread()], undefined, SP)[0]?.pass).toBe(false);
    expect(judgeClosed(closed, [thread({ status: 'active' })], undefined, SP)[1]?.pass).toBe(false);
    expect(judgeClosed(closed, [thread({ status: 4 })], undefined, SP)[1]?.pass).toBe(true);
    expect(judgeClosed(closed, [], undefined, SP)[1]?.pass).toBe(false);
    expect(judgeClosed(closed, [thread()], 'a'.repeat(40), SP)[2]?.pass).toBe(false);
  });
});
