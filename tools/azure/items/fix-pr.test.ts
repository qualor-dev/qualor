import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { cancelComment, fixBody, fixTitle } from '../../../server/src/fixes/body';
import type { Thr } from './19-decoration.js';
import {
  benchFixYaml,
  clearFixWith,
  CANCEL_TEXT,
  CLOSING_SENTENCE,
  closedThread,
  endsWithClosing,
  FIX_DOCKER_PATH,
  fixedFor,
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
  type ClearOps,
  type FixPr,
  type KnownFix,
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

  /** The advisories the bench listed for lodash 4.17.20 on 2026-11-24 (live run 1). */
  const BENCH_ADVISORIES = [
    { vulnerabilityId: 'CVE-2021-23337', fixedVersion: '4.17.21' },
    { vulnerabilityId: 'CVE-2026-4800', fixedVersion: '4.18.0' },
    { vulnerabilityId: 'CVE-2020-28500', fixedVersion: '4.17.21' },
    { vulnerabilityId: 'CVE-2025-13465', fixedVersion: '4.17.23' },
  ];

  it('wants at least the highest fixed version among the listed advisories', () => {
    const ok = judgeTarget('4.18.0', BENCH_ADVISORIES);
    expect(ok.pass).toBe(true);
    expect(ok.got).toBe(
      'target 4.18.0; highest fixed version 4.18.0 (CVE-2026-4800) among CVE-2021-23337 4.17.21, CVE-2026-4800 4.18.0, CVE-2020-28500 4.17.21, CVE-2025-13465 4.17.23',
    );
    expect(judgeTarget('4.17.23', BENCH_ADVISORIES).pass).toBe(false);
    expect(judgeTarget('4.17.21', BENCH_ADVISORIES).pass).toBe(false);
    expect(judgeTarget('4.18.1', BENCH_ADVISORIES).pass).toBe(true);
    // Numeric, not textual: 4.17.100 is above 4.17.23.
    expect(judgeTarget('4.17.100', [{ vulnerabilityId: 'A', fixedVersion: '4.17.23' }]).pass).toBe(
      true,
    );
  });

  it('fails without a target, a version, or an advisory with a fixed version', () => {
    expect(judgeTarget(null, BENCH_ADVISORIES).pass).toBe(false);
    expect(judgeTarget('latest', BENCH_ADVISORIES).pass).toBe(false);
    const none = judgeTarget('4.18.0', [{ vulnerabilityId: 'A', fixedVersion: null }]);
    expect(none).toMatchObject({
      pass: false,
      got: 'target 4.18.0; no listed advisory has a fixed version above 4.17.20',
    });
    expect(judgeTarget('4.18.0', []).pass).toBe(false);
  });

  it("takes an advisory's lowest fixed version above the installed one", () => {
    expect(fixedFor({ vulnerabilityId: 'A', fixedVersion: '3.10.0, 4.17.22, 4.17.30' })).toBe(
      '4.17.22',
    );
    expect(fixedFor({ vulnerabilityId: 'A', fixedVersion: '4.17.19' })).toBeNull();
    expect(fixedFor({ vulnerabilityId: 'A', fixedVersion: null })).toBeNull();
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

describe('item 24 clean-up (clearFixWith)', () => {
  const OPEN: KnownFix = { id: 'f1', state: 'open', branch: BRANCH, mrNumber: 7 };

  /** Stubbed calls that log their order; a call named in `fail` throws. */
  function stubs(
    over: { reread?: () => KnownFix | undefined; active?: number[]; stillActive?: number[] } = {},
    fail: string[] = [],
  ) {
    const calls: string[] = [];
    const step = (name: string): void => {
      calls.push(name);
      if (fail.includes(name)) throw new Error(`${name} failed`);
    };
    const ops: ClearOps = {
      reread: () => {
        step('reread');
        return Promise.resolve(over.reread ? over.reread() : OPEN);
      },
      cancel: (id) => Promise.resolve().then(() => step(`cancel ${id}`)),
      activePrs: (branch) =>
        Promise.resolve().then(() => {
          step(`activePrs ${branch}`);
          return over.active ?? [];
        }),
      isActive: (id) =>
        Promise.resolve().then(() => {
          step(`isActive ${id}`);
          return (over.stillActive ?? []).includes(id);
        }),
      abandon: (id) => Promise.resolve().then(() => step(`abandon ${id}`)),
      deleteBranch: (branch) => Promise.resolve().then(() => step(`deleteBranch ${branch}`)),
    };
    return { ops, calls };
  }

  it('cancels in Qualor first, then abandons the pull requests and deletes the branch', async () => {
    const { ops, calls } = stubs({ active: [7] });
    await clearFixWith(ops, OPEN);
    expect(calls).toEqual([
      'reread',
      'cancel f1',
      `activePrs ${BRANCH}`,
      'abandon 7',
      `deleteBranch ${BRANCH}`,
    ]);
  });

  it('cancels nothing that has ended, and still clears Azure DevOps', async () => {
    const { ops, calls } = stubs({ reread: () => ({ ...OPEN, state: 'cancelled' }) });
    await clearFixWith(ops, OPEN);
    expect(calls).toEqual([
      'reread',
      `activePrs ${BRANCH}`,
      'isActive 7',
      `deleteBranch ${BRANCH}`,
    ]);
  });

  it('clears Azure DevOps when the cancel fails, and then throws', async () => {
    const { ops, calls } = stubs({ active: [7, 9] }, ['cancel f1']);
    await expect(clearFixWith(ops, OPEN)).rejects.toThrow('the bench Qualor: cancel f1 failed');
    expect(calls).toEqual([
      'reread',
      'cancel f1',
      `activePrs ${BRANCH}`,
      'abandon 7',
      'abandon 9',
      `deleteBranch ${BRANCH}`,
    ]);
  });

  it("falls back to the fix's last known branch and pull request when the re-read fails", async () => {
    const other = 'qualor/fix/js/lodash-2';
    const { ops, calls } = stubs({ stillActive: [11] }, ['reread']);
    await expect(
      clearFixWith(ops, { id: 'f2', state: 'open', branch: other, mrNumber: 11 }),
    ).rejects.toThrow('the bench Qualor: reread failed');
    expect(calls).toEqual([
      'reread',
      `activePrs ${other}`,
      'isActive 11',
      'abandon 11',
      `deleteBranch ${other}`,
    ]);
  });

  it('keeps going past a failed listing or abandon, deletes the branch, and names every failure', async () => {
    const listing = stubs({ stillActive: [7] }, [`activePrs ${BRANCH}`]);
    await expect(clearFixWith(listing.ops, OPEN)).rejects.toThrow(
      `the pull requests of ${BRANCH}: activePrs ${BRANCH} failed`,
    );
    // The listing failed: the known pull request is still abandoned when it is active.
    expect(listing.calls).toEqual([
      'reread',
      'cancel f1',
      `activePrs ${BRANCH}`,
      'isActive 7',
      'abandon 7',
      `deleteBranch ${BRANCH}`,
    ]);

    const abandon = stubs({ active: [7, 9] }, ['cancel f1', 'abandon 7']);
    await expect(clearFixWith(abandon.ops, OPEN)).rejects.toThrow(
      'the bench Qualor: cancel f1 failed; abandon pull request 7: abandon 7 failed',
    );
    expect(abandon.calls.slice(-2)).toEqual(['abandon 9', `deleteBranch ${BRANCH}`]);
  });
});
