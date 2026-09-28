import { mkdirSync, renameSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { commitAll, fileUrl, GIT_TEST_ENV, gitSync, initRepo, settingsFor } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { detectCi, type CiInfo } from '../config/ci';
import { CliError } from '../errors';
import { createLogger, silentLogger, type Logger } from '../log';
import type { BaselineWarning, NewCodeBaselineClient } from '../server/baseline-client';
import { Warnings } from '../warnings';
import { createGit, type Git } from './git';
import { resolveScm, type ScmFlags } from './scm';

const tmp = useTempDirs();
const TEN = Array.from({ length: 10 }, (_, i) => `line ${i + 1}`).join('\n') + '\n';

function resolve(
  root: string,
  options: {
    flags?: ScmFlags;
    config?: Parameters<typeof settingsFor>[1];
    ci?: Parameters<typeof settingsFor>[2];
    client?: NewCodeBaselineClient | null;
    log?: Logger;
  } = {},
) {
  const warnings = new Warnings();
  const result = resolveScm({
    git: createGit(root, GIT_TEST_ENV),
    settings: settingsFor(root, options.config, options.ci),
    flags: options.flags ?? {},
    baselineClient: options.client ?? null,
    warnings,
    log: options.log ?? silentLogger,
    deepenSteps: [50],
  });
  return { result, warnings };
}

const codes = (w: Warnings) => w.list().map((x) => x.code);

/** main (1 commit) + feature (changes of every kind) + an untracked file; origin/main points at main. */
function featureRepo(): { root: string; base: string } {
  const root = tmp();
  initRepo(root);
  writeTree(root, {
    'src/a.ts': TEN,
    'src/old.ts': TEN,
    'src/same.ts': 'same\n',
    'src/dir with space/ü.ts': 'a\nb\nc\n',
  });
  const base = commitAll(root, 'base');
  gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
  gitSync(root, 'checkout', '-q', '-b', 'feature');
  writeTree(root, {
    'src/a.ts': TEN.replace('line 3', 'LINE 3') + 'line 11\n',
    'src/added.ts': 'new\n',
    'src/dir with space/ü.ts': 'a\nB\nc\n',
  });
  renameSync(path.join(root, 'src', 'old.ts'), path.join(root, 'src', 'new.ts'));
  writeTree(root, { 'src/new.ts': TEN.replace('line 5', 'LINE 5') });
  commitAll(root, 'feature');
  writeTree(root, { 'src/untracked.ts': 'u\n' });
  return { root, base };
}

describe('resolveScm: branches and merge requests', () => {
  it('diffs a feature branch against its merge-base with main', async () => {
    const { root, base } = featureRepo();
    const { result, warnings } = resolve(root);
    const { scm, newLines } = await result;
    expect(scm).toMatchObject({
      provider: 'none',
      branch: 'feature',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: base, kind: 'merge_base', status: 'ok' },
      renames: [{ from: 'src/old.ts', to: 'src/new.ts' }],
    });
    expect(scm.revision).toBe(gitSync(root, 'rev-parse', 'HEAD'));
    expect(newLines('src/a.ts')).toEqual([
      [3, 3],
      [11, 11],
    ]);
    expect(newLines('src/new.ts')).toEqual([[5, 5]]);
    expect(newLines('src/added.ts')).toBe('all');
    expect(newLines('src/untracked.ts')).toBe('all');
    expect(newLines('src/dir with space/ü.ts')).toEqual([[2, 2]]);
    expect(newLines('src/same.ts')).toEqual([]);
    expect(warnings.list()).toEqual([]);
  });

  it('reports an unavailable baseline (never "no new code") when origin/main is missing and autoFetch is off', async () => {
    const { root } = featureRepo();
    gitSync(root, 'update-ref', '-d', 'refs/remotes/origin/main');
    const { result, warnings } = resolve(root, { config: { scm: { autoFetch: false } } });
    const { scm, newLines } = await result;
    expect(scm.baseline).toEqual({ revision: null, kind: 'merge_base', status: 'unavailable' });
    expect(newLines('src/a.ts')).toBeUndefined();
    expect(codes(warnings)).toEqual(['BASELINE_UNAVAILABLE']);
  });

  it(
    'fetches and deepens a shallow merge-request clone until the merge-base exists',
    { timeout: 60_000 },
    async () => {
      const origin = tmp();
      initRepo(origin);
      for (let i = 1; i <= 6; i++) {
        writeTree(origin, { [`f${i}.txt`]: `${i}\n` });
        commitAll(origin, `c${i}`);
      }
      gitSync(origin, 'checkout', '-q', '-b', 'feature', 'HEAD~3');
      for (let i = 7; i <= 9; i++) {
        writeTree(origin, { [`g${i}.txt`]: `${i}\n` });
        commitAll(origin, `c${i}`);
      }
      const expectedBase = gitSync(origin, 'merge-base', 'feature', 'main');
      gitSync(origin, 'checkout', '-q', 'main');
      const parent = tmp();
      gitSync(
        parent,
        'clone',
        '-q',
        '--depth',
        '1',
        '--branch',
        'feature',
        '--single-branch',
        fileUrl(origin),
        'clone',
      );
      const clone = path.join(parent, 'clone');
      expect(gitSync(clone, 'rev-parse', '--is-shallow-repository')).toBe('true');

      const off = resolve(clone, {
        flags: { mr: '7', mrTarget: 'main' },
        config: { scm: { autoFetch: false } },
      });
      expect((await off.result).scm.baseline.status).toBe('unavailable');

      const { result, warnings } = resolve(clone, { flags: { mr: '7', mrTarget: 'main' } });
      const { scm, newLines } = await result;
      expect(scm.mergeRequest).toEqual({ id: '7', targetBranch: 'main', sourceBranch: 'feature' });
      expect(scm.baseline).toEqual({ revision: expectedBase, kind: 'merge_base', status: 'ok' });
      expect(newLines('g7.txt')).toBe('all');
      expect(newLines('f1.txt')).toEqual([]);
      expect(warnings.list()).toEqual([]);
    },
  );

  it(
    're-fetches a stale origin/<target> when autoFetch is on, and uses the local copy when it is off',
    { timeout: 60_000 },
    async () => {
      const origin = tmp();
      initRepo(origin);
      writeTree(origin, { 'a.txt': 'a\n' });
      const c1 = commitAll(origin, 'c1');
      writeTree(origin, { 'b.txt': 'b\n' });
      const c2 = commitAll(origin, 'c2');
      const parent = tmp();
      gitSync(parent, 'clone', '-q', fileUrl(origin), 'clone');
      const clone = path.join(parent, 'clone');
      gitSync(clone, 'checkout', '-q', '-b', 'feature');
      writeTree(clone, { 'c.txt': 'c\n' });
      commitAll(clone, 'c3');
      // A cached CI workspace: origin/main still points at an older commit than the real main.
      gitSync(clone, 'update-ref', 'refs/remotes/origin/main', c1);

      const stale = await resolve(clone, { config: { scm: { autoFetch: false } } }).result;
      expect(stale.scm.baseline).toEqual({ revision: c1, kind: 'merge_base', status: 'ok' });

      const { result, warnings } = resolve(clone);
      const { scm, newLines } = await result;
      expect(scm.baseline).toEqual({ revision: c2, kind: 'merge_base', status: 'ok' });
      expect(newLines('b.txt')).toEqual([]);
      expect(newLines('c.txt')).toBe('all');
      expect(warnings.list()).toEqual([]);
    },
  );

  it('uses origin/<target> already in the clone, without a warning, when it cannot be refreshed', async () => {
    // GitHub's checkout with persist-credentials: false and fetch-depth: 0 (github.md §11): the
    // target is in the clone, but a fetch of a private repository has no credentials.
    const { root, base } = featureRepo();
    const lines: string[] = [];
    const log = createLogger('debug', (text) => lines.push(text));
    const { result, warnings } = resolve(root, { log });
    expect((await result).scm.baseline).toEqual({
      revision: base,
      kind: 'merge_base',
      status: 'ok',
    });
    expect(warnings.list()).toEqual([]);
    expect(lines.filter((l) => l.startsWith('warn: '))).toEqual([]);
    expect(lines).toContain('could not refresh origin/main; using the copy already in the clone\n');
  });

  it('refuses branch names that could be read as git options', async () => {
    const { root } = featureRepo();
    const { result, warnings } = resolve(root, {
      flags: { mr: '1', mrTarget: '--upload-pack=touch pwned' },
    });
    expect((await result).scm.baseline.status).toBe('unavailable');
    expect(warnings.list()[0]?.message).toContain('not a valid branch name');
  });

  it('uses a valid CI revision and CI branch names', async () => {
    const { root } = featureRepo();
    const ci = {
      ...detectCi({}),
      provider: 'gitlab' as const,
      revision: 'a'.repeat(40),
      branch: 'feature',
      mainBranch: 'main',
    };
    const { scm } = await resolve(root, { ci }).result;
    expect(scm).toMatchObject({ provider: 'gitlab', revision: 'a'.repeat(40), branch: 'feature' });
  });

  it('copies the GitLab CI context into scm.gitlab, and leaves it out elsewhere (scm.md §3)', async () => {
    const { root } = featureRepo();
    const ci = {
      ...detectCi({}),
      provider: 'gitlab' as const,
      gitlab: {
        projectId: '4711',
        pipelineId: '99001',
        mergeRequestEventType: 'detached' as const,
      },
    };
    const { scm } = await resolve(root, { ci }).result;
    expect(scm.gitlab).toEqual({
      projectId: '4711',
      pipelineId: '99001',
      mergeRequestEventType: 'detached',
    });
    expect((await resolve(root).result).scm).not.toHaveProperty('gitlab');
  });

  it('leaves scm.gitlab out when GitLab CI gave none of its values (scm.md §3)', async () => {
    const { root } = featureRepo();
    const ci = { ...detectCi({}), provider: 'gitlab' as const, gitlab: {} };
    const { scm } = await resolve(root, { ci }).result;
    expect(scm).not.toHaveProperty('gitlab');
  });

  it('warns and falls back to HEAD when the CI-reported revision is not a valid git SHA', async () => {
    const { root } = featureRepo();
    const ci = { ...detectCi({}), revision: 'not-a-sha' };
    const { result, warnings } = resolve(root, { ci });
    const { scm } = await result;
    expect(scm.revision).toBe(gitSync(root, 'rev-parse', 'HEAD'));
    expect(codes(warnings)).toEqual(['CI_REVISION_INVALID']);
  });

  it('reports BASELINE_DETACHED_HEAD when HEAD is detached and no --branch is given', async () => {
    const { root } = featureRepo();
    gitSync(root, 'checkout', '-q', '--detach', 'HEAD');
    const { result, warnings } = resolve(root);
    const { scm, newLines } = await result;
    expect(scm.branch).toBeNull();
    expect(scm.baseline).toEqual({ revision: null, kind: 'none', status: 'unavailable' });
    expect(newLines('src/a.ts')).toBeUndefined();
    expect(codes(warnings)).toEqual(['BASELINE_DETACHED_HEAD']);
  });

  it('counts an uncommitted edit to a tracked file as new (ruling C15)', async () => {
    const { root } = featureRepo();
    writeTree(root, { 'src/same.ts': 'changed\n' });
    const { newLines } = await resolve(root).result;
    expect(newLines('src/same.ts')).toEqual([[1, 1]]);
  });

  it(
    'falls back to --unshallow when the deepen steps are not enough to reach the merge-base',
    { timeout: 60_000 },
    async () => {
      const origin = tmp();
      initRepo(origin);
      for (let i = 1; i <= 6; i++) {
        writeTree(origin, { [`f${i}.txt`]: `${i}\n` });
        commitAll(origin, `c${i}`);
      }
      gitSync(origin, 'checkout', '-q', '-b', 'feature', 'HEAD~3');
      for (let i = 7; i <= 9; i++) {
        writeTree(origin, { [`g${i}.txt`]: `${i}\n` });
        commitAll(origin, `c${i}`);
      }
      const expectedBase = gitSync(origin, 'merge-base', 'feature', 'main');
      gitSync(origin, 'checkout', '-q', 'main');
      const parent = tmp();
      gitSync(
        parent,
        'clone',
        '-q',
        '--depth',
        '1',
        '--branch',
        'feature',
        '--single-branch',
        fileUrl(origin),
        'clone',
      );
      const clone = path.join(parent, 'clone');

      // deepenSteps: [1] is deliberately too small to reach a merge-base 3 commits back, so this
      // must exercise the final `--unshallow` fallback rather than succeeding during the loop.
      const warnings = new Warnings();
      const { scm } = await resolveScm({
        git: createGit(clone, GIT_TEST_ENV),
        settings: settingsFor(clone),
        flags: { mr: '7', mrTarget: 'main' },
        baselineClient: null,
        warnings,
        log: silentLogger,
        deepenSteps: [1],
      });
      expect(scm.baseline).toEqual({ revision: expectedBase, kind: 'merge_base', status: 'ok' });
      expect(gitSync(clone, 'rev-parse', '--is-shallow-repository')).toBe('false');
      expect(warnings.list()).toEqual([]);
    },
  );
});

describe('resolveScm: newLines correctness under hostile git configuration', () => {
  it('counts only the truly changed lines when diff.interHunkContext would otherwise merge nearby hunks', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'f.txt': 'l1\nl2\nl3\nl4\nl5\n' });
    const base = commitAll(root, 'base');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'f.txt': 'l1\nCHANGED2\nl3\nCHANGED4\nl5\n' });
    commitAll(root, 'feature');
    // A user- or repo-level setting, not something the CLI controls; the fix must override it.
    gitSync(root, 'config', 'diff.interHunkContext', '3');
    const { newLines } = await resolve(root).result;
    expect(newLines('f.txt')).toEqual([
      [2, 2],
      [4, 4],
    ]);
  });

  it('ignores a .gitattributes textconv driver so newLines matches the real file, not the converted text', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, {
      'f.txt': 'l1\nl2\nl3\n',
      '.gitattributes': 'f.txt diff=upper\n',
      'textconv.sh': '#!/bin/sh\ntr a-z A-Z < "$1"\n',
    });
    const base = commitAll(root, 'base');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'f.txt': 'l1\nCHANGED2\nl3\n' });
    commitAll(root, 'feature');
    gitSync(root, 'config', 'diff.upper.textconv', 'sh textconv.sh');
    const { newLines } = await resolve(root).result;
    expect(newLines('f.txt')).toEqual([[2, 2]]);
  });

  it('omits newLines for a modified binary file instead of reporting it as unchanged', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'img.bin': new Uint8Array([0, 1, 2, 3]) });
    const base = commitAll(root, 'base');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'img.bin': new Uint8Array([0, 1, 2, 99]) });
    commitAll(root, 'feature');
    const { newLines } = await resolve(root).result;
    expect(newLines('img.bin')).toBeUndefined();
  });

  it('still reports a newly added binary file as "all"', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'src/a.ts': TEN });
    const base = commitAll(root, 'base');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'img.bin': new Uint8Array([0, 1, 2, 3]) });
    commitAll(root, 'feature');
    const { newLines } = await resolve(root).result;
    expect(newLines('img.bin')).toBe('all');
  });
});

describe('resolveScm: main branch', () => {
  function mainRepo(): { root: string; first: string } {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'src/a.ts': TEN });
    const first = commitAll(root, 'c1');
    writeTree(root, { 'src/a.ts': TEN.replace('line 2', 'LINE 2') });
    commitAll(root, 'c2');
    writeTree(root, { 'src/a.ts': TEN.replace('line 2', 'LINE 2').replace('line 9', 'LINE 9') });
    commitAll(root, 'c3');
    return { root, first };
  }
  const client = (
    answer: { revision: string | null; warnings?: BaselineWarning[] } | 'unsupported',
    asked: unknown[] = [],
  ): NewCodeBaselineClient => ({
    fetchBaseline: (q) => {
      asked.push(q);
      return Promise.resolve(answer === 'unsupported' ? answer : { warnings: [], ...answer });
    },
  });

  it('passes the scan version and copies the server warnings into the report (N3)', async () => {
    const { root, first } = mainRepo();
    const asked: unknown[] = [];
    const { result, warnings } = resolve(root, {
      config: { project: { key: 'acme/app', version: '2.0.0' } },
      client: client({ revision: first, warnings: ['NEW_CODE_DEFINITION_FALLBACK'] }, asked),
    });
    expect((await result).scm.baseline.status).toBe('ok');
    expect(asked).toEqual([{ projectKey: 'acme/app', branch: 'main', version: '2.0.0' }]);
    expect(codes(warnings)).toEqual(['NEW_CODE_DEFINITION_FALLBACK']);
    expect(warnings.list()[0]?.message).toContain('days: 30');
  });

  it('diffs against the server baseline', async () => {
    const { root, first } = mainRepo();
    const { scm, newLines } = await resolve(root, { client: client({ revision: first }) }).result;
    expect(scm.baseline).toEqual({ revision: first, kind: 'server_baseline', status: 'ok' });
    expect(newLines('src/a.ts')).toEqual([
      [2, 2],
      [9, 9],
    ]);
  });

  it('records a first analysis without newLines', async () => {
    const { root } = mainRepo();
    const { scm, newLines } = await resolve(root, { client: client({ revision: null }) }).result;
    expect(scm.baseline).toEqual({
      revision: null,
      kind: 'server_baseline',
      status: 'first_analysis',
    });
    expect(newLines('src/a.ts')).toBeUndefined();
  });

  it('treats a missing endpoint or a missing server as unavailable, with a warning', async () => {
    const { root } = mainRepo();
    const missing = resolve(root, { client: client('unsupported') });
    expect((await missing.result).scm.baseline.status).toBe('unavailable');
    expect(codes(missing.warnings)).toEqual(['BASELINE_ENDPOINT_UNAVAILABLE']);
    const none = resolve(root, { client: null });
    expect((await none.result).scm.baseline.status).toBe('unavailable');
    expect(codes(none.warnings)).toEqual(['BASELINE_SERVER_NOT_CONFIGURED']);
  });

  it('reports a distinct warning when the server is configured but project.key is missing', async () => {
    const { root } = mainRepo();
    const { result, warnings } = resolve(root, {
      config: { project: {} },
      client: client({ revision: null }),
    });
    expect((await result).scm.baseline.status).toBe('unavailable');
    expect(codes(warnings)).toEqual(['BASELINE_PROJECT_KEY_MISSING']);
  });

  it('rejects an invalid revision from the baseline endpoint instead of treating it as a commit', async () => {
    const { root } = mainRepo();
    const { result, warnings } = resolve(root, { client: client({ revision: 'not-a-valid-sha' }) });
    const { scm, newLines } = await result;
    expect(scm.baseline).toEqual({
      revision: null,
      kind: 'server_baseline',
      status: 'unavailable',
    });
    expect(newLines('src/a.ts')).toBeUndefined();
    expect(codes(warnings)).toEqual(['BASELINE_UNAVAILABLE']);
    expect(warnings.list()[0]?.message).toContain('invalid revision');
  });

  it(
    'fetches a server baseline commit missing from a shallow clone',
    { timeout: 60_000 },
    async () => {
      const { root: origin, first } = mainRepo();
      const parent = tmp();
      gitSync(parent, 'clone', '-q', '--depth', '1', fileUrl(origin), 'clone');
      const clone = path.join(parent, 'clone');
      const { scm, newLines } = await resolve(clone, { client: client({ revision: first }) })
        .result;
      expect(scm.baseline.status).toBe('ok');
      expect(newLines('src/a.ts')).toEqual([
        [2, 2],
        [9, 9],
      ]);
    },
  );
});

describe('resolveScm: repository shape', () => {
  it('exits 2 outside a git work tree and in a repository without commits', async () => {
    const plain = tmp();
    await expect(resolve(plain).result).rejects.toMatchObject({ exitCode: 2 });
    const empty = tmp();
    initRepo(empty);
    const err: unknown = await resolve(empty).result.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).message).toContain('no commits');
  });

  it('includes git\'s stderr (e.g. a dubious-ownership refusal) in the "not a git work tree" error', async () => {
    const root = tmp();
    const dubious: Git = async (args) =>
      args[0] === 'rev-parse' && args.includes('--is-inside-work-tree')
        ? {
            code: 128,
            stdout: '',
            stderr:
              "fatal: detected dubious ownership in repository at '/repo'\n" +
              'To add an exception for this directory, call:\n' +
              '\tgit config --global --add safe.directory /repo',
          }
        : { code: 0, stdout: '', stderr: '' };
    const err: unknown = await resolveScm({
      git: dubious,
      settings: settingsFor(root),
      flags: {},
      baselineClient: null,
      warnings: new Warnings(),
      log: silentLogger,
      deepenSteps: [50],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(2);
    expect((err as CliError).message).toContain('detected dubious ownership');
    expect((err as CliError).message).toContain('safe.directory');
  });

  it('reports paths relative to a scan root inside a larger repository', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'app/src/x.ts': TEN, 'other/y.ts': TEN });
    const base = commitAll(root, 'base');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', base);
    gitSync(root, 'checkout', '-q', '-b', 'feature');
    writeTree(root, { 'app/src/x.ts': TEN.replace('line 4', 'LINE 4'), 'other/y.ts': 'changed\n' });
    commitAll(root, 'change');
    mkdirSync(path.join(root, 'app'), { recursive: true });
    const { newLines, scm } = await resolve(path.join(root, 'app')).result;
    expect(scm.baseline.status).toBe('ok');
    expect(newLines('src/x.ts')).toEqual([[4, 4]]);
  });
});

describe('scm.github.checkout (github.md §3)', () => {
  /** A CiInfo of a GitHub pull request workflow (github.md §3). */
  const githubCi = () => ({
    ...detectCi({}),
    provider: 'github' as const,
    mergeRequest: { id: '7', targetBranch: 'main' },
    gitlab: null,
  });

  /** One commit on main, origin/main pointing at it; returns the root and HEAD. */
  function oneCommitRepo(): { root: string; head: string } {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'a.ts': 'a\n' });
    const head = commitAll(root, 'a');
    gitSync(root, 'update-ref', 'refs/remotes/origin/main', head);
    return { root, head };
  }

  const resolveWith = async (root: string, ci: CiInfo) => (await resolve(root, { ci }).result).scm;

  it('is head when HEAD is the pull request head, other when it is not', async () => {
    const { root, head } = oneCommitRepo();
    const ci = { ...githubCi(), pullRequestHead: head, github: { repositoryId: '1' } };
    expect((await resolveWith(root, ci)).github).toEqual({ repositoryId: '1', checkout: 'head' });
    const other = { ...ci, pullRequestHead: 'f'.repeat(40) };
    expect((await resolveWith(root, other)).github).toEqual({
      repositoryId: '1',
      checkout: 'other',
    });
  });

  it('has no checkout on a push, and no github key when the context is empty', async () => {
    const { root } = oneCommitRepo();
    const push = {
      ...githubCi(),
      mergeRequest: null,
      pullRequestHead: null,
      github: { runId: '9' },
    };
    expect((await resolveWith(root, push)).github).toEqual({ runId: '9' });
    const none = { ...push, github: {} };
    expect(await resolveWith(root, none)).not.toHaveProperty('github');
  });
});
