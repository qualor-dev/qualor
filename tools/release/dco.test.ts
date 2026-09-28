import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { dcoProblems, parseLog, type Commit } from './dco';

const commit = (message: string, o: Partial<Commit> = {}): Commit => ({
  sha: 'abcdef0123456789',
  parents: 1,
  author: 'Ada Lovelace',
  email: 'ada@example.com',
  message,
  ...o,
});

describe('the DCO check (release.md §13)', () => {
  it('accepts a commit signed off by its author', () => {
    expect(
      dcoProblems([commit('feat: x\n\nSigned-off-by: Ada Lovelace <ADA@example.com>\n')]),
    ).toEqual([]);
  });

  it('names a commit without a sign-off, or signed off by someone else', () => {
    expect(dcoProblems([commit('feat: x\n')])).toEqual([
      'abcdef012345 "feat: x": no "Signed-off-by: Ada Lovelace <ada@example.com>" line',
    ]);
    expect(
      dcoProblems([commit('fix: y\n\nSigned-off-by: Someone Else <else@example.com>\n')]),
    ).toHaveLength(1);
    // Quoted in the body, not a trailer line of its own.
    expect(
      dcoProblems([commit('fix: y\n\nsee Signed-off-by: Ada Lovelace <ada@example.com>\n')]),
    ).toHaveLength(1);
  });

  it('skips merge commits', () => {
    expect(dcoProblems([commit('Merge branch x\n', { parents: 2 })])).toEqual([]);
  });

  it('reads git log records', () => {
    const log =
      'a1\x1fp1\x1fAda\x1fada@x\x1ffeat: a\n\nSigned-off-by: Ada <ada@x>\n\x1e\n' +
      'b2\x1fp1 p2\x1fBob\x1fbob@x\x1fMerge\n\x1e\n';
    expect(parseLog(log)).toEqual([
      {
        sha: 'a1',
        parents: 1,
        author: 'Ada',
        email: 'ada@x',
        message: 'feat: a\n\nSigned-off-by: Ada <ada@x>\n',
      },
      { sha: 'b2', parents: 2, author: 'Bob', email: 'bob@x', message: 'Merge\n' },
    ]);
  });

  it('runs in both CIs, on pull and merge requests only, with no secret', () => {
    const gh = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      jobs: Record<
        string,
        {
          if?: string;
          steps: { run?: string; env?: Record<string, string>; with?: Record<string, unknown> }[];
        }
      >;
    };
    const job = gh.jobs['dco'];
    expect(job?.if).toBe("github.event_name == 'pull_request'");
    expect(job?.steps[0]?.with).toMatchObject({ 'fetch-depth': 0, 'persist-credentials': false });
    expect(
      job?.steps.some((s) => s.run === 'pnpm exec tsx tools/release/dco.ts "$BASE" "$HEAD"'),
    ).toBe(true);
    expect(JSON.stringify(job)).not.toMatch(/secrets|github\.token/);
    const gl = parse(readFileSync('.gitlab-ci.yml', 'utf8')) as Record<
      string,
      { rules?: { if: string }[]; variables?: Record<string, string>; script?: string[] }
    >;
    expect(gl['dco']?.rules).toEqual([{ if: '$CI_PIPELINE_SOURCE == "merge_request_event"' }]);
    expect(gl['dco']?.variables?.['GIT_DEPTH']).toBe('0');
    expect(gl['dco']?.script).toEqual([
      'pnpm exec tsx tools/release/dco.ts "$CI_MERGE_REQUEST_DIFF_BASE_SHA" "$CI_COMMIT_SHA"',
    ]);
  });
});
