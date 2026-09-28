import { spawnSync } from 'node:child_process';

/**
 * The DCO check (CONTRIBUTING.md, release.md §13): every commit of a pull request or merge
 * request, merges excepted, carries a `Signed-off-by:` line naming its author. The `dco` jobs of
 * both CIs run `tsx tools/release/dco.ts <base> <head>`; they need no secret and only read git.
 */
export interface Commit {
  sha: string;
  parents: number;
  author: string;
  email: string;
  message: string;
}

const SIGN_OFF = /^Signed-off-by:\s*(.+?)\s*<([^>]+)>\s*$/gm;

export function dcoProblems(commits: readonly Commit[]): string[] {
  const problems: string[] = [];
  for (const c of commits) {
    if (c.parents > 1) continue;
    const signed = [...c.message.matchAll(SIGN_OFF)].some(
      (m) => m[1] === c.author && m[2]?.toLowerCase() === c.email.toLowerCase(),
    );
    if (!signed) {
      const subject = c.message.split('\n')[0] ?? '';
      problems.push(
        `${c.sha.slice(0, 12)} ${JSON.stringify(subject)}: no "Signed-off-by: ${c.author} ` +
          `<${c.email}>" line`,
      );
    }
  }
  return problems;
}

/** Record and unit separators: no commit message can contain them. */
const RS = '\x1e';
const US = '\x1f';

export function parseLog(text: string): Commit[] {
  return text
    .split(RS)
    .map((r) => r.replace(/^\n/, ''))
    .filter((r) => r.trim() !== '')
    .map((r) => {
      const [sha = '', parents = '', author = '', email = '', message = ''] = r.split(US);
      return {
        sha,
        parents: parents.trim() === '' ? 0 : parents.trim().split(' ').length,
        author,
        email,
        message,
      };
    });
}

export function readCommits(base: string, head: string): Commit[] {
  const r = spawnSync(
    'git',
    ['log', `--format=%H${US}%P${US}%an${US}%ae${US}%B${RS}`, `${base}..${head}`],
    { encoding: 'utf8' },
  );
  if (r.status !== 0) throw new Error(`git log ${base}..${head} failed:\n${r.stderr}`);
  return parseLog(r.stdout);
}

if (process.argv[1]?.endsWith('dco.ts')) {
  const [base, head] = process.argv.slice(2);
  if (!base || !head) {
    process.stderr.write('usage: tsx tools/release/dco.ts <base sha> <head sha>\n');
    process.exitCode = 2;
  } else {
    const commits = readCommits(base, head);
    const problems = dcoProblems(commits);
    if (problems.length > 0) {
      process.stderr.write(
        `DCO: ${problems.length} commit(s) without a sign-off (CONTRIBUTING.md, "Licence and ` +
          `sign-off"; add it with git rebase --signoff):\n  ${problems.join('\n  ')}\n`,
      );
      process.exitCode = 1;
    } else {
      process.stdout.write(`DCO: all ${commits.length} commit(s) signed off\n`);
    }
  }
}
