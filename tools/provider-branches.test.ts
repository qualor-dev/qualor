import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SCM_PROVIDERS } from '../packages/shared/src/scm';

/**
 * Guard against two-way provider branches. Every comparison of a value with 'gitlab' or 'github'
 * must either move to an exhaustive switch (assertNever default) or a Record<ScmProvider, T>, or
 * carry a `provider-guard: <reason>` marker. BASELINE lists the comparisons still to convert, per
 * file; later tasks lower it, and the test refuses a baseline entry that is already clean.
 */
const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const DIRS = ['server/src', 'cli/src', 'packages/shared/src', 'ui/src', 'enterprise/src'];
const SKIP = /\.(test|spec|db\.test)\.ts$|^ui\/src\/app\/api\/schema\.ts$/;
const COMPARISON =
  /(?:[!=]==|<>|!=)\s*['"](?:gitlab|github)['"]|['"](?:gitlab|github)['"]\s*[!=]==/;

const BASELINE: Record<string, number> = {
  'server/src/fixes/body.ts': 2,
  'server/src/fixes/repository.ts': 1,
  'server/src/llm/post.ts': 5,
  'server/src/llm/render.ts': 1,
  'server/src/onboarding/ci-setup.ts': 5,
  'server/src/onboarding/setup-run.ts': 2,
  'server/src/review/render.ts': 2,
  'server/src/review/reply-commands.ts': 1,
  'server/src/review/reply-job.ts': 1,
  'server/src/review/reply-scan.ts': 2,
  'server/src/review/reply-sides.ts': 1,
  'server/src/review/run-ends.ts': 1,
  'server/src/routes/github-webhooks.ts': 3,
  'server/src/routes/gitlab-webhooks.ts': 1,
  'server/src/routes/repository-setup.ts': 1,
  'server/src/routes/scm-connections.ts': 6,
  'ui/src/app/fixes/fix-link.ts': 2,
  'ui/src/app/project/settings/fixes-panel.html': 2,
  'ui/src/app/projects/add-repositories.page.html': 1,
  'ui/src/app/projects/repository-list.ts': 1,
  'ui/src/app/projects/repository-setup.ts': 2,
  'ui/src/app/projects/setup-result.ts': 5,
  'ui/src/app/settings/github.page.ts': 1,
  'ui/src/app/settings/gitlab.page.ts': 1,
  'ui/src/app/settings/repositories.page.html': 2,
  'ui/src/app/settings/repositories.page.ts': 5,
};

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== 'node_modules') walk(full, out);
    } else if (/\.(ts|html)$/.test(name)) out.push(full);
  }
}

function sources(dirs: string[] = DIRS): string[] {
  const files: string[] = [];
  for (const dir of dirs) walk(join(ROOT, dir), files);
  return files
    .map((f) => relative(ROOT, f).replaceAll('\\', '/'))
    .filter((f) => !SKIP.test(f))
    .sort();
}

const read = (file: string): string => readFileSync(join(ROOT, file), 'utf8');

function counts(): Record<string, number> {
  const found: Record<string, number> = {};
  for (const file of sources()) {
    const n = read(file)
      .split('\n')
      .filter((line) => COMPARISON.test(line) && !line.includes('provider-guard:')).length;
    if (n > 0) found[file] = n;
  }
  return found;
}

/** The text of each `switch (…provider…)` block, found by matching braces. */
function providerSwitches(text: string): string[] {
  const blocks: string[] = [];
  const start = /switch\s*\(([^)]*)\)\s*\{/g;
  for (let m = start.exec(text); m; m = start.exec(text)) {
    if (!/provider/i.test(m[1] ?? '')) continue;
    let depth = 1;
    let i = m.index + m[0].length;
    while (i < text.length && depth > 0) {
      if (text[i] === '{') depth++;
      else if (text[i] === '}') depth--;
      i++;
    }
    blocks.push(text.slice(m.index, i));
  }
  return blocks;
}

describe('provider branches', () => {
  const current = counts();

  it('no file has more unmarked provider comparisons than its baseline', () => {
    for (const [file, n] of Object.entries(current)) {
      expect(n, file).toBeLessThanOrEqual(BASELINE[file] ?? 0);
    }
  });

  it('the baseline holds no file that is already clean', () => {
    for (const [file, n] of Object.entries(BASELINE)) {
      expect(current[file] ?? 0, file).toBe(n);
    }
  });

  it('every switch on a provider ends in assertNever', () => {
    const bad: string[] = [];
    for (const file of sources(['server/src', 'cli/src', 'ui/src'])) {
      for (const block of providerSwitches(read(file))) {
        if (!block.includes('assertNever(')) bad.push(`${file}: ${block.split('\n')[0]}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('the UI’s provider list is the shared one', () => {
    const found = /export const SCM_PROVIDERS = (\[[^\]]*\]) as const;/.exec(
      read('ui/src/app/shared/scm-provider.ts'),
    );
    expect(found).not.toBeNull();
    expect(JSON.parse(found![1]!.replaceAll("'", '"'))).toEqual([...SCM_PROVIDERS]);
  });
});
