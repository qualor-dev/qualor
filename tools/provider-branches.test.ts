import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SCM_PROVIDERS } from '../packages/shared/src/scm';

/**
 * Guard against two-way provider branches. Every comparison of a value with 'gitlab' or 'github'
 * must either move to an exhaustive switch (assertNever default, or `@default never;` in a template) or a Record<ScmProvider, T>, or
 * carry a `provider-guard: <reason>` marker. No file is exempt.
 */
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIRS = ['server/src', 'cli/src', 'packages/shared/src', 'ui/src', 'enterprise/src'];
const SKIP = /\.(test|spec|db\.test)\.ts$|^ui\/src\/app\/api\/schema\.ts$/;
const COMPARISON =
  /(?:[!=]==|<>|!=)\s*['"](?:gitlab|github)['"]|['"](?:gitlab|github)['"]\s*[!=]==/;

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

/** The text from `open` (an opening bracket) to its match, brackets balanced; null when unbalanced. */
function balanced(text: string, open: number, pair: '()' | '{}'): string | null {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === pair[0]) depth++;
    else if (text[i] === pair[1] && --depth === 0) return text.slice(open, i + 1);
  }
  return null;
}

/** The text of each TypeScript `switch (…provider…) { … }` block; the condition's parentheses balance. */
function providerSwitches(text: string): string[] {
  const blocks: string[] = [];
  const start = /switch\s*\(/g;
  for (let m = start.exec(text); m; m = start.exec(text)) {
    const open = m.index + m[0].length - 1;
    const condition = balanced(text, open, '()');
    if (condition === null || !/provider/i.test(condition)) continue;
    const brace = text.indexOf('{', open + condition.length);
    const body = brace < 0 ? null : balanced(text, brace, '{}');
    if (body === null) continue;
    blocks.push(text.slice(m.index, brace + body.length));
  }
  return blocks;
}

/** The text of each template `@switch (…) { … }` that has a 'gitlab' or 'github' case. */
function templateProviderSwitches(text: string): string[] {
  const blocks: string[] = [];
  const start = /@switch\s*\(/g;
  for (let m = start.exec(text); m; m = start.exec(text)) {
    const open = m.index + m[0].length - 1;
    const condition = balanced(text, open, '()');
    if (condition === null) continue;
    const brace = text.indexOf('{', open + condition.length);
    const body = brace < 0 ? null : balanced(text, brace, '{}');
    if (body === null) continue;
    const block = text.slice(m.index, brace + body.length);
    if (/@case\s*\(\s*['"](?:gitlab|github)['"]\s*\)/.test(block)) blocks.push(block);
  }
  return blocks;
}

const missingAssertNever = (text: string): string[] =>
  providerSwitches(text).filter((block) => !block.includes('assertNever('));
const missingDefaultNever = (text: string): string[] =>
  templateProviderSwitches(text).filter((block) => !/@default\s+never\s*;/.test(block));

describe('provider branches', () => {
  const current = counts();

  it('no file has an unmarked provider comparison', () => {
    expect(current).toEqual({});
  });

  it('every TypeScript switch on a provider ends in assertNever', () => {
    const bad: string[] = [];
    for (const file of sources(['server/src', 'cli/src', 'ui/src'])) {
      if (!file.endsWith('.ts')) continue;
      for (const block of missingAssertNever(read(file)))
        bad.push(`${file}: ${block.split('\n')[0]}`);
    }
    expect(bad).toEqual([]);
  });

  it('every template @switch with a provider case ends in @default never;', () => {
    const bad: string[] = [];
    for (const file of sources(['ui/src'])) {
      if (!file.endsWith('.html')) continue;
      for (const block of missingDefaultNever(read(file)))
        bad.push(`${file}: ${block.split('\n')[0]}`);
    }
    expect(bad).toEqual([]);
  });

  describe('positive controls: each rule flags a sample it must flag', () => {
    it('a TS switch without assertNever, also with a nested-paren condition', () => {
      const plain = "switch (row.provider) { case 'gitlab': return 1; default: return 2; }";
      const nested = "switch (providerOf(row.connection(a))) { case 'gitlab': return 1; }";
      expect(missingAssertNever(plain)).toHaveLength(1);
      expect(missingAssertNever(nested)).toHaveLength(1);
    });

    it('accepts a TS switch that ends in assertNever, and ignores one on another value', () => {
      const ok = 'switch (p(x)) { case 1: break; default: return assertNever(p(x)); }';
      expect(missingAssertNever(ok.replace('p(x)', 'provider(x)'))).toEqual([]);
      expect(missingAssertNever('switch (kind(x)) { case 1: break; }')).toEqual([]);
    });

    it('a template @switch with a provider case but no @default never;', () => {
      const bad = "@switch (needs()) { @case ('gitlab') { <p>a</p> } @case (null) { } }";
      const ok = "@switch (provider) { @case ('github') { <p>a</p> } @default never; }";
      expect(missingDefaultNever(bad)).toHaveLength(1);
      expect(missingDefaultNever(ok)).toEqual([]);
      expect(missingDefaultNever('@switch (n) { @case (1) { } }')).toEqual([]);
    });
  });

  it('the UI’s provider list is the shared one', () => {
    const found = /export const SCM_PROVIDERS = (\[[^\]]*\]) as const;/.exec(
      read('ui/src/app/shared/scm-provider.ts'),
    );
    expect(found).not.toBeNull();
    expect(JSON.parse(found![1]!.replaceAll("'", '"'))).toEqual([...SCM_PROVIDERS]);
  });
});
