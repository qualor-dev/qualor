import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Azure DevOps (sub-plans 2–9): each part of a later sub-plan that Azure DevOps reaches today is a
 * stub that answers "not available yet", and carries `azure-pending(<sub-plan>): <what>` on its line
 * (`<!-- azure-pending(N): … -->` in a template). PENDING is how many of each sub-plan's markers
 * the sources hold: a sub-plan that builds its part removes its markers and lowers its number, so
 * the count always says what is left. Sub-plan 9 ends with `{}`.
 */
export const PENDING: Record<string, number> = {};

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIRS = ['server/src', 'cli/src', 'packages/shared/src', 'ui/src', 'enterprise/src'];
const SKIP = /\.(test|spec|db\.test)\.ts$|^ui\/src\/app\/api\/schema(-ee)?\.ts$/;
const MARKER = /azure-pending\((\d+)\)/g;
/** A marker says what is pending: `azure-pending(N): <what>`. */
const NAMED = /azure-pending\(\d+\): \S/;

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== 'node_modules') walk(full, out);
    } else if (/\.(ts|html)$/.test(name)) out.push(full);
  }
}

function sources(): string[] {
  const files: string[] = [];
  for (const dir of DIRS) walk(join(ROOT, dir), files);
  return files
    .map((f) => relative(ROOT, f).replaceAll('\\', '/'))
    .filter((f) => !SKIP.test(f))
    .sort();
}

const read = (file: string): string => readFileSync(join(ROOT, file), 'utf8');

/** The markers of `text` by sub-plan number. */
export function markerCounts(text: string): Record<string, number> {
  const found: Record<string, number> = {};
  for (const m of text.matchAll(MARKER)) found[m[1]!] = (found[m[1]!] ?? 0) + 1;
  return found;
}

describe('azure-pending markers (Azure DevOps sub-plans 2–9)', () => {
  const files = sources();

  it('the sources hold as many markers of each sub-plan as PENDING says', () => {
    const total: Record<string, number> = {};
    for (const file of files) {
      for (const [plan, n] of Object.entries(markerCounts(read(file)))) {
        total[plan] = (total[plan] ?? 0) + n;
      }
    }
    expect(total).toEqual(PENDING);
  });

  it('every marker says what is pending, after a colon', () => {
    const bad: string[] = [];
    for (const file of files) {
      read(file)
        .split('\n')
        .forEach((line, i) => {
          if (line.includes('azure-pending') && !NAMED.test(line)) bad.push(`${file}:${i + 1}`);
        });
    }
    expect(bad).toEqual([]);
  });

  it('counts each marker of a line, by its number (positive control)', () => {
    const sample = [
      "case 'azure': // azure-pending(4): decoration",
      '<!-- azure-pending(2): the mapping --> // azure-pending(4): x',
      'azure-pending (4) is not a marker',
    ].join('\n');
    expect(markerCounts(sample)).toEqual({ '2': 1, '4': 2 });
    expect(NAMED.test('// azure-pending(7)')).toBe(false);
  });
});
