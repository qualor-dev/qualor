import { describe, expect, it } from 'vitest';
import type { DesiredInlineIssue } from '../decoration-data';
import { annotationsOnDiff } from './decorate';
import { annotationsDigest } from './render';

const issue = (overrides: Partial<DesiredInlineIssue>): DesiredInlineIssue => ({
  id: '00000000-0000-7000-8000-000000000001',
  severity: 'medium',
  quality: 'maintainability',
  ruleKey: 'eslint:no-console',
  helpUri: null,
  path: 'src/a.ts',
  line: 3,
  message: 'Problem',
  ...overrides,
});
const added = new Map([
  ['src/a.ts', new Set([3, 4])],
  ['src/b.ts', new Set([1])],
]);
const url = (id: string) => `https://qualor.example.com/projects/p/issues/${id}`;

describe('annotationsOnDiff (github.md §6.4)', () => {
  it('sends tied issues in one order whatever order they come in, so the digest holds', () => {
    const a = issue({ id: '00000000-0000-7000-8000-00000000000a', ruleKey: 'eslint:no-debugger' });
    const b = issue({ id: '00000000-0000-7000-8000-00000000000b', ruleKey: 'eslint:no-console' });
    const c = issue({ id: '00000000-0000-7000-8000-00000000000c', ruleKey: 'eslint:no-console' });
    const forward = annotationsOnDiff([a, b, c], added, url);
    const backward = annotationsOnDiff([c, b, a], added, url);
    expect(forward).toEqual(backward);
    expect(annotationsDigest(forward.annotations)).toBe(annotationsDigest(backward.annotations));
    // Rule key, then issue id, break the tie on one line.
    expect(forward.annotations.map((x) => x.message.slice(-1))).toEqual(['b', 'c', 'a']);
  });

  it('orders by severity descending, then path, then line', () => {
    const placed = annotationsOnDiff(
      [
        issue({ id: '00000000-0000-7000-8000-000000000001', severity: 'low', line: 3 }),
        issue({ id: '00000000-0000-7000-8000-000000000002', path: 'src/b.ts', line: 1 }),
        issue({ id: '00000000-0000-7000-8000-000000000003', line: 4 }),
        issue({ id: '00000000-0000-7000-8000-000000000004', line: 3 }),
        issue({
          id: '00000000-0000-7000-8000-000000000005',
          severity: 'blocker',
          path: 'src/b.ts',
          line: 1,
        }),
      ],
      added,
      url,
    );
    expect(placed.annotations.map((x) => [x.annotation_level, x.path, x.start_line])).toEqual([
      ['failure', 'src/b.ts', 1],
      ['warning', 'src/a.ts', 3],
      ['warning', 'src/a.ts', 4],
      ['warning', 'src/b.ts', 1],
      ['notice', 'src/a.ts', 3],
    ]);
    expect(placed.unplaced).toBe(0);
  });

  it('counts an issue without a positive safe line, off the added lines or without a patch as not placed', () => {
    const placed = annotationsOnDiff(
      [
        issue({ line: 0 }),
        issue({ line: -3 }),
        issue({ line: 3.5 }),
        issue({ line: Number.MAX_SAFE_INTEGER + 2 }),
        issue({ line: null }),
        issue({ path: null }),
        issue({ line: 1 }),
        issue({ path: 'src/binary.png', line: 1 }),
        issue({ line: 4 }),
      ],
      added,
      url,
    );
    expect(placed.annotations.map((x) => x.start_line)).toEqual([4]);
    expect(placed.unplaced).toBe(8);
  });
});
