import { describe, expect, it } from 'vitest';
import {
  mergeRanges,
  parseBinaryPaths,
  parseNameStatusZ,
  parseUnifiedDiff,
  unquoteGitPath,
} from './diff';

describe('parseUnifiedDiff', () => {
  it('collects new-side ranges per file, rename-aware, ignoring deletions', () => {
    const out = [
      'diff --git a/src/added.ts b/src/added.ts',
      'new file mode 100644',
      '--- /dev/null',
      '+++ b/src/added.ts',
      '@@ -0,0 +1,2 @@',
      '+n',
      '+++ this added line starts with two pluses',
      'diff --git a/src/del.ts b/src/del.ts',
      'deleted file mode 100644',
      '--- a/src/del.ts',
      '+++ /dev/null',
      '@@ -1,2 +0,0 @@',
      '-x',
      '-y',
      'diff --git a/src/dir with space/ümlaut.ts b/src/dir with space/ümlaut.ts',
      '--- a/src/dir with space/ümlaut.ts\t',
      '+++ b/src/dir with space/ümlaut.ts\t',
      '@@ -2 +2 @@ a',
      '-b',
      '+B',
      'diff --git a/src/old.ts b/src/new.ts',
      'similarity index 67%',
      'rename from src/old.ts',
      'rename to src/new.ts',
      '--- a/src/old.ts',
      '+++ b/src/new.ts',
      '@@ -3 +3 @@',
      '-3',
      '+THREE',
      '@@ -4,0 +5,2 @@',
      '+x',
      '+y',
      '\\ No newline at end of file',
      '@@ -10,0 +11 @@',
      '+11',
      'diff --git "a/src/q\\"uote.ts" "b/src/q\\"uote.ts"',
      '--- "a/src/q\\"uote.ts"',
      '+++ "b/src/q\\"uote.ts"',
      '@@ -1,0 +2 @@',
      '+more',
      '',
    ].join('\n');
    expect([...parseUnifiedDiff(out)]).toEqual([
      ['src/added.ts', [[1, 2]]],
      ['src/dir with space/ümlaut.ts', [[2, 2]]],
      [
        'src/new.ts',
        [
          [3, 3],
          [5, 6],
          [11, 11],
        ],
      ],
      ['src/q"uote.ts', [[2, 2]]],
    ]);
  });

  it('merges adjacent and overlapping ranges', () => {
    expect(
      mergeRanges([
        [5, 6],
        [1, 2],
        [3, 3],
        [6, 9],
      ]),
    ).toEqual([
      [1, 3],
      [5, 9],
    ]);
  });

  it('never counts an unchanged context line as new, even when interHunkContext merges two hunks into one', () => {
    // What `git -c diff.interHunkContext=3 diff` produces for changes on lines 2 and 4 of a
    // 5-line file: one merged hunk whose body interleaves an unchanged context line (' l3')
    // between the two real changes. A header-count-only reading of "@@ -2,3 +2,3 @@" would
    // wrongly report [2,4] as all new; walking the body must report only [2,2] and [4,4].
    const out = [
      'diff --git a/f.txt b/f.txt',
      '--- a/f.txt',
      '+++ b/f.txt',
      '@@ -2,3 +2,3 @@',
      '-l2',
      '+CHANGED2',
      ' l3',
      '-l4',
      '+CHANGED4',
      '',
    ].join('\n');
    expect([...parseUnifiedDiff(out)]).toEqual([
      [
        'f.txt',
        [
          [2, 2],
          [4, 4],
        ],
      ],
    ]);
  });
});

describe('parseBinaryPaths', () => {
  it('collects the new-side path of every binary file change', () => {
    const out = [
      'diff --git a/img.png b/img.png',
      'index 1234567..89abcde 100644',
      'Binary files a/img.png and b/img.png differ',
      'diff --git a/added.bin b/added.bin',
      'new file mode 100644',
      'index 0000000..abcdef1',
      'Binary files /dev/null and b/added.bin differ',
      'diff --git a/removed.bin b/removed.bin',
      'deleted file mode 100644',
      'index abcdef1..0000000',
      'Binary files a/removed.bin and /dev/null differ',
      '',
    ].join('\n');
    expect(parseBinaryPaths(out)).toEqual(new Set(['img.png', 'added.bin']));
  });

  it('returns an empty set for text-only diffs', () => {
    expect(
      parseBinaryPaths('diff --git a/f.ts b/f.ts\n--- a/f.ts\n+++ b/f.ts\n@@ -1 +1 @@\n-a\n+b\n'),
    ).toEqual(new Set());
  });
});

describe('parseNameStatusZ', () => {
  it('reads NUL-separated statuses including renames and copies', () => {
    const out =
      'A\0src/added.ts\0D\0src/del.ts\0M\0src/dir with space/ü.ts\0R067\0src/old.ts\0src/new.ts\0C100\0a.ts\0b.ts\0';
    expect(parseNameStatusZ(out)).toEqual([
      { status: 'A', path: 'src/added.ts' },
      { status: 'D', path: 'src/del.ts' },
      { status: 'M', path: 'src/dir with space/ü.ts' },
      { status: 'R', from: 'src/old.ts', path: 'src/new.ts' },
      { status: 'C', from: 'a.ts', path: 'b.ts' },
    ]);
    expect(parseNameStatusZ('')).toEqual([]);
  });
});

describe('unquoteGitPath', () => {
  it('decodes C-style escapes and octal UTF-8 bytes', () => {
    expect(unquoteGitPath('"b/\\303\\274.ts"')).toBe('b/ü.ts');
    expect(unquoteGitPath('"a\\tb\\\\c\\"d"')).toBe('a\tb\\c"d');
    expect(unquoteGitPath('"😀 \\n"')).toBe('😀 \n');
    expect(unquoteGitPath('plain')).toBe('plain');
  });
});
