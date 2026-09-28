import { describe, expect, it } from 'vitest';
import { addedLines, addedLineTexts } from './inline';

describe('addedLineTexts (llm.md §8.3)', () => {
  it('maps each added line of the new file to its text', () => {
    expect(addedLineTexts('@@ -1,2 +1,3 @@\n a\n+b\n+ c\n d')).toEqual(
      new Map([
        [2, 'b'],
        [3, ' c'],
      ]),
    );
  });

  it('skips removed lines and the no-newline notice, and follows every hunk', () => {
    const diff = [
      '@@ -1,3 +1,3 @@',
      ' keep',
      '-old',
      '+new',
      ' keep',
      '@@ -20,2 +20,3 @@',
      ' x',
      '+y\r',
      '+',
      '\\ No newline at end of file',
    ].join('\n');
    expect(addedLineTexts(diff)).toEqual(
      new Map([
        [2, 'new'],
        [21, 'y'],
        [22, ''],
      ]),
    );
    expect([...addedLines(diff)]).toEqual([2, 21, 22]);
  });

  it('reads nothing before the first hunk header', () => {
    expect(addedLineTexts('+++ b/file\n+not a line\n@@ -0,0 +1 @@\n+first')).toEqual(
      new Map([[1, 'first']]),
    );
  });
});
