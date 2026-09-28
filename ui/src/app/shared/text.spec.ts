import { clip } from './text';

describe('clip', () => {
  it('keeps at most max UTF-16 units and never half a surrogate pair', () => {
    expect(clip('abcdef', 4)).toBe('abcd');
    expect(clip('ab', 4)).toBe('ab');
    expect(clip('a😀b', 2)).toBe('a');
    expect(clip('a😀b', 3)).toBe('a😀');
  });
});
