import { menuIndex, wrapIndex } from './menu-keys';

describe('menu keys', () => {
  it('moves one item with the arrows, wrapping at both ends', () => {
    expect(menuIndex('ArrowDown', 2, 3)).toBe(0);
    expect(menuIndex('ArrowDown', 0, 3)).toBe(1);
    expect(menuIndex('ArrowUp', 0, 3)).toBe(2);
    expect(menuIndex('ArrowUp', 2, 3)).toBe(1);
  });

  it('goes to the first item with Home and the last with End', () => {
    expect(menuIndex('Home', 2, 3)).toBe(0);
    expect(menuIndex('End', 0, 3)).toBe(2);
  });

  it('leaves any other key alone', () => {
    expect(menuIndex('a', 1, 3)).toBeNull();
    expect(menuIndex('Tab', 1, 3)).toBeNull();
  });

  it('wraps an index one step past either end', () => {
    expect(wrapIndex(-1, 3)).toBe(2);
    expect(wrapIndex(3, 3)).toBe(0);
    expect(wrapIndex(1, 3)).toBe(1);
  });
});
