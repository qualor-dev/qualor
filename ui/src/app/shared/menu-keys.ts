/** An index one step past either end wrapped to the other end of a list of `count`. */
export function wrapIndex(index: number, count: number): number {
  if (index < 0) return count - 1;
  return index >= count ? 0 : index;
}

/**
 * The item a menu key moves to: ArrowDown the next, ArrowUp the previous (both wrap), Home the
 * first, End the last. Any other key is not a menu key: null.
 */
export function menuIndex(key: string, index: number, count: number): number | null {
  switch (key) {
    case 'ArrowDown':
      return wrapIndex(index + 1, count);
    case 'ArrowUp':
      return wrapIndex(index - 1, count);
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return null;
  }
}
