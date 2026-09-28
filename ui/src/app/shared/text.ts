/** At most `max` UTF-16 units, never ending in half a surrogate pair (which cannot be encoded). */
export function clip(value: string, max: number): string {
  const cut = value.slice(0, max);
  return /[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut;
}
