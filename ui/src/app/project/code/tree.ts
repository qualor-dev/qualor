import type { ItemOf } from '../../api/types';

export type TreeItem = ItemOf<'/api/v0/branches/{id}/files'>;
export type TreeSort = {
  key: 'name' | 'ncloc' | 'complexity' | 'coverage' | 'duplicated_lines_density' | 'issues';
  dir: 'asc' | 'desc';
};

/** Byte order like the server's name sort: no locale, upper case before lower case. */
function byName(a: TreeItem, b: TreeItem): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * The loaded rows in the order of a column header: directories always before files; within each
 * group by the key (a row without the measure last, whichever the direction), ties by name.
 */
export function sortTree(items: readonly TreeItem[], sort: TreeSort): TreeItem[] {
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...items].sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    if (sort.key === 'name') return sign * byName(a, b) || byName(a, b);
    const x = a.measures[sort.key] ?? null;
    const y = b.measures[sort.key] ?? null;
    if (x === null || y === null) {
      if (x === y) return byName(a, b);
      return x === null ? 1 : -1;
    }
    return sign * (x - y) || byName(a, b);
  });
}

/** `'src/app'` → `src`, `src/app`: each segment with the directory it leads to; `''` → none. */
export function crumbs(dir: string): { name: string; dir: string }[] {
  if (!dir) return [];
  const names = dir.split('/');
  return names.map((name, i) => ({ name, dir: names.slice(0, i + 1).join('/') }));
}
