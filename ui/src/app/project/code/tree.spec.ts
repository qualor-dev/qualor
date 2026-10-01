import { crumbs, sortTree, type TreeItem } from './tree';

const dir = (name: string, m: Record<string, number | null>) =>
  ({ type: 'dir', name, path: name, language: null, kind: null, measures: m }) as TreeItem;
const file = (name: string, m: Record<string, number | null>) =>
  ({
    type: 'file',
    name,
    path: name,
    language: 'typescript',
    kind: 'main',
    measures: m,
  }) as TreeItem;

describe('sortTree', () => {
  it('keeps directories first and sorts each group, nulls last', () => {
    const items = [
      file('b.ts', { coverage: 50 }),
      dir('z', { coverage: 10 }),
      file('a.ts', { coverage: null }),
      dir('y', { coverage: 90 }),
    ];
    expect(sortTree(items, { key: 'coverage', dir: 'asc' }).map((i) => i.name)).toEqual([
      'z',
      'y',
      'b.ts',
      'a.ts',
    ]);
    expect(sortTree(items, { key: 'coverage', dir: 'desc' }).map((i) => i.name)).toEqual([
      'y',
      'z',
      'b.ts',
      'a.ts',
    ]);
    expect(sortTree(items, { key: 'name', dir: 'asc' }).map((i) => i.name)).toEqual([
      'y',
      'z',
      'a.ts',
      'b.ts',
    ]);
  });

  it('breaks ties by name in byte order and does not change its input', () => {
    const items = [
      file('b.ts', { ncloc: 5 }),
      file('B.ts', { ncloc: 5 }),
      file('a.ts', { ncloc: 5 }),
    ];
    const copy = [...items];
    expect(sortTree(items, { key: 'ncloc', dir: 'desc' }).map((i) => i.name)).toEqual([
      'B.ts',
      'a.ts',
      'b.ts',
    ]);
    expect(items).toEqual(copy);
  });

  it('sorts names descending within each group', () => {
    const items = [file('a.ts', {}), dir('x', {}), file('b.ts', {}), dir('y', {})];
    expect(sortTree(items, { key: 'name', dir: 'desc' }).map((i) => i.name)).toEqual([
      'y',
      'x',
      'b.ts',
      'a.ts',
    ]);
  });
});

describe('crumbs', () => {
  it('splits a directory into breadcrumbs, with odd characters kept as they are', () => {
    expect(crumbs('')).toEqual([]);
    expect(crumbs('src/app')).toEqual([
      { name: 'src', dir: 'src' },
      { name: 'app', dir: 'src/app' },
    ]);
    expect(crumbs('src/my dir/#x?%')).toEqual([
      { name: 'src', dir: 'src' },
      { name: 'my dir', dir: 'src/my dir' },
      { name: '#x?%', dir: 'src/my dir/#x?%' },
    ]);
  });
});
