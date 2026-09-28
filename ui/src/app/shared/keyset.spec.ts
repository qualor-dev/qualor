import { KeysetList } from './keyset';

describe('KeysetList', () => {
  it('loads the first page, appends the next, and stops at the last', async () => {
    const pages: Record<string, { items: number[]; nextCursor: string | null }> = {
      first: { items: [1, 2], nextCursor: 'c2' },
      c2: { items: [3], nextCursor: null },
    };
    const calls: [string, string | null][] = [];
    const list = new KeysetList<number, string>(async (q, cursor) => {
      calls.push([q, cursor]);
      return pages[cursor ?? 'first']!;
    });
    await list.reset('q');
    expect(list.items()).toEqual([1, 2]);
    await list.more();
    expect(list.items()).toEqual([1, 2, 3]);
    expect(list.nextCursor()).toBeNull();
    await list.more();
    expect(calls).toEqual([
      ['q', null],
      ['q', 'c2'],
    ]);
  });

  it('clears the items and drops an answer still on its way', async () => {
    let release: (value: { items: string[]; nextCursor: null }) => void = () => undefined;
    const list = new KeysetList<string, string>((q) =>
      q === 'slow'
        ? new Promise((resolve) => (release = resolve))
        : Promise.resolve({ items: [q], nextCursor: null }),
    );
    await list.reset('fast');
    expect(list.items()).toEqual(['fast']);
    const slow = list.reset('slow');
    list.clear();
    release({ items: ['slow'], nextCursor: null });
    await slow;
    expect(list.items()).toEqual([]);
    expect(list.nextCursor()).toBeNull();
    expect(list.loading()).toBe(false);
    expect(list.loaded()).toBe(false);
    await list.reload();
    expect(list.items()).toEqual([]);
  });

  it('drops the answer of a search that a newer one replaced', async () => {
    let release: (value: { items: string[]; nextCursor: null }) => void = () => undefined;
    const list = new KeysetList<string, string>((q) =>
      q === 'slow'
        ? new Promise((resolve) => (release = resolve))
        : Promise.resolve({ items: [q], nextCursor: null }),
    );
    const slow = list.reset('slow');
    await list.reset('fast');
    release({ items: ['slow'], nextCursor: null });
    await slow;
    expect(list.items()).toEqual(['fast']);
    expect(list.loading()).toBe(false);
  });

  it('keeps a localized error instead of throwing', async () => {
    const list = new KeysetList<string, string>(() => Promise.reject(new TypeError('offline')));
    await list.reset('x');
    expect(list.error()).toContain('could not be reached');
    expect(list.loaded()).toBe(false);
  });

  it('stops paging when the server repeats a cursor it already answered', async () => {
    let calls = 0;
    const list = new KeysetList<number, string>(async () => {
      calls++;
      return { items: [calls], nextCursor: 'same' };
    });
    await list.reset('q');
    await list.more();
    expect(list.items()).toEqual([1, 2]);
    expect(list.nextCursor()).toBeNull();
    await list.more();
    expect(calls).toBe(2);
  });

  it('keeps the first page of the latest accepted answer only (facets travel with it)', async () => {
    type Page = { items: string[]; nextCursor: string | null; tag: string };
    let release: (value: Page) => void = () => undefined;
    const list = new KeysetList<string, string, Page>((q, cursor) =>
      q === 'slow'
        ? new Promise((resolve) => (release = resolve))
        : Promise.resolve({ items: [q], nextCursor: cursor ? null : 'c2', tag: `${q}:${cursor}` }),
    );
    const slow = list.reset('slow');
    await list.reset('fast');
    release({ items: ['slow'], nextCursor: null, tag: 'slow:null' });
    await slow;
    expect(list.firstPage()?.tag).toBe('fast:null');
    await list.more();
    // A next page does not replace the first one.
    expect(list.firstPage()?.tag).toBe('fast:null');
  });

  it('reloads through to the last page, within a bound', async () => {
    const list = new KeysetList<number, string>(async (_q, cursor) => {
      const n = cursor === null ? 0 : Number(cursor);
      return { items: [n], nextCursor: n < 9 ? String(n + 1) : null };
    });
    await list.reset('q');
    await list.reloadToEnd(5);
    expect(list.items()).toEqual([0, 1, 2, 3, 4]);
    await list.reloadToEnd(20);
    expect(list.items()).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(list.nextCursor()).toBeNull();
  });

  it('refreshes every loaded page in place, swapping the items only when all have answered', async () => {
    let version = 1;
    const calls: (string | null)[] = [];
    let hold: Promise<void> = Promise.resolve();
    const list = new KeysetList<string, string>(async (_q, cursor) => {
      calls.push(cursor);
      await hold;
      const page = cursor === null ? 1 : Number(cursor);
      return {
        items: [`v${version}p${page}a`, `v${version}p${page}b`],
        nextCursor: page < 3 ? String(page + 1) : null,
      };
    });
    await list.reset('q');
    await list.more();
    expect(list.items()).toEqual(['v1p1a', 'v1p1b', 'v1p2a', 'v1p2b']);
    version = 2;
    calls.length = 0;
    let release: () => void = () => undefined;
    hold = new Promise((resolve) => (release = resolve));
    const pending = list.refresh();
    // The old rows stay while the pages load again.
    expect(list.items()).toEqual(['v1p1a', 'v1p1b', 'v1p2a', 'v1p2b']);
    release();
    await pending;
    expect(calls).toEqual([null, '2']);
    expect(list.items()).toEqual(['v2p1a', 'v2p1b', 'v2p2a', 'v2p2b']);
    expect(list.nextCursor()).toBe('3');
  });

  it('drops a refresh that a newer search replaced', async () => {
    let slow = false;
    let release: () => void = () => undefined;
    const list = new KeysetList<string, string>(async (q) => {
      if (slow && q === 'a') await new Promise<void>((resolve) => (release = resolve));
      return { items: [q], nextCursor: null };
    });
    await list.reset('a');
    slow = true;
    const refreshing = list.refresh();
    await list.reset('b');
    release();
    await refreshing;
    expect(list.items()).toEqual(['b']);
  });
});
