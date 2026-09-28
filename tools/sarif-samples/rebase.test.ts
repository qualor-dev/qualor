import { describe, expect, it } from 'vitest';
import { rebaseSarif } from './rebase';

describe('rebaseSarif', () => {
  it('rewrites file URIs and absolute paths under the prefixes', () => {
    const input = {
      runs: [
        {
          a: 'file:///E:/work/qualor/fixtures/ts-basic/src/math.ts',
          b: 'file:///e%3A/work/qualor/fixtures/ts-basic/src/x.ts',
          c: 'E:\\work\\qualor\\fixtures\\ts-basic\\src\\y.ts',
          d: '/src/src/z.ts',
          e: 'file:///src/src/w.ts',
          f: 'src/relative.ts',
          g: 'file:///elsewhere/q.ts',
          n: 3,
        },
      ],
    };
    expect(rebaseSarif(input, ['E:\\work\\qualor\\fixtures\\ts-basic', '/src'])).toEqual({
      runs: [
        {
          a: 'file:///fixture-root/src/math.ts',
          b: 'file:///fixture-root/src/x.ts',
          c: 'file:///fixture-root/src/y.ts',
          d: 'file:///fixture-root/src/z.ts',
          e: 'file:///fixture-root/src/w.ts',
          f: 'src/relative.ts',
          g: 'file:///elsewhere/q.ts',
          n: 3,
        },
      ],
    });
  });

  it('keeps plain paths as paths with the plain option (ESLint JSON output)', () => {
    expect(
      rebaseSarif(
        {
          filePath: 'C:\\work\\ts-basic\\src\\math.ts',
          cwd: 'C:\\work\\ts-basic',
          u: 'file:///C:/work/ts-basic/a.ts',
        },
        ['C:\\work\\ts-basic'],
        { plain: true },
      ),
    ).toEqual({
      filePath: '/fixture-root/src/math.ts',
      cwd: '/fixture-root/',
      u: 'file:///fixture-root/a.ts',
    });
  });

  it('rewrites a string equal to a prefix (a base URI) to the root', () => {
    expect(rebaseSarif({ u: 'file:///src/' }, ['/src'])).toEqual({ u: 'file:///fixture-root/' });
  });

  it('rewrites a non-conformant single-slash file: URI (e.g. SpotBugs originalUriBaseIds), preserving its trailing slash', () => {
    expect(rebaseSarif({ u: 'file:/work/src/main/java/' }, ['/work'])).toEqual({
      u: 'file:///fixture-root/src/main/java/',
    });
  });

  it('does not treat a file: URI with a real host as the non-conformant single-slash form', () => {
    expect(rebaseSarif({ u: 'file://otherhost/work/x.ts' }, ['/work'])).toEqual({
      u: 'file://otherhost/work/x.ts',
    });
  });
});
