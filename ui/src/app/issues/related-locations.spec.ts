import { readRelatedLocations } from './related-locations';

describe('readRelatedLocations (spec §6.2)', () => {
  it('keeps well-formed entries in report order', () => {
    expect(
      readRelatedLocations([
        { path: 'src/a.ts', startLine: 4, message: 'Tainted value read here' },
        { path: 'src/b.ts', startLine: 10, endLine: 12 },
      ]),
    ).toEqual([
      { path: 'src/a.ts', startLine: 4, endLine: null, message: 'Tainted value read here' },
      { path: 'src/b.ts', startLine: 10, endLine: 12, message: null },
    ]);
  });

  it('drops malformed entries and anything that is not an array', () => {
    expect(readRelatedLocations(null)).toEqual([]);
    expect(readRelatedLocations({ path: 'x' })).toEqual([]);
    expect(
      readRelatedLocations([
        { path: 'src/a.ts' },
        { path: 3, startLine: 1 },
        { path: '', startLine: 1 },
        { path: 'src/a.ts', startLine: 0 },
        { path: 'src/a.ts', startLine: 1.5 },
        { path: 'src/a.ts', startLine: 5, endLine: 2 },
        'src/a.ts:3',
        { path: 'src/ok.ts', startLine: 2, message: 7 },
      ]),
    ).toEqual([{ path: 'src/ok.ts', startLine: 2, endLine: null, message: null }]);
  });

  it('keeps at most 20 (the report bound)', () => {
    const many = Array.from({ length: 25 }, (_, i) => ({ path: 'a.ts', startLine: i + 1 }));
    expect(readRelatedLocations(many)).toHaveLength(20);
  });
});
