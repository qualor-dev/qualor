import {
  apiQuery,
  branchFromParams,
  clearFilter,
  facetValues,
  filtersFromParams,
  filtersToParams,
  isFiltered,
  toggle,
} from './issue-filters';

describe('issue filters', () => {
  it('reads the URL, dropping unknown values, duplicates and anything over the API bounds', () => {
    const f = filtersFromParams({
      severity: ['high', 'high', 'catastrophic'],
      status: 'resolved',
      rule: Array.from({ length: 60 }, (_, i) => `eslint:r${i}`),
      inNewCode: 'true',
      q: 'x'.repeat(300),
      sort: 'nope',
    });
    expect(f.severity).toEqual(['high']);
    expect(f.status).toEqual(['resolved']);
    expect(f.rule).toHaveLength(50);
    expect(f.inNewCode).toBe(true);
    expect(f.q).toHaveLength(200);
    expect(f.sort).toBe('severity');
    expect(filtersFromParams({}).status).toEqual(['open']);
  });

  it('never lets a crafted URL produce a query the server rejects (api.md GET /issues)', () => {
    const f = filtersFromParams({
      rule: ['eslint:ok', 'nul\u0000rule', 'r'.repeat(513), 'r'.repeat(512)],
      engine: [...Array.from({ length: 25 }, (_, i) => `e${i}`), 'x'.repeat(65)],
      path: [...Array.from({ length: 25 }, (_, i) => `src/${i}/`), 'bad\u0000path'],
      q: `${'a'.repeat(199)}\u{1F600}`,
      includeDuplicates: 'yes',
      inNewCode: 'TRUE',
    });
    expect(f.rule).toEqual(['eslint:ok', 'r'.repeat(512)]);
    expect(f.engine).toHaveLength(20);
    expect(f.path).toHaveLength(20);
    expect(f.path).not.toContain('bad\u0000path');
    // 200 UTF-16 units would split the emoji's surrogate pair, which cannot be URL-encoded.
    expect(f.q).toBe('a'.repeat(199));
    expect(() => encodeURIComponent(f.q)).not.toThrow();
    expect(filtersFromParams({ q: 'pay\u0000ment' }).q).toBe('payment');
    expect(f.includeDuplicates).toBe(false);
    expect(f.inNewCode).toBe(false);
    expect(filtersFromParams({ includeDuplicates: 'true' }).includeDuplicates).toBe(true);
  });

  it('clears a group back to its default: Open for the status, nothing for the others', () => {
    const f = filtersFromParams({ status: ['resolved', 'closed'], severity: 'high', path: 'src/' });
    expect(isFiltered(f, 'status')).toBe(true);
    expect(isFiltered(f, 'severity')).toBe(true);
    expect(isFiltered(f, 'quality')).toBe(false);
    const status = clearFilter(f, 'status');
    expect(status.status).toEqual(['open']);
    expect(isFiltered(status, 'status')).toBe(false);
    expect(filtersToParams(status).status).toBeNull();
    // Clearing one group leaves the others as they were.
    expect(status.severity).toEqual(['high']);
    expect(clearFilter(f, 'severity').severity).toEqual([]);
    expect(clearFilter(f, 'severity').status).toEqual(['resolved', 'closed']);
    expect(filtersToParams(clearFilter(f, 'path')).path).toBeNull();
    expect(isFiltered(filtersFromParams({}), 'status')).toBe(false);
  });

  it('accepts only a UUID as the branch', () => {
    const id = '0190a6c2-0000-7000-8000-000000000042';
    expect(branchFromParams({ branch: id })).toBe(id);
    expect(branchFromParams({ branch: 'main' })).toBeNull();
    // Exactly zod's z.uuid(): version 1-8 and the RFC variant (8-b), else the server says 422.
    expect(branchFromParams({ branch: '0190a6c2-0000-0000-8000-000000000042' })).toBeNull();
    expect(branchFromParams({ branch: '0190a6c2-0000-9000-8000-000000000042' })).toBeNull();
    expect(branchFromParams({ branch: '0190a6c2-0000-7000-c000-000000000042' })).toBeNull();
    expect(branchFromParams({ branch: '0190A6C2-0000-1000-B000-000000000042' })).toBe(
      '0190A6C2-0000-1000-B000-000000000042',
    );
    expect(branchFromParams({ branch: [id, id] })).toBeNull();
    expect(branchFromParams({})).toBeNull();
  });

  it('writes only what differs from the defaults back to the URL', () => {
    const f = toggle(filtersFromParams({}), 'severity', 'blocker');
    expect(filtersToParams(f)).toEqual({
      status: null,
      severity: ['blocker'],
      quality: null,
      kind: null,
      rule: null,
      engine: null,
      path: null,
      inNewCode: null,
      includeDuplicates: null,
      q: null,
      sort: null,
    });
    expect(toggle(f, 'severity', 'blocker').severity).toEqual([]);
  });

  it('asks for facets with the first page only', () => {
    const f = filtersFromParams({ severity: 'high', q: ' pay ' });
    expect(apiQuery(f, 'b1', null)).toMatchObject({
      branchId: 'b1',
      status: ['open'],
      severity: ['high'],
      q: 'pay',
      facets: 'severity,quality,status,rule,engine',
    });
    expect(apiQuery(f, 'b1', 'next')).not.toHaveProperty('facets');
    expect(apiQuery(f, 'b1', null)).not.toHaveProperty('includeDuplicates');
    expect(
      apiQuery(filtersFromParams({ includeDuplicates: 'true', path: 'src/' }), 'b1', null),
    ).toMatchObject({ includeDuplicates: 'true', path: ['src/'] });
  });

  it('shows counts only where the facet own filter makes them meaningful (api.md §3)', () => {
    expect(facetValues(['high', 'low'], [{ value: 'high', count: 3 }], [])).toEqual([
      { value: 'high', count: 3, selected: false },
      { value: 'low', count: 0, selected: false },
    ]);
    expect(facetValues(['high', 'low'], [{ value: 'high', count: 3 }], ['high'])).toEqual([
      { value: 'high', count: 3, selected: true },
      { value: 'low', count: null, selected: false },
    ]);
    // Open sets (rules): returned values plus selected ones.
    expect(facetValues([], [{ value: 'eslint:eqeqeq', count: 2 }], ['semgrep:x'])).toEqual([
      { value: 'eslint:eqeqeq', count: null, selected: false },
      { value: 'semgrep:x', count: 0, selected: true },
    ]);
  });
});
