import type { Params } from '@angular/router';
import { isUuid } from '../shared/ids';
import { clip } from '../shared/text';

/** The issue list's filters, as the URL carries them (so a filtered list can be shared). */
export interface IssueFilters {
  status: string[];
  severity: string[];
  quality: string[];
  kind: string[];
  rule: string[];
  engine: string[];
  /** Literal path prefixes (api.md: `%` and `_` are not wildcards). */
  path: string[];
  inNewCode: boolean;
  /** api.md: duplicates are hidden unless asked for. */
  includeDuplicates: boolean;
  q: string;
  sort: IssueSort;
}

export type IssueSort = 'severity' | 'createdAt' | 'path';
type FacetName = 'severity' | 'quality' | 'status' | 'rule' | 'engine';
export type ListFilter = 'status' | 'severity' | 'quality' | 'kind' | 'rule' | 'engine' | 'path';

export const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'];
export const QUALITIES = ['security', 'reliability', 'maintainability'];
export const STATUSES = ['open', 'resolved', 'wont_fix', 'false_positive', 'closed'];
export const KINDS = ['issue', 'hotspot'];
const FACETS: FacetName[] = ['severity', 'quality', 'status', 'rule', 'engine'];
const SORTS: IssueSort[] = ['severity', 'createdAt', 'path'];
/** api.md §3 `GET /issues`: how many values each repeatable filter takes. */
const BOUNDS: Record<ListFilter, number> = {
  status: 5,
  severity: 5,
  quality: 3,
  kind: 2,
  rule: 50,
  engine: 20,
  path: 20,
};
/** The server's length limit of one value of an open filter (routes/issues.ts `text(n)`). */
const VALUE_LENGTH: Record<'rule' | 'engine' | 'path', number> = {
  rule: 512,
  engine: 64,
  path: 1_024,
};
export const Q_MAX_LENGTH = 200;

function list(value: unknown, allowed?: string[]): string[] {
  const raw = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
  const strings = raw.filter((v): v is string => typeof v === 'string' && v !== '');
  const kept = allowed ? strings.filter((v) => allowed.includes(v)) : strings;
  return [...new Set(kept)];
}

/** Values of an open filter the server accepts: 1..max characters, no U+0000 (api.md). */
function open(value: unknown, filter: 'rule' | 'engine' | 'path'): string[] {
  return list(value)
    .filter((v) => v.length <= VALUE_LENGTH[filter] && !v.includes('\u0000'))
    .slice(0, BOUNDS[filter]);
}

/**
 * The filters a URL asks for, validated and clamped to what `GET /issues` accepts: a crafted or
 * stale URL loses unknown values, duplicates and anything over the bounds instead of producing a
 * request the server rejects.
 */
export function filtersFromParams(params: Params): IssueFilters {
  const status = list(params['status'], STATUSES);
  const sort = SORTS.find((s) => s === params['sort']) ?? 'severity';
  const q = typeof params['q'] === 'string' ? params['q'].replaceAll('\u0000', '') : '';
  return {
    status: status.length > 0 ? status : ['open'],
    severity: list(params['severity'], SEVERITIES),
    quality: list(params['quality'], QUALITIES),
    kind: list(params['kind'], KINDS),
    rule: open(params['rule'], 'rule'),
    engine: open(params['engine'], 'engine'),
    path: open(params['path'], 'path'),
    inNewCode: params['inNewCode'] === 'true',
    includeDuplicates: params['includeDuplicates'] === 'true',
    q: clip(q, Q_MAX_LENGTH),
    sort,
  };
}

/** The branch the URL names, when it is a UUID; otherwise the page uses the main branch. */
export function branchFromParams(params: Params): string | null {
  const branch: unknown = params['branch'];
  return isUuid(branch) ? branch : null;
}

/** Router query parameters for the filters; defaults are left out, `null` removes a parameter. */
export function filtersToParams(f: IssueFilters): Params {
  const many = (values: string[]) => (values.length > 0 ? values : null);
  const onlyOpen = f.status.length === 1 && f.status[0] === 'open';
  return {
    status: onlyOpen ? null : many(f.status),
    severity: many(f.severity),
    quality: many(f.quality),
    kind: many(f.kind),
    rule: many(f.rule),
    engine: many(f.engine),
    path: many(f.path),
    inNewCode: f.inNewCode ? 'true' : null,
    includeDuplicates: f.includeDuplicates ? 'true' : null,
    q: f.q.trim() ? f.q.trim() : null,
    sort: f.sort === 'severity' ? null : f.sort,
  };
}

/** Adds or removes one value of a repeatable filter. */
export function toggle(f: IssueFilters, filter: ListFilter, value: string): IssueFilters {
  const current = f[filter];
  const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  return { ...f, [filter]: next.slice(0, BOUNDS[filter]) };
}

/** A group's values back to their default: Open for the status, none for the others. */
export function clearFilter(f: IssueFilters, filter: ListFilter): IssueFilters {
  return { ...f, [filter]: filter === 'status' ? ['open'] : [] };
}

/** Whether a group differs from its default, so that clearing it changes the list. */
export function isFiltered(f: IssueFilters, filter: ListFilter): boolean {
  const values = f[filter];
  return filter === 'status' ? !(values.length === 1 && values[0] === 'open') : values.length > 0;
}

/** The `GET /issues` query for a page (facets only with the first page). */
export function apiQuery(f: IssueFilters, branchId: string, cursor: string | null) {
  const many = (values: string[]) => (values.length > 0 ? values : undefined);
  return {
    branchId,
    limit: 50,
    sort: f.sort,
    status: many(f.status) as ('open' | 'resolved' | 'wont_fix' | 'false_positive' | 'closed')[],
    severity: many(f.severity) as ('blocker' | 'high' | 'medium' | 'low' | 'info')[] | undefined,
    quality: many(f.quality) as ('security' | 'reliability' | 'maintainability')[] | undefined,
    kind: many(f.kind) as ('issue' | 'hotspot')[] | undefined,
    rule: many(f.rule),
    engine: many(f.engine),
    path: many(f.path),
    ...(f.inNewCode ? { inNewCode: 'true' as const } : {}),
    ...(f.includeDuplicates ? { includeDuplicates: 'true' as const } : {}),
    ...(f.q.trim() ? { q: f.q.trim() } : {}),
    ...(cursor ? { cursor } : { facets: FACETS.join(',') }),
  };
}

export interface FacetValue {
  value: string;
  /** Null when the count is not meaningful: see {@link facetValues}. */
  count: number | null;
  selected: boolean;
}

/**
 * The values to offer for a facet. api.md §3: facet counts are computed over the filtered set,
 * including the facet's own filter, so once a severity is chosen the other severities count 0
 * even when such issues exist. While a facet's own filter is active, only its selected values
 * show a count; the other known values are still offered (to widen the filter), without one.
 */
export function facetValues(
  known: string[],
  counts: { value: string; count: number }[] | undefined,
  selected: string[],
): FacetValue[] {
  const byValue = new Map((counts ?? []).map((c) => [c.value, c.count]));
  const values = [...known, ...[...byValue.keys(), ...selected].filter((v) => !known.includes(v))];
  const filtered = selected.length > 0;
  return [...new Set(values)].map((value) => {
    const isSelected = selected.includes(value);
    return {
      value,
      count: filtered && !isSelected ? null : (byValue.get(value) ?? 0),
      selected: isSelected,
    };
  });
}
