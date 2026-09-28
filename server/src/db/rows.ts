/** The first row of a query that must return one (INSERT … RETURNING, a checked SELECT). */
export function first<T>(rows: readonly T[]): T {
  const row = rows[0];
  if (row === undefined) throw new Error('expected at least one row');
  return row;
}
