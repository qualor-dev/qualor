import { createHash } from 'node:crypto';
import {
  formatLicenseExpression,
  isSpdxException,
  isSpdxId,
  parseLicenseExpression,
  type LicenseExpr,
} from '@qualor/shared';

/** True when every id, and every `WITH` exception, is on the SPDX list. */
function isRealExpression(expr: LicenseExpr): boolean {
  if (expr.kind === 'id') return isSpdxId(expr.id);
  if (expr.kind === 'with') return isSpdxId(expr.id) && isSpdxException(expr.exception);
  return isRealExpression(expr.left) && isRealExpression(expr.right);
}

/** The parsed entry, or null when it is malformed or names something outside the SPDX list. */
function parseReal(entry: string): LicenseExpr | null {
  const expr = parseLicenseExpression(entry);
  return expr !== null && isRealExpression(expr) ? expr : null;
}

/** AND-joins expressions; the formatter parenthesises an OR inside an AND. */
function andAll(exprs: readonly LicenseExpr[]): string {
  const [first, ...rest] = exprs;
  let joined = first as LicenseExpr;
  for (const right of rest) joined = { kind: 'and', left: joined, right };
  return formatLicenseExpression(joined);
}

function entriesOf(licenses: readonly string[]): string[] {
  return licenses.map((l) => l.trim()).filter((l) => l !== '');
}

/**
 * The CycloneDX `licenses` of a component (a list read as all applying). all valid gives one AND-joined expression (even for a single id, since the CycloneDX id enum is shorter than the SPDX list); any unparsable entry gives names.
 * No licences gives undefined, so the key is left out.
 */
export function cycloneDxLicenses(licenses: readonly string[]): object[] | undefined {
  const entries = entriesOf(licenses);
  if (entries.length === 0) return undefined;
  const parsed = entries.map(parseReal);
  const exprs = parsed.filter((e): e is LicenseExpr => e !== null);
  if (exprs.length !== entries.length) {
    return entries.map((name) => ({ license: { name } }));
  }
  return [{ expression: andAll(exprs) }];
}

/**
 * The SPDX `licenseDeclared` of a package: the AND-joined expression, `NOASSERTION` when empty.
 * An unparsable entry becomes `LicenseRef-<first 12 hex of the sha256 of its text>`, and its text
 * is added to `extracted`, keyed by that id.
 */
export function spdxLicense(licenses: readonly string[], extracted: Map<string, string>): string {
  const entries = entriesOf(licenses);
  if (entries.length === 0) return 'NOASSERTION';
  const exprs = entries.map((entry): LicenseExpr => {
    const expr = parseReal(entry);
    if (expr !== null) return expr;
    const id = `LicenseRef-${createHash('sha256').update(entry).digest('hex').slice(0, 12)}`;
    extracted.set(id, entry);
    return { kind: 'id', id };
  });
  return andAll(exprs);
}
