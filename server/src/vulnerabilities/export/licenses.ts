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
 * The `LicenseRef-<hex>` id of a free text, from the start of the sha256 of the text: 12 hex
 * digits, or 4 more at a time while `extracted` holds another text under the id (D8-4).
 */
function licenseRef(text: string, extracted: Map<string, string>): string {
  const hex = createHash('sha256').update(text).digest('hex');
  let digits = 12;
  let id = `LicenseRef-${hex.slice(0, digits)}`;
  while (digits < hex.length && (extracted.get(id) ?? text) !== text) {
    digits += 4;
    id = `LicenseRef-${hex.slice(0, digits)}`;
  }
  return id;
}

/**
 * The SPDX `licenseDeclared` of a package: the AND-joined expression, `NOASSERTION` when empty.
 * An unparsable entry becomes a `LicenseRef-<hex>` of its text (`licenseRef`), and its text is
 * added to `extracted`, keyed by that id.
 */
export function spdxLicense(licenses: readonly string[], extracted: Map<string, string>): string {
  const entries = entriesOf(licenses);
  if (entries.length === 0) return 'NOASSERTION';
  const exprs = entries.map((entry): LicenseExpr => {
    const expr = parseReal(entry);
    if (expr !== null) return expr;
    const id = licenseRef(entry, extracted);
    extracted.set(id, entry);
    return { kind: 'id', id };
  });
  return andAll(exprs);
}
