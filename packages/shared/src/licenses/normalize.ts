/**
 * Manifest licence strings to canonical SPDX ids or expressions. What cannot be mapped comes back
 * trimmed and otherwise as written (`Public Domain` stays that: it names no licence).
 */
import { formatLicenseExpression, licenseTerms, parseLicenseExpression } from './expression';
import { isSpdxId, splitTerm } from './spdx';

/**
 * Whole-string spellings (compared lower-case, whitespace collapsed) that an SPDX parse would not
 * map. The deprecated ids (`GPL-2.0`, `LGPL-2.1+` ...) and case variants go through the parser.
 */
export const ALIASES: Readonly<Record<string, string>> = {
  gplv2: 'GPL-2.0-only',
  'gplv2+': 'GPL-2.0-or-later',
  gplv3: 'GPL-3.0-only',
  'gplv3+': 'GPL-3.0-or-later',
  lgplv2: 'LGPL-2.0-only',
  'lgplv2+': 'LGPL-2.0-or-later',
  lgplv21: 'LGPL-2.1-only',
  'lgplv2.1': 'LGPL-2.1-only',
  'lgplv2.1+': 'LGPL-2.1-or-later',
  'lgplv21+': 'LGPL-2.1-or-later',
  lgplv3: 'LGPL-3.0-only',
  'lgplv3+': 'LGPL-3.0-or-later',
  agplv3: 'AGPL-3.0-only',
  'agplv3+': 'AGPL-3.0-or-later',
  'apache 2.0': 'Apache-2.0',
  'apache-2': 'Apache-2.0',
  'apache 2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  'apache license, version 2.0': 'Apache-2.0',
  'the apache license, version 2.0': 'Apache-2.0',
  bsd: 'BSD-3-Clause',
  'bsd-2': 'BSD-2-Clause',
  'bsd-3': 'BSD-3-Clause',
  'bsd license': 'BSD-3-Clause',
  'mit license': 'MIT',
  'the mit license': 'MIT',
  'isc license': 'ISC',
};

export function normalizeLicense(raw: string): string {
  const trimmed = raw.trim();
  // Own keys only: `constructor` or `__proto__` must not find an Object.prototype member.
  const key = trimmed.toLowerCase().replace(/\s+/g, ' ');
  const alias = Object.hasOwn(ALIASES, key) ? ALIASES[key] : undefined;
  if (alias !== undefined) return alias;
  const expr = parseLicenseExpression(trimmed);
  if (expr === null) return trimmed;
  // A lone unrecognised word stays as written; a compound expression is rewritten when any part is known.
  if (expr.kind === 'id') return isSpdxId(expr.id) ? expr.id : trimmed;
  const known = licenseTerms(expr).some((t) => isSpdxId(splitTerm(t).id));
  return known ? formatLicenseExpression(expr) : trimmed;
}
