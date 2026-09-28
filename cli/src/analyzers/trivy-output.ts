import { lstatSync, readFileSync, type Stats } from 'node:fs';
import path from 'node:path';
import { REPORT_BOUNDS, splitSourceLines } from '@qualor/shared';
import { z } from 'zod';

/**
 * A lockfile larger than this is not searched for a package Trivy did not place (config.md §6);
 * its findings then sit at the file itself. Real `pnpm-lock.yaml` files reach tens of MiB.
 */
export const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;

/** At most this many vendor ids (GHSA-…) and CWE entries are kept per finding and rule. */
const MAX_IDS = 16;

const text = z.string().max(4_096);
const location = z.looseObject({
  StartLine: z.number().int().positive().optional(),
  EndLine: z.number().int().positive().optional(),
});
const pkg = z.looseObject({
  ID: text.optional(),
  Name: text.optional(),
  Version: text.optional(),
  Identifier: z.looseObject({ PURL: text.optional(), UID: text.optional() }).optional(),
  Relationship: text.optional(),
  Locations: z.array(location).optional(),
});
const vulnerability = z.looseObject({
  VulnerabilityID: z.string().min(1).max(REPORT_BOUNDS.ruleIdChars),
  VendorIDs: z.array(text).optional(),
  PkgID: text.optional(),
  PkgName: text,
  PkgIdentifier: z.looseObject({ PURL: text.optional(), UID: text.optional() }).optional(),
  InstalledVersion: text,
  FixedVersion: text.optional(),
  Severity: text.optional(),
  Title: z.string().optional(),
  PrimaryURL: z.string().optional(),
  CweIDs: z.array(text).optional(),
});
const result = z.looseObject({
  Target: z.string(),
  Type: text.optional(),
  Packages: z.array(pkg).optional(),
  Vulnerabilities: z.array(vulnerability).optional(),
});
/** `trivy fs --format json` (report schema version 2), only the fields Qualor uses. */
export const trivyReportSchema = z.looseObject({
  SchemaVersion: z.literal(2),
  Trivy: z.looseObject({ Version: text.optional() }).optional(),
  Results: z.array(result).optional(),
});

type TrivyPackage = z.infer<typeof pkg>;
type TrivyVulnerability = z.infer<typeof vulnerability>;

/**
 * The lines of a lockfile Trivy named, read the way the normaliser reads sources (each segment
 * from the repository root with `lstat`, no link followed, a regular file) but with a larger
 * bound: null when it cannot be searched.
 */
export function lockfileLines(root: string, repoPath: string): string[] | null {
  if (repoPath === '' || repoPath.split('/').some((s) => s === '' || s === '.' || s === '..')) {
    return null;
  }
  let current = root;
  let stat: Stats | undefined;
  for (const segment of repoPath.split('/')) {
    current = path.join(current, segment);
    try {
      stat = lstatSync(current);
    } catch {
      return null;
    }
    if (stat.isSymbolicLink()) return null;
  }
  if (stat === undefined || !stat.isFile() || stat.size > MAX_LOCKFILE_BYTES) return null;
  try {
    return splitSourceLines(readFileSync(current, 'utf8'));
  } catch {
    return null;
  }
}

const OPEN = new Set([' ', '	', "'", '"']);
const CLOSE = new Set([':', '(', "'", '"', ' ']);
/** After a lockfile v5 key (`/name/version`): its end, or v5's `_peer@…` or later `(peer@…)`. */
const V5_CLOSE = new Set([':', '(', '_', "'", '"']);

/**
 * config.md §6: the first line holding `<name>@<version>` as a whole word, for lockfiles whose
 * entries Trivy does not place (`pnpm-lock.yaml`: `  minimist@1.2.5:`, `  '@babel/core@7.1.0':`,
 * `  foo@1.0.0(bar@2.0.0):`, the older `  /minimist@1.2.5:`, and lockfile v5's
 * `  /minimist/1.2.5:`, `  /@babel/core/7.1.0:`, `  /foo/1.0.0_bar@2.0.0:`). A text search, not a
 * lockfile parser: 1-based, or null.
 */
export function findPackageLine(
  lines: readonly string[],
  name: string,
  version: string,
): number | null {
  const needle = `${name}@${version}`;
  const v5Needle = `/${name}/${version}`;
  // Before the name: the start of the line, a space or a quote, optionally then one `/`.
  const opens = (line: string, at: number) => {
    const start = line[at - 1] === '/' ? at - 1 : at;
    return start === 0 || OPEN.has(line[start - 1] ?? '');
  };
  // `endOk`: the text may end the line (a v5 key always ends with `:` or a peer suffix).
  const search = (
    line: string,
    text: string,
    open: (at: number) => boolean,
    close: ReadonlySet<string>,
    endOk: boolean,
  ) => {
    for (let at = line.indexOf(text); at !== -1; at = line.indexOf(text, at + 1)) {
      const after = line[at + text.length];
      if (open(at) && (after === undefined ? endOk : close.has(after))) return true;
    }
    return false;
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (search(line, needle, (at) => opens(line, at), CLOSE, true)) return i + 1;
    // v5: the leading `/` is part of the key, so it must follow the line start, a space or a quote.
    const v5Opens = (at: number) => at === 0 || OPEN.has(line[at - 1] ?? '');
    if (search(line, v5Needle, v5Opens, V5_CLOSE, false)) return i + 1;
  }
  return null;
}

/** The package entry Trivy reported for a vulnerability (by its unique id, else its package id). */
function packageOf(
  packages: readonly TrivyPackage[],
  v: TrivyVulnerability,
): TrivyPackage | undefined {
  const uid = v.PkgIdentifier?.UID;
  return (
    (uid !== undefined ? packages.find((p) => p.Identifier?.UID === uid) : undefined) ??
    (v.PkgID !== undefined ? packages.find((p) => p.ID === v.PkgID) : undefined)
  );
}

interface Region {
  startLine: number;
  endLine?: number;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Ruling T3 (config.md §6): the line inside Trivy's `[start, end]` range of a package entry that
 * holds its resolved version. gates.md §5 decides new code by a finding's start line, and an
 * upgrade changes an entry's version lines, not its key (`"node_modules/x": {`, `x@^1:`,
 * `<dependency>`). `package-lock.json`: `"version": "<v>"`; `yarn.lock`: `version "<v>"` (v1) or
 * `version: <v>` (berry); `pom.xml`: `<version><v></version>`, or for `<version>${p}</version>`
 * the line of the `<p>` property that sets it (else that `<version>` line). Null for another type
 * or when no line matches: the caller keeps the range start.
 */
export function versionLine(
  lines: readonly string[],
  type: string | undefined,
  start: number,
  end: number,
  version: string,
): number | null {
  const v = escape(version);
  const inRange = (re: RegExp): number | null => {
    for (let i = start; i <= Math.min(end, lines.length); i++) {
      if (re.test(lines[i - 1] ?? '')) return i;
    }
    return null;
  };
  switch (type) {
    case 'npm':
      return inRange(new RegExp(`^\\s*"version"\\s*:\\s*"${v}"\\s*,?\\s*$`));
    case 'yarn':
      return inRange(new RegExp(`^\\s+version:?\\s+"?${v}"?\\s*$`));
    case 'pom': {
      const literal = inRange(new RegExp(`<version>\\s*${v}\\s*</version>`));
      if (literal !== null) return literal;
      const reference = /<version>\s*\$\{([\w.-]{1,256})\}\s*<\/version>/;
      const at = inRange(reference);
      if (at === null) return null;
      const name = escape(reference.exec(lines[at - 1] ?? '')?.[1] ?? '');
      const property = new RegExp(`<${name}>\\s*${v}\\s*</${name}>`);
      const set = lines.findIndex((l) => property.test(l));
      return set === -1 ? at : set + 1;
    }
    default:
      return null;
  }
}

function regionOf(
  p: TrivyPackage | undefined,
  v: TrivyVulnerability,
  type: string | undefined,
  lines: () => readonly string[] | null,
): Region | undefined {
  const at = p?.Locations?.find((l) => l.StartLine !== undefined);
  if (at?.StartLine !== undefined) {
    const end = at.EndLine !== undefined && at.EndLine >= at.StartLine ? at.EndLine : at.StartLine;
    const found = lines();
    const line =
      (found === null ? null : versionLine(found, type, at.StartLine, end, v.InstalledVersion)) ??
      at.StartLine;
    return { startLine: line, endLine: line };
  }
  const found = lines();
  const line = found === null ? null : findPackageLine(found, v.PkgName, v.InstalledVersion);
  return line === null ? undefined : { startLine: line };
}

const severityOf = (s: string | undefined) =>
  s !== undefined && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(s) ? s : 'UNKNOWN';

/** report-format.md §7.1: the finding message. */
export function trivyMessage(v: TrivyVulnerability): string {
  const title = v.Title?.trim();
  const fixed = v.FixedVersion?.trim();
  return `${v.PkgName} ${v.InstalledVersion}: ${v.VulnerabilityID}${title ? ` ${title}` : ''} (${
    fixed ? `fixed in ${fixed}` : 'no fixed version'
  })`;
}

interface SarifRuleOut {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[]; cwe: string[]; trivySeverity: string };
}

/**
 * Trivy's JSON (`trivy fs --format json --list-all-pkgs`) as a SARIF 2.1.0 log (config.md §6,
 * report-format.md §7.1): one result per vulnerability and lockfile, `ruleId` the vulnerability id,
 * located at the package's entry in the lockfile (the version line of Trivy's own range, ruling
 * T3; else a `name@version` search of the file; else the file itself), with the package in `properties.dependency`, which
 * the shared mapping turns into the finding's identity. Throws on output that is not Trivy's
 * JSON report (the runner then records a fixed failure reason).
 */
export function trivyJsonToSarif(output: unknown, root: string): unknown {
  const report = trivyReportSchema.parse(output);
  const rules = new Map<string, SarifRuleOut>();
  const results: unknown[] = [];
  for (const target of report.Results ?? []) {
    const packages = target.Packages ?? [];
    let cached: readonly string[] | null | undefined;
    const lines = () =>
      cached === undefined ? (cached = lockfileLines(root, target.Target)) : cached;
    for (const v of target.Vulnerabilities ?? []) {
      const severity = severityOf(v.Severity);
      const cwe = (v.CweIDs ?? []).filter((c) => /^CWE-\d{1,7}$/.test(c)).slice(0, MAX_IDS);
      if (!rules.has(v.VulnerabilityID)) {
        const title = v.Title?.trim();
        rules.set(v.VulnerabilityID, {
          id: v.VulnerabilityID,
          name: v.VulnerabilityID,
          shortDescription: { text: title ? title : v.VulnerabilityID },
          ...(v.PrimaryURL?.startsWith('https://') === true && { helpUri: v.PrimaryURL }),
          properties: {
            tags: ['dependency', ...(target.Type !== undefined ? [target.Type] : [])],
            cwe,
            trivySeverity: severity,
          },
        });
      }
      const p = packageOf(packages, v);
      const region = regionOf(p, v, target.Type, lines);
      const purl = v.PkgIdentifier?.PURL ?? p?.Identifier?.PURL;
      results.push({
        ruleId: v.VulnerabilityID,
        message: { text: trivyMessage(v) },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: target.Target },
              ...(region !== undefined && { region }),
            },
          },
        ],
        properties: {
          trivySeverity: severity,
          dependency: {
            name: v.PkgName,
            version: v.InstalledVersion,
            ...(v.FixedVersion ? { fixedVersion: v.FixedVersion } : {}),
            ...(purl !== undefined && purl.length <= 512 ? { purl } : {}),
            ...(target.Type !== undefined ? { type: target.Type } : {}),
            ...(p?.Relationship === 'direct' ? { direct: true } : {}),
          },
          ...(v.VendorIDs !== undefined && v.VendorIDs.length > 0
            ? { vendorIds: v.VendorIDs.slice(0, MAX_IDS) }
            : {}),
        },
      });
    }
  }
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Trivy',
            ...(report.Trivy?.Version !== undefined && { version: report.Trivy.Version }),
            informationUri: 'https://trivy.dev/',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
