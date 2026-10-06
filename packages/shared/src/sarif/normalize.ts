import { contextHash, filelessHash, lineHash, MAX_HASHED_LINES } from '../hash';
import { normalizeRepoPath, PathError } from '../paths';
import type { ReportFinding, RuleMeta } from '../report/schema';
import { REPORT_BOUNDS } from '../report/schema';
import { QUALITIES, type Quality, type Severity } from '../report/taxonomy';
import { currentHelpUri } from '../rules/help-uri';
import {
  sarifLogSchema,
  type SarifLevel,
  type SarifLocation,
  type SarifResult,
  type SarifRule,
  type SarifRun,
} from './types';

export const REDACTED = '«redacted»';
const SNIPPET_CONTEXT = 3;

export class SarifError extends Error {
  override name = 'SarifError';
}

export interface EngineMapping {
  /** Rule-level metadata the engine implies (quality, severity, kind, extra tags). */
  rule?(rule: SarifRule): Partial<Pick<RuleMeta, 'quality' | 'defaultSeverity' | 'kind'>>;
  /** Per-result severity override (e.g. SpotBugs rank). */
  severity?(result: SarifResult, rule: SarifRule | undefined): Severity | undefined;
  /** Replace the flagged region with «redacted» in hashes and snippets (secrets); per rule when a function. */
  redactRegion?: boolean | ((rule: SarifRule | undefined) => boolean);
  /** Never copy the results' partialFingerprints (e.g. Gitleaks: commit author and email). */
  dropPartialFingerprints?: boolean;
  /**
   * A redacting result's `region.snippet.text` is the secret itself (Gitleaks), not the whole
   * match (Semgrep). Only such texts feed the fragment scrub of messages; every secret text is
   * still scrubbed exactly.
   */
  exactSecretText?: boolean;
  /**
   * What a finding is, independent of its file's text (report-format.md §7.3): a dependency
   * scanner's `name@version` of the vulnerable package. When it returns a value for a located
   * finding, both hashes are `hex32(ruleKey ‖ 0 ‖ path ‖ 0 ‖ identity)` instead of the hashes of
   * the flagged lines, so the finding keeps its identity when the lockfile around it changes and
   * when the file is too large to read (a lockfile over 1 MiB), and not when the version changes.
   */
  identity?(result: SarifResult): string | undefined;
}

/** SARIF §3.27.10: a result without `level` defaults to `none` unless its kind is absent or `fail`. */
function resultLevel(result: SarifResult, rule: SarifRule | undefined): SarifLevel {
  if (result.level !== undefined) return result.level;
  if (result.kind !== undefined && result.kind !== 'fail') return 'none';
  return rule?.defaultConfiguration?.level ?? 'warning';
}

function withinFingerprintBounds(pf: Readonly<Record<string, string>>): boolean {
  const entries = Object.entries(pf);
  return (
    entries.length <= REPORT_BOUNDS.partialFingerprintKeys &&
    entries.every(
      ([k, v]) =>
        k.length <= REPORT_BOUNDS.partialFingerprintKeyChars &&
        v.length <= REPORT_BOUNDS.partialFingerprintValueChars,
    )
  );
}

function shouldRedact(mapping: EngineMapping | undefined, rule: SarifRule | undefined): boolean {
  const r = mapping?.redactRegion;
  return typeof r === 'function' ? r(rule) : r === true;
}

export interface NormalizeOptions {
  engineId: string;
  repoRoot: string;
  readLines(path: string): readonly string[] | null;
  knownPaths?: ReadonlySet<string>;
  /** Prefixes tried (in order) when a result path is not a readable/known file, e.g. ['src/main/java']. */
  sourceRoots?: readonly string[];
  mapping?: EngineMapping;
  /**
   * Secret regions found by other engines (report-format §7 cross-engine redaction, ruling C11).
   * Applied to this log's snippets only, merged with this log's own secret regions before
   * redacting; never affects hashes or the returned `secretRegions`.
   */
  extraSecretRegions?: readonly SourceRegion[];
  /**
   * Secret text found by other engines, alongside `extraSecretRegions`. Scrubbed from this log's
   * messages, snippets and properties wherever it appears (like this log's own secret text);
   * never affects hashes or the secret text `normalizeSarifWithSecrets` returns for this log.
   */
  extraSecretTexts?: readonly string[];
  /**
   * The subset of `extraSecretTexts` that is a secret itself (`SecretExport.fragmentTexts` of
   * other engines): their fragments are scrubbed from this log's messages too.
   */
  extraFragmentTexts?: readonly string[];
}

export interface NormalizeWarning {
  code: string;
  message: string;
  count: number;
}

/** A resolved source region (1-based lines; columns 1-based and inclusive). */
export interface SourceRegion {
  path: string;
  startLine: number;
  startColumn?: number;
  endLine: number;
  endColumn?: number;
}

export interface NormalizeResult {
  version: string | null;
  rules: RuleMeta[];
  findings: ReportFinding[];
  warnings: NormalizeWarning[];
  /**
   * Primary regions of every result whose rule redacts (secrets), including suppressed results.
   * Within one `normalizeSarif` call these regions are already applied to every snippet. Cross-engine
   * contract (report-format §7): the CLI must apply the union of all engines' `secretRegions` to the
   * snippets of every other engine's findings before building the report. Hashes are never affected.
   *
   * Positions only, never the secret's own text, so `NormalizeResult` is always safe to
   * serialise (JSON.stringify, logging, a report file). The secret text itself is only ever
   * available through `normalizeSarifWithSecrets`.
   */
  secretRegions: SourceRegion[];
}

/** The secret material one log's redacting results carry, for the CLI's cross-engine pass only. */
export interface SecretExport {
  regions: SourceRegion[];
  /** `region.snippet.text` (≥ 8 chars), or text derived from a redacting result's own single-line
   * region when it has none. Never write this outside the CLI's in-memory cross-engine pass. */
  texts: string[];
  /** The texts that are the secret itself (`EngineMapping.exactSecretText`), for fragments. */
  fragmentTexts: string[];
}

export function levelToSeverity(level: SarifLevel): Severity {
  switch (level) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'note':
      return 'low';
    case 'none':
      return 'info';
  }
}

export function parseCwe(values: readonly unknown[]): number[] {
  const out = new Set<number>();
  for (const v of values) {
    if (typeof v === 'number' && Number.isInteger(v) && v > 0) out.add(v);
    if (typeof v === 'string') {
      const m = /cwe[-/](\d+)/i.exec(v);
      if (m) out.add(Number(m[1]));
    }
  }
  return [...out].sort((a, b) => a - b);
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

/**
 * A tool version fit for the report (`engines[].version`): trimmed, 1–128 characters, no control
 * characters; anything else (a garbled `--version` probe, a crafted package.json) becomes null.
 */
export function toolVersion(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  const control = [...t].some((c) => (c.codePointAt(0) ?? 0) < 0x20 || c === '\u007f');
  if (t.length === 0 || t.length > REPORT_BOUNDS.engineVersionChars || control) {
    return null;
  }
  return t;
}

/** Empty or whitespace-only text is treated as absent in the message fallback chain (R9). */
function nonBlank(s: string | undefined): string | undefined {
  return s !== undefined && s.trim().length > 0 ? s : undefined;
}

class Warnings {
  private readonly map = new Map<string, NormalizeWarning>();
  add(code: string, message: string): void {
    const w = this.map.get(code);
    if (w) w.count += 1;
    else this.map.set(code, { code, message, count: 1 });
  }
  list(): NormalizeWarning[] {
    return [...this.map.values()];
  }
}

/** Returns the lower-cased URI scheme (e.g. "file"), or null when the URI has none. */
function schemeOf(uri: string): string | null {
  const idx = uri.indexOf(':');
  if (idx <= 0) return null;
  const candidate = uri.slice(0, idx);
  return /^[a-zA-Z][a-zA-Z0-9+.-]*$/.test(candidate) ? candidate.toLowerCase() : null;
}

/** Converts a `file:` URI to a path. Returns null for a non-empty host (UNC/remote). */
function fileUriToPath(uri: string): string | null {
  const url = new URL(uri);
  if (url.host !== '') return null;
  let p = decodeURIComponent(url.pathname);
  if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
  return p;
}

/**
 * Resolves a SARIF artifactLocation URI (optionally against a uriBaseId) to a filesystem
 * path. Returns null when the URI's scheme is neither absent (a relative path) nor `file:`
 * (report-format §7, controller ruling R9), or when a `file:` URI has a non-empty host.
 */
function resolveUri(run: SarifRun, uri: string, baseId: string | undefined): string | null {
  const base = baseId ? run.originalUriBaseIds?.[baseId]?.uri : undefined;
  const combined =
    base !== undefined && schemeOf(uri) === null && !uri.startsWith('/')
      ? base.endsWith('/')
        ? base + uri
        : `${base}/${uri}`
      : uri;
  const scheme = schemeOf(combined);
  if (scheme === null) return decodeURIComponent(combined);
  if (scheme !== 'file') return null;
  return fileUriToPath(combined);
}

type Resolved = SourceRegion;

type PathOutcome = Resolved | 'none' | 'invalid' | 'out-of-scope';

/**
 * Resolves a location's path and region without checking scope, so a caller that needs the raw
 * geometry even for an out-of-scope path (fix-round-2 finding 4: deriving a secret's text from a
 * file outside `knownPaths`, e.g. `.env`) can still get it. `resolveLocation` below layers the
 * scope check on top of this for the normal finding-location path.
 */
function resolveRegionUnscoped(
  run: SarifRun,
  l: SarifLocation | undefined,
  o: Pick<NormalizeOptions, 'repoRoot' | 'knownPaths' | 'readLines' | 'sourceRoots'>,
): Resolved | 'none' | 'invalid' {
  const uri = l?.physicalLocation?.artifactLocation?.uri;
  if (uri === undefined) return 'none';
  let path: string;
  try {
    const resolved = resolveUri(run, uri, l?.physicalLocation?.artifactLocation?.uriBaseId);
    if (resolved === null) return 'invalid';
    path = normalizeRepoPath(resolved, o.repoRoot);
  } catch (e) {
    if (e instanceof PathError || e instanceof URIError || e instanceof TypeError) return 'invalid';
    throw e;
  }
  const known = (p: string) => (o.knownPaths ? o.knownPaths.has(p) : o.readLines(p) !== null);
  if (!known(path)) {
    const alt = (o.sourceRoots ?? []).map((r) => `${r.replace(/\/+$/, '')}/${path}`).find(known);
    if (alt !== undefined) path = alt;
  }
  const r = l?.physicalLocation?.region;
  const startLine = Math.max(1, r?.startLine ?? 1);
  const endLine = Math.max(startLine, r?.endLine ?? startLine);
  const out: Resolved = { path, startLine, endLine };
  if (r?.startColumn !== undefined) out.startColumn = Math.max(1, r.startColumn);
  if (r?.endColumn !== undefined) {
    let end = r.endColumn - 1;
    if (endLine === startLine && out.startColumn !== undefined)
      end = Math.max(out.startColumn, end);
    out.endColumn = Math.max(1, end);
  }
  return out;
}

function resolveLocation(
  run: SarifRun,
  l: SarifLocation | undefined,
  o: Pick<NormalizeOptions, 'repoRoot' | 'knownPaths' | 'readLines' | 'sourceRoots'>,
): PathOutcome {
  const resolved = resolveRegionUnscoped(run, l, o);
  if (typeof resolved === 'string') return resolved;
  if (o.knownPaths && !o.knownPaths.has(resolved.path)) return 'out-of-scope';
  return resolved;
}

/**
 * Returns a copy of `lines` with every region replaced by «redacted». Spans are computed on the
 * original text and merged per line, so overlapping or adjacent regions on one line never leak
 * characters. A region line without columns is redacted whole.
 */
function redact(lines: readonly string[], regions: readonly Resolved[]): string[] {
  const spans = new Map<number, [number, number][]>();
  for (const loc of regions) {
    for (let n = loc.startLine; n <= Math.min(loc.endLine, lines.length); n++) {
      const len = (lines[n - 1] ?? '').length;
      const from = n === loc.startLine && loc.startColumn !== undefined ? loc.startColumn - 1 : 0;
      const to = n === loc.endLine && loc.endColumn !== undefined ? loc.endColumn : len;
      const lo = Math.min(from, len);
      const list = spans.get(n) ?? [];
      list.push([lo, Math.min(Math.max(to, lo), len)]);
      spans.set(n, list);
    }
  }
  const copy = [...lines];
  for (const [n, list] of spans) {
    const text = copy[n - 1] ?? '';
    list.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    let out = '';
    let pos = 0;
    let current: [number, number] | undefined;
    for (const span of list) {
      if (current && span[0] <= current[1]) {
        current[1] = Math.max(current[1], span[1]);
        continue;
      }
      if (current) {
        out += text.slice(pos, current[0]) + REDACTED;
        pos = current[1];
      }
      current = [span[0], span[1]];
    }
    if (current) out += text.slice(pos, current[0]) + REDACTED + text.slice(current[1]);
    copy[n - 1] = out;
  }
  return copy;
}

/** Minimum length of a secret text that is scrubbed wherever it appears. */
const MIN_SCRUB_CHARS = 8;

/**
 * Secrets sharing one 8-character prefix that are checked at each position of a string; the rest
 * of such a group is found with `indexOf` instead, so a flood of secrets with one common prefix
 * keeps the scan near-linear in the string length.
 */
const MAX_PREFIX_CANDIDATES = 8;

/**
 * Replaces every occurrence of a secret text (at least 8 characters) with `«redacted»`. Secrets
 * are indexed by their first 8 characters, so a string is scanned once: at each position the
 * longest of at most `MAX_PREFIX_CANDIDATES` secrets with that prefix is matched, and any other
 * secret of a larger group is searched with `indexOf`. Overlapping matches (two secrets sharing
 * characters, or one that starts inside another) are merged into one `«redacted»`, so no tail of
 * an overlap survives; adjacent matches stay separate.
 */
function scrubber(secrets: ReadonlySet<string>): (s: string) => string {
  const byPrefix = new Map<string, string[]>();
  for (const t of secrets) {
    if (t.length < MIN_SCRUB_CHARS) continue;
    const key = t.slice(0, MIN_SCRUB_CHARS);
    const list = byPrefix.get(key);
    if (list === undefined) byPrefix.set(key, [t]);
    else list.push(t);
  }
  if (byPrefix.size === 0) return (s) => s;
  const overflow: string[] = [];
  for (const [key, list] of byPrefix) {
    list.sort((a, b) => b.length - a.length);
    if (list.length > MAX_PREFIX_CANDIDATES) {
      overflow.push(...list.slice(MAX_PREFIX_CANDIDATES));
      byPrefix.set(key, list.slice(0, MAX_PREFIX_CANDIDATES));
    }
  }
  return (s) => {
    const spans: [number, number][] = [];
    for (let i = 0; i + MIN_SCRUB_CHARS <= s.length; i += 1) {
      const match = byPrefix.get(s.slice(i, i + MIN_SCRUB_CHARS))?.find((t) => s.startsWith(t, i));
      if (match !== undefined) spans.push([i, i + match.length]);
    }
    for (const t of overflow) {
      for (let i = s.indexOf(t); i !== -1; i = s.indexOf(t, i + 1)) spans.push([i, i + t.length]);
    }
    if (spans.length === 0) return s;
    spans.sort((a, b) => a[0] - b[0]);
    let out = '';
    let last = 0;
    let current: [number, number] | undefined;
    for (const span of spans) {
      if (current !== undefined && span[0] < current[1]) {
        current[1] = Math.max(current[1], span[1]);
        continue;
      }
      if (current !== undefined) {
        out += s.slice(last, current[0]) + REDACTED;
        last = current[1];
      }
      current = [span[0], span[1]];
    }
    if (current !== undefined) {
      out += s.slice(last, current[0]) + REDACTED;
      last = current[1];
    }
    return out + s.slice(last);
  };
}

/** A quoted string literal (one line) of at least 8 characters inside a whole-match snippet. */
const QUOTED_LITERAL = /"([^"\n]{8,})"|'([^'\n]{8,})'|`([^`\n]{8,})`/g;

/**
 * The secret inside a whole-match snippet (Semgrep: `const apiKey = "…";`): its quoted string
 * literals of at least 8 characters. Unlike the whole match, they hold no code words, so they
 * are safe to scrub exactly and by fragment everywhere. Bounded by the snippet itself.
 */
function quotedLiterals(match: string): string[] {
  return [...match.matchAll(QUOTED_LITERAL)].map((m) => m[1] ?? m[2] ?? m[3] ?? '');
}

/** Fragments indexed for the message scrub, at most (memory stays in the tens of MB). */
const MAX_FRAGMENT_GRAMS = 250_000;

/**
 * Messages only: every run of text covered by 8-character fragments of a secret text is replaced,
 * so a message that quotes only part of a match (a Semgrep metavariable bound to the secret
 * inside a longer `region.snippet.text`) is scrubbed too. Any substring of at least 8 characters
 * of a secret is the union of its 8-character fragments, so each is caught; adjacent fragments
 * may merge into one wider `«redacted»` (over-redaction, never under-redaction). Linear in the
 * message length. Only texts that are the secret itself feed it (fix round 2 of tasks 5-6: a
 * whole-match snippet would blank ordinary code words), and at most `MAX_FRAGMENT_GRAMS`
 * fragments are indexed: a text that does not fit, or one over 4 KiB, is scrubbed exactly only.
 * `secrets` are indexed in the order given (the caller puts other engines' texts first, then
 * the shortest), so under the cap as many texts as possible keep their fragment scrub.
 */
function fragmentScrubber(secrets: Iterable<string>): (s: string) => string {
  const grams = new Set<string>();
  for (const t of secrets) {
    const count = t.length - MIN_SCRUB_CHARS + 1;
    if (count <= 0 || t.length > 4096 || grams.size + count > MAX_FRAGMENT_GRAMS) continue;
    for (let i = 0; i < count; i += 1) grams.add(t.slice(i, i + MIN_SCRUB_CHARS));
  }
  if (grams.size === 0) return (s) => s;
  return (s) => {
    const covered = new Uint8Array(s.length);
    let any = false;
    for (let i = 0; i + MIN_SCRUB_CHARS <= s.length; i += 1) {
      if (grams.has(s.slice(i, i + MIN_SCRUB_CHARS))) {
        covered.fill(1, i, i + MIN_SCRUB_CHARS);
        any = true;
      }
    }
    if (!any) return s;
    let out = '';
    for (let i = 0; i < s.length;) {
      if (covered[i] === 1) {
        while (i < s.length && covered[i] === 1) i += 1;
        out += REDACTED;
      } else {
        out += s[i];
        i += 1;
      }
    }
    return out;
  };
}

/** Recursively scrubs every string leaf of a JSON-like value (finding-2: `properties`). */
function scrubDeep(value: unknown, scrub: (s: string) => string): unknown {
  if (typeof value === 'string') return scrub(value);
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, scrub));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrubDeep(v, scrub)]));
  }
  return value;
}

/**
 * Drops (rather than scrubs) any `partialFingerprints` entry whose value contains a secret: a
 * scrubbed hash or commit SHA is no longer useful as a fingerprint anyway (finding 2).
 */
function dropSecretFingerprints(
  pf: Readonly<Record<string, string>>,
  secrets: ReadonlySet<string>,
): Record<string, string> {
  if (secrets.size === 0) return { ...pf };
  const list = [...secrets];
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(pf)) {
    if (!list.some((s) => v.includes(s))) out[k] = v;
  }
  return out;
}

/**
 * Every occurrence of a secret text on the raw (unredacted) lines of one file, as one-line
 * regions to merge with the column-based regions before a single `redact()` pass (ruling R18).
 * Computing spans on the raw text first, rather than string-replacing a secret's exact text
 * after the column-based redaction already ran, means a misaligned column (e.g. a byte offset
 * from an engine that counts UTF-8 bytes, on a line with non-ASCII text before the secret) can
 * no longer leave a fragment of the secret visible: the text search finds the true span
 * regardless of what the reported column pointed at.
 */
function textSpans(
  path: string,
  lines: readonly string[],
  secrets: ReadonlySet<string>,
): Resolved[] {
  const out: Resolved[] = [];
  for (const secret of secrets) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      let from = 0;
      for (;;) {
        const idx = line.indexOf(secret, from);
        if (idx === -1) break;
        out.push({
          path,
          startLine: i + 1,
          startColumn: idx + 1,
          endLine: i + 1,
          endColumn: idx + secret.length,
        });
        from = idx + secret.length;
      }
    }
  }
  return out;
}

/**
 * Finding 2: when a redacting result has no `region.snippet.text`, the secret's literal value is
 * derived from its own single-line region on the raw line instead, so the result's `message` (and
 * any coincidental copy of the secret elsewhere) can still be scrubbed.
 */
function deriveSecretText(raw: readonly string[] | null, primary: Resolved): string | undefined {
  if (raw === null || primary.startLine !== primary.endLine || primary.startColumn === undefined) {
    return undefined;
  }
  const line = raw[primary.startLine - 1];
  if (line === undefined) return undefined;
  const text = line.slice(primary.startColumn - 1, primary.endColumn ?? line.length);
  return text.length >= MIN_SCRUB_CHARS ? text : undefined;
}

function ruleMeta(
  rule: SarifRule,
  mapping: EngineMapping | undefined,
  scrub: (s: string) => string,
): RuleMeta {
  const props = rule.properties ?? {};
  const allTags = Array.isArray(props['tags'])
    ? (props['tags'] as unknown[]).filter((t): t is string => typeof t === 'string')
    : [];
  const cweProp = Array.isArray(props['cwe']) ? (props['cwe'] as unknown[]) : [];
  const qualorProp = props['qualor'] as { quality?: unknown } | undefined;
  const declared = QUALITIES.find((q) => q === qualorProp?.quality);
  const mapped = mapping?.rule?.(rule) ?? {};
  const level = rule.defaultConfiguration?.level;
  const defaultSeverity = mapped.defaultSeverity ?? (level ? levelToSeverity(level) : undefined);
  // A relationship to the CWE taxonomy (SpotBugs) names the CWE by its bare number; only a plain
  // positive number of at most 7 digits counts, so a crafted id cannot become an unsafe integer.
  const cweRelations = (rule.relationships ?? [])
    .filter((r) => r.target?.toolComponent?.name?.toUpperCase() === 'CWE')
    .map((r) => r.target?.id ?? '')
    .filter((id) => /^[1-9]\d{0,6}$/.test(id))
    .map((id) => `CWE-${id}`);
  const cwe = parseCwe([...allTags, ...cweProp, ...cweRelations]).slice(0, REPORT_BOUNDS.ruleCwes);
  const quality: Quality = mapped.quality ?? declared ?? 'maintainability';
  // Report bounds (report-format §5): text is truncated, an over-long URI or tag is dropped (a cut
  // URI would point somewhere else), so tool metadata can never make the report invalid.
  const tags = allTags
    .filter((t) => t.length <= REPORT_BOUNDS.ruleTagChars)
    .slice(0, REPORT_BOUNDS.ruleTags);
  // A link Qualor knows is dead (rules.sonarsource.com, which SonarAnalyzer.CSharp still writes)
  // becomes the rule's live page.
  const helpUri =
    rule.helpUri !== undefined && rule.helpUri.length <= REPORT_BOUNDS.helpUriChars
      ? currentHelpUri(rule.helpUri)
      : undefined;
  return {
    id: rule.id,
    // A rule's name and description are free text a tool (or an external SARIF file) controls,
    // so the secrets any engine found are scrubbed from them like from messages (plan 2A).
    ...(rule.name !== undefined && {
      name: truncate(scrub(rule.name), REPORT_BOUNDS.ruleNameChars),
    }),
    ...(rule.shortDescription?.text !== undefined && {
      shortDescription: truncate(
        scrub(rule.shortDescription.text),
        REPORT_BOUNDS.ruleDescriptionChars,
      ),
    }),
    ...(helpUri !== undefined && { helpUri }),
    ...(defaultSeverity !== undefined && { defaultSeverity }),
    quality,
    kind: mapped.kind ?? 'issue',
    ...(tags.length > 0 && { tags }),
    ...(cwe.length > 0 && { cwe }),
  };
}

interface Prepared {
  run: SarifRun;
  result: SarifResult;
  ruleId: string;
  rule: SarifRule | undefined;
  primary: Resolved | 'none';
  redacts: boolean;
  /** This result's own secret text (snippet.text, or derived from its region), if any. */
  ownSecretText: string | undefined;
}

function normalizeCore(
  input: unknown,
  o: NormalizeOptions,
): { result: NormalizeResult; texts: string[]; fragmentTexts: string[] } {
  const parsed = sarifLogSchema.safeParse(input);
  if (!parsed.success) throw new SarifError(`not a SARIF 2.1.0 log: ${parsed.error.message}`);
  const warnings = new Warnings();
  const rulesById = new Map<string, SarifRule>();
  const findings: ReportFinding[] = [];
  const firstRun = parsed.data.runs[0];
  const version = toolVersion(
    firstRun?.tool.driver.version ?? firstRun?.tool.driver.semanticVersion ?? null,
  );
  const cache = new Map<string, readonly string[] | null>();
  const lines = (p: string) => {
    if (!cache.has(p)) cache.set(p, o.readLines(p));
    return cache.get(p) ?? null;
  };

  // Pass 1: resolve rules and primary locations, and collect every secret region and secret
  // text in the log so that pass 2 can redact them from all snippets, not only their own.
  const prepared: Prepared[] = [];
  const secretRegions: SourceRegion[] = [];
  const secretTexts = new Set<string>();
  const fragmentTexts = new Set<string>();
  for (const run of parsed.data.runs) {
    const driverRules = run.tool.driver.rules ?? [];
    for (const c of [run.tool.driver, ...(run.tool.extensions ?? [])]) {
      for (const r of c.rules ?? []) if (!rulesById.has(r.id)) rulesById.set(r.id, r);
    }
    const collectSecret = (
      result: SarifResult,
    ): { primary: PathOutcome; text: string | undefined } => {
      const primary = resolveLocation(run, result.locations?.[0], o);
      if (typeof primary !== 'string') secretRegions.push(primary);
      const snippetText = result.locations?.[0]?.physicalLocation?.region?.snippet?.text;
      let text: string | undefined =
        snippetText !== undefined && snippetText.length >= MIN_SCRUB_CHARS
          ? snippetText
          : undefined;
      if (text === undefined) {
        // Fix-round-2 finding 4: derive the secret text even when the result's own file sits
        // outside the scan scope (e.g. a `.env` no engine's findings otherwise reference) — the
        // region is still resolved (ignoring the scope check) as long as the file is actually
        // readable and the region is an unambiguous single line with columns.
        const region =
          primary === 'out-of-scope'
            ? resolveRegionUnscoped(run, result.locations?.[0], o)
            : primary;
        if (typeof region !== 'string') text = deriveSecretText(lines(region.path), region);
      }
      if (text !== undefined) secretTexts.add(text);
      // Only the tool's own secret text is the secret itself; a region-derived text covers the
      // match (Gitleaks' columns include `apiKey = "…"`), so it is scrubbed exactly only.
      if (text !== undefined && text === snippetText && o.mapping?.exactSecretText === true) {
        fragmentTexts.add(text);
      } else if (snippetText !== undefined && snippetText.length <= 4096) {
        // A whole-match snippet (Semgrep): its quoted literals are the secret itself.
        for (const literal of quotedLiterals(snippetText)) {
          secretTexts.add(literal);
          fragmentTexts.add(literal);
        }
      }
      return { primary, text };
    };
    for (const result of run.results ?? []) {
      if (result.kind === 'pass' || result.kind === 'notApplicable') continue;
      const suppressed = result.suppressions?.some((s) => s.status !== 'rejected') ?? false;
      const ruleId =
        result.ruleId ??
        result.rule?.id ??
        (result.ruleIndex !== undefined ? driverRules[result.ruleIndex]?.id : undefined);
      const rule = ruleId !== undefined ? rulesById.get(ruleId) : undefined;
      const redacts = shouldRedact(o.mapping, rule);
      if (ruleId === undefined) {
        // Ruling R18: a result's secret must still be redacted even when it carries no rule id
        // (e.g. a mapping that redacts unconditionally, regardless of the rule).
        if (redacts) collectSecret(result);
        if (!suppressed) {
          warnings.add('RESULT_WITHOUT_RULE', 'SARIF result without a rule id was dropped');
        }
        continue;
      }
      if (ruleId.length > REPORT_BOUNDS.ruleIdChars) {
        // Its rule is dropped too (below): an id over the report bound cannot be reported, and
        // truncating it could merge two rules. Its secret, if any, is still redacted everywhere.
        if (redacts) collectSecret(result);
        if (!suppressed) {
          warnings.add(
            'RULE_ID_TOO_LONG',
            `finding of a rule whose id is over ${REPORT_BOUNDS.ruleIdChars} characters was dropped`,
          );
        }
        continue;
      }
      const { primary, text: ownSecretText } = redacts
        ? collectSecret(result)
        : { primary: resolveLocation(run, result.locations?.[0], o), text: undefined };
      if (suppressed) continue;
      if (primary === 'invalid') {
        warnings.add(
          'FINDING_PATH_INVALID',
          'finding with an invalid or out-of-repo path was dropped',
        );
        continue;
      }
      if (primary === 'out-of-scope') {
        warnings.add(
          'FINDING_OUT_OF_SCOPE',
          'finding on a file outside the analysis scope was dropped',
        );
        continue;
      }
      prepared.push({ run, result, ruleId, rule, primary, redacts, ownSecretText });
    }
  }

  // Messages, secondary-location messages and properties are scrubbed by plain text search (they
  // carry no columns to misalign); snippets are scrubbed by merging text-search spans with the
  // column-based regions before one redaction pass (ruling R18), so a misaligned column can never
  // leave a fragment of the secret visible.
  const allSecretTexts =
    (o.extraSecretTexts?.length ?? 0) === 0
      ? secretTexts
      : new Set([...secretTexts, ...(o.extraSecretTexts ?? [])]);
  const scrub = scrubber(allSecretTexts);
  // Under the fragment cap, other engines' texts come first (this log's own secret results never
  // show their message anyway), then the shortest, so as many texts as possible are indexed.
  const byLength = (a: string, b: string) => a.length - b.length;
  const scrubFragments = fragmentScrubber(
    new Set([
      ...[...(o.extraFragmentTexts ?? [])].sort(byLength),
      ...[...fragmentTexts].sort(byLength),
    ]),
  );
  const scrubMessage = (s: string) => scrubFragments(scrub(s));
  const regionsByPath = new Map<string, Resolved[]>();
  for (const r of [...secretRegions, ...(o.extraSecretRegions ?? [])])
    regionsByPath.set(r.path, [...(regionsByPath.get(r.path) ?? []), r]);
  const displayCache = new Map<string, string[]>();
  const displayLines = (p: string, raw: readonly string[]) => {
    let d = displayCache.get(p);
    if (!d) {
      const spans = [...(regionsByPath.get(p) ?? []), ...textSpans(p, raw, allSecretTexts)];
      d = redact(raw, spans);
      displayCache.set(p, d);
    }
    return d;
  };

  // Pass 2: build findings.
  for (const { run, result, ruleId, rule, primary, redacts, ownSecretText } of prepared) {
    const ruleKey = `${o.engineId}:${ruleId}`;
    // A redacting (secret) result's own message is never used: a tool can interpolate part of
    // the match into it (a Semgrep metavariable bound to the secret alone), which no text scrub
    // of the whole match can find. The rule's static text stands in for it.
    const text = redacts
      ? (nonBlank(rule?.fullDescription?.text) ?? nonBlank(rule?.shortDescription?.text) ?? ruleId)
      : (nonBlank(result.message?.text) ??
        nonBlank(result.message?.markdown) ??
        nonBlank(rule?.shortDescription?.text) ??
        ruleId);
    const message = truncate(scrubMessage(text), REPORT_BOUNDS.messageChars);
    const severity =
      o.mapping?.severity?.(result, rule) ?? levelToSeverity(resultLevel(result, rule));

    const finding: ReportFinding = {
      engineId: o.engineId,
      ruleId,
      message,
      severity,
      location: null,
      lineHash: filelessHash(ruleKey, message),
      contextHash: filelessHash(ruleKey, message),
    };

    if (primary !== 'none') {
      finding.location = {
        path: primary.path,
        startLine: primary.startLine,
        ...(primary.startColumn !== undefined && { startColumn: primary.startColumn }),
        endLine: primary.endLine,
        ...(primary.endColumn !== undefined && { endColumn: primary.endColumn }),
      };
      const raw = lines(primary.path);
      const identity = o.mapping?.identity?.(result);
      if (identity !== undefined) {
        finding.lineHash = filelessHash(ruleKey, identity, primary.path);
        finding.contextHash = finding.lineHash;
      }
      if (raw === null || primary.startLine > raw.length) {
        if (identity !== undefined) {
          // Nothing to fall back from: the identity is the hash input (a large lockfile).
        } else {
          warnings.add(
            'HASH_FALLBACK',
            'source unavailable for a finding; used a message-based hash',
          );
          finding.lineHash = filelessHash(ruleKey, message, primary.path);
          finding.contextHash = finding.lineHash;
        }
      } else {
        // Hashes: a redacting finding hashes its own region (plus, finding 6, any exact match of
        // its own secret text on that same region's lines, so a misaligned column cannot leave a
        // fragment of the secret baked into the hash input either); every other finding hashes
        // the unredacted lines, so its fingerprint does not depend on whether a secret scan ran.
        // Cross-engine `extraSecretTexts`/`extraSecretRegions` never reach the hash.
        const ownSpans =
          redacts && ownSecretText !== undefined
            ? textSpans(primary.path, raw, new Set([ownSecretText])).filter(
                (s) => s.startLine >= primary.startLine && s.startLine <= primary.endLine,
              )
            : [];
        const hashed = redacts ? redact(raw, [primary, ...ownSpans]) : raw;
        const end = Math.min(primary.endLine, raw.length);
        if (identity === undefined) {
          finding.lineHash = lineHash(hashed, primary.startLine, end);
          finding.contextHash = contextHash(hashed, primary.startLine, end);
        }
        // Snippets: every secret region and secret text of this log (and, cross-engine, every
        // other engine's) is redacted.
        const shown = displayLines(primary.path, raw);
        const from = Math.max(1, primary.startLine - SNIPPET_CONTEXT);
        const to = Math.min(
          shown.length,
          Math.min(end, primary.startLine + MAX_HASHED_LINES - 1) + SNIPPET_CONTEXT,
        );
        finding.snippet = {
          startLine: from,
          lines: shown.slice(from - 1, to).map((l) => truncate(l, REPORT_BOUNDS.snippetLineChars)),
        };
      }
    }

    const secondary: NonNullable<ReportFinding['secondaryLocations']> = [];
    for (const l of [...(result.locations ?? []).slice(1), ...(result.relatedLocations ?? [])]) {
      if (secondary.length >= REPORT_BOUNDS.secondaryLocations) break;
      const s = resolveLocation(run, l, {
        repoRoot: o.repoRoot,
        readLines: o.readLines,
        sourceRoots: o.sourceRoots,
      });
      if (typeof s === 'string') continue;
      secondary.push({
        path: s.path,
        startLine: s.startLine,
        ...(s.startColumn !== undefined && { startColumn: s.startColumn }),
        endLine: s.endLine,
        ...(s.endColumn !== undefined && { endColumn: s.endColumn }),
        ...(l.message?.text !== undefined && {
          message: truncate(scrubMessage(l.message.text), REPORT_BOUNDS.messageChars),
        }),
      });
    }
    if (secondary.length > 0) finding.secondaryLocations = secondary;
    // Finding 2: a redacting result's properties/partialFingerprints are dropped entirely
    // (defense in depth: a secret-detection rule's own metadata may carry other sensitive
    // material besides the flagged region). A non-redacting result still has its
    // partialFingerprints values dropped if one happens to contain a secret another result
    // found, and every string leaf of its properties scrubbed the same way.
    if (result.partialFingerprints && !redacts && o.mapping?.dropPartialFingerprints !== true) {
      if (withinFingerprintBounds(result.partialFingerprints)) {
        const kept = dropSecretFingerprints(result.partialFingerprints, allSecretTexts);
        if (Object.keys(kept).length > 0) finding.partialFingerprints = kept;
      } else {
        warnings.add(
          'PARTIAL_FINGERPRINTS_DROPPED',
          'result partialFingerprints over the report bounds were dropped',
        );
      }
    }
    if (result.properties && !redacts) {
      if (
        Buffer.byteLength(JSON.stringify(result.properties), 'utf8') <=
        REPORT_BOUNDS.propertiesBytes
      ) {
        finding.properties = scrubDeep(result.properties, scrub) as Record<string, unknown>;
      } else {
        warnings.add('PROPERTIES_TOO_LARGE', 'result properties over 4 KiB were dropped');
      }
    }
    findings.push(finding);
  }

  const output: NormalizeResult = {
    version,
    rules: [...rulesById.values()]
      .filter((r) => r.id.length > 0 && r.id.length <= REPORT_BOUNDS.ruleIdChars)
      .map((r) => ruleMeta(r, o.mapping, scrubMessage)),
    findings,
    warnings: warnings.list(),
    secretRegions,
  };
  return { result: output, texts: [...secretTexts], fragmentTexts: [...fragmentTexts] };
}

export function normalizeSarif(input: unknown, o: NormalizeOptions): NormalizeResult {
  return normalizeCore(input, o).result;
}

/**
 * Like `normalizeSarif`, but also returns the secret regions and secret text this log's
 * redacting results carry (`secrets`), for the CLI's cross-engine redaction pass (ruling
 * C11/R18, report-format §7). `result` never contains secret plaintext and is always safe to
 * serialise (JSON.stringify, a report file, a log line); `secrets.texts` does, and the caller
 * must keep it out of anything that gets written or transmitted.
 */
export function normalizeSarifWithSecrets(
  input: unknown,
  o: NormalizeOptions,
): { result: NormalizeResult; secrets: SecretExport } {
  const { result, texts, fragmentTexts } = normalizeCore(input, o);
  return { result, secrets: { regions: result.secretRegions, texts, fragmentTexts } };
}
