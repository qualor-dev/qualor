import type { FixLockfileAdditions, FixPreparedValue, FixTargetValue } from '../db/schema';
import {
  codeSpan,
  linesWithinBytes,
  MAX_PATH_CHARS,
  MAX_VALUE_CHARS,
  plainValue,
  qualorLink,
  ruleKeyMarkdown,
} from '../scm/markdown';
import type { VulnerabilitySeverity } from '../vulnerabilities/order';

/**
 * The text of a fix MR (0.16 fix MRs §6.7, B3, R29, R30, rulings T3i, F25): its title, its body and
 * the comments Qualor closes it with. Every value comes from the fix job's upload or from an
 * advisory (package names, versions, paths, mechanisms, dependents, lockfile entries, vulnerability
 * ids, titles and URLs), so each goes through `plainValue` (the title, which renders no Markdown)
 * or `codeSpan` (scm.md §6); an advisory link is an https URL only (`ruleKeyMarkdown`), and a table
 * cell has its pipes escaped ({@link cell}).
 */

export type FixProvider = 'gitlab' | 'github';

/** One vulnerability as the body lists it: the package's main rows of that id (§6.7). */
export interface FixBodyVulnerability {
  id: string;
  severity: VulnerabilitySeverity;
  title: string | null;
  url: string | null;
}

export interface FixBodyInput {
  provider: FixProvider;
  /** One per vulnerable installed version (B3), as the upload named them. */
  targets: FixTargetValue[];
  /** The vulnerabilities the MR fixes. */
  vulnerabilities: FixBodyVulnerability[];
  /** The package's vulnerabilities with no fixed version above its installed versions. */
  unfixable: FixBodyVulnerability[];
  lockfiles: FixPreparedValue['lockfiles'];
  /** Ruling T3i: the entries each uploaded lockfile adds. */
  additions: FixLockfileAdditions[];
  /** The targets that leave their installed version's release line (a major version change). */
  majorJumps: FixTargetValue[];
  /** The project's Vulnerabilities tab (`vulnerabilitiesUrl`, ruling F25); null without one. */
  vulnerabilitiesUrl: string | null;
}

/** Ruling T3i: the new lockfile entries the body names at most, in all. */
export const MAX_SHOWN_ADDITIONS = 30;
/** Rows of the vulnerability table, and ids of the unfixable line, at most (a body is bounded). */
export const MAX_SHOWN_VULNERABILITIES = 50;
/** Ruling T10d: version lines, lockfile lines and major version pairs the body shows at most each. */
export const MAX_SHOWN_LINES = 30;
/** Ruling T10d: the versions a transitive pin's line names at most. */
const MAX_PIN_TARGETS = 5;
/**
 * Ruling T10d: the whole body, at most, cut at whole lines with its last sentence kept. GitHub
 * takes 65 536 characters in a pull request's body; GitLab takes more.
 */
export const MAX_BODY_CHARS = 60_000;
/** A version as a title or a body shows it, at most. */
const VERSION_CHARS = 64;

const changeWord = (provider: FixProvider): string => (provider === 'github' ? 'PR' : 'MR');

const version = (value: string): string => codeSpan(value, VERSION_CHARS);
const path = (value: string): string => codeSpan(value, MAX_PATH_CHARS);

/**
 * Rulings FW2, FW2b: a value as a GitLab title shows it: a code span (`codeSpan`) of at most `max`
 * characters of it, since GitLab reads mentions in a title (`@all/x`, a version `1.0@all` would
 * notify a group) but not inside code. A value whose backticks lengthen the fence is cut further,
 * so the span, fence and padding included, stays within `max + 4` characters.
 */
function titleSpan(value: string, max: number): string {
  let span = codeSpan(value, max);
  for (let room = max - 1; [...span].length > max + 4 && room > 0; room -= 1) {
    span = codeSpan(value, room);
  }
  return span;
}

/**
 * R30 (amended by rulings FW2, FW2b): `Bump <pkg> from <installed> to <target>`, the commit
 * message and the MR title, one line. The commit message (no `provider`) and a GitHub title are
 * plain, each value through `plainValue` (at most 243 characters); a GitLab title holds the name
 * and both versions in code spans ({@link titleSpan}; at most 255 characters, GitLab's limit).
 */
export function fixTitle(
  packageName: string,
  installed: string,
  target: string,
  provider?: FixProvider,
): string {
  const shown =
    provider === 'gitlab' ? titleSpan : (value: string, max: number) => plainValue(value, max);
  return `Bump ${shown(packageName, MAX_VALUE_CHARS)} from ${shown(installed, VERSION_CHARS)} to ${shown(target, VERSION_CHARS)}`;
}

/** R29: the comment Qualor closes a cancelled fix's MR with ("PR" on GitHub). */
export function cancelComment(provider: FixProvider): string {
  return `Qualor closed this ${changeWord(provider)}: a member cancelled the fix in Qualor.`;
}

/**
 * spec §6.7: the comment Qualor closes an MR with once main no longer has the vulnerable package.
 * The package and the branch are values (a scope like `@all` is no mention): in code spans.
 */
export function goneComment(packageName: string, mainBranch: string): string {
  return `Qualor no longer finds a vulnerable ${codeSpan(packageName)} on ${path(mainBranch)}`;
}

/**
 * A table cell's Markdown with every pipe escaped (GFM splits a row at a pipe even inside a code
 * span, and unescapes `\|` in the cell before reading it). A pipe after an odd run of backslashes
 * is escaped already; after an even run (none included) one more backslash escapes it, so no
 * renderer can split the row there, whichever way it counts backslashes.
 */
function cell(markdown: string): string {
  let out = '';
  let slashes = 0;
  for (const c of markdown) {
    if (c === '|' && slashes % 2 === 0) out += '\\';
    out += c;
    slashes = c === '\\' ? slashes + 1 : 0;
  }
  return out;
}

/** `and N more`, then `what` when given; '' when nothing is hidden. */
function andMore(hidden: number, what?: string): string {
  if (hidden <= 0) return '';
  return what === undefined ? `and ${hidden} more` : `and ${hidden} more ${what}`;
}

/** The id, linked to its advisory when the URL is a safe https URL (the rule-key link's rules). */
const vulnerabilityId = (v: FixBodyVulnerability): string => ruleKeyMarkdown(v.id, v.url);

/** The table of the vulnerabilities fixed: id (linked), severity, title; [] when there is none. */
function vulnerabilityTable(vulnerabilities: readonly FixBodyVulnerability[]): string[] {
  if (vulnerabilities.length === 0) return [];
  const shown = vulnerabilities.slice(0, MAX_SHOWN_VULNERABILITIES);
  const rows = shown.map((v) => {
    const title = v.title === null ? '' : cell(codeSpan(v.title, MAX_VALUE_CHARS));
    return `| ${cell(vulnerabilityId(v))} | ${v.severity} | ${title} |`;
  });
  const more = andMore(vulnerabilities.length - shown.length, 'vulnerabilities');
  return [
    '| Vulnerability | Severity | Title |',
    '|---|---|---|',
    ...rows,
    // A line right after a table would be one more row: a blank line ends the table.
    ...(more === '' ? [] : ['', more]),
  ];
}

/** `**No fixed version yet:** <id> (<severity>), …`; [] when every vulnerability has a fix. */
function unfixableLines(unfixable: readonly FixBodyVulnerability[]): string[] {
  if (unfixable.length === 0) return [];
  const shown = unfixable
    .slice(0, MAX_SHOWN_VULNERABILITIES)
    .map((v) => `${codeSpan(v.id)} (${v.severity})`);
  const more = andMore(unfixable.length - shown.length);
  return [`**No fixed version yet:** ${[...shown, ...(more === '' ? [] : [more])].join(', ')}`];
}

/** Ruling T10d: each target once (the upload may name one twice). */
function uniqueTargets(targets: readonly FixTargetValue[]): FixTargetValue[] {
  const seen = new Set<string>();
  return targets.filter((t) => {
    const key = JSON.stringify([t.installed, t.target, t.lockfile]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Ruling T10d: the lines of the first {@link MAX_SHOWN_LINES} items, then `more(hidden)` when some
 * are left out.
 */
function capped<T>(
  items: readonly T[],
  render: (item: T) => string,
  more: (hidden: number) => string,
): string[] {
  const lines = items.slice(0, MAX_SHOWN_LINES).map(render);
  const hidden = items.length - lines.length;
  return hidden > 0 ? [...lines, more(hidden)] : lines;
}

/**
 * B3: one line per target (at most {@link MAX_SHOWN_LINES}, then `and N more`), each but the last
 * ended by a hard break (GitLab joins soft lines).
 */
function versionLines(targets: readonly FixTargetValue[]): string[] {
  const lines = capped(
    targets,
    (t) => `**Versions:** ${version(t.installed)} → ${version(t.target)} in ${path(t.lockfile)}`,
    (hidden) => andMore(hidden),
  );
  return lines.map((line, i) => (i < lines.length - 1 ? `${line}\\` : line));
}

/**
 * The targets a lockfile's pin must reach: those named for it, else every target; at most
 * {@link MAX_PIN_TARGETS}, then how many more.
 */
function pinTargets(lockfile: string, targets: readonly FixTargetValue[]): string {
  const own = targets.filter((t) => t.lockfile === lockfile);
  const values = [...new Set((own.length > 0 ? own : targets).map((t) => t.target))];
  const shown = values.slice(0, MAX_PIN_TARGETS).map(version).join(' or ');
  const more = andMore(values.length - MAX_PIN_TARGETS);
  return more === '' ? shown : `${shown} (${more})`;
}

/** Who must bring the target before the pin can go: the dependents, else fixed words. */
function dependentsText(dependents: readonly string[]): string {
  if (dependents.length === 0) return 'the packages that depend on it bring';
  const names = dependents.map((d) => codeSpan(d)).join(', ');
  return dependents.length === 1 ? `${names} brings` : `${names} bring`;
}

type FixLockfile = FixPreparedValue['lockfiles'][number];

/** spec §6.7: `direct`, or how the transitive version is pinned and when the pin can go. */
function relationText(lockfile: FixLockfile, targets: readonly FixTargetValue[]): string {
  if (lockfile.relation === 'direct') return 'direct';
  const mechanism = lockfile.mechanism === null ? 'an override' : codeSpan(lockfile.mechanism);
  return `transitive — pinned through ${mechanism}; remove the pin when ${dependentsText(lockfile.dependents)} ${pinTargets(lockfile.path, targets)} or later`;
}

/** One line per lockfile, at most {@link MAX_SHOWN_LINES}, then `- and N more`. */
function lockfileLines(
  lockfiles: readonly FixLockfile[],
  targets: readonly FixTargetValue[],
): string[] {
  return capped(
    lockfiles,
    (l) => `- ${path(l.path)}: ${relationText(l, targets)}`,
    (hidden) => `- ${andMore(hidden)}`,
  );
}

type LockEntry = FixLockfileAdditions['entries'][number];

/** `name@version`, or an alias as `slot (name@version)`, in one code span. */
function entryText(entry: LockEntry): string {
  const resolved = `${entry.name}@${entry.version}`;
  const alias = entry.slot !== null && entry.slot !== entry.name;
  return codeSpan(alias ? `${entry.slot} (${resolved})` : resolved, MAX_PATH_CHARS);
}

/**
 * Ruling T3i: `**New in the lockfile:**`, then each path with its new entries, at most
 * {@link MAX_SHOWN_ADDITIONS} in all, then `and N more`; [] when no lockfile adds an entry.
 */
function additionLines(additions: readonly FixLockfileAdditions[]): string[] {
  const lines: string[] = [];
  let room = MAX_SHOWN_ADDITIONS;
  let hidden = 0;
  for (const added of additions) {
    const shown = added.entries.slice(0, room);
    hidden += added.entries.length - shown.length;
    room -= shown.length;
    if (shown.length > 0) lines.push(`- ${path(added.path)}: ${shown.map(entryText).join(', ')}`);
  }
  if (lines.length === 0) return [];
  const more = andMore(hidden);
  return ['**New in the lockfile:**', ...lines, ...(more === '' ? [] : [`- ${more}`])];
}

/** The major version warning, its pairs at most {@link MAX_SHOWN_LINES}, then `and N more`. */
function majorLines(majorJumps: readonly FixTargetValue[]): string[] {
  if (majorJumps.length === 0) return [];
  const pairs = capped(
    majorJumps,
    (t) => `${version(t.installed)} → ${version(t.target)}`,
    (hidden) => andMore(hidden),
  ).join(', ');
  return [`> **Major version change:** ${pairs} may need code changes.`];
}

function qualorLines(url: string | null): string[] {
  const link = qualorLink('Vulnerabilities in Qualor', url);
  return link === null ? [] : [link];
}

/**
 * Ruling T10d: the parts, separated by blank lines, within {@link MAX_BODY_CHARS} with `last`
 * after them: cut at whole lines (no code span or table row is cut open), and a hard break left
 * last by the cut taken off, as no line follows it.
 */
function bounded(parts: readonly string[][], last: string): string {
  const lines = parts
    .filter((part) => part.length > 0)
    .flatMap((part, i) => (i === 0 ? part : ['', ...part]));
  const head = linesWithinBytes(lines, MAX_BODY_CHARS - last.length - 2).trimEnd();
  const kept = head.endsWith('\\') ? head.slice(0, -1) : head;
  return kept === '' ? last : `${kept}\n\n${last}`;
}

/**
 * spec §6.7, B3, R29, rulings T3i, T10d: the MR body, its parts separated by blank lines and the
 * empty ones left out: the vulnerabilities fixed (a table), the unfixable ones, one version line
 * per target, each lockfile direct or transitive, the lockfiles' new entries, a major version
 * warning, the link to the project's Vulnerabilities tab, and the sentence that says how Qualor
 * keeps the MR ("PR" on GitHub), which always stays. At most {@link MAX_BODY_CHARS} in all.
 */
export function fixBody(input: FixBodyInput): string {
  const targets = uniqueTargets(input.targets);
  return bounded(
    [
      vulnerabilityTable(input.vulnerabilities),
      unfixableLines(input.unfixable),
      versionLines(targets),
      lockfileLines(input.lockfiles, targets),
      additionLines(input.additions),
      majorLines(input.majorJumps),
      qualorLines(input.vulnerabilitiesUrl),
    ],
    `Qualor keeps this ${changeWord(input.provider)} current and closes it when the vulnerability is gone. Push to this branch to take it over.`,
  );
}
