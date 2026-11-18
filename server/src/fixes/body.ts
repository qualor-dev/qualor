import type { FixLockfileAdditions, FixPreparedValue, FixTargetValue } from '../db/schema';
import {
  codeSpan,
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
/** A version as a title or a body shows it, at most. */
const VERSION_CHARS = 64;

const changeWord = (provider: FixProvider): string => (provider === 'github' ? 'PR' : 'MR');

const version = (value: string): string => codeSpan(value, VERSION_CHARS);
const path = (value: string): string => codeSpan(value, MAX_PATH_CHARS);

/**
 * R30: `Bump <pkg> from <installed> to <target>`, the commit message and the MR title. One line of
 * at most 236 characters (GitLab takes 255): each value through `plainValue`.
 */
export function fixTitle(packageName: string, installed: string, target: string): string {
  const name = plainValue(packageName, MAX_VALUE_CHARS);
  return `Bump ${name} from ${plainValue(installed, VERSION_CHARS)} to ${plainValue(target, VERSION_CHARS)}`;
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

/** B3: one line per target, each but the last ended by a hard break (GitLab joins soft lines). */
function versionLines(targets: readonly FixTargetValue[]): string[] {
  return targets.map(
    (t, i) =>
      `**Versions:** ${version(t.installed)} → ${version(t.target)} in ${path(t.lockfile)}${i < targets.length - 1 ? '\\' : ''}`,
  );
}

/** The targets a lockfile's pin must reach: those named for it, else every target. */
function pinTargets(lockfile: string, targets: readonly FixTargetValue[]): string {
  const own = targets.filter((t) => t.lockfile === lockfile);
  const values = [...new Set((own.length > 0 ? own : targets).map((t) => t.target))];
  return values.map(version).join(' or ');
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

function lockfileLines(
  lockfiles: readonly FixLockfile[],
  targets: readonly FixTargetValue[],
): string[] {
  return lockfiles.map((l) => `- ${path(l.path)}: ${relationText(l, targets)}`);
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

function majorLines(majorJumps: readonly FixTargetValue[]): string[] {
  if (majorJumps.length === 0) return [];
  const pairs = majorJumps.map((t) => `${version(t.installed)} → ${version(t.target)}`).join(', ');
  return [`> **Major version change:** ${pairs} may need code changes.`];
}

function qualorLines(url: string | null): string[] {
  const link = qualorLink('Vulnerabilities in Qualor', url);
  return link === null ? [] : [link];
}

/**
 * spec §6.7, B3, R29, ruling T3i: the MR body, its parts separated by blank lines and the empty
 * ones left out: the vulnerabilities fixed (a table), the unfixable ones, one version line per
 * target, each lockfile direct or transitive, the lockfiles' new entries, a major version
 * warning, the link to the project's Vulnerabilities tab, and the sentence that says how Qualor
 * keeps the MR ("PR" on GitHub).
 */
export function fixBody(input: FixBodyInput): string {
  const parts = [
    vulnerabilityTable(input.vulnerabilities),
    unfixableLines(input.unfixable),
    versionLines(input.targets),
    lockfileLines(input.lockfiles, input.targets),
    additionLines(input.additions),
    majorLines(input.majorJumps),
    qualorLines(input.vulnerabilitiesUrl),
    [
      `Qualor keeps this ${changeWord(input.provider)} current and closes it when the vulnerability is gone. Push to this branch to take it over.`,
    ],
  ];
  return parts
    .filter((lines) => lines.length > 0)
    .map((lines) => lines.join('\n'))
    .join('\n\n');
}
