import { parseVersionLabel, type ParsedVersion } from './label';

export type VersionRule = { kind: 'lines'; lines: number } | { kind: 'all' } | { kind: 'none' };

export type TrackingReason =
  | 'pinned'
  | 'unsupported'
  | 'prerelease'
  | 'newest_in_line'
  | 'replaced'
  | 'older_line'
  | 'recent'
  | 'older'
  | 'rule_all'
  | 'rule_none';

export interface TrackingInput {
  id: string;
  label: string;
  analyzedAt: Date;
  tracking: 'auto' | 'pinned' | 'unsupported';
}

type Decision = { tracked: boolean; reason: TrackingReason };

interface Entry {
  input: TrackingInput;
  parsed: ParsedVersion | null;
}

/** Positive when `a` is newer: higher numbers first, then the later analysis. */
function compareNewer(a: Entry, b: Entry): number {
  const an = a.parsed?.numbers;
  const bn = b.parsed?.numbers;
  if (an && bn) {
    for (let i = 0; i < 4; i++) {
      const diff = (an[i] ?? 0) - (bn[i] ?? 0);
      if (diff !== 0) return diff;
    }
  }
  return a.input.analyzedAt.getTime() - b.input.analyzedAt.getTime();
}

/** Code-unit order (not locale-dependent). */
function compare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Applies the overrides (pinned, unsupported) to `result`; answers the entries the rule decides. */
function applyOverrides(entries: readonly Entry[], result: Map<string, Decision>): Entry[] {
  const rest: Entry[] = [];
  for (const entry of entries) {
    const { input } = entry;
    if (input.tracking === 'pinned') result.set(input.id, { tracked: true, reason: 'pinned' });
    else if (input.tracking === 'unsupported') {
      result.set(input.id, { tracked: false, reason: 'unsupported' });
    } else rest.push(entry);
  }
  return rest;
}

/** Rule `all` or `none` for the entries without an override; a prerelease is never tracked. */
function decideByRule(
  rest: readonly Entry[],
  kind: Exclude<VersionRule['kind'], 'lines'>,
  result: Map<string, Decision>,
): void {
  for (const { input, parsed } of rest) {
    if (parsed?.prerelease) result.set(input.id, { tracked: false, reason: 'prerelease' });
    else if (kind === 'all') result.set(input.id, { tracked: true, reason: 'rule_all' });
    else result.set(input.id, { tracked: false, reason: 'rule_none' });
  }
}

interface ReleaseLine {
  major: number;
  minor: number;
  entries: Entry[];
}

/** Adds a parsed release (not a prerelease) to its line in `lineMembers`. */
function addToLine(lineMembers: Map<string, ReleaseLine>, entry: Entry): void {
  const p = entry.parsed;
  if (!p || p.prerelease) return;
  let line = lineMembers.get(p.line);
  if (!line) {
    line = { major: p.numbers[0], minor: p.numbers[1], entries: [] };
    lineMembers.set(p.line, line);
  }
  line.entries.push(entry);
}

/**
 * The `lines` newest release lines, and the newest release of each. Lines are ranked over every
 * release whose label parses, whatever its override.
 */
function currentLinesOf(
  entries: readonly Entry[],
  lines: number,
): { currentLines: Set<string>; newestOfLine: Map<string, Entry> } {
  const lineMembers = new Map<string, ReleaseLine>();
  for (const entry of entries) addToLine(lineMembers, entry);
  const ranked = [...lineMembers.entries()].sort(
    ([, a], [, b]) => b.major - a.major || b.minor - a.minor,
  );
  const currentLines = new Set(ranked.slice(0, lines).map(([key]) => key));
  const newestOfLine = new Map<string, Entry>();
  for (const [key, line] of lineMembers) {
    if (!currentLines.has(key)) continue;
    let newest: Entry | undefined;
    for (const entry of line.entries) {
      if (!newest || compareNewer(entry, newest) > 0) newest = entry;
    }
    if (newest) newestOfLine.set(key, newest);
  }
  return { currentLines, newestOfLine };
}

/**
 * Rule `lines` for the entries without an override: the newest release of each current line is
 * tracked; releases whose label does not parse are ranked by analysis, the `lines` most recent
 * tracked.
 */
function decideByLines(
  entries: readonly Entry[],
  rest: readonly Entry[],
  lines: number,
  result: Map<string, Decision>,
): void {
  const { currentLines, newestOfLine } = currentLinesOf(entries, lines);
  const unparsed: Entry[] = [];
  for (const entry of rest) {
    const { input, parsed } = entry;
    if (!parsed) unparsed.push(entry);
    else if (parsed.prerelease) result.set(input.id, { tracked: false, reason: 'prerelease' });
    else if (!currentLines.has(parsed.line)) {
      result.set(input.id, { tracked: false, reason: 'older_line' });
    } else if (newestOfLine.get(parsed.line) === entry) {
      result.set(input.id, { tracked: true, reason: 'newest_in_line' });
    } else result.set(input.id, { tracked: false, reason: 'replaced' });
  }

  unparsed.sort(
    (a, b) =>
      b.input.analyzedAt.getTime() - a.input.analyzedAt.getTime() ||
      compare(a.input.id, b.input.id),
  );
  unparsed.forEach(({ input }, index) => {
    result.set(input.id, {
      tracked: index < lines,
      reason: index < lines ? 'recent' : 'older',
    });
  });
}

/**
 * Decides which versions of a project are tracked for vulnerabilities.
 * Overrides (pinned, unsupported) apply first; the rule decides the rest.
 */
export function computeTracking(
  versions: readonly TrackingInput[],
  rule: VersionRule,
): Map<string, Decision> {
  const result = new Map<string, Decision>();
  const entries: Entry[] = versions.map((input) => ({
    input,
    parsed: parseVersionLabel(input.label),
  }));
  const rest = applyOverrides(entries, result);
  if (rule.kind === 'lines') decideByLines(entries, rest, rule.lines, result);
  else decideByRule(rest, rule.kind, result);
  return result;
}
