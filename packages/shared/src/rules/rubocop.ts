import table from '../../rules/rubocop-cops.json' with { type: 'json' };
import type { Quality, Severity } from '../report/taxonomy';
import {
  departmentOf,
  qualorDefaultCops,
  RUBOCOP_COP_NAME,
  RUBOCOP_SYNTAX_COP,
  type RubocopCopState,
  rubocopTableSchema,
} from './rubocop-default';

export * from './rubocop-default';

/**
 * RuboCop (plan 9B, config.md §3, §6). `RUBOCOP_VERSION` is the RuboCop the qualor/scanner image
 * ships (tools/analyzers/install-rubocop.sh; tools/ci.test.ts checks they agree). The CLI runs only
 * a RuboCop of the same major.minor, because rubocop-cops.json describes that version.
 */
export const RUBOCOP_VERSION = '1.91.0';

/** The Ruby syntax RuboCop parses unless `analyzers.rubocop.targetRubyVersion` says otherwise. */
export const RUBOCOP_DEFAULT_TARGET_RUBY = '4.0';

/** A RuboCop department (`Lint`) or cop name (`Lint/UselessAssignment`). */
export const RUBOCOP_SELECTOR = /^[A-Z][A-Za-z]*(?:\/[A-Z][A-Za-z0-9]*)?$/;

/** The generated table, checked by the schema the generator writes it with (rubocop-default.ts). */
const TABLE = rubocopTableSchema.parse(table);

/** Every cop of the pinned RuboCop and its default state (rubocop-cops.json, generated). */
export const RUBOCOP_COPS: ReadonlyMap<string, RubocopCopState> = new Map(
  Object.entries(TABLE.cops),
);
export const RUBOCOP_DEPARTMENTS: ReadonlySet<string> = new Set(
  [...RUBOCOP_COPS.keys()].map(departmentOf),
);
/** The `TargetRubyVersion` values the pinned RuboCop parses. */
export const RUBOCOP_TARGET_RUBIES: readonly string[] = TABLE.targetRubies;

export function rubocopSelectorKnown(s: string): boolean {
  return RUBOCOP_COPS.has(s) || RUBOCOP_DEPARTMENTS.has(s);
}

function expand(s: string, states: ReadonlySet<RubocopCopState>): string[] {
  if (s === 'qualor-default') return qualorDefaultCops(RUBOCOP_COPS);
  if (RUBOCOP_DEPARTMENTS.has(s)) {
    return [...RUBOCOP_COPS]
      .filter(([name, state]) => departmentOf(name) === s && states.has(state))
      .map(([name]) => name);
  }
  return RUBOCOP_COPS.has(s) ? [s] : [];
}

const DEFAULT_ON: ReadonlySet<RubocopCopState> = new Set(['enabled']);
const ANY: ReadonlySet<RubocopCopState> = new Set(['enabled', 'pending', 'disabled']);

/**
 * The cops a scan runs (config.md §6): `select`'s departments (their cops enabled by default),
 * cop names (whatever their state) and qualor-default, minus every cop of `ignore`'s departments
 * and cops. `Lint/Syntax` never counts: it is RuboCop's parse error, not a rule. Sorted.
 */
export function rubocopSelection(select: readonly string[], ignore: readonly string[]): string[] {
  const removed = new Set(ignore.flatMap((s) => expand(s, ANY)));
  const chosen = new Set(select.flatMap((s) => expand(s, DEFAULT_ON)));
  return [...chosen].filter((c) => c !== RUBOCOP_SYNTAX_COP && !removed.has(c)).sort();
}

/** `targetRubyVersion` as RuboCop's configuration writes it: `3.3`, `4` → `4.0`. */
export function normalizeTargetRuby(v: string | number): string {
  return typeof v === 'number' ? v.toFixed(1) : v;
}

/** Whether this CLI runs a RuboCop that reports `version` (the same major.minor as RUBOCOP_VERSION). */
export function rubocopVersionSupported(version: string): boolean {
  const [major, minor] = RUBOCOP_VERSION.split('.');
  const m = /^(\d+)\.(\d+)\.\d+$/.exec(version);
  return m !== null && m[1] === major && m[2] === minor;
}

/** report-format.md §7.1: the security cops whose finding is usually exploitable as it stands. */
const RUBOCOP_HIGH = new Set([
  'Security/Eval',
  'Security/IoMethods',
  'Security/JSONLoad',
  'Security/MarshalLoad',
  'Security/Open',
  'Security/YAMLLoad',
]);
const LOW_DEPARTMENTS = new Set(['Style', 'Layout', 'Naming', 'Gemspec', 'Bundler', 'Migration']);

/** report-format.md §7.1: quality by department; a department RuboCop 1.91 lacks is maintainability. */
export function rubocopQuality(cop: string): Quality {
  const d = departmentOf(cop);
  if (d === 'Security') return 'security';
  if (d === 'Lint') return 'reliability';
  return 'maintainability';
}

/** report-format.md §7.1: severity by department and the high set; never RuboCop's own severity. */
export function rubocopSeverity(cop: string): Severity {
  if (RUBOCOP_HIGH.has(cop)) return 'high';
  return LOW_DEPARTMENTS.has(departmentOf(cop)) ? 'low' : 'medium';
}

/** The cop's page on docs.rubocop.org (anchor: department and cop, lower-cased, letters and digits). */
export function rubocopHelpUri(cop: string): string | null {
  if (!RUBOCOP_COP_NAME.test(cop)) return null;
  const anchor = cop.toLowerCase().replace(/[^a-z0-9]/g, '');
  return `https://docs.rubocop.org/rubocop/latest/cops_${departmentOf(cop).toLowerCase()}.html#${anchor}`;
}
