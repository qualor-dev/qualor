/**
 * Ruff (plan 8C, config.md §3, §6). `RUFF_VERSION` is the Ruff the qualor/scanner image ships
 * (tools/analyzers/install.sh RUFF_VERSION; tools/ci.test.ts checks they agree). The CLI runs only
 * a Ruff of the same major.minor, because the generated rule tables (ruff-keys.json,
 * ruff-default-keys.json, ruff-categories.json) describe that version.
 */
export const RUFF_VERSION = '0.16.9';

/** A Ruff rule selector: a linter prefix or a rule code (`F`, `E4`, `PLE`, `S608`, `ASYNC100`, `ALL`). */
export const RUFF_SELECTOR = /^[A-Z]{1,5}[0-9]{0,4}$/;

/** `qualor-default`: Ruff's own defaults, flake8-bugbear, Pylint errors, flake8-bandit's security rules. */
export const RUFF_DEFAULT_SELECT: readonly string[] = ['E4', 'E7', 'E9', 'F', 'B', 'PLE', 'S'];

/**
 * What qualor-default leaves out (config.md §6): assert (S101), rules not about security (S110,
 * S112), rules that flag nearly every use of `random` or `subprocess` (S311, S603, S606, S607),
 * and bugbear rules that are noisy in common frameworks (B008, B904, B905).
 */
export const RUFF_DEFAULT_IGNORE: readonly string[] = [
  'S101',
  'S110',
  'S112',
  'S311',
  'S603',
  'S606',
  'S607',
  'B008',
  'B904',
  'B905',
];

export interface RuffSelection {
  select: string[];
  ignore: string[];
}

/**
 * The `--select` and `--ignore` lists for `analyzers.ruff`. qualor-default's own ignores apply
 * only with qualor-default, and never to a code the project selects by name: Ruff lets an ignore
 * of the same specificity win, so `select: [qualor-default, S311]` would otherwise still drop
 * S311.
 */
export function ruffSelection(select: readonly string[], ignore: readonly string[]): RuffSelection {
  const withDefault = select.includes('qualor-default');
  const explicit = select.filter((s) => s !== 'qualor-default');
  const defaultIgnore = withDefault
    ? RUFF_DEFAULT_IGNORE.filter((code) => !explicit.includes(code))
    : [];
  return {
    select: [...new Set([...(withDefault ? RUFF_DEFAULT_SELECT : []), ...explicit])],
    ignore: [...new Set([...defaultIgnore, ...ignore])],
  };
}

/** Whether this CLI runs a Ruff that reports `version` (the same major.minor as RUFF_VERSION). */
export function ruffVersionSupported(version: string): boolean {
  const [major, minor] = RUFF_VERSION.split('.');
  const m = /^(\d+)\.(\d+)\.\d+/.exec(version);
  return m !== null && m[1] === major && m[2] === minor;
}
