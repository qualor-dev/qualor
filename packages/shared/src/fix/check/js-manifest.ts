/**
 * B1 for JS manifests (spec §12): a fix may change the version spec of the package where a
 * dependency section already names it, and add or change the package's pin in an override
 * mechanism (`overrides`, `pnpm.overrides`, `resolutions`, `pnpm-workspace.yaml` `overrides`).
 * Removing every allowed difference from the uploaded file must leave the base file.
 */
import { validRange } from 'semver';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type FixRule,
} from './types';
import {
  at,
  isObject,
  own,
  parseYaml,
  sameValue,
  setOwn,
  stripBom,
  type JsonObject,
} from './values';

const DEPENDENCY_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

/** Where `package.json` pins a package: npm, pnpm, and Yarn (classic and Berry). */
const PACKAGE_JSON_PINS: readonly (readonly string[])[] = [
  ['overrides'],
  ['pnpm', 'overrides'],
  ['resolutions'],
];

/** A package name, scoped or not, as a selector's parent names it. */
const PACKAGE_NAME = /^(?:@[\w.~-]+\/)?[\w.~-]+$/;

function isRange(text: string): boolean {
  return text.trim() !== '' && validRange(text) !== null;
}

/**
 * A plain version or version range (`semver.validRange`): no URL, `file:`, `link:`, git,
 * `github:`, `workspace:`, `catalog:`, `npm:` alias, dist-tag or `$` reference.
 */
export function isPlainSpec(value: unknown): boolean {
  return typeof value === 'string' && isRange(value);
}

/** `<name>` or `<name>@<range>`, the parent of a pnpm `<parent>><pkg>` selector. */
function isParentSelector(parent: string): boolean {
  const atSign = parent.indexOf('@', 1);
  if (atSign < 0) return PACKAGE_NAME.test(parent);
  return PACKAGE_NAME.test(parent.slice(0, atSign)) && isRange(parent.slice(atSign + 1));
}

/**
 * Whether an override key pins the package: `<pkg>`, `<pkg>@<range>`, `<pkg>@npm:<range>`,
 * `**\/<pkg>` or `<parent>><pkg>`.
 */
export function pinsPackage(selector: string, packageName: string): boolean {
  if (selector === packageName || selector === `**/${packageName}`) return true;
  if (selector.startsWith(`${packageName}@`)) {
    const range = selector.slice(packageName.length + 1);
    return isRange(range.startsWith('npm:') ? range.slice('npm:'.length) : range);
  }
  return (
    selector.endsWith(`>${packageName}`) &&
    isParentSelector(selector.slice(0, -packageName.length - 1))
  );
}

/**
 * One dependency section: a key the base section lacks is `new_dependency` (`other_change` when it
 * is the package itself, which only overrides may add); a changed spec of the package must be
 * plain and is put back to the base's, so the final comparison ignores it.
 */
function dependencySectionRule(
  base: JsonObject,
  next: JsonObject,
  section: string,
  packageName: string,
): FixRule | null {
  const deps = own(next, section);
  if (!isObject(deps)) return null;
  const baseValue = own(base, section);
  const baseDeps = isObject(baseValue) ? baseValue : {};
  const added = Object.keys(deps).filter((name) => !Object.hasOwn(baseDeps, name));
  if (added.some((name) => name !== packageName)) return 'new_dependency';
  if (added.length > 0) return 'other_change';
  const spec = own(deps, packageName);
  if (spec === undefined || sameValue(spec, own(baseDeps, packageName))) return null;
  if (!isPlainSpec(spec)) return 'bad_spec';
  setOwn(deps, packageName, own(baseDeps, packageName));
  return null;
}

function isPinChange(
  pins: JsonObject,
  basePins: JsonObject | null,
  selector: string,
  packageName: string,
): boolean {
  if (!pinsPackage(selector, packageName)) return false;
  if (basePins === null || !Object.hasOwn(basePins, selector)) return true;
  return !sameValue(pins[selector], basePins[selector]);
}

/** Puts one pin back to the base's, or removes it when the base has none. */
function restorePin(pins: JsonObject, basePins: JsonObject | null, selector: string): void {
  if (basePins !== null && Object.hasOwn(basePins, selector)) {
    setOwn(pins, selector, basePins[selector]);
  } else {
    Reflect.deleteProperty(pins, selector);
  }
}

/** Drops the containers the change created for its pins alone (`pnpm: { overrides: {} }`). */
function pruneCreated(base: JsonObject, next: JsonObject, path: readonly string[]): void {
  for (let depth = path.length; depth > 0; depth--) {
    const prefix = path.slice(0, depth);
    const container = at(next, prefix);
    const created = at(base, prefix) === undefined && isObject(container);
    if (!created || Object.keys(container).length > 0) return;
    const parent = at(next, prefix.slice(0, -1));
    if (isObject(parent)) Reflect.deleteProperty(parent, prefix[depth - 1] ?? '');
  }
}

/**
 * One override container: each added or changed pin of the package must be plain (`bad_spec`) and
 * is taken back out, so the final comparison ignores it. Other keys are left for that comparison.
 */
function pinContainerRule(
  base: JsonObject,
  next: JsonObject,
  path: readonly string[],
  packageName: string,
): FixRule | null {
  const pins = at(next, path);
  if (!isObject(pins)) return null;
  const baseValue = at(base, path);
  const basePins = isObject(baseValue) ? baseValue : null;
  const changed = Object.keys(pins).filter((s) => isPinChange(pins, basePins, s, packageName));
  if (changed.some((selector) => !isPlainSpec(pins[selector]))) return 'bad_spec';
  for (const selector of changed) restorePin(pins, basePins, selector);
  if (changed.length > 0) pruneCreated(base, next, path);
  return null;
}

function packageJsonRule(base: JsonObject, next: JsonObject, packageName: string): FixRule | null {
  for (const section of DEPENDENCY_SECTIONS) {
    const rule = dependencySectionRule(base, next, section, packageName);
    if (rule !== null) return rule;
  }
  for (const path of PACKAGE_JSON_PINS) {
    const rule = pinContainerRule(base, next, path, packageName);
    if (rule !== null) return rule;
  }
  return sameValue(base, next) ? null : 'other_change';
}

function parseJsonObject(text: string): JsonObject | null {
  try {
    const value: unknown = JSON.parse(stripBom(text));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

function result(rule: FixRule | null, path: string): FixCheckResult {
  return rule === null ? FIX_CHECK_OK : fixRefused(rule, path);
}

/**
 * B1 for `package.json`: allowed are a changed spec of the package where a dependency section
 * already has it, and an added or changed pin of the package under `overrides`, `pnpm.overrides`
 * or `resolutions` (containers may be created). Every changed or added value must be plain
 * (`bad_spec`); a new dependency is `new_dependency`; anything else is `other_change`.
 */
export function checkPackageJson(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const base = parseJsonObject(change.base);
  const next = parseJsonObject(change.next);
  if (base === null || next === null) return fixRefused('unparsable', change.path);
  return result(packageJsonRule(base, next, ctx.packageName), change.path);
}

/** A YAML mapping; an empty document is an empty mapping; null for anything else or an error. */
function parseYamlObject(text: string): JsonObject | null {
  try {
    const value = parseYaml(text, { merge: true });
    if (value === null || value === undefined) return {};
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

/** B1 for `pnpm-workspace.yaml`: only the package's pin under `overrides` may be added or changed. */
export function checkPnpmWorkspace(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const base = parseYamlObject(change.base);
  const next = parseYamlObject(change.next);
  if (base === null || next === null) return fixRefused('unparsable', change.path);
  const rule = pinContainerRule(base, next, ['overrides'], ctx.packageName);
  return result(rule ?? (sameValue(base, next) ? null : 'other_change'), change.path);
}
