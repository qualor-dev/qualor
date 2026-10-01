import type { IssueKind, Quality, Severity } from '../report/taxonomy';

/**
 * PHPStan (plan 9A, config.md §3, §6). `PHPSTAN_VERSION` is the PHPStan the qualor/scanner image
 * ships (tools/analyzers/install.sh PHPSTAN_VERSION; tools/ci.test.ts checks they agree). The CLI
 * runs only a PHPStan of the same major.minor.
 */
export const PHPSTAN_VERSION = '2.2.16';

/**
 * The `phpVersion` Qualor analyses for (PHP 8.5; PHPStan 2.2 accepts 70100-80699). Without it,
 * PHPStan parses with the grammar of the PHP that runs it, so the image's PHP 8.2 would turn every
 * PHP 8.4 file into parse errors.
 */
export const PHPSTAN_PHP_VERSION = 80599;

/** `analyzers.phpstan.level`'s default (plan 9A decision 1, measured on six projects). */
export const PHPSTAN_DEFAULT_LEVEL = 2;

/**
 * Unknown symbols (config.md §6): whether a class, function, method or property is known depends
 * on what the job installed and on framework magic PHPStan only understands through extensions,
 * which Qualor never loads. They are dropped from every run. `argument.unknown` (an unknown named
 * argument) is the same question about a function or method PHPStan cannot see.
 */
export const PHPSTAN_UNKNOWN_SYMBOL_IDS: ReadonlySet<string> = new Set([
  'argument.unknown',
  'attribute.notFound',
  'class.notFound',
  'classConstant.notFound',
  'constant.notFound',
  'function.notFound',
  'interface.notFound',
  'method.notFound',
  'property.notFound',
  'staticMethod.notFound',
  'staticProperty.notFound',
  'trait.notFound',
]);

/** Artefacts of a parent class PHPStan cannot see, dropped when it ran without dependencies. */
export const PHPSTAN_NO_DEPENDENCY_IDS: ReadonlySet<string> = new Set([
  'class.noParent',
  'new.noConstructor',
]);

/** Messages that are not findings: a file PHPStan cannot parse, and ignore-comment bookkeeping. */
export function phpstanNotFinding(identifier: string): boolean {
  return identifier === 'phpstan.parse' || identifier.startsWith('ignore.');
}

/** Whether this CLI runs a PHPStan that reports `version` (the same major.minor as PHPSTAN_VERSION). */
export function phpstanVersionSupported(version: string): boolean {
  const [major, minor] = PHPSTAN_VERSION.split('.');
  const m = /^(\d+)\.(\d+)\.\d+$/.exec(version);
  return m !== null && m[1] === major && m[2] === minor;
}

const MAINTAINABILITY_PREFIXES = [
  'phpDoc.',
  'varTag.',
  'missingType.',
  'generics.',
  'typeAlias.',
  'methodTag.',
  'propertyTag.',
  'mixinTag.',
];
const MAINTAINABILITY_SUFFIXES = [
  '.unused',
  '.unusedType',
  '.unusedParameter',
  '.onlyWritten',
  '.onlyRead',
  '.alreadyNarrowedType',
  '.phpDocType',
  '.unresolvableType',
];

/**
 * report-format.md §7.1: PHPDoc, unused-code and redundancy identifiers are maintainability/low;
 * every other identifier (a wrong call, an undefined variable, an impossible type) is
 * reliability/medium. Always an issue.
 */
export function phpstanRule(identifier: string): {
  quality: Quality;
  kind: IssueKind;
  defaultSeverity: Severity;
} {
  const maintainability =
    identifier === 'new.static' ||
    MAINTAINABILITY_PREFIXES.some((p) => identifier.startsWith(p)) ||
    MAINTAINABILITY_SUFFIXES.some((s) => identifier.endsWith(s));
  return maintainability
    ? { quality: 'maintainability', kind: 'issue', defaultSeverity: 'low' }
    : { quality: 'reliability', kind: 'issue', defaultSeverity: 'medium' };
}
