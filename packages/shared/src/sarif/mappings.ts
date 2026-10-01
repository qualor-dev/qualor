import type { IssueKind, Quality, Severity } from '../report/taxonomy';
import type { EngineMapping } from './normalize';
import type { SarifResult, SarifRule } from './types';
import { phpstanRule } from '../rules/phpstan';
import { rubocopQuality, rubocopSeverity } from '../rules/rubocop';
import { swiftlintQuality, swiftlintSeverity } from '../rules/swiftlint';
import ruffCategories from '../../rules/ruff-categories.json' with { type: 'json' };

function tags(rule: SarifRule | undefined): string[] {
  const t = rule?.properties?.['tags'];
  return Array.isArray(t) ? t.filter((x): x is string => typeof x === 'string') : [];
}

const ESLINT_SECURITY = new Set(['no-eval', 'no-implied-eval', 'no-new-func', 'no-script-url']);
const ESLINT_RELIABILITY = new Set([
  'no-undef',
  'no-unreachable',
  'no-dupe-keys',
  'no-dupe-else-if',
  'no-self-assign',
  'no-constant-condition',
  'no-unsafe-finally',
  'no-unsafe-negation',
  'use-isnan',
  'valid-typeof',
  'no-cond-assign',
  'no-fallthrough',
  'no-func-assign',
  'no-import-assign',
  '@typescript-eslint/no-floating-promises',
  '@typescript-eslint/no-misused-promises',
]);

const eslint: EngineMapping = {
  rule: (r) => ({
    quality:
      r.id.startsWith('security/') || ESLINT_SECURITY.has(r.id)
        ? 'security'
        : ESLINT_RELIABILITY.has(r.id)
          ? 'reliability'
          : 'maintainability',
  }),
};

const PMD_PRIORITY: Readonly<Record<number, Severity>> = {
  1: 'high',
  2: 'medium',
  3: 'medium',
  4: 'low',
  5: 'info',
};
const pmdSeverity = (r: SarifRule | undefined) => PMD_PRIORITY[Number(r?.properties?.['priority'])];

const pmd: EngineMapping = {
  rule: (r) => {
    const ruleset = String(r.properties?.['ruleset'] ?? '');
    const quality: Quality =
      ruleset === 'Security'
        ? 'security'
        : ruleset === 'Error Prone' || ruleset === 'Multithreading'
          ? 'reliability'
          : 'maintainability';
    const defaultSeverity = pmdSeverity(r);
    return { quality, ...(defaultSeverity && { defaultSeverity }) };
  },
  severity: (_result, r) => pmdSeverity(r),
};

const spotbugs: EngineMapping = {
  rule: (r) => {
    const t = tags(r).map((x) => x.toUpperCase());
    const quality: Quality = t.includes('SECURITY')
      ? 'security'
      : t.includes('CORRECTNESS') || t.includes('MT_CORRECTNESS')
        ? 'reliability'
        : 'maintainability';
    return { quality };
  },
  severity: (result) => {
    const rank = Number(result.properties?.['rank']);
    if (!Number.isInteger(rank) || rank < 1) return undefined;
    if (rank <= 4) return 'high';
    if (rank <= 9) return 'medium';
    if (rank <= 14) return 'low';
    return 'info';
  },
};

const isCwe = (t: string) => /^cwe-\d+/i.test(t);

const semgrep: EngineMapping = {
  rule: (r) => {
    const t = tags(r);
    const lower = t.map((x) => x.toLowerCase());
    const quality: Quality =
      lower.includes('security') || t.some(isCwe)
        ? 'security'
        : lower.includes('correctness')
          ? 'reliability'
          : 'maintainability';
    return { quality };
  },
  redactRegion: (r) => tags(r).some((t) => /^cwe-798\b/i.test(t) || /secret/i.test(t)),
};

const gitleaks: EngineMapping = {
  rule: () => ({ quality: 'security', defaultSeverity: 'blocker', kind: 'issue' }),
  severity: () => 'blocker',
  redactRegion: true,
  // Gitleaks puts the secret itself (not the whole match) into region.snippet.text.
  exactSecretText: true,
  // Gitleaks partialFingerprints carry commit author, email, date and message: personal data.
  dropPartialFingerprints: true,
};

/**
 * Trivy's severity (the vendor's rating it selected, else the CVSS score's band; plan 2B ruling
 * O5). UNKNOWN is a vulnerability nobody has rated yet, which is not the same as a harmless one.
 */
const TRIVY_SEVERITY: Readonly<Record<string, Severity>> = {
  CRITICAL: 'blocker',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNKNOWN: 'medium',
};
const trivySeverity = (value: unknown): Severity | undefined =>
  typeof value === 'string' && Object.hasOwn(TRIVY_SEVERITY, value)
    ? TRIVY_SEVERITY[value]
    : undefined;

/** The vulnerable package the CLI's Trivy conversion records on each result (plan 2B). */
function dependencyOf(result: SarifResult): { name: string; version: string } | undefined {
  const d = result.properties?.['dependency'];
  if (typeof d !== 'object' || d === null) return undefined;
  const { name, version } = d as { name?: unknown; version?: unknown };
  return typeof name === 'string' && name !== '' && typeof version === 'string' && version !== ''
    ? { name, version }
    : undefined;
}

const trivy: EngineMapping = {
  rule: (r) => {
    const defaultSeverity = trivySeverity(r.properties?.['trivySeverity']);
    return { quality: 'security', kind: 'issue', ...(defaultSeverity && { defaultSeverity }) };
  },
  severity: (result, r) =>
    trivySeverity(result.properties?.['trivySeverity']) ??
    trivySeverity(r?.properties?.['trivySeverity']),
  identity: (result) => {
    const d = dependencyOf(result);
    return d === undefined ? undefined : `${d.name}@${d.version}`;
  },
};

/**
 * SonarQube's rule category as SonarAnalyzer.CSharp writes it into SARIF (`properties.category`)
 * and the sonarjs runner copies it (report-format.md §7.1): "<Severity> <Type>".
 */
const SONAR_SEVERITY: Record<string, Severity> = {
  Blocker: 'blocker',
  Critical: 'high',
  Major: 'medium',
  Minor: 'low',
  Info: 'info',
};
const SONAR_TYPE: Record<string, { quality: Quality; kind: IssueKind }> = {
  Bug: { quality: 'reliability', kind: 'issue' },
  Vulnerability: { quality: 'security', kind: 'issue' },
  'Security Hotspot': { quality: 'security', kind: 'hotspot' },
  'Code Smell': { quality: 'maintainability', kind: 'issue' },
};
const SONAR_CATEGORY =
  /^(Blocker|Critical|Major|Minor|Info) (Bug|Vulnerability|Security Hotspot|Code Smell)$/;

export function sonarCategory(
  category: string,
): { quality: Quality; kind: IssueKind; defaultSeverity: Severity } | null {
  const m = SONAR_CATEGORY.exec(category);
  if (m === null) return null;
  // The regex's two groups are mandatory (no `?`), so a match always captures both; the lookups
  // below are total for any string the alternation can produce. `noUncheckedIndexedAccess` still
  // types them `| undefined` because it does not know that, so the checks stay to avoid `!`.
  const severity = SONAR_SEVERITY[m[1] ?? ''];
  const type = SONAR_TYPE[m[2] ?? ''];
  if (severity === undefined || type === undefined) return null;
  return { ...type, defaultSeverity: severity };
}

/** Roslyn rule categories (`properties.category`, plan 2D probe P5) that are about correctness. */
const ROSLYN_RELIABILITY = new Set(['reliability', 'usage']);

const roslyn: EngineMapping = {
  rule: (r) => {
    const raw = String(r.properties?.['category'] ?? '');
    const sonar = sonarCategory(raw);
    if (sonar !== null) return sonar;
    const category = raw.toLowerCase();
    const quality: Quality =
      category === 'security'
        ? 'security'
        : ROSLYN_RELIABILITY.has(category)
          ? 'reliability'
          : 'maintainability';
    return { quality, kind: 'issue' };
  },
  severity: (_result, rule) =>
    sonarCategory(String(rule?.properties?.['category'] ?? ''))?.defaultSeverity,
};

/**
 * SonarQube-compatible JS/TS rules (eslint-plugin-sonarjs 2.0.4, LGPL-3.0, config.md §6). Every
 * rule the pass reports carries a SonarQube category from its own `categories.json`; without one
 * (should not happen for a bundled rule) it defaults like ESLint's own default.
 */
const sonarjs: EngineMapping = {
  rule: (r) =>
    sonarCategory(String(r.properties?.['category'] ?? '')) ?? {
      quality: 'maintainability',
      kind: 'issue',
    },
  severity: (_result, rule) =>
    sonarCategory(String(rule?.properties?.['category'] ?? ''))?.defaultSeverity,
};

/** Ruff's own rule category per code (tools/analyzers/ruff-keys.ts, the pinned Ruff). */
const RUFF_CATEGORY: Readonly<Record<string, string>> = ruffCategories;
/** report-format.md §7.1: the security rules whose finding is usually exploitable as it stands. */
const RUFF_HIGH = new Set([
  'S102',
  'S202',
  'S301',
  'S302',
  'S307',
  'S323',
  'S501',
  'S506',
  'S602',
  'S604',
  'S605',
  'S608',
  'S610',
  'S611',
  'S701',
  'S702',
  'S704',
]);

/** report-format.md §7.1: quality and severity from Ruff's category; always an issue. */
export function ruffRule(code: string): {
  quality: Quality;
  kind: IssueKind;
  defaultSeverity: Severity;
} {
  const category = Object.hasOwn(RUFF_CATEGORY, code) ? RUFF_CATEGORY[code] : undefined;
  switch (category) {
    case 'security':
      return {
        quality: 'security',
        kind: 'issue',
        defaultSeverity: RUFF_HIGH.has(code) ? 'high' : 'medium',
      };
    case 'correctness':
    case 'suspicious':
      return { quality: 'reliability', kind: 'issue', defaultSeverity: 'medium' };
    case 'style':
    case 'pedantic':
    case 'restriction':
    case 'formatting':
      return { quality: 'maintainability', kind: 'issue', defaultSeverity: 'low' };
    default:
      // complexity, performance, and a code this table does not know.
      return { quality: 'maintainability', kind: 'issue', defaultSeverity: 'medium' };
  }
}

/** Ruff (plan 8C): its SARIF `level` is always `error`, so the rule decides the severity. */
const ruff: EngineMapping = {
  rule: (r) => ruffRule(r.id),
  severity: (result, rule) => ruffRule(rule?.id ?? result.ruleId ?? '').defaultSeverity,
};

/**
 * stylelint (config.md §6, plan 8D). Qualor's pass marks each rule `possible-error` (it is in
 * stylelint-config-recommended or stylelint-config-recommended-scss, the "avoid errors" sets) or
 * `convention`. The category decides quality and severity; the configured `error`/`warning`
 * does not (stylelint configs set every rule to `error`).
 */
const STYLELINT_CATEGORIES: ReadonlyMap<string, { quality: Quality; defaultSeverity: Severity }> =
  new Map([
    ['possible-error', { quality: 'reliability', defaultSeverity: 'medium' }],
    ['convention', { quality: 'maintainability', defaultSeverity: 'low' }],
  ]);
const STYLELINT_CONVENTION = { quality: 'maintainability', defaultSeverity: 'low' } as const;
function stylelintMeta(rule: SarifRule | undefined): {
  quality: Quality;
  defaultSeverity: Severity;
} {
  return (
    STYLELINT_CATEGORIES.get(String(rule?.properties?.['category'] ?? '')) ?? STYLELINT_CONVENTION
  );
}
const stylelint: EngineMapping = {
  rule: (r) => ({ ...stylelintMeta(r), kind: 'issue' }),
  severity: (_result, r) => stylelintMeta(r).defaultSeverity,
};

/** HTMLHint (plan 8D): rule ids that are markup errors, and those about accessibility. */
const HTMLHINT_RELIABILITY = new Set([
  'tag-pair',
  'attr-no-duplication',
  'id-unique',
  'src-not-empty',
  'attr-unsafe-chars',
  'attr-value-no-duplication',
  'tags-check',
  'spec-char-escape',
  'empty-tag-not-self-closed',
  'tagname-specialchars',
]);
const HTMLHINT_ACCESSIBILITY = new Set([
  'alt-require',
  'frame-title-require',
  'html-lang-require',
  'input-requires-label',
]);
function htmlhintMeta(id: string): { quality: Quality; defaultSeverity: Severity } {
  if (HTMLHINT_RELIABILITY.has(id)) return { quality: 'reliability', defaultSeverity: 'medium' };
  if (HTMLHINT_ACCESSIBILITY.has(id))
    return { quality: 'maintainability', defaultSeverity: 'medium' };
  return { quality: 'maintainability', defaultSeverity: 'low' };
}
const htmlhint: EngineMapping = {
  rule: (r) => ({ ...htmlhintMeta(r.id), kind: 'issue' }),
  severity: (result, r) => htmlhintMeta(r?.id ?? result.ruleId ?? '').defaultSeverity,
};

/**
 * detekt (Kotlin, config.md §6): the CLI's transform (cli/src/analyzers/detekt-sarif.ts) puts each
 * rule's rule set into `properties.ruleset`. Rule sets about wrong or fragile behaviour are
 * reliability, the rest maintainability; detekt 1.23 has no security rule set.
 */
const DETEKT_RELIABILITY = new Set(['potential-bugs', 'coroutines', 'exceptions']);
const DETEKT_LOW = new Set(['style', 'naming', 'comments']);
const detektRuleset = (r: SarifRule | undefined): string =>
  String(r?.properties?.['ruleset'] ?? '');
const detektDefaultSeverity = (r: SarifRule | undefined): Severity =>
  DETEKT_LOW.has(detektRuleset(r)) ? 'low' : 'medium';

const detekt: EngineMapping = {
  rule: (r) => ({
    quality: DETEKT_RELIABILITY.has(detektRuleset(r)) ? 'reliability' : 'maintainability',
    defaultSeverity: detektDefaultSeverity(r),
  }),
  // A project's own `severity: error | info` arrives as SARIF level error / note; detekt's own
  // default is warning, which takes the rule set's default instead of a flat medium.
  severity: (result, r) =>
    result.level === 'error'
      ? 'high'
      : result.level === 'note'
        ? 'low'
        : result.level === 'none'
          ? 'info'
          : detektDefaultSeverity(r),
};

/**
 * SwiftLint (Swift, plan 8F, report-format.md §7.1): quality and severity from the rule's SwiftLint
 * kind (swiftlint-rules.json), not only from its configured warning/error.
 */
const swiftlint: EngineMapping = {
  rule: (r) => ({
    quality: swiftlintQuality(r.id),
    kind: 'issue',
    defaultSeverity: swiftlintSeverity(r.id, 'warning'),
  }),
  severity: (result, rule) =>
    swiftlintSeverity(result.ruleId ?? rule?.id ?? '', result.level ?? 'warning'),
};

/** PHPStan (plan 9A): every converted result is a `warning`; the identifier decides (§7.1). */
const phpstan: EngineMapping = {
  rule: (r) => phpstanRule(r.id),
  severity: (result, rule) => phpstanRule(rule?.id ?? result.ruleId ?? '').defaultSeverity,
};

/**
 * RuboCop (Ruby, plan 9B, report-format.md §7.1): quality and severity from the cop's department
 * (and the high set), never from RuboCop's own offense severity.
 */
const rubocop: EngineMapping = {
  rule: (r) => ({
    quality: rubocopQuality(r.id),
    kind: 'issue',
    defaultSeverity: rubocopSeverity(r.id),
  }),
  severity: (result, rule) => rubocopSeverity(result.ruleId ?? rule?.id ?? ''),
};

export const ENGINE_MAPPINGS = {
  eslint,
  pmd,
  spotbugs,
  semgrep,
  gitleaks,
  trivy,
  roslyn,
  sonarjs,
  ruff,
  stylelint,
  htmlhint,
  detekt,
  swiftlint,
  phpstan,
  rubocop,
} as const satisfies Record<string, EngineMapping>;

export function engineMapping(engineId: string): EngineMapping | undefined {
  return Object.hasOwn(ENGINE_MAPPINGS, engineId)
    ? ENGINE_MAPPINGS[engineId as keyof typeof ENGINE_MAPPINGS]
    : undefined;
}
