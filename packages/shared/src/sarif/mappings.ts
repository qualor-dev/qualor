import type { IssueKind, Quality, Severity } from '../report/taxonomy';
import type { EngineMapping } from './normalize';
import type { SarifResult, SarifRule } from './types';

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

export const ENGINE_MAPPINGS = {
  eslint,
  pmd,
  spotbugs,
  semgrep,
  gitleaks,
  trivy,
  roslyn,
  sonarjs,
} as const satisfies Record<string, EngineMapping>;

export function engineMapping(engineId: string): EngineMapping | undefined {
  return Object.hasOwn(ENGINE_MAPPINGS, engineId)
    ? ENGINE_MAPPINGS[engineId as keyof typeof ENGINE_MAPPINGS]
    : undefined;
}
