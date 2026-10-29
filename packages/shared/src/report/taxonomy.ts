export const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * The qualities a report or SARIF input may declare (report-format.md §5). `licensing` is not one:
 * only the server makes licence issues (6M), and an older server receiving a newer scanner's report
 * must never see it.
 */
export const REPORT_QUALITIES = ['security', 'reliability', 'maintainability'] as const;
export type ReportQuality = (typeof REPORT_QUALITIES)[number];

/** Every quality of the server's issues and rules, its API filters and the UI. */
export const QUALITIES = [...REPORT_QUALITIES, 'licensing'] as const;
export type Quality = (typeof QUALITIES)[number];

export const ISSUE_KINDS = ['issue', 'hotspot'] as const;
export type IssueKind = (typeof ISSUE_KINDS)[number];

/**
 * Which files a rule reports on (0.13): `main` code only, `test` code only, or `all` (the default of
 * a rule that declares none), as SonarQube's rule scope.
 */
export const RULE_SCOPES = ['main', 'test', 'all'] as const;
export type RuleScope = (typeof RULE_SCOPES)[number];

/** The rule scope `value` names, or undefined when it is none. */
export function ruleScopeOf(value: unknown): RuleScope | undefined {
  return RULE_SCOPES.find((s) => s === value);
}

/**
 * A finding's confidence, set by Qualor's C# taint engine only (`result.properties.confidence` of its SARIF): `medium`
 * when the path it reports goes through the heap, a lookup by a request key or a fallback edge, shown as "possible";
 * `high` otherwise. Every other analyzer, and the OpenGrep rules, set none.
 */
export const CONFIDENCES = ['high', 'medium'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

/**
 * The confidence of a finding: its `properties.confidence` when the finding is Qualor's own (engine `qualor`) and the
 * value is one of CONFIDENCES; otherwise none (another tool's SARIF may use the same property name with other values).
 */
export function findingConfidence(finding: {
  engineId: string;
  properties?: Record<string, unknown> | undefined;
}): Confidence | undefined {
  if (finding.engineId !== 'qualor') return undefined;
  const value = finding.properties?.['confidence'];
  return (CONFIDENCES as readonly unknown[]).includes(value) ? (value as Confidence) : undefined;
}

export const LANGUAGES = [
  'typescript',
  'javascript',
  'java',
  'csharp',
  'python',
  'html',
  'css',
  'kotlin',
  'swift',
  'php',
  'ruby',
  'go',
  'c',
  'cpp',
  'other',
] as const;
export type Language = (typeof LANGUAGES)[number];

export const BUILTIN_ENGINES = [
  'eslint',
  'sonarjs',
  'ruff',
  'pmd',
  'spotbugs',
  'semgrep',
  'gitleaks',
  'trivy',
  'roslyn',
  'stylelint',
  'htmlhint',
  'detekt',
  'swiftlint',
  'phpstan',
  'rubocop',
  'staticcheck',
  'govet',
  'gosec',
  'cppcheck',
  'clang-tidy',
  'qualor',
  // 6M §6: the server's licence policy findings. Reserved: no report engine may take the id.
  'license',
  // 6M §1: the CLI's licence pass. Reserved: an external engine of that id with a status other
  // than ok would stop the server's licence stage on every analysis.
  'trivy-licenses',
  // 6I-3: the findings of the server's AI review. Reserved: no report engine may take the id.
  'ai',
] as const;
export type BuiltinEngine = (typeof BUILTIN_ENGINES)[number];

export const ENGINE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;
