export const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const QUALITIES = ['security', 'reliability', 'maintainability'] as const;
export type Quality = (typeof QUALITIES)[number];

export const ISSUE_KINDS = ['issue', 'hotspot'] as const;
export type IssueKind = (typeof ISSUE_KINDS)[number];

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
  'go',
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
  'staticcheck',
  'govet',
  'gosec',
] as const;
export type BuiltinEngine = (typeof BUILTIN_ENGINES)[number];

export const ENGINE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;
