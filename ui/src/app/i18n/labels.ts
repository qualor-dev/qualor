/**
 * Display labels for the API's enum values (brief §7: every user-facing string goes through
 * i18n). Each label is a `$localize` message with a stable custom id, extracted with the template
 * messages by `pnpm --filter @qualor/ui i18n:extract`. An unknown value (a newer server) falls
 * back to the raw value, which is better than an empty cell.
 */
export type LabelKind =
  | 'severity'
  | 'quality'
  | 'kind'
  | 'status'
  | 'gate'
  | 'transition'
  | 'language'
  | 'metric'
  | 'role'
  | 'gateWarning'
  | 'auditOutcome'
  | 'auditActor'
  | 'auditBreak'
  | 'ssoProtocol';

const LABELS: Record<LabelKind, Record<string, string>> = {
  severity: {
    blocker: $localize`:@@label.severity.blocker:Blocker`,
    high: $localize`:@@label.severity.high:High`,
    medium: $localize`:@@label.severity.medium:Medium`,
    low: $localize`:@@label.severity.low:Low`,
    info: $localize`:@@label.severity.info:Info`,
  },
  quality: {
    security: $localize`:@@label.quality.security:Security`,
    reliability: $localize`:@@label.quality.reliability:Reliability`,
    maintainability: $localize`:@@label.quality.maintainability:Maintainability`,
  },
  kind: {
    issue: $localize`:@@label.kind.issue:Issue`,
    hotspot: $localize`:@@label.kind.hotspot:Security hotspot`,
  },
  status: {
    open: $localize`:@@label.status.open:Open`,
    resolved: $localize`:@@label.status.resolved:Resolved`,
    wont_fix: $localize`:@@label.status.wontFix:Won't fix`,
    false_positive: $localize`:@@label.status.falsePositive:False positive`,
    closed: $localize`:@@label.status.closed:Closed`,
  },
  gate: {
    passed: $localize`:@@label.gate.passed:Passed`,
    failed: $localize`:@@label.gate.failed:Failed`,
    error: $localize`:@@label.gate.error:Error`,
    none: $localize`:@@label.gate.none:No gate`,
  },
  transition: {
    open: $localize`:@@label.transition.open:Reopen`,
    resolved: $localize`:@@label.transition.resolved:Resolve`,
    wont_fix: $localize`:@@label.transition.wontFix:Won't fix`,
    false_positive: $localize`:@@label.transition.falsePositive:False positive`,
  },
  language: {
    typescript: $localize`:@@label.language.typescript:TypeScript`,
    javascript: $localize`:@@label.language.javascript:JavaScript`,
    java: $localize`:@@label.language.java:Java`,
    csharp: $localize`:@@label.language.csharp:C#`,
    python: $localize`:@@label.language.python:Python`,
    html: $localize`:@@label.language.html:HTML`,
    css: $localize`:@@label.language.css:CSS`,
    kotlin: $localize`:@@label.language.kotlin:Kotlin`,
    swift: $localize`:@@label.language.swift:Swift`,
    php: $localize`:@@label.language.php:PHP`,
    ruby: $localize`:@@label.language.ruby:Ruby`,
    go: $localize`:@@label.language.go:Go`,
    '*': $localize`:@@label.language.any:Other engines`,
  },
  /** The `warnings` of a gate result (gates.md §5, §6; server gates/stage.ts, shared evaluate.ts). */
  gateWarning: {
    NEW_CODE_DEFINITION_FALLBACK: $localize`:@@gateWarning.definitionFallback:No earlier version was found for the new-code baseline; the last 30 days are new code instead.`,
    NEW_CODE_BASELINE_MISSING: $localize`:@@gateWarning.baselineMissing:The fixed new-code baseline no longer exists; the last 30 days are new code instead.`,
    BASELINE_ENDPOINT_UNAVAILABLE: $localize`:@@gateWarning.baselineEndpoint:The scanner could not ask the server for the new-code baseline.`,
    NEW_CODE_UNAVAILABLE: $localize`:@@gateWarning.newCodeUnavailable:New code could not be determined, so conditions on new code were not checked. Fetch the full history in CI (for example GIT_DEPTH: 0) or allow the baseline fetch.`,
    GATE_CONDITION_UNKNOWN_METRIC: $localize`:@@gateWarning.unknownMetric:A gate condition uses a metric this server no longer knows; it was skipped.`,
  },
  /** Organisation and project roles, the same in every edition (rbac-audit.md §17). */
  role: {
    admin: $localize`:@@label.role.admin:Organization admin`,
    project_admin: $localize`:@@label.role.projectAdmin:Project admin`,
    member: $localize`:@@label.role.member:Maintainer`,
    viewer: $localize`:@@label.role.viewer:Viewer`,
  },
  /** An audit event's outcome (rbac-audit.md §8). */
  auditOutcome: {
    success: $localize`:@@label.auditOutcome.success:Succeeded`,
    failure: $localize`:@@label.auditOutcome.failure:Failed`,
  },
  /** Who acted, when it was not a signed-in user (rbac-audit.md §9). */
  auditActor: {
    anonymous: $localize`:@@label.auditActor.anonymous:Not signed in`,
    system: $localize`:@@label.auditActor.system:Qualor`,
  },
  /** Why a verification of the audit chain failed (rbac-audit.md §10.3). */
  auditBreak: {
    hash_mismatch: $localize`:@@label.auditBreak.hashMismatch:the event was changed after it was recorded (its hash does not match)`,
    prev_mismatch: $localize`:@@label.auditBreak.prevMismatch:the event does not follow the one before it (its previous hash does not match)`,
    gap: $localize`:@@label.auditBreak.gap:an event before it is missing`,
    anchor_mismatch: $localize`:@@label.auditBreak.anchorMismatch:the oldest event does not continue from the retention anchor`,
  },
  /** The protocol of a single sign-on connection (sso-scim.md §4). */
  ssoProtocol: {
    oidc: $localize`:@@label.ssoProtocol.oidc:OpenID Connect`,
    saml: $localize`:@@label.ssoProtocol.saml:SAML`,
  },
  metric: {
    files: $localize`:@@metric.files:Files`,
    lines: $localize`:@@metric.lines:Lines`,
    ncloc: $localize`:@@metric.ncloc:Lines of code`,
    comment_lines: $localize`:@@metric.commentLines:Comment lines`,
    functions: $localize`:@@metric.functions:Functions`,
    classes: $localize`:@@metric.classes:Classes`,
    statements: $localize`:@@metric.statements:Statements`,
    complexity: $localize`:@@metric.complexity:Cyclomatic complexity`,
    cognitive_complexity: $localize`:@@metric.cognitiveComplexity:Cognitive complexity`,
    issues: $localize`:@@metric.issues:Issues`,
    blocker_issues: $localize`:@@metric.blockerIssues:Blocker issues`,
    high_issues: $localize`:@@metric.highIssues:High issues`,
    medium_issues: $localize`:@@metric.mediumIssues:Medium issues`,
    low_issues: $localize`:@@metric.lowIssues:Low issues`,
    info_issues: $localize`:@@metric.infoIssues:Info issues`,
    security_issues: $localize`:@@metric.securityIssues:Security issues`,
    reliability_issues: $localize`:@@metric.reliabilityIssues:Reliability issues`,
    maintainability_issues: $localize`:@@metric.maintainabilityIssues:Maintainability issues`,
    accepted_issues: $localize`:@@metric.acceptedIssues:Won't fix issues`,
    false_positive_issues: $localize`:@@metric.falsePositiveIssues:False positive issues`,
    security_rating: $localize`:@@metric.securityRating:Security rating`,
    reliability_rating: $localize`:@@metric.reliabilityRating:Reliability rating`,
    lines_to_cover: $localize`:@@metric.linesToCover:Lines to cover`,
    uncovered_lines: $localize`:@@metric.uncoveredLines:Uncovered lines`,
    conditions_to_cover: $localize`:@@metric.conditionsToCover:Conditions to cover`,
    uncovered_conditions: $localize`:@@metric.uncoveredConditions:Uncovered conditions`,
    line_coverage: $localize`:@@metric.lineCoverage:Line coverage`,
    branch_coverage: $localize`:@@metric.branchCoverage:Condition coverage`,
    coverage: $localize`:@@metric.coverage:Coverage`,
    duplicated_lines: $localize`:@@metric.duplicatedLines:Duplicated lines`,
    duplicated_blocks: $localize`:@@metric.duplicatedBlocks:Duplicated blocks`,
    duplicated_lines_density: $localize`:@@metric.duplicatedLinesDensity:Duplicated lines (%)`,
  },
};

/** `new_coverage` → "Coverage on new code"; any other key → its label. */
export function label(kind: LabelKind, value: string | null | undefined): string {
  if (value === null || value === undefined) return '';
  if (kind === 'metric' && value.startsWith('new_')) {
    const base = LABELS.metric[value.slice(4)] ?? value.slice(4);
    return $localize`:@@metric.onNewCode:${base}:metric: on new code`;
  }
  return LABELS[kind][value] ?? value;
}
