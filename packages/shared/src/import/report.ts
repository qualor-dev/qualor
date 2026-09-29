import { z } from 'zod';

export const IMPORT_WARNING_CODES = [
  'SONARQUBE_ISSUE_WINDOW',
  'SONARQUBE_RULE_WINDOW',
  'SONARQUBE_ACTIVATION_MISSING',
  'SONARQUBE_PROJECT_WINDOW',
  'SONARQUBE_RESULTS_CHANGED',
  'SONARQUBE_INACTIVE_RULES_TRUNCATED',
  'ISSUES_NOT_READ',
  'HOTSPOTS_NOT_COUNTED',
  'PATH_PREFIX_HINT',
  'ISSUE_STATUSES_NOT_SENT',
  'ISSUE_STATUSES_FAILED',
  'TOKEN_ON_COMMAND_LINE',
  'INSECURE_URL',
] as const;

/** Why a gate condition is not imported: `mapGateCondition`'s reasons and `planGate`'s. */
export const CONDITION_UNMAPPED_REASONS = [
  'metric',
  'operator',
  'threshold',
  'threshold_out_of_range',
  'duplicate_metric',
  'operator_conflict',
] as const;
/** The reasons of a condition that lost to another on the same Qualor metric (`qualorMetric`). */
const COLLISIONS: ReadonlySet<string> = new Set(['duplicate_metric', 'operator_conflict']);

const outcome = z.enum([
  'created',
  'would_create',
  'updated',
  'would_update',
  'unchanged',
  'conflict',
  'skipped',
  'failed',
]);
const id = z.uuid().nullable();
const text = z.string().max(2000);
/** Spec §5.3: what SonarQube sends, as bounded when read. */
const sonarKey = z.string().max(1024);
const sonarName = z.string().max(1000);
const languageKey = z.string().max(64);
const metricKey = z.string().max(200);
/** A list of SonarQube rule keys of one profile (at most its 10 000 active rules, spec §5.3). */
const ruleKeys = z.array(sonarKey).max(10_000);
/**
 * Spec §12.2: the SonarQube URL's origin and path only; never a user name, password, query or
 * fragment (the URL is refused with them, spec §3, and nothing else of it may leak here).
 */
const origin = z
  .string()
  .max(2048)
  .refine((u) => {
    if (/[?#]/.test(u)) return false;
    try {
      const url = new URL(u);
      return (
        (url.protocol === 'https:' || url.protocol === 'http:') &&
        url.username === '' &&
        url.password === ''
      );
    } catch {
      return false;
    }
  }, 'an http(s) origin and path, without credentials, query or fragment');
/** `--set-defaults` (spec §9, §13): the default this run set, or would set under `--dry-run`. */
const defaultChange = z.enum(['set', 'would_set']).nullable();

const profileReport = z.strictObject({
  sonarKey,
  name: sonarName,
  sonarLanguage: languageKey,
  language: languageKey.nullable(),
  outcome,
  reason: text.nullable(),
  qualorProfileId: id,
  defaultChange,
  rules: z.strictObject({
    active: z.number().int().min(0),
    mapped: z.number().int().min(0),
    deactivated: z.number().int().min(0),
    severityOverrides: z.number().int().min(0),
    pendingReview: ruleKeys,
    statusOnly: ruleKeys,
    unmapped: z.array(z.strictObject({ key: sonarKey, name: sonarName })).max(2000),
    unmappedCount: z.number().int().min(0),
    parametersNotImported: ruleKeys,
    /** Mapped, but not run by Qualor's bundled configuration (import-sonarqube.md §7.1). */
    mappedNotRun: ruleKeys,
  }),
});

const sonarCondition = { metric: metricKey, op: z.string().max(16), error: z.string().max(100) };
/**
 * A condition: `mapped` with its Qualor condition, or `unmapped` with its reason. `qualorMetric`
 * names the Qualor metric a condition lost on (`duplicate_metric`, `operator_conflict`), and is
 * `null` for the other reasons.
 */
const conditionReport = z
  .discriminatedUnion('outcome', [
    z.strictObject({
      ...sonarCondition,
      outcome: z.literal('mapped'),
      qualor: z.strictObject({
        metric: metricKey,
        operator: z.enum(['gt', 'lt']),
        threshold: z.number(),
      }),
      approximate: z.boolean(),
      reason: z.null(),
    }),
    z.strictObject({
      ...sonarCondition,
      outcome: z.literal('unmapped'),
      qualor: z.null(),
      approximate: z.literal(false),
      reason: z.enum(CONDITION_UNMAPPED_REASONS),
      qualorMetric: metricKey.nullable(),
    }),
  ])
  .refine(
    (c) => c.outcome === 'mapped' || COLLISIONS.has(c.reason) === (c.qualorMetric !== null),
    'qualorMetric names the metric of duplicate_metric and operator_conflict, and only theirs',
  );

const gateReport = z.strictObject({
  name: sonarName,
  outcome,
  reason: text.nullable(),
  qualorGateId: id,
  defaultChange,
  conditions: z.array(conditionReport).max(100),
});

const assignment = z.strictObject({
  outcome: z.enum(['assigned', 'would_assign', 'unchanged', 'conflict', 'skipped', 'failed']),
  reason: text.nullable(),
});

const count = z.number().int().min(0);
const projectReport = z.strictObject({
  key: sonarKey,
  outcome: z.enum(['found', 'created', 'would_create', 'missing', 'key_invalid', 'failed']),
  reason: text.nullable(),
  qualorProjectId: id,
  profiles: z.array(assignment.extend({ language: languageKey, profile: sonarName })).max(100),
  gate: assignment.extend({ gate: sonarName }).nullable(),
  issues: z
    .strictObject({
      outcome: z.enum(['done', 'not_analysed', 'skipped', 'failed']),
      read: count,
      applied: count,
      wouldApply: count,
      alreadySet: count,
      conflict: count,
      unmatched: count,
      ambiguous: count,
      /** Items the server answered `competitors_unknown` (an open competitor may be missing). */
      competitorsUnknown: count,
      /** Items of a path too large to send whole with its competitors: never sent (`not_sent`). */
      notSent: count,
      /** Resolved issues found open again by the open read (reopened meanwhile): never sent (`changed`). */
      changed: count,
      /** Items with no answer: their request was refused (`ISSUE_STATUSES_FAILED`). */
      failed: count,
      unmappedRule: count,
      pathInvalid: count,
      /** Items the endpoint would refuse for a field other than the path (not expected): not sent. */
      invalid: count,
      notRead: count,
      /** Reviewed security hotspots, counted only; `null` when SonarQube did not answer the count. */
      hotspotsNotImported: count.nullable(),
      unmappedRules: z.array(z.strictObject({ key: sonarKey, issues: count })).max(1000),
      items: z
        .array(
          z.strictObject({
            sonarKey: z.string().max(100),
            rule: sonarKey,
            /** Spec §10.2: a relative path of at most 1 024 bytes. */
            path: z.string().max(1024).nullable(),
            line: z.number().int().min(1).max(10_000_000).nullable(),
            outcome: z.enum([
              'applied',
              'would_apply',
              'already_set',
              'conflict',
              'unmatched',
              'ambiguous',
              'competitors_unknown',
              'not_sent',
              'changed',
              'failed',
            ]),
            qualorIssueId: id,
          }),
        )
        .max(10_000),
    })
    .nullable(),
});

export const importReportSchema = z.strictObject({
  format: z.literal('qualor-import-report'),
  version: z.literal(1),
  source: z.strictObject({
    kind: z.literal('sonarqube'),
    edition: z.enum(['server', 'cloud']),
    origin,
    organization: sonarKey.nullable(),
    version: z.string().max(64).nullable(),
  }),
  dryRun: z.boolean(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
  organization: z.strictObject({ id: z.uuid(), key: z.string().max(64) }),
  /** Spec §5.3: at most 1 000 profiles and 1 000 gates are read; projects 10 000 (and --project's). */
  profiles: z.array(profileReport).max(1000),
  gates: z.array(gateReport).max(1000),
  projects: z.array(projectReport).max(11_000),
  warnings: z
    .array(z.strictObject({ code: z.enum(IMPORT_WARNING_CODES), message: text }))
    .max(100_000),
  /**
   * Ruling S13: `null` when the run finished; else it stopped on a fatal failure (a token
   * refused, a server unreachable) once writing had begun, and the report holds what it did.
   */
  aborted: z.strictObject({ reason: text.min(1) }).nullable(),
});
export type ImportReport = z.infer<typeof importReportSchema>;
