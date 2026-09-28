import type { GateResult, IssueKind, Quality, ReportFinding, Severity } from '@qualor/shared';

/** A rule as the ingestion stages need it (rules.* after the catalog upsert). */
export interface ResolvedRule {
  id: string;
  key: string;
  engineId: string;
  defaultSeverity: Severity;
  quality: Quality;
  kind: IssueKind;
  cwe: readonly number[];
}

/** A report finding that survived the profile filter, with its rule and effective severity. */
export interface AcceptedFinding {
  /** Position in `report.findings`. */
  index: number;
  finding: ReportFinding;
  rule: ResolvedRule;
  /** Profile `severity_override`, else the finding's own severity, else the rule default. */
  severity: Severity;
  /** data-model.md §5.1, computed over ALL report findings (before filtering). */
  fingerprint: string;
}

/** Measure values keyed like gate metrics: `coverage` (overall) and `new_coverage` (new). */
export type MeasureValues = Record<string, number | null>;

/**
 * Values one stage hands to the next, inside one ingestion transaction. Each field is set by
 * exactly one stage (in `DEFAULT_STAGES` order) and read by later ones via {@link requireState}.
 */
export interface IngestionState {
  /** Set by the rules stage: the findings that become (or match) issues. */
  findings?: readonly AcceptedFinding[];
  /** Set by the measures stage. */
  measures?: MeasureValues;
  /** Set by the gate stage. The hook later stages (webhooks, server step 13) read. */
  gate?: GateResult;
  /**
   * Set by the webhook stage: the `finished_at` the analysis is stored with, so the payload it
   * enqueues matches `GET /analyses/{id}` exactly. Without it, ingestion uses the time it stores.
   */
  finishedAt?: Date;
}

/** A stage-ordering bug, never a report problem: thrown as a plain Error (retried, then dead). */
export function requireState<K extends keyof IngestionState>(
  state: IngestionState,
  key: K,
): NonNullable<IngestionState[K]> {
  const value = state[key];
  if (value === undefined) throw new Error(`ingestion state "${key}" is not set yet`);
  return value as NonNullable<IngestionState[K]>;
}
