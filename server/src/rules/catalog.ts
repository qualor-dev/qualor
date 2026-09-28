import { sql } from 'drizzle-orm';
import {
  engineRuleDefaults,
  type IssueKind,
  type Quality,
  type Report,
  type Severity,
} from '@qualor/shared';
import { jsonChunks, textList } from '../db/bulk';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { rules } from '../db/schema';
import type { ResolvedRule } from '../ingest/state';

export function ruleKey(engineId: string, ruleId: string): string {
  return `${engineId}:${ruleId}`;
}

/** report-format.md §7.1 per-engine defaults, shared with the CLI (packages/shared). */
export { engineRuleDefaults };

/** One `rules` row as written by ingestion (origin 'reported'). */
export interface ReportedRuleRow {
  id: string;
  key: string;
  engine_id: string;
  engine_rule_id: string;
  name: string;
  description_md: string | null;
  help_uri: string | null;
  languages: string[];
  default_severity: Severity;
  quality: Quality;
  kind: IssueKind;
  tags: string[];
  cwe: number[];
}

/**
 * Splits the report's rules into rows WITH metadata (from `engines[].rules`; these may refresh an
 * existing reported rule) and BARE rows (rule ids only findings mention; these only ever create a
 * missing rule and never overwrite metadata an earlier report supplied). Within an engine the
 * first metadata entry for an id wins: the schema does not forbid duplicates.
 */
export function ruleRowsFromReport(report: Report): {
  withMetadata: ReportedRuleRow[];
  bare: ReportedRuleRow[];
} {
  const withMetadata = new Map<string, ReportedRuleRow>();
  for (const engine of report.engines) {
    const defaults = engineRuleDefaults(engine.id);
    for (const meta of engine.rules) {
      const key = ruleKey(engine.id, meta.id);
      if (withMetadata.has(key)) continue;
      withMetadata.set(key, {
        id: uuidv7(),
        key,
        engine_id: engine.id,
        engine_rule_id: meta.id,
        name: meta.name ?? meta.id,
        description_md: meta.shortDescription ?? null,
        help_uri: meta.helpUri ?? null,
        languages: meta.languages ?? [],
        default_severity: meta.defaultSeverity ?? defaults.defaultSeverity,
        quality: meta.quality ?? defaults.quality,
        kind: meta.kind ?? 'issue',
        tags: meta.tags ?? [],
        cwe: meta.cwe ?? [],
      });
    }
  }
  const bare = new Map<string, ReportedRuleRow>();
  for (const finding of report.findings) {
    const key = ruleKey(finding.engineId, finding.ruleId);
    if (withMetadata.has(key) || bare.has(key)) continue;
    const defaults = engineRuleDefaults(finding.engineId);
    bare.set(key, {
      id: uuidv7(),
      key,
      engine_id: finding.engineId,
      engine_rule_id: finding.ruleId,
      name: finding.ruleId,
      description_md: null,
      help_uri: null,
      languages: [],
      default_severity: finding.severity ?? defaults.defaultSeverity,
      quality: defaults.quality,
      kind: 'issue',
      tags: [],
      cwe: [],
    });
  }
  // Sorted by key: two concurrent ingestions upserting an overlapping set of rules then lock
  // those rows in the same relative order, so they wait on each other instead of deadlocking
  // (Postgres 40P01) when their row sets overlap but were built in different (report) orders.
  const byKey = (a: ReportedRuleRow, b: ReportedRuleRow): number =>
    a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
  return {
    withMetadata: [...withMetadata.values()].sort(byKey),
    bare: [...bare.values()].sort(byKey),
  };
}

interface RuleColumn {
  name: string;
  type: 'uuid' | 'text' | 'jsonb';
  /** A `jsonb` column holding a JSON array: expand it into a Postgres array of this element type. */
  arrayOf?: 'text' | 'integer';
}

/**
 * The single source of truth for the shape `jsonb_to_recordset` reads a chunk as: each report
 * field becomes one record column, in this order. {@link RECORD}, {@link VALUES} and
 * {@link COLUMNS} are all generated from this list so they cannot drift from one another.
 */
const RULE_COLUMNS: readonly RuleColumn[] = [
  { name: 'id', type: 'uuid' },
  { name: 'key', type: 'text' },
  { name: 'engine_id', type: 'text' },
  { name: 'engine_rule_id', type: 'text' },
  { name: 'name', type: 'text' },
  { name: 'description_md', type: 'text' },
  { name: 'help_uri', type: 'text' },
  { name: 'languages', type: 'jsonb', arrayOf: 'text' },
  { name: 'default_severity', type: 'text' },
  { name: 'quality', type: 'text' },
  { name: 'kind', type: 'text' },
  { name: 'tags', type: 'jsonb', arrayOf: 'text' },
  { name: 'cwe', type: 'jsonb', arrayOf: 'integer' },
];

/** Every inserted row also gets these two literal, non-record columns (in this order). */
const LITERAL_COLUMNS = [
  { name: 'status', value: `'ready'` },
  { name: 'origin', value: `'reported'` },
];

const RECORD = sql.raw(`r(${RULE_COLUMNS.map((c) => `${c.name} ${c.type}`).join(', ')})`);
const VALUES = sql.raw(
  [
    ...RULE_COLUMNS.map((c) =>
      c.arrayOf
        ? `ARRAY(SELECT jsonb_array_elements_text(r.${c.name})${c.arrayOf === 'integer' ? '::integer' : ''})`
        : `r.${c.name}`,
    ),
    ...LITERAL_COLUMNS.map((c) => c.value),
  ].join(', '),
);
const COLUMNS = sql.raw(
  `(${[...RULE_COLUMNS.map((c) => c.name), ...LITERAL_COLUMNS.map((c) => c.name)].join(', ')})`,
);

/** The record as named columns (`n.<name>`), for the UPDATE of changed metadata. */
const NAMED_VALUES = sql.raw(
  RULE_COLUMNS.map((c) =>
    c.arrayOf
      ? `ARRAY(SELECT jsonb_array_elements_text(r.${c.name})${c.arrayOf === 'integer' ? '::integer' : ''}) AS ${c.name}`
      : `r.${c.name} AS ${c.name}`,
  ).join(', '),
);

/** Re-inserts of rules a concurrent cleanup deleted between insert and lookup, at most. */
const RULE_LOOKUP_RETRIES = 3;

/** The metadata a report may refresh on a reported rule (data-model.md §4.4). */
const METADATA = [
  'name',
  'description_md',
  'help_uri',
  'languages',
  'default_severity',
  'quality',
  'kind',
  'tags',
  'cwe',
] as const;
const METADATA_OF = (table: string) =>
  sql.raw(`(${METADATA.map((c) => `${table}.${c}`).join(', ')})`);
const METADATA_SET = sql.raw(METADATA.map((c) => `${c} = n.${c}`).join(', '));

/**
 * data-model.md §4.4: a rule never seen before is created with `origin = 'reported'`; a reported
 * rule's metadata is refreshed when a report carries different metadata; a `builtin` rule is
 * never overwritten. Returns every rule the report's findings reference, by key.
 *
 * Rules are global (shared by every organisation), so an ingestion must not hold locks on
 * rows it does not change: an `INSERT … ON CONFLICT DO UPDATE` locks every conflicting row, even
 * one its `WHERE` then leaves alone, until the ingestion commits. So new rules are inserted with
 * `ON CONFLICT DO NOTHING` (no row lock), and only the reported rules whose metadata really
 * differs are locked, in key order (so overlapping ingestions cannot deadlock), and updated. A
 * report that re-sends 20 000 unchanged rules costs no writes and no row locks but on the rules
 * its findings reference.
 *
 * The rules the findings reference are looked up `FOR KEY SHARE`, held until the ingestion
 * commits: a bare rule nothing else refers to may be deleted by a profile change in any
 * organisation (routes/profiles.ts `removeBareRules`, which locks `FOR UPDATE SKIP LOCKED` and so
 * skips a rule an ingestion holds), and without the lock it could vanish between this lookup and
 * the issue insert of the tracking stage, failing the ingestion's foreign key. KEY SHARE conflicts
 * neither with the metadata UPDATE above (NO KEY UPDATE) nor with other ingestions. When the
 * delete locked first, the lookup waits for it and then misses the rule: the rule is inserted
 * again and looked up again (a bounded loop; the new row is invisible to other transactions, so
 * nothing else can delete it before this one commits).
 */
export async function upsertReportedRules(
  tx: Executor,
  report: Report,
): Promise<Map<string, ResolvedRule>> {
  const { withMetadata, bare } = ruleRowsFromReport(report);
  for (const chunk of jsonChunks(withMetadata)) {
    await tx.execute(sql`
      INSERT INTO rules ${COLUMNS}
      SELECT ${VALUES} FROM jsonb_to_recordset(${chunk}::jsonb) AS ${RECORD}
      ON CONFLICT (key) DO NOTHING`);
    // Rows this INSERT just created match their own metadata, so only pre-existing, changed
    // rows are locked here (FOR UPDATE re-checks the condition after waiting on a lock).
    await tx.execute(sql`
      WITH n AS (SELECT ${NAMED_VALUES} FROM jsonb_to_recordset(${chunk}::jsonb) AS ${RECORD}),
      changed AS (
        SELECT rules.id FROM rules JOIN n ON n.key = rules.key
         WHERE rules.origin = 'reported'
           AND ${METADATA_OF('rules')} IS DISTINCT FROM ${METADATA_OF('n')}
         ORDER BY rules.key
         FOR UPDATE OF rules)
      UPDATE rules SET ${METADATA_SET}, updated_at = now()
        FROM n, changed
       WHERE rules.id = changed.id AND n.key = rules.key`);
  }
  for (const chunk of jsonChunks(bare)) {
    await tx.execute(sql`
      INSERT INTO rules ${COLUMNS}
      SELECT ${VALUES} FROM jsonb_to_recordset(${chunk}::jsonb) AS ${RECORD}
      ON CONFLICT (key) DO NOTHING`);
  }
  const referenced = [...new Set(report.findings.map((f) => ruleKey(f.engineId, f.ruleId)))];
  const resolved = new Map<string, ResolvedRule>();
  if (referenced.length === 0) return resolved;
  const lookup = async (keys: readonly string[]) => {
    const rows = await tx
      .select({
        id: rules.id,
        key: rules.key,
        engineId: rules.engineId,
        defaultSeverity: rules.defaultSeverity,
        quality: rules.quality,
        kind: rules.kind,
        cwe: rules.cwe,
      })
      .from(rules)
      .where(sql`${rules.key} IN ${textList(keys)}`)
      .orderBy(rules.key)
      .for('key share');
    for (const row of rows) {
      resolved.set(row.key, {
        id: row.id,
        key: row.key,
        engineId: row.engineId,
        defaultSeverity: row.defaultSeverity as Severity,
        quality: row.quality as Quality,
        kind: row.kind,
        cwe: row.cwe,
      });
    }
  };
  await lookup(referenced);
  const sources = new Map([...withMetadata, ...bare].map((r) => [r.key, r] as const));
  for (let retry = 0; retry < RULE_LOOKUP_RETRIES; retry++) {
    const missing = referenced.filter((key) => !resolved.has(key));
    if (missing.length === 0) break;
    // Deleted after the insert above, before the lock (a bare rule a profile change removed).
    const again = missing.flatMap((key) => {
      const source = sources.get(key);
      return source ? [{ ...source, id: uuidv7() }] : [];
    });
    for (const chunk of jsonChunks(again)) {
      await tx.execute(sql`
        INSERT INTO rules ${COLUMNS}
        SELECT ${VALUES} FROM jsonb_to_recordset(${chunk}::jsonb) AS ${RECORD}
        ON CONFLICT (key) DO NOTHING`);
    }
    await lookup(missing);
  }
  return resolved;
}
