import { lstatSync, readFileSync } from 'node:fs';
import { sarifLogSchema, toolVersion } from '@qualor/shared';
import type { Logger } from '../log';

/** config.md §6.1: each log is bounded like any SARIF log. */
const MAX_LOG_BYTES = 256 * 1024 * 1024;

export interface MergedLogs {
  /** One SARIF 2.1.0 run: every rule once, every distinct result once. */
  sarif: unknown;
  version: string | null;
  results: number;
  duplicates: number;
}

interface Driver {
  semanticVersion?: unknown;
  version?: unknown;
  rules?: unknown;
}
interface Run {
  tool?: { driver?: Driver };
  results?: unknown;
}
interface Result {
  ruleId?: unknown;
  ruleIndex?: unknown;
  message?: { text?: unknown };
  locations?: {
    physicalLocation?: {
      artifactLocation?: { uri?: unknown };
      region?: {
        startLine?: unknown;
        startColumn?: unknown;
        endLine?: unknown;
        endColumn?: unknown;
      };
    };
  }[];
}

const part = (v: unknown) => (typeof v === 'string' || typeof v === 'number' ? String(v) : '');

/** Ruling D5. */
function resultKey(r: Result): string {
  const loc = r.locations?.[0]?.physicalLocation;
  const region = loc?.region;
  return [
    part(r.ruleId),
    part(loc?.artifactLocation?.uri),
    part(region?.startLine),
    part(region?.startColumn),
    part(region?.endLine),
    part(region?.endColumn),
    part(r.message?.text),
  ].join('\u0000');
}

/** A run's compiler version: its `semanticVersion`, else the first word of its `version`. */
function driverVersion(driver: Driver | undefined): string | null {
  const raw =
    typeof driver?.semanticVersion === 'string'
      ? driver.semanticVersion
      : part(driver?.version).split(' ')[0];
  return toolVersion(raw === '' ? null : raw);
}

/** Adds a run's rules by id; a rule already seen keeps its first definition. */
function addRules(rules: Map<string, unknown>, driver: Driver | undefined): void {
  const runRules = Array.isArray(driver?.rules) ? (driver.rules as { id?: unknown }[]) : [];
  for (const rule of runRules) {
    if (typeof rule.id === 'string' && !rules.has(rule.id)) rules.set(rule.id, rule);
  }
}

/** Adds a run's results not seen before, in log order; returns how many were duplicates. */
function addResults(run: Run, seen: Set<string>, results: unknown[]): number {
  let duplicates = 0;
  for (const raw of Array.isArray(run.results) ? (run.results as Result[]) : []) {
    const key = resultKey(raw);
    if (seen.has(key)) {
      duplicates += 1;
      continue;
    }
    seen.add(key);
    // The merged run lists its rules in another order, so a result names its rule by id.
    const rest: Result = { ...raw };
    delete rest.ruleIndex;
    results.push(rest);
  }
  return duplicates;
}

/** Rulings D4–D6: one run, rules by id (first seen), results deduplicated in log order. */
export function mergeRoslynLogs(logs: readonly unknown[]): MergedLogs {
  const rules = new Map<string, unknown>();
  const seen = new Set<string>();
  const results: unknown[] = [];
  let duplicates = 0;
  let version: string | null = null;
  for (const log of logs) {
    for (const run of ((log as { runs?: Run[] }).runs ?? []) as Run[]) {
      const driver = run.tool?.driver;
      version ??= driverVersion(driver);
      addRules(rules, driver);
      duplicates += addResults(run, seen, results);
    }
  }
  return {
    sarif: {
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Microsoft (R) Visual C# Compiler',
              ...(version !== null && { semanticVersion: version }),
              rules: [...rules.values()],
            },
          },
          columnKind: 'utf16CodeUnits',
          results,
        },
      ],
    },
    version,
    results: results.length,
    duplicates,
  };
}

/** Reads each log (a regular file, ≤ 256 MiB, SARIF 2.1.0); the detail of a failure is debug-only. */
export function readRoslynLogs(
  files: readonly string[],
  log: Logger,
): { logs: unknown[]; unreadable: number } {
  const logs: unknown[] = [];
  let unreadable = 0;
  for (const file of files) {
    try {
      const stat = lstatSync(file);
      if (!stat.isFile() || stat.size > MAX_LOG_BYTES)
        throw new Error('not a regular file of at most 256 MiB');
      const json = JSON.parse(readFileSync(file, 'utf8')) as unknown;
      if (!sarifLogSchema.safeParse(json).success) throw new Error('not a SARIF 2.1.0 log');
      logs.push(json);
    } catch (err) {
      unreadable += 1;
      log.debug(
        `roslyn: ${file} was not read: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return { logs, unreadable };
}
