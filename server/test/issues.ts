import { hex32 } from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import type { Executor } from '../src/db/client';
import { first } from '../src/db/rows';
import { branches, issues, rules } from '../src/db/schema';

/** The project's main branch (created with the project). */
export async function mainBranchId(db: Executor, projectId: string): Promise<string> {
  const [row] = await db
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), eq(branches.isMain, true)));
  if (!row) throw new Error(`project ${projectId} has no main branch`);
  return row.id;
}

export interface RuleSeed {
  key: string;
  engineId?: string;
  name?: string;
  languages?: string[];
  quality?: 'security' | 'reliability' | 'maintainability';
  defaultSeverity?: 'blocker' | 'high' | 'medium' | 'low' | 'info';
  cwe?: number[];
  helpUri?: string | null;
}

/** Inserts (or returns) a reported rule; `engineId` defaults to the key's prefix. */
export async function seedRule(db: Executor, seed: RuleSeed): Promise<string> {
  const [engineId = 'eslint', ...rest] = seed.key.split(':');
  const row = first(
    await db
      .insert(rules)
      .values({
        key: seed.key,
        engineId: seed.engineId ?? engineId,
        engineRuleId: rest.join(':'),
        name: seed.name ?? seed.key,
        languages: seed.languages ?? [],
        defaultSeverity: seed.defaultSeverity ?? 'medium',
        quality: seed.quality ?? 'maintainability',
        kind: 'issue',
        cwe: seed.cwe ?? [],
        helpUri: seed.helpUri ?? null,
        origin: 'reported',
      })
      .onConflictDoUpdate({ target: rules.key, set: { name: sql`excluded.name` } })
      .returning({ id: rules.id }),
  );
  return row.id;
}

export interface IssueSeed {
  projectId: string;
  branchId: string;
  ruleId: string;
  message?: string;
  path?: string | null;
  startLine?: number | null;
  severity?: 'blocker' | 'high' | 'medium' | 'low' | 'info';
  quality?: 'security' | 'reliability' | 'maintainability';
  kind?: 'issue' | 'hotspot';
  status?: 'open' | 'resolved' | 'wont_fix' | 'false_positive' | 'closed';
  inNewCode?: boolean;
  duplicateOfIssueId?: string | null;
  snippet?: unknown;
}

let seedCounter = 0;

/** Inserts one issue directly (no ingestion), with distinct hashes. */
export async function seedIssue(db: Executor, seed: IssueSeed): Promise<string> {
  seedCounter += 1;
  const path = seed.path === undefined ? 'src/a.ts' : seed.path;
  const row = first(
    await db
      .insert(issues)
      .values({
        projectId: seed.projectId,
        branchId: seed.branchId,
        ruleId: seed.ruleId,
        fingerprint: hex32(`fp:${seedCounter}`),
        lineHash: hex32(`line:${seedCounter}`),
        contextHash: hex32(`context:${seedCounter}`),
        path,
        startLine: seed.startLine === undefined ? (path === null ? null : 1) : seed.startLine,
        message: seed.message ?? `Issue ${seedCounter}`,
        severity: seed.severity ?? 'medium',
        quality: seed.quality ?? 'maintainability',
        kind: seed.kind ?? 'issue',
        status: seed.status ?? 'open',
        inNewCode: seed.inNewCode ?? false,
        duplicateOfIssueId: seed.duplicateOfIssueId ?? null,
        snippet: seed.snippet ?? null,
        firstSeenAt: sql`now()`,
        closedAt: seed.status === 'closed' ? sql`now()` : null,
      })
      .returning({ id: issues.id }),
  );
  return row.id;
}
