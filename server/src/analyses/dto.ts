import { z } from 'zod';
import type { analyses, branches } from '../db/schema';
import { gateStatusSchema, iso, isoOrNull, timestamp } from '../http/schemas';

type AnalysisRow = typeof analyses.$inferSelect;
type BranchRow = typeof branches.$inferSelect;

/**
 * An analysis as the API shows it (`GET /analyses/{id}`, api.md §3). Shared by the analysis routes
 * and the webhook stage, whose `analysis.completed` payload is exactly this body.
 */
export const analysisSchema = z.object({
  id: z.uuid(),
  projectId: z.uuid(),
  status: z.enum(['queued', 'processing', 'succeeded', 'failed']),
  branch: z
    .object({ id: z.uuid(), kind: z.enum(['branch', 'merge_request']), name: z.string() })
    .nullable(),
  revision: z.string().nullable(),
  analysisDate: timestamp.nullable(),
  gateStatus: gateStatusSchema.nullable(),
  gateResult: z.unknown(),
  error: z
    .object({
      code: z.string(),
      message: z.string(),
      errors: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
    })
    .nullable(),
  warnings: z.array(
    z.object({ code: z.string(), message: z.string(), count: z.number().int().optional() }),
  ),
  engines: z.array(
    z.object({
      id: z.string(),
      kind: z.enum(['builtin', 'external']),
      version: z.string().nullable(),
      status: z.enum(['ok', 'failed', 'skipped', 'timeout']),
      reason: z.string().nullable(),
      durationMs: z.number().int(),
      // Plan 2B: the vulnerability database Trivy used, and when it was built.
      database: z.object({ name: z.string(), updatedAt: z.string() }).optional(),
    }),
  ),
  queuedAt: timestamp,
  startedAt: timestamp.nullable(),
  finishedAt: timestamp.nullable(),
});

export function analysisDto(
  analysis: AnalysisRow,
  branch: BranchRow | null,
): z.infer<typeof analysisSchema> {
  return {
    id: analysis.id,
    projectId: analysis.projectId,
    status: analysis.status,
    branch: branch ? { id: branch.id, kind: branch.kind, name: branch.name } : null,
    revision: analysis.revision,
    analysisDate: isoOrNull(analysis.analysisDate),
    gateStatus: analysis.gateStatus,
    gateResult: analysis.gateResult ?? null,
    error: analysis.error,
    warnings: analysis.warnings,
    engines: analysis.engines,
    queuedAt: iso(analysis.queuedAt),
    startedAt: isoOrNull(analysis.startedAt),
    finishedAt: isoOrNull(analysis.finishedAt),
  };
}
