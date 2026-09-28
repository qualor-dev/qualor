import { METRICS, validateRepoPath } from '@qualor/shared';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireUser } from '../auth/access';
import { pageSchema } from '../http/pagination';
import { notFound, validationFailed } from '../http/problem';
import { idParams, timestamp } from '../http/schemas';
import {
  fileDetail,
  fileIssues,
  fileTree,
  isMetricKey,
  latestMeasures,
  measureHistory,
} from '../measures/read';
import { branchForUser } from '../projects/access';

const BASE_KEYS = METRICS.map((m) => m.key);
const BASE_KEY_SET = new Set(BASE_KEYS);
const MAX_HISTORY_METRICS = 20;

/** `?metrics=a,b` → a de-duplicated list; `check` decides which keys are acceptable. */
function metricList(
  raw: string | undefined,
  check: (key: string) => boolean,
  path: string,
): string[] | undefined {
  if (raw === undefined) return undefined;
  const keys = [
    ...new Set(
      raw
        .split(',')
        .map((k) => k.trim())
        .filter((k) => k !== ''),
    ),
  ];
  const unknown = keys.filter((k) => !check(k));
  if (keys.length === 0 || unknown.length > 0) {
    throw validationFailed([
      {
        path,
        message:
          keys.length === 0
            ? 'At least one metric is required'
            : `Unknown metric: ${unknown.join(', ')}`,
      },
    ]);
  }
  return keys;
}

const measureItemSchema = z.record(z.string(), z.number().nullable());

const treeItemSchema = z.object({
  type: z.enum(['dir', 'file']),
  name: z.string(),
  path: z.string(),
  language: z.string().nullable(),
  kind: z.enum(['main', 'test']).nullable(),
  measures: measureItemSchema,
});

const lineRanges = z.array(z.tuple([z.number().int(), z.number().int()]));

const fileIssueSchema = z.object({
  id: z.uuid(),
  ruleKey: z.string(),
  message: z.string(),
  severity: z.string(),
  quality: z.string(),
  kind: z.string(),
  status: z.string(),
  inNewCode: z.boolean(),
  duplicateOfIssueId: z.uuid().nullable(),
  startLine: z.number().int().nullable(),
  startColumn: z.number().int().nullable(),
  endLine: z.number().int().nullable(),
  endColumn: z.number().int().nullable(),
});

const fileSchema = z.object({
  path: z.string(),
  language: z.string(),
  kind: z.enum(['main', 'test']),
  analysisId: z.uuid(),
  measures: measureItemSchema,
  coverage: z
    .object({
      covered: lineRanges,
      uncovered: lineRanges,
      branches: z.array(z.tuple([z.number().int(), z.number().int(), z.number().int()])),
    })
    .nullable(),
  newLines: z.union([z.literal('all'), lineRanges]).nullable(),
  duplications: z.array(
    z.object({
      startLine: z.number().int(),
      endLine: z.number().int(),
      /** At most 10 of the other blocks of the group. */
      others: z.array(
        z.object({ path: z.string(), startLine: z.number().int(), endLine: z.number().int() }),
      ),
      /** How many other blocks the group has. */
      othersTotal: z.number().int(),
    }),
  ),
  /** The file has more duplicated blocks than `duplications` lists (the stored detail is bounded). */
  duplicationsTruncated: z.boolean(),
  issues: z.array(fileIssueSchema),
  /** More than 500 issues: only the first 500 (by line) are listed. */
  issuesTruncated: z.boolean(),
});

const nameCursor = z.strictObject({ name: z.string() });

function decodeNameCursor(cursor: string | undefined): string | undefined {
  if (cursor === undefined) return undefined;
  try {
    return nameCursor.parse(JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))).name;
  } catch {
    throw validationFailed([{ path: 'query.cursor', message: 'Invalid cursor' }]);
  }
}

function encodeNameCursor(name: string): string {
  return Buffer.from(JSON.stringify({ name }), 'utf8').toString('base64url');
}

/** `''` (the root) or a repo-relative directory without a trailing slash. */
const dirParam = z
  .string()
  .max(1024)
  .default('')
  .refine((d) => d === '' || validateRepoPath(d) === null, { message: 'Invalid directory path' });

/** A repo-relative file path (report-format.md §2 rules). */
const pathParam = z
  .string()
  .min(1)
  .max(1024)
  .refine((p) => validateRepoPath(p) === null, { message: 'Invalid file path' });

export const measureRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/branches/:id/measures',
    {
      schema: {
        tags: ['measures'],
        summary: 'Latest measures of a branch (overall and new code)',
        params: idParams,
        querystring: z.strictObject({ metrics: z.string().max(2_000).optional() }),
        response: {
          200: z.array(
            z.object({
              metric: z.string(),
              overall: z.number().nullable(),
              new: z.number().nullable(),
            }),
          ),
        },
      },
    },
    async (request) => {
      const branch = await branchForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const keys =
        metricList(request.query.metrics, (k) => BASE_KEY_SET.has(k), 'query.metrics') ?? BASE_KEYS;
      if (branch.lastAnalysisId === null) return [];
      return latestMeasures(deps.db, branch.lastAnalysisId, keys);
    },
  );

  app.get(
    '/branches/:id/measures/history',
    {
      schema: {
        tags: ['measures'],
        summary: 'Measure history of a branch (at most 1 000 points per metric)',
        params: idParams,
        querystring: z.strictObject({
          metrics: z.string().max(2_000),
          from: timestamp.optional(),
          to: timestamp.optional(),
        }),
        response: {
          200: z.array(
            z.object({
              metric: z.string(),
              points: z.array(
                z.object({ analysisId: z.uuid(), date: timestamp, value: z.number().nullable() }),
              ),
            }),
          ),
        },
      },
    },
    async (request) => {
      const branch = await branchForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const keys = metricList(request.query.metrics, isMetricKey, 'query.metrics') ?? [];
      if (keys.length > MAX_HISTORY_METRICS) {
        throw validationFailed([
          { path: 'query.metrics', message: `At most ${MAX_HISTORY_METRICS} metrics` },
        ]);
      }
      const { from, to } = request.query;
      return measureHistory(deps.db, branch.id, keys, {
        from: from === undefined ? undefined : new Date(from),
        to: to === undefined ? undefined : new Date(to),
      });
    },
  );

  app.get(
    '/branches/:id/files',
    {
      schema: {
        tags: ['measures'],
        summary: 'Component tree: the files and aggregated directories directly under ?dir',
        params: idParams,
        querystring: z.strictObject({
          dir: dirParam,
          sort: z.enum(['name']).default('name'),
          limit: z.coerce.number().int().min(1).max(500).default(50),
          cursor: z.string().max(2_000).optional(),
        }),
        response: { 200: pageSchema(treeItemSchema) },
      },
    },
    async (request) => {
      const branch = await branchForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const { dir, limit, cursor } = request.query;
      const rows = await fileTree(deps.db, branch.id, dir, decodeNameCursor(cursor), limit + 1);
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return {
        items,
        nextCursor: rows.length > limit && last ? encodeNameCursor(last.name) : null,
      };
    },
  );

  app.get(
    '/branches/:id/file',
    {
      schema: {
        tags: ['measures'],
        summary: 'One file: measures, coverage lines, duplication blocks and its issues',
        params: idParams,
        querystring: z.strictObject({ path: pathParam }),
        response: { 200: fileSchema },
      },
    },
    async (request) => {
      const branch = await branchForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const detail = await fileDetail(deps.db, branch.id, request.query.path);
      if (!detail) throw notFound('File');
      const { rows, truncated } = await fileIssues(deps.db, branch.id, request.query.path);
      const { row } = detail;
      const duplications = (row.duplications ?? []) as z.infer<typeof fileSchema>['duplications'];
      return {
        path: row.path,
        language: row.language,
        kind: row.kind,
        analysisId: row.analysisId,
        measures: detail.measures,
        coverage: (row.coverage ?? null) as z.infer<typeof fileSchema>['coverage'],
        newLines: (row.newLines ?? null) as z.infer<typeof fileSchema>['newLines'],
        duplications,
        duplicationsTruncated: (row.metrics?.duplicationEntries ?? 0) > duplications.length,
        issues: rows.map(({ issue, ruleKey }) => ({
          id: issue.id,
          ruleKey,
          message: issue.message,
          severity: issue.severity,
          quality: issue.quality,
          kind: issue.kind,
          status: issue.status,
          inNewCode: issue.inNewCode,
          duplicateOfIssueId: issue.duplicateOfIssueId,
          startLine: issue.startLine,
          startColumn: issue.startColumn,
          endLine: issue.endLine,
          endColumn: issue.endColumn,
        })),
        issuesTruncated: truncated,
      };
    },
  );
};
