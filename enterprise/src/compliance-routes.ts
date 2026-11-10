// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { Readable } from 'node:stream';
import type { FastifyPluginAsync } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type {
  ComplianceReportView,
  PluginContext,
  PluginJobHandler,
} from '@qualor/server/plugin-contract';
import { assembleReport, DETAIL_LIMIT, parseCanonical } from './compliance/assemble';
import { csvRows } from './compliance/csv';
import { renderPdf } from './compliance/pdf';
import { RenderTimeoutError } from './pdf/layout';
import { standardRefs } from './compliance/standard';

const BUILD_QUEUE = 'ee.compliance.build';
export const HOUSEKEEPING_QUEUE = 'ee.compliance.housekeeping';
/** 4E-1 §2.5: the PDF render budget. */
const RENDER_BUDGET_MS = 60_000;
/** 4E-1 §3: the list's page size. */
const LIST_DEFAULT = 20;
const LIST_MAX = 100;
const BUILD_FAILED = 'the report could not be built';

/**
 * 4E-1 §2.4 step 1: one row; `{ projectId, branchId? }`, `{ projectId, versionId }` (0.15: a
 * version holds its dependencies only) or `{ organizationId }`, never a mix.
 */
const createBody = z.union([
  z.strictObject({ organizationId: z.uuid() }),
  z.strictObject({ projectId: z.uuid(), branchId: z.uuid().optional() }),
  z.strictObject({ projectId: z.uuid(), versionId: z.uuid() }),
]);

const listQuery = z
  .strictObject({
    organizationId: z.uuid().optional(),
    projectId: z.uuid().optional(),
    limit: z.coerce.number().int().min(1).max(LIST_MAX).default(LIST_DEFAULT),
    cursor: z.uuid().optional(),
  })
  .superRefine((q, issues) => {
    if ((q.organizationId === undefined) === (q.projectId === undefined)) {
      issues.addIssue({
        code: 'custom',
        path: ['organizationId'],
        message: 'Give exactly one of organizationId and projectId',
      });
    }
  });

const idParams = z.strictObject({ id: z.uuid() });
const formats = ['json', 'csv', 'pdf', 'sbom'] as const;
const CYCLONEDX = 'application/vnd.cyclonedx+json; version=1.6';
type Format = (typeof formats)[number];

const severityCounts = z.object({
  blocker: z.number().int(),
  high: z.number().int(),
  medium: z.number().int(),
  low: z.number().int(),
  info: z.number().int(),
});

/** 4E-1 §2.6: what the list and the preview show, without unzipping the report. */
const summary = z.object({
  findings: z.object({
    total: z.number().int(),
    bySeverity: severityCounts,
    inNewCode: z.number().int(),
  }),
  standards: z.array(
    z.object({
      id: z.string(),
      categories: z.array(
        z.object({
          id: z.string(),
          title: z.string(),
          open: z.number().int(),
          bySeverity: severityCounts,
          inNewCode: z.number().int(),
          rules: z.number().int(),
          oldestFirstSeenAt: z.string().nullable(),
        }),
      ),
      notMapped: z.object({
        open: z.number().int(),
        bySeverity: severityCounts,
        inNewCode: z.number().int(),
        rules: z.number().int(),
      }),
      distinctTotal: z.number().int(),
    }),
  ),
  secrets: z.object({ open: z.number().int() }),
  dependencies: z.object({ open: z.number().int(), bySeverity: severityCounts }),
  triage: z.object({ falsePositive: z.number().int(), wontFix: z.number().int() }),
  truncated: z.boolean(),
});

const named = z.object({ id: z.string(), key: z.string(), name: z.string() });
/** 4E-1 §3: a report as the API shows it, never its data. */
const reportView = z.object({
  id: z.string(),
  scope: z.enum(['project', 'organization']),
  organization: named,
  project: named.nullable(),
  branch: z.object({ id: z.string(), name: z.string() }).nullable(),
  version: z.object({ id: z.string(), label: z.string() }).nullable(),
  status: z.enum(['pending', 'ready', 'failed']),
  createdBy: z.string(),
  createdAt: z.string(),
  completedAt: z.string().nullable(),
  standards: z.array(z.object({ id: z.string(), version: z.string(), sourceSha256: z.string() })),
  sha256: z.string().nullable(),
  sizeBytes: z.number().int().nullable(),
  error: z.string().nullable(),
  summary: summary.nullable(),
  sbom: z.object({ sha256: z.string() }).nullable(),
  canDelete: z.boolean(),
});

type ShownView = z.input<typeof reportView>;
/**
 * Core types the summary as `unknown` (it stores what the plugin built); the response schema
 * checks it on the way out, so a stored summary of another shape is never sent half-typed.
 */
const shown = (view: ComplianceReportView): ShownView => view as ShownView;

const AUDIT_ANCHOR =
  'AUDIT_CHAIN_ANCHOR_MALFORMED: the audit-chain instance setting is malformed; an administrator must restore it';

/** The scope's key for a file name: the project key, or the organisation key, in [a-z0-9-]. */
function scopeKey(view: ComplianceReportView): string {
  const key = (view.project?.key ?? view.organization.key)
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return key === '' ? 'report' : key;
}

/**
 * The report's `generatedAt` as yyyymmdd. The canonical JSON writes it third (§2.3), so the head
 * of the bytes holds it; the row's completion date stands in if it does not.
 */
function reportDay(
  canonical: Buffer,
  view: ComplianceReportView,
  field: 'generatedAt' | 'timestamp' = 'generatedAt',
): string {
  const head = canonical.subarray(0, 512).toString('utf8');
  const match = new RegExp(`"${field}":"(\\d{4})-(\\d{2})-(\\d{2})T`).exec(head);
  if (match) return `${match[1]}${match[2]}${match[3]}`;
  return (view.completedAt ?? view.createdAt).slice(0, 10).replaceAll('-', '');
}

/** The reason a failed row shows: a known build failure's own text, never SQL or parameters. */
function publicReason(err: unknown): string {
  const known = err as { code?: unknown; detail?: unknown } | null;
  if (known?.code === 'REPORT_BUILD_FAILED' && typeof known.detail === 'string') {
    return known.detail;
  }
  return BUILD_FAILED;
}

/**
 * The code a failure carries, for the log: a problem code (REPORT_BUILD_FAILED) or a PostgreSQL
 * SQLSTATE (5 characters), on the error or a `cause` it wraps (drizzle wraps driver errors).
 * Never the message, the SQL or the parameters.
 */
function failureCode(err: unknown): string | undefined {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === 'string' && /^(?:[0-9A-Z]{5}|[A-Z][A-Z0-9_]{2,63})$/.test(code)) {
      return code;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * 4E-1 §2.4, §2.5, §3: the compliance report API, feature `compliance-export`. Core's
 * `ctx.compliance` checks every caller (a report it cannot read is a 404) and writes the audit
 * events; these routes validate the input, queue the build and render the downloads.
 */
export function complianceRoutes(ctx: PluginContext): FastifyPluginAsync {
  /** §2.5: users with a download in flight (one at a time each), by the download's own token. */
  const downloading = new Map<string, symbol>();

  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.post(
      '/compliance/reports',
      {
        config: {
          openapi: {
            problems: [404, 409],
            problemDescriptions: {
              404: 'The organisation, the project, the branch or the version is not visible to the caller',
              409: `REPORT_PENDING (a report for this scope is being built); NO_ANALYSIS (the branch has no successful analysis); MONITORING_OFF (vulnerability monitoring is off for the project); NOT_CHECKED (the version has not been checked for vulnerabilities yet); ${AUDIT_ANCHOR}`,
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'Create a compliance report of an organisation (org.compliance.manage) or of a project branch or version (project.compliance.create); it is built in the background',
          body: createBody,
          response: { 202: reportView },
        },
      },
      async (request, reply) => {
        const view = await ctx.compliance.create(request, request.body, standardRefs());
        try {
          // §2.4: one build at a time, one attempt; the user creates a new report after a failure.
          await ctx.enqueue(
            BUILD_QUEUE,
            { reportId: view.id },
            { concurrencyKey: BUILD_QUEUE, maxAttempts: 1 },
          );
        } catch (err) {
          // Otherwise the pending row would hold the scope until the housekeeping fails it.
          await ctx.compliance.fail(view.id, 'the build could not be queued').catch(() => false);
          throw err;
        }
        return reply.code(202).send(shown(view));
      },
    );

    app.get(
      '/compliance/reports',
      {
        config: {
          openapi: {
            problems: [404],
            problemDescriptions: {
              404: 'The organisation or the project is not visible to the caller',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            "An organisation's reports (an organisation-level member) or a project's (project.read), newest first",
          querystring: listQuery,
          response: {
            200: z.object({ items: z.array(reportView), nextCursor: z.string().nullable() }),
          },
        },
      },
      async (request) => {
        const q = request.query;
        const filter =
          q.projectId !== undefined
            ? { projectId: q.projectId }
            : { organizationId: q.organizationId as string };
        const page = await ctx.compliance.list(request, filter, {
          limit: q.limit,
          ...(q.cursor === undefined ? {} : { cursor: q.cursor }),
        });
        return { items: page.items.map(shown), nextCursor: page.nextCursor };
      },
    );

    app.get(
      '/compliance/reports/:id',
      {
        schema: {
          tags: ['enterprise'],
          summary: 'A compliance report: its state and summary',
          params: idParams,
          response: { 200: reportView },
        },
      },
      async (request) => shown(await ctx.compliance.get(request, request.params.id)),
    );

    app.get(
      '/compliance/reports/:id/download',
      {
        config: {
          openapi: {
            problems: [404, 409, 429, 503],
            problemDescriptions: {
              404: 'NOT_FOUND (no such report, or for format sbom, a report that attaches no SBOM)',
              409: `REPORT_NOT_READY (the report is pending or failed); ${AUDIT_ANCHOR}`,
              429: 'A download is already running for you (RATE_LIMITED)',
              503: 'REPORT_RENDER_TIMEOUT (the PDF took longer than 60 seconds to render)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'Download a ready report as its canonical JSON, as CSV or PDF, or the SBOM it attaches; the download is recorded',
          params: idParams,
          querystring: z.strictObject({ format: z.enum(formats) }),
          response: {
            200: {
              description:
                'The file, as an attachment: the canonical JSON (its SHA-256 is the report sha256), the CSV (UTF-8 with a BOM), the PDF, or the CycloneDX 1.6 SBOM (its SHA-256 is the sbom.sha256 of the report JSON)',
              content: {
                [CYCLONEDX]: { schema: z.string() },
                'application/json': { schema: z.string() },
                'text/csv': { schema: z.string() },
                'application/pdf': { schema: z.string() },
              },
            },
          },
        },
      },
      async (request, reply) => {
        const { id } = request.params;
        const format: Format = request.query.format;
        const userId = ctx.access.requireUser(request).user.id;
        if (downloading.has(userId)) {
          throw ctx.access.problem(429, 'RATE_LIMITED', 'A download is already running for you');
        }
        const token = Symbol(userId);
        downloading.set(userId, token);
        // Frees only this download's slot: a late 'close' never frees the user's next download.
        const release = () => {
          if (downloading.get(userId) === token) downloading.delete(userId);
        };
        // JSON and PDF free the slot when their work ends, even for a client that went away
        // meanwhile. The CSV streams past this handler: its generator, or a dropped connection,
        // frees it.
        let streaming = false;
        try {
          if (format === 'sbom') {
            const { view, sbom } = await ctx.compliance.downloadSbom(request, id);
            // The SBOM's timestamp is the report's generatedAt, so the name matches the JSON's.
            const day = reportDay(sbom, view, 'timestamp');
            return reply
              .header('cache-control', 'no-store')
              .header(
                'content-disposition',
                `attachment; filename="qualor-compliance-${scopeKey(view)}-${day}-${view.id.slice(0, 8)}.cdx.json"`,
              )
              .header('content-type', CYCLONEDX)
              .send(sbom as unknown as string);
          }
          const { view, canonical } = await ctx.compliance.download(request, id, format);
          const filename = `qualor-compliance-${scopeKey(view)}-${reportDay(canonical, view)}-${view.id.slice(0, 8)}.${format}`;
          // Set only on the file itself: a problem (a PDF that outruns its budget) is no attachment.
          const attachment = () =>
            reply
              // §2.5: no proxy or browser cache keeps a copy.
              .header('cache-control', 'no-store')
              .header('content-disposition', `attachment; filename="${filename}"`);
          if (format === 'json') {
            return attachment()
              .header('content-type', 'application/json; charset=utf-8')
              .send(canonical as unknown as string);
          }
          if (format === 'csv') {
            if (request.raw.destroyed || reply.raw.destroyed) {
              throw ctx.access.problem(499, 'CLIENT_ABORTED', 'The client closed the connection');
            }
            const rows = csvRows(parseCanonical(canonical));
            async function* lines(): AsyncGenerator<string> {
              try {
                yield* rows;
              } finally {
                release();
              }
            }
            streaming = true;
            // Attached with no await before the send: a client that goes away before the
            // stream's generator ever runs frees the slot too.
            reply.raw.once('close', release);
            return (
              attachment()
                .header('content-type', 'text/csv; charset=utf-8')
                // Fastify sends a stream as it is, past the serializer; the schema documents it.
                .send(Readable.from(lines()) as unknown as string)
            );
          }
          let file: Buffer;
          try {
            file = await renderPdf(parseCanonical(canonical), {
              deadline: Date.now() + RENDER_BUDGET_MS,
              // Ruling R9: the cover prints the stored SHA-256 of the canonical JSON.
              ...(view.sha256 === null ? {} : { sha256: view.sha256 }),
            });
          } catch (err) {
            if (err instanceof RenderTimeoutError) {
              ctx.logger.warn({ reportId: view.id }, 'compliance report PDF render timed out');
              throw ctx.access.problem(
                503,
                'REPORT_RENDER_TIMEOUT',
                'The PDF took too long to render',
              );
            }
            throw err;
          }
          return attachment()
            .header('content-type', 'application/pdf')
            .send(file as unknown as string);
        } finally {
          if (!streaming) release();
        }
      },
    );

    app.delete(
      '/compliance/reports/:id',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              409: `REPORT_PENDING (a report that is being built cannot be deleted); ${AUDIT_ANCHOR}`,
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'Delete a ready or failed report (org.compliance.manage)',
          params: idParams,
          response: { 204: z.undefined().describe('Deleted') },
        },
      },
      async (request, reply) => {
        await ctx.compliance.remove(request, request.params.id);
        return reply.code(204).send();
      },
    );
  };
}

/**
 * 4E-1 §2.4: the build (one report, queued by `POST /compliance/reports`) and the hourly
 * housekeeping (retention, and pending rows whose build did not finish). Both are skipped while
 * the feature is inactive (enterprise.md §10.3); the row then stays pending.
 */
export function complianceJobs(ctx: PluginContext): Record<string, PluginJobHandler> {
  return {
    [BUILD_QUEUE]: async (job) => {
      const { reportId } = z.strictObject({ reportId: z.uuid() }).parse(job.payload);
      try {
        const source = await ctx.compliance.collect(reportId, {
          limit: DETAIL_LIMIT,
          signal: job.signal,
        });
        const built = assembleReport({
          id: reportId,
          generatedBy: source.createdBy,
          serverVersion: ctx.serverVersion,
          source,
        });
        // False when the row is gone or no longer pending, or when core failed it for an
        // oversized summary: nothing more to do either way.
        await ctx.compliance.complete(reportId, {
          canonical: built.canonical,
          sha256: built.sha256,
          summary: built.summary,
          sbom: built.sbom,
          standards: built.json.standards.map((s) => ({
            id: s.id,
            version: s.version,
            sourceSha256: s.sourceSha256,
          })),
        });
      } catch (err) {
        await ctx.compliance.fail(reportId, publicReason(err)).catch(() => false);
        const code = failureCode(err);
        ctx.logger.warn(
          {
            reportId,
            err: String((err as Error | null)?.name ?? 'Error'),
            ...(code === undefined ? {} : { code }),
          },
          'compliance report failed',
        );
      }
    },
    [HOUSEKEEPING_QUEUE]: async () => {
      const { deleted, failed } = await ctx.compliance.housekeeping();
      if (deleted > 0 || failed > 0) {
        ctx.logger.info({ deleted, failed }, 'compliance housekeeping');
      }
    },
  };
}
