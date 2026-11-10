// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { Readable } from 'node:stream';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type {
  PluginContext,
  PortfolioProjectRow,
  PortfolioScopeInput,
} from '@qualor/server/plugin-contract';
import { RenderTimeoutError } from './pdf/layout';
import { portfolioCsv } from './portfolio/csv';
import { PDF_PROJECTS_MAX, renderPortfolioPdf } from './portfolio/pdf';

/** 4E-2 §3: the PDF render budget, as in 4E-1. */
const RENDER_BUDGET_MS = 60_000;
/** 4E-2 §3: the projects page size. */
const PAGE_DEFAULT = 50;
const PAGE_MAX = 100;
const SORTS = [
  'key',
  'gate',
  'security',
  'reliability',
  'issues',
  'ncloc',
  'coverage',
  'lastAnalysis',
  'vulnerableReleases',
  'exploited',
] as const;
const formats = ['csv', 'pdf'] as const;

/** §3: every route's scope; `organizationId` exactly with the organisation scope. */
const scopeShape = {
  scope: z.enum(['organization', 'all']),
  organizationId: z.uuid().optional(),
};
type ScopeQuery = { scope: 'organization' | 'all'; organizationId?: string | undefined };
const oneScope = (q: ScopeQuery): boolean =>
  (q.scope === 'organization') === (q.organizationId !== undefined);
const ONE_SCOPE = {
  path: ['organizationId'],
  message: 'Give organizationId with scope=organization, and only then',
};
const granularity = z.enum(['week', 'month']).default('week');

const overviewQuery = z.strictObject({ ...scopeShape, granularity }).refine(oneScope, ONE_SCOPE);
const projectsQuery = z
  .strictObject({
    ...scopeShape,
    sort: z.enum(SORTS).default('key'),
    limit: z.coerce.number().int().min(1).max(PAGE_MAX).default(PAGE_DEFAULT),
    cursor: z.string().max(2_048).optional(),
  })
  .refine(oneScope, ONE_SCOPE);
const exportQuery = z
  .strictObject({ ...scopeShape, granularity, format: z.enum(formats) })
  .refine(oneScope, ONE_SCOPE);

const count = z.number().int();
const severityCounts = z.object({
  blocker: count,
  high: count,
  medium: count,
  low: count,
  info: count,
});
const rating = z.enum(['A', 'B', 'C', 'D', 'E']);
const ratingCounts = z.object({ A: count, B: count, C: count, D: count, E: count });

/** §2: the aggregate over a set of projects; shares and percentages are null without data. */
const aggregateShape = {
  projects: count,
  analysed: count,
  abandoned: count,
  gate: z.object({ passed: count, failed: count, error: count, none: count }),
  passedShare: z.number().nullable(),
  securityRating: ratingCounts,
  reliabilityRating: ratingCounts,
  ncloc: z.number(),
  coverage: z.number().nullable(),
  duplication: z.number().nullable(),
  issues: count,
  bySeverity: severityCounts,
  securityIssues: count,
  reliabilityIssues: count,
  maintainabilityIssues: count,
  newIssues: count,
};

/** §2: one project's current state on its main branch; null where it has no analysis or value. */
const projectRow = z.object({
  organization: z.object({ key: z.string(), name: z.string() }),
  project: z.object({ id: z.string(), key: z.string(), name: z.string() }),
  lastAnalysisAt: z.string().nullable(),
  abandoned: z.boolean(),
  gate: z.enum(['passed', 'failed', 'error', 'none']).nullable(),
  securityRating: rating.nullable(),
  reliabilityRating: rating.nullable(),
  ncloc: z.number().nullable(),
  coverage: z.number().nullable(),
  duplication: z.number().nullable(),
  issues: count.nullable(),
  bySeverity: severityCounts.nullable(),
  newIssues: count.nullable(),
  secrets: count,
  vulnerableDependencies: count,
  vulnerableReleases: count.nullable(),
  exploited: count.nullable(),
});

const named = { id: z.string(), key: z.string(), name: z.string() };
const overviewView = z.object({
  generatedAt: z.string(),
  scope: z.object({
    kind: z.enum(['organization', 'all']),
    organization: z.object(named).nullable(),
  }),
  granularity: z.enum(['week', 'month']),
  totals: z.object({
    ...aggregateShape,
    secrets: count,
    vulnerableDependencies: count,
    vulnerableReleases: count.nullable(),
    exploited: count.nullable(),
  }),
  organizations: z.array(z.object({ ...named, ...aggregateShape })).nullable(),
  trend: z.array(
    z.object({
      start: z.string(),
      end: z.string(),
      ...aggregateShape,
      analyses: count,
      triage: count,
    }),
  ),
  attention: z.object({
    exploited: z.array(projectRow).nullable(),
    failingGates: z.array(projectRow),
    worstSecurity: z.array(projectRow),
    mostSevere: z.array(projectRow),
    abandoned: z.array(projectRow),
  }),
});

const NOT_VISIBLE = 'The organisation is not visible to the caller (Organization not found)';
const TIMEOUT = 'PORTFOLIO_TIMEOUT (the portfolio took longer than its 20-second budget)';

/** The service's scope input from a validated query. */
function inputOf(q: ScopeQuery): PortfolioScopeInput {
  return q.scope === 'organization'
    ? { scope: 'organization', organizationId: q.organizationId as string }
    : { scope: 'all' };
}

/** The organisation key for a file name, in [a-z0-9-], or `all`. */
function fileKey(organizationKey: string | null): string {
  if (organizationKey === null) return 'all';
  const key = organizationKey
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return key === '' ? 'organization' : key;
}

/** §3: `qualor-portfolio-<org key|all>-<yyyymmdd>.<ext>`, the day of `at` (UTC). */
const fileName = (organizationKey: string | null, at: string, format: string): string =>
  `qualor-portfolio-${fileKey(organizationKey)}-${at.slice(0, 10).replaceAll('-', '')}.${format}`;

/**
 * The rows of `source`, the first one already read: core checks the caller and computes the rows
 * on the first `next()`, so a refusal (403, 404, 503) is thrown here, before any header is sent.
 */
async function pulled(
  source: AsyncIterable<PortfolioProjectRow>,
): Promise<AsyncGenerator<PortfolioProjectRow>> {
  const iterator = source[Symbol.asyncIterator]();
  const first = await iterator.next();
  return (async function* () {
    try {
      let next = first;
      while (!next.done) {
        yield next.value;
        next = await iterator.next();
      }
    } finally {
      await iterator.return?.();
    }
  })();
}

/**
 * 4E-2 §3: the portfolio API, feature `portfolio`. Core's `ctx.portfolio` checks every caller
 * (an organisation it cannot read is a 404) and computes the numbers; these routes validate the
 * input and render the exports.
 */
export function portfolioRoutes(ctx: PluginContext): FastifyPluginAsync {
  /** §3: users with an export in flight (one at a time each), by the export's own token. */
  const exporting = new Map<string, symbol>();

  /** The CSV: its organisation key (null for all), and every row, streamed. */
  async function csvExport(request: FastifyRequest, input: PortfolioScopeInput) {
    const organizationKey =
      input.scope === 'organization'
        ? (await ctx.access.requireOrganizationAccess(request, input.organizationId, 'org.read'))
            .organizationKey
        : null;
    const rows = await pulled(ctx.portfolio.exportRows(request, input));
    return { organizationKey, at: new Date().toISOString(), rows };
  }

  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.get(
      '/portfolio',
      {
        config: {
          openapi: {
            problems: [404, 503],
            problemDescriptions: { 404: NOT_VISIBLE, 503: TIMEOUT },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'The portfolio of an organisation or of every organisation: totals, the 12-period trend, the organisations and the attention lists, over the projects the caller can read',
          querystring: overviewQuery,
          response: { 200: overviewView },
        },
      },
      async (request) =>
        ctx.portfolio.overview(request, inputOf(request.query), {
          granularity: request.query.granularity,
        }),
    );

    app.get(
      '/portfolio/projects',
      {
        config: {
          openapi: {
            problems: [404, 503],
            problemDescriptions: { 404: NOT_VISIBLE, 503: TIMEOUT },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            "A page of the portfolio's projects, each on its main branch, in the sort's order",
          querystring: projectsQuery,
          response: {
            200: z.object({ items: z.array(projectRow), nextCursor: z.string().nullable() }),
          },
        },
      },
      async (request) => {
        const q = request.query;
        return ctx.portfolio.projects(request, inputOf(q), {
          sort: q.sort,
          limit: q.limit,
          ...(q.cursor === undefined ? {} : { cursor: q.cursor }),
        });
      },
    );

    app.get(
      '/portfolio/export',
      {
        config: {
          openapi: {
            problems: [404, 429, 503],
            problemDescriptions: {
              404: NOT_VISIBLE,
              429: 'An export is already running for you (RATE_LIMITED)',
              503: `${TIMEOUT}, or the PDF took longer than 60 seconds to render`,
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'Download the portfolio as CSV (every project) or as PDF (the overview and the first 50 projects by gate)',
          querystring: exportQuery,
          response: {
            200: {
              description: 'The file, as an attachment: the CSV (UTF-8 with a BOM) or the PDF',
              content: {
                'text/csv': { schema: z.string() },
                'application/pdf': { schema: z.string() },
              },
            },
          },
        },
      },
      async (request, reply) => {
        const q = request.query;
        const input = inputOf(q);
        const { user } = ctx.access.requireUser(request);
        if (exporting.has(user.id)) {
          throw ctx.access.problem(429, 'RATE_LIMITED', 'An export is already running for you');
        }
        const token = Symbol(user.id);
        exporting.set(user.id, token);
        // Frees only this export's slot: a late 'close' never frees the user's next export.
        const release = () => {
          if (exporting.get(user.id) === token) exporting.delete(user.id);
        };
        // The PDF frees the slot when its work ends, even for a client that went away meanwhile.
        // The CSV streams past this handler: its generator, or a dropped connection, frees it.
        let streaming = false;
        try {
          if (q.format === 'csv') {
            const { organizationKey, at, rows } = await csvExport(request, input);
            if (request.raw.destroyed || reply.raw.destroyed) {
              await rows.return(undefined);
              throw ctx.access.problem(499, 'CLIENT_ABORTED', 'The client closed the connection');
            }
            async function* lines(): AsyncGenerator<string> {
              try {
                yield* portfolioCsv(rows);
              } finally {
                release();
              }
            }
            streaming = true;
            // Attached with no await before the send: a client that goes away before the
            // stream's generator ever runs frees the slot too.
            reply.raw.once('close', release);
            return (
              reply
                // §3: no proxy or browser cache keeps a copy.
                .header('cache-control', 'no-store')
                .header(
                  'content-disposition',
                  `attachment; filename="${fileName(organizationKey, at, 'csv')}"`,
                )
                .header('content-type', 'text/csv; charset=utf-8')
                // Fastify sends a stream as it is, past the serializer; the schema documents it.
                .send(Readable.from(lines()) as unknown as string)
            );
          }
          // Two snapshots, not one: under concurrent writes the PDF's project list may disagree
          // slightly with its overview. The PDF is not a stored snapshot (§3).
          const overview = await ctx.portfolio.overview(request, input, {
            granularity: q.granularity,
          });
          // §3: the PDF lists the first 50 projects by gate, then security rating.
          const { items } = await ctx.portfolio.projects(request, input, {
            sort: 'gate',
            limit: PDF_PROJECTS_MAX,
          });
          let file: Buffer;
          try {
            file = await renderPortfolioPdf(overview, items, {
              generatedBy: user.displayName?.trim() || user.username,
              serverVersion: ctx.serverVersion,
              deadline: Date.now() + RENDER_BUDGET_MS,
            });
          } catch (err) {
            if (err instanceof RenderTimeoutError) {
              ctx.logger.warn('portfolio PDF render timed out');
              throw ctx.access.problem(503, 'PORTFOLIO_TIMEOUT', 'The PDF took too long to render');
            }
            throw err;
          }
          const organizationKey = overview.scope.organization?.key ?? null;
          return reply
            .header('cache-control', 'no-store')
            .header(
              'content-disposition',
              `attachment; filename="${fileName(organizationKey, overview.generatedAt, 'pdf')}"`,
            )
            .header('content-type', 'application/pdf')
            .send(file as unknown as string);
        } finally {
          if (!streaming) release();
        }
      },
    );
  };
}
