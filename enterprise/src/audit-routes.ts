// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { Readable } from 'node:stream';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AuditFilter, PluginContext } from '@qualor/server/plugin-contract';

/** rbac-audit.md §12: an export covers at most this many days. */
const MAX_EXPORT_DAYS = 366;
const DAY_MS = 86_400_000;
/** rbac-audit.md §13: at most 20 action filters. */
const MAX_ACTIONS = 20;
/** rbac-audit.md §13: the stream test sends at most this many batches a minute per caller. */
const STREAM_TESTS_PER_MINUTE = 10;

/**
 * An exact action name, or a prefix ending in `.*` (`issue.*`). Every segment starts with a
 * letter, so nothing matches everything: `.*`, `*` and SQL wildcards are refused (422).
 */
const ACTION = /^[a-z][a-z_]*(\.[a-z][a-z_]*)*(\.\*)?$/;
const action = z
  .string()
  .max(100)
  .regex(ACTION, 'Use an action name, or a prefix ending in .* (for example issue.*)');
const isoDate = z.iso.datetime({ offset: true });

/** A lone UTF-16 surrogate: a high one not followed by a low one, or a low one without a high. */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * api.md §2.1, as core's `text()` (the plugin cannot import it at run time): free text compared
 * with a `text` column refuses U+0000 (PostgreSQL cannot hold it: a 500 otherwise) and a lone
 * surrogate, with one 422 error on the field, NUL's message when it holds one.
 */
function storableText(max: number) {
  return z
    .string()
    .min(1)
    .max(max)
    .refine((s) => !s.includes('\u0000'), 'Must not contain NUL characters')
    .refine(
      (s) => s.includes('\u0000') || !LONE_SURROGATE.test(s),
      'Must be well-formed Unicode (no lone surrogate)',
    );
}

const filterQuery = {
  action: z.union([action, z.array(action).min(1).max(MAX_ACTIONS)]).optional(),
  outcome: z.enum(['success', 'failure']).optional(),
  actorUserId: z.uuid().optional(),
  organizationId: z.uuid().optional(),
  projectId: z.uuid().optional(),
  targetType: storableText(64).optional(),
  targetId: storableText(200).optional(),
};

export const eventsQuery = z.strictObject({
  ...filterQuery,
  from: isoDate.optional(),
  to: isoDate.optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  cursor: z.string().max(200).optional(),
});

/** §12: `from` < `to`, at most 366 days apart; the refusal names `query.to`. */
export const exportQuery = z
  .strictObject({ ...filterQuery, from: isoDate, to: isoDate })
  .superRefine((q, issues) => {
    const span = Date.parse(q.to) - Date.parse(q.from);
    if (!(span > 0) || span > MAX_EXPORT_DAYS * DAY_MS) {
      issues.addIssue({
        code: 'custom',
        path: ['to'],
        message: `to must be after from, at most ${MAX_EXPORT_DAYS} days later`,
      });
    }
  });

const ref = z.object({ id: z.string(), key: z.string().nullable() }).nullable();
/** §10.1: the record, with its place in the chain. */
const auditEvent = z.object({
  v: z.literal(1),
  seq: z.string(),
  id: z.string(),
  occurredAt: z.string(),
  action: z.string(),
  outcome: z.enum(['success', 'failure']),
  actor: z.object({
    type: z.enum(['user', 'anonymous', 'system']),
    userId: z.string().nullable(),
    username: z.string().nullable(),
    tokenId: z.string().nullable(),
  }),
  organization: ref,
  project: ref,
  target: z
    .object({ type: z.string(), id: z.string().nullable(), label: z.string().nullable() })
    .nullable(),
  ip: z.string().nullable(),
  userAgent: z.string().nullable(),
  details: z.record(z.string(), z.unknown()),
  prevHash: z.string(),
  hash: z.string(),
});

const anchor = z.object({ throughSeq: z.string(), throughHash: z.string() }).nullable();

const streamStatus = z.object({
  /** Null while the state row is missing or malformed; `lastError` then says so. */
  cursorSeq: z.string().nullable(),
  pending: z.number().int(),
  lastSuccessAt: z.string().nullable(),
  lastError: z.string().nullable(),
  failingSince: z.string().nullable(),
  nextAttemptAt: z.string().nullable(),
  skipped: z.number().int(),
});
const streamView = z.object({
  url: z.string(),
  active: z.boolean(),
  secretSet: z.boolean(),
  status: streamStatus,
});
const settingsView = z.object({ retentionDays: z.number().int(), stream: streamView.nullable() });
/** `PUT` also returns a generated secret, once. */
const settingsSaved = z.object({
  retentionDays: z.number().int(),
  stream: streamView.extend({ secret: z.string().optional() }).nullable(),
});
const settingsBody = z.strictObject({
  retentionDays: z.number().int().optional(),
  stream: z
    .strictObject({
      url: z.string().min(1).max(2048),
      active: z.boolean().optional(),
      secret: z.string().max(256).optional(),
    })
    .nullable()
    .optional(),
});

type FilterQuery = { [K in keyof typeof filterQuery]?: z.output<(typeof filterQuery)[K]> };

/** The filter of a query, without the caller's scope. */
function filterOf(query: FilterQuery): AuditFilter {
  const actions =
    query.action === undefined
      ? undefined
      : Array.isArray(query.action)
        ? query.action
        : [query.action];
  return {
    ...(actions ? { actions } : {}),
    ...(query.outcome ? { outcome: query.outcome } : {}),
    ...(query.actorUserId ? { actorUserId: query.actorUserId } : {}),
    ...(query.projectId ? { projectId: query.projectId } : {}),
    ...(query.targetType ? { targetType: query.targetType } : {}),
    ...(query.targetId ? { targetId: query.targetId } : {}),
  };
}

/** `2027-01-01T00:00:00.000Z` → `2027-01-01T00-00-00Z`, for a file name. */
function fileStamp(date: Date): string {
  return date
    .toISOString()
    .replace(/\.\d{3}Z$/, 'Z')
    .replaceAll(':', '-');
}

/**
 * rbac-audit.md §12–§14: the audit log's read API, export, verification and settings (retention,
 * and the stream's configuration), feature `audit-log`; the stream's own routes are
 * {@link auditStreamRoutes} (§14.4). Every route needs an `admin`-scoped caller. `head`, `verify`
 * and the settings are instance admins' only; `events` and `export` are also open to an
 * organisation's admin for that organisation, whose view excludes instance events and every other
 * organisation.
 */
export function auditRoutes(ctx: PluginContext): FastifyPluginAsync {
  /** Users with an export running (§12: one at a time each). */
  const exporting = new Set<string>();
  /** §13: one verification at a time. */
  let verifying = false;

  /**
   * Without `organizationId`, instance admins only (403 FORBIDDEN otherwise). With one, the
   * caller needs `org.audit.read` in it (an instance admin holds it everywhere; 404 when the
   * organisation is invisible or missing); only an instance admin's view keeps instance events,
   * which an organisation filter excludes anyway. `organization` is the export's reference.
   */
  async function readScope(
    request: FastifyRequest,
    organizationId: string | undefined,
  ): Promise<{
    userId: string;
    scope: Pick<AuditFilter, 'organizationId' | 'instanceLevel'>;
    organization: { id: string; key: string } | null;
  }> {
    const principal = ctx.access.requireUser(request, 'admin');
    const userId = principal.user.id;
    if (organizationId === undefined) {
      ctx.access.requireInstanceAdmin(request);
      return { userId, scope: { instanceLevel: 'include' }, organization: null };
    }
    const access = await ctx.access.requireOrganizationAccess(
      request,
      organizationId,
      'org.audit.read',
    );
    return {
      userId,
      scope: {
        organizationId,
        instanceLevel: principal.user.isInstanceAdmin ? 'include' : 'exclude',
      },
      organization: { id: access.organizationId, key: access.organizationKey },
    };
  }

  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.get(
      '/audit/events',
      {
        config: {
          openapi: {
            problems: [404],
            problemDescriptions: {
              404: 'An organizationId the caller cannot see (Organization not found)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'Audit events, newest first',
          querystring: eventsQuery,
          response: {
            200: z.object({ items: z.array(auditEvent), nextCursor: z.string().nullable() }),
          },
        },
      },
      async (request) => {
        const q = request.query;
        const { scope } = await readScope(request, q.organizationId);
        return ctx.audit.query(
          {
            ...filterOf(q),
            ...(q.from ? { from: new Date(q.from) } : {}),
            ...(q.to ? { to: new Date(q.to) } : {}),
            ...scope,
          },
          { limit: q.limit, ...(q.cursor === undefined ? {} : { cursor: q.cursor }) },
        );
      },
    );

    app.get(
      '/audit/export',
      {
        config: {
          openapi: {
            problems: [404, 409, 429],
            problemDescriptions: {
              404: 'An organizationId the caller cannot see (Organization not found)',
              409: 'AUDIT_CHAIN_ANCHOR_MALFORMED (the audit-chain setting must be restored; the export is recorded first)',
              429: 'An export is already running for you (RATE_LIMITED)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'Export the audit events of a period (at most 366 days) as JSON Lines',
          querystring: exportQuery,
          response: {
            200: {
              description: 'One audit event per line, oldest first, each with prevHash and hash',
              content: { 'application/x-ndjson': { schema: z.string() } },
            },
          },
        },
      },
      async (request, reply) => {
        const q = request.query;
        const { userId, scope, organization } = await readScope(request, q.organizationId);
        const from = new Date(q.from);
        const to = new Date(q.to);
        const filter = filterOf(q);
        if (exporting.has(userId)) {
          throw ctx.access.problem(429, 'RATE_LIMITED', 'An export is already running for you');
        }
        exporting.add(userId);
        const release = () => exporting.delete(userId);
        try {
          // §12: recorded before the first line, with the period and the filters.
          await ctx.audit.record(ctx.access.actor(request), {
            action: 'audit.exported',
            // rbac-audit.md §8: a scoped export belongs to its organisation.
            organization,
            details: {
              from: from.toISOString(),
              to: to.toISOString(),
              filters: {
                ...filter,
                ...(q.organizationId ? { organizationId: q.organizationId } : {}),
              },
            },
          });
        } catch (err) {
          release();
          throw err;
        }
        const source = ctx.audit.exportLines({ ...filter, ...scope, from, to });
        async function* lines(): AsyncGenerator<string> {
          try {
            for await (const line of source) yield `${line}\n`;
          } finally {
            release();
          }
        }
        // A client that goes away before the body starts never runs the generator.
        reply.raw.once('close', release);
        return (
          reply
            .header('content-type', 'application/x-ndjson; charset=utf-8')
            // §12: no proxy or browser cache keeps a copy of the audit log.
            .header('cache-control', 'no-store')
            .header(
              'content-disposition',
              `attachment; filename="qualor-audit-${fileStamp(from)}-${fileStamp(to)}.jsonl"`,
            )
            // Fastify sends a stream as it is, past the serializer; the schema documents the body.
            .send(Readable.from(lines()) as unknown as string)
        );
      },
    );

    app.get(
      '/audit/head',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              409: 'AUDIT_CHAIN_ANCHOR_MALFORMED (the audit-chain setting must be restored)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'The newest audit event and the retention anchor',
          response: {
            200: z.object({
              seq: z.string().nullable(),
              hash: z.string().nullable(),
              occurredAt: z.string().nullable(),
              count: z.number().int(),
              anchor,
            }),
          },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        return ctx.audit.head();
      },
    );

    app.get(
      '/audit/verify',
      {
        config: {
          openapi: {
            problems: [429],
            problemDescriptions: { 429: 'A verification is already running (RATE_LIMITED)' },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'Verify the hash chain, or a range of it',
          querystring: z.strictObject({
            fromSeq: z.string().max(20).optional(),
            toSeq: z.string().max(20).optional(),
          }),
          response: {
            200: z.object({
              ok: z.boolean(),
              checked: z.number().int(),
              firstSeq: z.string().nullable(),
              lastSeq: z.string().nullable(),
              anchor,
              break: z
                .object({
                  seq: z.string(),
                  reason: z.enum(['hash_mismatch', 'prev_mismatch', 'gap', 'anchor_mismatch']),
                })
                .nullable(),
            }),
          },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        if (verifying) {
          throw ctx.access.problem(429, 'RATE_LIMITED', 'A verification is already running');
        }
        verifying = true;
        try {
          const { fromSeq, toSeq } = request.query;
          return await ctx.audit.verify({
            ...(fromSeq === undefined ? {} : { fromSeq }),
            ...(toSeq === undefined ? {} : { toSeq }),
          });
        } finally {
          verifying = false;
        }
      },
    );

    app.get(
      '/audit/settings',
      {
        schema: {
          tags: ['enterprise'],
          summary: 'Retention and the SIEM stream (never its secret)',
          response: { 200: settingsView },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        return ctx.audit.settings();
      },
    );

    app.put(
      '/audit/settings',
      {
        config: {
          openapi: {
            problems: [403, 409],
            problemDescriptions: {
              403: 'Authenticated but not allowed (FORBIDDEN, INSUFFICIENT_SCOPE, TOKEN_NOT_ALLOWED, SESSION_REQUIRED, CSRF_FAILED, PASSWORD_CHANGE_REQUIRED); FEATURE_NOT_LICENSED (a stream object needs audit-log.stream)',
              409: 'AUDIT_CHAIN_ANCHOR_MALFORMED (the audit-chain setting must be restored)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary:
            'Change the retention or the SIEM stream; a generated stream secret is returned once',
          body: settingsBody,
          response: { 200: settingsSaved },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        const { retentionDays, stream } = request.body;
        const { view, secret } = await ctx.audit.updateSettings(ctx.access.actor(request), {
          ...(retentionDays === undefined ? {} : { retentionDays }),
          ...(stream === undefined
            ? {}
            : {
                stream:
                  stream === null
                    ? null
                    : {
                        url: stream.url,
                        ...(stream.active === undefined ? {} : { active: stream.active }),
                        ...(stream.secret === undefined ? {} : { secret: stream.secret }),
                      },
              }),
        });
        return {
          ...view,
          stream: view.stream && { ...view.stream, ...(secret ? { secret } : {}) },
        };
      },
    );
  };
}

/**
 * rbac-audit.md §14.4: the SIEM stream's two routes, feature `audit-log.stream` (a registration of
 * its own, so core's guard answers 403 FEATURE_NOT_LICENSED naming it before a handler runs).
 * Instance admins only. Configuring the stream is `PUT /audit/settings` of {@link auditRoutes},
 * where core refuses a stream object without this feature.
 */
export function auditStreamRoutes(ctx: PluginContext): FastifyPluginAsync {
  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.post(
      '/audit/settings/stream/regenerate-secret',
      {
        config: {
          openapi: {
            problems: [404, 409],
            problemDescriptions: {
              404: 'No stream is configured',
              409: 'AUDIT_CHAIN_ANCHOR_MALFORMED (the audit-chain setting must be restored)',
            },
          },
        },
        schema: {
          tags: ['enterprise'],
          summary: "Replace the stream's secret with a generated one, returned once",
          response: { 200: z.object({ secret: z.string() }) },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        return { secret: await ctx.audit.regenerateStreamSecret(ctx.access.actor(request)) };
      },
    );

    app.post(
      '/audit/settings/stream/test',
      {
        config: {
          rateLimit: {
            max: STREAM_TESTS_PER_MINUTE,
            timeWindow: 60_000,
            // Authentication has run (an app-level onRequest hook): the key is the caller.
            keyGenerator: (request: FastifyRequest) => {
              try {
                return `audit-stream-test:${ctx.access.requireUser(request).user.id}`;
              } catch {
                return request.ip;
              }
            },
          },
          openapi: { problems: [429] },
        },
        schema: {
          tags: ['enterprise'],
          summary: 'Send one signed batch without events to the stream',
          response: {
            200: z.object({
              ok: z.boolean(),
              status: z.number().int().nullable(),
              excerpt: z.string().nullable(),
            }),
          },
        },
      },
      async (request) => {
        ctx.access.requireInstanceAdmin(request);
        return ctx.audit.testStream();
      },
    );
  };
}
