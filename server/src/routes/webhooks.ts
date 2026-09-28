import { and, asc, count, desc, eq, gt, lt, sql } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { urlOrigin, type AuditAction, type AuditDetails } from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import { organizationRef, projectRefs } from '../audit/refs';
import {
  type AccessContext,
  accessOf,
  requireOrganizationAccess,
  requirePermission,
  requireUser,
} from '../auth/access';
import { grantInOrganization, memberOf, organizationFacts } from '../auth/facts';
import { organizationPermissions } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import { randomBase62 } from '../auth/tokens';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  memberships,
  organizations,
  projects,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound, ProblemError, validationFailed } from '../http/problem';
import { idParams, iso, isoOrNull, noContent, noNul, timestamp } from '../http/schemas';
import {
  createDelivery,
  STALLED_DELIVERY_MINUTES,
  WEBHOOK_EVENTS,
  WEBHOOK_SECRET_AAD,
  type WebhookEvent,
} from '../webhooks/deliveries';
import { webhookSettings, webhookUrlProblem } from '../webhooks/url';

type WebhookRow = typeof webhookSubscriptions.$inferSelect;
type DeliveryRow = typeof webhookDeliveries.$inferSelect;

/** A resource bound, not an edition limit: every analysis fans out to at most this many. */
export const MAX_WEBHOOKS_PER_ORGANIZATION = 50;

/**
 * Redelivery bounds, per webhook, so `redeliver` cannot turn the server into a request generator
 * against the target: a redelivery is refused (429 `REDELIVERY_LIMIT_REACHED`) while the webhook
 * has this many pending deliveries (each may retry up to 6 times over about an hour; one whose
 * next attempt is long overdue lost its job and is not counted, see STALLED_DELIVERY_MINUTES) ...
 */
export const MAX_PENDING_DELIVERIES_FOR_REDELIVERY = 5;
/**
 * ... or when this many redeliveries of it were created in the last hour. Deliveries the
 * ingestion stage creates are not counted: a busy project does not use up an admin's
 * redeliveries. A stage delivery is created in the transaction its analysis finishes in, so its
 * `created_at` is at most the payload's `finishedAt`; a redelivery copies that payload later.
 * A delivery whose payload has no `finishedAt` counts as a redelivery.
 */
export const MAX_RECENT_DELIVERIES_FOR_REDELIVERY = 100;
const REDELIVERY_RETRY_AFTER_SECONDS = 60;
/** An ISO 8601 UTC instant as `iso()` writes it, checked before a payload value is cast. */
const ISO_INSTANT = String.raw`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$`;

/** A generated secret: `whsec_` and 32 base62 characters (about 190 bits). */
function generateSecret(): string {
  return `whsec_${randomBase62(32)}`;
}

const webhookSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  projectId: z.uuid().nullable(),
  url: z.string(),
  events: z.array(z.enum(WEBHOOK_EVENTS)),
  active: z.boolean(),
  createdAt: timestamp,
  updatedAt: timestamp,
});
/** Returned by POST only: a generated secret is shown exactly once. */
const createdWebhookSchema = webhookSchema.extend({ secret: z.string().optional() });
/** Returned by regenerate-secret only: the new secret is shown exactly once. */
const regeneratedWebhookSchema = webhookSchema.extend({ secret: z.string() });

const deliverySchema = z.object({
  id: z.uuid(),
  event: z.enum(WEBHOOK_EVENTS),
  status: z.enum(['pending', 'succeeded', 'failed']),
  attempts: z.number().int(),
  responseCode: z.number().int().nullable(),
  responseExcerpt: z.string().nullable(),
  nextAttemptAt: timestamp.nullable(),
  createdAt: timestamp,
});

function webhookDto(row: WebhookRow): z.infer<typeof webhookSchema> {
  return {
    id: row.id,
    organizationId: row.organizationId,
    projectId: row.projectId,
    url: row.url,
    events: row.events as WebhookEvent[],
    active: row.active,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

function deliveryDto(row: DeliveryRow): z.infer<typeof deliverySchema> {
  return {
    id: row.id,
    event: row.event as WebhookEvent,
    status: row.status,
    attempts: row.attempts,
    responseCode: row.responseCode,
    responseExcerpt: row.responseExcerpt,
    nextAttemptAt: isoOrNull(row.nextAttemptAt),
    createdAt: iso(row.createdAt),
  };
}

/** `webhook.created` and `.deleted`: the URL by its origin only, never the secret. */
function webhookAudit(row: WebhookRow): AuditDetails<'webhook.created'> {
  return {
    origin: urlOrigin(row.url),
    projectId: row.projectId,
    events: [...row.events],
    active: row.active,
  };
}

/** The fields `webhook.updated` names (never their values). */
const WEBHOOK_FIELDS = ['url', 'secret', 'events', 'active'] as const;

const events = z
  .array(z.enum(WEBHOOK_EVENTS))
  .min(1)
  .max(WEBHOOK_EVENTS.length)
  .refine((list) => new Set(list).size === list.length, { message: 'Each event at most once' });
const secret = noNul(z.string().min(16).max(256));
const url = noNul(z.string().min(1).max(2_048));

/**
 * The webhook named in the path. Every webhook route is 🛡 (api.md §3): a missing webhook and one
 * of an organisation the caller does not belong to are the same 404 (one query, the membership
 * joined); a member who is not an admin gets 403.
 */
async function webhookFor(
  access: AccessContext,
  principal: UserPrincipal,
  id: string,
): Promise<WebhookRow> {
  const [row] = await access.db
    .select({
      webhook: webhookSubscriptions,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, webhookSubscriptions.organizationId),
    })
    .from(webhookSubscriptions)
    .leftJoin(memberships, memberOf(principal.user, webhookSubscriptions.organizationId))
    .where(eq(webhookSubscriptions.id, id));
  if (!row) throw notFound('Webhook');
  const permissions = organizationPermissions(organizationFacts(principal.user, row));
  requirePermission(principal, permissions, 'org.webhooks.manage', 'org.read', 'Webhook');
  return row.webhook;
}

export const webhookRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const key = encryptionKey(deps.config.secretKey);
  /**
   * rbac-audit.md §8, §9: one event about `webhook` in the change's transaction `tx`, in its
   * organisation (and its project when it has one); the target's label is the URL's origin.
   */
  const audit = async <A extends AuditAction>(
    tx: Executor,
    request: FastifyRequest,
    webhook: WebhookRow,
    action: A,
    details: AuditDetails<A>,
  ): Promise<void> => {
    if (!deps.audit.active()) return;
    const event = {
      action,
      organization: await organizationRef(tx, webhook.organizationId),
      project:
        webhook.projectId === null ? null : (await projectRefs(tx, webhook.projectId)).project,
      target: { type: 'webhook', id: webhook.id, label: urlOrigin(webhook.url) },
      details,
    } as AuditEventInput;
    await deps.audit.record(tx, actorOf(request), [event]);
  };

  /**
   * 422 on `body.url` unless the URL passes webhookUrlProblem under the instance settings; the
   * WHATWG-normalised form is what is stored (and later checked again and sent).
   */
  const checkedUrl = async (raw: string): Promise<string> => {
    const problem = webhookUrlProblem(raw, await webhookSettings(deps.db));
    if (problem) throw validationFailed([{ path: 'body.url', message: problem }]);
    return new URL(raw).href;
  };

  app.get(
    '/webhooks',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['webhooks'],
        summary: 'Webhooks of an organisation (org admins)',
        querystring: z.strictObject({ ...pageQuery, organizationId: z.uuid() }),
        response: { 200: pageSchema(webhookSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { organizationId, limit, cursor } = request.query;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.webhooks.manage',
      );
      const after = decodeCursor(cursor);
      const rows = await deps.db
        .select()
        .from(webhookSubscriptions)
        .where(
          and(
            eq(webhookSubscriptions.organizationId, organizationId),
            after ? gt(webhookSubscriptions.id, after) : undefined,
          ),
        )
        .orderBy(asc(webhookSubscriptions.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return { items: page.items.map(webhookDto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/webhooks',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['webhooks'],
        summary:
          'Create a webhook for an organisation or one of its projects; a generated secret is returned once',
        body: z.strictObject({
          organizationId: z.uuid(),
          projectId: z.uuid().nullable().optional(),
          url,
          secret: secret.optional(),
          events,
          active: z.boolean().optional(),
        }),
        response: { 201: createdWebhookSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const body = request.body;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        body.organizationId,
        'org.webhooks.manage',
      );
      const webhookUrl = await checkedUrl(body.url);
      const projectId = body.projectId ?? null;
      if (projectId !== null) {
        const [project] = await deps.db
          .select({ id: projects.id })
          .from(projects)
          .where(and(eq(projects.id, projectId), eq(projects.organizationId, body.organizationId)));
        if (!project) {
          throw validationFailed([
            { path: 'body.projectId', message: 'No project of this organisation has this id' },
          ]);
        }
      }
      const generated = body.secret === undefined ? generateSecret() : undefined;
      const plaintext = body.secret ?? generated ?? '';
      const created = await deps.db.transaction(async (tx) => {
        // Serialises concurrent creations for the organisation, so the bound below holds (NO KEY
        // UPDATE: foreign-key checks of unrelated inserts are not blocked).
        await tx
          .select({ id: organizations.id })
          .from(organizations)
          .where(eq(organizations.id, body.organizationId))
          .for('no key update');
        const [existing] = await tx
          .select({ n: count() })
          .from(webhookSubscriptions)
          .where(eq(webhookSubscriptions.organizationId, body.organizationId));
        if ((existing?.n ?? 0) >= MAX_WEBHOOKS_PER_ORGANIZATION) {
          throw conflict(
            'WEBHOOK_LIMIT_REACHED',
            `An organisation has at most ${MAX_WEBHOOKS_PER_ORGANIZATION} webhooks`,
          );
        }
        const row = first(
          await tx
            .insert(webhookSubscriptions)
            .values({
              organizationId: body.organizationId,
              projectId,
              url: webhookUrl,
              secretEnc: encryptSecret(key, plaintext, WEBHOOK_SECRET_AAD),
              events: [...body.events],
              active: body.active ?? true,
            })
            .returning(),
        );
        await audit(tx, request, row, 'webhook.created', webhookAudit(row));
        return row;
      });
      return reply.code(201).send({
        ...webhookDto(created),
        ...(generated === undefined ? {} : { secret: generated }),
      });
    },
  );

  app.get(
    '/webhooks/:id',
    {
      schema: {
        tags: ['webhooks'],
        summary: 'A webhook (never its secret)',
        params: idParams,
        response: { 200: webhookSchema },
      },
    },
    async (request) =>
      webhookDto(await webhookFor(accessOf(deps), requireUser(request), request.params.id)),
  );

  app.patch(
    '/webhooks/:id',
    {
      schema: {
        tags: ['webhooks'],
        summary: 'Change the URL, secret (to a provided value), events or active flag',
        params: idParams,
        body: z
          .strictObject({
            url: url.optional(),
            secret: secret.optional(),
            events: events.optional(),
            active: z.boolean().optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: webhookSchema },
      },
    },
    async (request) => {
      const webhook = await webhookFor(accessOf(deps), requireUser(request), request.params.id);
      const body = request.body;
      const webhookUrl = body.url === undefined ? undefined : await checkedUrl(body.url);
      const updated = await deps.db.transaction(async (tx) => {
        const [row] = await tx
          .update(webhookSubscriptions)
          .set({
            ...(webhookUrl === undefined ? {} : { url: webhookUrl }),
            ...(body.secret === undefined
              ? {}
              : { secretEnc: encryptSecret(key, body.secret, WEBHOOK_SECRET_AAD) }),
            ...(body.events === undefined ? {} : { events: [...body.events] }),
            ...(body.active === undefined ? {} : { active: body.active }),
          })
          .where(eq(webhookSubscriptions.id, webhook.id))
          .returning();
        if (!row) throw notFound('Webhook');
        // Names only: a secret sent is a change, its value never recorded (rbac-audit.md §8).
        const changed = WEBHOOK_FIELDS.filter((field) => {
          if (field === 'secret') return body.secret !== undefined;
          if (field === 'events') return row.events.join(',') !== webhook.events.join(',');
          return row[field] !== webhook[field];
        });
        if (changed.length > 0) await audit(tx, request, row, 'webhook.updated', { changed });
        return row;
      });
      return webhookDto(updated);
    },
  );

  app.post(
    '/webhooks/:id/regenerate-secret',
    {
      schema: {
        tags: ['webhooks'],
        summary: 'Replace the secret with a generated one, returned once in this response',
        params: idParams,
        response: { 200: regeneratedWebhookSchema },
      },
    },
    async (request) => {
      const webhook = await webhookFor(accessOf(deps), requireUser(request), request.params.id);
      const generated = generateSecret();
      const updated = await deps.db.transaction(async (tx) => {
        const [row] = await tx
          .update(webhookSubscriptions)
          .set({ secretEnc: encryptSecret(key, generated, WEBHOOK_SECRET_AAD) })
          .where(eq(webhookSubscriptions.id, webhook.id))
          .returning();
        if (!row) throw notFound('Webhook');
        await audit(tx, request, row, 'webhook.secret_regenerated', {});
        return row;
      });
      return { ...webhookDto(updated), secret: generated };
    },
  );

  app.delete(
    '/webhooks/:id',
    {
      schema: {
        tags: ['webhooks'],
        summary: 'Delete a webhook and its delivery history; pending attempts stop',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const webhook = await webhookFor(accessOf(deps), requireUser(request), request.params.id);
      await deps.db.transaction(async (tx) => {
        const [deleted] = await tx
          .delete(webhookSubscriptions)
          .where(eq(webhookSubscriptions.id, webhook.id))
          .returning();
        if (deleted) await audit(tx, request, deleted, 'webhook.deleted', webhookAudit(deleted));
      });
      return reply.code(204).send();
    },
  );

  app.get(
    '/webhooks/:id/deliveries',
    {
      schema: {
        tags: ['webhooks'],
        summary: 'Recent deliveries, newest first (kept 30 days)',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(deliverySchema) },
      },
    },
    async (request) => {
      const webhook = await webhookFor(accessOf(deps), requireUser(request), request.params.id);
      const before = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select()
        .from(webhookDeliveries)
        .where(
          and(
            eq(webhookDeliveries.subscriptionId, webhook.id),
            before ? lt(webhookDeliveries.id, before) : undefined,
          ),
        )
        .orderBy(desc(webhookDeliveries.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      return { items: page.items.map(deliveryDto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/webhooks/:id/deliveries/:deliveryId/redeliver',
    {
      config: { openapi: { problems: [404, 429] } },
      schema: {
        tags: ['webhooks'],
        summary:
          'Send a delivery again, as a new delivery with the same event and payload (bounded per webhook)',
        params: z.strictObject({ id: z.uuid(), deliveryId: z.uuid() }),
        response: { 202: deliverySchema },
      },
    },
    async (request, reply) => {
      const webhook = await webhookFor(accessOf(deps), requireUser(request), request.params.id);
      const redelivered = await deps.db.transaction(async (tx) => {
        // Serialises redeliveries of this webhook, so the bounds below hold under concurrency (NO
        // KEY UPDATE: ingestion's delivery inserts only take KEY SHARE through the foreign key).
        const [locked] = await tx
          .select({ id: webhookSubscriptions.id })
          .from(webhookSubscriptions)
          .where(eq(webhookSubscriptions.id, webhook.id))
          .for('no key update');
        if (!locked) throw notFound('Webhook');
        const [original] = await tx
          .select()
          .from(webhookDeliveries)
          .where(
            and(
              eq(webhookDeliveries.id, request.params.deliveryId),
              eq(webhookDeliveries.subscriptionId, webhook.id),
            ),
          );
        if (!original) throw notFound('Delivery');
        const bounds = await tx.execute<{ pending: number; recent: number }>(sql`
          SELECT
            (SELECT count(*)::int FROM (
               SELECT 1 FROM webhook_deliveries
                WHERE subscription_id = ${webhook.id} AND status = 'pending'
                  AND (next_attempt_at IS NULL
                       OR next_attempt_at >= now() - make_interval(mins => ${STALLED_DELIVERY_MINUTES}))
                LIMIT ${MAX_PENDING_DELIVERIES_FOR_REDELIVERY}) p) AS pending,
            (SELECT count(*)::int FROM (
               SELECT 1 FROM webhook_deliveries
                WHERE subscription_id = ${webhook.id} AND created_at > now() - interval '1 hour'
                  AND CASE WHEN payload ->> 'finishedAt' ~ ${ISO_INSTANT}
                           THEN created_at > (payload ->> 'finishedAt')::timestamptz + interval '1 second'
                           ELSE true END
                LIMIT ${MAX_RECENT_DELIVERIES_FOR_REDELIVERY}) r) AS recent`);
        const [counts] = bounds.rows;
        if (
          !counts ||
          counts.pending >= MAX_PENDING_DELIVERIES_FOR_REDELIVERY ||
          counts.recent >= MAX_RECENT_DELIVERIES_FOR_REDELIVERY
        ) {
          throw new ProblemError(
            429,
            'REDELIVERY_LIMIT_REACHED',
            `A webhook may have at most ${MAX_PENDING_DELIVERIES_FOR_REDELIVERY} pending deliveries, and ${MAX_RECENT_DELIVERIES_FOR_REDELIVERY} deliveries in the last hour, for a redelivery; retry later`,
            { headers: { 'retry-after': String(REDELIVERY_RETRY_AFTER_SECONDS) } },
          );
        }
        const id = await createDelivery(tx, {
          subscriptionId: webhook.id,
          event: original.event as WebhookEvent,
          payload: original.payload,
        });
        const created = first(
          await tx.select().from(webhookDeliveries).where(eq(webhookDeliveries.id, id)),
        );
        // The delivery the person asked to send again (the path's), and its event.
        await audit(tx, request, webhook, 'webhook.redelivered', {
          deliveryId: original.id,
          event: original.event,
        });
        return created;
      });
      return reply.code(202).send(deliveryDto(redelivered));
    },
  );
};
