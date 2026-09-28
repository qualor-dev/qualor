import { METRICS, resolveMetricKey } from '@qualor/shared';
import { and, asc, eq, gt, inArray } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { AuditAction, AuditDetails } from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import { organizationRef } from '../audit/refs';
import {
  type AccessContext,
  accessOf,
  requireOrganizationAccess,
  requirePermission,
  requireUser,
} from '../auth/access';
import { grantInOrganization, memberOf, organizationFacts } from '../auth/facts';
import { organizationPermissions, type OrganizationPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import { gateConditions, memberships, qualityGates } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound, validationFailed } from '../http/problem';
import { idParams, iso, noContent, noNul, timestamp } from '../http/schemas';

type GateRow = typeof qualityGates.$inferSelect;
type ConditionRow = typeof gateConditions.$inferSelect;

const conditionSchema = z.object({
  id: z.uuid(),
  metric: z.string(),
  operator: z.enum(['gt', 'lt']),
  threshold: z.number(),
});

const gateSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  name: z.string(),
  isDefault: z.boolean(),
  isBuiltin: z.boolean(),
  conditions: z.array(conditionSchema),
  createdAt: timestamp,
  updatedAt: timestamp,
});
type GateDto = z.infer<typeof gateSchema>;

const gateName = noNul(z.string().trim().min(1).max(100));
const conditionParams = z.strictObject({ id: z.uuid(), condId: z.uuid() });
const conditionBody = {
  metric: z.string().min(1).max(64),
  operator: z.enum(['gt', 'lt']),
  threshold: z.number(),
};

function conditionDto(c: ConditionRow): z.infer<typeof conditionSchema> {
  return { id: c.id, metric: c.metricKey, operator: c.operator, threshold: c.threshold };
}

async function gateDtos(db: Executor, rows: readonly GateRow[]): Promise<GateDto[]> {
  if (rows.length === 0) return [];
  const conditions = await db
    .select()
    .from(gateConditions)
    .where(
      inArray(
        gateConditions.gateId,
        rows.map((r) => r.id),
      ),
    )
    .orderBy(asc(gateConditions.metricKey));
  return rows.map((g) => ({
    id: g.id,
    organizationId: g.organizationId,
    name: g.name,
    isDefault: g.isDefault,
    isBuiltin: g.isBuiltin,
    conditions: conditions.filter((c) => c.gateId === g.id).map(conditionDto),
    createdAt: iso(g.createdAt),
    updatedAt: iso(g.updatedAt),
  }));
}

/**
 * The gate named in the path. A missing gate and a gate of an organisation the caller does not
 * belong to are the same 404 (`Quality gate not found`), answered by one query either way (the
 * membership is joined), so neither the answer nor its timing reveals that another
 * organisation's gate exists. Then rbac-audit.md §3.3: 403 when visible but the caller's role or
 * token lacks `permission`.
 */
async function gateFor(
  access: AccessContext,
  principal: UserPrincipal,
  id: string,
  permission: OrganizationPermission,
): Promise<GateRow> {
  const [row] = await access.db
    .select({
      gate: qualityGates,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, qualityGates.organizationId),
    })
    .from(qualityGates)
    .leftJoin(memberships, memberOf(principal.user, qualityGates.organizationId))
    .where(eq(qualityGates.id, id));
  if (!row) throw notFound('Quality gate');
  const permissions = organizationPermissions(organizationFacts(principal.user, row));
  requirePermission(principal, permissions, permission, 'org.read', 'Quality gate');
  return row.gate;
}

function requireEditable(gate: GateRow): void {
  if (gate.isBuiltin) {
    throw conflict('BUILTIN_READ_ONLY', 'The built-in gate is read-only; copy it to change it');
  }
}

/**
 * gates.md §4: only catalog metrics; rating thresholds are 1–5, percentages 0–100 (ruling G3),
 * counts 0–MAX_SAFE_INTEGER. Together with `gate_conditions_gate_metric` (one condition per metric
 * and gate) this bounds a gate to at most `allMetricKeys().length` conditions.
 */
function validateCondition(metric: string, threshold: number, thresholdSent = true): void {
  const resolved = resolveMetricKey(metric);
  if (!resolved) {
    throw validationFailed([{ path: 'body.metric', message: `Unknown metric: ${metric}` }]);
  }
  const range =
    resolved.definition.type === 'rating'
      ? [1, 5]
      : resolved.definition.type === 'percent'
        ? [0, 100]
        : [0, Number.MAX_SAFE_INTEGER];
  const [lo = 0, hi = 0] = range;
  if (threshold < lo || threshold > hi) {
    throw validationFailed([
      {
        path: 'body.threshold',
        message: thresholdSent
          ? `Must be between ${lo} and ${hi} for ${metric}`
          : `The current threshold ${threshold} is not between ${lo} and ${hi} for ${metric}; send a threshold with the new metric`,
      },
    ]);
  }
}

/**
 * A condition as its audit events show it (rbac-audit.md §8). The threshold is written as text:
 * canonical JSON holds integers only, and a threshold may be a decimal (80.5).
 */
function conditionAudit(c: ConditionRow): {
  metric: string;
  operator: 'gt' | 'lt';
  threshold: string;
} {
  return { metric: c.metricKey, operator: c.operator, threshold: String(c.threshold) };
}

function conditionConflict(err: unknown): never {
  if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) {
    throw conflict('CONDITION_EXISTS', 'The gate already has a condition on this metric');
  }
  throw err;
}

export const gateRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const one = async (gate: GateRow): Promise<GateDto> => first(await gateDtos(deps.db, [gate]));
  /** rbac-audit.md §8, §9: one event about `gate`, written in the change's transaction `tx`. */
  const audit = async <A extends AuditAction>(
    tx: Executor,
    request: FastifyRequest,
    gate: Pick<GateRow, 'id' | 'organizationId' | 'name'>,
    action: A,
    details: AuditDetails<A>,
  ): Promise<void> => {
    if (!deps.audit.active()) return;
    const event = {
      action,
      organization: await organizationRef(tx, gate.organizationId),
      target: { type: 'quality_gate', id: gate.id, label: gate.name },
      details,
    } as AuditEventInput;
    await deps.audit.record(tx, actorOf(request), [event]);
  };

  app.get(
    '/metrics',
    {
      schema: {
        tags: ['gates'],
        summary: 'The metric catalog',
        response: {
          200: z.array(
            z.object({
              key: z.string(),
              name: z.string(),
              type: z.enum(['int', 'float', 'percent', 'rating']),
              direction: z.enum(['lower_is_better', 'higher_is_better', 'none']),
              scopes: z.array(z.enum(['overall', 'new'])),
              domain: z.string(),
            }),
          ),
        },
      },
    },
    async (request) => {
      requireUser(request);
      return METRICS.map((m) => ({ ...m, scopes: [...m.scopes] }));
    },
  );

  app.get(
    '/quality-gates',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['gates'],
        summary: 'Quality gates of an organisation',
        querystring: z.strictObject({ ...pageQuery, organizationId: z.uuid() }),
        response: { 200: pageSchema(gateSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { organizationId, limit, cursor } = request.query;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.read');
      const after = decodeCursor(cursor);
      const rows = await deps.db
        .select()
        .from(qualityGates)
        .where(
          and(
            eq(qualityGates.organizationId, organizationId),
            after ? gt(qualityGates.id, after) : undefined,
          ),
        )
        .orderBy(asc(qualityGates.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return { items: await gateDtos(deps.db, page.items), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/quality-gates',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['gates'],
        summary: 'Create an empty quality gate',
        body: z.strictObject({ organizationId: z.uuid(), name: gateName }),
        response: { 201: gateSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        request.body.organizationId,
        'org.gates.manage',
      );
      const gate = await deps.db.transaction(async (tx) => {
        const row = first(
          await tx
            .insert(qualityGates)
            .values({ organizationId: request.body.organizationId, name: request.body.name })
            .returning(),
        );
        await audit(tx, request, row, 'quality_gate.created', { name: row.name });
        return row;
      });
      return reply.code(201).send(await one(gate));
    },
  );

  app.get(
    '/quality-gates/:id',
    {
      schema: {
        tags: ['gates'],
        summary: 'A quality gate and its conditions',
        params: idParams,
        response: { 200: gateSchema },
      },
    },
    async (request) =>
      one(await gateFor(accessOf(deps), requireUser(request), request.params.id, 'org.read')),
  );

  app.patch(
    '/quality-gates/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['gates'],
        summary: 'Rename a quality gate (built-in: 409 BUILTIN_READ_ONLY)',
        params: idParams,
        body: z.strictObject({ name: gateName }),
        response: { 200: gateSchema },
      },
    },
    async (request) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      requireEditable(gate);
      const updated = await deps.db.transaction(async (tx) => {
        const [row] = await tx
          .update(qualityGates)
          .set({ name: request.body.name })
          .where(eq(qualityGates.id, gate.id))
          .returning();
        // Deleted concurrently, between the check above and this update.
        if (!row) throw notFound('Quality gate');
        if (row.name !== gate.name) {
          await audit(tx, request, row, 'quality_gate.updated', { from: gate.name, to: row.name });
        }
        return row;
      });
      return one(updated);
    },
  );

  app.delete(
    '/quality-gates/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['gates'],
        summary:
          'Delete a quality gate; its projects fall back to the default gate (built-in: 409)',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      requireEditable(gate);
      await deps.db.transaction(async (tx) => {
        const [deleted] = await tx
          .delete(qualityGates)
          .where(eq(qualityGates.id, gate.id))
          .returning();
        if (deleted) {
          await audit(tx, request, deleted, 'quality_gate.deleted', { name: deleted.name });
        }
      });
      return reply.code(204).send();
    },
  );

  app.post(
    '/quality-gates/:id/copy',
    {
      schema: {
        tags: ['gates'],
        summary: 'Copy a quality gate (the way to edit the built-in one)',
        params: idParams,
        body: z.strictObject({ name: gateName }),
        response: { 201: gateSchema },
      },
    },
    async (request, reply) => {
      const source = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      const copy = await deps.db.transaction(async (tx) => {
        const gate = first(
          await tx
            .insert(qualityGates)
            .values({ organizationId: source.organizationId, name: request.body.name })
            .returning(),
        );
        const conditions = await tx
          .select()
          .from(gateConditions)
          .where(eq(gateConditions.gateId, source.id));
        if (conditions.length > 0) {
          await tx.insert(gateConditions).values(
            conditions.map((c) => ({
              gateId: gate.id,
              metricKey: c.metricKey,
              operator: c.operator,
              threshold: c.threshold,
            })),
          );
        }
        await audit(tx, request, gate, 'quality_gate.copied', {
          sourceId: source.id,
          name: gate.name,
        });
        return gate;
      });
      return reply.code(201).send(await one(copy));
    },
  );

  app.post(
    '/quality-gates/:id/set-default',
    {
      schema: {
        tags: ['gates'],
        summary: "Make this the organisation's default gate",
        params: idParams,
        response: { 200: gateSchema },
      },
    },
    async (request) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      const updated = await deps.db.transaction(async (tx) => {
        // Lock the organisation's gates first (in id order, so lockers never deadlock), so two
        // concurrent set-default calls serialise instead of tripping quality_gates_one_default.
        await tx
          .select({ id: qualityGates.id })
          .from(qualityGates)
          .where(eq(qualityGates.organizationId, gate.organizationId))
          .orderBy(asc(qualityGates.id))
          .for('update');
        await tx
          .update(qualityGates)
          .set({ isDefault: false })
          .where(
            and(
              eq(qualityGates.organizationId, gate.organizationId),
              eq(qualityGates.isDefault, true),
            ),
          );
        const [row] = await tx
          .update(qualityGates)
          .set({ isDefault: true })
          .where(eq(qualityGates.id, gate.id))
          .returning();
        if (!row) throw notFound('Quality gate');
        await audit(tx, request, row, 'quality_gate.default_set', { name: row.name });
        return row;
      });
      return one(updated);
    },
  );

  app.post(
    '/quality-gates/:id/conditions',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['gates'],
        summary: 'Add a condition (a catalog metric, gt or lt, a threshold)',
        params: idParams,
        body: z.strictObject(conditionBody),
        response: { 201: conditionSchema },
      },
    },
    async (request, reply) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      requireEditable(gate);
      const { metric, operator, threshold } = request.body;
      validateCondition(metric, threshold);
      try {
        const row = await deps.db.transaction(async (tx) => {
          const added = first(
            await tx
              .insert(gateConditions)
              .values({ gateId: gate.id, metricKey: metric, operator, threshold })
              .returning(),
          );
          await audit(tx, request, gate, 'quality_gate.condition_added', {
            conditionId: added.id,
            ...conditionAudit(added),
          });
          return added;
        });
        return reply.code(201).send(conditionDto(row));
      } catch (err) {
        return conditionConflict(err);
      }
    },
  );

  app.patch(
    '/quality-gates/:id/conditions/:condId',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['gates'],
        summary: 'Change a condition',
        params: conditionParams,
        body: z
          .strictObject({
            metric: conditionBody.metric.optional(),
            operator: conditionBody.operator.optional(),
            threshold: conditionBody.threshold.optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: conditionSchema },
      },
    },
    async (request) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      requireEditable(gate);
      const [current] = await deps.db
        .select()
        .from(gateConditions)
        .where(
          and(eq(gateConditions.id, request.params.condId), eq(gateConditions.gateId, gate.id)),
        );
      if (!current) throw notFound('Condition');
      const metric = request.body.metric ?? current.metricKey;
      const threshold = request.body.threshold ?? current.threshold;
      validateCondition(metric, threshold, request.body.threshold !== undefined);
      let row: ConditionRow | undefined;
      try {
        row = await deps.db.transaction(async (tx) => {
          const [changed] = await tx
            .update(gateConditions)
            .set({
              metricKey: metric,
              operator: request.body.operator ?? current.operator,
              threshold,
            })
            .where(eq(gateConditions.id, current.id))
            .returning();
          if (!changed) return undefined;
          const from = conditionAudit(current);
          const to = conditionAudit(changed);
          if (JSON.stringify(from) !== JSON.stringify(to)) {
            await audit(tx, request, gate, 'quality_gate.condition_updated', {
              conditionId: changed.id,
              metric: to.metric,
              from,
              to,
            });
          }
          return changed;
        });
      } catch (err) {
        return conditionConflict(err);
      }
      // Deleted concurrently (the condition, or its gate), between the read above and the update.
      if (!row) throw notFound('Condition');
      return conditionDto(row);
    },
  );

  app.delete(
    '/quality-gates/:id/conditions/:condId',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['gates'],
        summary: 'Remove a condition',
        params: conditionParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const gate = await gateFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'org.gates.manage',
      );
      requireEditable(gate);
      const deleted = await deps.db.transaction(async (tx) => {
        const [removed] = await tx
          .delete(gateConditions)
          .where(
            and(eq(gateConditions.id, request.params.condId), eq(gateConditions.gateId, gate.id)),
          )
          .returning();
        if (removed) {
          await audit(tx, request, gate, 'quality_gate.condition_removed', {
            conditionId: removed.id,
            ...conditionAudit(removed),
          });
        }
        return removed;
      });
      if (!deleted) throw notFound('Condition');
      return reply.code(204).send();
    },
  );
};
