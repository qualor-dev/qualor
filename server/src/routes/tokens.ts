import { and, asc, eq, gt, isNull } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { requireSession, requireUser } from '../auth/access';
import { generateToken } from '../auth/tokens';
import { first } from '../db/rows';
import { apiTokens, TOKEN_SCOPES } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { notFound } from '../http/problem';
import {
  createdTokenSchema,
  expiresAtFrom,
  idParams,
  noContent,
  text,
  tokenDto,
  tokenSchema,
} from '../http/schemas';

const createTokenBody = z.strictObject({
  name: text(100),
  scopes: z
    .array(z.enum(TOKEN_SCOPES))
    .min(1)
    .max(TOKEN_SCOPES.length)
    .refine((s) => new Set(s).size === s.length, { message: 'Scopes must be unique' }),
  expiresInDays: z.number().int().min(1).max(3_650).optional(),
});

export const tokenRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/tokens',
    {
      schema: {
        tags: ['tokens'],
        summary: 'Your personal access tokens',
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(tokenSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select()
        .from(apiTokens)
        .where(
          and(
            eq(apiTokens.kind, 'personal'),
            eq(apiTokens.userId, principal.user.id),
            isNull(apiTokens.revokedAt),
            after ? gt(apiTokens.id, after) : undefined,
          ),
        )
        .orderBy(asc(apiTokens.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      return { items: page.items.map(tokenDto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/tokens',
    {
      schema: {
        tags: ['tokens'],
        summary: 'Create a personal access token (returned once)',
        body: createTokenBody,
        response: { 201: createdTokenSchema },
      },
    },
    async (request, reply) => {
      // Ruling R10: only a browser session may mint tokens, so a token can never widen itself.
      const principal = requireSession(request);
      const generated = generateToken('personal');
      const row = await deps.db.transaction(async (tx) => {
        const created = first(
          await tx
            .insert(apiTokens)
            .values({
              kind: 'personal',
              userId: principal.user.id,
              name: request.body.name,
              prefix: generated.prefix,
              secretHash: generated.secretHash,
              scopes: request.body.scopes,
              expiresAt: expiresAtFrom(request.body.expiresInDays),
              createdBy: principal.user.id,
            })
            .returning(),
        );
        // rbac-audit.md §8: the name, the public prefix and the scopes, never the token or its hash.
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'token.created',
            target: { type: 'token', id: created.id, label: created.name },
            details: {
              name: created.name,
              prefix: created.prefix,
              scopes: [...created.scopes],
              expiresAt: created.expiresAt?.toISOString() ?? null,
            },
          },
        ]);
        return created;
      });
      return reply.code(201).send({ ...tokenDto(row), token: generated.token });
    },
  );

  app.delete(
    '/tokens/:id',
    {
      schema: {
        tags: ['tokens'],
        summary: 'Revoke one of your tokens',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      // Revoking is a mutation, not a read: a read-only PAT must not be able to revoke its
      // owner's other tokens (scope ∩ role — the token's rights are never wider than its scope).
      const principal = requireUser(request, 'write');
      const revoked = await deps.db.transaction(async (tx) => {
        const rows = await tx
          .update(apiTokens)
          .set({ revokedAt: new Date() })
          .where(
            and(
              eq(apiTokens.id, request.params.id),
              eq(apiTokens.kind, 'personal'),
              eq(apiTokens.userId, principal.user.id),
              isNull(apiTokens.revokedAt),
            ),
          )
          .returning({ id: apiTokens.id, name: apiTokens.name, prefix: apiTokens.prefix });
        const [token] = rows;
        if (token) {
          // rbac-audit.md §10.2.1: a revocation is never blocked by a malformed audit anchor.
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            {
              action: 'token.revoked',
              target: { type: 'token', id: token.id, label: token.name },
              details: { name: token.name, prefix: token.prefix },
            },
          ]);
        }
        return rows;
      });
      if (revoked.length === 0) throw notFound('Token');
      return reply.code(204).send();
    },
  );
};
