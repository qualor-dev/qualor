import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { Executor } from '../db/client';
import { actorOf } from '../audit/recorder';
import { requireInstanceAdmin, requireSession } from '../auth/access';
import { forbidden, notFound, validationFailed } from '../http/problem';
import { idParams, noContent, timestamp } from '../http/schemas';
import {
  decide,
  listGrants,
  pendingRequestFor,
  revokeGrant,
  userGrant,
  type GrantView,
  type RevokedGrant,
} from '../oauth/grants';
import { MCP_SCOPES } from '../oauth/tokens';
import { mcpUrls } from '../oauth/urls';

const scope = z.enum(MCP_SCOPES);
const pendingSchema = z.object({
  id: z.uuid(),
  client: z.object({
    clientId: z.string(),
    name: z.string(),
    source: z.enum(['cimd', 'dcr']),
    logoUri: z.string().nullable(),
    clientUri: z.string().nullable(),
    redirectTarget: z.string(),
    redirectUri: z.string(),
  }),
  scopes: z.array(scope),
  expiresAt: timestamp,
  coveredByGrant: z.boolean(),
});

/** Spec §6 step 6: what the consent screen reads and answers; a browser session only. */
export const oauthConsentRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const issuer = () => mcpUrls(deps.config.publicUrl)?.issuer ?? null;

  /**
   * Reading binds the request to the caller: the first signed-in user to open it is the only one
   * who can see or answer it afterwards (intended, spec §6 step 5).
   */
  app.get(
    '/oauth/requests/:id',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['oauth'],
        summary: 'A pending OAuth authorization request',
        params: idParams,
        response: { 200: pendingSchema },
      },
    },
    async (request) => {
      const principal = requireSession(request);
      if (!issuer()) throw notFound('Authorization request');
      const view = await pendingRequestFor(deps.db, request.params.id, principal.user.id);
      if (!view) throw notFound('Authorization request');
      return { ...view, expiresAt: view.expiresAt.toISOString() };
    },
  );

  app.post(
    '/oauth/requests/:id/decision',
    {
      config: {
        openapi: {
          problems: [404],
          problemDescriptions: {
            403: 'CLIENT_NOT_ALLOWED: the administrator no longer allows this client',
            422: 'Validation failed (VALIDATION_FAILED; errors[] names each field), also when body.scopes names a scope the client did not ask for',
          },
        },
      },
      schema: {
        tags: ['oauth'],
        summary: 'Approve or deny a pending OAuth authorization request',
        params: idParams,
        body: z.discriminatedUnion('decision', [
          z.strictObject({ decision: z.literal('approve'), scopes: z.array(scope).min(1).max(2) }),
          z.strictObject({ decision: z.literal('deny') }),
        ]),
        response: { 200: z.object({ redirectTo: z.string() }) },
      },
    },
    async (request) => {
      const principal = requireSession(request);
      const iss = issuer();
      if (!iss) throw notFound('Authorization request');
      const body = request.body;
      const result = await decide(
        deps.db,
        {
          requestId: request.params.id,
          userId: principal.user.id,
          decision:
            body.decision === 'approve'
              ? { approve: true, scopes: body.scopes }
              : { approve: false },
          issuer: iss,
        },
        {
          // In the grant's transaction: the event commits or rolls back with it.
          onGrantChange: (tx, grant) =>
            deps.audit.record(tx, actorOf(request), [
              {
                action: 'oauth.grant_created',
                target: { type: 'oauth_grant', id: grant.id, label: grant.clientName },
                details: {
                  clientId: grant.clientId,
                  clientName: grant.clientName,
                  scopes: grant.scopes,
                },
              },
            ]),
          // An idle grant the approval replaces: the user's own approval ended it, hence 'user'.
          onIdleRevoked: (tx, grant) =>
            deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
              {
                action: 'oauth.grant_revoked',
                target: { type: 'oauth_grant', id: grant.id, label: grant.clientName },
                details: { clientId: grant.clientId, reason: 'user' },
              },
            ]),
        },
      );
      if (!result.ok && result.reason === 'scope_not_requested') {
        throw validationFailed([
          { path: 'body.scopes', message: 'Only the scopes the client asked for' },
        ]);
      }
      if (!result.ok && result.reason === 'client_not_allowed') {
        throw forbidden('CLIENT_NOT_ALLOWED', 'The administrator no longer allows this client');
      }
      if (!result.ok) throw notFound('Authorization request');
      return { redirectTo: result.redirectTo };
    },
  );

  const grantSchema = z.object({
    id: z.uuid(),
    client: z.object({
      clientId: z.string(),
      name: z.string(),
      source: z.enum(['cimd', 'dcr']),
      logoUri: z.string().nullable(),
      clientUri: z.string().nullable(),
    }),
    scopes: z.array(scope),
    createdAt: timestamp,
    lastUsedAt: timestamp.nullable(),
  });
  const grantsResponse = z.object({ items: z.array(grantSchema) });
  const dto = (g: GrantView) => ({
    ...g,
    createdAt: g.createdAt.toISOString(),
    lastUsedAt: g.lastUsedAt?.toISOString() ?? null,
  });

  /**
   * Revokes the user's live grant; `record` runs in the same transaction, so the event commits
   * with the revocation. 404 when the user has no such grant.
   */
  const revoke = async (
    userId: string,
    grantId: string,
    by: string,
    record: (tx: Executor, grant: RevokedGrant) => Promise<void>,
  ) => {
    const revoked = await deps.db.transaction(async (tx) => {
      const grant = await userGrant(tx, userId, grantId);
      if (!grant || !(await revokeGrant(tx, grant.id, by))) return false;
      await record(tx, grant);
      return true;
    });
    if (!revoked) throw notFound('Connected app');
  };
  const revokedEvent = (grant: RevokedGrant, reason: 'user' | 'admin') => ({
    action: 'oauth.grant_revoked' as const,
    target: { type: 'oauth_grant' as const, id: grant.id, label: grant.name },
    details: { clientId: grant.clientId, reason },
  });

  app.get(
    '/me/oauth-grants',
    {
      schema: {
        tags: ['oauth'],
        summary: 'The apps connected to your account through OAuth (MCP clients)',
        response: { 200: grantsResponse },
      },
    },
    async (request) => {
      const principal = requireSession(request);
      return { items: (await listGrants(deps.db, principal.user.id)).map(dto) };
    },
  );

  app.delete(
    '/me/oauth-grants/:id',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['oauth'],
        summary: 'Disconnect an app: its tokens stop at once',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireSession(request);
      await revoke(principal.user.id, request.params.id, principal.user.id, (tx, grant) =>
        deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
          revokedEvent(grant, 'user'),
        ]),
      );
      return reply.code(204).send();
    },
  );

  app.get(
    '/users/:id/oauth-grants',
    {
      schema: {
        tags: ['oauth'],
        summary: 'A user’s connected apps',
        params: idParams,
        response: { 200: grantsResponse },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      return { items: (await listGrants(deps.db, request.params.id)).map(dto) };
    },
  );

  app.delete(
    '/users/:id/oauth-grants/:grantId',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['oauth'],
        summary: 'Disconnect one of a user’s apps',
        params: z.strictObject({ id: z.uuid(), grantId: z.uuid() }),
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const admin = requireInstanceAdmin(request);
      await revoke(request.params.id, request.params.grantId, admin.user.id, (tx, grant) =>
        deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
          revokedEvent(grant, 'admin'),
        ]),
      );
      return reply.code(204).send();
    },
  );
};
