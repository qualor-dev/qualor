// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type { FastifyError, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { PluginContext } from '@qualor/server/plugin-contract';

/** sso-scim.md §12.1: a SCIM request body is at most 1 MiB. */
const SCIM_BODY_LIMIT = 1_048_576;
/** §12.1: the two request types; everything else is 415. */
const SCIM_REQUEST_TYPES = ['application/scim+json', 'application/json'];
/** §12.1: every SCIM answer, errors included (ruling SS7). */
const SCIM_CONTENT_TYPE = 'application/scim+json; charset=utf-8';
const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
/** What the parser hands core for a body that is not JSON; `ctx.scim.handle` answers 400 invalidSyntax. */
const INVALID_JSON = Symbol.for('qualor.scim.invalid-json');
const RFC_7644 = {
  url: 'https://www.rfc-editor.org/rfc/rfc7644',
  description: 'RFC 7644 (SCIM 2.0 protocol)',
};

const tokenView = z.strictObject({
  id: z.uuid(),
  connectionId: z.uuid(),
  name: z.string(),
  /** The token's first 12 characters, to recognise it. */
  prefix: z.string(),
  expiresAt: z.string().nullable(),
  lastUsedAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
  createdAt: z.string(),
});

/** A key that would reach an object's prototype (`__proto__`, `constructor.prototype`). */
class PoisonedJson extends Error {}

/**
 * JSON.parse that refuses prototype poisoning, as Fastify's own JSON parser does
 * (secure-json-parse, which the plugin cannot import): such a body is not valid SCIM.
 */
function parseScimJson(text: string): unknown {
  return JSON.parse(text, (key, value: unknown) => {
    if (key === '__proto__') throw new PoisonedJson();
    if (
      key === 'constructor' &&
      typeof value === 'object' &&
      value !== null &&
      Object.hasOwn(value, 'prototype')
    ) {
      throw new PoisonedJson();
    }
    return value;
  });
}

/** An RFC 7644 §3.12 error answer, for what fails before `ctx.scim.handle` runs. */
function scimError(status: 400 | 413 | 415, detail: string, scimType?: 'invalidSyntax') {
  return JSON.stringify({
    schemas: [SCIM_ERROR_SCHEMA],
    status: String(status),
    ...(scimType === undefined ? {} : { scimType }),
    detail,
  });
}

/** Fastify's own refusal of a request body (its content-type parser: FST_ERR_CTP_…). */
function bodyRefusal(error: FastifyError): { status: 400 | 413 | 415; detail: string } | null {
  if (typeof error.code !== 'string' || !error.code.startsWith('FST_ERR_CTP_')) return null;
  if (error.statusCode === 413) {
    return { status: 413, detail: 'The request body is larger than 1 MiB' };
  }
  if (error.statusCode === 415) {
    return { status: 415, detail: 'Send application/scim+json or application/json' };
  }
  return { status: 400, detail: 'The request body could not be read' };
}

/**
 * sso-scim.md §17.2: feature `scim`. The token routes need an instance admin (`ctx.access`); the
 * protocol routes under /scim/v2 are public for core's authentication (a SCIM token is not a
 * Qualor token) and `ctx.scim.handle` authenticates the SCIM bearer token itself: no session, no
 * CSRF. Core's feature guard answers 403 FEATURE_NOT_LICENSED (problem+json) while `scim` is
 * inactive (§11); every other answer under /scim/v2 is `application/scim+json` (ruling SS7).
 */
export function scimRoutes(ctx: PluginContext): FastifyPluginAsync {
  const admin = (request: FastifyRequest) => ctx.access.requireInstanceAdmin(request);

  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();
    const tagged = (summary: string) => ({ tags: ['enterprise'], summary });

    app.get(
      '/scim/tokens',
      {
        schema: {
          ...tagged('SCIM tokens (never the token itself)'),
          querystring: z.strictObject({ connectionId: z.uuid().optional() }),
          response: { 200: z.array(tokenView) },
        },
      },
      async (request) => {
        admin(request);
        return ctx.scim.listTokens(request.query.connectionId);
      },
    );

    app.post(
      '/scim/tokens',
      {
        config: {
          openapi: {
            problems: [404, 409],
            problemDescriptions: {
              404: 'The SSO connection does not exist',
              409: 'SCIM_TOKEN_LIMIT_REACHED (at most 5 active per connection); AUDIT_CHAIN_ANCHOR_MALFORMED: the audit-chain instance setting is malformed; an administrator must restore it',
            },
          },
        },
        schema: {
          ...tagged("Create a SCIM token for a connection: the answer's token is shown once"),
          body: z.strictObject({
            connectionId: z.uuid(),
            name: z.string().min(1).max(200),
            /** ISO 8601 with its offset; none (the default) never expires. */
            expiresAt: z.iso.datetime({ offset: true }).nullable().optional(),
          }),
          response: { 201: tokenView.extend({ token: z.string() }) },
        },
      },
      async (request, reply) => {
        admin(request);
        const { view, token } = await ctx.scim.createToken(ctx.access.actor(request), request.body);
        return reply.code(201).send({ ...view, token });
      },
    );

    app.delete(
      '/scim/tokens/:id',
      {
        schema: {
          ...tagged('Revoke a SCIM token (the row stays, revokedAt set)'),
          params: z.strictObject({ id: z.uuid() }),
          response: { 204: z.undefined().describe('Revoked') },
        },
      },
      async (request, reply) => {
        admin(request);
        await ctx.scim.revokeToken(ctx.access.actor(request), request.params.id);
        return reply.code(204).send();
      },
    );

    // ─── The SCIM protocol (§12): one wildcard route per method, core's handler ─────────────
    await plain.register(async (scim) => {
      // §12.1: only the two JSON types, at most 1 MiB; an empty body (a DELETE with a content
      // type, as Entra ID and Okta send it) is no body; a body that is not JSON goes to core as
      // a marker, which answers 400 invalidSyntax in SCIM.
      scim.removeAllContentTypeParsers();
      scim.addContentTypeParser(
        SCIM_REQUEST_TYPES,
        { parseAs: 'string', bodyLimit: SCIM_BODY_LIMIT },
        (_request, body, done) => {
          const text = typeof body === 'string' ? body : body.toString('utf8');
          if (text.trim() === '') {
            done(null, undefined);
            return;
          }
          try {
            done(null, parseScimJson(text));
          } catch {
            done(null, INVALID_JSON);
          }
        },
      );
      // A body Fastify refused before the handler (415, 413, a broken length) is still a SCIM
      // error. Everything else (core's feature guard's 403 included) goes on to core's handler.
      scim.setErrorHandler((error: FastifyError, _request, reply) => {
        const refusal = bodyRefusal(error);
        if (!refusal) throw error;
        return reply
          .code(refusal.status)
          .header('content-type', SCIM_CONTENT_TYPE)
          .header('cache-control', 'no-store')
          .send(
            scimError(
              refusal.status,
              refusal.detail,
              refusal.status === 400 ? 'invalidSyntax' : undefined,
            ),
          );
      });
      for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const) {
        scim.route({
          method,
          url: '/scim/v2/*',
          bodyLimit: SCIM_BODY_LIMIT,
          config: {
            public: true,
            openapi: {
              derived: false,
              problems: [403],
              problemDescriptions: {
                403: 'FEATURE_NOT_LICENSED: the licence does not list scim, or it lapsed (the one problem+json answer; the identity provider reports a provisioning failure)',
              },
            },
          },
          schema: {
            tags: ['enterprise'],
            summary: `SCIM 2.0 ${method} (ServiceProviderConfig, ResourceTypes, Schemas, Users, Groups)`,
            description:
              'The SCIM 2.0 service of one SSO connection: `Authorization: Bearer qlr_scim_…`. Requests are application/scim+json or application/json, at most 1 MiB; answers, errors included, are application/scim+json with the SCIM error schema (RFC 7644 §3.12). 1 200 requests a minute per token; after 60 failed authentications a minute from one address, its further failed authentications are answered 429 instead of 401 until the minute ends (a valid token from it proceeds); a write that conflicted with a concurrent one (a deadlock) is answered 503 with Retry-After, and changed nothing.',
            externalDocs: RFC_7644,
            security: [],
            produces: ['application/scim+json'],
            response: {
              default: z
                .unknown()
                .describe('A SCIM resource, list or error (application/scim+json)'),
            },
          },
          handler: (request, reply) => ctx.scim.handle(request, reply),
        });
      }
    });
  };
}
