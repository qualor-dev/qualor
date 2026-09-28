// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type { FastifyError, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type {
  IdentityView,
  PluginContext,
  SsoConnectionView,
  SsoGroupMappingView,
} from '@qualor/server/plugin-contract';

/** sso-scim.md §7.3: a start, 30 a minute per address. */
const STARTS_PER_MINUTE = 30;
/** §7.3: a link, 10 a minute per user. */
const LINKS_PER_MINUTE = 10;
/** §7.4: the ACS and the finish step, 60 a minute per address (each refusal writes an audit row). */
const FINISHES_PER_MINUTE = 60;
/** the 409 of disabling or deleting the last enabled connection. */
const LAST_CONNECTION_TEXT =
  'LAST_SSO_CONNECTION (password sign-in is limited to break-glass administrators and this is the last enabled connection)';
/** sso-scim.md §4.4: a second enabled connection without `sso.multi`. */
const MULTI_TEXT =
  'SSO_MULTI_NOT_LICENSED (without sso.multi, only one connection may be enabled: another one is)';
const MINUTE_MS = 60_000;
/** §6: the ACS form, at most 512 KiB (the SAMLResponse is base64 of a signed XML document). */
const ACS_BODY_LIMIT = 524_288;
/** §7.7: where a browser flow that is rate-limited ends. */
const RATE_LIMITED_LOCATION = '/login?sso_error=rate_limited';

/**
 * Every value of a core union, and only those: a value core adds (or drops) fails the type check
 * here, so a strict response schema never refuses a value core can produce.
 */
function allOf<T extends string>() {
  return <const A extends readonly T[]>(
    values: A & ([Exclude<T, A[number]>] extends [never] ? unknown : never),
  ): A => values;
}

type SamlView = NonNullable<SsoConnectionView['saml']>;
type OidcView = NonNullable<SsoConnectionView['oidc']>;
const PROTOCOLS = allOf<SsoConnectionView['protocol']>()(['oidc', 'saml']);
const GROUP_SOURCES = allOf<SsoConnectionView['groupSource']>()(['none', 'claims', 'scim']);
const CLIENT_AUTH = allOf<OidcView['clientAuth']>()(['client_secret_basic', 'client_secret_post']);
const NAME_ID_FORMATS = allOf<SamlView['nameIdFormat']>()([
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
]);
const LINK_METHODS = allOf<IdentityView['linkedBy']>()([
  'jit',
  'verified_email',
  'user',
  'scim',
  'scim_match',
]);
const ROLES = allOf<SsoGroupMappingView['role']>()(['admin', 'project_admin', 'member', 'viewer']);

const params = z.strictObject({ id: z.uuid() });
/** A browser flow's connection id: anything but a known connection ends at the login page (§7.3). */
const flowParams = z.strictObject({ id: z.string() });
const userParams = z.strictObject({ userId: z.uuid() });
const identityParams = z.strictObject({ identityId: z.uuid() });
const userIdentityParams = z.strictObject({ userId: z.uuid(), identityId: z.uuid() });

// ─── The bodies (spec §4; core checks every value again, with the field's path) ─────────────

const claimName = z.string().min(1).max(128);
const claimsInput = z.strictObject({
  username: claimName.nullable().optional(),
  email: claimName.nullable().optional(),
  displayName: claimName.nullable().optional(),
  groups: claimName.nullable().optional(),
});
const requiredClaim = z.strictObject({ claim: claimName, value: z.string().min(1).max(255) });
const url = z.string().min(1).max(2_048);
const pem = z.string().min(1).max(16_384);

const oidcInput = z.strictObject({
  issuer: url,
  clientId: z.string().min(1).max(255),
  /** Write-only: required on create, and again when the issuer changes. */
  clientSecret: z.string().min(1).max(1_024).optional(),
  clientAuth: z.enum(CLIENT_AUTH).optional(),
  scopes: z.array(z.string().min(1).max(128)).min(1).max(20).optional(),
  userinfo: z.boolean().optional(),
});
const samlInput = z.strictObject({
  idpEntityId: z.string().min(1).max(1_024),
  idpSsoUrl: url,
  idpCertificates: z.array(pem).min(1).max(3),
  metadataUrl: url.nullable().optional(),
  nameIdFormat: z.enum(NAME_ID_FORMATS).optional(),
  emailVerified: z.boolean().optional(),
  wantResponseSigned: z.boolean().optional(),
  /** Write-only: an unencrypted PKCS#8 PEM RSA key of 2048–4096 bits; needs `spCertificate`. */
  spKey: pem.optional(),
  /** `null` on a PATCH removes the SP key pair. */
  spCertificate: pem.nullable().optional(),
});
const commonInput = {
  enabled: z.boolean().optional(),
  jit: z.boolean().optional(),
  linkByEmail: z.boolean().optional(),
  groupSource: z.enum(GROUP_SOURCES).optional(),
  requiredClaims: z.array(requiredClaim).max(5).optional(),
  claims: claimsInput.optional(),
};
const connectionName = z.string().min(1).max(64);
const connectionInput = z.strictObject({
  name: connectionName,
  protocol: z.enum(PROTOCOLS),
  ...commonInput,
  oidc: oidcInput.optional(),
  saml: samlInput.optional(),
});
/** Any field but `protocol` (fixed at creation); the protocol's fields merge with the stored ones. */
const connectionPatch = z.strictObject({
  name: connectionName.optional(),
  ...commonInput,
  oidc: oidcInput.partial().optional(),
  saml: samlInput.partial().optional(),
});

const mappingInput = z.strictObject({
  group: z.string().min(1).max(510),
  organizationId: z.uuid(),
  projectId: z.uuid().nullable(),
  role: z.enum(ROLES),
});
const signInSettingsInput = z.strictObject({
  passwordSignIn: z.enum(['everyone', 'break_glass_only']),
  breakGlassUserIds: z.array(z.uuid()).max(10),
});

// ─── The answers: exactly the core types' fields, strict (a secret can never be in one) ──────

const certificateView = z.strictObject({
  pem: z.string(),
  sha256: z.string(),
  notAfter: z.string(),
  expired: z.boolean(),
});
const connectionView = z.strictObject({
  id: z.uuid(),
  name: z.string(),
  protocol: z.enum(PROTOCOLS),
  enabled: z.boolean(),
  /** sso-scim.md §4.4: enabled and signing people in (without sso.multi, the oldest enabled). */
  inEffect: z.boolean(),
  configValid: z.boolean(),
  jit: z.boolean(),
  linkByEmail: z.boolean(),
  groupSource: z.enum(GROUP_SOURCES),
  requiredClaims: z.array(z.strictObject({ claim: z.string(), value: z.string() })),
  claims: z.strictObject({
    username: z.string().nullable(),
    email: z.string().nullable(),
    displayName: z.string().nullable(),
    groups: z.string().nullable(),
  }),
  oidc: z
    .strictObject({
      issuer: z.string(),
      clientId: z.string(),
      clientAuth: z.enum(CLIENT_AUTH),
      scopes: z.array(z.string()),
      userinfo: z.boolean(),
      clientSecretSet: z.boolean(),
    })
    .nullable(),
  saml: z
    .strictObject({
      idpEntityId: z.string(),
      idpSsoUrl: z.string(),
      idpCertificates: z.array(certificateView),
      metadataUrl: z.string().nullable(),
      nameIdFormat: z.enum(NAME_ID_FORMATS),
      emailVerified: z.boolean(),
      wantResponseSigned: z.boolean(),
      spCertificate: z.string().nullable(),
      spKeySet: z.boolean(),
    })
    .nullable(),
  /** What to copy into the IdP; null while QUALOR_PUBLIC_URL is unset. */
  urls: z
    .strictObject({
      redirectUri: z.string(),
      acsUrl: z.string(),
      entityId: z.string(),
      metadataUrl: z.string(),
      startUrl: z.string(),
    })
    .nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
const testResult = z.strictObject({
  ok: z.boolean(),
  problem: z.strictObject({ code: z.string(), message: z.string() }).nullable(),
  endpoints: z
    .strictObject({
      authorization: z.string().nullable(),
      token: z.string().nullable(),
      jwks: z.string().nullable(),
      userinfo: z.string().nullable(),
    })
    .nullable(),
  certificates: z.array(certificateView).nullable(),
});
const metadataPreview = z.strictObject({
  idpEntityId: z.string(),
  idpSsoUrl: z.string(),
  certificates: z.array(certificateView),
});
const mappingView = z.strictObject({
  id: z.uuid(),
  group: z.string(),
  organizationId: z.uuid(),
  organizationKey: z.string(),
  projectId: z.uuid().nullable(),
  projectKey: z.string().nullable(),
  role: z.enum(ROLES),
});
const signInSettingsView = z.strictObject({
  passwordSignIn: z.enum(['everyone', 'break_glass_only']),
  breakGlassUserIds: z.array(z.uuid()),
  /** QUALOR_FORCE_PASSWORD_SIGN_IN is set (§10.4). */
  forced: z.boolean(),
  breakGlass: z.array(
    z.strictObject({ userId: z.uuid(), username: z.string(), usable: z.boolean() }),
  ),
});
const identityView = z.strictObject({
  id: z.uuid(),
  connectionId: z.uuid(),
  connectionName: z.string(),
  protocol: z.enum(PROTOCOLS),
  linkedBy: z.enum(LINK_METHODS),
  /** The IdP provisions it (SCIM): only an instance admin may unlink it. */
  scim: z.boolean(),
  createdAt: z.string(),
  lastSignInAt: z.string().nullable(),
});

const noContent = z.undefined().describe('Done');
const toIdp = z.undefined().describe("To the identity provider's sign-in page (Location)");
const toLogin = z
  .undefined()
  .describe(
    'To returnTo once signed in, or to /login?sso_error=<code> (for example unavailable, flow_expired or rate_limited)',
  );

const FEATURE_TEXT =
  'FEATURE_NOT_LICENSED: the licence does not list sso, or it lapsed (a problem+json answer)';
const AUDIT_ANCHOR_TEXT =
  'AUDIT_CHAIN_ANCHOR_MALFORMED: the audit-chain instance setting is malformed; an administrator must restore it';

const tagged = (summary: string) => ({ tags: ['enterprise'], summary });

/** @fastify/rate-limit's refusal, as core builds it (a 429 RATE_LIMITED problem). */
function isRateLimited(error: FastifyError): boolean {
  const e = error as { status?: unknown; statusCode?: unknown; code?: unknown };
  return (e.status === 429 || e.statusCode === 429) && e.code === 'RATE_LIMITED';
}

/**
 * sso-scim.md §17.2: feature `sso`. The admin routes check an instance admin through
 * `ctx.access` first; a user's own identities use the caller's principal; the browser flows are
 * public and carry their own checks in core (the binding cookie, the session for linking). Core's
 * feature guard answers 403 FEATURE_NOT_LICENSED on every route while `sso` is inactive (§11), and
 * `ctx.sso` refuses on its own too (ruling SS1). Every path is under /api/v0/ee/sso/, whose query
 * strings the request log drops (§7.8).
 */
export function ssoRoutes(ctx: PluginContext): FastifyPluginAsync {
  const admin = (request: FastifyRequest) => ctx.access.requireInstanceAdmin(request);
  const actor = (request: FastifyRequest) => ctx.access.actor(request);

  return async (plain) => {
    const app = plain.withTypeProvider<ZodTypeProvider>();

    app.get(
      '/sso/connections',
      { schema: { ...tagged('SSO connections'), response: { 200: z.array(connectionView) } } },
      async (request) => {
        admin(request);
        return ctx.sso.listConnections();
      },
    );

    app.post(
      '/sso/connections',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              409: `SSO_CONNECTION_LIMIT_REACHED (at most 10); SSO_CONNECTION_NAME_TAKEN; PUBLIC_URL_REQUIRED (enabling needs QUALOR_PUBLIC_URL); ${MULTI_TEXT}; ${AUDIT_ANCHOR_TEXT}`,
            },
          },
        },
        schema: {
          ...tagged('Add an SSO connection'),
          body: connectionInput,
          response: { 201: connectionView },
        },
      },
      async (request, reply) => {
        admin(request);
        return reply.code(201).send(await ctx.sso.createConnection(actor(request), request.body));
      },
    );

    app.get(
      '/sso/connections/:id',
      { schema: { ...tagged('An SSO connection'), params, response: { 200: connectionView } } },
      async (request) => {
        admin(request);
        return ctx.sso.getConnection(request.params.id);
      },
    );

    app.patch(
      '/sso/connections/:id',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              409: `SSO_CONNECTION_NAME_TAKEN; PUBLIC_URL_REQUIRED (enabling needs QUALOR_PUBLIC_URL); ${MULTI_TEXT}; ${LAST_CONNECTION_TEXT}; ${AUDIT_ANCHOR_TEXT}`,
            },
          },
        },
        schema: {
          ...tagged('Change an SSO connection'),
          params,
          body: connectionPatch,
          response: { 200: connectionView },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.updateConnection(actor(request), request.params.id, request.body);
      },
    );

    app.delete(
      '/sso/connections/:id',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: { 409: LAST_CONNECTION_TEXT },
          },
        },
        schema: {
          ...tagged('Delete an SSO connection, its identities, mappings and SCIM tokens'),
          params,
          response: { 204: noContent },
        },
      },
      async (request, reply) => {
        admin(request);
        await ctx.sso.deleteConnection(actor(request), request.params.id);
        return reply.code(204).send();
      },
    );

    app.post(
      '/sso/connections/:id/test',
      {
        schema: {
          ...tagged(
            'Test an SSO connection now (OIDC: discovery and JWKS; SAML: the certificates and the SSO URL)',
          ),
          params,
          response: { 200: testResult },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.testConnection(request.params.id);
      },
    );

    app.post(
      '/sso/connections/:id/saml/metadata',
      {
        schema: {
          ...tagged("Read the IdP's SAML metadata URL for review (saving is a PATCH)"),
          params,
          response: { 200: metadataPreview },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.readSamlMetadata(request.params.id);
      },
    );

    app.get(
      '/sso/connections/:id/mappings',
      {
        schema: {
          ...tagged("A connection's group mappings"),
          params,
          response: { 200: z.array(mappingView) },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.mappings(request.params.id);
      },
    );

    app.put(
      '/sso/connections/:id/mappings',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: { 409: AUDIT_ANCHOR_TEXT },
          },
        },
        schema: {
          ...tagged(
            "Replace a connection's group mappings (every role, at organisation or project level)",
          ),
          params,
          body: z.array(mappingInput).max(500),
          response: { 200: z.array(mappingView) },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.replaceMappings(actor(request), request.params.id, request.body);
      },
    );

    app.get(
      '/sso/settings',
      {
        schema: {
          ...tagged('Password sign-in and the break-glass administrators'),
          response: { 200: signInSettingsView },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.signInSettings();
      },
    );

    app.put(
      '/sso/settings',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: { 409: AUDIT_ANCHOR_TEXT },
          },
        },
        schema: {
          ...tagged('Change password sign-in and the break-glass administrators'),
          body: signInSettingsInput,
          response: { 200: signInSettingsView },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.updateSignInSettings(actor(request), request.body);
      },
    );

    app.get(
      '/sso/users/:userId/identities',
      {
        schema: {
          ...tagged("A user's linked identities"),
          params: userParams,
          response: { 200: z.array(identityView) },
        },
      },
      async (request) => {
        admin(request);
        return ctx.sso.userIdentities(request.params.userId);
      },
    );

    app.delete(
      '/sso/users/:userId/identities/:identityId',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              // rbac-audit.md §10.2.1: an unlink removes access, so a malformed anchor never refuses it.
              409: 'LAST_SIGN_IN_METHOD (nothing else would sign the user in: set a password first)',
            },
          },
        },
        schema: {
          ...tagged("Unlink a user's identity (also one the IdP provisions through SCIM)"),
          params: userIdentityParams,
          response: { 204: noContent },
        },
      },
      async (request, reply) => {
        admin(request);
        await ctx.sso.unlinkIdentity(
          actor(request),
          request.params.userId,
          request.params.identityId,
          true,
        );
        return reply.code(204).send();
      },
    );

    app.get(
      '/sso/me/identities',
      { schema: { ...tagged('Your linked identities'), response: { 200: z.array(identityView) } } },
      async (request) => {
        const me = ctx.access.requireUser(request);
        return ctx.sso.userIdentities(me.user.id);
      },
    );

    app.delete(
      '/sso/me/identities/:identityId',
      {
        config: {
          openapi: {
            problems: [409],
            problemDescriptions: {
              409: 'SCIM_MANAGED_IDENTITY (the IdP provisions it; an instance admin may remove it); LAST_SIGN_IN_METHOD (nothing else would sign you in)',
            },
          },
        },
        schema: {
          ...tagged('Unlink one of your identities'),
          params: identityParams,
          response: { 204: noContent },
        },
      },
      async (request, reply) => {
        const me = ctx.access.requireUser(request, 'write');
        await ctx.sso.unlinkIdentity(actor(request), me.user.id, request.params.identityId, false);
        return reply.code(204).send();
      },
    );

    app.post(
      '/sso/connections/:id/link',
      {
        config: {
          // §7.3: 10 a minute per user (authentication ran first, in the app's onRequest hook).
          rateLimit: {
            max: LINKS_PER_MINUTE,
            timeWindow: MINUTE_MS,
            keyGenerator: (request: FastifyRequest) => {
              try {
                return `user:${ctx.access.requireUser(request).user.id}`;
              } catch {
                return request.ip;
              }
            },
          },
          openapi: {
            problems: [429, 503],
            problemDescriptions: {
              403: 'SESSION_REQUIRED (a browser session only, never a token); FORBIDDEN',
              503: 'SSO_UNAVAILABLE: the identity provider cannot be used now',
            },
          },
        },
        schema: {
          ...tagged(
            'Start linking another identity to your account: open the answered URL in the browser',
          ),
          params,
          response: { 200: z.strictObject({ url: z.string() }) },
        },
      },
      async (request, reply) => ctx.sso.startLink(request, reply, request.params.id),
    );

    // ─── The public browser flows (§5–§7) ────────────────────────────────────────────────────
    await plain.register(async (flows) => {
      // §7.7: a browser flow never ends on a JSON page; beyond its rate limit it ends at the login
      // page with `rate_limited`. Everything else (the feature guard's 403 included) goes on to
      // core's error handler.
      flows.setErrorHandler((error: FastifyError, request, reply) => {
        if (isRateLimited(error)) {
          return reply.code(303).header('location', RATE_LIMITED_LOCATION).send();
        }
        throw error;
      });
      const flow = flows.withTypeProvider<ZodTypeProvider>();
      const publicFlow = {
        security: [],
        tags: ['enterprise'],
      };
      const flowOpenApi = {
        derived: false as const,
        problems: [403],
        problemDescriptions: { 403: FEATURE_TEXT },
      };

      flow.get(
        '/sso/:id/start',
        {
          config: {
            public: true,
            rateLimit: { max: STARTS_PER_MINUTE, timeWindow: MINUTE_MS },
            openapi: flowOpenApi,
          },
          schema: {
            ...publicFlow,
            summary: 'Start signing in with a connection (the sign-in page links here)',
            description:
              'Public, 30 a minute per address. `returnTo`: a path on this server (anything else becomes /). An unknown or disabled connection ends at /login?sso_error=unavailable.',
            params: flowParams,
            response: { 302: toIdp, 303: toLogin },
          },
        },
        (request, reply) => ctx.sso.start(request, reply, request.params.id),
      );

      flow.get(
        '/sso/oidc/:id/callback',
        {
          config: {
            public: true,
            // §7.4: every refused callback writes an audit row, as the ACS and finish do.
            rateLimit: { max: FINISHES_PER_MINUTE, timeWindow: MINUTE_MS },
            openapi: flowOpenApi,
          },
          schema: {
            ...publicFlow,
            summary: "The OIDC redirect URI: the identity provider's answer",
            description:
              'Public, 60 a minute per address. The query (`code`, `state`, `iss`, or `error`) is never logged. Works once, in the browser that started the flow.',
            params: flowParams,
            response: { 303: toLogin },
          },
        },
        (request, reply) => ctx.sso.oidcCallback(request, reply, request.params.id),
      );

      flow.get(
        '/sso/saml/:id/metadata',
        {
          config: {
            public: true,
            openapi: {
              derived: false,
              problems: [403, 404],
              problemDescriptions: {
                403: FEATURE_TEXT,
                404: 'Not a SAML connection, or QUALOR_PUBLIC_URL is unset',
              },
            },
          },
          schema: {
            ...publicFlow,
            summary: "Qualor's SAML service provider metadata, for the identity provider",
            params: flowParams,
            produces: ['application/samlmetadata+xml'],
            response: {
              200: z.string().describe('The SP metadata (application/samlmetadata+xml)'),
            },
          },
        },
        async (request, reply) =>
          reply
            .header('content-type', 'application/samlmetadata+xml; charset=utf-8')
            .send(await ctx.sso.spMetadata(request.params.id)),
      );

      flow.get(
        '/sso/finish',
        {
          config: {
            public: true,
            rateLimit: { max: FINISHES_PER_MINUTE, timeWindow: MINUTE_MS },
            openapi: flowOpenApi,
          },
          schema: {
            ...publicFlow,
            summary: 'Finish a SAML sign-in in the browser that started it',
            description:
              'Public, 60 a minute per address. The ACS redirects here with a one-time `code`.',
            response: { 303: toLogin },
          },
        },
        (request, reply) => ctx.sso.finish(request, reply),
      );

      // §6: the ACS takes only its form (urlencoded, 512 KiB, 415 for anything else), parsed
      // here without a dependency; every other parser is removed from its scope.
      await flows.register(async (acs) => {
        acs.removeAllContentTypeParsers();
        acs.addContentTypeParser(
          'application/x-www-form-urlencoded',
          { parseAs: 'string', bodyLimit: ACS_BODY_LIMIT },
          (_request, body, done) => {
            done(null, samlForm(typeof body === 'string' ? body : body.toString('utf8')));
          },
        );
        acs.withTypeProvider<ZodTypeProvider>().post(
          '/sso/saml/:id/acs',
          {
            bodyLimit: ACS_BODY_LIMIT,
            config: {
              public: true,
              rateLimit: { max: FINISHES_PER_MINUTE, timeWindow: MINUTE_MS },
              openapi: {
                ...flowOpenApi,
                requestBody: {
                  required: true,
                  content: {
                    'application/x-www-form-urlencoded': {
                      schema: {
                        type: 'object',
                        properties: {
                          SAMLResponse: { type: 'string' },
                          RelayState: { type: 'string' },
                        },
                        required: ['SAMLResponse'],
                      },
                    },
                  },
                },
              },
            },
            schema: {
              ...publicFlow,
              summary: "The SAML Assertion Consumer Service: the identity provider's POST",
              description:
                'Public, 60 a minute per address, at most 512 KiB. A valid response redirects to /api/v0/ee/sso/finish.',
              params: flowParams,
              response: { 303: toLogin },
            },
          },
          (request, reply) => ctx.sso.samlAcs(request, reply, request.params.id),
        );
      });
    });
  };
}

/**
 * The ACS body, as core's `parseSamlForm` reads it (the plugin cannot import it): only
 * `SAMLResponse` and `RelayState`, each only when it appears once (a repeated field is dropped,
 * so the ACS refuses the form).
 */
function samlForm(body: string): Record<string, string> {
  const form = new URLSearchParams(body);
  const out: Record<string, string> = {};
  for (const name of ['SAMLResponse', 'RelayState']) {
    const values = form.getAll(name);
    if (values.length === 1 && values[0] !== undefined) out[name] = values[0];
  }
  return out;
}
