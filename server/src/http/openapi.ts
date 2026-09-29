import type { FastifyDynamicSwaggerOptions } from '@fastify/swagger';
import { jsonSchemaTransform } from 'fastify-type-provider-zod';
import { isAuditedMutation } from '../audit/routes';
import { VERSION } from '../index';

/** RFC 9457 problem details, as rendered by http/problem.ts. */
const PROBLEM_SCHEMA = {
  type: 'object',
  description: 'RFC 9457 problem details (application/problem+json)',
  properties: {
    type: { type: 'string', description: 'urn:qualor:problem:<code in kebab case>' },
    title: { type: 'string' },
    status: { type: 'integer' },
    code: { type: 'string', description: 'Stable machine-readable error code' },
    detail: { type: 'string' },
    reason: {
      type: 'string',
      description:
        'LICENSE_INVALID: why the key was rejected (malformed, unknown-key, bad-signature, bad-payload, revoked, not-yet-valid). VALIDATION_FAILED of POST /ee/sso/connections/{id}/saml/metadata: what failed (a fetch.<reason> code of the connection Test, or config_invalid, metadata.no_url, metadata.not_saml, metadata.incomplete, metadata.sso_url). Map the code, not the text',
    },
    errors: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          path: { type: 'string', description: '<body|query|params|headers>.<dotted path>' },
          message: { type: 'string' },
        },
        required: ['path', 'message'],
      },
    },
  },
  required: ['type', 'title', 'status', 'code'],
};

const PROBLEM_DESCRIPTIONS: Record<number, string> = {
  401: 'Not authenticated (UNAUTHENTICATED, INVALID_CREDENTIALS)',
  403: 'Authenticated but not allowed (FORBIDDEN, INSUFFICIENT_SCOPE, TOKEN_NOT_ALLOWED, SESSION_REQUIRED, CSRF_FAILED, PASSWORD_CHANGE_REQUIRED)',
  404: 'Not found, or not visible to the caller',
  409: 'Conflicts with the current state',
  413: 'Too large (REPORT_TOO_LARGE, BODY_TOO_LARGE)',
  415: 'Unsupported Content-Type or Content-Encoding',
  422: 'Validation failed (VALIDATION_FAILED; errors[] names each field)',
  429: 'Rate limited (RATE_LIMITED); see Retry-After',
  503: 'Temporarily unavailable; see Retry-After',
};

/** Extra OpenAPI documentation a route declares in its `config.openapi` (see route-config.ts). */
export interface RouteOpenApi {
  /** Statuses beyond the ones derived automatically (401/403 when authenticated, 404 with path
   *  parameters, 422 with a body, query or path parameters). */
  problems?: readonly number[];
  /** Route-specific descriptions of problem statuses (the codes this route answers with). */
  problemDescriptions?: Readonly<Partial<Record<number, string>>>;
  /** Replaces the generated request body (for routes that stream a non-JSON body). */
  requestBody?: Record<string, unknown>;
  /** Extra header parameters. */
  headers?: readonly Record<string, unknown>[];
  /**
   * `false`: only `problems` are documented, none derived from the route's shape. For routes that
   * never answer those as problems: an SSO browser flow redirects, and SCIM answers in its own
   * format (sso-scim.md §7.7, §12.1).
   */
  derived?: false;
}

type Operation = {
  security?: unknown[];
  parameters?: { in: string }[];
  requestBody?: unknown;
  responses?: Record<string, unknown>;
};

/** `get /a/{id}`, as the document names an operation (`:id` → `{id}`, a wildcard `*` → `{*}`). */
function operationKey(method: string, url: string): string {
  return `${method.toLowerCase()} ${url.replace(/:(\w+)/g, '{$1}').replace(/\*$/, '{*}')}`;
}

function problemResponse(status: number, description?: string) {
  return {
    description: description ?? PROBLEM_DESCRIPTIONS[status] ?? 'Error',
    content: { 'application/problem+json': { schema: { $ref: '#/components/schemas/Problem' } } },
  };
}

/** rbac-audit.md §10.2: what every audited core operation adds to its 409. */
const AUDIT_ANCHOR_TEXT =
  'AUDIT_CHAIN_ANCHOR_MALFORMED: the audit-chain instance setting is malformed while no audit event is stored; an administrator must restore it (a retry does not help)';

function documentProblems(
  operation: Operation,
  route: RouteOpenApi | undefined,
  kinds: { audited: boolean },
): void {
  const statuses = new Set<number>(route?.problems ?? []);
  const descriptions: Partial<Record<number, string>> = { ...route?.problemDescriptions };
  const add409 = (text: string): void => {
    // A route's own 409s (declared, with or without a text) keep their description first.
    const own = descriptions[409] ?? (statuses.has(409) ? PROBLEM_DESCRIPTIONS[409] : undefined);
    descriptions[409] = own === undefined ? text : `${own}; ${text}`;
    statuses.add(409);
  };
  if (kinds.audited) add409(AUDIT_ANCHOR_TEXT);
  const isPublic = Array.isArray(operation.security) && operation.security.length === 0;
  const derived = route?.derived !== false;
  if (derived && !isPublic) {
    statuses.add(401);
    statuses.add(403);
  }
  const parameters = operation.parameters ?? [];
  if (derived && parameters.some((p) => p.in === 'path')) statuses.add(404);
  if (derived && (operation.requestBody || parameters.some((p) => p.in !== 'header'))) {
    statuses.add(422);
  }
  operation.responses ??= {};
  for (const status of [...statuses].sort((a, b) => a - b)) {
    operation.responses[String(status)] ??= problemResponse(status, descriptions[status]);
  }
}

export function openApiOptions(): FastifyDynamicSwaggerOptions {
  // Filled by `transform` (once per route) and consumed by `transformObject` (once per document).
  const routes = new Map<string, RouteOpenApi>();
  return {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'Qualor API',
        version: VERSION,
        description: 'Qualor REST API v0. Unstable: breaking changes are listed in CHANGELOG.md.',
      },
      components: {
        securitySchemes: {
          bearer: { type: 'http', scheme: 'bearer', description: 'qlr_pat_… or qlr_prj_… token' },
          session: { type: 'apiKey', in: 'cookie', name: 'qualor_session' },
        },
      },
      security: [{ bearer: [] }, { session: [] }],
    },
    transform: (input) => {
      const extra = input.route.config?.openapi;
      if (extra) {
        const methods = Array.isArray(input.route.method)
          ? input.route.method
          : [input.route.method];
        for (const method of methods) routes.set(operationKey(String(method), input.url), extra);
      }
      return jsonSchemaTransform(input);
    },
    transformObject: (documentObject) => {
      if (!('openapiObject' in documentObject)) return documentObject.swaggerObject;
      const doc = documentObject.openapiObject as {
        components?: { schemas?: Record<string, unknown> };
        paths?: Record<string, Record<string, unknown> | undefined>;
      };
      doc.components ??= {};
      doc.components.schemas = { ...doc.components.schemas, Problem: PROBLEM_SCHEMA };
      for (const [path, item] of Object.entries(doc.paths ?? {})) {
        for (const [method, value] of Object.entries(item ?? {})) {
          if (typeof value !== 'object' || value === null || !('responses' in value)) continue;
          const operation = value as Operation;
          const route = routes.get(operationKey(method, path));
          if (route?.requestBody) operation.requestBody = route.requestBody;
          if (route?.headers) {
            operation.parameters = [
              ...(operation.parameters ?? []),
              ...(route.headers as { in: string }[]),
            ];
          }
          documentProblems(operation, route, {
            audited: isAuditedMutation(method, path),
          });
        }
      }
      return documentObject.openapiObject;
    },
  };
}
