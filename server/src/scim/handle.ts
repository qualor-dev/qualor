import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from 'fastify';
import type { AuditRecorder } from '../audit/recorder';
import { LoginThrottle } from '../auth/throttle';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { pgErrorCode } from '../db/errors';
import { ProblemError } from '../http/problem';
import type { Edition } from '../license/edition';
import { loadConnection } from '../sso/connections';
import { SCIM_CONTENT_TYPE, ScimError, scimErrorBody } from './errors';
import { parseScimFilter } from './filter';
import { createGroup, deleteGroup, getGroup, listGroups, patchGroup, replaceGroup } from './groups';
import {
  MAX_RESULTS,
  RESOURCE_TYPES,
  SCHEMAS,
  scimBaseUrl,
  SERVICE_PROVIDER_CONFIG,
} from './representation';
import { resolveScimToken } from './tokens';
import {
  createUser,
  deleteUser,
  getUser,
  listUsers,
  patchUser,
  replaceUser,
  type ScimCaller,
  type ScimListQuery,
} from './users';

export interface ScimDeps {
  db: Db;
  secretKey: string;
  config: Pick<Config, 'publicUrl' | 'forcePasswordSignIn'>;
  edition: Edition;
  audit: AuditRecorder;
  log: FastifyBaseLogger;
}

/** spec §12.1: 1 200 requests a minute per token, in process (each replica counts on its own). */
export const SCIM_RATE_LIMIT = 1_200;
const throttle = new LoginThrottle({ max: SCIM_RATE_LIMIT, windowMs: 60_000 });
/**
 * Failed authentications a minute per address (A M-5): beyond them the address's failed
 * authentications are answered 429 instead of 401; a valid token from it proceeds.
 */
export const SCIM_AUTH_FAILURES_PER_MINUTE = 60;
const authFailures = new LoginThrottle({ max: SCIM_AUTH_FAILURES_PER_MINUTE, windowMs: 60_000 });
/** A deadlock (40P01) or a serialization failure (40001): nothing was written; the IdP retries. */
const RETRYABLE = new Set(['40P01', '40001']);
const RETRY_AFTER_SECONDS = '5';
/**
 * The body the enterprise plugin's parser hands over when a SCIM request's body is not JSON (the
 * parser runs before any handler, and a parser error would be a problem+json answer, not SCIM).
 */
export const SCIM_INVALID_JSON = Symbol.for('qualor.scim.invalid-json');
/** RFC 7644 §3.4.2.4 allows up to 2^31 − 1 as a 1-based index. */
const MAX_START_INDEX = 2_147_483_647;
/** Names in one `attributes=` or `excludedAttributes=` list. */
const MAX_ATTRIBUTE_NAMES = 50;

function integer(raw: unknown, fallback: number): number {
  if (typeof raw !== 'string' || !/^[ \t]*-?\d{1,12}[ \t]*$/.test(raw)) return fallback;
  return Number.parseInt(raw, 10);
}

function names(raw: unknown): string[] | null {
  if (typeof raw !== 'string') return null;
  const list = raw
    .split(',')
    .map((n) => n.trim())
    .filter((n) => n !== '');
  return list.length === 0 ? null : list.slice(0, MAX_ATTRIBUTE_NAMES);
}

/**
 * spec §12.5: the filter (400 `invalidFilter` when unsupported), `startIndex` (default 1, below 1
 * counts as 1), `count` (default and at most 100; 0 answers only `totalResults`), and the
 * attribute lists. A malformed number counts as absent.
 */
export function listQuery(
  q: Record<string, string | undefined>,
  resource: 'User' | 'Group',
): ScimListQuery {
  return {
    filter: parseScimFilter(q.filter, resource),
    startIndex: Math.min(MAX_START_INDEX, Math.max(1, integer(q.startIndex, 1))),
    count: Math.min(MAX_RESULTS, Math.max(0, integer(q.count, MAX_RESULTS))),
    attributes: names(q.attributes),
    excludedAttributes: names(q.excludedAttributes) ?? [],
  };
}

/**
 * Every request under `/api/v0/ee/scim/v2/*` (spec §12, ruling SS7): authenticates the SCIM token
 * (401 otherwise, and nothing else said), rate-limits per token, dispatches, and answers in
 * `application/scim+json` with the SCIM error schema. The token never reaches a log line.
 */
export async function handleScim(
  deps: ScimDeps,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply> {
  const send = (status: number, body: unknown) =>
    reply
      .code(status)
      .header('content-type', SCIM_CONTENT_TYPE)
      .header('cache-control', 'no-store')
      .send(body === null ? undefined : JSON.stringify(body));
  const noContent = () => reply.code(204).header('cache-control', 'no-store').send();
  try {
    // SS1: the plugin's route is feature-guarded; this is the core's own check.
    if (!deps.edition.isFeatureActive('scim')) {
      throw new ScimError(403, null, 'SCIM needs the scim feature');
    }
    // A failed authentication is counted per address; once an address used up its minute, its
    // failures are answered 429. The token is still resolved first: cloud IdPs share egress
    // addresses, so a stranger's bad tokens must never hold a valid token at 429.
    const refuse = (): ScimError => {
      if (authFailures.exhausted(request.ip)) {
        return new ScimError(429, null, 'Too many failed authentications; retry in a minute');
      }
      authFailures.hit(request.ip);
      return new ScimError(401, null, 'Authentication failed');
    };
    const auth = request.headers.authorization;
    const match = typeof auth === 'string' ? /^Bearer (\S+)$/.exec(auth) : null;
    const presented = match?.[1];
    const token = presented === undefined ? null : await resolveScimToken(deps.db, presented);
    if (!token) throw refuse();
    if (!throttle.hit(token.tokenId)) {
      throw new ScimError(429, null, 'Too many requests; retry in a minute');
    }
    const connection = await loadConnection(deps.db, token.connectionId, deps.secretKey);
    if (!connection) throw refuse();
    if (request.body === SCIM_INVALID_JSON) {
      throw new ScimError(400, 'invalidSyntax', 'The request body is not valid JSON');
    }
    const caller: ScimCaller = {
      deps,
      tokenId: token.tokenId,
      connectionId: token.connectionId,
      connection,
      baseUrl: scimBaseUrl(deps.config.publicUrl),
    };
    const params = request.params as Record<string, string | undefined>;
    const path = String(params['*'] ?? '');
    const [resource, id, extra] = path.split('/');
    if (extra !== undefined) throw new ScimError(404, null, 'Not found');
    const q = (request.query ?? {}) as Record<string, string | undefined>;
    switch (`${request.method} ${resource ?? ''}${id ? '/:id' : ''}`) {
      case 'GET ServiceProviderConfig':
        return send(200, SERVICE_PROVIDER_CONFIG(caller.baseUrl));
      case 'GET ResourceTypes':
        return send(200, RESOURCE_TYPES(caller.baseUrl));
      case 'GET Schemas':
        return send(200, SCHEMAS);
      case 'GET Users':
        return send(200, await listUsers(caller, listQuery(q, 'User')));
      case 'POST Users': {
        const r = await createUser(caller, request.body);
        reply.header('location', r.meta.location);
        return send(201, r);
      }
      case 'GET Users/:id':
        return send(
          200,
          await getUser(caller, id ?? '', {
            attributes: names(q.attributes),
            excludedAttributes: names(q.excludedAttributes) ?? [],
          }),
        );
      case 'PUT Users/:id':
        return send(200, await replaceUser(caller, id ?? '', request.body));
      case 'PATCH Users/:id':
        return send(200, await patchUser(caller, id ?? '', request.body));
      case 'DELETE Users/:id':
        await deleteUser(caller, id ?? '');
        return noContent();
      case 'GET Groups':
        return send(200, await listGroups(caller, listQuery(q, 'Group')));
      case 'POST Groups': {
        const r = await createGroup(caller, request.body);
        reply.header('location', r.meta.location);
        return send(201, r);
      }
      case 'GET Groups/:id':
        return send(
          200,
          await getGroup(caller, id ?? '', {
            attributes: names(q.attributes),
            excludedAttributes: names(q.excludedAttributes) ?? [],
          }),
        );
      case 'PUT Groups/:id':
        return send(200, await replaceGroup(caller, id ?? '', request.body));
      case 'PATCH Groups/:id':
        return send(200, await patchGroup(caller, id ?? '', request.body));
      case 'DELETE Groups/:id':
        await deleteGroup(caller, id ?? '');
        return noContent();
      default:
        throw new ScimError(404, null, 'Not found');
    }
  } catch (err) {
    if (err instanceof ScimError) {
      if (err.status === 429) reply.header('retry-after', '60');
      // RFC 6750 §3: a refused bearer token names the scheme.
      if (err.status === 401) reply.header('www-authenticate', 'Bearer');
      return send(err.status, scimErrorBody(err));
    }
    if (
      err instanceof ProblemError &&
      err.status === 409 &&
      err.code === 'AUDIT_CHAIN_ANCHOR_MALFORMED'
    ) {
      return send(
        409,
        scimErrorBody(
          new ScimError(
            409,
            null,
            'The audit chain anchor is malformed; an administrator must restore it',
          ),
        ),
      );
    }
    const code = pgErrorCode(err);
    if (code !== undefined && RETRYABLE.has(code)) {
      deps.log.warn({ component: 'scim', code }, 'scim request conflicted; the client may retry');
      reply.header('retry-after', RETRY_AFTER_SECONDS);
      return send(
        503,
        scimErrorBody(
          new ScimError(503, null, 'A concurrent change conflicted; retry the request'),
        ),
      );
    }
    // The class only: a message may echo request data (A M-4, as the SSO flows log, §7.7).
    deps.log.error(
      {
        component: 'scim',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
        ...(code === undefined ? {} : { code }),
      },
      'scim request failed',
    );
    return send(500, scimErrorBody(new ScimError(500, null, 'Internal error')));
  }
}
