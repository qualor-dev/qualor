import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import {
  outboundRequest,
  type OutboundFailed,
  type OutboundResult,
  type Resolver,
} from '../../http/outbound';
import { VERSION } from '../../index';
import { rs256Jwt } from '../github/app-auth';
import { ScmError } from '../provider';
import { retryAfterSeconds } from '../retry-after';
import type { ParsedCertificate } from './certificate';

/**
 * Azure DevOps design §7.1, confirmed by the probe (item 12): Azure DevOps' resource id with
 * `.default`, whatever the service principal may do there.
 */
export const ENTRA_SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default';
export const ENTRA_TIMEOUT_MS = 10_000;
/** A token answer is a few KiB; a larger one is not read. */
export const MAX_ENTRA_RESPONSE_BYTES = 1024 * 1024;
/** A client assertion is valid this long from its `nbf`. */
export const ASSERTION_LIFETIME_SECONDS = 600;
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** The request, for the logs, with the tenant replaced by its name. */
const ENTRA_REQUEST = 'POST /{tenant}/oauth2/v2.0/token';

/** The fixed texts; Entra's own words (its answer may name the client) are never shown or logged. */
export const ENTRA_TEXT = {
  refused: 'Microsoft Entra refused the service principal',
  badAnswer: "Microsoft Entra's token answer was not understood",
  tenant: 'The tenant id is not a GUID',
  rateLimited: 'Microsoft Entra is limiting token requests',
  notPublic:
    'The Microsoft Entra token endpoint resolves to a private, loopback or otherwise non-public address',
  unresolved: 'The Microsoft Entra token endpoint could not be resolved',
  timeout: 'Microsoft Entra did not answer in time',
} as const;

export type EntraCredential =
  | { kind: 'secret'; tenantId: string; clientId: string; secret: string }
  | { kind: 'certificate'; tenantId: string; clientId: string; certificate: ParsedCertificate };

export interface EntraOptions {
  /** The token endpoint of a tenant; default {@link entraTokenUrl}. Tests point it at a fake. */
  tokenUrl?: (tenantId: string) => string;
  /** Default {@link ENTRA_TIMEOUT_MS}. */
  timeoutMs?: number;
  resolve?: Resolver;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** Only the tests' fake token endpoint on loopback needs it; default false. */
  allowInternalHosts?: boolean;
}

/** Microsoft Entra ID's sign-in host, where service principals get their tokens. */
export const ENTRA_ORIGIN = 'https://login.microsoftonline.com';

/**
 * The tenant's OAuth 2.0 token endpoint (v2.0) of Microsoft Entra ID, or of the tests' stand-in
 * at `origin` (`Config.azureTokenUrl`).
 */
export function entraTokenUrl(tenantId: string, origin: string = ENTRA_ORIGIN): string {
  return `${origin}/${tenantId}/oauth2/v2.0/token`;
}

/** RFC 6749 §5.1; `expires_in` is a number, or (older endpoints) a numeric string. */
const tokenAnswer = z.looseObject({
  token_type: z.string().refine((type) => type.toLowerCase() === 'bearer'),
  access_token: z.string().min(1),
  expires_in: z
    .union([
      z.number(),
      z
        .string()
        .regex(/^\d{1,10}$/)
        .transform(Number),
    ])
    .pipe(z.number().int().positive()),
});

function transportError(failed: OutboundFailed): ScmError {
  const request = ENTRA_REQUEST;
  switch (failed.cause) {
    case 'not_public':
    case 'refused_address':
      return new ScmError('refused', ENTRA_TEXT.notPublic, { reason: 'not_public', request });
    case 'unresolved':
      return new ScmError('transient', ENTRA_TEXT.unresolved, { reason: 'unresolved', request });
    case 'too_large':
      return new ScmError('auth', ENTRA_TEXT.badAnswer, { reason: 'token_endpoint', request });
    case 'timeout':
    case 'connect_timeout':
      return new ScmError('transient', ENTRA_TEXT.timeout, { reason: 'timeout', request });
    default:
      return new ScmError(
        'transient',
        failed.code
          ? `Microsoft Entra could not be reached (${failed.code})`
          : 'Microsoft Entra could not be reached',
        { reason: 'unreachable', request },
      );
  }
}

/**
 * The client assertion of a certificate credential (Microsoft identity platform "certificate
 * credentials"): RS256, `x5t` the base64url SHA-1 of the certificate, audience the token endpoint.
 */
function clientAssertion(
  clientId: string,
  certificate: ParsedCertificate,
  audience: string,
  nowSeconds: number,
): string {
  return rs256Jwt(
    {
      aud: audience,
      iss: clientId,
      sub: clientId,
      jti: randomUUID(),
      nbf: nowSeconds,
      exp: nowSeconds + ASSERTION_LIFETIME_SECONDS,
    },
    certificate.key,
    { x5t: Buffer.from(certificate.thumbprintSha1, 'hex').toString('base64url') },
  );
}

/**
 * Azure DevOps design §7.1: an access token for Azure DevOps from Microsoft Entra, with the
 * client credentials grant of a service principal (a client secret, or a certificate's client
 * assertion), through {@link outboundRequest}: no redirect followed, at most
 * {@link MAX_ENTRA_RESPONSE_BYTES} read. `expiresAt` (ms since the epoch) counts from before the
 * request. Entra's refusals (400, 401), any other status but 2xx, 429 and 5xx (a 3xx included),
 * and a 2xx that holds no token are `auth` with reason `token_endpoint`; a 429 is `rate_limited`;
 * a 5xx, a timeout or a failed connection `transient`; an address the outbound policy refuses
 * `refused`. Errors carry fixed texts only: never Entra's answer, the secret or the assertion.
 * It caches nothing (callers keep tokens in `ScmRuntime.azureTokens` under {@link entraCacheKey}).
 */
export async function entraToken(
  credential: EntraCredential,
  options: EntraOptions = {},
): Promise<{ token: string; expiresAt: number }> {
  if (!TENANT_ID.test(credential.tenantId)) {
    throw new ScmError('refused', ENTRA_TEXT.tenant, { reason: 'invalid_input' });
  }
  const now = options.now ?? Date.now;
  const tokenUrl = (options.tokenUrl ?? entraTokenUrl)(credential.tenantId);
  const started = now();
  const result = await outboundRequest(
    {
      url: tokenUrl,
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
        'user-agent': `Qualor/${VERSION}`,
      },
      body: tokenForm(credential, tokenUrl, Math.floor(started / 1000)),
    },
    {
      allowInternalHosts: options.allowInternalHosts ?? false,
      timeoutMs: options.timeoutMs ?? ENTRA_TIMEOUT_MS,
      ...(options.resolve ? { resolve: options.resolve } : {}),
      maxResponseBytes: MAX_ENTRA_RESPONSE_BYTES,
      overflow: 'fail',
      names: { noun: 'Microsoft Entra', target: 'Microsoft Entra' },
    },
  );
  if (result.kind === 'failed') throw transportError(result);
  const { access_token: token, expires_in: seconds } = tokenOf(result, now);
  return { token, expiresAt: started + seconds * 1000 };
}

/** The client credentials form: the secret, or a client assertion signed `nowSeconds`. */
function tokenForm(credential: EntraCredential, tokenUrl: string, nowSeconds: number): string {
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: credential.clientId,
    scope: ENTRA_SCOPE,
  });
  if (credential.kind === 'secret') {
    form.set('client_secret', credential.secret);
  } else {
    form.set('client_assertion_type', ASSERTION_TYPE);
    form.set(
      'client_assertion',
      clientAssertion(credential.clientId, credential.certificate, tokenUrl, nowSeconds),
    );
  }
  return form.toString();
}

/** The token of Entra's answer, or the error that says why there is none. */
function tokenOf(
  result: Exclude<OutboundResult, OutboundFailed>,
  now: () => number,
): z.infer<typeof tokenAnswer> {
  const { status } = result;
  const request = ENTRA_REQUEST;
  if (status === 429) {
    throw new ScmError('rate_limited', ENTRA_TEXT.rateLimited, {
      status,
      retryAfterSeconds: retryAfterSeconds(result.headers, now()),
      request,
    });
  }
  if (status >= 500) {
    throw new ScmError('transient', `Microsoft Entra answered HTTP ${status}`, {
      status,
      reason: 'http',
      request,
    });
  }
  if (status < 200 || status >= 300) {
    throw new ScmError('auth', ENTRA_TEXT.refused, { status, reason: 'token_endpoint', request });
  }
  let json: unknown;
  try {
    json = JSON.parse(result.body.toString('utf8'));
  } catch {
    json = undefined;
  }
  const answer = tokenAnswer.safeParse(json);
  if (!answer.success) {
    throw new ScmError('auth', ENTRA_TEXT.badAnswer, { status, reason: 'token_endpoint', request });
  }
  return answer.data;
}

/**
 * The key of a connection's token in `ScmRuntime.azureTokens`: the connection id and a SHA-256
 * prefix of the tenant, the client and the secret or the certificate's thumbprint, so a replaced
 * credential is a new key. It holds no secret, but names the connection: never log it.
 */
export function entraCacheKey(connectionId: string, credential: EntraCredential): string {
  const proof =
    credential.kind === 'secret'
      ? `secret\0${credential.secret}`
      : `certificate\0${credential.certificate.thumbprintSha1}`;
  const id = createHash('sha256')
    .update(`${credential.tenantId}\0${credential.clientId}\0${proof}`, 'utf8')
    .digest('hex')
    .slice(0, 16);
  return `${connectionId}|entra|${id}`;
}
