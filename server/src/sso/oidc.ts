import type { FastifyReply, FastifyRequest } from 'fastify';
import * as client from 'openid-client';
import { isStorableText } from '../audit/canonical';
import type { SignInClaims } from './accounts';
import { bindingMatches, newBinding, setBindingCookie, SSO_COOKIE } from './binding';
import { requiredClaimsMet } from './claims';
import { completeSignIn, type FlowDeps } from './complete';
import type { OidcConfig } from './connection-config';
import {
  isConnectionInEffect,
  loadConnection,
  UNDECRYPTABLE_CLIENT_SECRET,
  type LoadedConnection,
} from './connections';
import { failSsoFlow, SsoFailure } from './errors';
import { SsoFetchRefused } from './fetch';
import { MAX_GROUP_VALUES } from './groups';
import { forgetOidcConfiguration, oidcConfiguration, type OidcConfiguration } from './oidc-config';
import { safeReturnTo } from './return-to';
import { FLOW_TTL_MS, putState, stateKey, takeState } from './states';
import { ssoUrls } from './urls';

export type { FlowDeps } from './complete';

/** sso-scim.md §5 step 1: the flow row of an OIDC sign-in or link (secrets expire in 10 minutes). */
export interface OidcFlowPayload {
  connectionId: string;
  verifier: string;
  nonce: string;
  returnTo: string;
  intent: 'sign_in' | 'link';
  linkUserId: string | null;
  /** The SHA-256 (hex) of the `qualor_sso` cookie. */
  binding: string;
}

/** spec §5 step 4: a claim read through `claims` is a string of 1–1 024 characters. */
const CLAIM_MAX = 1_024;
const SUBJECT_MAX = 255;
/** The IdP's OAuth `error` code, logged as `oidc.idp.<code>` (RFC 6749 codes are `[a-z_]`). */
const IDP_ERROR = /^[a-z_]{1,40}$/;
/** The ID token claims oauth4webapi compares, each a detail of its own. */
const ID_TOKEN_CLAIMS = new Set(['iss', 'aud', 'azp', 'nonce', 'exp', 'iat']);
/** spec §5, §19.3: the ID token's clock tolerance (as oidc-config.ts gives openid-client). */
const CLOCK_TOLERANCE_S = 60;
/** Details after which the cached JWKS may be stale (a key rotation): the next flow rediscovers. */
const KEY_DETAILS = new Set(['oidc.key_selection', 'oidc.id_token.signature']);

/**
 * Maps a library error to a fixed detail (spec §7.7): the oauth4webapi code openid-client keeps on
 * its ClientError, and the claim a comparison failed on; a refusal of ssoFetch however deep it was
 * wrapped. Never the message, which may echo the IdP's text.
 */
export function oidcDetail(err: unknown): string {
  let code: string | undefined;
  let claim: string | undefined;
  /** oauth4webapi's failed JWS check: an OAUTH_INVALID_RESPONSE whose cause holds the signature. */
  let signature = false;
  let current: unknown = err;
  for (let depth = 0; depth < 5 && current !== null && typeof current === 'object'; depth++) {
    if (current instanceof SsoFetchRefused) return `oidc.fetch.${current.reason}`;
    const fields = current as { code?: unknown; claim?: unknown; cause?: unknown };
    if (code === undefined && typeof fields.code === 'string') code = fields.code;
    if (claim === undefined && typeof fields.claim === 'string') claim = fields.claim;
    if (Object.hasOwn(fields, 'signature') && Object.hasOwn(fields, 'algorithm')) signature = true;
    current = fields.cause;
  }
  switch (code) {
    case 'OAUTH_JWT_CLAIM_COMPARISON_FAILED':
    case 'OAUTH_JWT_TIMESTAMP_CHECK_FAILED':
      return claim !== undefined && ID_TOKEN_CLAIMS.has(claim)
        ? `oidc.id_token.${claim}`
        : 'oidc.id_token.other';
    case 'OAUTH_RESPONSE_BODY_ERROR':
    case 'OAUTH_RESPONSE_IS_NOT_CONFORM':
    case 'OAUTH_RESPONSE_IS_NOT_JSON':
    case 'OAUTH_WWW_AUTHENTICATE_CHALLENGE':
      return 'oidc.token_endpoint';
    case 'OAUTH_INVALID_RESPONSE':
      return signature ? 'oidc.id_token.signature' : 'oidc.invalid_response';
    case 'OAUTH_PARSE_ERROR':
    case 'OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED':
      return 'oidc.invalid_response';
    case 'OAUTH_UNSUPPORTED_OPERATION':
      return 'oidc.unsupported_alg';
    case 'OAUTH_KEY_SELECTION_FAILED':
      return 'oidc.key_selection';
    case 'OAUTH_TIMEOUT':
    case 'OAUTH_ABORT':
      return 'oidc.fetch.timeout';
    default:
      return 'oidc.other';
  }
}

/**
 * A string of 1–1 024 characters that is not only blanks and that PostgreSQL can store (no U+0000,
 * no lone surrogate), else null (absent).
 */
function text(value: unknown): string | null {
  return typeof value === 'string' &&
    value.length <= CLAIM_MAX &&
    value.trim().length > 0 &&
    isStorableText(value)
    ? value
    : null;
}

/** An own property only: a claim named `constructor` is not the object's constructor. */
const own = (claims: Record<string, unknown> | null, name: string | null): unknown =>
  claims !== null && name !== null && Object.hasOwn(claims, name) ? claims[name] : undefined;

/**
 * spec §5 step 4, §8.3, §9.1: the sign-in's claims from the ID token's claims merged over
 * userinfo's (the ID token wins). Null without a storable `sub` of 1–255 characters. Each
 * configured claim counts only as a storable string (groups: an array of strings, or one string),
 * else it is absent. `email_verified` is the boolean `true` only (a string `"true"` is not), read
 * from the claims the email came from. More than MAX_GROUP_VALUES groups is refused, never cut
 * (`invalid_response`, `groups.too_many`).
 */
export function claimsFrom(
  tokens: Record<string, unknown>,
  userinfo: Record<string, unknown> | null,
  cfg: OidcConfig,
): SignInClaims | null {
  const sub = tokens.sub;
  if (
    typeof sub !== 'string' ||
    sub.length === 0 ||
    sub.length > SUBJECT_MAX ||
    !isStorableText(sub)
  ) {
    return null;
  }
  const merged: Record<string, unknown> = { ...(userinfo ?? {}), ...tokens };
  const read = (name: string | null): unknown => own(merged, name);
  // The email and its `email_verified` come from the same claims: the ID token when it names the
  // email claim, else userinfo. One source's flag never vouches for the other's address.
  const emailName = cfg.claims.email;
  const emailSource = own(tokens, emailName) !== undefined ? tokens : userinfo;
  const email = text(own(emailSource, emailName));
  const emailVerified = email !== null && emailSource?.email_verified === true;

  let groups: string[] = [];
  const rawGroups = read(cfg.claims.groups);
  if (Array.isArray(rawGroups)) {
    if (rawGroups.length > MAX_GROUP_VALUES) {
      throw new SsoFailure('invalid_response', 'groups.too_many');
    }
    if (rawGroups.every((g): g is string => typeof g === 'string')) groups = rawGroups;
  } else if (typeof rawGroups === 'string') {
    groups = [rawGroups];
  }

  return {
    subject: sub,
    username: text(read(cfg.claims.username)),
    email,
    emailVerified,
    displayName: text(read(cfg.claims.displayName)),
    groups,
  };
}

/** The connection's discovery, or `unavailable` with a fixed detail (an IdP down, a bad secret). */
async function discover(deps: FlowDeps, connection: LoadedConnection): Promise<OidcConfiguration> {
  if (connection.clientSecret === null) {
    deps.log.error(
      { component: 'sso', connectionId: connection.row.id },
      UNDECRYPTABLE_CLIENT_SECRET,
    );
    throw new SsoFailure('unavailable', 'oidc.secret');
  }
  try {
    return await oidcConfiguration(connection, {
      internalHosts: deps.config.ssoInternalHosts,
      ...(deps.resolve ? { resolve: deps.resolve } : {}),
    });
  } catch (err) {
    const detail = oidcDetail(err);
    throw new SsoFailure(
      'unavailable',
      detail.startsWith('oidc.fetch.') ? detail : 'oidc.discovery',
    );
  }
}

/**
 * The connection, if it may run a flow now: OIDC with a public URL (else `oidc.not_configured`),
 * `sso` active (else `oidc.inactive`), enabled (else `oidc.disabled`), in effect (else
 * `oidc.not_in_effect`, sso-scim.md §4.4); each `unavailable`.
 */
async function usable(
  deps: FlowDeps,
  connection: LoadedConnection | null,
): Promise<{ connection: LoadedConnection; cfg: OidcConfig; publicUrl: string }> {
  if (!connection || connection.parsed.protocol !== 'oidc' || !deps.config.publicUrl) {
    throw new SsoFailure('unavailable', 'oidc.not_configured');
  }
  if (!deps.edition.isFeatureActive('sso')) throw new SsoFailure('unavailable', 'oidc.inactive');
  if (!connection.row.enabled) throw new SsoFailure('unavailable', 'oidc.disabled');
  if (!(await isConnectionInEffect(deps.db, deps.edition, connection.row.id))) {
    throw new SsoFailure('unavailable', 'oidc.not_in_effect');
  }
  return { connection, cfg: connection.parsed.config, publicUrl: deps.config.publicUrl };
}

/**
 * sso-scim.md §5 step 1, §7.2, §7.3: stores the flow (keyed by the SHA-256 of `state`, 10 minutes),
 * sets the binding cookie, and returns the IdP's authorization URL with S256 PKCE (sent even when
 * the IdP does not advertise it), `state` and `nonce`. The caller redirects to it, or answers
 * `{ url }` for linking. Throws `SsoFailure('unavailable')` for a connection that cannot run.
 */
export async function startOidc(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  connection: LoadedConnection,
  intent: { returnTo: string; link: { userId: string } | null },
): Promise<string> {
  const { cfg, publicUrl } = await usable(deps, connection);
  const { config } = await discover(deps, connection);
  const state = client.randomState();
  const nonce = client.randomNonce();
  const verifier = client.randomPKCECodeVerifier();
  const binding = newBinding();
  const payload: OidcFlowPayload = {
    connectionId: connection.row.id,
    verifier,
    nonce,
    returnTo: safeReturnTo(intent.returnTo),
    intent: intent.link ? 'link' : 'sign_in',
    linkUserId: intent.link?.userId ?? null,
    binding: binding.hash,
  };
  await putState(deps.db, {
    key: stateKey('oidc', state),
    kind: 'oidc',
    connectionId: connection.row.id,
    payload,
    ttlMs: FLOW_TTL_MS,
  });
  setBindingCookie(reply, request, binding.cookie);
  return client.buildAuthorizationUrl(config, {
    redirect_uri: ssoUrls(publicUrl, connection.row.id).redirectUri,
    scope: cfg.scopes.join(' '),
    state,
    nonce,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  }).href;
}

/**
 * sso-scim.md §5 steps 2–5: the callback. The flow is taken first (SS3: it burns whatever follows),
 * then refused, before anything is sent to the IdP, for no `state`, an unknown or expired flow or
 * one of another connection (`flow_expired`), a binding that does not match the cookie
 * (`flow_mismatch`), an IdP `error` (`idp_error`, its code logged, never its description), an
 * unusable connection (`unavailable`), or an `iss` parameter naming another issuer or missing
 * while the IdP advertises it (mix-up, RFC 9207). Then the code is redeemed with the verifier,
 * state and nonce, against a URL rebuilt from QUALOR_PUBLIC_URL (never the Host header); the
 * claims are read, the required claims checked, and the account, groups and session follow.
 * Every failure is a 303 to `/login?sso_error=<code>`.
 */
export async function oidcCallback(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  connectionId: string,
): Promise<FastifyReply> {
  try {
    const query = request.query as Record<string, unknown>;
    const state = typeof query.state === 'string' ? query.state : null;
    if (!state) throw new SsoFailure('flow_expired', 'oidc.state_missing');
    const flow = await takeState<OidcFlowPayload>(deps.db, stateKey('oidc', state));
    if (!flow || flow.connectionId !== connectionId) {
      throw new SsoFailure('flow_expired', 'oidc.state_unknown');
    }
    if (!bindingMatches(request.cookies[SSO_COOKIE], flow.payload.binding)) {
      throw new SsoFailure('flow_mismatch', 'oidc.binding');
    }
    if (query.error !== undefined) {
      const code =
        typeof query.error === 'string' && IDP_ERROR.test(query.error) ? query.error : 'other';
      throw new SsoFailure('idp_error', `oidc.idp.${code}`);
    }
    const { connection, cfg, publicUrl } = await usable(
      deps,
      await loadConnection(deps.db, connectionId, deps.config.secretKey),
    );
    const { config } = await discover(deps, connection);

    // The mix-up defence (RFC 9207), before the code goes anywhere: the library checks it too.
    const issuer = config.serverMetadata().issuer;
    const iss = query.iss;
    if (
      (iss !== undefined && iss !== issuer) ||
      (iss === undefined && config.serverMetadata().authorization_response_iss_parameter_supported)
    ) {
      throw new SsoFailure('invalid_response', 'oidc.iss_param');
    }

    const currentUrl = new URL(ssoUrls(publicUrl, connectionId).redirectUri);
    currentUrl.search = new URL(request.url, 'http://path.invalid').search;
    let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
    try {
      tokens = await client.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: flow.payload.verifier,
        expectedState: state,
        expectedNonce: flow.payload.nonce,
        idTokenExpected: true,
      });
    } catch (err) {
      const detail = oidcDetail(err);
      // A key the cached JWKS lacks, or a signature it does not verify: after a rotation the next
      // flow starts from a fresh discovery and JWKS (this one's code is spent either way).
      if (KEY_DETAILS.has(detail)) forgetOidcConfiguration(connectionId);
      throw new SsoFailure('invalid_response', detail);
    }
    const idClaims = tokens.claims();
    if (!idClaims) throw new SsoFailure('invalid_response', 'oidc.id_token.missing');
    // spec §19.3: what oauth4webapi leaves out. `iat` no more than 60 s ahead (it checks only
    // that it is a number), and a present `azp` naming this client even with a single `aud`
    // (it checks `azp` only for several audiences; OIDC Core 3.1.3.7).
    if (idClaims.iat > Math.floor(Date.now() / 1000) + CLOCK_TOLERANCE_S) {
      throw new SsoFailure('invalid_response', 'oidc.id_token.iat');
    }
    if (idClaims.azp !== undefined && idClaims.azp !== cfg.clientId) {
      throw new SsoFailure('invalid_response', 'oidc.id_token.azp');
    }

    let userinfo: Record<string, unknown> | null = null;
    if (cfg.userinfo) {
      try {
        userinfo = { ...(await client.fetchUserInfo(config, tokens.access_token, idClaims.sub)) };
      } catch {
        throw new SsoFailure('invalid_response', 'oidc.userinfo');
      }
    }
    const idToken: Record<string, unknown> = { ...idClaims };
    const claims = claimsFrom(idToken, userinfo, cfg);
    if (!claims) throw new SsoFailure('invalid_response', 'oidc.claims');
    if (!requiredClaimsMet(cfg.requiredClaims, { ...(userinfo ?? {}), ...idToken })) {
      throw new SsoFailure('required_claim', 'oidc.required_claim');
    }
    return await completeSignIn(deps, request, reply, {
      connection,
      protocol: 'oidc',
      claims,
      flow: flow.payload,
    });
  } catch (err) {
    if (err instanceof SsoFailure) {
      return failSsoFlow(deps, request, reply, { connectionId, protocol: 'oidc', failure: err });
    }
    // Anything else still ends the flow on the login page, never a 500 with a library's text: only
    // the error's class name is logged (its message may echo what the IdP sent).
    deps.log.error(
      { component: 'sso', errorClass: err instanceof Error ? err.constructor.name : typeof err },
      'single sign-on failed unexpectedly',
    );
    return failSsoFlow(deps, request, reply, {
      connectionId,
      protocol: 'oidc',
      failure: new SsoFailure('invalid_response', 'oidc.other'),
    });
  }
}
