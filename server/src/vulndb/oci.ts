import { createHash } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import {
  outboundRequest,
  outboundStream,
  type OutboundFailed,
  type Resolver,
} from '../http/outbound';
import { VERSION } from '../index';
import { isInternalHostAllowed, scmRefusedAddress } from '../scm/url';
import { VULNDB_REPOSITORY_PATTERN } from './settings';

export const TRIVY_LAYER_MEDIA_TYPE = 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip';
export const OCI_MANIFEST_TYPE = 'application/vnd.oci.image.manifest.v1+json';
export const DOCKER_MANIFEST_TYPE = 'application/vnd.docker.distribution.manifest.v2+json';
/** Redirects followed by hand, each one checked as the first request was. */
export const MAX_REDIRECTS = 5;
/** The download caps: the layer's size, the whole download, and the wait between two chunks. */
export const DOWNLOAD_MAX_BYTES = 2 * 1024 ** 3;
export const DOWNLOAD_TOTAL_MS = 15 * 60_000;
export const DOWNLOAD_IDLE_MS = 60_000;
/** A token or manifest request, and the wait for a blob's status line. */
const REQUEST_TIMEOUT_MS = 30_000;
/** The OCI distribution spec's recommended manifest limit. */
const MANIFEST_MAX_BYTES = 4 * 1024 * 1024;
const TOKEN_MAX_BYTES = 1024 * 1024;
/** A refused answer's body is read only this far (outbound reads it only to classify it). */
const ERROR_BODY_BYTES = 64 * 1024;
const INTERNAL_HOSTS_VARIABLE = 'QUALOR_VULNDB_INTERNAL_HOSTS';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface OciReference {
  /** `host` or `host:port`. */
  registry: string;
  repository: string;
  /** A tag, or a `sha256:` digest. */
  reference: string;
}

/** Credentials for a mirror: sent as HTTP Basic to the token service (or a Basic registry). */
export interface OciAuth {
  username?: string;
  password?: string;
}

export interface OciOptions {
  /**
   * `config.vulndb.internalHosts`: only a request to one of these may reach a private address,
   * or use plain http.
   */
  internalHosts: ReadonlySet<string>;
  /** Tests substitute DNS; the default is the system resolver. */
  resolve?: Resolver;
  /** The caller gives up: the exchange (and a blob's stream) is cut. */
  signal?: AbortSignal;
}

export type OciProblemCode =
  'AUTH' | 'NOT_FOUND' | 'NO_LAYER' | 'BLOCKED' | 'UNREACHABLE' | 'BAD_ANSWER' | 'TOO_LARGE';

/** What went wrong, with a short text for an administrator (never a URL query or a secret). */
export interface OciProblem {
  code: OciProblemCode;
  message: string;
}

export interface LayerDescriptor {
  digest: string;
  size: number;
}

export function isOciProblem(value: unknown): value is OciProblem {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { code?: unknown }).code === 'string' &&
    typeof (value as { message?: unknown }).message === 'string'
  );
}

const problem = (code: OciProblemCode, message: string): OciProblem => ({ code, message });

/**
 * `registry/path/name:tag` or `registry/path/name@sha256:<hex>`, as the settings store it (the
 * first segment is always the registry). Throws for anything else.
 */
export function parseReference(ref: string): OciReference {
  if (ref.length > 512 || !VULNDB_REPOSITORY_PATTERN.test(ref)) {
    throw new Error('not an OCI reference (registry/repository:tag or @sha256:<digest>)');
  }
  const at = ref.indexOf('@');
  const split = at === -1 ? ref.lastIndexOf(':') : at;
  const name = ref.slice(0, split);
  const slash = name.indexOf('/');
  return {
    registry: name.slice(0, slash),
    repository: name.slice(slash + 1),
    reference: ref.slice(split + 1),
  };
}

/** One call: the reference, the credentials, and what the registry handed out so far. */
interface Session {
  ref: OciReference;
  auth: OciAuth;
  opts: OciOptions;
  /**
   * The registry's origin once a request reached it: `https://`, or `http://` for a listed
   * registry that answers no TLS.
   */
  base: string | null;
  /** The registry's `authorization` header, once the handshake gave one. */
  authorization: string | null;
  /** When the whole call must be over (epoch ms). */
  deadline: number;
}

type Mode = 'buffer' | 'stream';

type Got =
  | { kind: 'response'; url: URL; status: number; headers: IncomingHttpHeaders; body: Buffer }
  | { kind: 'stream'; url: URL; chunks: AsyncIterable<Buffer> }
  /** No answer: `first` says it was the request to the start URL (no redirect followed yet). */
  | { kind: 'failed'; url: URL; failed: OutboundFailed; first: boolean };

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function withHost(reason: string, host: string): string {
  return reason.includes(host) ? reason : `${reason} (${host})`;
}

/** What an exchange without an answer is. */
function problemOf(failed: OutboundFailed, url: URL): OciProblem {
  switch (failed.cause) {
    case 'not_public':
      return problem(
        'BLOCKED',
        `${url.host} resolves to a private, loopback or other non-public address; list it in ${INTERNAL_HOSTS_VARIABLE} to allow it`,
      );
    case 'refused_address':
      return problem('BLOCKED', `${url.host} resolves to a link-local or cloud metadata address`);
    case 'too_large':
      return problem('TOO_LARGE', failed.reason);
    case 'invalid_url':
    case 'request':
      return problem('BAD_ANSWER', withHost(failed.reason, url.host));
    default:
      return problem('UNREACHABLE', withHost(failed.reason, url.host));
  }
}

/** What a final answer outside 2xx is. */
function statusProblem(got: { url: URL; status: number }, missing: string): OciProblem {
  const answered = `${got.url.host} answered ${got.status}`;
  if (got.status === 401 || got.status === 403) return problem('AUTH', answered);
  if (got.status === 404) return problem('NOT_FOUND', `${missing} (${answered})`);
  return problem('BAD_ANSWER', answered);
}

/**
 * One request, with no redirect followed (http/outbound.ts): https, or http only for a host in
 * the internal-host list, which is also the only kind of host that may resolve to a private
 * address. Link-local and cloud metadata addresses are never reached, and loopback only for a
 * loopback host.
 */
async function exchange(
  session: Session,
  url: URL,
  headers: Record<string, string>,
  mode: Mode,
  maxBytes: number,
  first: boolean,
): Promise<Got | OciProblem> {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return problem('BLOCKED', 'The registry sent a URL that is not http or https');
  }
  const internal = isInternalHostAllowed(url, session.opts.internalHosts);
  if (url.protocol === 'http:' && !internal) {
    return problem(
      'BLOCKED',
      `${url.host} is reached over plain http, which only a host in ${INTERNAL_HOSTS_VARIABLE} may use`,
    );
  }
  const remainingMs = session.deadline - Date.now();
  if (remainingMs <= 0) {
    return problem(
      'UNREACHABLE',
      `The download was not complete within ${DOWNLOAD_TOTAL_MS / 60_000} min`,
    );
  }
  const request = { url: url.href, method: 'GET' as const, headers };
  const reach = {
    allowInternalHosts: internal,
    refuseAddress: scmRefusedAddress(url),
    names: { noun: 'registry', target: url.host },
    ...(session.opts.resolve ? { resolve: session.opts.resolve } : {}),
    ...(session.opts.signal ? { signal: session.opts.signal } : {}),
  };
  if (mode === 'buffer') {
    const got = await outboundRequest(request, {
      ...reach,
      timeoutMs: Math.min(REQUEST_TIMEOUT_MS, remainingMs),
      maxResponseBytes: maxBytes,
      overflow: 'fail',
    });
    if (got.kind === 'failed') return { kind: 'failed', url, failed: got, first };
    return { kind: 'response', url, status: got.status, headers: got.headers, body: got.body };
  }
  const got = await outboundStream(request, {
    ...reach,
    limits: {
      firstByteMs: Math.min(REQUEST_TIMEOUT_MS, remainingMs),
      idleMs: DOWNLOAD_IDLE_MS,
      totalMs: remainingMs,
      maxStreamBytes: DOWNLOAD_MAX_BYTES,
      maxErrorBytes: ERROR_BODY_BYTES,
    },
  });
  if (got.kind === 'failed') return { kind: 'failed', url, failed: got, first };
  if (got.kind === 'stream') return { kind: 'stream', url, chunks: got.chunks };
  return { kind: 'response', url, status: got.status, headers: got.headers, body: got.body };
}

/**
 * A request to `start` and the redirects it answers with, by hand, at most {@link MAX_REDIRECTS}.
 * Every hop is checked again ({@link exchange}). `authorization` goes only to `start`'s origin, so
 * a registry's token never reaches the host its blobs redirect to.
 */
async function follow(
  session: Session,
  start: URL,
  authorization: string | null,
  accept: string | null,
  mode: Mode,
  maxBytes: number,
): Promise<Got | OciProblem> {
  let url = start;
  for (let redirects = 0; ; redirects++) {
    const headers: Record<string, string> = { 'user-agent': `Qualor/${VERSION}` };
    if (accept !== null) headers.accept = accept;
    if (authorization !== null && url.origin === start.origin) {
      headers.authorization = authorization;
    }
    const got = await exchange(session, url, headers, mode, maxBytes, redirects === 0);
    if (isOciProblem(got) || got.kind !== 'response' || !REDIRECT_STATUSES.has(got.status)) {
      return got;
    }
    if (redirects === MAX_REDIRECTS) {
      return problem('BAD_ANSWER', `${url.host} answered more than ${MAX_REDIRECTS} redirects`);
    }
    const location = single(got.headers.location);
    if (location === undefined || location === '') {
      return problem('BAD_ANSWER', `${url.host} answered a redirect without a location`);
    }
    try {
      url = new URL(location, url);
    } catch {
      return problem('BAD_ANSWER', `${url.host} answered a redirect to an invalid URL`);
    }
  }
}

/**
 * A request to the registry. Its origin is found on the first one: https; for a listed registry
 * that gives no answer over https, plain http (as Docker treats an insecure registry).
 */
async function reach(
  session: Session,
  path: string,
  accept: string | null,
  mode: Mode,
  maxBytes: number,
): Promise<Got | OciProblem> {
  const send = (base: string) =>
    follow(session, new URL(path, base), session.authorization, accept, mode, maxBytes);
  if (session.base !== null) return send(session.base);
  const https = `https://${session.ref.registry}`;
  const got = await send(https);
  if (isOciProblem(got) || got.kind !== 'failed' || !got.first) {
    if (!isOciProblem(got)) session.base = https;
    return got;
  }
  const http = `http://${session.ref.registry}`;
  if (
    got.failed.cause !== 'connection' ||
    !isInternalHostAllowed(new URL(http), session.opts.internalHosts)
  ) {
    return got;
  }
  const plain = await send(http);
  // Neither answers: what https said is the more telling.
  if (!isOciProblem(plain) && plain.kind === 'failed' && plain.first) return got;
  session.base = http;
  return plain;
}

interface Challenge {
  scheme: 'bearer' | 'basic';
  params: Record<string, string>;
}

/** The first Bearer or Basic challenge of a `www-authenticate` header. */
function parseChallenge(header: string | string[] | undefined): Challenge | null {
  const values = Array.isArray(header) ? header : header === undefined ? [] : [header];
  for (const value of values) {
    const match = /^\s*(bearer|basic)(?:\s+(.*))?$/i.exec(value);
    if (!match) continue;
    const params: Record<string, string> = {};
    const pairs = /([a-z][a-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))/gi;
    for (const [, key = '', quoted, bare = ''] of (match[2] ?? '').matchAll(pairs)) {
      params[key.toLowerCase()] = quoted === undefined ? bare : quoted.replace(/\\(.)/g, '$1');
    }
    const scheme = (match[1] ?? '').toLowerCase() === 'basic' ? 'basic' : 'bearer';
    return { scheme, params };
  }
  return null;
}

function basicOf(auth: OciAuth): string | null {
  const username = auth.username ?? '';
  const password = auth.password ?? '';
  if (username === '' && password === '') return null;
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

/**
 * The handshake a 401 asks for: a Bearer token from the realm the challenge names (anonymous, or
 * with the credentials as HTTP Basic), or the credentials themselves for a Basic registry. Sets
 * the session's authorization; else the problem.
 */
async function authorize(
  session: Session,
  header: string | string[] | undefined,
): Promise<OciProblem | null> {
  const challenge = parseChallenge(header);
  const basic = basicOf(session.auth);
  if (challenge?.scheme === 'basic') {
    if (basic === null) return problem('AUTH', 'The registry needs a user and password');
    session.authorization = basic;
    return null;
  }
  const realm = challenge?.params.realm;
  if (realm === undefined || realm === '') {
    return problem('AUTH', 'The registry answered 401 without naming a token service');
  }
  let url: URL;
  try {
    url = new URL(realm);
  } catch {
    return problem('BAD_ANSWER', 'The registry named a token service URL that is not valid');
  }
  const service = challenge?.params.service;
  if (service !== undefined && service !== '') url.searchParams.set('service', service);
  url.searchParams.set('scope', `repository:${session.ref.repository}:pull`);
  const got = await follow(session, url, basic, 'application/json', 'buffer', TOKEN_MAX_BYTES);
  if (isOciProblem(got)) return got;
  if (got.kind === 'failed') return problemOf(got.failed, got.url);
  if (got.kind !== 'response') {
    return problem('BAD_ANSWER', 'The token service streamed its answer');
  }
  if (got.status === 401 || got.status === 403) {
    const hint =
      basic === null ? 'the registry needs a user and password' : 'check the user and password';
    return problem('AUTH', `The token service ${got.url.host} answered ${got.status}: ${hint}`);
  }
  if (got.status < 200 || got.status > 299) {
    return problem('BAD_ANSWER', `The token service ${got.url.host} answered ${got.status}`);
  }
  let token: unknown;
  try {
    const json = JSON.parse(got.body.toString('utf8')) as {
      token?: unknown;
      access_token?: unknown;
    };
    token = json.token ?? json.access_token;
  } catch {
    token = undefined;
  }
  if (typeof token !== 'string' || !/^[\x21-\x7e]{1,65536}$/.test(token)) {
    return problem('BAD_ANSWER', `The token service ${got.url.host} answered without a token`);
  }
  session.authorization = `Bearer ${token}`;
  return null;
}

/** A registry request, with the token handshake when the registry answers 401 (once). */
async function toRegistry(
  session: Session,
  path: string,
  accept: string | null,
  mode: Mode,
  maxBytes: number,
): Promise<Got | OciProblem> {
  const got = await reach(session, path, accept, mode, maxBytes);
  if (isOciProblem(got) || got.kind !== 'response' || got.status !== 401) return got;
  if (session.authorization !== null) return got;
  const refused = await authorize(session, got.headers['www-authenticate']);
  if (refused !== null) return refused;
  return reach(session, path, accept, mode, maxBytes);
}

function sessionOf(ref: string, auth: OciAuth, opts: OciOptions): Session {
  return {
    ref: parseReference(ref),
    auth,
    opts,
    base: null,
    authorization: null,
    deadline: Date.now() + DOWNLOAD_TOTAL_MS,
  };
}

const MANIFEST_ACCEPT = `${OCI_MANIFEST_TYPE}, ${DOCKER_MANIFEST_TYPE}`;
const MANIFEST_TYPES = new Set([OCI_MANIFEST_TYPE, DOCKER_MANIFEST_TYPE]);

/** The Trivy layer of a manifest's bytes, or the problem with them. */
function layerOf(
  body: Buffer,
  headers: IncomingHttpHeaders,
  ref: OciReference,
): LayerDescriptor | OciProblem {
  if (DIGEST_PATTERN.test(ref.reference)) {
    const digest = `sha256:${createHash('sha256').update(body).digest('hex')}`;
    if (digest !== ref.reference) {
      return problem('BAD_ANSWER', 'The manifest does not match the digest of the reference');
    }
  }
  let manifest: { mediaType?: unknown; layers?: unknown };
  try {
    manifest = JSON.parse(body.toString('utf8')) as typeof manifest;
  } catch {
    return problem('BAD_ANSWER', 'The manifest is not JSON');
  }
  if (typeof manifest !== 'object' || manifest === null) {
    return problem('BAD_ANSWER', 'The manifest is not a JSON object');
  }
  const contentType = single(headers['content-type'])?.split(';')[0]?.trim();
  const mediaType = typeof manifest.mediaType === 'string' ? manifest.mediaType : contentType;
  if (
    mediaType === undefined ||
    !MANIFEST_TYPES.has(mediaType) ||
    !Array.isArray(manifest.layers)
  ) {
    return problem('BAD_ANSWER', 'The reference does not name an image manifest');
  }
  const layer = (manifest.layers as unknown[]).find(
    (l): l is { digest?: unknown; size?: unknown } =>
      typeof l === 'object' &&
      l !== null &&
      (l as { mediaType?: unknown }).mediaType === TRIVY_LAYER_MEDIA_TYPE,
  );
  if (layer === undefined) {
    return problem('NO_LAYER', `The manifest has no layer of type ${TRIVY_LAYER_MEDIA_TYPE}`);
  }
  if (typeof layer.digest !== 'string' || !DIGEST_PATTERN.test(layer.digest)) {
    return problem('BAD_ANSWER', 'The Trivy layer has no sha256 digest');
  }
  if (typeof layer.size !== 'number' || !Number.isSafeInteger(layer.size) || layer.size < 0) {
    return problem('BAD_ANSWER', 'The Trivy layer has no valid size');
  }
  if (layer.size > DOWNLOAD_MAX_BYTES) {
    return problem('TOO_LARGE', `The Trivy layer is ${layer.size} bytes, over the 2 GiB limit`);
  }
  return { digest: layer.digest, size: layer.size };
}

/**
 * The digest and size of the Trivy database layer `ref` names: the manifest (OCI or Docker v2),
 * fetched after the registry's Bearer handshake (anonymous, or `auth` as HTTP Basic to the token
 * realm). Throws only for a `ref` that is not a reference.
 */
export async function fetchLayerDescriptor(
  ref: string,
  auth: OciAuth,
  opts: OciOptions,
): Promise<LayerDescriptor | OciProblem> {
  const session = sessionOf(ref, auth, opts);
  const { repository, reference } = session.ref;
  const got = await toRegistry(
    session,
    `/v2/${repository}/manifests/${reference}`,
    MANIFEST_ACCEPT,
    'buffer',
    MANIFEST_MAX_BYTES,
  );
  if (isOciProblem(got)) return got;
  if (got.kind === 'failed') return problemOf(got.failed, got.url);
  if (got.kind !== 'response') return problem('BAD_ANSWER', 'The manifest was streamed');
  if (got.status < 200 || got.status > 299) {
    return statusProblem(got, `The registry has no ${repository}:${reference}`);
  }
  return layerOf(got.body, got.headers, session.ref);
}

/**
 * The blob `digest` of `ref`'s repository, as it arrives: the registry's handshake, then the
 * redirects to its storage (each checked again, without the token). The download is capped at
 * {@link DOWNLOAD_MAX_BYTES}, {@link DOWNLOAD_TOTAL_MS} in all and {@link DOWNLOAD_IDLE_MS}
 * between chunks; the chunks throw `OutboundStreamError` when it fails after it began. The bytes
 * are not checked against the digest here (storeDataset does that). Throws only for a `ref` that
 * is not a reference or a `digest` that is not sha256.
 */
export async function openBlob(
  ref: string,
  digest: string,
  auth: OciAuth,
  opts: OciOptions,
): Promise<AsyncIterable<Buffer> | OciProblem> {
  if (!DIGEST_PATTERN.test(digest)) throw new Error('not a sha256 digest');
  const session = sessionOf(ref, auth, opts);
  const got = await toRegistry(
    session,
    `/v2/${session.ref.repository}/blobs/${digest}`,
    null,
    'stream',
    ERROR_BODY_BYTES,
  );
  if (isOciProblem(got)) return got;
  if (got.kind === 'failed') return problemOf(got.failed, got.url);
  if (got.kind === 'stream') return got.chunks;
  return statusProblem(got, `The registry has no blob ${digest}`);
}
