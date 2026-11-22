import type { IncomingHttpHeaders } from 'node:http';
import { z } from 'zod';
import { outboundRequest, type OutboundFailed, type Resolver } from '../../http/outbound';
import { VERSION } from '../../index';
import { namedRequest, ScmError, type ScmErrorKind, type ScmErrorOptions } from '../provider';
import { retryAfterSeconds } from '../retry-after';
import { scmRefusedAddress } from '../url';
import { AZURE_REPOSITORY_ID } from './url';

/** Azure DevOps design §7.4, as for GitLab: every request has 10 s in all ... */
export const AZURE_TIMEOUT_MS = 10_000;
/** ... answers over 8 MiB are refused ... */
export const MAX_AZURE_RESPONSE_BYTES = 8 * 1024 * 1024;
/** ... and one job makes at most this many requests. */
export const MAX_AZURE_REQUESTS = 400;
/** Design §7.9 and the probe (item 19): `7.0` everywhere, named preview versions where needed. */
export const AZURE_API_VERSION = '7.0';
/** connectionData is a preview route (Server answers 7.0 with VssInvalidPreviewVersionException). */
export const CONNECTION_DATA_API_VERSION = '7.0-preview';
/** A success that asks the next request to wait (`Retry-After`, `X-RateLimit-Delay`): at most 30 s. */
export const MAX_AZURE_PACE_MS = 30_000;

/** The fixed texts; Azure DevOps' own words are never shown or logged. */
export const AZURE_TEXT = {
  signInPage: 'Azure DevOps answered with a sign-in page; check the credential',
  refused: 'Azure DevOps refused the credential (HTTP 401)',
  signInRequired: 'The identity is not a member of this organization or has no access level',
  forbidden: 'The Azure DevOps identity lacks the permission for this request (HTTP 403)',
  notFound: 'Azure DevOps found nothing there, or the identity cannot see it (HTTP 404)',
  rateLimited: 'Azure DevOps is limiting requests (HTTP 429)',
  badAnswer: "Azure DevOps's answer was not understood",
  repositoryId: 'The repository id is not an Azure DevOps repository id (a GUID)',
  notPublic:
    'The Azure DevOps host resolves to a private, loopback or otherwise non-public address; list it in QUALOR_SCM_INTERNAL_HOSTS',
  refusedAddress:
    'The Azure DevOps host resolves to a link-local, cloud metadata or loopback address',
  unresolved: 'The Azure DevOps host could not be resolved',
  timeout: 'Azure DevOps did not answer in time',
} as const;

/** A failed Azure DevOps request; see {@link ScmError}. */
export class AzureError extends ScmError {
  constructor(
    kind: ScmErrorKind,
    message: string,
    options: Omit<ScmErrorOptions, 'providerMessage'> & { azureMessage?: string | null } = {},
  ) {
    const { azureMessage, ...rest } = options;
    super(kind, message, { ...rest, providerMessage: azureMessage ?? null });
    this.name = 'AzureError';
  }

  /** The `message` of Azure DevOps' error body (decisions only, never logged or shown). */
  get azureMessage(): string | null {
    return this.providerMessage;
  }
}

/**
 * A PAT (sent as Basic with an empty user name), or a bearer token from Microsoft Entra that
 * `token()` gives for each request (the caller caches it); an Entra failure is the error
 * `entraToken` throws, passed on as it is.
 */
export type AzureCredential =
  { kind: 'pat'; pat: string } | { kind: 'bearer'; token: () => Promise<string> };

export interface AzureConnectionInput {
  /** The normalised base URL: `https://dev.azure.com/<organization>`, or a Server collection. */
  baseUrl: string;
  credential: AzureCredential;
  allowInternalHosts: boolean;
}

export interface AzureClientOptions {
  timeoutMs?: number;
  resolve?: Resolver;
  /** Default {@link MAX_AZURE_REQUESTS}. */
  maxRequests?: number;
  /** How the client waits before a request a success asked to delay; default a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** Gives up every request of this client once it aborts. */
  signal?: AbortSignal;
}

/** Who the credential is: `authenticatedUser` of connectionData. */
export interface AzureIdentity {
  id: string;
  /** `providerDisplayName`: the app's name for a service principal, else the account's. */
  displayName: string;
}

export interface AzureRepository {
  /** Lower-case GUIDs. */
  id: string;
  name: string;
  projectId: string;
  projectName: string;
  webUrl: string;
  /** Without `refs/heads/`; null for an empty repository. */
  defaultBranch: string | null;
  isDisabled: boolean;
}

// ─── Response shapes (the fields Qualor reads; server/test/azure-shapes/ holds recorded ones) ──

const connectionData = z.looseObject({
  authenticatedUser: z.looseObject({
    id: z.string().min(1),
    providerDisplayName: z.string().min(1),
  }),
});
const repository = z.looseObject({
  id: z.string().regex(AZURE_REPOSITORY_ID),
  name: z.string().min(1),
  project: z.looseObject({ id: z.string().regex(AZURE_REPOSITORY_ID), name: z.string().min(1) }),
  webUrl: z.string().min(1),
  defaultBranch: z.string().nullish(),
  isDisabled: z.boolean().nullish(),
});
const repositoryList = z.looseObject({ value: z.array(repository) });
/** WrappedException, the error body (probe item 10). */
const errorBody = z.looseObject({ message: z.string() });

/** For tests against the recorded shapes. */
export const AZURE_SHAPES = { connectionData, repository, repositoryList } as const;

function repositoryOf(answer: z.infer<typeof repository>): AzureRepository {
  return {
    id: answer.id.toLowerCase(),
    name: answer.name,
    projectId: answer.project.id.toLowerCase(),
    projectName: answer.project.name,
    webUrl: answer.webUrl,
    defaultBranch: answer.defaultBranch ? answer.defaultBranch.replace(/^refs\/heads\//, '') : null,
    isDisabled: answer.isDisabled ?? false,
  };
}

/** A request as a fixed text for the logs: each GUID Qualor put in the path is `{id}`. */
export function azureRoute(method: string, path: string): string {
  return `${method} ${path.replace(/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/g, '{id}')}`;
}

function transportError(failed: OutboundFailed): AzureError {
  switch (failed.cause) {
    case 'not_public':
      return new AzureError('refused', AZURE_TEXT.notPublic, { reason: 'not_public' });
    case 'refused_address':
      return new AzureError('refused', AZURE_TEXT.refusedAddress, { reason: 'not_public' });
    case 'unresolved':
      return new AzureError('transient', AZURE_TEXT.unresolved, { reason: 'unresolved' });
    case 'too_large':
      return new AzureError('bad_answer', AZURE_TEXT.badAnswer);
    case 'timeout':
    case 'connect_timeout':
      return new AzureError('transient', AZURE_TEXT.timeout, { reason: 'timeout' });
    default:
      return new AzureError(
        'transient',
        failed.code
          ? `Azure DevOps could not be reached (${failed.code})`
          : 'Azure DevOps could not be reached',
        { reason: 'unreachable' },
      );
  }
}

/** The body's text without a leading byte order mark (Server writes one before JSON). */
function textOf(body: Buffer): string {
  const text = body.toString('utf8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** Azure DevOps' error `message`, for decisions only, with the credential cut out. */
function azureMessageOf(body: Buffer, secrets: string[]): string | null {
  try {
    const parsed = errorBody.safeParse(JSON.parse(textOf(body)));
    if (!parsed.success) return null;
    let text = parsed.data.message;
    for (const secret of secrets) if (secret) text = text.split(secret).join('[credential]');
    return text.slice(0, 1_000);
  } catch {
    return null;
  }
}

/** Milliseconds a success asks the next request to wait: `Retry-After`, else `X-RateLimit-Delay`. */
function paceOf(headers: IncomingHttpHeaders, nowMs: number): number {
  const retryAfter = headers['retry-after']?.trim() ?? '';
  const delay = headers['x-ratelimit-delay'];
  let ms = 0;
  if (/^\d{1,9}(\.\d+)?$/.test(retryAfter)) ms = Number(retryAfter) * 1000;
  else if (retryAfter !== '' && !Number.isNaN(Date.parse(retryAfter))) {
    ms = Date.parse(retryAfter) - nowMs;
  } else if (typeof delay === 'string' && /^\d{1,9}(\.\d+)?$/.test(delay.trim())) {
    ms = Number(delay.trim()) * 1000;
  }
  return Math.min(MAX_AZURE_PACE_MS, Math.max(0, Math.ceil(ms)));
}

/** Waits `ms`, or less when `signal` aborts (the next request then fails at once). */
function timer(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(handle);
      signal?.removeEventListener('abort', done);
      resolve();
    };
    const handle = setTimeout(done, ms);
    signal?.addEventListener('abort', done, { once: true });
  });
}

/**
 * Azure DevOps REST (design §7.1, §7.9), through {@link outboundRequest}: the connection's base URL
 * only, the SSRF rules unless the host is listed in `QUALOR_SCM_INTERNAL_HOSTS`, 10 s per request,
 * answers up to 8 MiB, at most {@link MAX_AZURE_REQUESTS} requests per client (one client per job),
 * `api-version=7.0` unless a route names its own. No redirect is followed: any 3xx, and any 2xx
 * HTML page, is a sign-in page, so a refused credential. Nothing is retried; a success with
 * `Retry-After` or `X-RateLimit-Delay` makes the next request wait (at most 30 s). The credential
 * goes only into `Authorization`; no error, return value or log line carries it.
 */
export class AzureDevOpsClient {
  #requestCount = 0;
  /** Until when (ms since the epoch) the next request waits; 0: it does not. */
  #notBefore = 0;
  /** True private fields: the credential is no property a logger could print. */
  readonly #connection: AzureConnectionInput;
  readonly #options: AzureClientOptions;

  constructor(connection: AzureConnectionInput, options: AzureClientOptions = {}) {
    this.#connection = connection;
    this.#options = options;
  }

  /**
   * Requests counted against the budget so far; one the outbound rules refused, or whose token
   * Entra refused, counts too.
   */
  get requestCount(): number {
    return this.#requestCount;
  }

  async connectionData(): Promise<AzureIdentity> {
    const answer = await this.#get(
      '/_apis/connectionData',
      connectionData,
      CONNECTION_DATA_API_VERSION,
    );
    const { id, providerDisplayName } = answer.authenticatedUser;
    return { id, displayName: providerDisplayName };
  }

  /** Every repository of the organisation or collection, with its project (design §7.2). */
  async repositories(): Promise<AzureRepository[]> {
    const answer = await this.#get('/_apis/git/repositories', repositoryList);
    return answer.value.map(repositoryOf);
  }

  async repository(id: string): Promise<AzureRepository> {
    if (!AZURE_REPOSITORY_ID.test(id)) {
      throw new AzureError('refused', AZURE_TEXT.repositoryId, { reason: 'invalid_input' });
    }
    return repositoryOf(await this.#get(`/_apis/git/repositories/${id.toLowerCase()}`, repository));
  }

  /** The answer of a GET as `schema` reads it; its error names the route ({@link azureRoute}). */
  async #get<T>(
    path: string,
    schema: z.ZodType<T>,
    apiVersion: string = AZURE_API_VERSION,
  ): Promise<T> {
    const max = this.#options.maxRequests ?? MAX_AZURE_REQUESTS;
    if (this.#requestCount >= max) {
      throw new AzureError('budget', `More than ${max} Azure DevOps requests in one job`);
    }
    this.#requestCount += 1;
    const now = this.#options.now ?? Date.now;
    const wait = this.#notBefore - now();
    this.#notBefore = 0;
    if (wait > 0) {
      await (this.#options.sleep ?? ((ms) => timer(ms, this.#options.signal)))(wait);
    }
    // Outside the naming below: an Entra failure keeps the request it names.
    const { authorization, secrets } = await this.#authorization();
    try {
      const { status, json } = await this.#send(path, apiVersion, authorization, secrets, now);
      const parsed = schema.safeParse(json);
      if (!parsed.success) throw new AzureError('bad_answer', AZURE_TEXT.badAnswer, { status });
      return parsed.data;
    } catch (err) {
      throw namedRequest(err, azureRoute('GET', path));
    }
  }

  /** The `Authorization` header, and the secrets no message may carry. */
  async #authorization(): Promise<{ authorization: string; secrets: string[] }> {
    const { credential } = this.#connection;
    if (credential.kind === 'pat') {
      const basic = Buffer.from(`:${credential.pat}`).toString('base64');
      return { authorization: `Basic ${basic}`, secrets: [credential.pat, basic] };
    }
    const token = await credential.token();
    return { authorization: `Bearer ${token}`, secrets: [token] };
  }

  async #send(
    path: string,
    apiVersion: string,
    authorization: string,
    secrets: string[],
    now: () => number,
  ): Promise<{ status: number; json: unknown }> {
    const { baseUrl, allowInternalHosts } = this.#connection;
    const separator = path.includes('?') ? '&' : '?';
    const result = await outboundRequest(
      {
        url: `${baseUrl}${path}${separator}api-version=${apiVersion}`,
        method: 'GET',
        headers: { authorization, accept: 'application/json', 'user-agent': `Qualor/${VERSION}` },
      },
      {
        allowInternalHosts,
        refuseAddress: scmRefusedAddress(new URL(baseUrl)),
        timeoutMs: this.#options.timeoutMs ?? AZURE_TIMEOUT_MS,
        ...(this.#options.resolve ? { resolve: this.#options.resolve } : {}),
        maxResponseBytes: MAX_AZURE_RESPONSE_BYTES,
        overflow: 'fail',
        names: { noun: 'Azure DevOps', target: 'Azure DevOps' },
        ...(this.#options.signal ? { signal: this.#options.signal } : {}),
      },
    );
    if (result.kind === 'failed') throw transportError(result);
    const { status, headers, body } = result;
    const html = /text\/html/i.test(headers['content-type'] ?? '');
    if ((status >= 300 && status < 400) || (status >= 200 && status < 300 && html)) {
      throw new AzureError('auth', AZURE_TEXT.signInPage, { status, reason: 'html_answer' });
    }
    if (status >= 200 && status < 300) {
      this.#notBefore = now() + paceOf(headers, now());
      try {
        return { status, json: JSON.parse(textOf(body)) as unknown };
      } catch {
        throw new AzureError('bad_answer', AZURE_TEXT.badAnswer, { status });
      }
    }
    if (status === 401) {
      const serviceError = [headers['x-tfs-serviceerror'] ?? []].flat().join(' ');
      if (serviceError.includes('TF401444') || body.includes('TF401444')) {
        throw new AzureError('auth', AZURE_TEXT.signInRequired, {
          status,
          reason: 'sign_in_required',
        });
      }
      throw new AzureError('auth', AZURE_TEXT.refused, { status, reason: 'http' });
    }
    const azureMessage = azureMessageOf(body, secrets);
    if (status === 403) {
      throw new AzureError('auth', AZURE_TEXT.forbidden, {
        status,
        reason: 'permission_missing',
        azureMessage,
      });
    }
    if (status === 404) {
      throw new AzureError('not_found', AZURE_TEXT.notFound, {
        status,
        reason: 'http',
        azureMessage,
      });
    }
    if (status === 429) {
      throw new AzureError('rate_limited', AZURE_TEXT.rateLimited, {
        status,
        reason: 'http',
        retryAfterSeconds: retryAfterSeconds(headers, now()),
        azureMessage,
      });
    }
    throw new AzureError(
      status >= 500 ? 'transient' : 'refused',
      `Azure DevOps answered HTTP ${status}`,
      {
        status,
        reason: 'http',
        azureMessage,
      },
    );
  }
}
