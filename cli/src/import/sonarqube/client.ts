import {
  currentUserSchema,
  type ImportReport,
  organizationsSchema,
  pageTotal,
  parseSonarVersion,
  type SonarVersion,
  versionAtLeast,
} from '@qualor/shared';
import type { z } from 'zod';
import { CliError, EXIT } from '../../errors';
import type { Logger } from '../../log';
import {
  clean,
  type HttpResponse,
  request,
  type RequestOptions,
  retryAfterMs,
  type ServerEndpoint,
  UnreachableError,
} from '../../server/http';

/** Spec §4.4 and §4.5: the only paths this client may request, all of them reads. */
export const SONAR_READ_ENDPOINTS: ReadonlySet<string> = new Set([
  'api/server/version',
  'api/users/current',
  'api/organizations/search',
  'api/qualityprofiles/search',
  'api/rules/search',
  'api/qualitygates/list',
  'api/qualitygates/show',
  'api/qualitygates/get_by_project',
  'api/components/search',
  'api/components/show',
  'api/project_branches/list',
  'api/issues/search',
  'api/hotspots/search',
]);

/** Spec §4.4: the endpoints SonarQube Cloud scopes by `organization`. */
export const ORG_ENDPOINTS: ReadonlySet<string> = new Set([
  'api/qualityprofiles/search',
  'api/rules/search',
  'api/qualitygates/list',
  'api/qualitygates/show',
  'api/qualitygates/get_by_project',
  'api/components/search',
  'api/issues/search',
]);

export type SonarKind = 'server' | 'cloud';
export type Transport = (ep: ServerEndpoint, o: RequestOptions) => Promise<HttpResponse>;
type Warning = ImportReport['warnings'][number];

export interface SonarClientOptions {
  endpoint: ServerEndpoint;
  kind: SonarKind;
  organization: string | null;
  transport?: Transport | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  /** Where each warning is logged once, when it is recorded. */
  log?: Logger | undefined;
}

const MAX_ANSWER_BYTES = 8 * 1024 * 1024;
const VERSION_MAX_BYTES = 64;
const RETRY_STATUSES = new Set([429, 502, 503, 504]);
const BACKOFF_MS = [1000, 2000, 4000] as const;
const MAX_RETRY_AFTER_MS = 60_000;
/** Spec §5.2: pages of 500. */
export const PAGE_SIZE = 500;
/** SonarQube's result window: p × ps ≤ 10 000 (spec §5.2), so at most 20 pages of 500. */
export const RESULT_WINDOW = 10_000;
const CLOUD_HOSTS = new Set(['sonarcloud.io', 'sonarqube.us']);

/** Spec §4.1: `auto` decides by the `--url` host only (`https` and exactly those hosts). */
export function detectSonarKind(url: string): SonarKind {
  const u = new URL(url);
  return u.protocol === 'https:' && CLOUD_HOSTS.has(u.hostname) ? 'cloud' : 'server';
}

const sleeper = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const readOnly = (what: string) =>
  new CliError(EXIT.SERVER, `internal error: the SonarQube client is read-only: refusing ${what}`);

/**
 * The one way a request leaves the SonarQube client (spec §4.5): `GET` on a path of
 * `SONAR_READ_ENDPOINTS`, both checked before any I/O; `organization` added on Cloud's **org**
 * endpoints; bounded retries of transient failures (spec §5.1). Redirects are never followed:
 * the transport returns a 3xx like any status.
 */
export async function sonarGet(
  o: SonarClientOptions,
  method: string,
  path: string,
  query: Record<string, string | undefined>,
  maxBytes: number,
): Promise<HttpResponse> {
  if (method !== 'GET') throw readOnly(`${JSON.stringify(method)} /${path}`);
  if (!SONAR_READ_ENDPOINTS.has(path)) {
    throw readOnly(`/${path}, which is not a read endpoint it knows`);
  }
  const q =
    o.kind === 'cloud' && ORG_ENDPOINTS.has(path)
      ? { ...query, organization: o.organization ?? '' }
      : query;
  const transport = o.transport ?? request;
  const sleep = o.sleep ?? sleeper;
  for (let attempt = 0; ; attempt += 1) {
    const backoff = BACKOFF_MS[attempt];
    let res: HttpResponse;
    try {
      res = await transport(o.endpoint, {
        method: 'GET',
        path,
        query: q,
        maxResponseBytes: maxBytes,
      });
    } catch (err) {
      if (err instanceof UnreachableError && backoff !== undefined) {
        await sleep(backoff);
        continue;
      }
      throw err;
    }
    if (!RETRY_STATUSES.has(res.status) || backoff === undefined) return res;
    const wait = retryAfterMs(res.headers, 0, Number.MAX_SAFE_INTEGER);
    if (wait !== null && wait > MAX_RETRY_AFTER_MS) return res;
    await sleep(wait ?? backoff);
  }
}

/** A 404: exit 4 like any failure, unless the caller expects it (`components/show`, spec §5.1). */
export class SonarNotFound extends CliError {
  override name = 'SonarNotFound';
  constructor(path: string) {
    super(EXIT.SERVER, `SonarQube answered 404 to GET /${path}`);
  }
}

function invalid(what: string, path: string, why: string): CliError {
  return new CliError(EXIT.SERVER, `SonarQube sent an invalid ${what} (GET /${path}: ${why})`);
}

/**
 * Reads SonarQube (spec §4, §5). Its only way out is `sonarGet`, always with `GET`; it has no
 * method that takes an HTTP method.
 */
export class SonarClient {
  readonly warnings: Warning[] = [];
  readonly #o: SonarClientOptions;

  constructor(o: SonarClientOptions) {
    this.#o = o;
  }

  get kind(): SonarKind {
    return this.#o.kind;
  }

  /** Records a warning for the report and logs it, once, here. */
  warn(code: Warning['code'], message: string): void {
    this.warnings.push({ code, message });
    this.#o.log?.warn(clean(message));
  }

  #check(res: HttpResponse, path: string): void {
    if (res.status === 200) return;
    if (res.status >= 300 && res.status < 400) {
      throw new CliError(
        EXIT.SERVER,
        `SonarQube answered GET /${path} with a redirect (${res.status}); redirects are not followed: pass the final address as --url`,
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new CliError(
        EXIT.AUTH,
        `SonarQube refused the token (${res.status}) for GET /${path}; use a user token (not an analysis token) with Browse permission on the projects`,
      );
    }
    if (res.status === 404) throw new SonarNotFound(path);
    throw new CliError(EXIT.SERVER, `SonarQube answered ${res.status} to GET /${path}`);
  }

  async get<T>(
    path: string,
    query: Record<string, string | undefined>,
    schema: z.ZodType<T>,
    what: string,
  ): Promise<T> {
    const res = await sonarGet(this.#o, 'GET', path, query, MAX_ANSWER_BYTES);
    this.#check(res, path);
    const type = String(res.headers['content-type'] ?? '');
    if (!type.startsWith('application/json')) throw invalid(what, path, 'not JSON');
    let body: unknown;
    try {
      body = JSON.parse(res.body) as unknown;
    } catch {
      throw invalid(what, path, 'not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) throw invalid(what, path, 'unexpected shape');
    return parsed.data;
  }

  /** `api/server/version`: plain text, at most 64 bytes. */
  async version(): Promise<string> {
    const res = await sonarGet(this.#o, 'GET', 'api/server/version', {}, VERSION_MAX_BYTES);
    this.#check(res, 'api/server/version');
    return res.body.trim();
  }

  /**
   * Spec §5.2: pages of `pageSize` (500), never one past the result window (`p × ps ≤ window`,
   * so at most 20 pages of one query), at most `maxItems` items (it must be at least 1); the
   * total is checked on every page and a change is a warning. Each item is kept once, by
   * `keyOf`: a page that shifted repeats items of the one before.
   *
   * Ruling S10: `complete` only when the items read, each counted once, reach the final total
   * **and** that total never changed between the pages of this read (`stable`). A change means
   * items moved between pages, so some may have been skipped whatever the count says. An item
   * closed and another opened between two pages leave the total as it was and cannot be seen
   * (spec §17).
   */
  async pages<P extends { paging?: { total: number }; total?: number }, T>(
    path: string,
    query: Record<string, string | undefined>,
    schema: z.ZodType<P>,
    pick: (page: P) => readonly T[],
    keyOf: (item: T) => string,
    what: string,
    maxItems: number = RESULT_WINDOW,
    bounds: { window?: number; pageSize?: number } = {},
  ): Promise<{ items: T[]; total: number; complete: boolean; stable: boolean }> {
    if (!(maxItems > 0)) {
      throw new CliError(
        EXIT.SERVER,
        `internal error: a read of ${what}s must allow at least one item (${String(maxItems)})`,
      );
    }
    const window = Math.min(bounds.window ?? RESULT_WINDOW, RESULT_WINDOW);
    const pageSize = Math.min(bounds.pageSize ?? PAGE_SIZE, PAGE_SIZE);
    const items: T[] = [];
    const seen = new Set<string>();
    let total: number | null = null;
    let stable = true;
    const limit = Math.min(maxItems, window);
    for (let p = 1; p * pageSize <= window && items.length < limit; p += 1) {
      const page = await this.get(
        path,
        { ...query, ps: String(pageSize), p: String(p) },
        schema,
        what,
      );
      const t = pageTotal(page);
      if (t === null) throw invalid(what, path, 'no total');
      if (total !== null && t !== total) {
        stable = false;
        this.warn(
          'SONARQUBE_RESULTS_CHANGED',
          `the number of ${what}s changed while it was read (${total} → ${t})`,
        );
      }
      total = t;
      const got = pick(page);
      for (const item of got) {
        if (items.length >= limit) break;
        const k = keyOf(item);
        if (seen.has(k)) continue;
        seen.add(k);
        items.push(item);
      }
      if (got.length === 0 || items.length >= Math.min(t, limit)) break;
    }
    const final = total ?? 0;
    return { items, total: final, complete: stable && items.length >= final, stable };
  }
}

export interface ConnectOptions {
  url: string;
  token: string;
  kind: 'auto' | SonarKind;
  organization: string | null;
  auth: 'auto' | 'bearer' | 'basic';
  timeoutMs: number;
  ca?: string | undefined;
  log: Logger;
  transport?: Transport | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
}

export interface SonarConnection {
  client: SonarClient;
  kind: SonarKind;
  version: SonarVersion | null;
  login: string;
}

/** Spec §4.3: the version (Server), the token, the organisation (Cloud). */
export async function connectSonar(o: ConnectOptions): Promise<SonarConnection> {
  const kind = o.kind === 'auto' ? detectSonarKind(o.url) : o.kind;
  if (kind === 'cloud' && o.organization === null) {
    throw new CliError(EXIT.USAGE, 'SonarQube Cloud needs --organization (the organisation key)');
  }
  if (kind === 'server' && o.organization !== null) {
    throw new CliError(
      EXIT.USAGE,
      '--organization is only for SonarQube Cloud; SonarQube Server has no organisations',
    );
  }
  const endpoint = (auth: ServerEndpoint['auth']): ServerEndpoint => ({
    url: o.url,
    token: o.token,
    timeoutMs: o.timeoutMs,
    auth,
    ...(o.ca !== undefined && { ca: o.ca }),
  });
  const base = {
    kind,
    organization: o.organization,
    transport: o.transport,
    sleep: o.sleep,
    log: o.log,
  };
  let version: SonarVersion | null = null;
  let auth: 'bearer' | 'basic' = o.auth === 'basic' ? 'basic' : 'bearer';
  if (kind === 'server') {
    const text = await new SonarClient({ ...base, endpoint: endpoint('none') }).version();
    version = parseSonarVersion(text);
    if (version === null) {
      throw new CliError(
        EXIT.USAGE,
        `SonarQube reported a version this command cannot read (${clean(text).slice(0, 64)})`,
      );
    }
    if (!versionAtLeast(version, 9, 9)) {
      throw new CliError(
        EXIT.USAGE,
        `SonarQube ${version.text} is older than 9.9, the oldest version qualor import sonarqube supports`,
      );
    }
    if (o.auth === 'auto') auth = version.major >= 10 ? 'bearer' : 'basic';
  }
  const client = new SonarClient({ ...base, endpoint: endpoint(auth) });
  const user = await client.get('api/users/current', {}, currentUserSchema, 'current user');
  if (!user.isLoggedIn) {
    throw new CliError(
      EXIT.AUTH,
      'SonarQube did not accept the token; use a user token (not an analysis token)',
    );
  }
  if (kind === 'cloud') {
    const orgs = await client.get(
      'api/organizations/search',
      { organizations: o.organization ?? '' },
      organizationsSchema,
      'organisation list',
    );
    if (!orgs.organizations.some((x) => x.key === o.organization)) {
      throw new CliError(
        EXIT.USAGE,
        `no SonarQube Cloud organisation ${clean(o.organization ?? '')} is visible to this token`,
      );
    }
  }
  o.log.debug(`connected to SonarQube ${kind === 'cloud' ? 'Cloud' : (version?.text ?? '')}`);
  return { client, kind, version, login: user.login ?? '' };
}
