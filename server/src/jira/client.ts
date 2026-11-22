import type { IncomingHttpHeaders } from 'node:http';
import { z } from 'zod';
import type { JiraDeployment, JiraStatusCategory } from '../db/schema';
import { outboundRequest, type OutboundFailed, type Resolver } from '../http/outbound';
import { VERSION } from '../index';
import { JIRA_ISSUE_KEY_PATTERN } from '../patterns';
import { retryAfterSeconds } from '../scm/retry-after';
import { scmRefusedAddress } from '../scm/url';

/** spec §6.7: every request has 10 s in all (3 s of it to connect, http/outbound.ts) ... */
export const JIRA_TIMEOUT_MS = 10_000;
/** ... answers over 8 MiB are refused (createmeta `allowedValues` can be large) ... */
export const JIRA_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
/** ... but Data Center's unpaged `GET /rest/api/2/project`: 32 MiB (about 20 000 projects) ... */
export const JIRA_PROJECT_LIST_MAX_BYTES = 32 * 1024 * 1024;
/** ... in 30 s ... */
export const JIRA_PROJECT_LIST_TIMEOUT_MS = 30_000;
/** ... and one job makes at most this many requests. */
export const MAX_JIRA_REQUESTS = 400;
/** Issues per bulk create (Jira Cloud's limit; Data Center states none, spec §6.7). */
export const JIRA_BULK_MAX = 50;
/** Issue ids per `id in (…)` search, and the page size asked for. */
export const JIRA_SEARCH_BATCH = 100;
/** Labels per `labels in (…)` search. */
export const JIRA_LABEL_BATCH = 50;
/** Projects the picker answers with. */
export const JIRA_PICKER_MAX = 50;
/** Items asked for per createmeta page. */
export const CREATEMETA_PAGE_SIZE = 50;
/** Issue types or fields read of one createmeta listing, at most. */
export const MAX_CREATEMETA_ITEMS = 1_000;
/** `jiraText` is cut to this many characters. */
const JIRA_TEXT_MAX = 500;

/**
 * Why a Jira call failed. The user-visible texts are the callers' (`JIRA_PROBLEM_TEXT`, ruling
 * P14); `JiraError.message` is the code itself.
 */
export type JiraErrorCode =
  | 'token_refused'
  | 'captcha'
  | 'redirected'
  | 'not_public'
  | 'unresolved'
  | 'timeout'
  | 'unreachable'
  | 'permission_missing'
  | 'not_found'
  | 'rate_limited'
  | 'field_refused'
  | 'limit_reached'
  | 'server_error'
  | 'http_error'
  | 'bad_answer'
  | 'budget';

/**
 * The codes that refuse what was sent, not the connection: in a create, they fail the elements
 * and leave the call answered (spec §6.4, ruling P6). Any other failed element is a bad answer.
 */
export const ELEMENT_CODES: ReadonlySet<JiraErrorCode> = new Set([
  'field_refused',
  'permission_missing',
  'not_found',
  'limit_reached',
]);

/**
 * A failed Jira call (spec §6.7). `message` is the code: never a URL, header or body. `jiraText` is
 * Jira's own words of a 400 (its `errorMessages` and `errors` values), with the token, the email
 * and the Basic credential cut out; it is the only place they reach users (spec §6.4).
 */
export class JiraError extends Error {
  readonly code: JiraErrorCode;
  /** The HTTP status, when Jira answered. */
  readonly status: number | null;
  /** A 429's `Retry-After`, clamped to 1 s – 15 min; null without one. */
  readonly retryAfterSeconds: number | null;
  readonly jiraText: string | null;

  constructor(
    code: JiraErrorCode,
    options: {
      status?: number | null;
      retryAfterSeconds?: number | null;
      jiraText?: string | null;
    } = {},
  ) {
    super(code);
    this.name = 'JiraError';
    this.code = code;
    this.status = options.status ?? null;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
    this.jiraText = options.jiraText ?? null;
  }
}

export type JiraAuth =
  { kind: 'basic'; email: string; token: string } | { kind: 'bearer'; token: string };

export interface JiraConnectionInput {
  deployment: JiraDeployment;
  /**
   * Where every call goes (normalised, without a trailing slash, jira/url.ts): Cloud's `apiUrl`
   * or `siteUrl`, Data Center's `siteUrl` with its context path.
   */
  apiBase: string;
  auth: JiraAuth;
  /** A Data Center host listed in `QUALOR_JIRA_INTERNAL_HOSTS` (`jiraHostAllowed`). */
  allowInternalHosts: boolean;
}

export interface JiraClientOptions {
  /** Every request's deadline but the Data Center project list's (default 10 s). */
  timeoutMs?: number;
  /** The Data Center project list's deadline (default 30 s); `timeoutMs` does not cut it. */
  projectListTimeoutMs?: number;
  connectTimeoutMs?: number;
  resolve?: Resolver;
  maxRequests?: number;
}

export interface JiraProjectRef {
  id: string;
  key: string;
  name: string;
}

export interface CreateMetaIssueType {
  id: string;
  name: string;
  subtask: boolean;
}

export interface CreateMetaField {
  fieldId: string;
  name: string;
  required: boolean;
  hasDefaultValue: boolean;
  allowedValues: { id: string; name: string }[];
}

export interface CreatedIssue {
  id: string;
  key: string;
}

/**
 * One outcome per element sent, in the order sent. A failed element's code is one of
 * {@link ELEMENT_CODES} (Jira refused it), or `bad_answer` (its answer is not understood: the issue
 * may exist).
 */
export type BulkOutcome = ({ created: CreatedIssue } | { failed: JiraError })[];

export interface JiraIssueState {
  id: string;
  key: string;
  statusName: string;
  statusCategory: JiraStatusCategory;
}

// ─── Answer shapes (the fields Qualor reads; server/test/jira-shapes/ holds recorded ones) ──────

const myself = z.looseObject({ displayName: z.string() });
/** A created comment: Jira answers with it, its `id` included. */
const comment = z.looseObject({ id: z.string() });
const project = z.looseObject({ id: z.string(), key: z.string(), name: z.string() });
/** Cloud's `project/search` page. */
const projectPage = z.looseObject({
  values: z.array(project),
  total: z.number().int().nonnegative(),
});
/**
 * A createmeta page. Cloud names its items `issueTypes` or `fields`; Data Center is believed to
 * name them `values` (unverified until Task 15, jira-shapes/README.md), so any of the three is read.
 */
const createmetaPage = z.looseObject({
  issueTypes: z.array(z.unknown()).optional(),
  fields: z.array(z.unknown()).optional(),
  values: z.array(z.unknown()).optional(),
  total: z.number().int().optional(),
  isLast: z.boolean().optional(),
});
const issueType = z.looseObject({
  id: z.string(),
  name: z.string(),
  subtask: z.boolean().optional(),
});
const field = z.looseObject({
  fieldId: z.string(),
  name: z.string(),
  required: z.boolean(),
  hasDefaultValue: z.boolean().optional(),
  /** Options of every kind (priorities, versions, select options): each read on its own. */
  allowedValues: z.array(z.unknown()).optional(),
});
/** A priority or version has a `name`; a select option has a `value`. */
const allowedValue = z.looseObject({
  id: z.string(),
  name: z.string().optional(),
  value: z.string().optional(),
});
/** Jira issue ids are integers; only such ids are ever stored or put into JQL. */
const ISSUE_ID = /^\d{1,18}$/;
/** Ruling T6b: only a key of Jira's form, as the audit catalogue names it, is ever stored. */
const issueKey = z.string().max(255).regex(JIRA_ISSUE_KEY_PATTERN);
const createdIssue = z.looseObject({ id: z.string().regex(ISSUE_ID), key: issueKey });

/** Whether a key Jira gave has Jira's form (T6b); a search's keys are checked by the caller. */
export function isJiraIssueKey(key: string): boolean {
  return issueKey.safeParse(key).success;
}

/** Whether a stored id may go into an `id in (…)` search. */
export function isJiraIssueId(id: string): boolean {
  return ISSUE_ID.test(id);
}

const elementError = z.looseObject({
  status: z.number().int().optional(),
  elementErrors: z.unknown().optional(),
  failedElementNumber: z.number().int(),
});
/** Each created issue is read on its own: one with a bad id or key fails only its element. */
const bulkAnswer = z.looseObject({
  issues: z.array(z.unknown()).optional(),
  errors: z.array(elementError).optional(),
});
/**
 * A status category Jira knows besides its three (`undefined`, "No Category", which Jira shows grey)
 * reads as `new`, so one odd status never fails the whole answer.
 */
const statusCategory = z.enum(['new', 'indeterminate', 'done']).catch('new');
/** A searched issue's id goes back into JQL: one not of Jira's form fails the page (bad answer). */
const searchedIssue = z.looseObject({
  id: z.string().regex(ISSUE_ID),
  key: z.string(),
  fields: z.looseObject({
    status: z.looseObject({
      name: z.string(),
      statusCategory: z.looseObject({ key: statusCategory }),
    }),
    labels: z.array(z.string()).optional(),
  }),
});
const cloudSearchPage = z.looseObject({
  issues: z.array(searchedIssue),
  nextPageToken: z.string().nullable().optional(),
  isLast: z.boolean().optional(),
});
const dcSearchPage = z.looseObject({
  issues: z.array(searchedIssue),
  total: z.number().int().nonnegative(),
});
/** Jira's ErrorCollection; a part of another type is left out, not refused. */
const errorBody = z.looseObject({
  errorMessages: z.array(z.unknown()).optional().catch(undefined),
  errors: z.record(z.string(), z.unknown()).optional().catch(undefined),
});

/** Every recorded shape the client parses, for the shape test (server/test/jira-shapes/). */
export const JIRA_SHAPES = {
  myself,
  comment,
  projectPage,
  projects: z.array(project),
  createmetaPage,
  createdIssue,
  bulkAnswer,
  cloudSearchPage,
  dcSearchPage,
  errorBody,
} as const;

type SearchedIssue = z.infer<typeof searchedIssue>;

/**
 * Whether a createmeta page of `read` items, read up to `startAt`, is the last: an empty one is;
 * else `isLast` when Jira says it, else `total`, else a short page.
 */
function lastCreatemetaPage(
  page: z.infer<typeof createmetaPage>,
  read: number,
  startAt: number,
): boolean {
  if (read === 0) return true;
  if (page.isLast !== undefined) return page.isLast;
  if (page.total !== undefined) return startAt >= page.total;
  return read < CREATEMETA_PAGE_SIZE;
}

// ─── Errors ─────────────────────────────────────────────────────────────────────────────────────

/**
 * `text` with every secret replaced by `[redacted]`, longest first (the Basic credential holds the
 * email and the token); the email in any case.
 */
function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of [...secrets].sort((a, b) => b.length - a.length)) {
    if (secret === '') continue;
    const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(escaped, secret.includes('@') ? 'gi' : 'g'), '[redacted]');
  }
  return out;
}

/** At most `max` UTF-16 units, never half of a surrogate pair. */
function cut(text: string, max: number): string {
  if (text.length <= max) return text;
  const code = text.charCodeAt(max - 1);
  return text.slice(0, code >= 0xd800 && code <= 0xdbff ? max - 1 : max);
}

/**
 * Jira's words of a refusal: its `errorMessages` and `errors` values joined with `; `, line breaks
 * as spaces, the secrets cut out, at most 500 characters; null without any.
 */
function jiraTextOf(body: unknown, secrets: readonly string[]): string | null {
  const parsed = errorBody.safeParse(body);
  if (!parsed.success) return null;
  const parts = [
    ...(parsed.data.errorMessages ?? []),
    ...Object.values(parsed.data.errors ?? {}),
  ].filter((part): part is string => typeof part === 'string' && part.trim() !== '');
  if (parts.length === 0) return null;
  return cut(redact(parts.join('; '), secrets).replace(/\r\n|[\r\n]/g, ' '), JIRA_TEXT_MAX);
}

/** The code of an answer's status (spec §6.7); 400 is Jira refusing what was sent. */
function codeOfStatus(status: number): JiraErrorCode {
  if (status >= 300 && status < 400) return 'redirected';
  if (status === 400) return 'field_refused';
  if (status === 401) return 'token_refused';
  if (status === 403) return 'permission_missing';
  if (status === 404) return 'not_found';
  if (status === 413 || status === 422) return 'limit_reached';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'http_error';
}

/**
 * Data Center's CAPTCHA lockout (spec §6.1): `X-Seraph-LoginReason: AUTHENTICATION_DENIED` means
 * the credential was not even checked, whatever the status says.
 */
function loginDenied(headers: IncomingHttpHeaders): boolean {
  const reason = headers['x-seraph-loginreason'];
  const values = Array.isArray(reason) ? reason : [reason ?? ''];
  return values
    .flatMap((v) => v.split(','))
    .some((v) => v.trim().toUpperCase() === 'AUTHENTICATION_DENIED');
}

/** A body as JSON, or undefined when it is not (an HTML page); an empty body is null. */
function jsonOf(body: Buffer): unknown {
  if (body.length === 0) return null;
  try {
    return JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}

/** The error for a Jira request that got no answer: refused by the outbound rules, or no reply. */
function transportError(failed: OutboundFailed): JiraError {
  switch (failed.cause) {
    case 'not_public':
    case 'refused_address':
      return new JiraError('not_public');
    case 'unresolved':
      return new JiraError('unresolved');
    case 'timeout':
    case 'connect_timeout':
      return new JiraError('timeout');
    case 'too_large':
      return new JiraError('bad_answer');
    default:
      return new JiraError('unreachable');
  }
}

/**
 * The error of one element of a bulk answer: 400 is `field_refused` with Jira's words, 403, 404,
 * 413 and 422 refuse the element too. Any other status (401, 429 or 5xx inside an answered bulk)
 * refuses nothing Qualor can name: a bad answer, so the element waits to be reconciled.
 */
function elementErrorOf(e: z.infer<typeof elementError>, secrets: readonly string[]): JiraError {
  const status = e.status ?? 400;
  const code = codeOfStatus(status);
  if (!ELEMENT_CODES.has(code)) return new JiraError('bad_answer', { status });
  return new JiraError(code, {
    status,
    jiraText: status === 400 ? jiraTextOf(e.elementErrors, secrets) : null,
  });
}

/**
 * The outcome of each element of a bulk create (spec §11.3), from Jira's answer: an element named
 * by `errors[].failedElementNumber` failed, and the created issues, which Jira lists in the order
 * sent without the failed ones, belong to the others in turn; a created issue whose id or key is
 * not of Jira's form is a bad answer of its element (T6b). Null when the answer is not understood
 * or its counts do not add up (R17: the call counts as unanswered). `secrets` are cut out of the
 * elements' Jira texts.
 */
export function mapBulkAnswer(
  sent: number,
  answer: unknown,
  secrets: readonly string[] = [],
): BulkOutcome | null {
  const parsed = bulkAnswer.safeParse(answer);
  if (!parsed.success) return null;
  const issues = parsed.data.issues ?? [];
  const failed = new Map<number, JiraError>();
  for (const e of parsed.data.errors ?? []) {
    const index = e.failedElementNumber;
    if (index < 0 || index >= sent || failed.has(index)) return null;
    failed.set(index, elementErrorOf(e, secrets));
  }
  if (issues.length !== sent - failed.size) return null;
  const created = issues.values();
  const outcome: BulkOutcome = [];
  for (let i = 0; i < sent; i++) {
    const error = failed.get(i);
    if (error) {
      outcome.push({ failed: error });
      continue;
    }
    const issue = createdIssue.safeParse(created.next().value);
    outcome.push(
      issue.success
        ? { created: { id: issue.data.id, key: issue.data.key } }
        : { failed: new JiraError('bad_answer') },
    );
  }
  return outcome;
}

/** A JQL string literal. */
function jqlString(value: string): string {
  return `"${value.replace(/[\\"]/g, '\\$&')}"`;
}

function stateOf(issue: SearchedIssue): JiraIssueState {
  return {
    id: issue.id,
    key: issue.key,
    statusName: issue.fields.status.name,
    statusCategory: issue.fields.status.statusCategory.key,
  };
}

type JiraMethod = 'GET' | 'POST';

interface Answer {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

/**
 * Jira REST v2 on Cloud and Data Center (spec §6.7), through {@link outboundRequest}: the
 * connection's `apiBase` only, the SSRF rules unless the host is listed in
 * `QUALOR_JIRA_INTERNAL_HOSTS` (link-local and metadata addresses never), no redirect followed, 10 s
 * per request, bounded answers and a request budget per client (one client per job or route). The
 * credential goes only into `Authorization`; no error, return value or log line carries it.
 */
export class JiraClient {
  private requestCount = 0;
  private readonly maxRequests: number;
  private readonly refuseAddress: (address: string) => boolean;
  readonly #deployment: JiraDeployment;
  readonly #apiBase: string;
  readonly #allowInternalHosts: boolean;
  /** True private fields: not own enumerable properties a logger could print. */
  readonly #authorization: string;
  /** The token, the email and the Basic credential, cut out of Jira's words. */
  readonly #secrets: readonly string[];

  constructor(
    connection: JiraConnectionInput,
    private readonly options: JiraClientOptions = {},
  ) {
    this.#deployment = connection.deployment;
    this.#apiBase = connection.apiBase.replace(/\/+$/, '');
    this.#allowInternalHosts = connection.allowInternalHosts;
    const { auth } = connection;
    if (auth.kind === 'basic') {
      const pair = `${auth.email}:${auth.token}`;
      const basic = Buffer.from(pair).toString('base64');
      this.#authorization = `Basic ${basic}`;
      this.#secrets = [auth.token, auth.email, pair, basic];
    } else {
      this.#authorization = `Bearer ${auth.token}`;
      this.#secrets = [auth.token];
    }
    this.maxRequests = options.maxRequests ?? MAX_JIRA_REQUESTS;
    this.refuseAddress = scmRefusedAddress(new URL(this.#apiBase));
  }

  /** Requests made so far, refused ones included. */
  get requests(): number {
    return this.requestCount;
  }

  /** Requests the budget still allows. */
  get remaining(): number {
    return Math.max(0, this.maxRequests - this.requestCount);
  }

  get deployment(): JiraDeployment {
    return this.#deployment;
  }

  get apiBase(): string {
    return this.#apiBase;
  }

  /** One request, counted against the budget; an answer of any status, else a `JiraError`. */
  private async exchange(
    method: JiraMethod,
    path: string,
    body?: unknown,
    caps: { maxBytes: number; timeoutMs: number } = {
      maxBytes: JIRA_MAX_RESPONSE_BYTES,
      timeoutMs: this.options.timeoutMs ?? JIRA_TIMEOUT_MS,
    },
  ): Promise<Answer> {
    if (this.requestCount >= this.maxRequests) throw new JiraError('budget');
    this.requestCount += 1;
    const result = await outboundRequest(
      {
        url: `${this.#apiBase}${path}`,
        method,
        headers: {
          authorization: this.#authorization,
          accept: 'application/json',
          'user-agent': `Qualor/${VERSION}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      {
        allowInternalHosts: this.#allowInternalHosts,
        refuseAddress: this.refuseAddress,
        timeoutMs: caps.timeoutMs,
        ...(this.options.connectTimeoutMs === undefined
          ? {}
          : { connectTimeoutMs: this.options.connectTimeoutMs }),
        ...(this.options.resolve ? { resolve: this.options.resolve } : {}),
        maxResponseBytes: caps.maxBytes,
        overflow: 'fail',
        names: { noun: 'Jira', target: 'Jira' },
      },
    );
    if (result.kind === 'failed') throw transportError(result);
    if (loginDenied(result.headers)) throw new JiraError('captcha', { status: result.status });
    return { status: result.status, headers: result.headers, body: result.body };
  }

  /** The error of an answer outside 2xx. */
  private refusal(answer: Answer): JiraError {
    const { status, headers } = answer;
    return new JiraError(codeOfStatus(status), {
      status,
      retryAfterSeconds: status === 429 ? retryAfterSeconds(headers) : null,
      jiraText: status === 400 ? jiraTextOf(jsonOf(answer.body), this.#secrets) : null,
    });
  }

  /** A request whose answer must be a 2xx of JSON in `schema`. */
  private async call<T>(
    schema: z.ZodType<T>,
    method: JiraMethod,
    path: string,
    body?: unknown,
    caps?: { maxBytes: number; timeoutMs: number },
  ): Promise<T> {
    const answer = await this.exchange(method, path, body, caps);
    if (answer.status < 200 || answer.status >= 300) throw this.refusal(answer);
    const parsed = schema.safeParse(jsonOf(answer.body));
    if (!parsed.success) throw new JiraError('bad_answer', { status: answer.status });
    return parsed.data;
  }

  /** `GET /rest/api/2/myself`: who the credential is. */
  async myself(): Promise<{ displayName: string }> {
    const me = await this.call(myself, 'GET', '/rest/api/2/myself');
    return { displayName: me.displayName };
  }

  /** Data Center's unpaged project list, under its own caps (spec §6.7). */
  private dcProjects(): Promise<z.infer<typeof project>[]> {
    return this.call(z.array(project), 'GET', '/rest/api/2/project', undefined, {
      maxBytes: JIRA_PROJECT_LIST_MAX_BYTES,
      timeoutMs: this.options.projectListTimeoutMs ?? JIRA_PROJECT_LIST_TIMEOUT_MS,
    });
  }

  /** How many projects the credential sees: Cloud's `total`, Data Center's list length. */
  async projectsVisible(): Promise<number> {
    if (this.#deployment === 'data_center') return (await this.dcProjects()).length;
    const page = await this.call(projectPage, 'GET', '/rest/api/2/project/search?maxResults=1');
    return page.total;
  }

  /**
   * The picker: at most 50 projects whose key or name contains `query` (any case). Cloud searches
   * with `project/search`; Data Center filters its whole list here.
   */
  async searchProjects(query: string): Promise<JiraProjectRef[]> {
    const wanted = query.trim();
    const ref = (p: z.infer<typeof project>): JiraProjectRef => ({
      id: p.id,
      key: p.key,
      name: p.name,
    });
    if (this.#deployment === 'cloud') {
      const page = await this.call(
        projectPage,
        'GET',
        `/rest/api/2/project/search?query=${encodeURIComponent(wanted)}&maxResults=${JIRA_PICKER_MAX}`,
      );
      return page.values.slice(0, JIRA_PICKER_MAX).map(ref);
    }
    const lower = wanted.toLowerCase();
    return (await this.dcProjects())
      .filter((p) => p.key.toLowerCase().includes(lower) || p.name.toLowerCase().includes(lower))
      .slice(0, JIRA_PICKER_MAX)
      .map(ref);
  }

  /**
   * Every item of a createmeta listing, page by page, at most {@link MAX_CREATEMETA_ITEMS}: until
   * `isLast` says so, else until `total`, else until a short page.
   */
  private async createmeta<T>(path: string, item: z.ZodType<T>): Promise<T[]> {
    const items: T[] = [];
    let startAt = 0;
    while (items.length < MAX_CREATEMETA_ITEMS) {
      const page = await this.call(
        createmetaPage,
        'GET',
        `${path}?startAt=${startAt}&maxResults=${CREATEMETA_PAGE_SIZE}`,
      );
      const parsed = z.array(item).safeParse(page.issueTypes ?? page.fields ?? page.values);
      if (!parsed.success) throw new JiraError('bad_answer');
      items.push(...parsed.data);
      startAt += parsed.data.length;
      if (lastCreatemetaPage(page, parsed.data.length, startAt)) break;
    }
    return items.slice(0, MAX_CREATEMETA_ITEMS);
  }

  /** The issue types the credential may create in the project, sub-tasks left out. */
  async issueTypes(projectKey: string): Promise<CreateMetaIssueType[]> {
    const types = await this.createmeta(
      `/rest/api/2/issue/createmeta/${encodeURIComponent(projectKey)}/issuetypes`,
      issueType,
    );
    return types
      .filter((t) => t.subtask !== true)
      .map((t) => ({ id: t.id, name: t.name, subtask: false }));
  }

  /** The fields of an issue type's create screen, at most 1 000. */
  async issueTypeFields(projectKey: string, issueTypeId: string): Promise<CreateMetaField[]> {
    const fields = await this.createmeta(
      `/rest/api/2/issue/createmeta/${encodeURIComponent(projectKey)}/issuetypes/${encodeURIComponent(issueTypeId)}`,
      field,
    );
    return fields.map((f) => ({
      fieldId: f.fieldId,
      name: f.name,
      required: f.required,
      hasDefaultValue: f.hasDefaultValue ?? false,
      allowedValues: (f.allowedValues ?? []).flatMap((value) => {
        const option = allowedValue.safeParse(value);
        if (!option.success) return [];
        return [
          { id: option.data.id, name: option.data.name ?? option.data.value ?? option.data.id },
        ];
      }),
    }));
  }

  /** `POST /rest/api/2/issue`: one issue. */
  async createIssue(fields: Record<string, unknown>): Promise<CreatedIssue> {
    const created = await this.call(createdIssue, 'POST', '/rest/api/2/issue', { fields });
    return { id: created.id, key: created.key };
  }

  /**
   * Up to {@link JIRA_BULK_MAX} issues, one outcome per element in the order sent. One element goes
   * through `POST /rest/api/2/issue`, more through `POST /rest/api/2/issue/bulk`. A refusal of what
   * was sent (400, 403, 404, 413, 422) fails the elements it concerns, or every element when Jira
   * names none (ruling P6); anything else (no answer, 3xx, 401, 429, 5xx, an answer that does not
   * add up, R17, a single created issue whose id or key is not of Jira's form) throws, as it
   * concerns the whole call.
   */
  async createIssues(fields: readonly Record<string, unknown>[]): Promise<BulkOutcome> {
    if (fields.length > JIRA_BULK_MAX) {
      throw new RangeError(`At most ${JIRA_BULK_MAX} issues per bulk create`);
    }
    const [first] = fields;
    if (first === undefined) return [];
    if (fields.length === 1) {
      try {
        return [{ created: await this.createIssue(first) }];
      } catch (err) {
        if (err instanceof JiraError && ELEMENT_CODES.has(err.code)) return [{ failed: err }];
        throw err;
      }
    }
    const answer = await this.exchange('POST', '/rest/api/2/issue/bulk', {
      issueUpdates: fields.map((f) => ({ fields: f })),
    });
    const json = jsonOf(answer.body);
    if (answer.status >= 200 && answer.status < 300) {
      const outcome = mapBulkAnswer(fields.length, json, this.#secrets);
      if (outcome === null) throw new JiraError('bad_answer', { status: answer.status });
      return outcome;
    }
    const refused = this.refusal(answer);
    if (!ELEMENT_CODES.has(refused.code)) throw refused;
    return (
      mapBulkAnswer(fields.length, json, this.#secrets) ?? fields.map(() => ({ failed: refused }))
    );
  }

  /**
   * One JQL search, every page: Cloud `POST /rest/api/2/search/jql` by `nextPageToken`, Data
   * Center `POST /rest/api/2/search` by `startAt` with `validateQuery: "warn"` (an unknown id
   * does not fail the query).
   */
  private async search(jql: string): Promise<SearchedIssue[]> {
    const fields = ['status', 'labels'];
    const issues: SearchedIssue[] = [];
    if (this.#deployment === 'cloud') {
      let nextPageToken: string | undefined;
      do {
        const page = await this.call(cloudSearchPage, 'POST', '/rest/api/2/search/jql', {
          jql,
          fields,
          maxResults: JIRA_SEARCH_BATCH,
          ...(nextPageToken === undefined ? {} : { nextPageToken }),
        });
        issues.push(...page.issues);
        nextPageToken =
          page.isLast === true || page.issues.length === 0
            ? undefined
            : (page.nextPageToken ?? undefined);
      } while (nextPageToken !== undefined);
      return issues;
    }
    let startAt = 0;
    for (;;) {
      const page = await this.call(dcSearchPage, 'POST', '/rest/api/2/search', {
        jql,
        fields,
        startAt,
        maxResults: JIRA_SEARCH_BATCH,
        validateQuery: 'warn',
      });
      issues.push(...page.issues);
      startAt += page.issues.length;
      if (page.issues.length === 0 || startAt >= page.total) return issues;
    }
  }

  /**
   * Finds or gives up on each id of `batch` (spec §6.5 step 4). Cloud fails a whole query on one
   * unknown id (400), and so may a Data Center whose `validateQuery: "warn"` does not help (M3):
   * the batch is halved until each id is found or alone, and a lone id answering 400 or 404 is
   * missing this pass. Each request counts against the budget. Only the codes of those answers
   * count: a CAPTCHA lockout or a redirect is thrown whatever its status.
   */
  private async settle(
    batch: readonly string[],
    found: Map<string, JiraIssueState>,
    missing: string[],
  ): Promise<void> {
    let issues: SearchedIssue[];
    try {
      issues = await this.search(`id in (${batch.join(',')})`);
    } catch (err) {
      await this.settleRefused(err, batch, found, missing);
      return;
    }
    for (const issue of issues) found.set(issue.id, stateOf(issue));
    for (const id of batch) if (!found.has(id)) missing.push(id);
  }

  /**
   * {@link settle} of a batch whose query failed: a lone id answering 400 or 404 is missing, a
   * larger batch answering 400 is halved, and anything else is thrown.
   */
  private async settleRefused(
    err: unknown,
    batch: readonly string[],
    found: Map<string, JiraIssueState>,
    missing: string[],
  ): Promise<void> {
    if (!(err instanceof JiraError)) throw err;
    const halvable = err.code === 'field_refused';
    if (batch.length === 1 && (halvable || err.code === 'not_found')) {
      missing.push(...batch);
      return;
    }
    if (!halvable) throw err;
    const half = Math.ceil(batch.length / 2);
    await this.settle(batch.slice(0, half), found, missing);
    await this.settle(batch.slice(half), found, missing);
  }

  /**
   * The status of each issue by its id, 100 ids per query: those Jira returns (with their key now,
   * as a moved issue keeps its id), and those it does not. A failure throws what was read before
   * it away: the sync pass calls this per batch of {@link JIRA_SEARCH_BATCH}, so a budget stop
   * keeps the batches it read.
   */
  async searchByIds(
    ids: readonly string[],
  ): Promise<{ found: Map<string, JiraIssueState>; missing: string[] }> {
    const unique = [...new Set(ids)];
    if (unique.some((id) => !ISSUE_ID.test(id))) throw new RangeError('Not a Jira issue id');
    const found = new Map<string, JiraIssueState>();
    const missing: string[] = [];
    for (let i = 0; i < unique.length; i += JIRA_SEARCH_BATCH) {
      await this.settle(unique.slice(i, i + JIRA_SEARCH_BATCH), found, missing);
    }
    return { found, missing };
  }

  /**
   * The issue that carries each label (spec §6.5 step 1, the reconciliation label), 50 labels per
   * query; a label no issue carries is absent.
   */
  async searchByLabels(labels: readonly string[]): Promise<Map<string, JiraIssueState>> {
    const unique = [...new Set(labels)];
    const out = new Map<string, JiraIssueState>();
    for (let i = 0; i < unique.length; i += JIRA_LABEL_BATCH) {
      const batch = unique.slice(i, i + JIRA_LABEL_BATCH);
      const wanted = new Set(batch);
      const issues = await this.search(`labels in (${batch.map(jqlString).join(', ')})`);
      for (const issue of issues) {
        for (const label of issue.fields.labels ?? []) {
          if (wanted.has(label) && !out.has(label)) out.set(label, stateOf(issue));
        }
      }
    }
    return out;
  }

  /**
   * `POST /rest/api/2/issue/{id}/comment`: a comment in wiki markup. Jira answers with the
   * comment; any other 2xx (a sign-in page) is a bad answer, so nothing counts as posted (M2).
   */
  async addComment(issueId: string, body: string): Promise<void> {
    await this.call(comment, 'POST', `/rest/api/2/issue/${encodeURIComponent(issueId)}/comment`, {
      body,
    });
  }
}
