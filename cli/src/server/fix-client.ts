import { Readable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  fixClaimAnswerSchema,
  type FixClaimAnswer,
  type FixClaimBody,
  type FixFamily,
  type FixResultBody,
} from '@qualor/shared/fix';
import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import {
  clean,
  describeFailure,
  parseJson,
  parseProblem,
  pathSegment,
  request,
  retryAfterMs,
  type HttpResponse,
  type RequestOptions,
  type ServerEndpoint,
} from './http';

/**
 * The fix job's two routes (spec §6.5, §6.7, R4, R6, R16): `POST /api/v0/projects/fixes/claim` and
 * `PUT /api/v0/fixes/{id}/result`, with the project's analysis token. Both bodies are sent as a
 * stream with `Content-Length`, not as `json`: `json` is capped at 1 MiB (a result carries up to
 * 32 MiB of files) and does not go through `HTTP(S)_PROXY`.
 */

/** R16: a 503 of the result route (SCM_UNAVAILABLE, FIX_CHECK_BUSY) is retried this many times. */
export const FIX_RESULT_RETRIES = 3;
/** R16: the wait before a retry without `Retry-After`. */
export const FIX_RESULT_RETRY_MS = 10_000;
/** Ruling T9b: the longest `Retry-After` honoured. */
export const FIX_RESULT_MAX_RETRY_MS = 60_000;
/**
 * The longest the result request may go without progress: the server reads the base files from the
 * SCM (up to 120 s) and checks them in a worker (up to 30 s) before it answers, after the uploads
 * ahead of it.
 */
export const FIX_RESULT_TIMEOUT_MS = 300_000;

/** A JSON value as a streamed request body. */
function jsonBody(value: unknown): NonNullable<RequestOptions['body']> {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  return { stream: () => Readable.from([payload]), contentLength: payload.length };
}

const JSON_HEADERS = { 'content-type': 'application/json' } as const;
const FULL_SHA1 = /^[0-9a-f]{40}$/;

/** The problem's code, when it has one. */
const codeOf = (res: HttpResponse): string | undefined => parseProblem(res.body)?.code;

/** config.md §7, R35: 401/403 exit 5, a bare 404 (no fix routes) and any other refusal exit 4. */
function refusal(res: HttpResponse, what: string): CliError {
  const text = describeFailure(res);
  if (res.status === 401 || res.status === 403) {
    return new CliError(
      EXIT.AUTH,
      `the server refused the ${what} (${text}); qualor fix needs the project's analysis token`,
    );
  }
  if (res.status === 404 && codeOf(res) === undefined) {
    return new CliError(
      EXIT.SERVER,
      'the server has no fix endpoints (404); it needs Qualor 0.16 or later, and server.url must be the Qualor server',
    );
  }
  return new CliError(EXIT.SERVER, `the server refused the ${what} (${text})`);
}

/**
 * R4, ruling F12: one claim (`max: 1`) for the families this job can serve, on the checked-out
 * branch and revision. The revision is sent when it is a full SHA-1 (the server only logs it).
 * 409 `NOT_MAIN_BRANCH` exits 2, 404 `PROJECT_NOT_FOUND` exits 4.
 */
export async function claimFix(
  ep: ServerEndpoint,
  input: { projectKey: string; families: FixFamily[]; branch: string; revision: string },
): Promise<FixClaimAnswer> {
  const body: FixClaimBody = {
    families: input.families,
    max: 1,
    branch: input.branch,
    ...(FULL_SHA1.test(input.revision) && { revision: input.revision }),
  };
  const res = await request(ep, {
    method: 'POST',
    path: 'api/v0/projects/fixes/claim',
    query: { projectKey: input.projectKey },
    headers: JSON_HEADERS,
    body: jsonBody(body),
  });
  if (res.status === 200) return parseJson(res, fixClaimAnswerSchema, 'fix claim answer');
  if (res.status === 409 && codeOf(res) === 'NOT_MAIN_BRANCH') {
    throw new CliError(
      EXIT.USAGE,
      `qualor fix runs on the project's main branch only; ${clean(input.branch)} is not it (${describeFailure(res)})`,
    );
  }
  if (res.status === 404 && codeOf(res) === 'PROJECT_NOT_FOUND') {
    throw new CliError(
      EXIT.SERVER,
      `project ${clean(input.projectKey)} does not exist on the server, or the token cannot see it (${describeFailure(res)})`,
    );
  }
  throw refusal(res, 'fix claim');
}

/**
 * What the server made of a result: taken (with the fix's state), the claim lost, refused, or the
 * project can take no fixes now (ruling T12f; the fix stays `preparing` until its lease runs out).
 */
export type FixSendAnswer =
  { accepted: string } | 'lease_lost' | { refused: string } | { stopped: string };

/**
 * Rulings T12f, FW15: the result route's 409s that mean the project's fixes cannot go on (as R4's
 * reasons): the project unmapped, the connection's switch off, or the project's own switch off.
 */
const STOPPING_CONFLICTS: ReadonlySet<string> = new Set([
  'SCM_NOT_BOUND',
  'FIX_MRS_NOT_ALLOWED',
  'FIXES_DISABLED',
]);

const acceptedSchema = z.looseObject({ state: z.string() });

/** A 422's rule and file: `UPLOAD_REFUSED <rule>: <fixed text> (<file>)`. */
function refusedText(res: HttpResponse): string {
  const p = parseProblem(res.body);
  const reason = p?.['reason'];
  const rule = typeof reason === 'string' ? ` ${clean(reason).slice(0, 64)}` : '';
  const title = p?.title === undefined ? '' : `: ${clean(p.title)}`;
  const file = p?.detail === undefined ? '' : ` (${clean(p.detail)})`;
  return `${res.status} ${clean(p?.code ?? '')}${rule}${title}${file}`.trim();
}

/** Ruling T9b: `Retry-After` (at most 60 s), else 10 s. */
const retryDelay = (res: HttpResponse): number =>
  retryAfterMs(res.headers, 0, FIX_RESULT_MAX_RETRY_MS) ?? FIX_RESULT_RETRY_MS;

/** The answer to a result, or null for a 503 that may be retried. */
function resultAnswer(res: HttpResponse, retries: number): FixSendAnswer | null {
  if (res.status === 202) {
    return { accepted: clean(parseJson(res, acceptedSchema, 'fix result answer').state) };
  }
  if (res.status === 409 && codeOf(res) === 'FIX_LEASE_LOST') return 'lease_lost';
  if (res.status === 409 && STOPPING_CONFLICTS.has(codeOf(res) ?? '')) {
    return { stopped: describeFailure(res) };
  }
  if (res.status === 422) return { refused: refusedText(res) };
  if (res.status !== 503) throw refusal(res, 'fix result');
  if (retries < FIX_RESULT_RETRIES) return null;
  throw new CliError(
    EXIT.SERVER,
    `the server could not check the fix result after ${FIX_RESULT_RETRIES} retries (${describeFailure(res)})`,
  );
}

/**
 * `PUT /api/v0/fixes/{id}/result` (R6): any 202 is accepted, with the state the server answers
 * (`committing`, or `failed`/`open` after a permanent SCM error, ruling T9d); 409 `FIX_LEASE_LOST`
 * is `lease_lost`; 409 `SCM_NOT_BOUND`, `FIX_MRS_NOT_ALLOWED` or `FIXES_DISABLED` is `stopped`
 * (rulings T12f, FW15); a 422 is
 * `refused` with the rule and file. A 503 (`SCM_UNAVAILABLE`,
 * `FIX_CHECK_BUSY`) is retried 3 times, after its `Retry-After` (at most 60 s) or 10 s (R16, T9b);
 * every other answer is a CliError as for the claim.
 */
export async function sendFixResult(
  ep: ServerEndpoint,
  fixId: string,
  body: FixResultBody,
  o: { wait?: (ms: number) => Promise<unknown>; log?: Logger },
): Promise<FixSendAnswer> {
  const wait = o.wait ?? ((ms: number) => sleep(ms));
  const endpoint = { ...ep, timeoutMs: Math.max(ep.timeoutMs, FIX_RESULT_TIMEOUT_MS) };
  const payload = jsonBody(body);
  for (let retries = 0; ; retries++) {
    const res = await request(endpoint, {
      method: 'PUT',
      path: `api/v0/fixes/${pathSegment(fixId)}/result`,
      headers: JSON_HEADERS,
      body: payload,
    });
    const answer = resultAnswer(res, retries);
    if (answer !== null) return answer;
    const delay = retryDelay(res);
    o.log?.info(
      `the server cannot check the fix now (${describeFailure(res)}); retrying in ${Math.round(delay / 1000)} s`,
    );
    await wait(delay);
  }
}
