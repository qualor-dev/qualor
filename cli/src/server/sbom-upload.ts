import { createReadStream } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import {
  clean,
  parseJson,
  parseProblem,
  request,
  type HttpResponse,
  type ServerEndpoint,
} from './http';
import { busyRetryDelay } from './upload';

/**
 * 503 `UPLOADS_BUSY` is retried this many times in all, for at most `MAX_SBOM_RETRY_WAIT_MS`. The
 * server parses one SBOM at a time and holds that slot while the body is still arriving (ruling
 * R14), so a slow upload ahead of this one can keep it busy for minutes: five minutes of waiting
 * (a scan upload waits one) outlasts a 32 MiB body on a slow link. A retry costs one refused
 * request before `100 Continue`, never a body.
 */
export const MAX_SBOM_RETRY_ATTEMPTS = 300;
export const MAX_SBOM_RETRY_WAIT_MS = 300_000;
/** After the first busy retry, one in this many is logged. */
const BUSY_LOG_EVERY = 10;

/** `busyRetryDelay` with the SBOM budget above. */
export function sbomRetryDelay(res: HttpResponse, attempt: number, waited: number): number | null {
  return busyRetryDelay(res, attempt, waited, {
    attempts: MAX_SBOM_RETRY_ATTEMPTS,
    waitMs: MAX_SBOM_RETRY_WAIT_MS,
  });
}

const count = z.number().int().min(0);

/** The answer of `PUT /api/v0/projects/sbom` (mirrors the server's schema; extra fields are kept). */
export const sbomUploadAnswerSchema = z.looseObject({
  version: z.looseObject({ id: z.string(), label: z.string(), source: z.string() }),
  format: z.string(),
  subject: z.string().nullable(),
  distribution: z.looseObject({ family: z.string(), version: z.string() }).nullable(),
  packages: count,
  osPackages: count,
  skipped: z.looseObject({ noPurl: count, unsupportedType: count, duplicate: count }),
  warnings: z.array(z.looseObject({ code: z.string(), message: z.string() })),
  monitoring: z.looseObject({ enabled: z.boolean(), recheckQueued: z.boolean() }),
});
export type SbomUploadAnswer = z.infer<typeof sbomUploadAnswerSchema>;

export interface SbomUploadInput {
  projectKey: string;
  version?: string;
  /** The gzipped SBOM on disk (`withPrivateGzipFile`). */
  file: string;
  size: number;
}

/** The problem's title and detail, cleaned of control sequences and bounded. */
function problemText(res: HttpResponse): string {
  const p = parseProblem(res.body);
  const code = p?.code !== undefined && /^[A-Z][A-Z0-9_]{0,63}$/.test(p.code) ? ` ${p.code}` : '';
  const parts = [p?.title, p?.detail]
    .filter((t): t is string => t !== undefined)
    .map(clean)
    .filter((t) => t !== '');
  return `${res.status}${code}${parts.length === 0 ? '' : `: ${parts.join(': ')}`}`;
}

/** config.md §7: 401/403 exit 5, any other refusal exits 4. */
function sbomRefusal(res: HttpResponse, input: SbomUploadInput): CliError {
  const text = problemText(res);
  if (res.status === 401 || res.status === 403) {
    return new CliError(EXIT.AUTH, `the server rejected the SBOM upload (${text})`);
  }
  if (res.status === 404 && parseProblem(res.body)?.code === 'PROJECT_NOT_FOUND') {
    return new CliError(
      EXIT.SERVER,
      `project ${clean(input.projectKey)} does not exist on the server, or the token cannot see it (${text})`,
    );
  }
  if (res.status === 404) {
    return new CliError(
      EXIT.SERVER,
      'the server has no SBOM upload endpoint (404); it needs Qualor 0.16 or later, and server.url must be the Qualor server',
    );
  }
  return new CliError(EXIT.SERVER, `the server rejected the SBOM upload (${text})`);
}

/**
 * `PUT /api/v0/projects/sbom?projectKey=&version=` with the gzipped SBOM streamed from disk,
 * `Content-Length` and `Expect: 100-continue` (a bad token, an unknown project or an oversized
 * body is refused before a byte is sent). 201 is a new version, 200 a replaced one. 503
 * `UPLOADS_BUSY` is retried within the SBOM budget above; auth, TLS and error handling are the
 * scan upload's (`request`).
 */
export async function uploadSbom(
  ep: ServerEndpoint,
  input: SbomUploadInput,
  o: { log: Logger; wait?: (ms: number) => Promise<unknown> },
): Promise<{ status: 200 | 201; answer: SbomUploadAnswer }> {
  const wait = o.wait ?? ((ms: number) => sleep(ms));
  let waited = 0;
  for (let attempt = 1; ; attempt++) {
    const res = await request(ep, {
      method: 'PUT',
      path: 'api/v0/projects/sbom',
      query: {
        projectKey: input.projectKey,
        ...(input.version !== undefined && { version: input.version }),
      },
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: { stream: () => createReadStream(input.file), contentLength: input.size },
    });
    if (res.status === 200 || res.status === 201) {
      return {
        status: res.status,
        answer: parseJson(res, sbomUploadAnswerSchema, 'SBOM upload response'),
      };
    }
    const delay = sbomRetryDelay(res, attempt, waited);
    if (delay !== null) {
      // Up to 300 retries: the first one is logged, then every 10th.
      if (attempt === 1) {
        o.log.info(`the server is busy with another upload; retrying in ${delay / 1000} s`);
      } else if (attempt % BUSY_LOG_EVERY === 0) {
        o.log.info(
          `the server is still busy (retry ${attempt}, ${Math.round(waited / 1000)} s so far); retrying`,
        );
      }
      waited += delay;
      await wait(delay);
      continue;
    }
    throw sbomRefusal(res, input);
  }
}
