import { createReadStream } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import type { Logger } from '../log';
import {
  describeFailure,
  parseJson,
  parseProblem,
  request,
  retryAfterMs,
  type ServerEndpoint,
} from './http';

export const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';
/** 503 `UPLOADS_BUSY` is retried this many times in all, waiting `Retry-After` (1–30 s). */
export const MAX_UPLOAD_ATTEMPTS = 5;
/** The waits between those attempts add up to at most this. */
export const MAX_UPLOAD_RETRY_WAIT_MS = 60_000;
const MIN_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;
const DEFAULT_RETRY_MS = 2_000;

export interface UploadInput {
  projectKey: string;
  /** The gzipped report on disk (written by `writeReport` / `withPrivateReportFile`). */
  file: string;
  size: number;
}

export interface UploadResult {
  analysisId: string;
}

const accepted = z.looseObject({
  analysisId: z.uuid(),
  status: z.literal('queued'),
  statusUrl: z.string(),
});

/**
 * `POST /api/v0/analyses?projectKey=` (api.md §3) with the gzipped report, streamed from disk,
 * `Content-Length` and `Expect: 100-continue`: the server refuses a bad token, an unknown project
 * or an oversized report before a byte of the body is sent. 503 `UPLOADS_BUSY` is retried
 * (ruling E5) after `Retry-After`, clamped to 1–30 s, at most `MAX_UPLOAD_ATTEMPTS` times and
 * `MAX_UPLOAD_RETRY_WAIT_MS` in all. config.md §7: 401/403 exit 5, any other refusal or an
 * unreachable server exits 4. The token never appears in a message (`request` masks it).
 */
export async function uploadReport(
  ep: ServerEndpoint,
  input: UploadInput,
  o: { log: Logger; wait?: (ms: number) => Promise<unknown> },
): Promise<UploadResult> {
  const wait = o.wait ?? ((ms: number) => sleep(ms));
  let waited = 0;
  for (let attempt = 1; ; attempt++) {
    const res = await request(ep, {
      method: 'POST',
      path: 'api/v0/analyses',
      query: { projectKey: input.projectKey },
      headers: { 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
      body: { stream: () => createReadStream(input.file), contentLength: input.size },
    });
    if (res.status === 202) {
      return { analysisId: parseJson(res, accepted, 'upload response').analysisId };
    }
    const problem = parseProblem(res.body);
    if (res.status === 503 && problem?.code === 'UPLOADS_BUSY' && attempt < MAX_UPLOAD_ATTEMPTS) {
      const delay = Math.min(
        retryAfterMs(res.headers, MIN_RETRY_MS, MAX_RETRY_MS) ?? DEFAULT_RETRY_MS,
        MAX_UPLOAD_RETRY_WAIT_MS - waited,
      );
      if (delay > 0) {
        o.log.info(`the server is busy with other uploads; retrying in ${delay / 1000} s`);
        waited += delay;
        await wait(delay);
        continue;
      }
    }
    if (res.status === 401 || res.status === 403) {
      throw new CliError(EXIT.AUTH, `the server rejected the upload (${describeFailure(res)})`);
    }
    if (res.status === 404 && problem?.code === 'PROJECT_NOT_FOUND') {
      throw new CliError(
        EXIT.SERVER,
        `project ${input.projectKey} does not exist on the server, or the token cannot see it (404 PROJECT_NOT_FOUND)`,
      );
    }
    if (res.status === 404) {
      throw new CliError(
        EXIT.SERVER,
        'the server has no report upload endpoint (404); check that server.url is the Qualor server',
      );
    }
    if (res.status === 413) {
      throw new CliError(
        EXIT.SERVER,
        `the report (${(input.size / 1024 / 1024).toFixed(1)} MiB gzipped) is larger than the server accepts (${describeFailure(res)})`,
      );
    }
    throw new CliError(EXIT.SERVER, `the server rejected the upload (${describeFailure(res)})`);
  }
}
