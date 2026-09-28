import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { CliError, EXIT, type ExitCode } from '../errors';
import type { Logger } from '../log';
import {
  clean,
  describeFailure,
  parseJson,
  request,
  retryAfterMs,
  UnreachableError,
  type ServerEndpoint,
} from './http';

const conditionSchema = z.looseObject({
  metric: z.string(),
  operator: z.string(),
  threshold: z.number(),
  value: z.number().nullable(),
  status: z.string(),
});

/**
 * `GET /api/v0/analyses/{id}` (api.md §3; `analysisSchema` in server/src/routes/analyses.ts):
 * only what the CLI decides or prints on. `gateResult` is plan 1C's `gate_result` (the
 * `GateResult` of @qualor/shared: gate, conditions, warnings); the server types it `unknown`, so
 * a shape this CLI cannot read is dropped rather than fatal (the verdict is `gateStatus`).
 */
const analysisSchema = z.looseObject({
  id: z.string(),
  status: z.enum(['queued', 'processing', 'succeeded', 'failed']),
  gateStatus: z.enum(['passed', 'failed', 'error', 'none']).nullable(),
  gateResult: z
    .looseObject({
      gate: z.looseObject({ name: z.string() }).nullable().optional(),
      conditions: z.array(conditionSchema).optional(),
      warnings: z.array(z.string()).optional(),
    })
    .nullable()
    .optional()
    .catch(null),
  error: z.looseObject({ code: z.string(), message: z.string() }).nullable(),
});
export type AnalysisStatus = z.infer<typeof analysisSchema>;

/** api.md §3: exponential backoff from 1 s to 10 s while the analysis is queued or processing. */
const POLL_MIN_MS = 1_000;
const POLL_MAX_MS = 10_000;
/** Request timeout and rate limiting (ruling V10): retried like a 5xx. */
const TRANSIENT_4XX: ReadonlySet<number> = new Set([408, 429]);
/** Each poll request gets at least this long, even right before the gate deadline. */
const MIN_REQUEST_MS = 1_000;
/** The analysis status is a small JSON document (a few engines, warnings and conditions). */
const MAX_STATUS_RESPONSE_BYTES = 1024 * 1024;

export interface WaitOptions {
  /** `gate.timeoutSeconds`: the whole wait, from the upload's 202 to a finished analysis. */
  timeoutMs: number;
  log: Logger;
  now?: () => number;
  wait?: (ms: number) => Promise<unknown>;
}

/**
 * Polls the analysis until it has succeeded or failed (config.md §3 `gate.wait`, ruling E6).
 * Network errors, 5xx, 408 and 429 (ruling V10) are retried until the deadline, which exits 4
 * (config.md §7); 401/403 exit 5 and any other 4xx (the analysis is gone) exits 4 at once. Each request waits at most
 * `server.timeoutSeconds` and never much past the gate deadline, so a server that accepts the
 * connection and never answers cannot hold the CLI beyond `gate.timeoutSeconds` (+1 s).
 */
export async function waitForAnalysis(
  ep: ServerEndpoint,
  analysisId: string,
  o: WaitOptions,
): Promise<AnalysisStatus> {
  const now = o.now ?? (() => Date.now());
  const wait = o.wait ?? ((ms: number) => sleep(ms));
  const deadline = now() + o.timeoutMs;
  /** The last status read, and the last failure (cleaned) since then. */
  let last: string | null = null;
  let lastError: string | null = null;
  const timedOut = () => {
    const state =
      last === null
        ? `the state of analysis ${analysisId} is unknown; last error: ${lastError ?? 'none'}`
        : `analysis ${analysisId} is still ${last}${lastError === null ? '' : `; last error: ${lastError}`}`;
    return new CliError(
      EXIT.SERVER,
      `the quality gate was not available after ${Math.round(o.timeoutMs / 1000)} s (${state}); raise gate.timeoutSeconds or use --no-wait`,
    );
  };
  let delay = POLL_MIN_MS;
  for (;;) {
    let retryAfter: number | null = null;
    const requestMs = Math.min(ep.timeoutMs, Math.max(MIN_REQUEST_MS, deadline - now()));
    try {
      const res = await request(
        { ...ep, timeoutMs: requestMs },
        {
          method: 'GET',
          path: `api/v0/analyses/${analysisId}`,
          maxResponseBytes: MAX_STATUS_RESPONSE_BYTES,
        },
      );
      if (res.status === 200) {
        const analysis = parseJson(res, analysisSchema, 'analysis status');
        if (analysis.status === 'succeeded' || analysis.status === 'failed') return analysis;
        last = analysis.status;
        lastError = null;
      } else if (res.status === 401 || res.status === 403) {
        throw new CliError(
          EXIT.AUTH,
          `the server rejected the token while waiting for the quality gate (${describeFailure(res)})`,
        );
      } else if (res.status < 500 && !TRANSIENT_4XX.has(res.status)) {
        throw new CliError(
          EXIT.SERVER,
          `the server answered ${describeFailure(res)} for analysis ${analysisId}`,
        );
      } else {
        // 5xx, 408 and 429 (ruling V10): transient, retried until the deadline.
        lastError = describeFailure(res);
        o.log.debug(`analysis status: ${lastError}; retrying`);
      }
      retryAfter = retryAfterMs(res.headers, POLL_MIN_MS, POLL_MAX_MS);
    } catch (err) {
      // An unreachable server is retried until the deadline; anything the server said is final.
      if (!(err instanceof UnreachableError)) throw err;
      lastError = clean(err.message);
      o.log.debug(`analysis status: ${lastError}; retrying`);
    }
    // The last pause is shortened so that one more poll happens at the deadline itself.
    const remaining = deadline - now();
    if (remaining <= 0) throw timedOut();
    await wait(Math.min(Math.max(delay, retryAfter ?? 0), remaining));
    delay = Math.min(POLL_MAX_MS, delay * 2);
  }
}

/**
 * config.md §7 and gates.md §6: passed or none → 0; failed → 1; error (including a failed
 * analysis, whose gate is `error`) → 1 with `gate.failOnError`, else 0.
 */
export function gateExitCode(analysis: AnalysisStatus, failOnError: boolean): ExitCode {
  const status = analysis.status === 'failed' ? 'error' : (analysis.gateStatus ?? 'none');
  if (status === 'failed') return EXIT.GATE_FAILED;
  if (status === 'error') return failOnError ? EXIT.GATE_FAILED : EXIT.OK;
  return EXIT.OK;
}

/** At most this many conditions and warnings are printed; the rest are counted. */
export const MAX_PRINTED_CONDITIONS = 20;
export const MAX_PRINTED_WARNINGS = 10;

const OPERATORS: Readonly<Record<string, string>> = { gt: '>', lt: '<' };

/**
 * The lines `qualor scan` prints about the verdict (stderr, like every log line). Everything the
 * server sent is cleaned for the terminal (no escape sequences or control characters) and each
 * line is bounded; so is the number of lines.
 */
export function describeGate(analysis: AnalysisStatus): string[] {
  if (analysis.status === 'failed') {
    const code = analysis.error?.code ?? 'PROCESSING_ERROR';
    const message = analysis.error?.message ?? '';
    return [clean(`analysis ${analysis.id} failed on the server: ${code} ${message}`)];
  }
  const name = analysis.gateResult?.gate?.name;
  const lines = [
    clean(
      `quality gate${name === undefined ? '' : ` "${clean(name)}"`}: ${analysis.gateStatus ?? 'none'}`,
    ),
  ];
  const notPassed = (analysis.gateResult?.conditions ?? []).filter((c) => c.status !== 'passed');
  for (const c of notPassed.slice(0, MAX_PRINTED_CONDITIONS)) {
    const op = OPERATORS[c.operator] ?? c.operator;
    lines.push(
      `  ${clean(`${c.metric} ${op} ${c.threshold}: ${c.value ?? 'no value'} (${c.status})`)}`,
    );
  }
  if (notPassed.length > MAX_PRINTED_CONDITIONS) {
    lines.push(`  ... and ${notPassed.length - MAX_PRINTED_CONDITIONS} more conditions`);
  }
  const warnings = analysis.gateResult?.warnings ?? [];
  for (const w of warnings.slice(0, MAX_PRINTED_WARNINGS)) lines.push(`  warning: ${clean(w)}`);
  if (warnings.length > MAX_PRINTED_WARNINGS) {
    lines.push(`  ... and ${warnings.length - MAX_PRINTED_WARNINGS} more warnings`);
  }
  return lines;
}
