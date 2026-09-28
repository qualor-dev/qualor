import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import { silentLogger, type Logger } from '../log';
import {
  clean,
  describeFailure,
  parseJson,
  parseProblem,
  request,
  type HttpResponse,
  type ServerEndpoint,
} from './http';

/**
 * The warning codes `GET /projects/new-code-baseline` may return (api.md §3: an enum, a
 * compatibility commitment). The CLI copies them into the report (report-format §4); a code it
 * does not know is ignored (ruling V7), so a newer server never breaks an older CLI.
 */
export const BASELINE_WARNINGS = [
  'NEW_CODE_DEFINITION_FALLBACK',
  'NEW_CODE_BASELINE_MISSING',
] as const;
export type BaselineWarning = (typeof BASELINE_WARNINGS)[number];

export const BASELINE_WARNING_MESSAGES: Readonly<Record<BaselineWarning, string>> = {
  NEW_CODE_DEFINITION_FALLBACK:
    'the project new-code definition could not be applied (previous_version without version labels); the server used days: 30',
  NEW_CODE_BASELINE_MISSING:
    'the fixed new-code baseline analysis no longer exists on the main branch; the server used days: 30',
};

export interface BaselineAnswer {
  revision: string | null;
  /** The known codes from the response `warnings` (report-format §4). */
  warnings: BaselineWarning[];
}

/** Ruling C6 and its N3 follow-ups: the main-branch baseline comes from the server (gates.md §5). */
export interface NewCodeBaselineClient {
  /** `'unsupported'` when the server does not offer the endpoint. */
  fetchBaseline(q: {
    projectKey: string;
    branch: string;
    version?: string | undefined;
  }): Promise<BaselineAnswer | 'unsupported'>;
}

const response = z.looseObject({
  revision: z
    .string()
    .regex(/^[0-9a-f]{40}([0-9a-f]{24})?$/)
    .nullable(),
  // Ruling V7: entries are read leniently; only known string codes are kept (below), so a newer
  // server's code of any shape never fails an older CLI.
  warnings: z.array(z.unknown()).optional(),
});

/** At most this many codes are looked at; the server sends at most two. */
const MAX_BASELINE_WARNINGS = 16;

function isBaselineWarning(code: string): code is BaselineWarning {
  return (BASELINE_WARNINGS as readonly string[]).includes(code);
}

/** A tiny JSON object; a server bug or a proxy gone wrong should never make the CLI buffer megabytes. */
const MAX_BASELINE_RESPONSE_BYTES = 64 * 1024;

/**
 * Plan 1C ruling N3: a server without the route answers a plain 404 (`NOT_FOUND`, or no problem
 * body at all); a plan-1A server matches the path as `/projects/:id` and answers 422
 * `VALIDATION_FAILED` on `params.id`. Both mean "this server has no baseline endpoint".
 */
export function isMissingEndpoint(res: HttpResponse): boolean {
  const problem = parseProblem(res.body);
  if (res.status === 404) return problem?.code !== 'PROJECT_NOT_FOUND';
  if (res.status === 422 && problem?.code === 'VALIDATION_FAILED') {
    return (problem.errors ?? []).some((e) => e.path.startsWith('params.'));
  }
  return false;
}

/**
 * The server's main branch, from the 409 `NOT_MAIN_BRANCH` problem text (`Only the main branch
 * (x) has a server-side …`; the server puts it in `title`, `detail` is read too). Greedy up to
 * the last `) has`, so a name with parentheses survives; cleaned for the terminal.
 */
export function serverMainBranch(res: HttpResponse): string | null {
  const p = parseProblem(res.body);
  for (const text of [p?.title, p?.detail]) {
    if (text === undefined) continue;
    const name = /main branch \((.{1,255})\) has\b/s.exec(text)?.[1];
    if (name !== undefined) return clean(name);
  }
  return null;
}

export function httpBaselineClient(
  ep: ServerEndpoint,
  log: Logger = silentLogger,
): NewCodeBaselineClient {
  return {
    async fetchBaseline({ projectKey, branch, version }) {
      const res = await request(ep, {
        method: 'GET',
        path: 'api/v0/projects/new-code-baseline',
        query: { projectKey, branch, version },
        maxResponseBytes: MAX_BASELINE_RESPONSE_BYTES,
      });
      if (res.status === 200) {
        const body = parseJson(res, response, 'new-code baseline response');
        const entries = (body.warnings ?? []).slice(0, MAX_BASELINE_WARNINGS);
        const known = entries.filter(
          (c): c is BaselineWarning => typeof c === 'string' && isBaselineWarning(c),
        );
        if (known.length < entries.length) {
          const shown = entries
            .filter((c) => !known.includes(c as BaselineWarning))
            .map((c) => (typeof c === 'string' ? clean(c).slice(0, 64) : `(${typeof c})`));
          log.debug(
            `ignoring new-code baseline warnings this CLI does not know: ${shown.join(', ')}`,
          );
        }
        return { revision: body.revision, warnings: known };
      }
      if (isMissingEndpoint(res)) return 'unsupported';
      if (res.status === 401 || res.status === 403) {
        throw new CliError(
          EXIT.AUTH,
          `the server rejected the token when asked for the new-code baseline (${describeFailure(res)})`,
        );
      }
      const problem = parseProblem(res.body);
      if (res.status === 404) {
        throw new CliError(
          EXIT.SERVER,
          `project ${projectKey} does not exist on the server, or the token cannot see it (404 PROJECT_NOT_FOUND)`,
        );
      }
      if (res.status === 409 && problem?.code === 'NOT_MAIN_BRANCH') {
        const serverMain = serverMainBranch(res) ?? "the project's main branch";
        throw new CliError(
          EXIT.USAGE,
          `this scan treats "${branch}" as the main branch, but the server's main branch for ${projectKey} is ${serverMain}; ` +
            'set scm.mainBranch (or fix the default branch in CI), or change the main branch of the project on the server',
        );
      }
      throw new CliError(
        EXIT.SERVER,
        `the server answered ${describeFailure(res)} to the new-code baseline request`,
      );
    },
  };
}
