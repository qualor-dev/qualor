import type { FastifyError, FastifyInstance, FastifyReply } from 'fastify';
import { hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod';
import { isForeignKeyViolation, pgErrorCode } from '../db/errors';

const PG_SERIALIZATION_FAILURE = '40001';
const PG_DEADLOCK_DETECTED = '40P01';
/** `lock_timeout` expired (issue transitions wait on rows an ingestion holds). */
const PG_LOCK_NOT_AVAILABLE = '55P03';
/** Text the database cannot store: invalid byte sequence (e.g. U+0000), untranslatable character. */
const PG_CHARACTER_NOT_IN_REPERTOIRE = '22021';
const PG_UNTRANSLATABLE_CHARACTER = '22P05';

export interface FieldError {
  path: string;
  message: string;
}

/**
 * Top-level members a problem may carry beyond RFC 9457's own (each documented in the shared
 * Problem schema, http/openapi.ts): a machine-readable detail a client maps to its own text.
 */
export interface ProblemExtensions {
  /**
   * 422 LICENSE_INVALID: the verifier's reason code (enterprise.md §4, §9). 422 VALIDATION_FAILED
   * of **Read metadata** (SAML): what failed (sso/saml.ts SAML_METADATA_PROBLEM_CODES).
   */
  reason?: string;
}

export interface Problem extends ProblemExtensions {
  type: string;
  title: string;
  status: number;
  code: string;
  detail?: string;
  errors?: FieldError[];
}

export interface ProblemOptions {
  detail?: string;
  errors?: FieldError[];
  headers?: Record<string, string>;
  extensions?: ProblemExtensions;
}

export function problemType(code: string): string {
  return `urn:qualor:problem:${code.toLowerCase().replaceAll('_', '-')}`;
}

/** Throw this anywhere in a request; the error handler renders it as application/problem+json. */
export class ProblemError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string | undefined;
  readonly errors: FieldError[] | undefined;
  readonly headers: Record<string, string>;
  readonly extensions: ProblemExtensions;

  constructor(status: number, code: string, title: string, options: ProblemOptions = {}) {
    super(title);
    this.name = 'ProblemError';
    this.status = status;
    this.code = code;
    this.detail = options.detail;
    this.errors = options.errors;
    this.headers = options.headers ?? {};
    this.extensions = { ...options.extensions };
  }

  toProblem(): Problem {
    return {
      type: problemType(this.code),
      title: this.message,
      status: this.status,
      code: this.code,
      ...this.extensions,
      ...(this.detail === undefined ? {} : { detail: this.detail }),
      ...(this.errors === undefined ? {} : { errors: this.errors }),
    };
  }
}

export const unauthenticated = (): ProblemError =>
  new ProblemError(401, 'UNAUTHENTICATED', 'Authentication required', {
    headers: { 'www-authenticate': 'Bearer' },
  });
export const forbidden = (
  code = 'FORBIDDEN',
  title = 'You are not allowed to do this',
): ProblemError => new ProblemError(403, code, title);
export const notFound = (what = 'Resource', code = 'NOT_FOUND'): ProblemError =>
  new ProblemError(404, code, `${what} not found`);
export const conflict = (code: string, title: string): ProblemError =>
  new ProblemError(409, code, title);
export const validationFailed = (errors: FieldError[]): ProblemError =>
  new ProblemError(422, 'VALIDATION_FAILED', 'Request validation failed', { errors });

const CONTEXT_PREFIX: Record<string, string> = {
  body: 'body',
  querystring: 'query',
  params: 'params',
  headers: 'headers',
};

function toProblemError(error: FastifyError): ProblemError | null {
  if (hasZodFastifySchemaValidationErrors(error)) {
    const prefix = CONTEXT_PREFIX[error.validationContext ?? 'body'] ?? 'body';
    return validationFailed(
      error.validation.map((issue) => ({
        path: [prefix, ...issue.instancePath.split('/').filter((s) => s !== '')].join('.'),
        message: issue.message ?? 'Invalid value',
      })),
    );
  }
  // Database errors the client can act on. Never echo the error itself: drizzle's message embeds
  // the SQL and its parameters.
  const sqlState = pgErrorCode(error);
  if (
    sqlState === PG_DEADLOCK_DETECTED ||
    sqlState === PG_SERIALIZATION_FAILURE ||
    sqlState === PG_LOCK_NOT_AVAILABLE
  ) {
    return new ProblemError(
      503,
      'CONCURRENCY_CONFLICT',
      'The request conflicted with a concurrent change; retry it',
      { headers: { 'retry-after': '1' } },
    );
  }
  if (sqlState === PG_CHARACTER_NOT_IN_REPERTOIRE || sqlState === PG_UNTRANSLATABLE_CHARACTER) {
    // A backstop: routes reject U+0000 in their schemas (http/schemas.ts `text`, `noNul`), with
    // the field's path. Here the field is unknown, so `errors` is empty.
    return new ProblemError(422, 'VALIDATION_FAILED', 'Request validation failed', {
      detail: 'A text value contains a character the database cannot store (such as U+0000)',
      errors: [],
    });
  }
  if (isForeignKeyViolation(sqlState)) {
    return new ProblemError(
      409,
      'CONFLICT',
      'The request refers to something that was changed or deleted concurrently',
    );
  }
  const status = error.statusCode ?? 500;
  if (status === 413)
    return new ProblemError(413, 'BODY_TOO_LARGE', 'The request body is too large');
  if (status === 415)
    return new ProblemError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Unsupported Content-Type');
  if (status >= 400 && status < 500) {
    return new ProblemError(status, 'BAD_REQUEST', 'The request could not be understood', {
      detail: error.message,
    });
  }
  return null;
}

function sendProblem(reply: FastifyReply, problem: ProblemError): FastifyReply {
  for (const [name, value] of Object.entries(problem.headers)) reply.header(name, value);
  return reply.code(problem.status).type('application/problem+json').send(problem.toProblem());
}

export function installErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError, request, reply) => {
    const problem = error instanceof ProblemError ? error : toProblemError(error);
    if (problem) return sendProblem(reply, problem);
    request.log.error({ err: error }, 'unhandled error');
    return sendProblem(reply, new ProblemError(500, 'INTERNAL_ERROR', 'Internal server error'));
  });
  app.setNotFoundHandler((request, reply) => sendProblem(reply, notFound('Route')));
}
