import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { installErrorHandling, ProblemError } from './problem';

describe('problem+json errors (RFC 9457)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = Fastify({ bodyLimit: 1024 });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    installErrorHandling(app);
    const typed = app.withTypeProvider<ZodTypeProvider>();
    typed.post(
      '/echo',
      { schema: { body: z.strictObject({ name: z.string().min(1) }) } },
      async (request) => ({
        name: request.body.name,
      }),
    );
    typed.get(
      '/items/:id',
      {
        schema: {
          params: z.strictObject({ id: z.uuid() }),
          querystring: z.strictObject({ limit: z.coerce.number().int().min(1).optional() }),
        },
      },
      async (request) => ({ id: request.params.id }),
    );
    app.get('/conflict', async () => {
      throw new ProblemError(409, 'THING_TAKEN', 'Thing taken', {
        detail: 'd',
        headers: { 'x-extra': '1' },
      });
    });
    // What drizzle throws: a DrizzleQueryError whose message embeds the SQL and its parameters,
    // wrapping the driver error that carries the SQLSTATE.
    const pgFailure = (code: string): Error =>
      new Error('Failed query: select secret-param-value', {
        cause: Object.assign(new Error('pg says no'), { code }),
      });
    app.get('/pg/:code', async (request) => {
      throw pgFailure((request.params as { code: string }).code);
    });
    app.get('/boom', async () => {
      throw new Error('database password is hunter2');
    });
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
  });

  it('maps body validation failures to 422 with errors[].path', async () => {
    const res = await app.inject({ method: 'POST', url: '/echo', payload: { name: '', extra: 1 } });
    expect(res.statusCode).toBe(422);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    const body = res.json();
    expect(body).toMatchObject({
      status: 422,
      code: 'VALIDATION_FAILED',
      type: 'urn:qualor:problem:validation-failed',
    });
    expect(body.errors.map((e: { path: string }) => e.path).sort()).toEqual(['body', 'body.name']);
  });

  it('prefixes params and query paths', async () => {
    const params = await app.inject({ method: 'GET', url: '/items/not-a-uuid' });
    expect(params.json().errors[0].path).toBe('params.id');
    const query = await app.inject({
      method: 'GET',
      url: '/items/0190a0b0-0000-7000-8000-000000000000?limit=0',
    });
    expect(query.json().errors[0].path).toBe('query.limit');
  });

  it('renders a thrown ProblemError with its headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/conflict' });
    expect(res.statusCode).toBe(409);
    expect(res.headers['x-extra']).toBe('1');
    expect(res.json()).toEqual({
      type: 'urn:qualor:problem:thing-taken',
      title: 'Thing taken',
      status: 409,
      code: 'THING_TAKEN',
      detail: 'd',
    });
  });

  it('hides unexpected errors behind 500 INTERNAL_ERROR', async () => {
    const res = await app.inject({ method: 'GET', url: '/boom' });
    expect(res.statusCode).toBe(500);
    expect(res.json().code).toBe('INTERNAL_ERROR');
    expect(res.body).not.toContain('hunter2');
  });

  it('maps deadlocks (40P01), serialization failures (40001) and lock timeouts (55P03) to 503 with Retry-After', async () => {
    for (const code of ['40P01', '40001', '55P03']) {
      const res = await app.inject({ method: 'GET', url: `/pg/${code}` });
      expect([res.statusCode, res.json().code], code).toEqual([503, 'CONCURRENCY_CONFLICT']);
      expect(res.headers['retry-after']).toBe('1');
      expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
      expect(res.body).not.toContain('secret-param-value');
    }
  });

  it('maps a foreign-key violation (23503) to 409 CONFLICT', async () => {
    const res = await app.inject({ method: 'GET', url: '/pg/23503' });
    expect([res.statusCode, res.json().code]).toEqual([409, 'CONFLICT']);
    expect(res.body).not.toContain('secret-param-value');
  });

  it('maps text the database cannot store (22021, 22P05: e.g. U+0000) to 422 VALIDATION_FAILED', async () => {
    for (const code of ['22021', '22P05']) {
      const res = await app.inject({ method: 'GET', url: `/pg/${code}` });
      expect([res.statusCode, res.json().code], code).toEqual([422, 'VALIDATION_FAILED']);
      expect(res.json().errors).toEqual([]);
      expect(res.body).not.toContain('secret-param-value');
    }
  });

  it('keeps other database errors behind 500 INTERNAL_ERROR', async () => {
    const res = await app.inject({ method: 'GET', url: '/pg/23505' });
    expect([res.statusCode, res.json().code]).toEqual([500, 'INTERNAL_ERROR']);
  });

  it('maps parser errors: malformed JSON 400, oversized 413, unknown media type 415, unknown route 404', async () => {
    const malformed = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json' },
      payload: '{"name":',
    });
    expect([malformed.statusCode, malformed.json().code]).toEqual([400, 'BAD_REQUEST']);
    const large = await app.inject({
      method: 'POST',
      url: '/echo',
      payload: { name: 'x'.repeat(2_000) },
    });
    expect([large.statusCode, large.json().code]).toEqual([413, 'BODY_TOO_LARGE']);
    const xml = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/xml' },
      payload: '<a/>',
    });
    expect([xml.statusCode, xml.json().code]).toEqual([415, 'UNSUPPORTED_MEDIA_TYPE']);
    const missing = await app.inject({ method: 'GET', url: '/nope' });
    expect([missing.statusCode, missing.json().code]).toEqual([404, 'NOT_FOUND']);
  });
});
