import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { CliError } from '../errors';
import { createLogger } from '../log';
import { httpBaselineClient, isMissingEndpoint, serverMainBranch } from './baseline-client';

const serve = useTestServers();
const q = { projectKey: 'acme/app', branch: 'main' };
const client = (url: string, token = 'qlr_prj_t') =>
  httpBaselineClient({ url, token, timeoutMs: 5_000 });

async function failure(url: string, token = 'qlr_secret'): Promise<CliError> {
  const err: unknown = await client(url, token)
    .fetchBaseline(q)
    .catch((e: unknown) => e);
  if (!(err instanceof CliError)) throw new Error(`expected a CliError, got ${String(err)}`);
  expect(err.message).not.toContain(token);
  return err;
}

describe('httpBaselineClient', () => {
  it('asks with the token, the project, the branch and the version, and returns revision and warnings', async () => {
    const { url, requests } = await serve(
      (_req, res) =>
        json(res, 200, {
          revision: 'a'.repeat(40),
          analysisId: null,
          analysisDate: null,
          definition: { type: 'days', value: 30 },
          warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
        }),
      { prefix: '/qualor' },
    );
    expect(await client(url).fetchBaseline({ ...q, version: '1.4.0' })).toEqual({
      revision: 'a'.repeat(40),
      warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
    });
    expect(requests[0]?.url).toBe(
      '/qualor/api/v0/projects/new-code-baseline?projectKey=acme%2Fapp&branch=main&version=1.4.0',
    );
    expect(requests[0]?.headers.authorization).toBe('Bearer qlr_prj_t');
    expect(requests[0]?.headers['user-agent']).toMatch(/^qualor-cli\//);
  });

  it('maps null to a first analysis and leaves out an absent version', async () => {
    const { url, requests } = await serve((_req, res) => json(res, 200, { revision: null }));
    expect(await client(url).fetchBaseline(q)).toEqual({ revision: null, warnings: [] });
    expect(requests[0]?.url).not.toContain('version');
  });

  it('treats a plain 404, a 404 without a problem body and an old server 422 as a missing endpoint (N3)', async () => {
    for (const handler of [
      (res: Parameters<typeof problem>[0]) => problem(res, 404, 'NOT_FOUND'),
      (res: Parameters<typeof problem>[0]) => {
        res.writeHead(404).end('Not Found');
      },
      (res: Parameters<typeof problem>[0]) =>
        json(res, 422, {
          code: 'VALIDATION_FAILED',
          errors: [{ path: 'params.id', message: 'Invalid UUID' }],
        }),
    ]) {
      const { url } = await serve((_req, res) => handler(res));
      expect(await client(url).fetchBaseline(q)).toBe('unsupported');
    }
  });

  it('reports an unknown or invisible project as an error, not as a missing endpoint (N3)', async () => {
    const { url } = await serve((_req, res) => problem(res, 404, 'PROJECT_NOT_FOUND'));
    const err = await failure(url);
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('project acme/app does not exist on the server');
  });

  it('turns 409 NOT_MAIN_BRANCH into a config error naming both branches (N3)', async () => {
    const { url } = await serve((_req, res) =>
      problem(
        res,
        409,
        'NOT_MAIN_BRANCH',
        'Only the main branch (trunk) has a server-side new-code baseline',
      ),
    );
    const err = await failure(url);
    expect(err.exitCode).toBe(2);
    expect(err.message).toContain('"main" as the main branch');
    expect(err.message).toContain('main branch for acme/app is trunk');
  });

  it.each([
    [401, 'UNAUTHENTICATED', 5],
    [403, 'INSUFFICIENT_SCOPE', 5],
    [500, 'INTERNAL_ERROR', 4],
    [422, 'VALIDATION_FAILED', 4],
  ])('status %i %s exits %i and never echoes the token', async (status, code, exitCode) => {
    const { url } = await serve((_req, res) => problem(res, status, code));
    const err = await failure(url);
    expect(err.exitCode).toBe(exitCode);
    expect(err.message).toContain(`${status} ${code}`);
  });

  it('ignores unknown warning codes and caps the list (ruling V7)', async () => {
    const warnings = [
      'NEW_CODE_BASELINE_MISSING',
      'UNKNOWN_CODE',
      ...Array.from({ length: 40 }, (_, i) => `NEWER_${i}`),
      'NEW_CODE_DEFINITION_FALLBACK',
    ];
    const { url } = await serve((_req, res) => json(res, 200, { revision: null, warnings }));
    const lines: string[] = [];
    const answer = await httpBaselineClient(
      { url, token: 't', timeoutMs: 5_000 },
      createLogger('debug', (t) => lines.push(t)),
    ).fetchBaseline(q);
    expect(answer).toEqual({ revision: null, warnings: ['NEW_CODE_BASELINE_MISSING'] });
    expect(lines.join('')).toContain('UNKNOWN_CODE');
  });

  it('drops an over-long or non-string warning entry instead of failing (ruling V7)', async () => {
    const warnings = [
      'X'.repeat(500),
      42,
      null,
      { code: 'NEW_CODE_BASELINE_MISSING' },
      ['NEW_CODE_BASELINE_MISSING'],
      'NEW_CODE_DEFINITION_FALLBACK',
    ];
    const { url } = await serve((_req, res) => json(res, 200, { revision: null, warnings }));
    const lines: string[] = [];
    const answer = await httpBaselineClient(
      { url, token: 't', timeoutMs: 5_000 },
      createLogger('debug', (t) => lines.push(t)),
    ).fetchBaseline(q);
    expect(answer).toEqual({ revision: null, warnings: ['NEW_CODE_DEFINITION_FALLBACK'] });
    // The debug line stays bounded: an over-long code is not repeated in full.
    expect(lines.join('')).not.toContain('X'.repeat(100));
  });

  it('names the failing request fields of a 422, cleaned', async () => {
    const { url } = await serve((_req, res) =>
      json(res, 422, {
        code: 'VALIDATION_FAILED',
        title: 'Request validation failed',
        errors: [
          { path: 'query.version', message: 'Too long' },
          { path: 'query.\u001b[31mbranch', message: 'x' },
          { path: 'query.a', message: 'x' },
          { path: 'query.b', message: 'x' },
          { path: 'query.c', message: 'x' },
        ],
      }),
    );
    const err = await failure(url);
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('query.version');
    expect(err.message).toContain('query.branch');
    expect(err.message).not.toContain('\u001b');
    expect(err.message).not.toContain('query.c');
  });

  it.each(['not json', '{"revision":"nothex"}', '{"revision":null,"warnings":"NOT_A_LIST"}'])(
    'exits 4 on an invalid body %s',
    async (body) => {
      const { url } = await serve((_req, res) => {
        res.writeHead(200).end(body);
      });
      expect((await failure(url)).exitCode).toBe(4);
    },
  );

  it('exits 4 when the server is unreachable', async () => {
    const { url, server } = await serve((_req, res) => json(res, 200, {}));
    await new Promise<void>((resolve) => server.close(() => resolve()));
    expect((await failure(url)).exitCode).toBe(4);
  });

  it('rejects an oversized response, declared or chunked', async () => {
    const big = await serve((_req, res) =>
      json(res, 200, { revision: null, padding: 'x'.repeat(70_000) }),
    );
    expect((await failure(big.url)).message).toContain('larger than');
    const chunked = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      for (let i = 0; i < 100; i++) res.write('x'.repeat(1_000));
      res.end();
    });
    expect((await failure(chunked.url)).message).toContain('larger than');
  });
});

describe('baseline response helpers', () => {
  const res = (status: number, body: unknown) => ({
    status,
    headers: {},
    body: JSON.stringify(body),
  });
  it('recognises a missing endpoint only for the N3 shapes', () => {
    expect(isMissingEndpoint(res(404, { code: 'PROJECT_NOT_FOUND' }))).toBe(false);
    expect(
      isMissingEndpoint(
        res(422, { code: 'VALIDATION_FAILED', errors: [{ path: 'query.version', message: 'x' }] }),
      ),
    ).toBe(false);
    expect(isMissingEndpoint(res(500, {}))).toBe(false);
  });
  it('reads the server main branch from the 409 detail, if it is there', () => {
    expect(serverMainBranch(res(409, { detail: 'Only the main branch (develop) has …' }))).toBe(
      'develop',
    );
    expect(
      serverMainBranch(
        res(409, { title: 'Only the main branch (main) has a server-side new-code baseline' }),
      ),
    ).toBe('main');
    expect(serverMainBranch(res(409, { detail: 'something else' }))).toBeNull();
    // Branch names may hold parentheses and must not smuggle terminal escapes into the message.
    expect(
      serverMainBranch(
        res(409, {
          title: 'Only the main branch (release(2)) has a server-side new-code baseline',
        }),
      ),
    ).toBe('release(2)');
    expect(
      serverMainBranch(
        res(409, {
          title: 'Only the main branch (a\u001b[2Jb\nc) has a server-side new-code baseline',
        }),
      ),
    ).toBe('ab c');
  });
});
