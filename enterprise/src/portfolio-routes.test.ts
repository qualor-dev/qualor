// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';
import type {
  PluginContext,
  PluginPortfolio,
  PortfolioProjectRow,
} from '@qualor/server/plugin-contract';
import { portfolioRoutes } from './portfolio-routes';
import type * as Pdf from './portfolio/pdf';
import { RenderTimeoutError } from './pdf/layout';
import { sampleOverview, sampleRows } from './portfolio/test-overview';

/** The PDF renderer, real unless a test makes it time out or holds it. */
const pdf = vi.hoisted(() => ({
  timeout: false,
  calls: [] as unknown[][],
  hold: undefined as Promise<unknown> | undefined,
}));
vi.mock('./portfolio/pdf', async (importOriginal) => {
  const real = await importOriginal<typeof Pdf>();
  return {
    ...real,
    renderPortfolioPdf: async (...args: Parameters<typeof real.renderPortfolioPdf>) => {
      pdf.calls.push(args);
      await pdf.hold;
      if (pdf.timeout) throw new RenderTimeoutError();
      return real.renderPortfolioPdf(...args);
    },
  };
});

const ORG_ID = '7a9e3c1d-2b4f-4c6e-8a0b-1c2d3e4f5a6b';
const ORG = `scope=organization&organizationId=${ORG_ID}`;
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

/** A GET on a real socket that the client drops after `ms`, as a browser that goes away. */
function dropAfter(url: string, ms: number): Promise<void> {
  return new Promise((resolve) => {
    const req = http.get(url, { agent: false });
    req.on('error', () => undefined);
    setTimeout(() => {
      req.destroy();
      resolve();
    }, ms);
  });
}

/** The status of a GET on a real socket, its body read to the end. */
function statusOf(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    http
      .get(url, { agent: false }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      })
      .on('error', reject);
  });
}

/** Listens on a free local port: the base URL. */
async function listening(server: FastifyInstance): Promise<string> {
  await server.listen({ port: 0, host: '127.0.0.1' });
  return `http://127.0.0.1:${(server.server.address() as AddressInfo).port}`;
}

/** A deferred promise a test settles by hand. */
function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const problem = (status: number, code: string, title: string) =>
  Object.assign(new Error(title), { statusCode: status, code });

type FakePortfolio = { [K in keyof PluginPortfolio]: Mock<PluginPortfolio[K]> };
type Logged = [level: string, ...args: unknown[]];

/** The rows of `sampleRows()`, after `before` (when given) settles. */
function rowsAfter(before?: Promise<unknown>) {
  return async function* (): AsyncGenerator<PortfolioProjectRow> {
    await before;
    yield* sampleRows();
  };
}

/** The routes over a fake context: every caller is `x-user` (u1 by default). */
function harness(over: Partial<FakePortfolio> = {}, user: Record<string, unknown> = {}) {
  const logged: Logged[] = [];
  const service: FakePortfolio = {
    overview: vi.fn(async () => sampleOverview('organization')),
    projects: vi.fn(async () => ({ items: sampleRows(), nextCursor: null })),
    exportRows: vi.fn(rowsAfter()),
    ...over,
  };
  const requireOrganizationAccess = vi.fn(async (_request: unknown, organizationId: string) => ({
    organizationId,
    organizationKey: 'platform',
    role: 'viewer',
    permissions: new Set(['org.read']),
  }));
  const ctx = {
    serverVersion: '0.8.0',
    logger: {
      debug: (...args: unknown[]) => logged.push(['debug', ...args]),
      info: (...args: unknown[]) => logged.push(['info', ...args]),
      warn: (...args: unknown[]) => logged.push(['warn', ...args]),
      error: (...args: unknown[]) => logged.push(['error', ...args]),
    },
    access: {
      requireUser: (request: { headers: Record<string, unknown> }) => {
        const id = String(request.headers['x-user'] ?? 'u1');
        return {
          user: {
            id,
            username: `user-${id}`,
            displayName: 'Ann Example',
            isInstanceAdmin: false,
            ...user,
          },
        };
      },
      requireOrganizationAccess,
      problem,
    },
    portfolio: service,
  } as unknown as PluginContext;
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  void app.register(portfolioRoutes(ctx));
  return { app, service, logged, requireOrganizationAccess };
}

let app: FastifyInstance | undefined;
afterEach(async () => {
  pdf.timeout = false;
  pdf.calls.length = 0;
  pdf.hold = undefined;
  vi.useRealTimers();
  await app?.close();
  app = undefined;
});

describe('the scope of every portfolio route (4E-2 §3)', () => {
  it('needs organizationId exactly with the organisation scope, as a uuid', async () => {
    const h = harness();
    app = h.app;
    for (const path of ['/portfolio', '/portfolio/projects', '/portfolio/export?format=csv&']) {
      const url = (query: string) => (path.endsWith('&') ? `${path}${query}` : `${path}?${query}`);
      for (const query of [
        '',
        'scope=organization',
        `scope=all&organizationId=${ORG_ID}`,
        'scope=organization&organizationId=nope',
        'scope=project',
        `${ORG}&granularity=day`,
      ]) {
        const res = await app.inject({ url: url(query) });
        expect(res.statusCode, url(query)).toBe(400);
      }
    }
    expect(h.service.overview).not.toHaveBeenCalled();
    expect(h.service.projects).not.toHaveBeenCalled();
    expect(h.service.exportRows).not.toHaveBeenCalled();
  });
});

describe('GET /portfolio (4E-2 §3)', () => {
  it('answers the overview of the scope, by week unless months are asked for', async () => {
    const h = harness();
    app = h.app;
    const res = await app.inject({ url: `/portfolio?${ORG}` });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual(sampleOverview('organization'));
    await app.inject({ url: '/portfolio?scope=all&granularity=month' });
    expect(h.service.overview.mock.calls.map((c) => [c[1], c[2]])).toEqual([
      [{ scope: 'organization', organizationId: ORG_ID }, { granularity: 'week' }],
      [{ scope: 'all' }, { granularity: 'month' }],
    ]);
  });

  it('passes the service problems through (404, 503 PORTFOLIO_TIMEOUT)', async () => {
    const h = harness();
    h.service.overview.mockRejectedValueOnce(problem(404, 'NOT_FOUND', 'Organization not found'));
    h.service.overview.mockRejectedValueOnce(
      problem(503, 'PORTFOLIO_TIMEOUT', 'The portfolio took too long to compute'),
    );
    app = h.app;
    expect((await app.inject({ url: `/portfolio?${ORG}` })).statusCode).toBe(404);
    const late = await app.inject({ url: '/portfolio?scope=all' });
    expect(late.statusCode).toBe(503);
    expect(late.json()).toMatchObject({ code: 'PORTFOLIO_TIMEOUT' });
  });
});

describe('GET /portfolio/projects (4E-2 §3)', () => {
  it('pages the rows: a sort, a limit of 1 to 100 (50 by default) and a cursor', async () => {
    const h = harness();
    app = h.app;
    for (const query of [
      `${ORG}&limit=101`,
      `${ORG}&limit=0`,
      `${ORG}&limit=1.5`,
      `${ORG}&sort=name`,
    ]) {
      expect((await app.inject({ url: `/portfolio/projects?${query}` })).statusCode, query).toBe(
        400,
      );
    }
    expect(h.service.projects).not.toHaveBeenCalled();
    const res = await app.inject({ url: `/portfolio/projects?${ORG}` });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({ items: sampleRows(), nextCursor: null });
    await app.inject({ url: '/portfolio/projects?scope=all&sort=gate&limit=100&cursor=abc' });
    expect(h.service.projects.mock.calls.map((c) => [c[1], c[2]])).toEqual([
      [
        { scope: 'organization', organizationId: ORG_ID },
        { sort: 'key', limit: 50 },
      ],
      [{ scope: 'all' }, { sort: 'gate', limit: 100, cursor: 'abc' }],
    ]);
  });

  it('accepts the vulnerable-release and exploited sorts', async () => {
    const h = harness();
    app = h.app;
    for (const sort of ['vulnerableReleases', 'exploited']) {
      const res = await app.inject({ url: `/portfolio/projects?${ORG}&sort=${sort}` });
      expect(res.statusCode, res.body).toBe(200);
    }
    expect(h.service.projects.mock.calls.map((c) => c[2].sort)).toEqual([
      'vulnerableReleases',
      'exploited',
    ]);
  });
});

describe('GET /portfolio/export (4E-2 §3)', () => {
  const exportOf = (query: string, headers: Record<string, string> = {}) =>
    app!.inject({ url: `/portfolio/export?${query}`, headers });

  it('refuses another format', async () => {
    const h = harness();
    app = h.app;
    expect((await exportOf(`${ORG}&format=xlsx`)).statusCode).toBe(400);
    expect((await exportOf(ORG)).statusCode).toBe(400);
    expect(h.service.exportRows).not.toHaveBeenCalled();
  });

  it('streams the CSV with its BOM, one line per row, named by the organisation key and the day', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-13T23:59:00.000Z'));
    const h = harness();
    app = h.app;
    const res = await exportOf(`${ORG}&format=csv`);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-portfolio-platform-20261013.csv"',
    );
    expect(res.rawPayload.subarray(0, 3).equals(BOM)).toBe(true);
    const lines = res.body.replace(/^\uFEFF/, '').split('\r\n');
    expect(lines.pop()).toBe('');
    expect(lines[0]).toMatch(/^organization_key,organization,project_key,project,/);
    expect(lines).toHaveLength(sampleRows().length + 1);
    expect(h.service.exportRows.mock.calls[0]?.[1]).toEqual({
      scope: 'organization',
      organizationId: ORG_ID,
    });
    expect(h.requireOrganizationAccess.mock.calls[0]?.slice(1)).toEqual([ORG_ID, 'org.read']);

    const all = await exportOf('scope=all&format=csv');
    expect(all.headers['content-disposition']).toBe(
      'attachment; filename="qualor-portfolio-all-20261013.csv"',
    );
    expect(h.requireOrganizationAccess).toHaveBeenCalledTimes(1);
  });

  it('answers a problem, not a broken stream, when the rows are refused, and frees the slot', async () => {
    const h = harness({
      // As core's generator: the refusal comes on the first next().
      exportRows: vi.fn(async function* (): AsyncGenerator<PortfolioProjectRow> {
        const rows: PortfolioProjectRow[] = await Promise.reject(
          problem(503, 'PORTFOLIO_TIMEOUT', 'The portfolio took too long to compute'),
        );
        yield* rows;
      }),
    });
    app = h.app;
    const res = await exportOf('scope=all&format=csv');
    expect(res.statusCode).toBe(503);
    expect(res.headers['content-disposition']).toBeUndefined();
    expect(res.json()).toMatchObject({ code: 'PORTFOLIO_TIMEOUT' });
    h.service.exportRows.mockImplementation(rowsAfter());
    expect((await exportOf('scope=all&format=csv')).statusCode).toBe(200);
  });

  it('renders the PDF from the overview and the first 50 rows by gate, named by generatedAt', async () => {
    const h = harness();
    app = h.app;
    const res = await exportOf(`${ORG}&format=pdf&granularity=month`);
    expect(res.statusCode, res.body.slice(0, 200)).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-portfolio-platform-20261013.pdf"',
    );
    expect(res.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
    const input = { scope: 'organization', organizationId: ORG_ID };
    expect(h.service.overview.mock.calls[0]?.slice(1)).toEqual([input, { granularity: 'month' }]);
    expect(h.service.projects.mock.calls[0]?.slice(1)).toEqual([
      input,
      { sort: 'gate', limit: 50 },
    ]);
    const [overview, rows, options] = pdf.calls[0] as [unknown, unknown, Record<string, unknown>];
    expect(overview).toEqual(sampleOverview('organization'));
    expect(rows).toEqual(sampleRows());
    expect(options).toEqual({
      generatedBy: 'Ann Example',
      serverVersion: '0.8.0',
      deadline: expect.any(Number),
      // R4: every project with a vulnerable release, from the full stream.
      vulnerable: [sampleRows()[0]],
    });
    // 4E-2 §3: a 60 s budget, as in 4E-1.
    const deadline = options.deadline as number;
    expect(deadline - Date.now()).toBeGreaterThan(50_000);
    expect(deadline - Date.now()).toBeLessThanOrEqual(60_000);
    expect(h.service.exportRows).toHaveBeenCalledTimes(1);
  });

  it('names the all scope "all", and the author by username when there is no display name', async () => {
    const h = harness(
      { overview: vi.fn(async () => sampleOverview('all')) },
      { displayName: '  ' },
    );
    app = h.app;
    const res = await exportOf('scope=all&format=pdf');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-portfolio-all-20261013.pdf"',
    );
    expect((pdf.calls[0]?.[2] as { generatedBy: string }).generatedBy).toBe('user-u1');
  });

  it('answers 503 PORTFOLIO_TIMEOUT when the PDF outruns its budget, and frees the slot', async () => {
    const h = harness();
    app = h.app;
    pdf.timeout = true;
    const late = await exportOf(`${ORG}&format=pdf`);
    expect(late.statusCode).toBe(503);
    expect(late.json()).toMatchObject({ code: 'PORTFOLIO_TIMEOUT' });
    expect(h.logged).toContainEqual(['warn', 'portfolio PDF render timed out']);
    pdf.timeout = false;
    expect((await exportOf(`${ORG}&format=pdf`)).statusCode).toBe(200);
  });

  it('runs one export per user at a time (429 RATE_LIMITED), and frees it when it ends or is dropped', async () => {
    const first = deferred();
    const h = harness();
    h.service.exportRows.mockImplementationOnce(rowsAfter(first.promise));
    app = h.app;
    const running = exportOf('scope=all&format=csv');
    await vi.waitFor(() => expect(h.service.exportRows).toHaveBeenCalledTimes(1));
    const second = await exportOf(`${ORG}&format=pdf`);
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ code: 'RATE_LIMITED' });
    // Another user is not held up.
    expect((await exportOf('scope=all&format=csv', { 'x-user': 'u2' })).statusCode).toBe(200);
    first.resolve();
    expect((await running).statusCode).toBe(200);
    expect((await exportOf('scope=all&format=csv')).statusCode).toBe(200);

    // A dropped connection frees the slot too (Review Focus 4).
    const dropped = deferred();
    h.service.exportRows.mockImplementationOnce(rowsAfter(dropped.promise));
    const abort = new AbortController();
    const aborted = app.inject({
      url: '/portfolio/export?scope=all&format=csv',
      signal: abort.signal,
    });
    await vi.waitFor(() => expect(h.service.exportRows).toHaveBeenCalledTimes(4));
    expect((await exportOf('scope=all&format=csv')).statusCode).toBe(429);
    dropped.resolve();
    abort.abort();
    await aborted.catch(() => undefined);
    await vi.waitFor(async () =>
      expect((await exportOf('scope=all&format=csv')).statusCode).toBe(200),
    );
  });

  it('frees the slot when the client goes away while the rows are computed (a real socket)', async () => {
    const computed = deferred();
    const h = harness();
    h.service.exportRows.mockImplementationOnce(async function* () {
      await new Promise((r) => setTimeout(r, 300));
      computed.resolve();
      yield* sampleRows();
    });
    app = h.app;
    const url = `${await listening(app)}/portfolio/export?scope=all&format=csv`;
    await dropAfter(url, 100);
    // The dropped export's handler has gone on past its rows.
    await computed.promise;
    await new Promise((r) => setTimeout(r, 50));
    expect(await statusOf(url)).toBe(200);
    expect(h.service.exportRows).toHaveBeenCalledTimes(2);
  });

  it('keeps the slot while a dropped PDF export still renders, and frees it after (a real socket)', async () => {
    const render = deferred();
    pdf.hold = render.promise;
    const h = harness();
    app = h.app;
    const url = `${await listening(app)}/portfolio/export?${ORG}&format=pdf`;
    // The client goes away during the render.
    await dropAfter(url, 200);
    expect(pdf.calls).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 50));
    // The render still runs: the user's next export waits for it.
    expect(await statusOf(url)).toBe(429);
    pdf.hold = undefined;
    render.resolve();
    // Two real renders come first (the held one, then this request's own), about half a second
    // each on a loaded CI runner: waitFor's default 1 s is too short (CI after 0.9.0).
    await vi.waitFor(async () => expect(await statusOf(url)).toBe(200), {
      timeout: 15_000,
      interval: 50,
    });
  });

  it('frees the slot when the PDF data is refused', async () => {
    const h = harness();
    h.service.overview.mockRejectedValueOnce(problem(404, 'NOT_FOUND', 'Organization not found'));
    app = h.app;
    expect((await exportOf(`${ORG}&format=pdf`)).statusCode).toBe(404);
    expect((await exportOf(`${ORG}&format=pdf`)).statusCode).toBe(200);
  });
});
