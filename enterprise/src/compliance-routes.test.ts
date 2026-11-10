// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createHash } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';
import type {
  ComplianceReportView,
  ComplianceSource,
  PluginCompliance,
  PluginContext,
  PluginJob,
} from '@qualor/server/plugin-contract';
import { complianceJobs, complianceRoutes } from './compliance-routes';
import type * as Pdf from './compliance/pdf';
import { RenderTimeoutError } from './pdf/layout';
import { sampleReport } from './compliance/test-report';

/** The PDF renderer, real unless a test makes it time out or holds it. */
const pdf = vi.hoisted(() => ({
  timeout: false,
  options: [] as unknown[],
  hold: undefined as Promise<unknown> | undefined,
}));
vi.mock('./compliance/pdf', async (importOriginal) => {
  const real = await importOriginal<typeof Pdf>();
  return {
    ...real,
    renderPdf: async (...args: Parameters<typeof real.renderPdf>) => {
      pdf.options.push(args[1]);
      await pdf.hold;
      if (pdf.timeout) throw new RenderTimeoutError();
      return real.renderPdf(...args);
    },
  };
});

const REPORT_ID = '0b6f1c1e-5d3a-4a8e-9f2b-7c1d2e3f4a5b';
const ORG_ID = '7a9e3c1d-2b4f-4c6e-8a0b-1c2d3e4f5a6b';
const PROJECT_ID = '1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9';

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
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function view(over: Partial<ComplianceReportView> = {}): ComplianceReportView {
  return {
    id: REPORT_ID,
    scope: 'project',
    organization: { id: ORG_ID, key: 'acme', name: 'Acme' },
    project: { id: PROJECT_ID, key: 'alpha', name: 'Alpha' },
    branch: { id: '2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f', name: 'main' },
    status: 'ready',
    createdBy: 'Ann',
    createdAt: '2026-10-12T10:00:00.000Z',
    completedAt: '2026-10-12T10:00:01.000Z',
    standards: [{ id: 's', version: '1', sourceSha256: '0'.repeat(64) }],
    sha256: 'f'.repeat(64),
    sizeBytes: 100,
    error: null,
    summary: null,
    canDelete: false,
    ...over,
  };
}

/** The canonical bytes of the sample report, generated on 2026-10-12. */
function canonical(): Buffer {
  return Buffer.from(
    JSON.stringify({ ...sampleReport(), generatedAt: '2026-10-12T10:00:00.000Z' }),
    'utf8',
  );
}

function source(): ComplianceSource {
  return {
    generatedAt: '2026-10-12T10:00:00.000Z',
    createdBy: 'Ann',
    scope: {
      kind: 'project',
      organization: { id: ORG_ID, key: 'acme', name: 'Acme' },
      project: { id: PROJECT_ID, key: 'alpha', name: 'Alpha' },
      branch: null,
    },
    projects: [],
    groups: [],
    findings: [],
    triage: [],
    datasets: { vulnerabilityDatabase: null, kev: null, epss: null },
  };
}

type Logged = [level: string, ...args: unknown[]];

/** The routes and jobs over a fake context: every caller is `x-user` (u1 by default). */
type FakeCompliance = { [K in keyof PluginCompliance]: Mock<PluginCompliance[K]> };

function harness(compliance: Partial<FakeCompliance> = {}) {
  const logged: Logged[] = [];
  const service: FakeCompliance = {
    create: vi.fn(async () => view({ status: 'pending', sha256: null, completedAt: null })),
    list: vi.fn(async () => ({ items: [view()], nextCursor: null })),
    get: vi.fn(async () => view()),
    download: vi.fn(async () => ({ view: view(), canonical: canonical() })),
    remove: vi.fn(async () => undefined),
    collect: vi.fn(async () => source()),
    complete: vi.fn(async () => true),
    fail: vi.fn(async () => true),
    housekeeping: vi.fn(async () => ({ deleted: 0, failed: 0 })),
    ...compliance,
  };
  const enqueue = vi.fn(async () => 'job-1');
  const ctx = {
    serverVersion: '0.8.0',
    logger: {
      debug: (...args: unknown[]) => logged.push(['debug', ...args]),
      info: (...args: unknown[]) => logged.push(['info', ...args]),
      warn: (...args: unknown[]) => logged.push(['warn', ...args]),
      error: (...args: unknown[]) => logged.push(['error', ...args]),
    },
    access: {
      requireUser: (request: { headers: Record<string, unknown> }) => ({
        user: { id: String(request.headers['x-user'] ?? 'u1'), isInstanceAdmin: false },
      }),
      problem: (status: number, code: string, title: string) =>
        Object.assign(new Error(title), { statusCode: status, code }),
    },
    compliance: service,
    enqueue,
  } as unknown as PluginContext;
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  void app.register(complianceRoutes(ctx));
  const jobs = complianceJobs(ctx);
  const run = (queue: string, payload: unknown) =>
    jobs[queue]!({
      id: 'j1',
      queue,
      payload,
      attempts: 1,
      signal: new AbortController().signal,
    } satisfies PluginJob);
  return { app, service, enqueue, logged, run };
}

let app: FastifyInstance | undefined;
afterEach(async () => {
  pdf.timeout = false;
  pdf.options.length = 0;
  pdf.hold = undefined;
  await app?.close();
  app = undefined;
});

describe('POST /compliance/reports (4E-1 §3)', () => {
  it('refuses a body with both an organisation and a project', async () => {
    const h = harness();
    app = h.app;
    const res = await app.inject({
      method: 'POST',
      url: '/compliance/reports',
      payload: { organizationId: ORG_ID, projectId: PROJECT_ID },
    });
    expect(res.statusCode).toBe(400);
    expect(h.service.create).not.toHaveBeenCalled();
  });

  it('refuses ids that are not uuids before the service sees them', async () => {
    const h = harness();
    app = h.app;
    for (const payload of [
      { organizationId: 'nope' },
      { projectId: 'nope' },
      { projectId: PROJECT_ID, branchId: 'nope' },
      {},
    ]) {
      const res = await app.inject({ method: 'POST', url: '/compliance/reports', payload });
      expect(res.statusCode, JSON.stringify(payload)).toBe(400);
    }
    expect(h.service.create).not.toHaveBeenCalled();
  });

  it('creates the report with every standard and queues one build at a time (202)', async () => {
    const h = harness();
    app = h.app;
    const res = await app.inject({
      method: 'POST',
      url: '/compliance/reports',
      payload: { organizationId: ORG_ID },
    });
    expect(res.statusCode).toBe(202);
    expect(res.json()).toMatchObject({ id: REPORT_ID, status: 'pending' });
    const [, input, standards] = h.service.create.mock.calls[0] as unknown as [
      unknown,
      unknown,
      { id: string }[],
    ];
    expect(input).toEqual({ organizationId: ORG_ID });
    expect(standards.map((s) => s.id)).toEqual([
      'owasp-top10-2021',
      'owasp-top10-2025',
      'cwe-top25-2025',
      'asvs-4.0.3',
      'pci-dss-4.0.1-6.2.4',
    ]);
    expect(h.enqueue).toHaveBeenCalledWith(
      'ee.compliance.build',
      { reportId: REPORT_ID },
      { concurrencyKey: 'ee.compliance.build', maxAttempts: 1 },
    );
  });

  it('fails the new row when the build cannot be queued, so the scope is not blocked', async () => {
    const h = harness();
    h.enqueue.mockRejectedValueOnce(new Error('the database went away'));
    app = h.app;
    const res = await app.inject({
      method: 'POST',
      url: '/compliance/reports',
      payload: { projectId: PROJECT_ID },
    });
    expect(res.statusCode).toBe(500);
    expect(h.service.fail).toHaveBeenCalledWith(REPORT_ID, 'the build could not be queued');
  });
});

describe('GET /compliance/reports (4E-1 §3)', () => {
  it('needs exactly one of organizationId and projectId, and a limit of 1 to 100', async () => {
    const h = harness();
    app = h.app;
    for (const query of [
      '',
      `?organizationId=${ORG_ID}&projectId=${PROJECT_ID}`,
      `?organizationId=${ORG_ID}&limit=101`,
      `?organizationId=${ORG_ID}&limit=0`,
      `?organizationId=${ORG_ID}&cursor=nope`,
      '?organizationId=nope',
    ]) {
      const res = await app.inject({ url: `/compliance/reports${query}` });
      expect(res.statusCode, query).toBe(400);
    }
    expect(h.service.list).not.toHaveBeenCalled();
  });

  it('lists a scope with the default limit of 20, or a cursor', async () => {
    const h = harness();
    app = h.app;
    const res = await app.inject({ url: `/compliance/reports?projectId=${PROJECT_ID}` });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ items: [{ id: REPORT_ID }], nextCursor: null });
    await app.inject({
      url: `/compliance/reports?organizationId=${ORG_ID}&limit=5&cursor=${REPORT_ID}`,
    });
    expect(h.service.list.mock.calls.map((c) => [c[1], c[2]])).toEqual([
      [{ projectId: PROJECT_ID }, { limit: 20 }],
      [{ organizationId: ORG_ID }, { limit: 5, cursor: REPORT_ID }],
    ]);
  });
});

describe('GET and DELETE /compliance/reports/:id', () => {
  it('reads and deletes a report by its uuid, and refuses another id', async () => {
    const h = harness();
    app = h.app;
    expect((await app.inject({ url: `/compliance/reports/${REPORT_ID}` })).json()).toMatchObject({
      id: REPORT_ID,
    });
    const del = await app.inject({ method: 'DELETE', url: `/compliance/reports/${REPORT_ID}` });
    expect(del.statusCode).toBe(204);
    expect(h.service.remove.mock.calls[0]?.[1]).toBe(REPORT_ID);
    expect((await app.inject({ url: '/compliance/reports/nope' })).statusCode).toBe(400);
    expect(
      (await app.inject({ method: 'DELETE', url: '/compliance/reports/nope' })).statusCode,
    ).toBe(400);
    expect(h.service.get).toHaveBeenCalledTimes(1);
  });
});

describe('GET /compliance/reports/:id/download (4E-1 §2.5)', () => {
  const download = (format: string, headers: Record<string, string> = {}) =>
    app!.inject({ url: `/compliance/reports/${REPORT_ID}/download?format=${format}`, headers });

  it('sends the canonical JSON as it is stored, not cached', async () => {
    const h = harness();
    app = h.app;
    const res = await download('json');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-compliance-alpha-20261012-0b6f1c1e.json"',
    );
    expect(res.rawPayload.equals(canonical())).toBe(true);
    expect(h.service.download.mock.calls[0]?.slice(1)).toEqual([REPORT_ID, 'json']);
  });

  it('streams the CSV with its BOM and a file name of the project key and the report date', async () => {
    app = harness().app;
    const res = await download('csv');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-disposition']).toMatch(
      /^attachment; filename="qualor-compliance-alpha-20261012-[0-9a-f]{8}\.csv"$/,
    );
    expect(res.rawPayload.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(true);
    // The header, two findings and one triage row.
    expect(res.body.split('\r\n').filter((l) => l !== '')).toHaveLength(4);
  });

  it('names an organisation report by the organisation key, sanitised', async () => {
    const h = harness({
      download: vi.fn(async () => ({
        view: view({
          scope: 'organization',
          organization: { id: ORG_ID, key: 'Acme_Corp.EU', name: 'Acme' },
          project: null,
          branch: null,
        }),
        canonical: canonical(),
      })),
    });
    app = h.app;
    expect((await download('json')).headers['content-disposition']).toBe(
      'attachment; filename="qualor-compliance-acme-corp-eu-20261012-0b6f1c1e.json"',
    );
  });

  it('renders the PDF with the stored sha256, and answers 503 REPORT_RENDER_TIMEOUT past its budget', async () => {
    const h = harness();
    app = h.app;
    const res = await download('pdf');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-compliance-alpha-20261012-0b6f1c1e.pdf"',
    );
    expect(res.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
    // Ruling R9: the cover's SHA-256 is the stored one, not a re-serialisation; a 60 s budget.
    expect(pdf.options).toEqual([{ deadline: expect.any(Number), sha256: 'f'.repeat(64) }]);
    const { deadline } = pdf.options[0] as { deadline: number };
    expect(deadline - Date.now()).toBeGreaterThan(50_000);
    expect(deadline - Date.now()).toBeLessThanOrEqual(60_000);
    pdf.timeout = true;
    const late = await download('pdf');
    expect(late.statusCode).toBe(503);
    expect(late.json()).toMatchObject({ code: 'REPORT_RENDER_TIMEOUT' });
    // The problem is no attachment.
    expect(late.headers['content-disposition']).toBeUndefined();
    expect(h.logged).toContainEqual([
      'warn',
      { reportId: REPORT_ID },
      'compliance report PDF render timed out',
    ]);
    // The slot is free again.
    pdf.timeout = false;
    expect((await download('pdf')).statusCode).toBe(200);
  });

  it('refuses another format', async () => {
    const h = harness();
    app = h.app;
    expect((await download('xlsx')).statusCode).toBe(400);
    expect(h.service.download).not.toHaveBeenCalled();
  });

  it('runs one download per user at a time (429 RATE_LIMITED), and frees it when it ends or is dropped', async () => {
    const first = deferred<{ view: ComplianceReportView; canonical: Buffer }>();
    const h = harness();
    h.service.download.mockImplementationOnce(() => first.promise);
    app = h.app;
    const running = download('csv');
    await vi.waitFor(() => expect(h.service.download).toHaveBeenCalledTimes(1));
    const second = await download('json');
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ code: 'RATE_LIMITED' });
    // Another user is not held up.
    expect((await download('json', { 'x-user': 'u2' })).statusCode).toBe(200);
    first.resolve({ view: view(), canonical: canonical() });
    expect((await running).statusCode).toBe(200);
    expect((await download('json')).statusCode).toBe(200);

    // A dropped connection frees the slot too.
    const dropped = deferred<{ view: ComplianceReportView; canonical: Buffer }>();
    h.service.download.mockImplementationOnce(() => dropped.promise);
    const abort = new AbortController();
    const aborted = app.inject({
      url: `/compliance/reports/${REPORT_ID}/download?format=csv`,
      signal: abort.signal,
    });
    await vi.waitFor(() => expect(h.service.download).toHaveBeenCalledTimes(4));
    expect((await download('json')).statusCode).toBe(429);
    dropped.resolve({ view: view(), canonical: canonical() });
    abort.abort();
    await aborted.catch(() => undefined);
    await vi.waitFor(async () => expect((await download('json')).statusCode).toBe(200));
  });

  it('frees the slot when the client goes away while the report is read (a real socket)', async () => {
    const read = deferred<undefined>();
    const h = harness();
    h.service.download.mockImplementationOnce(async () => {
      await new Promise((r) => setTimeout(r, 300));
      read.resolve(undefined);
      return { view: view(), canonical: canonical() };
    });
    app = h.app;
    const url = `${await listening(app)}/compliance/reports/${REPORT_ID}/download?format=csv`;
    await dropAfter(url, 100);
    // The dropped download's handler has gone on past the read.
    await read.promise;
    await new Promise((r) => setTimeout(r, 50));
    expect(await statusOf(url)).toBe(200);
    expect(h.service.download).toHaveBeenCalledTimes(2);
  });

  it('keeps the slot while a dropped PDF download still renders, and frees it after (a real socket)', async () => {
    const render = deferred<undefined>();
    pdf.hold = render.promise;
    const h = harness();
    app = h.app;
    const url = `${await listening(app)}/compliance/reports/${REPORT_ID}/download?format=pdf`;
    // The client goes away during the render.
    await dropAfter(url, 200);
    expect(pdf.options).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 50));
    // The render still runs: the user's next download waits for it.
    expect(await statusOf(url)).toBe(429);
    pdf.hold = undefined;
    render.resolve(undefined);
    // Each try is a real request; a busy CI runner needs more than waitFor's default 1 s.
    await vi.waitFor(async () => expect(await statusOf(url)).toBe(200), {
      timeout: 10_000,
      interval: 100,
    });
  });

  it('frees the slot when the service refuses the download', async () => {
    const h = harness();
    h.service.download.mockRejectedValueOnce(
      Object.assign(new Error('The report is not ready'), {
        statusCode: 409,
        code: 'REPORT_NOT_READY',
      }),
    );
    app = h.app;
    expect((await download('json')).statusCode).toBe(409);
    expect((await download('json')).statusCode).toBe(200);
  });
});

describe('the build job ee.compliance.build (4E-1 §2.4)', () => {
  it('assembles the collected source and completes the row with the sha256 of its canonical bytes', async () => {
    const h = harness();
    await h.run('ee.compliance.build', { reportId: REPORT_ID });
    expect(h.service.collect).toHaveBeenCalledWith(REPORT_ID, {
      limit: 50_000,
      signal: expect.any(AbortSignal),
    });
    const [id, result] = h.service.complete.mock.calls[0] as unknown as [
      string,
      {
        canonical: Buffer;
        sha256: string;
        summary: { findings: { total: number } };
        standards: unknown;
      },
    ];
    expect(id).toBe(REPORT_ID);
    expect(result.sha256).toBe(createHash('sha256').update(result.canonical).digest('hex'));
    const json = JSON.parse(result.canonical.toString('utf8')) as Record<string, unknown>;
    expect(json).toMatchObject({
      id: REPORT_ID,
      generatedBy: 'Ann',
      server: { version: '0.8.0' },
    });
    expect(result.summary.findings.total).toBe(0);
    // The standards the build used, as the JSON names them (the row and the JSON agree).
    const standards = (
      json.standards as { id: string; version: string; sourceSha256: string }[]
    ).map((s) => ({ id: s.id, version: s.version, sourceSha256: s.sourceSha256 }));
    expect(standards.length).toBeGreaterThan(0);
    expect(result.standards).toEqual(standards);
    expect(h.service.fail).not.toHaveBeenCalled();
  });

  it('fails the row with a known build failure as it is', async () => {
    const h = harness({
      collect: vi.fn(async () => {
        throw Object.assign(new Error('The report could not be built'), {
          code: 'REPORT_BUILD_FAILED',
          detail: 'too many projects for one report',
        });
      }),
    });
    await h.run('ee.compliance.build', { reportId: REPORT_ID });
    expect(h.service.fail).toHaveBeenCalledWith(REPORT_ID, 'too many projects for one report');
    expect(h.service.complete).not.toHaveBeenCalled();
    expect(h.logged).toContainEqual([
      'warn',
      { reportId: REPORT_ID, err: 'Error', code: 'REPORT_BUILD_FAILED' },
      'compliance report failed',
    ]);
  });

  it('never stores SQL or parameters: another failure is "the report could not be built"', async () => {
    const h = harness({
      collect: vi.fn(async () => {
        // As drizzle wraps a driver error: the query and its parameters on the outer error, the
        // SQLSTATE on its cause.
        throw Object.assign(new Error('Failed query: SELECT * FROM secret_table WHERE id = $1'), {
          query: 'SELECT * FROM secret_table WHERE id = $1',
          params: ['hunter2'],
          cause: Object.assign(new Error('relation "secret_table" does not exist'), {
            code: '42P01',
          }),
        });
      }),
    });
    await h.run('ee.compliance.build', { reportId: REPORT_ID });
    expect(h.service.fail).toHaveBeenCalledWith(REPORT_ID, 'the report could not be built');
    expect(JSON.stringify(h.logged)).not.toMatch(/secret_table|hunter2/);
    // The SQLSTATE is logged, so an operator can tell one failure from another.
    expect(h.logged).toContainEqual([
      'warn',
      { reportId: REPORT_ID, err: 'Error', code: '42P01' },
      'compliance report failed',
    ]);
  });

  it('does not throw when the row is gone, or when failing it fails', async () => {
    const h = harness({
      complete: vi.fn(async () => false),
    });
    await expect(h.run('ee.compliance.build', { reportId: REPORT_ID })).resolves.toBeUndefined();
    expect(h.service.fail).not.toHaveBeenCalled();
    const broken = harness({
      collect: vi.fn(async () => {
        throw new Error('boom');
      }),
      fail: vi.fn(async () => {
        throw new Error('the database went away');
      }),
    });
    await expect(
      broken.run('ee.compliance.build', { reportId: REPORT_ID }),
    ).resolves.toBeUndefined();
  });

  it('refuses a payload that is not { reportId: uuid }', async () => {
    const h = harness();
    await expect(h.run('ee.compliance.build', { reportId: 'nope' })).rejects.toThrow();
    await expect(h.run('ee.compliance.build', { reportId: REPORT_ID, x: 1 })).rejects.toThrow();
    expect(h.service.collect).not.toHaveBeenCalled();
  });
});

describe('the housekeeping job ee.compliance.housekeeping (4E-1 §2.4 step 5)', () => {
  it('runs the core housekeeping and logs only when it changed something', async () => {
    const h = harness();
    await h.run('ee.compliance.housekeeping', {});
    expect(h.service.housekeeping).toHaveBeenCalledTimes(1);
    expect(h.logged).toEqual([]);
    h.service.housekeeping.mockResolvedValueOnce({ deleted: 2, failed: 1 });
    await h.run('ee.compliance.housekeeping', {});
    expect(h.logged).toEqual([['info', { deleted: 2, failed: 1 }, 'compliance housekeeping']]);
  });
});
