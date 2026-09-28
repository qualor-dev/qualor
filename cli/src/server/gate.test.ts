import net from 'node:net';
import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { silentLogger } from '../log';
import {
  describeGate,
  gateExitCode,
  MAX_PRINTED_CONDITIONS,
  MAX_PRINTED_WARNINGS,
  waitForAnalysis,
  type AnalysisStatus,
} from './gate';

const serve = useTestServers();
const ID = '0192a4c6-1c2e-7a3b-9f00-0000000000aa';
const ep = (url: string, timeoutMs = 5_000) => ({ url, token: 'qlr_prj_secret', timeoutMs });

function analysis(o: Partial<AnalysisStatus> & Pick<AnalysisStatus, 'status'>): AnalysisStatus {
  return { id: ID, gateStatus: null, gateResult: null, error: null, ...o };
}

/** A fake clock: `wait` advances it instead of sleeping. */
function clock() {
  let t = 0;
  const waits: number[] = [];
  return {
    now: () => t,
    wait: (ms: number) => {
      waits.push(ms);
      t += ms;
      return Promise.resolve();
    },
    waits,
  };
}

describe('waitForAnalysis', () => {
  it('polls with exponential backoff (1 s → 10 s), honouring Retry-After, until the analysis finishes', async () => {
    const answers: [number, unknown, Record<string, string>?][] = [
      [200, analysis({ status: 'queued' }), { 'retry-after': '3' }],
      [200, analysis({ status: 'processing' })],
      [503, { code: 'CONCURRENCY_CONFLICT' }],
      [200, analysis({ status: 'processing' })],
      [200, analysis({ status: 'processing' })],
      [200, analysis({ status: 'succeeded', gateStatus: 'passed' })],
    ];
    const { url, requests } = await serve((_req, res) => {
      const [status, body, headers] = answers.shift() ?? [500, {}];
      json(res, status, body, headers);
    });
    const c = clock();
    const done = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 300_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    });
    expect(done.gateStatus).toBe('passed');
    expect(c.waits).toEqual([3_000, 2_000, 4_000, 8_000, 10_000]);
    expect(requests.map((r) => r.url)).toEqual(
      Array.from({ length: 6 }, () => `/api/v0/analyses/${ID}`),
    );
    expect(requests[0]?.headers.authorization).toBe('Bearer qlr_prj_secret');
  });

  it('lets a longer Retry-After on a 5xx win too, capped at 10 s', async () => {
    const answers: [number, unknown, Record<string, string>?][] = [
      [503, { code: 'UNAVAILABLE' }, { 'retry-after': '7' }],
      [502, {}, { 'retry-after': '3600' }],
      [200, analysis({ status: 'succeeded', gateStatus: 'failed' })],
    ];
    const { url } = await serve((_req, res) => {
      const [status, body, headers] = answers.shift() ?? [500, {}];
      json(res, status, body, headers);
    });
    const c = clock();
    const done = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 300_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    });
    expect(done.gateStatus).toBe('failed');
    expect(c.waits).toEqual([7_000, 10_000]);
  });

  it('gives up with exit 4 at gate.timeoutSeconds, naming the analysis and its state', async () => {
    const { url } = await serve((_req, res) => json(res, 200, analysis({ status: 'queued' })));
    const c = clock();
    const err: unknown = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 10_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
    expect((err as Error).message).toContain(`analysis ${ID} is still queued`);
    expect(c.waits.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(10_000);
  });

  it('shortens the last pause to poll once more at the deadline', async () => {
    let polls = 0;
    const { url } = await serve((_req, res) => {
      polls += 1;
      json(res, 200, analysis(polls < 5 ? { status: 'processing' } : { status: 'succeeded' }));
    });
    const c = clock();
    const done = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 10_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    });
    expect(done.status).toBe('succeeded');
    expect(c.waits).toEqual([1_000, 2_000, 4_000, 3_000]);
  });

  it('retries a 429 after its Retry-After (ruling V10)', async () => {
    const answers: [number, unknown, Record<string, string>?][] = [
      [429, { code: 'RATE_LIMITED' }, { 'retry-after': '5' }],
      [200, analysis({ status: 'succeeded', gateStatus: 'passed' })],
    ];
    const { url, requests } = await serve((_req, res) => {
      const [status, body, headers] = answers.shift() ?? [500, {}];
      json(res, status, body, headers);
    });
    const c = clock();
    const done = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 60_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    });
    expect(done.gateStatus).toBe('passed');
    expect(c.waits).toEqual([5_000]);
    expect(requests).toHaveLength(2);
  });

  it('retries a 408 until the deadline, then exits 4 with the state unknown (ruling V10)', async () => {
    const { url, requests } = await serve((_req, res) =>
      problem(res, 408, 'REQUEST_TIMEOUT', 'proxy \u001b]0;x\u0007timed out'),
    );
    const c = clock();
    const err: unknown = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 20_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
    expect(c.waits).toEqual([1_000, 2_000, 4_000, 8_000, 5_000]);
    expect(requests).toHaveLength(6);
    const message = (err as Error).message;
    expect(message).toContain(`the state of analysis ${ID} is unknown`);
    expect(message).toContain('last error: 408 REQUEST_TIMEOUT: proxy timed out');
    expect(message).not.toContain('still queued');
    // eslint-disable-next-line no-control-regex -- asserting their absence
    expect(message).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
  });

  it('retries an unreachable server until the deadline', async () => {
    const { url, server } = await serve((_req, res) => json(res, 200, {}));
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const c = clock();
    const err: unknown = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 20_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
    expect(c.waits.length).toBeGreaterThan(2);
    expect((err as Error).message).toContain(`the state of analysis ${ID} is unknown`);
    expect((err as Error).message).toContain('last error: cannot reach');
  });

  it(
    'never outlives gate.timeoutSeconds by much when the server accepts and never answers',
    { timeout: 20_000 },
    async () => {
      const sockets: net.Socket[] = [];
      const hung = net.createServer((s) => sockets.push(s));
      await new Promise<void>((resolve) => hung.listen(0, '127.0.0.1', resolve));
      const { port } = hung.address() as net.AddressInfo;
      try {
        const started = Date.now();
        // server.timeoutSeconds is a minute, gate.timeoutSeconds 1.5 s: the gate deadline wins.
        const err: unknown = await waitForAnalysis(ep(`http://127.0.0.1:${port}`, 60_000), ID, {
          timeoutMs: 1_500,
          log: silentLogger,
        }).catch((e: unknown) => e);
        expect(err).toMatchObject({ exitCode: 4 });
        expect((err as Error).message).toContain('not available after');
        expect(Date.now() - started).toBeLessThan(5_000);
      } finally {
        for (const s of sockets) s.destroy();
        await new Promise<void>((resolve) => hung.close(() => resolve()));
      }
    },
  );

  it.each([
    [401, 'UNAUTHENTICATED', 5],
    [403, 'FORBIDDEN', 5],
    [404, 'NOT_FOUND', 4],
    [409, 'CONFLICT', 4],
    [410, 'GONE', 4],
  ])('stops at once on %i %s (exit %i)', async (status, code, exitCode) => {
    const { url } = await serve((_req, res) => problem(res, status, code));
    const c = clock();
    const err: unknown = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 60_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode });
    expect((err as Error).message).not.toContain('qlr_prj_secret');
    expect(c.waits).toEqual([]);
  });

  it('exits 4 on a status body it cannot read', async () => {
    const { url } = await serve((_req, res) => json(res, 200, { id: ID, status: 'exploded' }));
    const c = clock();
    const err: unknown = await waitForAnalysis(ep(url), ID, {
      timeoutMs: 60_000,
      log: silentLogger,
      now: c.now,
      wait: c.wait,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
    expect((err as Error).message).toContain('invalid analysis status');
  });
});

describe('gateExitCode (config.md §7)', () => {
  it.each([
    ['succeeded', 'passed', true, 0],
    ['succeeded', 'none', true, 0],
    ['succeeded', null, true, 0],
    ['succeeded', 'failed', false, 1],
    ['succeeded', 'error', true, 1],
    ['succeeded', 'error', false, 0],
    ['failed', 'error', true, 1],
    ['failed', null, false, 0],
    ['failed', null, true, 1],
  ] as const)(
    '%s analysis with gate %s and failOnError %s exits %i',
    (status, gateStatus, failOnError, code) => {
      expect(gateExitCode(analysis({ status, gateStatus }), failOnError)).toBe(code);
    },
  );
});

describe('describeGate', () => {
  it('lists the conditions that did not pass and the warnings', () => {
    expect(
      describeGate(
        analysis({
          status: 'succeeded',
          gateStatus: 'failed',
          gateResult: {
            gate: { name: 'Qualor way' },
            conditions: [
              { metric: 'new_issues', operator: 'gt', threshold: 0, value: 2, status: 'failed' },
              {
                metric: 'new_coverage',
                operator: 'lt',
                threshold: 80,
                value: 91,
                status: 'passed',
              },
              {
                metric: 'new_duplicated_lines_density',
                operator: 'gt',
                threshold: 3,
                value: null,
                status: 'no_value',
              },
            ],
            warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
          },
        }),
      ),
    ).toEqual([
      'quality gate "Qualor way": failed',
      '  new_issues > 0: 2 (failed)',
      '  new_duplicated_lines_density > 3: no value (no_value)',
      '  warning: NEW_CODE_DEFINITION_FALLBACK',
    ]);
    expect(
      describeGate(
        analysis({ status: 'failed', error: { code: 'REPORT_INVALID', message: 'files.0.path' } }),
      ),
    ).toEqual([`analysis ${ID} failed on the server: REPORT_INVALID files.0.path`]);
  });

  it('prints server text without escape sequences or control characters, and bounded', () => {
    const lines = describeGate(
      analysis({
        status: 'succeeded',
        gateStatus: 'failed',
        gateResult: {
          gate: { name: 'Evil\u001b[2J\u001b[31m gate\r\nfake: passed' },
          conditions: Array.from({ length: 50 }, (_, i) => ({
            metric: `m${i}\u0007\u001b]0;title\u0007`,
            operator: 'gt\n',
            threshold: 0,
            value: 1,
            status: 'failed\u001b[0m',
          })),
          warnings: [
            'W\u001b[1mX\u0000Y',
            'x'.repeat(10_000),
            ...Array.from({ length: 40 }, (_, i) => `W${i}`),
          ],
        },
      }),
    );
    for (const line of lines) {
      // eslint-disable-next-line no-control-regex -- asserting their absence
      expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
      expect(line.length).toBeLessThanOrEqual(600);
    }
    expect(lines[0]).toBe('quality gate "Evil gate fake: passed": failed');
    expect(lines).toContain(`  ... and ${50 - MAX_PRINTED_CONDITIONS} more conditions`);
    expect(lines).toContain(`  ... and ${42 - MAX_PRINTED_WARNINGS} more warnings`);
    expect(lines.length).toBeLessThanOrEqual(1 + MAX_PRINTED_CONDITIONS + MAX_PRINTED_WARNINGS + 2);
    const failed = describeGate(
      analysis({
        id: `${ID}\u001b[2J`,
        status: 'failed',
        error: { code: 'BOOM\u001b[31m', message: `line1\nline2${'y'.repeat(5_000)}` },
      }),
    );
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatch(/^analysis [0-9a-f-]+ failed on the server: BOOM line1 line2y+$/);
    expect(failed[0]?.length).toBeLessThanOrEqual(600);
  });
});
