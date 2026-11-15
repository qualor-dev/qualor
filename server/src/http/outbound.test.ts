import { getEventListeners } from 'node:events';
import { createServer } from 'node:http';
import { createServer as createNetServer, type AddressInfo, type Socket } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { withStreamServer } from '../../test/stream-server';
import {
  outboundRequest,
  outboundStream,
  type OutboundRequest,
  type OutboundResult,
  type OutboundStreamLimits,
  type OutboundStreamOptions,
  type OutboundStreamResult,
  type Resolver,
} from './outbound';

/** A loopback server that records the last request's method, body and content-length. */
async function echoServer() {
  let last: { method: string; body: string; length: string | undefined } | null = null;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      last = {
        method: req.method ?? '',
        body: Buffer.concat(chunks).toString('utf8'),
        length: req.headers['content-length'],
      };
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/x`,
    last: () => last,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

it('sends PATCH with its body and content-length', async () => {
  const seen = await echoServer();
  try {
    const result = await outboundRequest(
      {
        url: seen.url,
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: '{"a":1}',
      },
      {
        allowInternalHosts: true,
        timeoutMs: 2_000,
        maxResponseBytes: 1024,
        overflow: 'fail',
        names: { noun: 'test', target: 'test' },
      },
    );
    expect(result.kind).toBe('response');
    expect(seen.last()).toEqual({ method: 'PATCH', body: '{"a":1}', length: '7' });
  } finally {
    await seen.close();
  }
});

it('sends DELETE without a body', async () => {
  const seen = await echoServer();
  try {
    const result = await outboundRequest(
      { url: seen.url, method: 'DELETE', headers: {} },
      {
        allowInternalHosts: true,
        timeoutMs: 2_000,
        maxResponseBytes: 1024,
        overflow: 'fail',
        names: { noun: 'test', target: 'test' },
      },
    );
    expect(result.kind).toBe('response');
    expect(seen.last()).toEqual({ method: 'DELETE', body: '', length: undefined });
  } finally {
    await seen.close();
  }
});

it('calls a host unresolved, not a timeout, when its lookup fails or outlasts the connect deadline', async () => {
  const options = {
    allowInternalHosts: true,
    timeoutMs: 30_000,
    connectTimeoutMs: 100,
    maxResponseBytes: 1024,
    overflow: 'fail' as const,
    names: { noun: 'test', target: 'test' },
  };
  const request = { url: 'https://gitlab-ce/api/v4/user', method: 'GET' as const, headers: {} };
  // A single-label name the resolver keeps retrying: no answer before the connect deadline.
  const slow = await outboundRequest(request, {
    ...options,
    resolve: () => new Promise(() => undefined),
  });
  expect(slow).toMatchObject({
    kind: 'failed',
    cause: 'unresolved',
    unreachable: true,
    reason: 'The test host could not be resolved within 100 ms',
  });
  // EAI_AGAIN (a temporary resolver failure) and ENOTFOUND alike.
  for (const code of ['EAI_AGAIN', 'ENOTFOUND']) {
    const failed = await outboundRequest(request, {
      ...options,
      resolve: () => Promise.reject(Object.assign(new Error(code), { code })),
    });
    expect(failed).toMatchObject({ kind: 'failed', cause: 'unresolved' });
  }
});

const NAMES = { noun: 'test', target: 'test' };

/** The limits of a call; a test changes the ones it is about, and the rest are out of its way. */
const LIMITS: OutboundStreamLimits = {
  firstByteMs: 5_000,
  idleMs: 1_000,
  totalMs: 60_000,
  maxStreamBytes: 1_024,
  maxErrorBytes: 1_024,
};

function streamOptions(
  over: Omit<Partial<OutboundStreamOptions>, 'limits'> & {
    limits?: Partial<OutboundStreamLimits>;
  } = {},
): OutboundStreamOptions {
  const { limits, ...rest } = over;
  return { allowInternalHosts: true, names: NAMES, ...rest, limits: { ...LIMITS, ...limits } };
}

const post = (url: string): OutboundRequest => ({
  url,
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{}',
});

const get = (url: string): OutboundRequest => ({ url, method: 'GET', headers: {} });

/** The chunks of a call that streams, as an iterator; any other answer fails the test. */
async function streamed(pending: Promise<OutboundStreamResult>): Promise<AsyncIterator<Buffer>> {
  const result = await pending;
  if (result.kind !== 'stream') throw new Error(`Not a stream: ${JSON.stringify(result)}`);
  return result.chunks[Symbol.asyncIterator]();
}

/** Whether a promise has settled yet; a test moves the timers and looks. */
function track(promise: Promise<unknown>): { settled: boolean } {
  const state = { settled: false };
  void promise.then(
    () => (state.settled = true),
    () => (state.settled = true),
  );
  return state;
}

const chunk = (text: string) => ({ done: false, value: Buffer.from(text) });
const finished = { done: true, value: undefined };

/**
 * Lets the event loop run some turns, so that what a server wrote has been read by its client (the
 * timers may be faked: only immediates are used).
 */
async function reading(): Promise<void> {
  for (let turn = 0; turn < 10; turn += 1)
    await new Promise<void>((resolve) => setImmediate(resolve));
}

/** The timers a call arms, moved by the test; the clock too, so what a call has used is nothing. */
function fakeTimers(): void {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
}

describe('outboundRequest with a buffered body', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const buffered = {
    allowInternalHosts: true,
    timeoutMs: 30_000,
    maxResponseBytes: 1_024,
    overflow: 'fail' as const,
    names: NAMES,
  };

  it('says the answer did not finish when a buffered body outlasts the timeout', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundRequest(get(server.url), buffered);
      const answer = await server.next();
      answer.head(200, { 'content-type': 'text/plain' });
      await answer.write('0123456789');
      await reading();
      await vi.advanceTimersByTimeAsync(30_000);
      const result = await pending;
      expect(result).toMatchObject({ kind: 'failed', cause: 'timeout' });
      const reason = (result as { reason: string }).reason;
      expect(reason).toContain('did not finish within 30 s');
      expect(reason).not.toContain('No response');
      await answer.closed;
    });
  });

  it('says there was no response when no status line arrives in time', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundRequest(get(server.url), buffered);
      const answer = await server.next();
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await pending).toMatchObject({
        kind: 'failed',
        cause: 'timeout',
        reason: 'No response within 30 s',
      });
      await answer.closed;
    });
  });
});

describe('outboundStream', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('streams the body of a 2xx as it arrives, and ends with it', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      expect(answer).toMatchObject({ method: 'POST', body: '{}' });
      answer.head(200, { 'content-type': 'text/event-stream', 'x-request-id': 'r-1' });
      const result = await pending;
      expect(result).toMatchObject({ kind: 'stream', status: 200 });
      if (result.kind !== 'stream') throw new Error('unreachable');
      expect(result.headers['x-request-id']).toBe('r-1');
      const chunks = result.chunks[Symbol.asyncIterator]();
      await answer.write('one');
      expect(await chunks.next()).toEqual(chunk('one'));
      await answer.write('two');
      expect(await chunks.next()).toEqual(chunk('two'));
      await answer.end();
      expect(await chunks.next()).toEqual(finished);
      // Once the body is over, the stream stays over.
      expect(await chunks.next()).toEqual(finished);
      await answer.closed;
    });
  });

  it('the idle timer restarts on each chunk', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { idleMs: 1_000 } }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      for (const piece of ['a', 'b', 'c']) {
        // Every wait is shorter than the limit, and the three together are far longer.
        await vi.advanceTimersByTimeAsync(900);
        await answer.write(piece);
        expect(await chunks.next()).toEqual(chunk(piece));
      }
      const silence = chunks.next().catch((e: unknown) => e);
      const state = track(silence);
      await vi.advanceTimersByTimeAsync(999);
      expect(state.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(await silence).toMatchObject({
        name: 'OutboundStreamError',
        cause: 'timeout',
        timer: 'idle',
        reason: 'No data from test for 1 s',
      });
      await answer.closed;
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('no first byte in time is a timeout', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { firstByteMs: 5_000 } }),
      ).catch((e: unknown) => e);
      const state = track(pending);
      // The request has reached the server, and the server stays silent.
      const answer = await server.next();
      await vi.advanceTimersByTimeAsync(4_999);
      expect(state.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(await pending).toEqual({
        kind: 'failed',
        cause: 'timeout',
        timer: 'first_byte',
        unreachable: true,
        reason: 'No response within 5 s',
        code: null,
      });
      // The request was cut where it was.
      await answer.closed;
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('the status line ends the wait for the first byte: the idle limit takes over from there', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { firstByteMs: 5_000, idleMs: 1_000 } }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      const silence = chunks.next().catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(await silence).toMatchObject({ cause: 'timeout', timer: 'idle' });
      await answer.closed;
    });
  });

  it('the total limit cuts a stream that keeps sending', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { firstByteMs: 5_000, idleMs: 1_000, totalMs: 3_000 } }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      for (const piece of ['a', 'b', 'c']) {
        await vi.advanceTimersByTimeAsync(800);
        await answer.write(piece);
        expect(await chunks.next()).toEqual(chunk(piece));
      }
      // 2 400 ms in: the idle limit would allow 1 000 ms more, the total limit 600.
      const next = chunks.next().catch((e: unknown) => e);
      const state = track(next);
      await vi.advanceTimersByTimeAsync(599);
      expect(state.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(await next).toMatchObject({
        name: 'OutboundStreamError',
        cause: 'timeout',
        timer: 'total',
        reason: 'The answer of test was not complete within 3 s',
      });
      await answer.closed;
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('the total limit runs from the call, so it can end the wait for the status line', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { firstByteMs: 5_000, totalMs: 2_000 } }),
      ).catch((e: unknown) => e);
      const answer = await server.next();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(await pending).toMatchObject({
        kind: 'failed',
        cause: 'timeout',
        timer: 'total',
        unreachable: true,
        reason: 'The answer of test was not complete within 2 s',
      });
      await answer.closed;
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('the 16 MiB raw cap, tried with a small one: more bytes than maxStreamBytes is too_large', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { maxStreamBytes: 10 } }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.write('123456');
      expect(await chunks.next()).toEqual(chunk('123456'));
      // 11 in all: one over.
      await answer.write('78901');
      await expect(chunks.next()).rejects.toMatchObject({
        name: 'OutboundStreamError',
        cause: 'too_large',
        reason: 'The answer of test is larger than 10 bytes',
      });
      // The connection is cut, and the stream is over.
      await answer.closed;
      expect(await chunks.next()).toEqual(finished);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('allows exactly as many raw bytes as maxStreamBytes', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { maxStreamBytes: 10 } }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.write('123456');
      expect(await chunks.next()).toEqual(chunk('123456'));
      await answer.write('7890');
      expect(await chunks.next()).toEqual(chunk('7890'));
      await answer.end();
      expect(await chunks.next()).toEqual(finished);
    });
  });

  it('an abort cuts a stream that is running, and the signal keeps no listener of it', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.write('a');
      expect(await chunks.next()).toEqual(chunk('a'));
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(1);
      const next = chunks.next().catch((e: unknown) => e);
      controller.abort();
      expect(await next).toMatchObject({
        name: 'OutboundStreamError',
        cause: 'aborted',
        reason: 'The request to test was given up',
      });
      await answer.closed;
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      expect(vi.getTimerCount()).toBe(0);
      expect(await chunks.next()).toEqual(finished);
    });
  });

  it('an abort while the answer is awaited is an aborted failure, as the request gives it', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      controller.abort();
      expect(await pending).toMatchObject({
        kind: 'failed',
        cause: 'aborted',
        unreachable: false,
        reason: 'The request to test was given up',
      });
      await answer.closed;
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('a consumer that stops early with return() leaves no timer, listener or socket behind', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.write('a');
      expect(await chunks.next()).toEqual(chunk('a'));
      // The idle and the total timers are running, and the signal is listened to.
      expect(vi.getTimerCount()).toBeGreaterThan(0);
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(1);
      expect(await chunks.return?.()).toEqual(finished);
      expect(vi.getTimerCount()).toBe(0);
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      await answer.closed;
      expect(await chunks.next()).toEqual(finished);
    });
  });

  it('a consumer that stops early with break leaves nothing behind', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      answer.head();
      const result = await pending;
      if (result.kind !== 'stream') throw new Error('Not a stream');
      await answer.write('a');
      for await (const piece of result.chunks) {
        expect(piece.toString()).toBe('a');
        break;
      }
      expect(vi.getTimerCount()).toBe(0);
      await answer.closed;
    });
  });

  it('a consumer that stops before it has read anything leaves nothing behind either', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await chunks.return?.();
      expect(vi.getTimerCount()).toBe(0);
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      await answer.closed;
    });
  });

  it('a stream that is read to its end leaves nothing behind', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.end('the end');
      expect(await chunks.next()).toEqual(chunk('the end'));
      expect(await chunks.next()).toEqual(finished);
      expect(vi.getTimerCount()).toBe(0);
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
    });
  });

  it('a connection lost while streaming is a connection failure', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      answer.head();
      const chunks = await streamed(pending);
      await answer.write('a');
      expect(await chunks.next()).toEqual(chunk('a'));
      const next = chunks.next().catch((e: unknown) => e);
      answer.cut();
      expect(await next).toMatchObject({ name: 'OutboundStreamError', cause: 'connection' });
      expect(vi.getTimerCount()).toBe(0);
      expect(await chunks.next()).toEqual(finished);
    });
  });

  it('a connection that closes before the end of the body is a connection failure, not an end', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      // A body of 10 bytes, of which the server sends 4 and cuts.
      answer.head(200, { 'content-type': 'text/event-stream', 'content-length': '10' });
      const chunks = await streamed(pending);
      await answer.write('abcd');
      answer.cut();
      const seen: string[] = [];
      let failure: unknown = null;
      try {
        for (;;) {
          const step = await chunks.next();
          if (step.done === true) break;
          seen.push(step.value.toString());
        }
      } catch (error) {
        failure = error;
      }
      expect(seen.join('')).toBe('abcd');
      expect(failure).toMatchObject({ cause: 'connection' });
    });
  });

  it('reads the body of a refused answer whole, and closes the connection', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      answer.head(429, { 'content-type': 'application/json', 'retry-after': '7' });
      await answer.write('{"error":');
      await answer.end('{"message":"No."}}');
      const result = await pending;
      expect(result).toMatchObject({ kind: 'response', status: 429 });
      if (result.kind !== 'response') throw new Error('unreachable');
      expect(result.body.toString()).toBe('{"error":{"message":"No."}}');
      expect(result.headers['retry-after']).toBe('7');
      await answer.closed;
    });
  });

  it('gives a 3xx as it is, following nothing', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      answer.head(307, { location: `${server.url}/elsewhere` });
      await answer.end();
      const result = await pending;
      expect(result).toMatchObject({ kind: 'response', status: 307 });
      expect(result.kind === 'response' && result.headers.location).toBe(`${server.url}/elsewhere`);
      expect(server.connections()).toBe(1);
    });
  });

  it('reads a refused answer only to classify it: what is over maxErrorBytes is cut, and the connection closed', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { maxErrorBytes: 10 } }),
      );
      const answer = await server.next();
      answer.head(500, { 'content-type': 'application/json' });
      // The server has 100 bytes and no end for them.
      await answer.write('0123456789'.repeat(10));
      const result = await pending;
      expect(result).toMatchObject({ kind: 'response', status: 500 });
      expect(result.kind === 'response' && result.body.toString()).toBe('0123456789');
      await answer.closed;
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('keeps the status of a refused answer whose body stalls: what arrived is the body', async () => {
    await withStreamServer(async (server) => {
      // Real time, and a short limit: the status line has to be read before the limit is armed.
      const pending = outboundStream(post(server.url), streamOptions({ limits: { idleMs: 100 } }));
      const answer = await server.next();
      answer.head(429, { 'retry-after': '3' });
      await answer.write('{"error"');
      const result = await pending;
      expect(result).toMatchObject({ kind: 'response', status: 429 });
      expect(result).toMatchObject({ body: Buffer.from('{"error"') });
      await answer.closed;
    });
  });

  it('reads the body of a refused answer that trickles in, each chunk restarting the idle limit', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { idleMs: 1_000 } }),
      );
      const answer = await server.next();
      answer.head(500, { 'content-type': 'application/json' });
      await answer.write('a');
      for (const piece of ['b', 'c', 'd']) {
        await reading();
        // Each wait is under the limit, and together they are over it.
        await vi.advanceTimersByTimeAsync(900);
        await answer.write(piece);
      }
      await answer.end();
      const result = await pending;
      expect(result).toMatchObject({ kind: 'response', status: 500 });
      expect(result.kind === 'response' && result.body.toString()).toBe('abcd');
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('cuts a refused answer whose body never starts at the idle limit, which its status line armed', async () => {
    await withStreamServer(async (server) => {
      // Real time again: the first-byte limit is far off, so only the idle limit can end this read.
      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { firstByteMs: 60_000, idleMs: 100 } }),
      );
      const answer = await server.next();
      answer.head(503, { 'content-type': 'application/json' });
      expect(await pending).toMatchObject({ kind: 'response', status: 503 });
      await answer.closed;
    });
  });

  it('keeps the status of a refused answer whose connection breaks while its body is read', async () => {
    await withStreamServer(async (server) => {
      const pending = outboundStream(post(server.url), streamOptions());
      const answer = await server.next();
      answer.head(503, { 'content-length': '50' });
      await answer.write('partial');
      answer.cut();
      expect(await pending).toMatchObject({ kind: 'response', status: 503 });
    });
  });

  it('gives a refused answer up when the signal aborts while its body is read', async () => {
    await withStreamServer(async (server) => {
      fakeTimers();
      const controller = new AbortController();
      const pending = outboundStream(
        post(server.url),
        streamOptions({ signal: controller.signal }),
      );
      const answer = await server.next();
      answer.head(500, { 'content-length': '50' });
      await answer.write('partial');
      await reading();
      const settled = pending.catch((e: unknown) => e);
      controller.abort();
      expect(await settled).toMatchObject({ kind: 'failed', cause: 'aborted' });
      await answer.closed;
      expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('is a connection failure, with no timer left, when nothing listens', async () => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    fakeTimers();
    try {
      const result = await outboundStream(post(`http://127.0.0.1:${port}/x`), streamOptions());
      expect(result).toMatchObject({
        kind: 'failed',
        cause: 'connection',
        unreachable: true,
        code: 'ECONNREFUSED',
        reason: 'The connection to test failed (ECONNREFUSED)',
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('holds the connect deadline, and calls a host that does not resolve unresolved', async () => {
    const result = await outboundStream(
      { url: 'https://gitlab-ce/api/v4/user', method: 'GET', headers: {} },
      streamOptions({
        connectTimeoutMs: 100,
        resolve: () => new Promise(() => undefined),
      }),
    );
    expect(result).toMatchObject({
      kind: 'failed',
      cause: 'unresolved',
      unreachable: true,
      reason: 'The test host could not be resolved within 100 ms',
    });
  });
});

type Over = {
  allowInternalHosts?: boolean;
  refuseAddress?: (address: string) => boolean;
  connectTimeoutMs?: number;
  resolve?: Resolver;
  signal?: AbortSignal;
};

/** The two callers of the checks before the connection, called alike. */
const CALLERS: [
  string,
  (request: OutboundRequest, over: Over) => Promise<OutboundResult | OutboundStreamResult>,
][] = [
  [
    'outboundRequest',
    (request, over) =>
      outboundRequest(request, {
        allowInternalHosts: false,
        timeoutMs: 5_000,
        maxResponseBytes: 1_024,
        overflow: 'fail',
        names: NAMES,
        ...over,
      }),
  ],
  [
    'outboundStream',
    (request, over) =>
      outboundStream(request, streamOptions({ allowInternalHosts: false, ...over })),
  ],
];

const answering =
  (...addresses: string[]): Resolver =>
  () =>
    Promise.resolve(
      addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })),
    );

describe.each(CALLERS)('%s: the checks before the connection', (_name, call) => {
  it('refuses an address that is not public, and never connects to it', async () => {
    await withStreamServer(async (server) => {
      expect(await call(get(server.url), {})).toEqual({
        kind: 'failed',
        cause: 'not_public',
        unreachable: false,
        reason: 'The test host resolves to a private, loopback or otherwise non-public address',
        code: null,
      });
      expect(server.connections()).toBe(0);
    });
  });

  it('refuses a private IP literal, and a name that resolves to a private address', async () => {
    expect(await call(get('http://10.0.0.5/x'), {})).toMatchObject({ cause: 'not_public' });
    expect(
      await call(get('https://llm.example.com/v1'), { resolve: answering('10.0.0.5') }),
    ).toMatchObject({ cause: 'not_public' });
  });

  it('refuses a name when any one of its addresses is private, not only the one it would use', async () => {
    expect(
      await call(get('https://llm.example.com/v1'), {
        resolve: answering('93.184.216.34', '10.0.0.5'),
      }),
    ).toMatchObject({ kind: 'failed', cause: 'not_public' });
  });

  it('refuses what refuseAddress names, internal hosts allowed or not', async () => {
    const refuseAddress = (address: string): boolean => address === '169.254.169.254';
    expect(
      await call(get('http://metadata.corp/x'), {
        allowInternalHosts: true,
        refuseAddress,
        resolve: answering('169.254.169.254'),
      }),
    ).toEqual({
      kind: 'failed',
      cause: 'refused_address',
      unreachable: false,
      reason: 'The test host resolves to a link-local, cloud metadata or loopback address',
      code: null,
    });
  });

  it('refuses a URL that is not valid or not http(s)', async () => {
    expect(await call(get('not a url'), {})).toMatchObject({
      cause: 'invalid_url',
      reason: 'The test URL is not valid',
    });
    expect(await call(get('ftp://example.com/x'), {})).toMatchObject({
      cause: 'invalid_url',
      reason: 'The test URL is not http or https',
    });
  });

  it('calls a host unresolved when the lookup fails, answers nothing or answers what is no address', async () => {
    for (const resolve of [
      () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })),
      answering(),
      answering('not-an-address'),
    ]) {
      expect(await call(get('https://llm.example.com/v1'), { resolve })).toMatchObject({
        kind: 'failed',
        cause: 'unresolved',
        unreachable: true,
        reason: 'The test host could not be resolved',
      });
    }
  });

  it('sends nothing, and looks nothing up, for a signal that aborted before', async () => {
    const resolve = vi.fn(answering('127.0.0.1'));
    const controller = new AbortController();
    controller.abort();
    expect(
      await call(get('https://llm.example.com/v1'), {
        allowInternalHosts: true,
        resolve,
        signal: controller.signal,
      }),
    ).toEqual({
      kind: 'failed',
      cause: 'aborted',
      unreachable: false,
      reason: 'The request to test was given up',
      code: null,
    });
    expect(resolve).not.toHaveBeenCalled();
  });

  it('sends nothing when the signal aborts during the lookup', async () => {
    await withStreamServer(async (server) => {
      let answerLookup: () => void = () => undefined;
      const lookup = new Promise<{ address: string; family: number }[]>((resolve) => {
        answerLookup = () => resolve([{ address: '127.0.0.1', family: 4 }]);
      });
      const controller = new AbortController();
      const pending = call(get(`http://pinned.test:${server.port}/x`), {
        allowInternalHosts: true,
        resolve: () => lookup,
        signal: controller.signal,
      });
      controller.abort();
      answerLookup();
      expect(await pending).toMatchObject({ kind: 'failed', cause: 'aborted' });
      expect(server.connections()).toBe(0);
    });
  });

  it('cuts a connection whose TLS handshake never ends at the connect deadline', async () => {
    // The host accepts the connection and says nothing: the handshake of an https request waits.
    const sockets: Socket[] = [];
    const silent = createNetServer((socket) => {
      sockets.push(socket);
    });
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    const { port } = silent.address() as AddressInfo;
    try {
      expect(
        await call(get(`https://127.0.0.1:${port}/x`), {
          allowInternalHosts: true,
          connectTimeoutMs: 100,
        }),
      ).toEqual({
        kind: 'failed',
        cause: 'connect_timeout',
        unreachable: true,
        reason: 'No connection within 100 ms',
        code: null,
      });
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => silent.close(() => resolve()));
    }
  });

  it('connects only to the addresses it checked: the name is looked up once, and never again', async () => {
    await withStreamServer(async (server) => {
      const resolve = vi.fn(answering('127.0.0.1'));
      const pending = call(get(`http://pinned.test:${server.port}/x`), {
        allowInternalHosts: true,
        resolve,
      });
      const answer = await server.next();
      // The name was never resolved by the system: the connection went to the checked address.
      expect(answer.headers.host).toBe(`pinned.test:${server.port}`);
      answer.head(200, { 'content-type': 'text/plain' });
      await answer.end('ok');
      const result = await pending;
      expect(['response', 'stream']).toContain(result.kind);
      if (result.kind === 'stream') await result.chunks[Symbol.asyncIterator]().return?.();
      expect(resolve).toHaveBeenCalledTimes(1);
    });
  });
});

describe('the failures both functions share are worded the same way', () => {
  it('a connection that fails', async () => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const url = `http://127.0.0.1:${port}/x`;
    const asked = await outboundRequest(post(url), {
      allowInternalHosts: true,
      timeoutMs: 5_000,
      maxResponseBytes: 1_024,
      overflow: 'fail',
      names: NAMES,
    });
    const streamedOnce = await outboundStream(post(url), streamOptions());
    const failure = {
      kind: 'failed',
      cause: 'connection',
      unreachable: true,
      code: 'ECONNREFUSED',
      reason: 'The connection to test failed (ECONNREFUSED)',
    };
    expect(asked).toEqual(failure);
    expect(streamedOnce).toEqual(failure);
  });

  it('an answer over its limit', async () => {
    await withStreamServer(async (server) => {
      const asked = outboundRequest(post(server.url), {
        allowInternalHosts: true,
        timeoutMs: 5_000,
        maxResponseBytes: 10,
        overflow: 'fail',
        names: NAMES,
      });
      const first = await server.next();
      first.head(200, { 'content-type': 'application/json' });
      await first.write('12345678901');
      expect(await asked).toMatchObject({
        kind: 'failed',
        cause: 'too_large',
        reason: 'The answer of test is larger than 10 bytes',
      });

      const pending = outboundStream(
        post(server.url),
        streamOptions({ limits: { maxStreamBytes: 10 } }),
      );
      const second = await server.next();
      second.head();
      const chunks = await streamed(pending);
      await second.write('12345678901');
      await expect(chunks.next()).rejects.toMatchObject({
        cause: 'too_large',
        reason: 'The answer of test is larger than 10 bytes',
      });
    });
  });
});
