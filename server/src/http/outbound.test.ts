import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, it } from 'vitest';
import { outboundRequest } from './outbound';

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
