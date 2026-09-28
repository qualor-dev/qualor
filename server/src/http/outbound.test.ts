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
