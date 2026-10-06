import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { TelemetryPayload } from './collect';
import { sendTelemetry } from './send';

const payload = {
  schema: 1,
  installationId: '00000000-0000-4000-8000-000000000000',
} as TelemetryPayload;
let server: Server | undefined;

async function listen(
  handler: (req: IncomingMessage, body: string) => [number, number?],
): Promise<string> {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      const [status, delayMs = 0] = handler(req, body);
      setTimeout(() => res.writeHead(status).end(), delayMs);
    });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/telemetry`;
}

afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = undefined;
});

describe('sendTelemetry', () => {
  it('posts the JSON with the user agent', async () => {
    let seen: { method?: string; type?: string; agent?: string; body?: string } = {};
    const url = await listen((req, body) => {
      seen = {
        method: req.method,
        type: req.headers['content-type'],
        agent: req.headers['user-agent'],
        body,
      };
      return [204];
    });
    expect(await sendTelemetry(url, payload, { userAgent: 'qualor-server/9.9.9' })).toEqual({
      ok: true,
    });
    expect(seen).toEqual({
      method: 'POST',
      type: 'application/json',
      agent: 'qualor-server/9.9.9',
      body: JSON.stringify(payload),
    });
  });

  it('reports a non-2xx answer, a timeout and a refused connection without throwing', async () => {
    const url = await listen(() => [500]);
    expect(await sendTelemetry(url, payload, { userAgent: 'x' })).toEqual({
      ok: false,
      reason: 'HTTP 500',
    });
    await new Promise<void>((r) => server!.close(() => r()));
    const slow = await listen(() => [204, 2_000]);
    expect(await sendTelemetry(slow, payload, { userAgent: 'x', timeoutMs: 100 })).toMatchObject({
      ok: false,
    });
    expect(await sendTelemetry('http://127.0.0.1:9/t', payload, { userAgent: 'x' })).toMatchObject({
      ok: false,
    });
  });
});
