import type { AddressInfo, Socket } from 'node:net';
import { sample } from '@qualor/shared/test/sbom';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  createProjectToken,
  createTestContext,
  login,
  organizationId,
  type TestContext,
} from '../../test/app';
import { rawExchange } from '../../test/raw-socket';

const KEY = 'acme/socket';

/**
 * PUT /projects/sbom over a real socket: `app.inject` sends no `100 Continue`, so only a socket
 * shows that a refusal never asks for the body (as vulndb.socket.db.test.ts does for its uploads).
 */
describe('PUT /projects/sbom over a real socket', () => {
  let ctx: TestContext;
  let port: number;
  let token: string;

  const head = (lines: string[]) =>
    [
      `PUT /api/v0/projects/sbom?projectKey=${encodeURIComponent(KEY)}&version=1.0.0 HTTP/1.1`,
      'Host: 127.0.0.1',
      `Authorization: Bearer ${token}`,
      'Content-Type: application/vnd.cyclonedx+json',
      ...lines,
      'Expect: 100-continue',
      '',
      '',
    ].join('\r\n');

  beforeAll(async () => {
    ctx = await createTestContext();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const project = await createProject(ctx, admin, {
      organizationId: await organizationId(ctx, 'default'),
      key: KEY,
    });
    token = await createProjectToken(ctx, admin, project.id);
    await ctx.app.listen({ port: 0, host: '127.0.0.1' });
    port = (ctx.app.server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    await ctx?.close();
  });

  it('refuses a declared Content-Length over 32 MiB with 413, without 100 Continue', async () => {
    const text = await rawExchange(port, head(['Content-Length: 33554433']), {
      done: (received) => received.includes('"code"'),
    });
    expect(text.startsWith('HTTP/1.1 413 '), text).toBe(true);
    expect(text).toContain('"code":"SBOM_TOO_LARGE"');
    expect(text).not.toContain('100 Continue');
  });

  it('refuses another content type with 415, without 100 Continue', async () => {
    const text = await rawExchange(
      port,
      head(['Content-Length: 1024']).replace(
        'Content-Type: application/vnd.cyclonedx+json',
        'Content-Type: text/plain',
      ),
      { done: (received) => received.includes('"code"') },
    );
    expect(text.startsWith('HTTP/1.1 415 '), text).toBe(true);
    expect(text).not.toContain('100 Continue');
  });

  it('sends 100 Continue to a valid upload, then answers 201', async () => {
    const body = Buffer.from(sample('trivy-debian.cdx.json'));
    let sent = false;
    const text = await rawExchange(port, head([`Content-Length: ${body.length}`]), {
      onData: (received: string, socket: Socket) => {
        if (sent || !received.includes('100 Continue\r\n\r\n')) return;
        sent = true;
        socket.write(body);
      },
      done: (received) => received.includes('"monitoring"'),
    });
    expect(sent).toBe(true);
    expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 201 /);
    expect(text).toContain('"source":"sbom"');
  });
});
