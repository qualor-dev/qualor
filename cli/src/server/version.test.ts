import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { VERSION } from '../index';
import { createLogger } from '../log';
import { checkServerVersion, releaseLine } from './version';

const serve = useTestServers();
const ep = (url: string) => ({ url, token: 'qlr_prj_secret', timeoutMs: 5_000 });

function capture(): { log: ReturnType<typeof createLogger>; text: () => string } {
  let text = '';
  return { log: createLogger('debug', (t) => (text += t)), text: () => text };
}

/** The same major and minor as this scanner, another patch. */
const samePatchLine = `${releaseLine(VERSION)}.99`;

describe('releaseLine', () => {
  it.each([
    ['0.3.0', '0.3'],
    ['12.40.7', '12.40'],
    ['1.2.0-rc.1', '1.2'],
    ['1.2', null],
    ['dev', null],
  ])('%s → %s', (version, line) => {
    expect(releaseLine(version)).toBe(line);
  });
});

describe('checkServerVersion', () => {
  it('logs the server version with the token and no warning on the same release line', async () => {
    const server = await serve((_req, res) => json(res, 200, { version: samePatchLine }));
    const out = capture();
    expect(await checkServerVersion(ep(server.url), out.log)).toBe(samePatchLine);
    expect(out.text()).toContain(`server ${server.url} runs Qualor ${samePatchLine}`);
    expect(out.text()).not.toContain('warn:');
    expect(server.requests.map((r) => [r.method, r.url, r.headers.authorization])).toEqual([
      ['GET', '/api/v0/system/version', 'Bearer qlr_prj_secret'],
    ]);
  });

  it('warns when the server is another release line', async () => {
    const server = await serve((_req, res) => json(res, 200, { version: '99.0.0' }));
    const out = capture();
    await checkServerVersion(ep(server.url), out.log);
    expect(out.text()).toContain(
      `warn: this scanner is ${VERSION} and the server is 99.0.0: use the scanner of the server's release (qualor/scanner:99.0)`,
    );
  });

  it.each([
    [
      'an older server without the route',
      (res: Parameters<typeof json>[0]) => problem(res, 404, 'NOT_FOUND'),
    ],
    ['a rejected token', (res: Parameters<typeof json>[0]) => problem(res, 401, 'UNAUTHENTICATED')],
    ['a body that is not a version', (res: Parameters<typeof json>[0]) => json(res, 200, { v: 1 })],
    ['a body that is not JSON', (res: Parameters<typeof json>[0]) => res.end('<html>')],
  ])('only logs at debug level for %s', async (_what, answer) => {
    const server = await serve((_req, res) => answer(res));
    const out = capture();
    expect(await checkServerVersion(ep(server.url), out.log)).toBeNull();
    expect(out.text()).toMatch(/^debug: /);
    expect(out.text().split('\n').filter(Boolean)).toHaveLength(1);
  });

  it('only logs at debug level when the server is unreachable', async () => {
    const server = await serve((_req, res) => json(res, 200, {}));
    const url = server.url;
    await new Promise<void>((resolve) => server.server.close(() => resolve()));
    const out = capture();
    expect(await checkServerVersion(ep(url), out.log)).toBeNull();
    expect(out.text()).toMatch(/^debug: the server did not report its version/);
  });

  it('cleans control characters out of the reported version', async () => {
    const server = await serve((_req, res) => json(res, 200, { version: '1.0.0\u001b[31m' }));
    const out = capture();
    expect(await checkServerVersion(ep(server.url), out.log)).toBe('1.0.0');
    expect(out.text()).not.toContain('\u001b');
  });
});
