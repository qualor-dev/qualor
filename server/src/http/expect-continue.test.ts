import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { expectsContinue } from './expect-continue';

/**
 * S15: `expectsContinue` must agree with Node's own decision. Node routes a request to
 * 'checkContinue' only when it expects `100 Continue`; with a listener for it, Node sends no
 * `100 Continue` itself, so a request Node routed there and the server did not recognise would
 * wait for a go-ahead that never comes.
 */
describe('expectsContinue agrees with Node', () => {
  const seen: { event: string; ours: boolean }[] = [];
  const server = createServer();
  let port = 0;
  const record = (event: string) => (req: IncomingMessage, res: ServerResponse) => {
    seen.push({ event, ours: expectsContinue(req) });
    res.writeHead(204, { connection: 'close' }).end();
  };
  server.on('request', record('request'));
  server.on('checkContinue', record('checkContinue'));
  server.on('checkExpectation', record('checkExpectation'));

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function send(version: string, expectValue: string): Promise<void> {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () =>
        socket.write(
          `POST /x HTTP/${version}\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n` +
            `Expect: ${expectValue}\r\n\r\n`,
        ),
      );
      socket.on('data', () => undefined);
      socket.on('error', () => resolve());
      socket.on('close', () => resolve());
    });
  }

  it.each([
    ['1.1', '100-continue', true],
    ['1.1', '100-Continue', true],
    ['1.1', '100-CONTINUE', true],
    ['1.1', '100-continue, x-trace', true],
    ['1.1', 'x-trace, 100-continue', true],
    ['1.1', 'foo;100-continue', true],
    ['1.1', '100-continue=1', true],
    ['1.1', '100-continuex', false],
    ['1.1', 'x100-continue', false],
    ['1.1', '1100-continue', false],
    ['1.1', '100_continue', false],
    ['1.1', 'something-else', false],
    ['1.0', '100-continue', false],
  ])('HTTP/%s Expect: %j → expects 100 Continue: %s', async (version, value, expected) => {
    seen.length = 0;
    await send(version, value);
    expect(seen).toHaveLength(1);
    const [{ event, ours }] = seen as [{ event: string; ours: boolean }];
    expect(event === 'checkContinue', `Node routed it to '${event}'`).toBe(expected);
    expect(ours).toBe(expected);
  });
});
