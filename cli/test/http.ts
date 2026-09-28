import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach } from 'vitest';

export interface Recorded {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  /** The request body as received (empty when the client never sent it). */
  body: Buffer;
}

export type Handler = (
  req: IncomingMessage,
  res: ServerResponse,
  recorded: Recorded,
) => void | Promise<void>;

export interface TestServer {
  url: string;
  requests: Recorded[];
  server: Server;
}

/**
 * Local HTTP servers on 127.0.0.1 (the CLI tests never touch the network), closed after each
 * test. The handler runs once the request body has been read, unless `readBody` is false (then it
 * runs on arrival, e.g. to answer before `100 Continue`).
 */
export function useTestServers(): (
  handler: Handler,
  o?: { readBody?: boolean; prefix?: string },
) => Promise<TestServer> {
  const servers: Server[] = [];
  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        (s) =>
          new Promise<void>((resolve) => {
            s.closeAllConnections();
            s.close(() => resolve());
          }),
      ),
    );
  });
  return async (handler, o = {}) => {
    const requests: Recorded[] = [];
    const server = createServer();
    const dispatch = (req: IncomingMessage, res: ServerResponse) => {
      const recorded: Recorded = {
        method: req.method ?? '',
        url: req.url ?? '',
        headers: req.headers,
        body: Buffer.alloc(0),
      };
      requests.push(recorded);
      if (o.readBody === false) {
        void handler(req, res, recorded);
        return;
      }
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        recorded.body = Buffer.concat(chunks);
        void handler(req, res, recorded);
      });
    };
    server.on('request', dispatch);
    // `Expect: 100-continue`: with `readBody: false` the handler decides (like a Qualor server,
    // which answers only once its checks pass); otherwise the go-ahead is immediate.
    server.on('checkContinue', (req: IncomingMessage, res: ServerResponse) => {
      if (o.readBody !== false) res.writeContinue();
      dispatch(req, res);
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    return { url: `http://127.0.0.1:${port}${o.prefix ?? ''}`, requests, server };
  };
}

export function json(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': status >= 400 ? 'application/problem+json' : 'application/json',
    'content-length': String(Buffer.byteLength(text)),
    ...headers,
  });
  res.end(text);
}

export function problem(res: ServerResponse, status: number, code: string, detail?: string): void {
  json(
    res,
    status,
    {
      type: `urn:qualor:problem:${code.toLowerCase()}`,
      title: code,
      status,
      code,
      ...(detail !== undefined && { detail }),
    },
    { connection: 'close' },
  );
}
