import net, { type AddressInfo } from 'node:net';

export interface ConnectProxy {
  /** `http://[user:pass@]127.0.0.1:port` */
  url: string;
  /** Every request head the proxy received, as text. */
  heads: string[];
  connections: () => number;
  close: () => void;
}

/**
 * A minimal `CONNECT` proxy on 127.0.0.1 for tests (it never touches the network): every tunnel
 * goes to `127.0.0.1:<the requested port>`, whatever host was asked for, so a client that sent
 * an unresolvable origin name through it proves it did not resolve that name itself. With
 * `credentials`, a `Proxy-Authorization: Basic` that does not match gets `407`.
 * `answer: 'never' | 'trickle'` makes it hold the CONNECT answer back, or send it a byte at a
 * time every 100 ms.
 */
export async function startConnectProxy(
  o: { credentials?: string; answer?: 'ok' | 'never' | 'trickle' } = {},
): Promise<ConnectProxy> {
  const heads: string[] = [];
  const sockets = new Set<net.Socket>();
  let connections = 0;
  const server = net.createServer((client) => {
    connections += 1;
    sockets.add(client);
    client.on('error', () => undefined);
    client.on('close', () => sockets.delete(client));
    let buffer = Buffer.alloc(0);
    const onData = (d: Buffer) => {
      buffer = Buffer.concat([buffer, d]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      client.off('data', onData);
      const head = buffer.subarray(0, end).toString('latin1');
      heads.push(head);
      const rest = buffer.subarray(end + 4);
      const [line = '', ...lines] = head.split('\r\n');
      const m = /^CONNECT \S+:(\d+) HTTP\/1\.1$/.exec(line);
      if (m === null) {
        client.end('HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n');
        return;
      }
      if (o.credentials !== undefined) {
        const expected = `proxy-authorization: Basic ${Buffer.from(o.credentials).toString('base64')}`;
        if (!lines.some((l) => l.toLowerCase() === expected.toLowerCase())) {
          client.end(
            'HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic\r\n' +
              'content-length: 0\r\n\r\n',
          );
          return;
        }
      }
      const answer = 'HTTP/1.1 200 Connection established\r\n\r\n';
      if (o.answer === 'never') return;
      if (o.answer === 'trickle') {
        let i = 0;
        const t = setInterval(() => {
          if (client.destroyed || i >= answer.length) {
            clearInterval(t);
            return;
          }
          client.write(answer[i] ?? '');
          i += 1;
        }, 100);
        return;
      }
      const upstream = net.connect({ host: '127.0.0.1', port: Number(m[1]) }, () => {
        client.write(answer);
        if (rest.length > 0) upstream.write(rest);
        client.pipe(upstream);
        upstream.pipe(client);
      });
      sockets.add(upstream);
      upstream.on('error', () => client.destroy());
      upstream.on('close', () => {
        sockets.delete(upstream);
        client.destroy();
      });
      client.on('close', () => upstream.destroy());
    };
    client.on('data', onData);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const auth =
    o.credentials === undefined
      ? ''
      : `${encodeURIComponent(o.credentials.split(':')[0] ?? '')}:${encodeURIComponent(o.credentials.split(':').slice(1).join(':'))}@`;
  return {
    url: `http://${auth}127.0.0.1:${port}`,
    heads,
    connections: () => connections,
    close: () => {
      for (const s of sockets) s.destroy();
      server.close();
    },
  };
}
