import net from 'node:net';

/**
 * Sends `head` over a raw socket and collects the server's bytes. `onData` may write more (e.g. a
 * body after `100 Continue`); the exchange ends when the server closes the connection, or when
 * `done(text)` returns true (the client then closes its side).
 */
export function rawExchange(
  port: number,
  head: string,
  options: {
    onData?: (text: string, socket: net.Socket) => void;
    done?: (text: string) => boolean;
  } = {},
): Promise<string> {
  return new Promise((resolve) => {
    let text = '';
    let finished = false;
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => socket.write(head));
    const finish = (): void => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(text);
    };
    socket.on('data', (d: Buffer) => {
      text += d.toString('utf8');
      options.onData?.(text, socket);
      if (options.done?.(text)) finish();
    });
    socket.on('error', () => {});
    socket.on('close', finish);
  });
}
