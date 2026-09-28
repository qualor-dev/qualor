import type { IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';

const MiB = 1024 * 1024;

/** S12: extra slack over the request's own size limit before giving up on draining it. */
export const LINGER_EXTRA_BYTES_MARGIN = 1 * MiB;
/** S12: give up if no new bytes have arrived on the socket for this long. */
export const LINGER_IDLE_MS = 5_000;
/** S12: give up after this long overall, regardless of progress. */
export const LINGER_TOTAL_MS = 15_000;
/** S12: how often socket.bytesRead is sampled. */
export const LINGER_POLL_MS = 50;

export interface LingeringCloseOptions {
  /** The request's own configured/declared size limit; draining gives up at this plus a margin. */
  maxBytes: number;
  /** Overridable for tests; defaults to LINGER_EXTRA_BYTES_MARGIN. */
  marginBytes?: number;
  /** Overridable for tests; defaults to LINGER_IDLE_MS. */
  idleMs?: number;
  /** Overridable for tests; defaults to LINGER_TOTAL_MS. */
  totalMs?: number;
  /** Overridable for tests; defaults to LINGER_POLL_MS. */
  pollMs?: number;
}

/**
 * Sends `Connection: close` semantics without letting Node's own immediate socket teardown turn
 * into a TCP RST.
 *
 * Node's `_http_server.js` `resOnFinish`, on seeing a response with `Connection: close`, calls
 * `socket.destroySoon()` the moment the response is flushed — with no regard for whether the
 * client is still writing. If the kernel still has unread bytes queued for that socket at that
 * point, destroying it sends a TCP RST instead of a clean close, and the client never sees the
 * response it was about to receive.
 *
 * **Fix round 2** (kept, still correct in spirit): intercept the exact call Node's internals are
 * about to make — `socket.destroySoon`, looked up by property at the moment the response
 * finishes, not an earlier-bound reference — and substitute a bounded drain of the request body
 * first, only destroying the socket once that drain is done or has given up.
 *
 * **S12 (fix round 3):** round 2 measured drain progress by listening for `'data'` on
 * `requestStream` (`request.raw`). That works when the route had paused a stream it was already
 * consuming (`readGzipUpload`'s mid-read rejections: 422 invalid gzip, 413 from the decompressed
 * or a chunked-over-the-limit compressed body) — resuming it drains real, already-buffered bytes,
 * fast, so a small byte cap based on 'data' events raced straight past the *socket*'s still-queued
 * bytes and destroyed while some were still unread: an RST regardless of the cap. And for a
 * request nothing has consumed yet (an early rejection: 401/403/404/415, or a declared-Content-
 * Length 413), Node's own `resOnFinish` calls the request's internal `_dump()` *before* calling
 * `destroySoon()`; `_dump()`'s own `resume()` keeps the socket draining at the OS level just fine
 * (confirmed: several hundred MiB in a couple of seconds) but no `'data'` event we can observe
 * ever fires for it, so a 'data'-based cap never triggered at all — only the deadline did, letting
 * hundreds of MiB through in the meantime.
 *
 * The fix: measure with `socket.bytesRead` instead — the total bytes Node has read off the
 * underlying file descriptor, updated regardless of whether the HTTP parser is still forwarding
 * them to `requestStream` or whether that stream is paused — sampled on a short interval rather
 * than trusted to `'data'` events. `requestStream.resume()` is still called (a harmless no-op if
 * `_dump()` already did it; necessary if the route had paused the stream) purely to keep bytes
 * flowing so `bytesRead` keeps moving; it is never used for measurement.
 *
 * Stops — whichever comes first — once: the request body actually ends (graceful: hands off to
 * the *original* `destroySoon`, the close Node would have done anyway, now that nothing is left
 * unread); `socket.bytesRead` has advanced past `maxBytes + marginBytes` since draining started;
 * no new bytes have arrived for `idleMs`; or `totalMs` has elapsed in total (the last three all
 * give up: a hard `socket.destroy()`, accepting the small chance of an RST as the cost of a firm
 * upper bound on how long and how much a rejected upload can hold a connection open for).
 *
 * If the body has already fully arrived by the time this is called (`readableEnded`/`complete`),
 * there is nothing to drain: `destroySoon` is left untouched, so Node's normal fast path runs the
 * moment it calls it. The same check runs again when Node calls the override (the body may have
 * ended in between), and a socket `'close'` while lingering stops the poller and detaches the
 * listeners.
 *
 * This depends on Node's http server calling `socket.destroySoon` — not `socket.end`/`.destroy`
 * directly — from `resOnFinish` when a response sets `Connection: close`. Verified on Node 22
 * (this project's CI) and Node 24 (local).
 *
 * Call from a route's `onSend` hook (which runs before the response is actually written out).
 */
export function lingerBeforeClosing(
  requestStream: IncomingMessage,
  socket: Socket,
  options: LingeringCloseOptions,
): void {
  if (socket.destroyed || typeof socket.destroySoon !== 'function') return;
  // Nothing to drain — leave destroySoon alone so Node's own (immediate) close runs unmodified.
  if (requestStream.readableEnded || requestStream.complete) return;

  const originalDestroySoon = socket.destroySoon.bind(socket);
  socket.destroySoon = () => lingerThenClose(requestStream, socket, originalDestroySoon, options);
}

function lingerThenClose(
  requestStream: IncomingMessage,
  socket: Socket,
  originalDestroySoon: () => void,
  options: LingeringCloseOptions,
): void {
  // The body may have finished arriving between onSend (which installed this override) and Node
  // flushing the response: its 'end' has already fired, so waiting for it would only run into the
  // idle timeout and a hard destroy(). Nothing is left unread — close the way Node would have.
  if (requestStream.readableEnded || requestStream.complete) {
    originalDestroySoon();
    return;
  }
  const maxBytes = options.maxBytes + (options.marginBytes ?? LINGER_EXTRA_BYTES_MARGIN);
  const idleMs = options.idleMs ?? LINGER_IDLE_MS;
  const totalMs = options.totalMs ?? LINGER_TOTAL_MS;
  const pollMs = options.pollMs ?? LINGER_POLL_MS;

  const startBytes = socket.bytesRead;
  const startedAt = Date.now();
  let lastProgressAt = startedAt;
  let lastBytes = startBytes;
  let done = false;

  const cleanup = (): void => {
    clearInterval(poller);
    requestStream.off('end', finishGracefully);
    requestStream.off('error', giveUp);
    socket.off('close', onSocketClose);
  };
  // The socket went away on its own (client hung up, request timeout): nothing left to do.
  const onSocketClose = (): void => {
    if (done) return;
    done = true;
    cleanup();
  };
  const giveUp = (): void => {
    if (done) return;
    done = true;
    cleanup();
    if (!socket.destroyed) socket.destroy();
  };
  const finishGracefully = (): void => {
    if (done) return;
    done = true;
    cleanup();
    originalDestroySoon();
  };

  requestStream.on('end', finishGracefully);
  requestStream.on('error', giveUp);
  socket.once('close', onSocketClose);
  // Keep the app-level stream draining: required when the route had paused it (a mid-read
  // rejection); a harmless no-op if Node's own _dump() already resumed it (an early rejection).
  // Measurement below never depends on this actually delivering 'data' events to us.
  requestStream.resume();

  const poller = setInterval(() => {
    const now = Date.now();
    const currentBytes = socket.bytesRead;
    if (currentBytes > lastBytes) {
      lastBytes = currentBytes;
      lastProgressAt = now;
    }
    if (currentBytes - startBytes > maxBytes) {
      giveUp();
    } else if (now - lastProgressAt >= idleMs) {
      giveUp();
    } else if (now - startedAt >= totalMs) {
      giveUp();
    }
  }, pollMs);
  poller.unref();
}
