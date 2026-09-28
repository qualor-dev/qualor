import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import type { IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { lingerBeforeClosing } from './lingering-close';

interface FakeSocket extends EventEmitter {
  destroyed: boolean;
  bytesRead: number;
  destroy: () => void;
  destroySoon: () => void;
}

/** Node's real net.Socket always has a working destroySoon (and emits 'close'); this stands in
 *  for it. */
function fakeSocket(onDestroy: () => void): FakeSocket {
  const socket: FakeSocket = Object.assign(new EventEmitter(), {
    destroyed: false,
    bytesRead: 0,
    destroy: () => {
      socket.destroyed = true;
      onDestroy();
    },
    destroySoon: () => socket.destroy(),
  });
  return socket;
}

function destroyedSignal(): { onDestroy: () => void; destroyed: Promise<void> } {
  let notify: () => void;
  const destroyed = new Promise<void>((resolve) => {
    notify = resolve;
  });
  return { onDestroy: () => notify(), destroyed };
}

/** A stand-in for `request.raw`: a real Readable (so readableEnded/'end'/'error' behave for
 * real), plus the http.IncomingMessage-specific `complete` flag lingerBeforeClosing also checks. */
function fakeRequestStream(complete = false): IncomingMessage {
  const stream = new Readable({ read() {} });
  Object.assign(stream, { complete });
  return stream as unknown as IncomingMessage;
}

async function alreadyEndedRequestStream(): Promise<IncomingMessage> {
  const stream = fakeRequestStream(false);
  const drained = new Promise<void>((resolve) => {
    stream.on('end', resolve);
  });
  stream.resume();
  stream.push(null);
  await drained;
  return stream;
}

describe('lingerBeforeClosing (S12: measure by socket.bytesRead, not request "data" events)', () => {
  it('destroys once socket.bytesRead advances past maxBytes + marginBytes', async () => {
    const stream = fakeRequestStream();
    const { onDestroy, destroyed } = destroyedSignal();
    const socket = fakeSocket(onDestroy);

    lingerBeforeClosing(stream, socket as unknown as Socket, {
      maxBytes: 1_000,
      marginBytes: 500,
      pollMs: 5,
      idleMs: 10_000,
      totalMs: 10_000,
    });
    expect(typeof socket.destroySoon).toBe('function');
    socket.destroySoon(); // what Node's resOnFinish calls once the response is flushed

    // A client that keeps sending: measured at the socket level, independent of whether anything
    // ever consumes `stream` as 'data' events (the round-2 bug: it didn't, for an early
    // rejection, because Node's own _dump() already detached listeners before this runs).
    const feeder = setInterval(() => {
      socket.bytesRead += 100;
    }, 5);

    await destroyed;
    clearInterval(feeder);
    expect(socket.destroyed).toBe(true);
  });

  it('gives up after idleMs once socket.bytesRead stops advancing', async () => {
    const stream = fakeRequestStream();
    const { onDestroy, destroyed } = destroyedSignal();
    const socket = fakeSocket(onDestroy);
    const start = Date.now();

    lingerBeforeClosing(stream, socket as unknown as Socket, {
      maxBytes: 10 * 1024 * 1024,
      pollMs: 5,
      idleMs: 30,
      totalMs: 10_000,
    });
    socket.destroySoon();
    socket.bytesRead = 100; // one burst, then silence — well under the byte cap

    await destroyed;
    expect(socket.destroyed).toBe(true);
    expect(Date.now() - start).toBeLessThan(1_000);
  });

  it('gives up after totalMs even under steady, under-cap, never-idle progress', async () => {
    const stream = fakeRequestStream();
    const { onDestroy, destroyed } = destroyedSignal();
    const socket = fakeSocket(onDestroy);

    lingerBeforeClosing(stream, socket as unknown as Socket, {
      maxBytes: 10 * 1024 * 1024,
      pollMs: 5,
      idleMs: 10_000,
      totalMs: 40,
    });
    socket.destroySoon();
    const feeder = setInterval(() => {
      socket.bytesRead += 10; // steady: never idle, never crosses the (huge) byte cap
    }, 5);

    await destroyed;
    clearInterval(feeder);
    expect(socket.destroyed).toBe(true);
  });

  it('hands off to the ORIGINAL destroySoon (graceful) when the body ends naturally, not destroy()', async () => {
    const stream = fakeRequestStream();
    const socket = fakeSocket(() => {});
    let originalCalled = false;
    // lingerBeforeClosing captures whatever destroySoon is at call time as "original".
    socket.destroySoon = () => {
      originalCalled = true;
    };

    lingerBeforeClosing(stream, socket as unknown as Socket, {
      maxBytes: 10 * 1024 * 1024,
      pollMs: 5,
      idleMs: 10_000,
      totalMs: 10_000,
    });
    socket.destroySoon(); // now calls the override, which saved the stand-in above as "original"
    const ended = new Promise<void>((resolve) => stream.on('end', resolve));
    stream.resume();
    stream.push(null); // the request body ends naturally, well within every deadline
    await ended;
    // 'end' on the stream and the module's own 'end' listener are both async; give it a tick.
    await new Promise((resolve) => setImmediate(resolve));

    expect(originalCalled).toBe(true);
    expect(socket.destroyed).toBe(false);
  });

  it('leaves destroySoon untouched when the body has already ended (readableEnded)', async () => {
    const stream = await alreadyEndedRequestStream();
    expect(stream.readableEnded).toBe(true);
    const socket = fakeSocket(() => {});
    const original = socket.destroySoon;

    lingerBeforeClosing(stream, socket as unknown as Socket, { maxBytes: 1 });

    expect(socket.destroySoon).toBe(original);
  });

  it('leaves destroySoon untouched when IncomingMessage.complete is already true', () => {
    const stream = fakeRequestStream(true);
    const socket = fakeSocket(() => {});
    const original = socket.destroySoon;

    lingerBeforeClosing(stream, socket as unknown as Socket, { maxBytes: 1 });

    expect(socket.destroySoon).toBe(original);
  });

  it('calls the original destroySoon at once when the body ended between onSend and destroySoon', async () => {
    const stream = fakeRequestStream();
    const socket = fakeSocket(() => {});
    let originalCalls = 0;
    socket.destroySoon = () => {
      originalCalls += 1;
    };
    lingerBeforeClosing(stream, socket as unknown as Socket, { maxBytes: 1, pollMs: 5 });
    // The body finishes arriving after onSend installed the override but before Node flushes the
    // response and calls destroySoon: 'end' has already fired, so waiting for it would hang until
    // the idle timeout and then destroy() (a possible RST) instead of closing gracefully.
    const ended = new Promise<void>((resolve) => stream.on('end', resolve));
    stream.resume();
    stream.push(null);
    await ended;
    expect(stream.readableEnded).toBe(true);
    socket.destroySoon();
    expect(originalCalls).toBe(1);
    expect(socket.destroyed).toBe(false);
    expect(stream.listenerCount('end')).toBe(1); // only this test's own listener
  });

  describe('when the socket closes while lingering', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('stops polling and detaches its request listeners', () => {
      vi.useFakeTimers();
      const stream = fakeRequestStream();
      let destroyCalls = 0;
      const socket = fakeSocket(() => {
        destroyCalls += 1;
      });
      const endListeners = stream.listenerCount('end');
      lingerBeforeClosing(stream, socket as unknown as Socket, {
        maxBytes: 1_000,
        marginBytes: 0,
        pollMs: 5,
        idleMs: 50,
        totalMs: 100,
      });
      socket.destroySoon();
      expect(vi.getTimerCount()).toBe(1);
      expect(stream.listenerCount('end')).toBe(endListeners + 1);
      socket.emit('close'); // e.g. the client hung up
      expect(vi.getTimerCount()).toBe(0);
      expect(stream.listenerCount('end')).toBe(endListeners);
      socket.bytesRead = 10_000; // over every cap: a live poller would destroy now
      vi.advanceTimersByTime(1_000);
      expect(destroyCalls).toBe(0);
    });
  });

  it('leaves an already-destroyed socket alone', () => {
    const stream = fakeRequestStream();
    const socket = fakeSocket(() => {});
    socket.destroyed = true;
    const original = socket.destroySoon;

    lingerBeforeClosing(stream, socket as unknown as Socket, { maxBytes: 1 });

    expect(socket.destroySoon).toBe(original);
  });
});
