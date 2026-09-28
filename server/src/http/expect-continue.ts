import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/** Requests whose `100 Continue` has been written (so their body is on its way). */
const continued = new WeakSet<IncomingMessage>();

/**
 * S15: the test Node itself applies before emitting 'checkContinue' (`_http_server.js`,
 * `continueExpression`), so a request Node routed here as expecting `100 Continue` is always
 * recognised as one, whatever the case, surrounding text or list form of its `Expect` value.
 */
const CONTINUE_EXPECTATION = /(?:^|\W)100-continue(?:$|\W)/i;

/**
 * True when Node treats the request as expecting `100 Continue`: HTTP/1.1 (Node ignores `Expect`
 * on HTTP/1.0, and RFC 9110 §10.1.1 forbids a `100` to an HTTP/1.0 client) and a matching value.
 */
export function expectsContinue(raw: IncomingMessage): boolean {
  const value = raw.headers.expect;
  return (
    raw.httpVersionMajor === 1 &&
    raw.httpVersionMinor === 1 &&
    value !== undefined &&
    CONTINUE_EXPECTATION.test(value)
  );
}

/**
 * Writes the interim `100 Continue` for a request that asked for one (`Expect: 100-continue`),
 * once. Call it only when the request has passed every check that could reject it without its
 * body, right before the body is read.
 */
export function sendContinue(request: FastifyRequest, reply: FastifyReply): void {
  const raw = request.raw;
  if (!expectsContinue(raw) || continued.has(raw) || reply.raw.headersSent) return;
  // light-my-request's fake response (app.inject) is a ServerResponse too, but be defensive.
  if (typeof reply.raw.writeContinue !== 'function') return;
  continued.add(raw);
  reply.raw.writeContinue();
}

/**
 * RFC 9110 §10.1.1 `Expect: 100-continue`. Node answers `100 Continue` automatically, before any
 * hook has run, unless the server has a `checkContinue` listener — so a client would upload a
 * 50 MiB report only to be told 401/404/413. With this installed the request is dispatched
 * normally and `100 Continue` is written only when the body is actually wanted: by a global
 * `preParsing` hook (after authentication, R14), or — for routes with `config.deferContinue`,
 * i.e. the report upload — by the handler itself once its own checks have passed.
 */
export function installExpectContinue(app: FastifyInstance): void {
  const server = app.server as Server;
  server.on('checkContinue', (req: IncomingMessage, res: ServerResponse) => {
    server.emit('request', req, res);
  });
  app.addHook('preParsing', async (request, reply, payload) => {
    if (request.routeOptions.config.deferContinue !== true) sendContinue(request, reply);
    return payload;
  });
}
