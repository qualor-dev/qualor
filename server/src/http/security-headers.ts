import type { FastifyHelmetOptions } from '@fastify/helmet';

/**
 * The Content-Security-Policy of every response (api.md §4). The web UI is served from the same
 * origin (plan 1F ruling Y2), so everything it loads is 'self': no 'unsafe-inline', no eval, no
 * third-party origin, never framed. Its index.html adds a per-request nonce to `script-src` and
 * `style-src` ({@link uiContentSecurityPolicy}): the build's one inline script is the import map
 * that carries the lazy chunks' integrity hashes, and Angular inserts component styles as
 * `<style>` elements; both carry the nonce the server writes into the page.
 * `upgrade-insecure-requests` is deliberately absent: a self-hosted server may be reached over
 * plain HTTP inside a network, and TLS is the reverse proxy's job.
 */
export function cspDirectives(nonce?: string): Record<string, string[]> {
  const withNonce = nonce === undefined ? ["'self'"] : ["'self'", `'nonce-${nonce}'`];
  return {
    'default-src': ["'self'"],
    'base-uri': ["'self'"],
    'connect-src': ["'self'"],
    'font-src': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'img-src': ["'self'", 'data:'],
    'object-src': ["'none'"],
    'script-src': withNonce,
    'script-src-attr': ["'none'"],
    'style-src': withNonce,
  };
}

export function serializeCsp(directives: Record<string, string[]>): string {
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(' ')}`)
    .join('; ');
}

/** The policy of the UI's index.html: {@link cspDirectives} with this response's nonce. */
export function uiContentSecurityPolicy(nonce: string): string {
  return serializeCsp(cspDirectives(nonce));
}

/** @fastify/helmet options: its defaults plus the strict CSP, `DENY` framing and no referrer. */
export function helmetOptions(): FastifyHelmetOptions {
  return {
    contentSecurityPolicy: { useDefaults: false, directives: cspDirectives() },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
  };
}
