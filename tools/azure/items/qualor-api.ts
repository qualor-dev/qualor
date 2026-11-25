/**
 * The bench Qualor's API as the probe items use it: an admin session (cookie and CSRF token) and
 * JSON calls. Moved out of item 21 so that items it imports can use it too (no import cycle).
 */
import { z } from 'zod';
import { shape } from './common.js';

/** A body read as JSON; null when it is empty or not JSON (a proxy's HTML page, say). */
function jsonOrNull(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export class QualorApi {
  #cookie = '';
  #csrf = '';
  constructor(private readonly base: string) {}

  /** One call, whatever its status: the status, the body read as JSON (else null) and its text. */
  async send(
    method: string,
    p: string,
    body?: unknown,
  ): Promise<{ status: number; json: unknown; text: string }> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.#cookie) headers['Cookie'] = this.#cookie;
    if (this.#csrf && method !== 'GET') headers['X-Qualor-CSRF'] = this.#csrf;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(`${this.base.replace(/\/+$/, '')}${p}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(60_000),
    });
    const text = await res.text();
    return { status: res.status, json: jsonOrNull(text), text };
  }

  async call(
    method: string,
    p: string,
    body?: unknown,
  ): Promise<{ status: number; json: unknown }> {
    const res = await this.send(method, p, body);
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`${method} ${p} -> ${res.status}: ${res.text.slice(0, 300)}`);
    }
    return { status: res.status, json: res.json };
  }

  async login(password: string): Promise<void> {
    const res = await fetch(`${this.base.replace(/\/+$/, '')}/api/v0/auth/login`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`Qualor admin login -> ${res.status}`);
    this.#cookie = res.headers
      .getSetCookie()
      .map((c) => c.split(';')[0])
      .join('; ');
    if (!this.#cookie.includes('qualor_session=')) throw new Error('login set no session cookie');
    const me = shape(
      z.object({ csrfToken: z.string() }).loose(),
      (await this.call('GET', '/api/v0/auth/me')).json,
      'auth/me',
    );
    this.#csrf = me.csrfToken;
  }

  async items<T extends z.ZodType>(p: string, schema: T): Promise<z.infer<T>[]> {
    const sep = p.includes('?') ? '&' : '?';
    const res = await this.call('GET', `${p}${sep}limit=100`);
    return shape(z.object({ items: z.array(schema) }), res.json, p).items;
  }

  /** Every item of a keyset-paged list (`nextCursor`), at most `maxPages` pages of 100. */
  async all<T extends z.ZodType>(p: string, schema: T, maxPages = 20): Promise<z.infer<T>[]> {
    const page = z.object({ items: z.array(schema), nextCursor: z.string().nullish() });
    const out: z.infer<T>[] = [];
    const sep = p.includes('?') ? '&' : '?';
    let cursor: string | null = null;
    for (let i = 0; i < maxPages; i++) {
      const at: string = cursor === null ? '' : `&cursor=${encodeURIComponent(cursor)}`;
      const answer = await this.call('GET', `${p}${sep}limit=100${at}`);
      const got = shape(page, answer.json, p);
      out.push(...got.items);
      cursor = got.nextCursor ?? null;
      if (cursor === null) return out;
    }
    throw new Error(`${p}: more than ${maxPages} pages`);
  }
}
