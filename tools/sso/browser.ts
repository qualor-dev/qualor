/**
 * sso-scim.md §19.4: a browser small enough to read. It keeps cookies per host (`host:port`, so
 * Keycloak's and Qualor's never mix on 127.0.0.1), sends the ones whose path matches, follows no
 * redirect on its own, and reads forms out of HTML. Nothing here runs a page's scripts: Keycloak's
 * SAML POST page is submitted by reading its form, as its script would.
 */

export interface Cookie {
  name: string;
  value: string;
  path: string;
}

export interface Page {
  /** The URL that answered. */
  url: string;
  status: number;
  /** The `location` header resolved against {@link url}, or null. */
  location: string | null;
  body: string;
}

export interface Form {
  /** The `action`, resolved against the page's URL when one is given. */
  action: string;
  fields: Record<string, string>;
}

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

/** The five named entities and numeric references (decimal and hex); anything else is kept. */
export function decodeEntities(text: string): string {
  return text.replace(/&(#[xX][0-9a-fA-F]{1,6}|#\d{1,7}|[a-z]+);/g, (whole, ref: string) => {
    const code = ref.startsWith('#')
      ? /^#[xX]/.test(ref)
        ? Number.parseInt(ref.slice(2), 16)
        : Number(ref.slice(1))
      : null;
    if (code === null) return ENTITIES[ref] ?? whole;
    return code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

function attribute(tag: string, name: string): string | null {
  const match = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  if (!match) return null;
  return decodeEntities(match[1] ?? match[2] ?? match[3] ?? '');
}

/**
 * The form whose `id` (or, failing that, `name`) is `id`: its `action` and the name and value of
 * each `input` in it, HTML entities decoded. Keycloak's login form is `kc-form-login`; its SAML
 * POST page's form is `saml-post-binding`, with `SAMLResponse` and `RelayState` inputs.
 */
export function formOf(html: string, id: string, base?: string): Form {
  const forms = [...html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)].map((m) => m[0]);
  const open = (form: string) => /<form\b[^>]*>/i.exec(form)?.[0] ?? '';
  const form =
    forms.find((f) => attribute(open(f), 'id') === id) ??
    forms.find((f) => attribute(open(f), 'name') === id);
  if (!form) throw new Error(`no form ${id} on the page`);
  const rawAction = attribute(open(form), 'action') ?? '';
  const action = base === undefined ? rawAction : new URL(rawAction, base).href;
  const fields: Record<string, string> = {};
  for (const [input] of form.matchAll(/<input\b[^>]*>/gi)) {
    const name = attribute(input, 'name');
    if (name !== null) fields[name] = attribute(input, 'value') ?? '';
  }
  return { action, fields };
}

/** Whether a cookie path matches a request path (RFC 6265 §5.1.4). */
function pathMatches(cookiePath: string, requestPath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath.charAt(cookiePath.length) === '/';
}

/** The default path of a cookie set without one (RFC 6265 §5.1.4). */
function defaultPath(requestPath: string): string {
  const slash = requestPath.lastIndexOf('/');
  return slash <= 0 ? '/' : requestPath.slice(0, slash);
}

export class TinyBrowser {
  /** host → `name path` → cookie. */
  private readonly jar = new Map<string, Map<string, Cookie>>();

  /** The cookies kept for `host` (`127.0.0.1:8080`). */
  cookies(host: string): Cookie[] {
    return [...(this.jar.get(host)?.values() ?? [])];
  }

  /** The value of the cookie `name` kept for `host`, or undefined. */
  cookie(host: string, name: string): string | undefined {
    return this.cookies(host).find((c) => c.name === name)?.value;
  }

  get(url: string): Promise<Page> {
    return this.request(url, { method: 'GET' });
  }

  postForm(url: string, fields: Record<string, string>): Promise<Page> {
    return this.request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
  }

  private async request(
    url: string,
    init: { method: string; headers?: Record<string, string>; body?: string },
  ): Promise<Page> {
    const target = new URL(url);
    const cookie = this.cookies(target.host)
      .filter((c) => pathMatches(c.path, target.pathname))
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');
    const res = await fetch(target, {
      method: init.method,
      redirect: 'manual',
      headers: { ...init.headers, ...(cookie ? { cookie } : {}) },
      body: init.body,
    });
    this.store(target, res.headers.getSetCookie());
    const location = res.headers.get('location');
    return {
      url: target.href,
      status: res.status,
      location: location === null ? null : new URL(location, target).href,
      body: await res.text(),
    };
  }

  private store(target: URL, headers: string[]): void {
    let jar = this.jar.get(target.host);
    if (!jar) {
      jar = new Map();
      this.jar.set(target.host, jar);
    }
    for (const header of headers) {
      const [pair = '', ...attributes] = header.split(';');
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      let path = defaultPath(target.pathname);
      let expired = false;
      for (const attr of attributes) {
        const [key = '', ...rest] = attr.split('=');
        const k = key.trim().toLowerCase();
        const v = rest.join('=').trim();
        if (k === 'path' && v.startsWith('/')) path = v;
        if (k === 'max-age' && Number(v) <= 0) expired = true;
        if (k === 'expires' && Date.parse(v) <= Date.now()) expired = true;
      }
      const key = `${name} ${path}`;
      if (expired || value === '') jar.delete(key);
      else jar.set(key, { name, value, path });
    }
  }
}
