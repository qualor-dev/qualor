import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { entraToken, type EntraAuth } from './entra.js';

export type AzureAuth =
  | { kind: 'pat'; pat: string }
  | { kind: 'secret'; tenantId: string; clientId: string; secret: string }
  | {
      kind: 'certificate';
      tenantId: string;
      clientId: string;
      certificatePem: string;
      keyPem: string;
    };

export class AzureProbeError extends Error {
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.name = 'AzureProbeError';
    this.code = code;
  }
}

export type AzureResponse = { status: number; headers: Record<string, string>; json: unknown };

export type RawResponse = { status: number; headers: Record<string, string>; text: string };

/**
 * One HTTP request with exactly the given headers (none added, redirects not followed). The
 * client sends through it; probe items use it directly for calls the client cannot express: no
 * credential at all, or a HEAD of a web page.
 */
// node:http(s) rather than fetch: Node's fetch cannot take a private CA without undici,
// which is not a dependency of this repository. Certificate checks stay on.
export function rawRequest(
  method: string,
  url: URL,
  headers: Record<string, string>,
  body?: string,
  opts: { caPem?: string; timeoutMs?: number } = {},
): Promise<RawResponse> {
  const doRequest = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = doRequest(
      url,
      { method, headers, ...(opts.caPem ? { ca: opts.caPem } : {}) },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const h: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) h[k] = Array.isArray(v) ? v.join(', ') : v;
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: h,
            text: Buffer.concat(chunks).toString('utf8'),
          });
        });
        res.on('error', reject);
      },
    );
    req.setTimeout(opts.timeoutMs ?? 60_000, () => {
      req.destroy(
        new AzureProbeError(
          'timeout',
          `no answer within the timeout for ${method} ${url.pathname}`,
        ),
      );
    });
    req.on('error', reject);
    req.end(body);
  });
}

const MAX_WAIT_S = 30;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class AzureClient {
  private notBefore = 0;
  private bearer: { token: string; expiresAt: number } | undefined;

  constructor(
    private readonly baseUrl: string,
    private readonly auth: AzureAuth,
    private readonly opts: { caPem?: string; fetch?: typeof fetch; timeoutMs?: number } = {},
  ) {}

  private async authorization(): Promise<string> {
    if (this.auth.kind === 'pat') {
      return `Basic ${Buffer.from(`:${this.auth.pat}`).toString('base64')}`;
    }
    if (!this.bearer || this.bearer.expiresAt - 60_000 <= Date.now()) {
      const entraOpts = this.opts.fetch ? { fetch: this.opts.fetch } : {};
      this.bearer = await entraToken(this.auth as EntraAuth, entraOpts);
    }
    return `Bearer ${this.bearer.token}`;
  }

  private send(
    method: string,
    url: URL,
    headers: Record<string, string>,
    body?: string,
  ): Promise<RawResponse> {
    return rawRequest(method, url, headers, body, {
      ...(this.opts.caPem ? { caPem: this.opts.caPem } : {}),
      timeoutMs: this.opts.timeoutMs ?? 60_000,
    });
  }

  async request(
    method: string,
    path: string,
    body?: unknown,
    opts: { apiVersion?: string; contentType?: string } = {},
  ): Promise<AzureResponse> {
    const url = new URL(this.baseUrl.replace(/\/+$/, '') + path);
    if (!url.searchParams.has('api-version')) {
      url.searchParams.set('api-version', opts.apiVersion ?? '7.0');
    }
    const payload =
      body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const headers: Record<string, string> = {
      authorization: await this.authorization(),
      accept: 'application/json',
    };
    if (payload !== undefined) {
      headers['content-type'] = opts.contentType ?? 'application/json';
      headers['content-length'] = String(Buffer.byteLength(payload));
    }

    const wait = this.notBefore - Date.now();
    if (wait > 0) await sleep(wait);
    let raw = await this.send(method, url, headers, payload);
    const retryAfter = Number(raw.headers['retry-after']);
    const hasRetryAfter = Number.isFinite(retryAfter) && retryAfter > 0;
    if (raw.status === 429 && hasRetryAfter) {
      await sleep(Math.min(retryAfter, MAX_WAIT_S) * 1000);
      raw = await this.send(method, url, headers, payload);
    } else if (raw.status >= 200 && raw.status < 300 && hasRetryAfter) {
      // The request succeeded: never repeat it, but make the next one wait.
      this.notBefore = Date.now() + Math.min(retryAfter, MAX_WAIT_S) * 1000;
    }

    const html = /text\/html/i.test(raw.headers['content-type'] ?? '');
    if (raw.status >= 200 && raw.status < 300 && html) {
      throw new AzureProbeError(
        'html_answer',
        `HTTP ${raw.status} answered with HTML for ${method} ${path}`,
      );
    }
    let json: unknown = null;
    if (raw.text.length > 0) {
      try {
        json = JSON.parse(raw.text);
      } catch {
        json = raw.text;
      }
    }
    return { status: raw.status, headers: raw.headers, json };
  }
}
