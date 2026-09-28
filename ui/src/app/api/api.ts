import { DOCUMENT, Injectable, InjectionToken, inject } from '@angular/core';
import { Router } from '@angular/router';
import createClient, { type Client, type Middleware } from 'openapi-fetch';
import { SessionStore } from '../auth/session';
import { ApiError, isProblem } from './errors';
import type { paths } from './schema';

/** The fetch the client uses; tests replace it. */
export const FETCH = new InjectionToken<typeof fetch>('FETCH', {
  providedIn: 'root',
  factory: () => (input, init) => fetch(input, init),
});

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
/** Where a 401 is an answer, not an expired session. */
const AUTH_PATHS = new Set(['/api/v0/auth/login', '/api/v0/auth/me']);

/**
 * The generated OpenAPI client (openapi-fetch over `schema.ts`), same origin, cookie session.
 * Every mutation carries `X-Qualor-CSRF` from `GET /auth/me` (api.md §2, ruling R13); a 401
 * anywhere but the auth endpoints ends the session and opens the login page with a return URL;
 * a 403 `PASSWORD_CHANGE_REQUIRED` opens the password change (ruling R7).
 */
@Injectable({ providedIn: 'root' })
export class Api {
  private readonly session = inject(SessionStore);
  private readonly router = inject(Router);
  private readonly fetchImpl = inject(FETCH);

  readonly client: Client<paths> = createClient<paths>({
    baseUrl: inject(DOCUMENT).location.origin,
    fetch: (request) => this.fetchImpl(request),
  });

  /**
   * What every request of the UI goes through, the enterprise client's too (`ee.ts`): the CSRF
   * header on mutations, the end of an expired session, the password change.
   */
  readonly middleware: Middleware = {
    onRequest: ({ request }) => {
      const token = this.session.csrfToken();
      if (!SAFE_METHODS.has(request.method) && token) request.headers.set('X-Qualor-CSRF', token);
      return request;
    },
    onResponse: async ({ request, response }) => {
      if (response.status === 401 && !AUTH_PATHS.has(new URL(request.url).pathname)) {
        this.sessionExpired();
      } else if (response.status === 403) {
        const body: unknown = await response
          .clone()
          .json()
          .catch(() => null);
        if (isProblem(body) && body.code === 'PASSWORD_CHANGE_REQUIRED') {
          void this.router.navigateByUrl('/change-password');
        }
      }
      return undefined;
    },
  };

  constructor() {
    this.client.use(this.middleware);
  }

  private sessionExpired(): void {
    // Requests in flight when the session ended answer 401 too; the first one already navigated,
    // and a second navigation would drop its return URL.
    if (this.session.me() === null) return;
    this.session.clear();
    const current = this.router.url;
    const returnUrl = current === '/' || current.startsWith('/login') ? undefined : current;
    void this.router.navigate(['/login'], { queryParams: returnUrl ? { returnUrl } : {} });
  }
}

interface Answer<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** The body of a 2xx answer; any other answer throws an {@link ApiError}. */
export async function ok<T>(pending: Promise<Answer<T>>): Promise<T> {
  const { data, error, response } = await pending;
  if (!response.ok) {
    throw new ApiError(
      response.status,
      isProblem(error) ? error : null,
      response.headers.get('retry-after'),
    );
  }
  return data as T;
}

/** Like {@link ok}, for answers without a body (204). */
export async function done(
  pending: Promise<{ error?: unknown; response: Response }>,
): Promise<void> {
  const { error, response } = await pending;
  if (!response.ok) {
    throw new ApiError(
      response.status,
      isProblem(error) ? error : null,
      response.headers.get('retry-after'),
    );
  }
}
