import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { Api, done, ok } from './api';
import { ApiError, isRetryable, problemMessage } from './errors';

describe('Api', () => {
  let server: FakeServer;
  let api: Api;
  let router: Router;
  let session: SessionStore;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    api = TestBed.inject(Api);
    router = TestBed.inject(Router);
    session = TestBed.inject(SessionStore);
    session.set(me());
  });

  it('sends the CSRF token on mutations only (ruling R13)', async () => {
    server.on('GET', '/api/v0/organizations', { body: { items: [], nextCursor: null } });
    server.on('POST', '/api/v0/auth/logout', { status: 204 });
    await ok(api.client.GET('/api/v0/organizations'));
    await done(api.client.POST('/api/v0/auth/logout'));
    expect(server.requests.map((r) => [r.method, r.headers.get('x-qualor-csrf')])).toEqual([
      ['GET', null],
      ['POST', 'csrf-token'],
    ]);
  });

  it('ends the session and opens the login page with a return URL on a 401', async () => {
    await router.navigateByUrl('/projects/p1/issues?status=open');
    server.on('GET', '/api/v0/organizations', {
      status: 401,
      body: problem(401, 'UNAUTHENTICATED'),
    });
    await expect(ok(api.client.GET('/api/v0/organizations'))).rejects.toBeInstanceOf(ApiError);
    await settle();
    expect(session.me()).toBeNull();
    expect(router.url).toBe('/login?returnUrl=%2Fprojects%2Fp1%2Fissues%3Fstatus%3Dopen');
  });

  it('keeps the first return URL when several requests fail with 401', async () => {
    await router.navigateByUrl('/projects?q=pay');
    server.on('GET', '/api/v0/organizations', {
      status: 401,
      body: problem(401, 'UNAUTHENTICATED'),
    });
    const first = ok(api.client.GET('/api/v0/organizations')).catch(() => null);
    const second = ok(api.client.GET('/api/v0/organizations')).catch(() => null);
    await Promise.all([first, second]);
    await settle();
    expect(router.url).toBe('/login?returnUrl=%2Fprojects%3Fq%3Dpay');
  });

  it('treats a 401 of the auth endpoints as an answer, not an expired session', async () => {
    await router.navigateByUrl('/somewhere');
    server.on('POST', '/api/v0/auth/login', {
      status: 401,
      body: problem(401, 'INVALID_CREDENTIALS'),
    });
    const failure = await done(
      api.client.POST('/api/v0/auth/login', { body: { username: 'a', password: 'b' } }),
    ).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe('INVALID_CREDENTIALS');
    expect(router.url).toBe('/somewhere');
    expect(session.me()).not.toBeNull();
  });

  it('opens the password change on 403 PASSWORD_CHANGE_REQUIRED (ruling R7)', async () => {
    server.on('GET', '/api/v0/organizations', {
      status: 403,
      body: problem(403, 'PASSWORD_CHANGE_REQUIRED'),
    });
    await expect(ok(api.client.GET('/api/v0/organizations'))).rejects.toBeInstanceOf(ApiError);
    await settle();
    expect(router.url).toBe('/change-password');
  });

  it('describes errors by code, never with the server text', () => {
    expect(problemMessage(new ApiError(409, problem(409, 'BUILTIN_READ_ONLY')))).toBe(
      'Built-in items cannot be changed. Copy it to make your own.',
    );
    expect(problemMessage(new ApiError(418, null))).toBe('The request failed (HTTP 418, -).');
    expect(problemMessage(new TypeError('Failed to fetch'))).toContain('could not be reached');
  });

  it('says why a change to the licence failed (enterprise.md §9.2)', () => {
    expect(
      problemMessage(new ApiError(409, problem(409, 'LICENSE_MANAGED_BY_ENVIRONMENT'))),
    ).toContain('QUALOR_LICENSE');
    expect(problemMessage(new ApiError(403, problem(403, 'FEATURE_NOT_LICENSED')))).toBe(
      'This feature needs an active Qualor Enterprise licence.',
    );
  });

  it('falls back to the generic text for an unknown 409 code', () => {
    // ORG_READ_ONLY is no longer special (enterprise.md §8): the server's sentence stays unshown.
    const stale = {
      ...problem(409, 'ORG_READ_ONLY'),
      detail: 'server detail',
      organizationLimit: 3,
    };
    expect(problemMessage(new ApiError(409, stale))).toBe(
      'The request failed (HTTP 409, ORG_READ_ONLY).',
    );
  });

  it('keeps Retry-After of a 503 CONCURRENCY_CONFLICT and says when to retry', async () => {
    server.on('POST', '/api/v0/issues/bulk-transition', {
      status: 503,
      headers: { 'retry-after': '3' },
      body: problem(503, 'CONCURRENCY_CONFLICT'),
    });
    const failure = await ok(
      api.client.POST('/api/v0/issues/bulk-transition', {
        body: { ids: ['0190a6c2-0000-7000-8000-000000000001'], to: 'resolved' },
      }),
    ).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(ApiError);
    const error = failure as ApiError;
    expect(error.retryAfter).toBe(3);
    expect(isRetryable(error)).toBe(true);
    expect(problemMessage(error)).toBe(
      'An analysis is updating these issues right now, so nothing was changed. Try again in 3 s.',
    );
    // No or a malformed Retry-After: still retryable, without a promised delay.
    const bare = new ApiError(503, problem(503, 'CONCURRENCY_CONFLICT'));
    expect(bare.retryAfter).toBeNull();
    expect(problemMessage(bare)).toBe(
      'An analysis is updating these issues right now, so nothing was changed. Try again in a moment.',
    );
    expect(isRetryable(new ApiError(409, problem(409, 'INVALID_TRANSITION')))).toBe(false);
    expect(new ApiError(503, null, 'soon').retryAfter).toBeNull();
    expect(new ApiError(503, null, '-2').retryAfter).toBeNull();
  });
});
