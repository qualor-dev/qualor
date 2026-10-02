import type { Provider } from '@angular/core';
import { FETCH } from '../app/api/api';
import type { Me } from '../app/api/types';

export interface RecordedRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export interface FakeReply {
  status?: number;
  body?: unknown;
  /** Response headers (for example `retry-after`). */
  headers?: Record<string, string>;
}

/** A reply, or a function of the request; a promise lets a test hold an answer back. */
type Responder = FakeReply | ((request: RecordedRequest) => FakeReply | Promise<FakeReply>);

/**
 * A stand-in for the server in component tests: answers `fetch` by method and path, records
 * every request, and answers anything unexpected with the API's 404 problem.
 */
export class FakeServer {
  readonly requests: RecordedRequest[] = [];
  private readonly routes: { method: string; path: string; responder: Responder }[] = [];

  on(method: string, path: string, responder: Responder): this {
    this.routes.unshift({ method, path, responder });
    return this;
  }

  requestsTo(method: string, path: string): RecordedRequest[] {
    return this.requests.filter((r) => r.method === method && r.path === path);
  }

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const text = request.method === 'GET' ? '' : await request.text();
    const recorded: RecordedRequest = {
      method: request.method,
      path: url.pathname,
      query: url.searchParams,
      headers: request.headers,
      body: text ? (JSON.parse(text) as unknown) : undefined,
    };
    this.requests.push(recorded);
    const route = this.routes.find((r) => r.method === request.method && r.path === url.pathname);
    const reply: FakeReply = route
      ? typeof route.responder === 'function'
        ? await route.responder(recorded)
        : route.responder
      : { status: 404, body: problem(404, 'NOT_FOUND') };
    const status = reply.status ?? 200;
    const headers = reply.headers ?? {};
    if (status === 204 || reply.body === undefined) return new Response(null, { status, headers });
    return new Response(JSON.stringify(reply.body), {
      status,
      headers: {
        'content-type': status >= 400 ? 'application/problem+json' : 'application/json',
        ...headers,
      },
    });
  };
}

export function problem(
  status: number,
  code: string,
  errors?: { path: string; message: string }[],
) {
  return {
    type: `urn:qualor:problem:${code.toLowerCase().replaceAll('_', '-')}`,
    title: code,
    status,
    code,
    ...(errors ? { errors } : {}),
  };
}

export function provideFakeServer(server: FakeServer): Provider[] {
  return [{ provide: FETCH, useValue: server.fetch }];
}

export const ORG_ID = '0190a6c2-0000-7000-8000-000000000001';

/** An organisation admin's permissions, as `GET /auth/me` lists them (rbac-audit.md §3.2). */
export const ORG_ADMIN_PERMISSIONS = [
  'org.audit.read',
  'org.gates.manage',
  'org.members.manage',
  'org.members.read',
  'org.profiles.manage',
  'org.projects.create',
  'org.read',
  'org.scm.manage',
  'org.webhooks.manage',
] as const;

/** A maintainer's (`member`) permissions on a project, as the project DTO lists them (§3.2). */
export const MEMBER_PROJECT_PERMISSIONS = [
  'ai.use',
  'issue.triage',
  'project.analyze',
  'project.read',
] as const;

/** A viewer's permissions on a project: reading only. */
export const VIEWER_PROJECT_PERMISSIONS = ['project.read'] as const;

export function me(
  overrides: { passwordChangeRequired?: boolean; admin?: boolean; demo?: boolean } = {},
): Me {
  return {
    user: {
      id: '0190a6c2-0000-7000-8000-00000000000a',
      username: 'alice',
      displayName: 'Alice',
      email: null,
      isInstanceAdmin: overrides.admin ?? false,
      active: true,
      passwordChangeRequired: overrides.passwordChangeRequired ?? false,
      hasPassword: true,
      sso: { identities: 0, scim: false },
      lastLoginAt: null,
      createdAt: '2026-09-01T00:00:00.000Z',
    },
    memberships: [
      {
        organizationId: ORG_ID,
        organizationKey: 'default',
        organizationName: 'Default',
        role: overrides.admin ? 'admin' : 'member',
        permissions: overrides.admin ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
      },
    ],
    projectGrants: [],
    csrfToken: 'csrf-token',
    demo: overrides.demo ?? false,
  };
}

export function page<T>(items: T[], nextCursor: string | null = null) {
  return { items, nextCursor };
}

/** Lets pending fetches, navigations and change detection finish (the fake fetch is async). */
export async function settle(fixture?: { whenStable(): Promise<unknown> }): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve));
    await fixture?.whenStable();
  }
}

/**
 * A secret field (an API key, a token, a webhook secret) that password managers must neither fill
 * nor offer to save: `data-1p-ignore` (1Password) and `data-lpignore` (LastPass); a password
 * input also has `autocomplete="new-password"`, which browsers honour where they ignore `off`.
 */
export function expectNoPasswordManager(field: Element): void {
  expect(field.hasAttribute('data-1p-ignore')).toBe(true);
  expect(field.getAttribute('data-lpignore')).toBe('true');
  if (field instanceof HTMLInputElement && field.type === 'password') {
    expect(field.getAttribute('autocomplete')).toBe('new-password');
  }
}
