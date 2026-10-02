import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { ApiError, isProblem } from '../api/errors';
import type { AuthMethods, Me } from '../api/types';
import { SessionStore } from './session';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly router = inject(Router);
  private loading: Promise<Me | null> | null = null;

  /**
   * The current user, asking the server only when it is not known yet (guards call this). Rejects
   * when the server cannot answer; nothing is cached then, so the next navigation asks again.
   */
  ensureLoaded(): Promise<Me | null> {
    const known = this.session.me();
    if (known !== undefined) return Promise.resolve(known);
    this.loading ??= this.refresh().finally(() => {
      this.loading = null;
    });
    return this.loading;
  }

  /**
   * `GET /auth/me`: the user, their memberships and the CSRF token; null when signed out (401).
   * A network error or any other answer (a 5xx while the server restarts) says nothing about the
   * session, so it throws and leaves the session as it was instead of signing the user out.
   *
   * Signed out, the browser itself logs the 401 of this request in the console ("Failed to load
   * resource … 401"); the app cannot suppress it. The e2e console-error guard (plan 1F Task 4)
   * must allow exactly that message for `GET /api/v0/auth/me`, and nothing else.
   */
  async refresh(): Promise<Me | null> {
    const { data, error, response } = await this.api.client.GET('/api/v0/auth/me');
    if (response.status === 401) {
      this.session.set(null);
      return null;
    }
    if (!response.ok || !data) {
      throw new ApiError(response.status, isProblem(error) ? error : null);
    }
    this.session.set(data);
    return data;
  }

  /**
   * `GET /auth/methods` (public, sso-scim.md §10): whether everyone may sign in with a password
   * and the enabled SSO providers. Rejects when the server cannot answer (an older server has no
   * such route); the sign-in page then shows only the password form.
   */
  methods(): Promise<AuthMethods> {
    return ok(this.api.client.GET('/api/v0/auth/methods'));
  }

  async login(username: string, password: string): Promise<Me | null> {
    await done(this.api.client.POST('/api/v0/auth/login', { body: { username, password } }));
    return this.refresh();
  }

  /** `POST /auth/demo` (public): signs in to the read-only demo, without a password. */
  async demo(): Promise<Me | null> {
    await done(this.api.client.POST('/api/v0/auth/demo'));
    return this.refresh();
  }

  async logout(): Promise<void> {
    try {
      await done(this.api.client.POST('/api/v0/auth/logout'));
    } catch {
      // The server could not end its session (it expires on its own); this browser's ends anyway.
    } finally {
      this.session.clear();
      await this.router.navigateByUrl('/login');
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await done(
      this.api.client.PUT('/api/v0/auth/me/password', { body: { currentPassword, newPassword } }),
    );
    try {
      await this.refresh();
    } catch {
      // The password did change; forget the stale session so the next guard asks the server again.
      this.session.me.set(undefined);
    }
  }
}
