import { Injectable, computed, signal } from '@angular/core';
import type { Me } from '../api/types';
import { can } from './permissions';

/**
 * Who is signed in: `undefined` until `GET /auth/me` has answered, `null` when nobody is. Kept
 * apart from the AuthService so the API client can read the CSRF token and end the session
 * without a dependency cycle.
 */
@Injectable({ providedIn: 'root' })
export class SessionStore {
  readonly me = signal<Me | null | undefined>(undefined);
  readonly user = computed(() => this.me()?.user ?? null);
  readonly csrfToken = computed(() => this.me()?.csrfToken ?? null);
  /** Signed in to the read-only demo (QUALOR_DEMO_USER): the server refuses every change. */
  readonly demo = computed(() => this.me()?.demo === true);

  set(me: Me | null): void {
    this.me.set(me);
  }

  clear(): void {
    this.me.set(null);
  }

  /**
   * Instance admins administer every organisation; others where their membership says admin. The
   * role is `null` for an organisation seen only through a project grant, which is never admin.
   */
  isOrgAdmin(organizationId: string | null | undefined): boolean {
    const me = this.me();
    if (!me || !organizationId) return false;
    if (me.user.isInstanceAdmin) return true;
    return me.memberships.some((m) => m.organizationId === organizationId && m.role === 'admin');
  }

  /**
   * Whether the caller sees every project of an organisation (server auth/facts.ts
   * `visibleProjectsCondition`): instance admins and anyone holding a role in it. A project grant
   * alone (role `null`) shows only the granted projects.
   */
  seesWholeOrg(organizationId: string | null | undefined): boolean {
    const me = this.me();
    if (!me || !organizationId) return false;
    if (me.user.isInstanceAdmin) return true;
    return me.memberships.some((m) => m.organizationId === organizationId && m.role !== null);
  }

  /**
   * Whether the caller's role in an organisation allows a permission (rbac-audit.md §3.1): the
   * membership's effective `permissions` of `GET /auth/me`; an instance admin has every one.
   */
  orgCan(organizationId: string | null | undefined, permission: string): boolean {
    const me = this.me();
    if (!me || !organizationId) return false;
    if (me.user.isInstanceAdmin) return true;
    return can(
      me.memberships.find((m) => m.organizationId === organizationId)?.permissions,
      permission,
    );
  }
}
