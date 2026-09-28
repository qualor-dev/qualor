import { Injectable, computed, inject, resource, signal } from '@angular/core';
import { Api, ok } from '../api/api';
import { SessionStore } from '../auth/session';
import type { Organization } from '../api/types';

const STORAGE_KEY = 'qualor.organizationId';
const PAGE_SIZE = 100;
/**
 * Pages read at most (100 × 100 organisations): the switcher lists them all, and the organisation
 * chosen earlier may be on any page.
 */
const MAX_PAGES = 100;

function stored(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

/**
 * The organisation the gates, profiles, rules and settings screens work on: the one chosen in the
 * header (remembered in this browser), else the first the user can see. Reloaded when the user
 * changes, so a second sign-in never shows the previous user's organisations.
 */
@Injectable({ providedIn: 'root' })
export class OrgContext {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly chosen = signal<string | null>(stored());

  readonly organizations = resource({
    params: () => this.session.user()?.id,
    loader: () => this.allOrganizations(),
  });

  /**
   * The organisations, or none while loading or after a failed load: `value()` of a resource in
   * the error state throws (Angular 22), so nothing else reads `organizations.value()` directly.
   */
  readonly orgs = computed(() => (this.organizations.hasValue() ? this.organizations.value() : []));

  readonly current = computed(() => {
    const all = this.orgs();
    return all.find((o) => o.id === this.chosen()) ?? all[0] ?? null;
  });
  readonly currentId = computed(() => this.current()?.id ?? null);
  readonly isAdmin = computed(() => this.session.isOrgAdmin(this.currentId()));

  /** Whether the caller's role in the current organisation allows a permission. */
  can(permission: string): boolean {
    return this.session.orgCan(this.currentId(), permission);
  }

  /**
   * Whether the caller may make a change that needs `permission` in an organisation (the current
   * one by default): the role check only, so the button is hidden instead of failing with 403
   * (rbac-audit.md §17). Since 5A a lapse changes no organisation (enterprise.md §8).
   */
  canChange(permission: string, organizationId: string | null = this.currentId()): boolean {
    return this.session.orgCan(organizationId, permission);
  }

  private async allOrganizations(): Promise<Organization[]> {
    const all: Organization[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < MAX_PAGES; i++) {
      const answer: { items: Organization[]; nextCursor: string | null } = await ok(
        this.api.client.GET('/api/v0/organizations', {
          params: { query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) } },
        }),
      );
      all.push(...answer.items);
      if (answer.nextCursor === null || answer.nextCursor === cursor) break;
      cursor = answer.nextCursor;
    }
    return all;
  }

  select(id: string): void {
    this.chosen.set(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // Private mode or blocked storage: the choice lasts for this page only.
    }
  }
}
