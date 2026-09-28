import { Component, computed, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { SystemInfo } from '../shell/system-info';

/** The enterprise settings entries the UI renders with its own screens (rbac-audit.md §17). */
const KNOWN_EXTENSIONS = new Set([
  'audit-log',
  'audit-settings',
  'linked-accounts',
  'sso',
  'sign-in',
  'scim',
]);

/**
 * Settings (plan 1F ruling Y7): personal tokens for everyone, users for instance admins, members
 * for those whose role lists `org.members.read` (rbac-audit.md §17), webhooks and SCM connections
 * (plan 2A, scm.md §2) for those whose role manages them; the licence and the plugins' entries
 * (enterprise.md §10.4, §11) for instance admins. The audit log (feature `audit-log`) is also
 * listed for org admins, whose role has `org.audit.read`; the entries the UI knows carry its own
 * labels. Linked accounts (feature `sso`, sso-scim.md §18) are listed for every user. The tabs
 * only hide what a user cannot use; each page checks the role again and the server decides.
 */
@Component({
  selector: 'q-settings-page',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './settings.page.html',
})
export class SettingsPage {
  private readonly session = inject(SessionStore);
  protected readonly org = inject(OrgContext);
  /** Plugin settings entries (enterprise.md §10.4); listed only while their feature is active. */
  protected readonly info = inject(SystemInfo);
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  private readonly ids = computed(() => new Set(this.info.extensions().map((e) => e.id)));
  protected readonly auditLog = computed(
    () => this.ids().has('audit-log') && (this.instanceAdmin() || this.org.can('org.audit.read')),
  );
  protected readonly auditSettings = computed(
    () => this.ids().has('audit-settings') && this.instanceAdmin(),
  );
  /** Every user's own SSO identities (sso-scim.md §18), while `sso` is active. */
  protected readonly linkedAccounts = computed(() => this.ids().has('linked-accounts'));
  /** Single sign-on, sign-in and SCIM (sso-scim.md §18): instance admins, while licensed. */
  protected readonly sso = computed(() => this.ids().has('sso') && this.instanceAdmin());
  protected readonly signIn = computed(() => this.ids().has('sign-in') && this.instanceAdmin());
  protected readonly scim = computed(() => this.ids().has('scim') && this.instanceAdmin());
  /** The entries of plugins the UI has no screen for (enterprise.md §10.4). */
  protected readonly otherExtensions = computed(() =>
    this.info.extensions().filter((e) => !KNOWN_EXTENSIONS.has(e.id)),
  );
}
