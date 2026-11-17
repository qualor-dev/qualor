import { Component, computed, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { PageHeader } from '../shared/page-header';
import { LICENSE_POLICY_FEATURE } from './license-policy';
import { SystemInfo } from '../shell/system-info';

/** The enterprise settings entries the UI renders with its own screens (rbac-audit.md §17). */
const KNOWN_EXTENSIONS = new Set([
  'audit-log',
  'audit-settings',
  'linked-accounts',
  'sso',
  'sign-in',
  'scim',
  'compliance',
  'support',
]);

/**
 * Settings (plan 1F ruling Y7): personal tokens and connected apps (6N spec §8) for everyone, users
 * and MCP for instance admins, members for those whose role lists `org.members.read` (rbac-audit.md
 * §17), webhooks and SCM connections (plan 2A, scm.md §2) for those whose role manages them; the
 * licence and the plugins' entries (enterprise.md §10.4, §11) for instance admins. The audit log
 * (feature `audit-log`) is also listed for org admins, whose role has `org.audit.read`, and the
 * compliance reports (feature `compliance-export`, 4E-1 §4) for the organisation's members; the
 * entries the UI knows carry its own labels. Only `settings.nav` entries are listed here, never a
 * plugin's project tab. Linked accounts (feature `sso`, sso-scim.md §18) are listed for every user.
 * The navigation only hides what a user cannot use; each page checks the role again and the server
 * decides. Its entries sit under Your account, Organization and Instance (UI redesign spec §7.8); a
 * group with nothing to show is left out.
 */
@Component({
  selector: 'q-settings-page',
  imports: [PageHeader, RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './settings.page.html',
  styleUrl: './settings.page.css',
  host: { class: 'bleed' },
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
  /** The support bundle (4E-3b §5): instance admins, while `support-bundle` is active. */
  protected readonly support = computed(() => this.ids().has('support') && this.instanceAdmin());
  /**
   * The organisation's compliance reports (4E-1 §4): for its members (an organisation role, which
   * always holds `org.read`) and instance admins, while `compliance-export` is active.
   */
  protected readonly compliance = computed(
    () => this.ids().has('compliance') && this.org.can('org.read'),
  );
  /**
   * The organisation's AI (spec §3.5): AI review, the assistant and, with the Enterprise plan, the
   * automatic fix suggestions, for holders of `org.ai.manage`, in every edition. The page itself
   * says when the instance has no AI provider or the organisation is not enabled.
   */
  protected readonly aiReview = computed(() => this.org.can('org.ai.manage'));
  /** The organisation's Jira connection (Jira 0.16 §6.1): for holders of `org.jira.manage`. */
  protected readonly jira = computed(() => this.org.can('org.jira.manage'));
  /**
   * The organisation's licence policy (6M §8): for holders of `org.licenses.manage`, while
   * `license-policy` is active; the address itself shows the Business note when it is not.
   */
  protected readonly licensePolicy = computed(
    () =>
      this.info.features().includes(LICENSE_POLICY_FEATURE) && this.org.can('org.licenses.manage'),
  );
  /**
   * The organization's entries: members, webhooks, the SCM connections, AI (spec §3.5), the
   * licence policy (6M §8), the audit log and the compliance reports.
   */
  protected readonly organization = computed(
    () =>
      this.org.can('org.members.read') ||
      this.org.can('org.webhooks.manage') ||
      this.org.can('org.scm.manage') ||
      this.jira() ||
      this.aiReview() ||
      this.licensePolicy() ||
      this.auditLog() ||
      this.compliance(),
  );
  /** The entries of plugins the UI has no screen for (enterprise.md §10.4). */
  protected readonly otherExtensions = computed(() =>
    this.info.extensions().filter((e) => !KNOWN_EXTENSIONS.has(e.id)),
  );
}
