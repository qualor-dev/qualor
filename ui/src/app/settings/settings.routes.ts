import { inject } from '@angular/core';
import { Router, type Routes } from '@angular/router';
import { unsavedChangesGuard } from '../shared/unsaved-changes';

/** Children of `/settings` (SettingsPage). */
export const settingsRoutes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'tokens' },
  {
    path: 'tokens',
    title: $localize`:@@title.tokens:Access tokens`,
    loadComponent: () => import('./tokens.page').then((m) => m.TokensPage),
  },
  {
    // Plan 2a: where the vulnerability database comes from and its state, for instance admins.
    // Leaving it with unsaved edits asks first.
    path: 'vulnerability-db',
    title: $localize`:@@title.vulnerabilityDb:Vulnerability database`,
    canDeactivate: [unsavedChangesGuard],
    loadComponent: () => import('./vulnerability-db.page').then((m) => m.VulnerabilityDbPage),
  },
  {
    // 6N spec §8: the MCP clients you connected (OAuth grants).
    path: 'connected-apps',
    title: $localize`:@@title.connectedApps:Connected apps`,
    loadComponent: () => import('./connected-apps.page').then((m) => m.ConnectedAppsPage),
  },
  {
    path: 'notifications',
    title: $localize`:@@title.notifications:Notifications`,
    loadComponent: () => import('./notifications.page').then((m) => m.NotificationsPage),
  },
  {
    path: 'organizations',
    title: $localize`:@@title.organizations:Organizations`,
    loadComponent: () => import('./organizations.page').then((m) => m.OrganizationsPage),
  },
  {
    path: 'users',
    title: $localize`:@@title.users:Users`,
    loadComponent: () => import('./users.page').then((m) => m.UsersPage),
  },
  {
    path: 'members',
    title: $localize`:@@title.members:Members`,
    loadComponent: () => import('./members.page').then((m) => m.MembersPage),
  },
  {
    path: 'webhooks',
    title: $localize`:@@title.webhooks:Webhooks`,
    loadComponent: () => import('./webhooks.page').then((m) => m.WebhooksPage),
  },
  {
    path: 'gitlab',
    title: $localize`:@@title.gitlab:GitLab`,
    loadComponent: () => import('./gitlab.page').then((m) => m.GitLabPage),
  },
  {
    path: 'github',
    title: $localize`:@@title.github:GitHub`,
    loadComponent: () => import('./github.page').then((m) => m.GitHubPage),
  },
  {
    path: 'repositories',
    title: $localize`:@@title.repositories:Repositories`,
    loadComponent: () => import('./repositories.page').then((m) => m.RepositoriesPage),
  },
  {
    // The organisation's AI (spec §3.5): AI review and its data-sharing confirmation, the
    // assistant read-only and, with the Enterprise plan, the automatic fix suggestions, for its
    // admins (org.ai.manage), in every edition. Leaving it with unsaved edits asks first.
    path: 'ai-review',
    title: $localize`:@@title.orgAi:AI`,
    canDeactivate: [unsavedChangesGuard],
    loadComponent: () => import('./ai-review.page').then((m) => m.AiReviewPage),
  },
  {
    // The automatic fix suggestions' own page became a section of the organisation's AI page;
    // links and bookmarks to it lead there.
    path: 'auto-fix',
    redirectTo: () =>
      inject(Router).createUrlTree(['/settings/ai-review'], { fragment: 'fix-suggestions' }),
  },
  {
    // 6M §8: the organisation's licence policy, for its admins (org.licenses.manage).
    path: 'license-policy',
    title: $localize`:@@title.licensePolicy:Licence policy`,
    loadComponent: () => import('./license-policy.page').then((m) => m.LicensePolicyPage),
  },
  {
    // The instance's AI provider (spec §3.4): the provider, the organisations that may use it,
    // the limits, and the data sent, for instance admins. Leaving it with unsaved edits asks first.
    path: 'ai',
    title: $localize`:@@title.aiProvider:AI provider`,
    canDeactivate: [unsavedChangesGuard],
    loadComponent: () => import('./ai.page').then((m) => m.AiSettingsPage),
  },
  {
    path: 'email',
    title: $localize`:@@title.email:Email`,
    loadComponent: () => import('./email.page').then((m) => m.EmailSettingsPage),
  },
  {
    // 6N spec §8: the MCP endpoint and which OAuth clients may connect (instance admins).
    path: 'mcp',
    title: $localize`:@@title.mcp:MCP`,
    loadComponent: () => import('./mcp.page').then((m) => m.McpPage),
  },
  {
    path: 'license',
    title: $localize`:@@title.license:Licence`,
    loadComponent: () => import('./license.page').then((m) => m.LicensePage),
  },
  {
    // rbac-audit.md §17: the enterprise entries the UI knows render its own screens.
    path: 'ee/audit-log',
    title: $localize`:@@title.auditLog:Audit log`,
    loadComponent: () => import('./audit-log.page').then((m) => m.AuditLogPage),
  },
  {
    path: 'ee/audit-settings',
    title: $localize`:@@title.auditSettings:Audit settings`,
    loadComponent: () => import('./audit-settings.page').then((m) => m.AuditSettingsPage),
  },
  {
    // sso-scim.md §18: every user's own identities, while `sso` is active.
    path: 'ee/linked-accounts',
    title: $localize`:@@title.linkedAccounts:Linked accounts`,
    loadComponent: () => import('./linked-accounts.page').then((m) => m.LinkedAccountsPage),
  },
  {
    // sso-scim.md §18: the single sign-on, sign-in and SCIM screens (instance admins).
    path: 'ee/sso',
    title: $localize`:@@title.sso:Single sign-on`,
    loadComponent: () => import('./sso.page').then((m) => m.SsoPage),
  },
  {
    path: 'ee/sign-in',
    title: $localize`:@@title.signIn:Sign-in`,
    loadComponent: () => import('./sign-in.page').then((m) => m.SignInSettingsPage),
  },
  {
    path: 'ee/scim',
    title: $localize`:@@title.scim:SCIM`,
    loadComponent: () => import('./scim.page').then((m) => m.ScimPage),
  },
  {
    // 4E-1 §4: the organisation's compliance reports, while `compliance-export` is active.
    path: 'ee/compliance',
    title: $localize`:@@title.complianceReports:Compliance reports`,
    loadComponent: () => import('./compliance.page').then((m) => m.SettingsCompliancePage),
  },
  {
    // 4E-3b §5: the support bundle (instance admins), while `support-bundle` is active.
    path: 'ee/support',
    title: $localize`:@@title.support:Support`,
    loadComponent: () => import('./support.page').then((m) => m.SupportPage),
  },
  {
    path: 'ee/:id',
    title: $localize`:@@title.extension:Enterprise`,
    loadComponent: () => import('./extension.page').then((m) => m.ExtensionPage),
  },
];
