import type { Routes } from '@angular/router';

/** Children of `/settings` (SettingsPage). */
export const settingsRoutes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'tokens' },
  {
    path: 'tokens',
    title: $localize`:@@title.tokens:Access tokens`,
    loadComponent: () => import('./tokens.page').then((m) => m.TokensPage),
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
    path: 'ai',
    title: $localize`:@@title.ai:AI assistant`,
    loadComponent: () => import('./ai.page').then((m) => m.AiSettingsPage),
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
    path: 'ee/:id',
    title: $localize`:@@title.extension:Enterprise`,
    loadComponent: () => import('./extension.page').then((m) => m.ExtensionPage),
  },
];
