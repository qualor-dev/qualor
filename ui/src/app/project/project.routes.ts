import type { Routes } from '@angular/router';

/** Children of `/projects/:projectId` (ProjectPage); they receive `projectId` as an input. */
export const projectRoutes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    title: $localize`:@@title.overview:Overview`,
    loadComponent: () => import('./branch-overview.page').then((m) => m.BranchOverviewPage),
  },
  {
    path: 'branches',
    title: $localize`:@@title.branches:Branches and merge requests`,
    loadComponent: () => import('./branches.page').then((m) => m.BranchesPage),
  },
  {
    path: 'issues',
    title: $localize`:@@title.issues:Issues`,
    loadComponent: () => import('../issues/issues.page').then((m) => m.IssuesPage),
  },
  {
    path: 'issues/:issueId',
    title: $localize`:@@title.issue:Issue`,
    loadComponent: () => import('../issues/issue.page').then((m) => m.IssuePage),
  },
  {
    // Vuln 2b §9.3: the tracked branches and versions with their open dependency vulnerabilities.
    path: 'vulnerabilities',
    title: $localize`:@@title.vulnerabilities:Vulnerabilities`,
    loadComponent: () =>
      import('./vulnerabilities/vulnerabilities.page').then((m) => m.VulnerabilitiesPage),
  },
  {
    // 6M §8: the branch's dependency inventory and, with a licence policy, its verdicts.
    path: 'dependencies',
    title: $localize`:@@title.dependencies:Dependencies`,
    loadComponent: () => import('./dependencies/dependencies.page').then((m) => m.DependenciesPage),
  },
  {
    path: 'code',
    title: $localize`:@@title.code:Code`,
    loadComponent: () => import('./code/code.page').then((m) => m.CodePage),
  },
  {
    // spec §4.3: `?branch=&path=` (the path as a query param, never a path segment), `#L<n>`.
    path: 'code/file',
    title: $localize`:@@title.file:File`,
    loadComponent: () => import('./code/file.page').then((m) => m.FilePage),
  },
  {
    // 4E-1 §4: the project's compliance reports, a plugin's project tab (`compliance-export`).
    path: 'compliance',
    title: $localize`:@@title.compliance:Compliance`,
    loadComponent: () => import('./compliance.page').then((m) => m.ProjectCompliancePage),
  },
  {
    // rbac-audit.md §17: the project's role grants, in every edition; the tab is shown to org admins.
    path: 'access',
    title: $localize`:@@title.access:Access`,
    loadComponent: () => import('./access.page').then((m) => m.AccessPage),
  },
  {
    path: 'settings',
    title: $localize`:@@title.projectSettings:Project settings`,
    loadComponent: () =>
      import('./settings/project-settings.page').then((m) => m.ProjectSettingsPage),
  },
  {
    path: 'branches/:branchId',
    title: $localize`:@@title.branch:Branch`,
    loadComponent: () => import('./branch-overview.page').then((m) => m.BranchOverviewPage),
  },
];
