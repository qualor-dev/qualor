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
    path: 'code',
    title: $localize`:@@title.code:Code`,
    loadComponent: () => import('./code/code.page').then((m) => m.CodePage),
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
