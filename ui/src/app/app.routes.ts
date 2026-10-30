import type { Routes } from '@angular/router';
import { requireGuest, requireSession, requireUser } from './auth/guards';
import { NotFoundPage } from './shared/not-found.page';
import { Shell } from './shell/shell';

export const routes: Routes = [
  {
    path: 'login',
    title: $localize`:@@title.login:Sign in`,
    canActivate: [requireGuest],
    loadComponent: () => import('./auth/login.page').then((m) => m.LoginPage),
  },
  {
    path: 'change-password',
    title: $localize`:@@title.changePassword:Change password`,
    canActivate: [requireSession],
    loadComponent: () => import('./auth/change-password.page').then((m) => m.ChangePasswordPage),
  },
  {
    path: 'forgot-password',
    title: $localize`:@@title.forgotPassword:Forgot password`,
    canActivate: [requireGuest],
    loadComponent: () => import('./auth/forgot-password.page').then((m) => m.ForgotPasswordPage),
  },
  {
    // No guard: the link works in any browser; it never signs in (mail E2 A5).
    path: 'reset-password',
    title: $localize`:@@title.resetPassword:Reset password`,
    loadComponent: () => import('./auth/reset-password.page').then((m) => m.ResetPasswordPage),
  },
  {
    path: 'accept-invite',
    title: $localize`:@@title.acceptInvite:Accept invitation`,
    loadComponent: () => import('./auth/accept-invite.page').then((m) => m.AcceptInvitePage),
  },
  {
    // mail E3: an email's stop link; no guard, it works without signing in.
    path: 'unsubscribe',
    title: $localize`:@@title.unsubscribe:Stop emails`,
    loadComponent: () => import('./auth/unsubscribe.page').then((m) => m.UnsubscribePage),
  },
  {
    // Spec §6 step 6: where /oauth/authorize sends the browser; outside the shell, signed in.
    path: 'oauth/consent',
    title: $localize`:@@title.consent:Connect an app`,
    canActivate: [requireUser],
    loadComponent: () => import('./oauth/consent.page').then((m) => m.ConsentPage),
  },
  {
    path: 'unavailable',
    title: $localize`:@@title.unavailable:Server unavailable`,
    loadComponent: () => import('./shared/unavailable.page').then((m) => m.UnavailablePage),
  },
  {
    path: '',
    component: Shell,
    canActivate: [requireUser],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'projects' },
      {
        path: 'projects',
        title: $localize`:@@title.projects:Projects`,
        loadComponent: () => import('./projects/projects.page').then((m) => m.ProjectsPage),
      },
      {
        // Onboarding: add a connection's repositories as projects; `:runId` follows a run. Before
        // `projects/:projectId`, which would take `add` for a project id.
        path: 'projects/add',
        title: $localize`:@@title.addRepositories:Add repositories`,
        loadComponent: () =>
          import('./projects/add-repositories.page').then((m) => m.AddRepositoriesPage),
      },
      {
        path: 'projects/add/:runId',
        title: $localize`:@@title.addRepositories:Add repositories`,
        loadComponent: () =>
          import('./projects/add-repositories.page').then((m) => m.AddRepositoriesPage),
      },
      {
        path: 'projects/:projectId',
        loadComponent: () => import('./project/project.page').then((m) => m.ProjectPage),
        loadChildren: () => import('./project/project.routes').then((m) => m.projectRoutes),
      },
      {
        path: 'gates',
        title: $localize`:@@title.gates:Quality gates`,
        loadComponent: () => import('./gates/gates.page').then((m) => m.GatesPage),
      },
      {
        path: 'gates/:gateId',
        title: $localize`:@@title.gate:Quality gate`,
        loadComponent: () => import('./gates/gate.page').then((m) => m.GatePage),
      },
      {
        path: 'portfolio',
        title: $localize`:@@title.portfolio:Portfolio`,
        loadComponent: () => import('./portfolio/portfolio.page').then((m) => m.PortfolioPage),
      },
      {
        path: 'rules',
        title: $localize`:@@title.rules:Rules`,
        loadComponent: () => import('./rules/rules.page').then((m) => m.RulesPage),
      },
      {
        path: 'profiles',
        title: $localize`:@@title.profiles:Quality profiles`,
        loadComponent: () => import('./rules/profiles.page').then((m) => m.ProfilesPage),
      },
      {
        path: 'profiles/:profileId',
        title: $localize`:@@title.profile:Quality profile`,
        loadComponent: () => import('./rules/profile.page').then((m) => m.ProfilePage),
      },
      {
        path: 'settings',
        title: $localize`:@@title.settings:Settings`,
        loadComponent: () => import('./settings/settings.page').then((m) => m.SettingsPage),
        loadChildren: () => import('./settings/settings.routes').then((m) => m.settingsRoutes),
      },
      {
        path: 'docs',
        title: $localize`:@@title.docs:Documentation`,
        loadComponent: () => import('./docs/docs.page').then((m) => m.DocsPage),
      },
      {
        path: 'docs/:page',
        title: $localize`:@@title.docs:Documentation`,
        loadComponent: () => import('./docs/docs.page').then((m) => m.DocsPage),
      },
      {
        path: '**',
        title: $localize`:@@title.notFound:Page not found`,
        component: NotFoundPage,
      },
    ],
  },
];
