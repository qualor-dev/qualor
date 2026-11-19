import { type Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, page, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { GatePage } from '../gates/gate.page';
import { GatesPage } from '../gates/gates.page';
import { PortfolioPage } from '../portfolio/portfolio.page';
import { AddRepositoriesPage } from '../projects/add-repositories.page';
import { ProjectsPage } from '../projects/projects.page';
import { ProfilePage } from '../rules/profile.page';
import { ProfilesPage } from '../rules/profiles.page';
import { RulesPage } from '../rules/rules.page';
import { AiReviewPage } from '../settings/ai-review.page';
import { AiSettingsPage } from '../settings/ai.page';
import { AuditLogPage } from '../settings/audit-log.page';
import { SettingsCompliancePage } from '../settings/compliance.page';
import { GitHubPage } from '../settings/github.page';
import { GitLabPage } from '../settings/gitlab.page';
import { JiraSettingsPage } from '../settings/jira.page';
import { LicensePolicyPage } from '../settings/license-policy.page';
import { MembersPage } from '../settings/members.page';
import { OrganizationsPage } from '../settings/organizations.page';
import { RepositoriesPage } from '../settings/repositories.page';
import { SettingsPage } from '../settings/settings.page';
import { SsoPage } from '../settings/sso.page';
import { WebhooksPage } from '../settings/webhooks.page';
import { SetupChecklist } from '../shell/setup-checklist';
import { Shell } from '../shell/shell';

/**
 * 0.16 issue #37 (spec §4 UI, "no organization anywhere"): an instance admin can delete every
 * organization but the last one that is not already being deleted, yet the list may still come back
 * empty (a delete finishing under a second tab, a user with no role anywhere). Every page that reads
 * `OrgContext.current()` or `currentId()` must then render, never throw, and never ask the server
 * about an organization called "null" or "undefined".
 */
const PAGES: {
  name: string;
  component: Type<unknown>;
  inputs?: Record<string, unknown>;
  /** Its own empty state is to show nothing (a corner checklist with nothing to check). */
  blank?: boolean;
  /** Its own record is not in the fake server: the one not-found alert it shows is its answer. */
  notFound?: boolean;
}[] = [
  { name: 'Gates', component: GatesPage },
  { name: 'Gate', component: GatePage, inputs: { gateId: 'g1' }, notFound: true },
  { name: 'Portfolio', component: PortfolioPage },
  { name: 'Add repositories', component: AddRepositoriesPage },
  { name: 'Projects', component: ProjectsPage },
  { name: 'Profiles', component: ProfilesPage },
  { name: 'Profile', component: ProfilePage, inputs: { profileId: 'q1' }, notFound: true },
  { name: 'Rules', component: RulesPage },
  { name: 'AI review', component: AiReviewPage },
  { name: 'AI provider', component: AiSettingsPage, notFound: true },
  { name: 'Audit log', component: AuditLogPage },
  { name: 'Compliance', component: SettingsCompliancePage },
  { name: 'GitHub', component: GitHubPage },
  { name: 'GitLab', component: GitLabPage },
  { name: 'Jira', component: JiraSettingsPage },
  { name: 'Licence policy', component: LicensePolicyPage },
  { name: 'Members', component: MembersPage },
  { name: 'Organizations', component: OrganizationsPage },
  { name: 'Repositories', component: RepositoriesPage },
  { name: 'Settings', component: SettingsPage },
  { name: 'SSO', component: SsoPage },
  { name: 'Webhooks', component: WebhooksPage },
  { name: 'Setup checklist', component: SetupChecklist, blank: true },
  { name: 'Shell', component: Shell },
];

describe('pages with no organization to show (0.16, issue #37)', () => {
  for (const { name, component, inputs, blank, notFound } of PAGES) {
    it(`${name} renders without an organization and asks the server about none`, async () => {
      const server = new FakeServer();
      server.on('GET', '/api/v0/organizations', { body: page([]) });
      server.on('GET', '/api/v0/projects', { body: page([]) });
      server.on('GET', '/api/v0/system/info', {
        body: { version: '0.1.0', edition: 'community', features: [], extensions: [] },
      });
      TestBed.configureTestingModule({
        providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
      });
      TestBed.inject(SessionStore).set(me({ admin: true }));
      const fixture = TestBed.createComponent(component);
      for (const [key, value] of Object.entries(inputs ?? {})) {
        fixture.componentRef.setInput(key, value);
      }
      await settle(fixture);
      const root = fixture.nativeElement as HTMLElement;
      if (!blank) expect(root.textContent?.trim()).not.toBe('');
      // Nothing to show is not an error: no page paints a failure for it.
      const alerts = [...root.querySelectorAll('.alert-error')].map((e) => e.textContent?.trim());
      expect(alerts).toEqual(notFound ? ['This item does not exist, or you cannot see it.'] : []);
      for (const request of server.requests) {
        expect(`${request.path}?${request.query.toString()}`).not.toMatch(/undefined|null/);
      }
    });
  }
});
