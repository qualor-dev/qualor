import { Component, computed, effect, inject, input } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ApiError, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { GateBadge } from '../shared/gate-badge';
import { Icon } from '../shared/icon';
import { type Crumb, PageHeader } from '../shared/page-header';
import { mergeRequestLink, notFound } from './branches';
import { CurrentProject } from './current-project';

/**
 * A project's frame on the ink page band (spec §7.1): its name with the main branch's gate, the
 * key and the main branch (or those of the branch or merge request an overview shows), and tabs
 * for the overview, branches and issues, plus
 * Access for organisation admins, in every edition. The project (and the caller's `permissions` on
 * it, which the tabs use to hide what the caller may not do, rbac-audit.md §17) is read through
 * `CurrentProject`.
 */
@Component({
  selector: 'q-project-page',
  imports: [RouterLink, RouterLinkActive, RouterOutlet, GateBadge, Icon, PageHeader],
  templateUrl: './project.page.html',
  host: { class: 'bleed' },
})
export class ProjectPage {
  private readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  readonly projectId = input.required<string>();

  protected readonly project = this.store.project;
  /** The project once loaded; never `project.value()` in the error state, which throws. */
  protected readonly current = this.store.current;
  /**
   * The branch or merge request an overview shows, when not the main one: the band carries its
   * gate, its name, a merge request's title and its page instead of the main branch's (§7.1).
   */
  protected readonly shown = this.store.shownBranch;
  /** A merge request's page, named by its host (scm.md §8; see {@link mergeRequestLink}). */
  protected readonly mrLink = computed(() => {
    const b = this.shown();
    return b ? mergeRequestLink(b.mrUrl, b.mrTitle || b.title) : null;
  });
  protected readonly crumbs: Crumb[] = [
    { label: $localize`:@@project.crumb:Projects`, link: '/projects' },
  ];
  /**
   * The Access tab (rbac-audit.md §17): for those who read the members of the project's
   * organisation (`org.members.read`), whatever the licence (§1.3).
   */
  protected readonly showAccess = computed(() => {
    const project = this.current();
    return project !== null && this.session.orgCan(project.organizationId, 'org.members.read');
  });
  /** The main branch's open issues, the Issues tab's count. */
  protected readonly issueCount = computed(() => {
    const value = this.current()?.mainBranch?.measures['issues'];
    return typeof value === 'number' ? value : null;
  });
  /** A malformed id in the URL (422 on the path) is, for the reader, a project that does not exist. */
  protected readonly errorMessage = computed(() => {
    const error = this.project.error();
    if (!error) return null;
    const malformed = error instanceof ApiError && error.status === 422;
    return problemMessage(malformed ? notFound() : error);
  });

  constructor() {
    effect(() => this.store.use(this.projectId()));
  }
}
