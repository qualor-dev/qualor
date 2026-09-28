import { Component, computed, effect, inject, input } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ApiError, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { notFound } from './branches';
import { CurrentProject } from './current-project';

/**
 * A project's frame: its name and key, and tabs for the overview, branches and issues, plus Access
 * for organisation admins, in every edition. The project (and the caller's `permissions` on it,
 * which the tabs use to hide what the caller may not do, rbac-audit.md §17) is read through
 * `CurrentProject`.
 */
@Component({
  selector: 'q-project-page',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './project.page.html',
})
export class ProjectPage {
  private readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  readonly projectId = input.required<string>();

  protected readonly project = this.store.project;
  /** The project once loaded; never `project.value()` in the error state, which throws. */
  protected readonly current = this.store.current;
  /**
   * The Access tab (rbac-audit.md §17): for those who read the members of the project's
   * organisation (`org.members.read`), whatever the licence (§1.3).
   */
  protected readonly showAccess = computed(() => {
    const project = this.current();
    return project !== null && this.session.orgCan(project.organizationId, 'org.members.read');
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
