import { Injectable, computed, inject, resource, signal } from '@angular/core';
import { Api, ok } from '../api/api';
import type { ResponseBody } from '../api/types';
import { can } from '../auth/permissions';
import { SessionStore } from '../auth/session';
import type { BranchView } from './branches';

export type ProjectDto = ResponseBody<'/api/v0/projects/{id}', 'get'>;

/**
 * The project the project screens show, read once for the frame and its tabs: `GET /projects/{id}`
 * with the caller's effective `permissions` on it (rbac-audit.md §16). A page calls `use(id)` with
 * its route's project id; the same id asks nothing again. Read again when the user changes, so a
 * second sign-in never sees the previous user's permissions.
 */
@Injectable({ providedIn: 'root' })
export class CurrentProject {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly id = signal<string | null>(null);

  readonly project = resource({
    params: () => {
      const id = this.id();
      const user = this.session.user()?.id;
      return id && user ? { id, user } : undefined;
    },
    loader: ({ params }) =>
      ok(this.api.client.GET('/api/v0/projects/{id}', { params: { path: { id: params.id } } })),
  });

  /** The loaded project; null while loading or after an error (`value()` throws in that state). */
  readonly current = computed<ProjectDto | null>(() => {
    if (!this.project.hasValue()) return null;
    const project = this.project.value();
    return project.id === this.id() ? project : null;
  });

  /**
   * The branch or merge request an overview shows, when it is not the main one: the frame names
   * it on the band (spec §7.1). The overview sets it and clears it when it goes.
   */
  readonly shownBranch = signal<BranchView | null>(null);

  use(id: string): void {
    this.id.set(id);
  }

  showBranch(branch: BranchView | null): void {
    this.shownBranch.set(branch);
  }

  /** The caller's permissions on project `id`, or undefined until it has loaded. */
  permissions(id: string): readonly string[] | undefined {
    const project = this.current();
    return project?.id === id ? project.permissions : undefined;
  }

  /**
   * Whether the caller may make a change that needs `permission` on project `id`: the project DTO
   * lists it. False until the project has loaded, so a button appears only once the server said
   * it may be used.
   */
  canChange(id: string, permission: string): boolean {
    const project = this.current();
    return project?.id === id && can(project.permissions, permission);
  }
}
