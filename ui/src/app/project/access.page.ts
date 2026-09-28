import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import type { GrantRole, ProjectGrant } from '../api/types';
import { ApiError, problemMessage } from '../api/errors';
import { roleLabel } from '../auth/permissions';
import { SessionStore } from '../auth/session';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { CurrentProject } from './current-project';

/** The roles a project grant may carry (rbac-audit.md §3.2: `admin` is organisation-wide only). */
const GRANT_ROLES: readonly GrantRole[] = ['project_admin', 'member', 'viewer'];
/** The longest name `GET /users/lookup` accepts (usernames are 1 to 64 characters). */
const USERNAME_MAX_LENGTH = 64;

/**
 * Project → Access (rbac-audit.md §16, §17): the project's role grants, which add a role on this
 * project only to whatever the person's organisation role gives. In every edition since
 * 5B (§1.3), through the core API. Org admins add a grant by exact user name
 * (`GET /users/lookup`, then `PUT /projects/{id}/members/{userId}`), change and remove one.
 * Nothing is asked while the caller cannot read the organisation's members (`org.members.read`).
 */
@Component({
  selector: 'q-access-page',
  templateUrl: './access.page.html',
})
export class AccessPage {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly store = inject(CurrentProject);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  readonly projectId = input.required<string>();

  protected readonly list = new KeysetList<ProjectGrant, string>((projectId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/projects/{id}/members', {
        params: { path: { id: projectId }, query: { limit: 100, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );

  protected readonly project = computed(() => {
    const project = this.store.current();
    return project?.id === this.projectId() ? project : null;
  });
  /** Who sees the grants: those who read the members of the project's organisation. */
  protected readonly allowed = computed(() => {
    const project = this.project();
    return project !== null && this.session.orgCan(project.organizationId, 'org.members.read');
  });
  protected readonly canManage = computed(() => {
    const project = this.project();
    return (
      this.allowed() &&
      project !== null &&
      this.session.orgCan(project.organizationId, 'org.members.manage')
    );
  });
  protected readonly roles = GRANT_ROLES;
  protected readonly username = signal('');
  protected readonly role = signal<GrantRole>('viewer');
  /** The role chosen in each row's select, until it is sent. */
  protected readonly chosen = signal<Readonly<Record<string, GrantRole>>>({});
  protected readonly usernameError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly usernameMax = USERNAME_MAX_LENGTH;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly usernameField = viewChild<ElementRef<HTMLInputElement>>('usernameField');
  /** Counts project changes: an answer for an earlier project is dropped. */
  private generation = 0;

  constructor() {
    effect(() => this.store.use(this.projectId()));
    effect(() => {
      const projectId = this.project()?.id ?? null;
      const allowed = this.allowed();
      untracked(() => {
        this.generation++;
        this.announcement.set(null);
        this.error.set(null);
        this.usernameError.set(null);
        this.chosen.set({});
        if (projectId && allowed) void this.list.reset(projectId);
      });
    });
  }

  protected roleText(role: string): string {
    return roleLabel(role);
  }

  protected chosenRole(grant: ProjectGrant): GrantRole {
    return this.chosen()[grant.userId] ?? grant.role;
  }

  protected choose(grant: ProjectGrant, event: Event): void {
    this.chosen.update((all) => ({ ...all, [grant.userId]: inputValue(event) as GrantRole }));
  }

  protected setUsername(event: Event): void {
    this.username.set(inputValue(event));
    this.usernameError.set(null);
  }

  protected setRole(event: Event): void {
    this.role.set(inputValue(event) as GrantRole);
  }

  protected async changeRole(grant: ProjectGrant): Promise<void> {
    const project = this.project();
    const role = this.chosenRole(grant);
    if (this.busy() || !project || role === grant.role) return;
    const question = $localize`:@@access.confirmChange:Change the role of ${grant.username}:name: on ${project.name}:project: to ${this.roleText(role)}:role:?`;
    if (!window.confirm(question)) {
      this.resetChoice(grant);
      return;
    }
    let changed = false;
    await this.run(async (current) => {
      const saved = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/members/{userId}', {
          params: { path: { id: project.id, userId: grant.userId } },
          body: { role },
        }),
      );
      if (!current()) return;
      changed = true;
      await this.list.refresh();
      this.chosen.update((all) => without(all, saved.userId));
      this.announcement.set(this.grantedText(saved));
      keepFocus(
        this.injector,
        this.document,
        () => rowByKey(this.table()?.nativeElement, saved.userId)?.querySelector('select'),
        () => this.heading().nativeElement,
      );
    });
    if (!changed) this.resetChoice(grant);
  }

  /** Puts a row's select back to the stored role (the `[selected]` binding alone cannot). */
  private resetChoice(grant: ProjectGrant): void {
    this.chosen.update((all) => without(all, grant.userId));
    const select = rowByKey(this.table()?.nativeElement, grant.userId)?.querySelector('select');
    if (select) select.value = grant.role;
  }

  protected async remove(grant: ProjectGrant): Promise<void> {
    const project = this.project();
    if (this.busy() || !project) return;
    const question = $localize`:@@access.confirmRemove:Remove the role of ${grant.username}:name: on ${project.name}:project:? Their organization role, if they have one, still applies.`;
    if (!window.confirm(question)) return;
    const index = this.list.items().findIndex((g) => g.userId === grant.userId);
    await this.run(async (current) => {
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}/members/{userId}', {
          params: { path: { id: project.id, userId: grant.userId } },
        }),
      );
      if (!current()) return;
      await this.list.refresh();
      this.announcement.set(
        $localize`:@@access.removed:The role of ${grant.username}:name: on this project was removed.`,
      );
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  /** Adds a grant by exact name: `GET /users/lookup`, then `PUT` with the chosen role. */
  protected async add(event: Event): Promise<void> {
    event.preventDefault();
    const project = this.project();
    const username = this.username().trim();
    const role = this.role();
    if (this.busy() || !project) return;
    if (!username) {
      this.fieldError($localize`:@@access.usernameRequired:Enter a user name.`);
      return;
    }
    await this.run(async (current) => {
      let user;
      try {
        user = await ok(
          this.api.client.GET('/api/v0/users/lookup', { params: { query: { username } } }),
        );
      } catch (err) {
        if (err instanceof ApiError && (err.status === 404 || err.status === 422)) {
          if (current()) {
            this.fieldError(
              $localize`:@@access.noSuchUser:No active user has that name. Check the spelling, or ask an instance administrator to create the user.`,
            );
          }
          return;
        }
        throw err;
      }
      if (!current()) return;
      const existing = this.list.items().find((g) => g.userId === user.id);
      if (existing) {
        this.fieldError(
          $localize`:@@access.alreadyGranted:${existing.username}:name: already has a role on this project. Change it in the table.`,
        );
        return;
      }
      const saved = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/members/{userId}', {
          params: { path: { id: project.id, userId: user.id } },
          body: { role },
        }),
      );
      if (!current()) return;
      clearField(this.usernameField(), this.username);
      await this.list.refresh();
      this.announcement.set(this.grantedText(saved));
    });
  }

  private grantedText(grant: ProjectGrant): string {
    return $localize`:@@access.granted:${grant.username}:name: now has the role ${this.roleText(grant.role)}:role: on this project.`;
  }

  private fieldError(message: string): void {
    this.usernameError.set(message);
    afterNextRender(() => this.usernameField()?.nativeElement.focus(), {
      injector: this.injector,
    });
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. An
   * answer that arrives after the project changed is dropped (`current()` is false then).
   */
  private async run(action: (current: () => boolean) => Promise<void>): Promise<void> {
    const generation = this.generation;
    const current = () => generation === this.generation;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action(current);
    } catch (err) {
      if (!current()) return;
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}

function without<T>(all: Readonly<Record<string, T>>, key: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([k]) => k !== key));
}
