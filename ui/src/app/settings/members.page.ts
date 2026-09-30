import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { AuthService } from '../auth/auth.service';
import { type Role, ROLES, roleLabel } from '../auth/permissions';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { onPhone } from '../shared/media';

export type Member = ItemOf<'/api/v0/organizations/{id}/members'>;
/** The longest name `GET /users/lookup` accepts (usernames are 1 to 64 characters). */
const USERNAME_MAX_LENGTH = 64;
/** The role a new member starts with in the "Add member" dialog. */
const DEFAULT_ROLE: Role = 'member';

/** A change the confirmation dialog asks about. */
type Pending =
  | { kind: 'change'; member: Member; role: Role; question: string }
  | { kind: 'remove'; member: Member; question: string };

/**
 * Settings → Members (rbac-audit.md §17): the current organisation's members and their
 * roles, for those whose role lists `org.members.read` (org admins, instance admins). Org admins
 * change a role, remove a member, and add a user by exact name (`GET /users/lookup`, then `PUT`).
 * Every edition offers the four roles, with the same names (rbac-audit.md §1.3, §6.1).
 * A membership that SSO group sync manages names its connection (sso-scim.md §9.3, §18); changing
 * its role takes it over from the sync, which the confirmation says.
 *
 * Step 8 of the redesign (spec §7.8), as Project → Access (step 5): the members in a panel with
 * quiet row actions; "Add member" opens a dialog holding the form (the default role again each
 * time); a change or removal asks in the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-members-page',
  imports: [Icon],
  templateUrl: './members.page.html',
})
export class MembersPage {
  private readonly api = inject(Api);
  private readonly auth = inject(AuthService);
  private readonly session = inject(SessionStore);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);
  protected readonly list = new KeysetList<Member, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/organizations/{id}/members', {
        params: {
          path: { id: organizationId },
          query: { limit: 100, ...(cursor ? { cursor } : {}) },
        },
      }),
    ),
  );

  protected readonly canRead = computed(() => this.org.can('org.members.read'));
  protected readonly canManage = computed(
    () => this.org.canChange('org.members.manage') && this.canRead(),
  );
  /** The roles a change may choose: the four, in every edition. */
  protected readonly roles: readonly Role[] = ROLES;
  protected readonly username = signal('');
  protected readonly role = signal<Role>(DEFAULT_ROLE);
  /** The role chosen in each row's select, until it is sent. */
  protected readonly chosen = signal<Readonly<Record<string, Role>>>({});
  protected readonly usernameError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  /** A refused addition other than its name, shown in the dialog that is still open. */
  protected readonly addError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The change the confirmation dialog asks about; null while it is closed. */
  protected readonly pending = signal<Pending | null>(null);
  /** A refused change or removal, shown in the question that asked (step 11). */
  protected readonly confirmError = signal<string | null>(null);
  /** The question's title names the person (step 11). */
  protected readonly confirmTitle = computed(() => {
    const pending = this.pending();
    if (!pending) return '';
    const name = pending.member.username;
    return pending.kind === 'remove'
      ? $localize`:@@members.removeTitleNamed:Remove ${name}:name:`
      : $localize`:@@members.changeTitleNamed:Change the role of ${name}:name:`;
  });
  protected readonly usernameMax = USERNAME_MAX_LENGTH;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly usernameField = viewChild<ElementRef<HTMLInputElement>>('usernameField');
  private readonly addDialog = viewChild<ElementRef<HTMLDialogElement>>('addDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const allowed = this.canRead();
      untracked(() => {
        this.orgGeneration++;
        this.announcement.set(null);
        this.error.set(null);
        this.usernameError.set(null);
        this.chosen.set({});
        if (organizationId && allowed) void this.list.reset(organizationId);
      });
    });
  }

  protected roleText(role: string | null): string {
    return roleLabel(role);
  }

  protected chosenRole(member: Member): Role {
    return this.chosen()[member.userId] ?? member.role;
  }

  protected choose(member: Member, event: Event): void {
    this.chosen.update((all) => ({ ...all, [member.userId]: inputValue(event) as Role }));
    // A phone's row has no room for Change role, and its picker commits once: the select asks.
    if (onPhone(this.document)) this.changeRole(member);
  }

  protected setUsername(event: Event): void {
    this.username.set(inputValue(event));
    this.usernameError.set(null);
  }

  protected setRole(event: Event): void {
    this.role.set(inputValue(event) as Role);
  }

  protected displayName(member: Member): string {
    return member.displayName ?? '';
  }

  /** Opens "Add member" on an empty name and the default role, never the last choice. */
  protected openAdd(): void {
    this.username.set('');
    this.role.set(DEFAULT_ROLE);
    this.usernameError.set(null);
    this.addError.set(null);
    openAfterRender(this.injector, () => this.addDialog()?.nativeElement);
  }

  protected closeAdd(): void {
    const dialog = this.addDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected changeRole(member: Member): void {
    const role = this.chosenRole(member);
    if (this.busy() || !this.org.currentId() || role === member.role) return;
    const organization = this.org.current()?.name ?? '';
    const self = member.userId === this.session.user()?.id;
    const to = this.roleText(role);
    const asked =
      self && member.role === 'admin'
        ? $localize`:@@members.confirmDemoteSelf:Change your own role in ${organization}:organization: to ${to}:role:? You can no longer manage its members, and only another administrator can make you an admin again.`
        : $localize`:@@members.confirmChange:Change the role of ${member.username}:name: in ${organization}:organization: to ${to}:role:?`;
    // sso-scim.md §9.3: a manual change ends group sync's hold on the membership.
    const question = member.managedBy
      ? `${asked} ${$localize`:@@members.takeOver:Changing this role takes it over from group sync.`}`
      : asked;
    this.ask({ kind: 'change', member, role, question });
  }

  protected remove(member: Member): void {
    if (this.busy() || !this.org.currentId()) return;
    const organization = this.org.current()?.name ?? '';
    const self = member.userId === this.session.user()?.id;
    const question = self
      ? $localize`:@@members.confirmRemoveSelf:Remove yourself from ${organization}:organization:? You lose access to its projects, and only another administrator can add you again.`
      : $localize`:@@members.confirmRemove:Remove ${member.username}:name: from ${organization}:organization:? They lose access to its projects.`;
    this.ask({ kind: 'remove', member, question });
  }

  private ask(pending: Pending): void {
    this.confirmError.set(null);
    this.pending.set(pending);
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pending() !== null,
    );
  }

  /**
   * Answers the question. It stays open until the server has answered, and a refusal stays in it
   * with its reason, as a branch delete's does; closed meanwhile (Escape), it opens again on one.
   */
  protected async confirmPending(): Promise<void> {
    const pending = this.pending();
    if (!pending || this.busy()) return;
    this.confirmError.set(null);
    const refusal =
      pending.kind === 'change'
        ? await this.applyChange(pending.member, pending.role)
        : await this.applyRemove(pending.member);
    if (refusal === null) {
      // Cleared first: the dialog's close event then reads no pending change to cancel.
      if (this.pending() === pending) this.pending.set(null);
      this.closeConfirm();
      return;
    }
    this.pending.set(pending);
    this.confirmError.set(refusal);
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pending() === pending,
    );
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing changes, a chosen role goes back. */
  protected cancelPending(): void {
    const pending = this.pending();
    this.pending.set(null);
    this.confirmError.set(null);
    this.closeConfirm();
    if (pending?.kind === 'change') this.resetChoice(pending.member);
  }

  private closeConfirm(): void {
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  /** Changes a role; the refusal's words when the server refuses (409 LAST_ADMIN, 403…), else null. */
  private async applyChange(member: Member, role: Role): Promise<string | null> {
    const organizationId = this.org.currentId();
    if (this.busy() || !organizationId) return null;
    let refusal: string | null = null;
    await this.run(
      async (current) => {
        const saved = await ok(
          this.api.client.PUT('/api/v0/organizations/{id}/members/{userId}', {
            params: { path: { id: organizationId, userId: member.userId } },
            body: { role },
          }),
        );
        if (!current()) return;
        await this.list.refresh();
        this.chosen.update((all) =>
          Object.fromEntries(Object.entries(all).filter(([userId]) => userId !== saved.userId)),
        );
        this.announcement.set(
          $localize`:@@members.changed:${saved.username}:name: is now ${this.roleText(saved.role)}:role:.`,
        );
        await this.afterOwnChange(saved.userId);
        keepFocus(
          this.injector,
          this.document,
          () => rowByKey(this.table()?.nativeElement, saved.userId)?.querySelector('select'),
          () => this.heading().nativeElement,
        );
      },
      (err) => (refusal = problemMessage(err)),
    );
    return refusal;
  }

  /**
   * Puts a row's select back to the member's stored role. The `[selected]` binding alone cannot:
   * its value did not change while the person picked another option in the element itself.
   */
  private resetChoice(member: Member): void {
    this.chosen.update((all) =>
      Object.fromEntries(Object.entries(all).filter(([userId]) => userId !== member.userId)),
    );
    const select = rowByKey(this.table()?.nativeElement, member.userId)?.querySelector('select');
    if (select) select.value = member.role;
  }

  /** Removes a member; the refusal's words when the server refuses, else null. */
  private async applyRemove(member: Member): Promise<string | null> {
    const organizationId = this.org.currentId();
    if (this.busy() || !organizationId) return null;
    const index = this.list.items().findIndex((m) => m.userId === member.userId);
    let refusal: string | null = null;
    await this.run(
      async (current) => {
        await done(
          this.api.client.DELETE('/api/v0/organizations/{id}/members/{userId}', {
            params: { path: { id: organizationId, userId: member.userId } },
          }),
        );
        if (!current()) return;
        await this.list.refresh();
        this.announcement.set($localize`:@@members.removed:${member.username}:name: removed.`);
        await this.afterOwnChange(member.userId);
        keepFocus(
          this.injector,
          this.document,
          // The next person's role: their Change role is muted until another role is chosen.
          () => rowAt(this.table()?.nativeElement, index)?.querySelector('select'),
          () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
          () => this.heading().nativeElement,
        );
      },
      (err) => (refusal = problemMessage(err)),
    );
    return refusal;
  }

  /** Adds a user by exact name: `GET /users/lookup`, then `PUT` with the chosen role. */
  protected async add(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    const username = this.username().trim();
    const role = this.role();
    if (this.busy() || !organizationId) return;
    this.addError.set(null);
    if (!username) {
      this.usernameError.set($localize`:@@members.usernameRequired:Enter a user name.`);
      this.focusUsername();
      return;
    }
    await this.run(
      async (current) => {
        let user;
        try {
          user = await ok(
            this.api.client.GET('/api/v0/users/lookup', { params: { query: { username } } }),
          );
        } catch (err) {
          if (err instanceof ApiError && (err.status === 404 || err.status === 422)) {
            if (!current()) return;
            this.usernameError.set(
              $localize`:@@members.noSuchUser:No active user has that name. Check the spelling, or ask an instance administrator to create the user.`,
            );
            this.focusUsername();
            return;
          }
          throw err;
        }
        if (!current()) return;
        const existing = this.list.items().find((m) => m.userId === user.id);
        if (existing) {
          this.usernameError.set(
            $localize`:@@members.alreadyMember:${existing.username}:name: is already a member. Change their role in the table.`,
          );
          this.focusUsername();
          return;
        }
        const saved = await ok(
          this.api.client.PUT('/api/v0/organizations/{id}/members/{userId}', {
            params: { path: { id: organizationId, userId: user.id } },
            body: { role },
          }),
        );
        if (!current()) return;
        clearField(this.usernameField(), this.username);
        this.closeAdd();
        await this.list.refresh();
        this.announcement.set(
          $localize`:@@members.added:${saved.username}:name: added as ${this.roleText(saved.role)}:role:.`,
        );
        await this.afterOwnChange(saved.userId);
      },
      (err) => this.addError.set(problemMessage(err)),
    );
  }

  /** A change to one's own membership changes one's permissions: `GET /auth/me` again. */
  private async afterOwnChange(userId: string): Promise<void> {
    if (userId !== this.session.user()?.id) return;
    try {
      await this.auth.refresh();
    } catch {
      // The change was made; the next navigation reads the session again.
    }
  }

  private focusUsername(): void {
    afterNextRender(() => this.usernameField()?.nativeElement.focus(), {
      injector: this.injector,
    });
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. An
   * answer that arrives after the organisation changed is dropped (`current()` is false then). A
   * refusal goes to `onError` when given (the dialog that is open), else to the page's alert.
   */
  private async run(
    action: (current: () => boolean) => Promise<void>,
    onError?: (err: unknown) => void,
  ): Promise<void> {
    const generation = this.orgGeneration;
    const current = () => generation === this.orgGeneration;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action(current);
    } catch (err) {
      if (!current()) return;
      if (onError) {
        onError(err);
        return;
      }
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
