import { DOCUMENT } from '@angular/common';
import {
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
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { PASSWORD_MIN_LENGTH } from '../auth/change-password.page';
import { SessionStore } from '../auth/session';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus, rowByKey } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';

export type User = ItemOf<'/api/v0/users'>;
type UserPatch = { active: boolean } | { isInstanceAdmin: boolean };
type Field = 'username' | 'displayName' | 'email' | 'password';
/** A change to one's own account the confirmation dialog asks about. */
type Pending = { kind: 'active' | 'admin'; user: User; question: string };

/** The server's bound on passwords (`z.string().min(12).max(256)`). */
const PASSWORD_MAX_LENGTH = 256;

/**
 * Instance administration of local users (api.md `GET/POST/PATCH /users`). A user an admin
 * creates, or whose password an admin resets, must choose a new password at the next sign-in
 * (ruling R7). The server refuses to demote or deactivate the last active admin (409 `LAST_ADMIN`,
 * ruling S9), shown as an alert while the row stays as it was.
 *
 * - Passwords are typed into `new-password` fields, sent once and cleared as soon as the server
 *   has answered; they are never shown.
 * - A change patches its row in place from the server's answer; the toggles keep their element,
 *   so focus stays on the button used, and the result is announced in the live region.
 * - Badges say how a user signs in (sso-scim.md §18): "No password", "SSO" (an identity of a
 *   connection) and "SCIM" (provisioned by an identity provider, which may overwrite changes made
 *   here); the "No password" filter lists only the users without a password.
 * - Deactivating or demoting yourself asks first; your own password is changed from the user menu
 *   (a reset here would end your session), so your row offers no reset.
 *
 * Step 8 of the redesign (spec §7.8): the users in a panel with quiet row actions; "New user"
 * opens a dialog holding the form; each other user's row resets their password in a dialog that
 * names them (it replaces the separate form with its user list); asking about your own account
 * uses the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-users-page',
  imports: [DateTimePipe, Icon],
  templateUrl: './users.page.html',
})
export class UsersPage {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly isAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly selfId = computed(() => this.session.user()?.id ?? null);
  /** The list's parameter: true lists only the users without a password (`?signIn=no-password`). */
  protected readonly list = new KeysetList<User, boolean>((noPassword, cursor) =>
    ok(
      this.api.client.GET('/api/v0/users', {
        params: {
          query: {
            limit: 100,
            ...(cursor ? { cursor } : {}),
            ...(noPassword ? { signIn: 'no-password' as const } : {}),
          },
        },
      }),
    ),
  );
  /**
   * The "No password" filter (sso-scim.md §11, §18): the users who can only sign in with single
   * sign-on, for instance after `sso` lapsed, so an admin can give them a password.
   */
  protected readonly noPasswordOnly = signal(false);
  protected readonly username = signal('');
  protected readonly displayName = signal('');
  protected readonly email = signal('');
  protected readonly password = signal('');
  protected readonly admin = signal(false);
  protected readonly errors = signal<Partial<Record<Field, string>>>({});
  /** The user whose password the reset dialog sets; null while it is closed. */
  protected readonly resetTarget = signal<User | null>(null);
  protected readonly resetPassword = signal('');
  protected readonly resetError = signal<string | null>(null);
  /** A refusal of an open dialog's form that names no field, shown in that dialog. */
  protected readonly dialogError = signal<string | null>(null);
  /** The change to your own account the confirmation dialog asks about. */
  protected readonly pending = signal<Pending | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly minLength = PASSWORD_MIN_LENGTH;
  protected readonly maxLength = PASSWORD_MAX_LENGTH;
  protected readonly isChecked = isChecked;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly usernameField = viewChild<ElementRef<HTMLInputElement>>('usernameField');
  private readonly displayNameField = viewChild<ElementRef<HTMLInputElement>>('displayNameField');
  private readonly emailField = viewChild<ElementRef<HTMLInputElement>>('emailField');
  private readonly passwordField = viewChild<ElementRef<HTMLInputElement>>('passwordField');
  private readonly resetField = viewChild<ElementRef<HTMLInputElement>>('resetField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly resetDialog = viewChild<ElementRef<HTMLDialogElement>>('resetDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  private started = false;

  constructor() {
    effect(() => {
      if (this.isAdmin() && !this.started) {
        this.started = true;
        untracked(() => void this.list.reset(this.noPasswordOnly()));
      }
    });
  }

  protected toggleNoPassword(): void {
    this.noPasswordOnly.update((on) => !on);
    this.announcement.set(null);
    void this.list.reset(this.noPasswordOnly());
  }

  protected set(field: Field, event: Event): void {
    const value = inputValue(event);
    if (field === 'username') this.username.set(value);
    else if (field === 'displayName') this.displayName.set(value);
    else if (field === 'email') this.email.set(value);
    else this.password.set(value);
    this.errors.update((all) => ({ ...all, [field]: undefined }));
  }

  protected setResetPassword(event: Event): void {
    this.resetPassword.set(inputValue(event));
    this.resetError.set(null);
  }

  /** Opens "New user" on an empty form, not an instance admin. */
  protected openCreate(): void {
    this.username.set('');
    this.displayName.set('');
    this.email.set('');
    this.password.set('');
    this.admin.set(false);
    this.errors.set({});
    this.dialogError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    clearField(this.passwordField(), this.password);
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const username = this.username().trim();
    const errors: Partial<Record<Field, string>> = {};
    if (!username) errors.username = usernameMessage();
    if (this.password().length < PASSWORD_MIN_LENGTH) errors.password = passwordShort();
    this.errors.set(errors);
    this.dialogError.set(null);
    if (Object.keys(errors).length > 0) {
      this.focusFirstInvalid();
      return;
    }
    const password = this.password();
    await this.run(
      async () => {
        const user = await ok(
          this.api.client.POST('/api/v0/users', {
            body: {
              username,
              password,
              isInstanceAdmin: this.admin(),
              ...(this.displayName().trim() ? { displayName: this.displayName().trim() } : {}),
              ...(this.email().trim() ? { email: this.email().trim() } : {}),
            },
          }),
        );
        this.announcement.set(
          $localize`:@@users.created:${user.username}:username: can sign in now and must choose a new password first.`,
        );
        clearField(this.usernameField(), this.username);
        clearField(this.displayNameField(), this.displayName);
        clearField(this.emailField(), this.email);
        this.admin.set(false);
        const dialog = this.createDialog()?.nativeElement;
        if (dialog) closeModal(dialog);
        await this.list.refresh();
      },
      (err) => this.createFailed(err),
    );
    // Sent once: the password is not kept, whatever the answer.
    clearField(this.passwordField(), this.password);
  }

  protected async toggleActive(user: User): Promise<void> {
    if (this.busy()) return;
    if (user.active && user.id === this.selfId()) {
      this.ask({
        kind: 'active',
        user,
        question: $localize`:@@users.confirmDeactivateSelf:Deactivate your own account? You are signed out at once and cannot sign in again.`,
      });
      return;
    }
    await this.patch(user, { active: !user.active }, 0);
  }

  protected async toggleAdmin(user: User): Promise<void> {
    if (this.busy()) return;
    if (user.isInstanceAdmin && user.id === this.selfId()) {
      this.ask({
        kind: 'admin',
        user,
        question: $localize`:@@users.confirmDemoteSelf:Remove your own instance admin role? You can no longer manage users.`,
      });
      return;
    }
    await this.patch(user, { isInstanceAdmin: !user.isInstanceAdmin }, 1);
  }

  private ask(pending: Pending): void {
    this.pending.set(pending);
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pending() !== null,
    );
  }

  protected async confirmPending(): Promise<void> {
    const pending = this.pending();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pending.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    if (pending.kind === 'active') await this.patch(pending.user, { active: false }, 0);
    else await this.patch(pending.user, { isInstanceAdmin: false }, 1);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing changes. */
  protected cancelPending(): void {
    this.pending.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  /** Opens the reset dialog for another user's row. */
  protected openReset(user: User): void {
    if (this.busy() || user.id === this.selfId()) return;
    this.resetTarget.set(user);
    this.resetPassword.set('');
    this.resetError.set(null);
    this.dialogError.set(null);
    openAfterRender(
      this.injector,
      () => this.resetDialog()?.nativeElement,
      () => this.resetTarget() !== null,
    );
  }

  protected closeReset(): void {
    const dialog = this.resetDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.cancelReset();
  }

  /** The reset dialog closed, however: its user and typed password are forgotten. */
  protected cancelReset(): void {
    this.resetTarget.set(null);
    clearField(this.resetField(), this.resetPassword);
  }

  protected async reset(event: Event): Promise<void> {
    event.preventDefault();
    const user = this.resetTarget();
    if (this.busy() || !user) return;
    this.dialogError.set(null);
    if (this.resetPassword().length < PASSWORD_MIN_LENGTH) {
      this.resetError.set(passwordShort());
      this.resetField()?.nativeElement.focus();
      return;
    }
    const password = this.resetPassword();
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.PATCH('/api/v0/users/{id}', {
            params: { path: { id: user.id } },
            body: { password },
          }),
        );
        this.replace(updated);
        this.announcement.set(
          $localize`:@@users.reset:${user.username}:username: must choose a new password at the next sign-in.`,
        );
        this.closeReset();
      },
      (err) => {
        if (fieldErrors(err)['body.password'] !== undefined) {
          this.resetError.set(passwordShort());
          this.resetField()?.nativeElement.focus();
        } else {
          this.dialogError.set(problemMessage(err));
        }
        return true;
      },
    );
    clearField(this.resetField(), this.resetPassword);
  }

  private async patch(user: User, body: UserPatch, slot: number): Promise<void> {
    await this.run(async () => {
      const updated = await ok(
        this.api.client.PATCH('/api/v0/users/{id}', { params: { path: { id: user.id } }, body }),
      );
      this.replace(updated);
      this.announcement.set(changeMessage(updated, body));
      keepFocus(
        this.injector,
        this.document,
        () => rowByKey(this.table()?.nativeElement, user.id)?.querySelectorAll('button')[slot],
        () => this.heading().nativeElement,
      );
    });
  }

  private replace(user: User): void {
    this.list.items.update((items) => items.map((u) => (u.id === user.id ? user : u)));
  }

  /**
   * Maps a refused new user to its fields; a refusal that names none shows in the dialog. Always
   * handled there: the dialog stays open with what was typed, the password aside.
   */
  private createFailed(err: unknown): boolean {
    const fields = fieldErrors(err);
    const errors: Partial<Record<Field, string>> = {};
    if (fields['body.username'] !== undefined) errors.username = usernameMessage();
    if (fields['body.password'] !== undefined) errors.password = passwordShort();
    if (fields['body.email'] !== undefined) {
      errors.email = $localize`:@@users.badEmail:Enter a valid email address of at most 320 characters.`;
    }
    if (fields['body.displayName'] !== undefined) {
      errors.displayName = $localize`:@@users.badDisplayName:Enter a display name of at most 255 characters, without control characters.`;
    }
    if (err instanceof ApiError && err.code === 'USERNAME_TAKEN') {
      errors.username = problemMessage(err);
    }
    if (err instanceof ApiError && err.code === 'EMAIL_TAKEN') errors.email = problemMessage(err);
    this.errors.set(errors);
    if (Object.keys(errors).length === 0) this.dialogError.set(problemMessage(err));
    this.focusFirstInvalid();
    return true;
  }

  /** Moves focus to the first field of the new-user form with an error. */
  private focusFirstInvalid(): void {
    const errors = this.errors();
    const field = errors.username
      ? this.usernameField()
      : errors.displayName
        ? this.displayNameField()
        : errors.email
          ? this.emailField()
          : errors.password
            ? this.passwordField()
            : undefined;
    field?.nativeElement.focus();
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing.
   * `onError` may place the error on fields or in a dialog (returning true); anything else is an
   * alert on the page.
   */
  private async run(
    action: () => Promise<void>,
    onError: (err: unknown) => boolean = () => false,
  ): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      if (!onError(err)) {
        this.error.set(problemMessage(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}

function passwordShort(): string {
  return $localize`:@@users.passwordShort:Use at least ${PASSWORD_MIN_LENGTH}:min: characters for the password.`;
}

function usernameMessage(): string {
  return $localize`:@@users.badUsername:Use 1 to 64 letters, digits, dots, dashes or underscores for the username.`;
}

function changeMessage(user: User, body: UserPatch): string {
  if ('active' in body) {
    return user.active
      ? $localize`:@@users.activated:${user.username}:username: can sign in again.`
      : $localize`:@@users.deactivated:${user.username}:username: is deactivated.`;
  }
  return user.isInstanceAdmin
    ? $localize`:@@users.madeAdmin:${user.username}:username: is now an instance admin.`
    : $localize`:@@users.removedAdmin:${user.username}:username: is no longer an instance admin.`;
}
