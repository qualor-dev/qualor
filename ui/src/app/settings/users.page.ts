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
import { keepFocus, rowByKey } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { KeysetList } from '../shared/keyset';

export type User = ItemOf<'/api/v0/users'>;
type UserPatch = { active: boolean } | { isInstanceAdmin: boolean };
type Field = 'username' | 'displayName' | 'email' | 'password';

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
 * - Deactivating or demoting yourself asks first; your own password is changed on the password
 *   page (a reset here would end your session), so the reset form does not offer you.
 */
@Component({
  selector: 'q-users-page',
  imports: [DateTimePipe],
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
  protected readonly others = computed(() =>
    this.list.items().filter((u) => u.id !== this.selfId()),
  );
  protected readonly username = signal('');
  protected readonly displayName = signal('');
  protected readonly email = signal('');
  protected readonly password = signal('');
  protected readonly admin = signal(false);
  protected readonly errors = signal<Partial<Record<Field, string>>>({});
  protected readonly resetUser = signal('');
  protected readonly resetPassword = signal('');
  protected readonly resetError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly minLength = PASSWORD_MIN_LENGTH;
  protected readonly maxLength = PASSWORD_MAX_LENGTH;
  protected readonly isChecked = isChecked;
  protected readonly value = inputValue;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly usernameField = viewChild<ElementRef<HTMLInputElement>>('usernameField');
  private readonly displayNameField = viewChild<ElementRef<HTMLInputElement>>('displayNameField');
  private readonly emailField = viewChild<ElementRef<HTMLInputElement>>('emailField');
  private readonly passwordField = viewChild<ElementRef<HTMLInputElement>>('passwordField');
  private readonly resetField = viewChild<ElementRef<HTMLInputElement>>('resetField');
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

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const username = this.username().trim();
    const errors: Partial<Record<Field, string>> = {};
    if (!username) errors.username = usernameMessage();
    if (this.password().length < PASSWORD_MIN_LENGTH) errors.password = passwordShort();
    this.errors.set(errors);
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
        await this.list.refresh();
      },
      (err) => this.createFailed(err),
    );
    // Sent once: the password is not kept, whatever the answer.
    clearField(this.passwordField(), this.password);
  }

  protected async toggleActive(user: User): Promise<void> {
    if (this.busy()) return;
    if (
      user.active &&
      user.id === this.selfId() &&
      !window.confirm(
        $localize`:@@users.confirmDeactivateSelf:Deactivate your own account? You are signed out at once and cannot sign in again.`,
      )
    ) {
      return;
    }
    await this.patch(user, { active: !user.active }, 0);
  }

  protected async toggleAdmin(user: User): Promise<void> {
    if (this.busy()) return;
    if (
      user.isInstanceAdmin &&
      user.id === this.selfId() &&
      !window.confirm(
        $localize`:@@users.confirmDemoteSelf:Remove your own instance admin role? You can no longer manage users.`,
      )
    ) {
      return;
    }
    await this.patch(user, { isInstanceAdmin: !user.isInstanceAdmin }, 1);
  }

  protected async reset(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const user = this.others().find((u) => u.id === this.resetUser());
    if (!user) return;
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
      },
      (err) => {
        if (fieldErrors(err)['body.password'] === undefined) return false;
        this.resetError.set(passwordShort());
        this.resetField()?.nativeElement.focus();
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

  /** Maps a refused new user to its fields; true when every problem found a field. */
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
    this.focusFirstInvalid();
    return Object.keys(errors).length > 0;
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
   * `onError` may place the error on fields (returning true); anything else is an alert.
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
