import { Component, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { fieldErrors, problemMessage } from '../api/errors';
import { inputValue } from '../shared/forms';
import { AuthService } from './auth.service';
import { SessionStore } from './session';

/** api.md §2: the minimum length `PUT /auth/me/password` accepts. */
export const PASSWORD_MIN_LENGTH = 12;

@Component({
  selector: 'q-change-password-page',
  templateUrl: './change-password.page.html',
})
export class ChangePasswordPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly session = inject(SessionStore);

  /** Ruling R7: an admin created or reset this account, so the password must change first. */
  protected readonly forced = computed(() => this.session.user()?.passwordChangeRequired === true);
  /** For password managers: which account the new password belongs to (a hidden field). */
  protected readonly username = computed(() => this.session.user()?.username ?? '');
  protected readonly current = signal('');
  protected readonly next = signal('');
  protected readonly confirm = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly currentError = signal<string | null>(null);
  protected readonly nextError = signal<string | null>(null);
  protected readonly minLength = PASSWORD_MIN_LENGTH;
  protected readonly inputValue = inputValue;

  /** A forced change blocks every other page; signing out is the other way off this one. */
  protected signOut(): void {
    void this.auth.logout();
  }

  protected async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    this.error.set(null);
    this.currentError.set(null);
    this.nextError.set(null);
    if (this.next().length < PASSWORD_MIN_LENGTH) {
      this.nextError.set(
        $localize`:@@password.tooShort:Use at least ${PASSWORD_MIN_LENGTH}:min: characters.`,
      );
      return;
    }
    if (this.next() !== this.confirm()) {
      this.nextError.set($localize`:@@password.mismatch:The two new passwords differ.`);
      return;
    }
    this.busy.set(true);
    try {
      await this.auth.changePassword(this.current(), this.next());
      await this.router.navigateByUrl('/projects');
    } catch (err) {
      const fields = fieldErrors(err);
      if (fields['body.currentPassword']) {
        this.currentError.set(
          $localize`:@@password.currentWrong:The current password is not correct.`,
        );
      } else if (fields['body.newPassword']) {
        this.nextError.set(
          $localize`:@@password.newRejected:Choose a new password that differs from the current one.`,
        );
      } else {
        this.error.set(problemMessage(err));
      }
    } finally {
      this.busy.set(false);
    }
  }
}
