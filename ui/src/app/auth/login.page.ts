import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  type ElementRef,
  inject,
  Injector,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import { ApiError, problemMessage } from '../api/errors';
import type { AuthMethods, SsoProvider } from '../api/types';
import { AuthLayout } from '../shared/auth-layout';
import { inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { AuthService } from './auth.service';
import { safeReturnUrl } from './guards';
import { ssoErrorText } from './sso-text';

/** What a server that cannot say (an older one, or a failed request) allows: passwords only. */
const PASSWORD_ONLY: AuthMethods = { password: 'everyone', providers: [] };

@Component({
  selector: 'q-login-page',
  imports: [AuthLayout, Icon],
  templateUrl: './login.page.html',
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  /** `?returnUrl=` (router input binding): where to go after signing in. */
  readonly returnUrl = input<string>();
  /**
   * `?sso_error=` (router input binding, sso-scim.md §7.7): why a single sign-on failed. Only
   * mapped to a fixed message; the value itself is never shown.
   */
  readonly ssoError = input<string | undefined>(undefined, { alias: 'sso_error' });

  /**
   * `GET /auth/methods`; undefined while it loads, so a folded password form never appears and
   * then vanishes under the cursor. A failure counts as a server without single sign-on.
   */
  protected readonly methods = signal<AuthMethods | undefined>(undefined);
  protected readonly providers = computed<readonly SsoProvider[]>(
    () => this.methods()?.providers ?? [],
  );
  /** Password sign-in is only for break-glass admins: the form is folded under a button. */
  protected readonly folded = computed(() => this.methods()?.password === 'break_glass_only');
  protected readonly unfolded = signal(false);
  protected readonly showForm = computed(
    () => this.methods() !== undefined && (!this.folded() || this.unfolded()),
  );
  protected readonly ssoErrorMessage = computed(() => {
    const code = this.ssoError();
    return code ? ssoErrorText(code) : null;
  });
  private readonly usernameField = viewChild<ElementRef<HTMLInputElement>>('usernameField');

  protected readonly username = signal('');
  protected readonly password = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly inputValue = inputValue;

  constructor() {
    this.auth.methods().then(
      (methods) => this.methods.set(methods),
      () => this.methods.set(PASSWORD_ONLY),
    );
  }

  /**
   * A provider's start address: a full navigation (the server redirects to the identity
   * provider), with where to come back to, limited to a path of this app.
   */
  protected startHref(provider: SsoProvider): string {
    const base = this.document.baseURI;
    const url = new URL(provider.startUrl, base);
    url.searchParams.set('returnTo', safeReturnUrl(this.returnUrl()));
    // A start address on this server stays relative, as the server gave it.
    return url.origin === new URL(base).origin
      ? `${url.pathname}${url.search}${url.hash}`
      : url.href;
  }

  /** Shows or hides the folded password form; showing it moves focus to its first field. */
  protected toggleForm(): void {
    this.unfolded.update((open) => !open);
    if (!this.unfolded()) return;
    afterNextRender(() => this.usernameField()?.nativeElement.focus(), {
      injector: this.injector,
    });
  }

  protected async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const me = await this.auth.login(this.username().trim(), this.password());
      const target = me?.user.passwordChangeRequired
        ? '/change-password'
        : safeReturnUrl(this.returnUrl());
      await this.router.navigateByUrl(target);
    } catch (err) {
      this.error.set(
        err instanceof ApiError && err.code === 'INVALID_CREDENTIALS'
          ? $localize`:@@login.invalid:Invalid username or password.`
          : problemMessage(err),
      );
      this.password.set('');
    } finally {
      this.busy.set(false);
    }
  }
}
