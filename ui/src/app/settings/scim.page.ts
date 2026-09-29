import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { done, ok } from '../api/api';
import { EeApi, type ScimToken, type SsoConnection } from '../api/ee';
import { ApiError, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { LabelPipe } from '../i18n/label.pipe';
import { SystemInfo } from '../shell/system-info';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openModal } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { CopyValue } from './copy-value';
import { SecretOnce } from './secret-once';
import { ssoProblem } from './sso-settings-text';

/** sso-scim.md §12.1: the SCIM base URL, below QUALOR_PUBLIC_URL. */
const SCIM_PATH = '/api/v0/ee/scim/v2';
/** Where every connection URL starts below QUALOR_PUBLIC_URL (§4.1). */
const SSO_PATH = '/api/v0/ee/sso/';
const MAX_NAME = 200;

/**
 * Settings → SCIM (sso-scim.md §12, §18; feature `scim`, instance admins): per SSO connection,
 * the SCIM base URL to copy into the identity provider and its tokens (name, prefix, created,
 * expiry, last use). **Create token** answers the token once: it is shown through `q-secret-once`
 * and forgotten on "Done", on the next change and when the page is left; the list only ever has
 * its prefix. **Revoke** asks first. The connections come from the `sso` routes, so the page needs
 * both features.
 *
 * Step 9 of the redesign (spec §7.8): a panel per connection with its base URL and its tokens;
 * **New token** opens a dialog for that connection, which then holds the token once (and opens
 * again on the outcome if it was closed while the server answered); **Revoke** asks in the page's
 * dialog instead of the browser's `confirm()`, with the same question.
 */
@Component({
  selector: 'q-scim-page',
  imports: [CopyValue, DateTimePipe, Icon, LabelPipe, SecretOnce],
  templateUrl: './scim.page.html',
  styleUrl: './scim.page.css',
})
export class ScimPage {
  private readonly ee = inject(EeApi);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  protected readonly licensed = computed(() => this.info.features().includes('scim'));
  protected readonly ssoActive = computed(() => this.info.features().includes('sso'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly allowed = computed(
    () => this.licensed() && this.ssoActive() && this.instanceAdmin(),
  );

  protected readonly connections = signal<SsoConnection[] | null>(null);
  protected readonly tokens = signal<ScimToken[]>([]);
  protected readonly loadError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The page was left: a late answer keeps no secret and opens no dialog. */
  private destroyed = false;
  /** The token the server just created, until "Done", the next change or leaving the page. */
  protected readonly secret = signal<string | null>(null);
  /** The connection "New token" was opened for. */
  private readonly creatingFor = signal<SsoConnection | null>(null);
  protected readonly createTitle = computed(() => {
    const connection = this.creatingFor();
    return connection ? this.newTokenTitle(connection) : '';
  });
  protected readonly name = signal('');
  protected readonly nameError = signal<string | null>(null);
  /** The optional expiry date (`YYYY-MM-DD`, UTC end of day). */
  protected readonly expiry = signal('');
  /** A refusal of the dialog's form that names no field, shown in the dialog. */
  protected readonly createError = signal<string | null>(null);
  /** The token Revoke asks about, with the question; null while the dialog is closed. */
  protected readonly pendingRevoke = signal<{ token: ScimToken; question: string } | null>(null);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      untracked(() => {
        this.connections.set(null);
        this.secret.set(null);
        if (allowed) void this.load();
      });
    });
    inject(DestroyRef).onDestroy(() => {
      this.destroyed = true;
      this.secret.set(null);
    });
  }

  /**
   * Escape does not close the dialog while it shows the secret (step 9 review): one reflexive key
   * would lose a secret shown only once. Done closes it; Escape still closes the form.
   */
  protected keepSecret(event: Event): void {
    if (this.secret()) event.preventDefault();
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      const [connections, tokens] = await Promise.all([
        ok(this.ee.client.GET('/api/v0/ee/sso/connections')),
        ok(this.ee.client.GET('/api/v0/ee/scim/tokens')),
      ]);
      this.connections.set(connections);
      this.tokens.set(tokens);
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  /**
   * `<QUALOR_PUBLIC_URL>/api/v0/ee/scim/v2`, from the connection's redirect URI (an absolute URL
   * below QUALOR_PUBLIC_URL; `startUrl` is a path); null while QUALOR_PUBLIC_URL is unset.
   */
  protected baseUrl(connection: SsoConnection): string | null {
    const redirect = connection.urls?.redirectUri;
    const at = redirect?.indexOf(SSO_PATH) ?? -1;
    return redirect && at > 0 ? `${redirect.slice(0, at)}${SCIM_PATH}` : null;
  }

  protected tokensOf(connection: SsoConnection): ScimToken[] {
    return this.tokens().filter((t) => t.connectionId === connection.id);
  }

  protected newTokenTitle(connection: SsoConnection): string {
    return $localize`:@@scim.newTokenFor:New token for ${connection.name}:name:`;
  }

  /** Opens "New token" for the connection on an empty form, with no token and no message. */
  protected openCreate(connection: SsoConnection): void {
    this.creatingFor.set(connection);
    this.secret.set(null);
    this.name.set('');
    this.expiry.set('');
    this.nameError.set(null);
    this.createError.set(null);
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  /** Cancel, or Done after the token: the dialog closes, and its close forgets the token. */
  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
    this.forget();
  }

  protected setName(event: Event): void {
    this.name.set(inputValue(event));
    this.nameError.set(null);
  }

  protected setExpiry(event: Event): void {
    this.expiry.set(inputValue(event));
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const connection = this.creatingFor();
    if (!connection || this.busy()) return;
    const name = this.name().trim();
    if (name === '' || name.length > MAX_NAME) {
      this.nameError.set(
        $localize`:@@scim.nameInvalid:Give the token a name of 1 to 200 characters, for example the identity provider it is for.`,
      );
      this.focus('scim-token-name');
      return;
    }
    const expiry = this.expiry();
    this.createError.set(null);
    await this.run(
      async () => {
        try {
          const created = await ok(
            this.ee.client.POST('/api/v0/ee/scim/tokens', {
              body: {
                connectionId: connection.id,
                name,
                expiresAt: /^\d{4}-\d{2}-\d{2}$/.test(expiry) ? `${expiry}T23:59:59Z` : null,
              },
            }),
          );
          // The page was left meanwhile: its token is not kept.
          if (this.destroyed) return;
          const { token, ...view } = created;
          this.tokens.update((all) => [...all, view]);
          this.name.set('');
          this.expiry.set('');
          this.secret.set(token);
          this.announcement.set(
            $localize`:@@scim.created:Token ${view.name}:name: created for ${connection.name}:connection:.`,
          );
        } catch (err) {
          if (!(err instanceof ApiError) || err.status !== 422) throw err;
          this.nameError.set(
            $localize`:@@scim.createInvalid:Check the name, and give an expiry date in the future or none.`,
          );
          this.focus('scim-token-name');
        }
      },
      (err) => this.createError.set(ssoProblem(err)),
    );
    if (this.destroyed) return;
    // Closed while the server answered (Escape, Cancel): the dialog opens again on the outcome, or
    // a token it made could never be copied.
    const outcome = this.secret() ?? this.createError() ?? this.nameError();
    const dialog = this.createDialog()?.nativeElement;
    if (dialog && outcome !== null) openModal(dialog);
  }

  /** Asks in the page's dialog; nothing is sent until its Revoke. */
  protected revoke(token: ScimToken): void {
    if (this.busy()) return;
    this.pendingRevoke.set({
      token,
      question: $localize`:@@scim.confirmRevoke:Revoke the SCIM token ${token.name}:name:? The identity provider can no longer provision people with it.`,
    });
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  protected async confirmRevoke(): Promise<void> {
    const pending = this.pendingRevoke();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingRevoke.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
    await this.applyRevoke(pending.token);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is revoked. */
  protected cancelRevoke(): void {
    this.pendingRevoke.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  private async applyRevoke(token: ScimToken): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      await done(
        this.ee.client.DELETE('/api/v0/ee/scim/tokens/{id}', {
          params: { path: { id: token.id } },
        }),
      );
      this.tokens.set(await ok(this.ee.client.GET('/api/v0/ee/scim/tokens')));
      this.announcement.set($localize`:@@scim.revoked:Token ${token.name}:name: revoked.`);
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  protected revokeLabel(token: ScimToken): string {
    return $localize`:@@scim.revokeNamed:Revoke ${token.name}:name:`;
  }

  protected forget(): void {
    this.secret.set(null);
  }

  private focus(id: string): void {
    afterNextRender(() => this.document.getElementById(id)?.focus(), { injector: this.injector });
  }

  /** Runs one change; a refusal goes to `onError` when given (the dialog), else to the page. */
  private async run(action: () => Promise<void>, onError?: (err: unknown) => void): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    this.secret.set(null);
    try {
      await action();
    } catch (err) {
      if (onError) {
        onError(err);
      } else {
        this.error.set(ssoProblem(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}
