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
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
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
 */
@Component({
  selector: 'q-scim-page',
  imports: [CopyValue, DateTimePipe, LabelPipe, SecretOnce],
  templateUrl: './scim.page.html',
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
  /** The token the server just created, until "Done", the next change or leaving the page. */
  protected readonly secret = signal<string | null>(null);
  /** The name typed for a new token, per connection. */
  protected readonly names = signal<Readonly<Record<string, string>>>({});
  protected readonly nameErrors = signal<Readonly<Record<string, string>>>({});
  /** The optional expiry date (`YYYY-MM-DD`, UTC end of day), per connection. */
  protected readonly expiries = signal<Readonly<Record<string, string>>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      untracked(() => {
        this.connections.set(null);
        this.secret.set(null);
        if (allowed) void this.load();
      });
    });
    inject(DestroyRef).onDestroy(() => this.secret.set(null));
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

  protected setName(connection: SsoConnection, event: Event): void {
    const value = inputValue(event);
    this.names.update((n) => ({ ...n, [connection.id]: value }));
    this.nameErrors.update((e) => ({ ...e, [connection.id]: '' }));
  }

  protected setExpiry(connection: SsoConnection, event: Event): void {
    const value = inputValue(event);
    this.expiries.update((e) => ({ ...e, [connection.id]: value }));
  }

  protected nameError(connection: SsoConnection): string | null {
    return this.nameErrors()[connection.id] || null;
  }

  protected async create(connection: SsoConnection, event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const name = (this.names()[connection.id] ?? '').trim();
    if (name === '' || name.length > MAX_NAME) {
      this.nameErrors.update((e) => ({
        ...e,
        [connection.id]: $localize`:@@scim.nameInvalid:Give the token a name of 1 to 200 characters, for example the identity provider it is for.`,
      }));
      this.focus(`scim-name-${connection.id}`);
      return;
    }
    const expiry = this.expiries()[connection.id] ?? '';
    await this.run(async () => {
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
        const { token, ...view } = created;
        this.tokens.update((all) => [...all, view]);
        this.names.update((n) => ({ ...n, [connection.id]: '' }));
        this.expiries.update((e) => ({ ...e, [connection.id]: '' }));
        this.secret.set(token);
        this.announcement.set(
          $localize`:@@scim.created:Token ${view.name}:name: created for ${connection.name}:connection:.`,
        );
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 422) throw err;
        this.nameErrors.update((e) => ({
          ...e,
          [connection.id]: $localize`:@@scim.createInvalid:Check the name, and give an expiry date in the future or none.`,
        }));
        this.focus(`scim-name-${connection.id}`);
      }
    });
  }

  protected async revoke(token: ScimToken): Promise<void> {
    if (this.busy()) return;
    const question = $localize`:@@scim.confirmRevoke:Revoke the SCIM token ${token.name}:name:? The identity provider can no longer provision people with it.`;
    if (!window.confirm(question)) return;
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

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    this.secret.set(null);
    try {
      await action();
    } catch (err) {
      this.error.set(ssoProblem(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
