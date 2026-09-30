import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  InjectionToken,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { done, ok } from '../api/api';
import { EeApi, type LinkedIdentity } from '../api/ee';
import { ApiError, problemMessage } from '../api/errors';
import type { SsoProvider } from '../api/types';
import { AuthService } from '../auth/auth.service';
import { ssoErrorText } from '../auth/sso-text';
import { LabelPipe } from '../i18n/label.pipe';
import { SystemInfo } from '../shell/system-info';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';

/**
 * Leaves the app for another address with a full navigation (linking goes through the identity
 * provider). A token, so tests can see the address without leaving the test page.
 */
export const LEAVE_APP = new InjectionToken<(url: string) => void>('LEAVE_APP', {
  providedIn: 'root',
  factory: () => {
    const document = inject(DOCUMENT);
    return (url: string) => document.location.assign(url);
  },
});

/** A refused link or unlink in this page's words (sso-scim.md §7.3, §8.5). */
function linkProblem(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'LAST_SIGN_IN_METHOD':
        return $localize`:@@linkedAccounts.lastMethod:This is your only way to sign in. Ask an administrator to set a password first.`;
      case 'SCIM_MANAGED_IDENTITY':
        return scimManagedText();
      case 'SSO_UNAVAILABLE':
        return $localize`:@@linkedAccounts.unavailable:The identity provider cannot be used right now. Try again later.`;
      case 'RATE_LIMITED':
        return $localize`:@@linkedAccounts.rateLimited:Too many link attempts. Wait a minute and try again.`;
    }
  }
  return problemMessage(err);
}

function scimManagedText(): string {
  return $localize`:@@linkedAccounts.scimManaged:Your identity provider manages this link; only an administrator can remove it.`;
}

/**
 * Settings → Linked accounts (sso-scim.md §18, feature `sso`, every user): your own identities
 * (connection, linked on, last sign-in), **Link** for each enabled connection you have none on
 * (`POST …/link`, then the browser goes to the identity provider and comes back here), and
 * **Unlink** after a confirmation. An identity your identity provider provisions (SCIM) has no
 * Unlink: only an administrator may remove it (409 `SCIM_MANAGED_IDENTITY`). The server refuses
 * to unlink your only way to sign in (409 `LAST_SIGN_IN_METHOD`). A failed link comes back as
 * `?sso_error=<code>`, shown as its fixed message. Nothing is asked of the enterprise API while
 * `sso` is inactive.
 *
 * Step 9 of the redesign (spec §7.8): your accounts as a table in a panel, the connections to link
 * in another; **Unlink** asks in the page's dialog instead of the browser's `confirm()`, with the
 * same question.
 */
@Component({
  selector: 'q-linked-accounts-page',
  imports: [DateTimePipe, LabelPipe],
  templateUrl: './linked-accounts.page.html',
  styleUrl: './linked-accounts.page.css',
})
export class LinkedAccountsPage {
  private readonly ee = inject(EeApi);
  private readonly auth = inject(AuthService);
  private readonly info = inject(SystemInfo);
  private readonly leave = inject(LEAVE_APP);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  /** `?sso_error=` (router input binding): why a link failed; only its fixed message is shown. */
  readonly ssoError = input<string | undefined>(undefined, { alias: 'sso_error' });

  protected readonly licensed = computed(() => this.info.features().includes('sso'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly ssoErrorMessage = computed(() => {
    const code = this.ssoError();
    return code ? ssoErrorText(code) : null;
  });

  protected readonly identities = signal<LinkedIdentity[] | null>(null);
  private readonly providers = signal<readonly SsoProvider[]>([]);
  /** The enabled connections you have no identity on. */
  protected readonly linkable = computed(() => {
    const linked = new Set((this.identities() ?? []).map((i) => i.connectionId));
    return this.providers().filter((p) => !linked.has(p.id));
  });
  protected readonly loadError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The identity Unlink asks about, with the question; null while the dialog is closed. */
  protected readonly pendingUnlink = signal<{
    identity: LinkedIdentity;
    question: string;
  } | null>(null);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    effect(() => {
      const licensed = this.licensed();
      untracked(() => {
        this.identities.set(null);
        if (licensed) void this.load();
      });
    });
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      const [identities, providers] = await Promise.all([
        ok(this.ee.client.GET('/api/v0/ee/sso/me/identities')),
        // The list of connections to link is a convenience: without it, nothing is offered.
        this.auth.methods().then(
          (methods) => methods.providers,
          () => [],
        ),
      ]);
      this.identities.set(identities);
      this.providers.set(providers);
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  protected async link(provider: SsoProvider): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      const { url } = await ok(
        this.ee.client.POST('/api/v0/ee/sso/connections/{id}/link', {
          params: { path: { id: provider.id } },
        }),
      );
      this.leave(url);
    });
  }

  /** Asks in the page's dialog; nothing is sent until its Unlink. */
  protected unlink(identity: LinkedIdentity): void {
    if (this.busy()) return;
    this.pendingUnlink.set({
      identity,
      question: $localize`:@@linkedAccounts.confirmUnlink:Unlink ${identity.connectionName}:connection:? You can no longer sign in with it until you link it again.`,
    });
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pendingUnlink() !== null,
    );
  }

  protected async confirmUnlink(): Promise<void> {
    const pending = this.pendingUnlink();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingUnlink.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
    await this.applyUnlink(pending.identity);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is unlinked. */
  protected cancelUnlink(): void {
    this.pendingUnlink.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  protected unlinkLabel(identity: LinkedIdentity): string {
    return $localize`:@@linkedAccounts.unlinkNamed:Unlink ${identity.connectionName}:connection:`;
  }

  private async applyUnlink(identity: LinkedIdentity): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      await done(
        this.ee.client.DELETE('/api/v0/ee/sso/me/identities/{identityId}', {
          params: { path: { identityId: identity.id } },
        }),
      );
      this.identities.set(await ok(this.ee.client.GET('/api/v0/ee/sso/me/identities')));
      this.announcement.set(
        $localize`:@@linkedAccounts.unlinked:${identity.connectionName}:connection: unlinked.`,
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  protected scimManaged(): string {
    return scimManagedText();
  }

  /** Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. */
  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      this.error.set(linkProblem(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
