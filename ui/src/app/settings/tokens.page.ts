import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  DestroyRef,
  type ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus, rowAt } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { SecretOnce } from './secret-once';

export type Token = ItemOf<'/api/v0/tokens'>;
type Scope = Token['scopes'][number];
const SCOPES: Scope[] = ['read', 'write', 'admin', 'analysis:write'];
/** The expiries offered, in days ('' = never); the server accepts 1 to 3 650. */
const EXPIRY_DAYS = ['30', '90', '365', ''];
const MAX_EXPIRY_DAYS = 3650;

function scopeLabel(scope: Scope): string {
  switch (scope) {
    case 'read':
      return $localize`:@@tokens.scope.read:Read`;
    case 'write':
      return $localize`:@@tokens.scope.write:Write (triage issues)`;
    case 'admin':
      return $localize`:@@tokens.scope.admin:Admin`;
    default:
      return $localize`:@@tokens.scope.analysis:Upload analyses`;
  }
}

/**
 * Personal access tokens (api.md `GET/POST/DELETE /tokens`). Only a browser session creates one
 * (ruling R10; a token gets 403 `SESSION_REQUIRED`, shown as such). The list shows a token's
 * prefix and metadata only; the whole token is in the `POST` answer alone, shown once in
 * `SecretOnce` and dropped on "Done", on the next creation and when the page is left.
 *
 * Step 8 of the redesign (spec §7.8): the list in a panel with a quiet Revoke; "New token" opens a
 * dialog holding the form, which then shows the secret with Copy and Done (closing the dialog in
 * any way forgets it); Revoke asks in the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-tokens-page',
  imports: [DateTimePipe, Icon, SecretOnce],
  templateUrl: './tokens.page.html',
})
export class TokensPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly list = new KeysetList<Token, null>((_p, cursor) =>
    ok(
      this.api.client.GET('/api/v0/tokens', {
        params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly name = signal('');
  protected readonly scopes = signal<ReadonlySet<Scope>>(new Set(['read']));
  protected readonly expiry = signal('90');
  /** The new token's secret, until "Done", the next creation or leaving the page. */
  protected readonly created = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  protected readonly scopesError = signal<string | null>(null);
  protected readonly expiryError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The page was left: a late answer keeps no secret and opens no dialog. */
  private destroyed = false;
  /** The name of the token whose secret the dialog shows, until the dialog closes. */
  private createdName: string | null = null;
  /** A refused creation other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  /** The token the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingRevoke = signal<{ token: Token; question: string } | null>(null);
  protected readonly allScopes = SCOPES;
  protected readonly expiries = EXPIRY_DAYS;
  protected readonly scopeLabel = scopeLabel;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  private readonly scopesField = viewChild<ElementRef<HTMLElement>>('scopesField');
  private readonly expiryField = viewChild<ElementRef<HTMLSelectElement>>('expiryField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    void this.list.reset(null);
    inject(DestroyRef).onDestroy(() => {
      this.destroyed = true;
      this.created.set(null);
    });
  }

  /**
   * Escape does not close the dialog while it shows the secret (step 9 review): one reflexive key
   * would lose a secret shown only once. Done closes it; Escape still closes the form.
   */
  protected keepSecret(event: Event): void {
    if (this.created()) event.preventDefault();
  }

  protected setName(event: Event): void {
    this.name.set(inputValue(event));
    this.nameError.set(null);
  }

  protected setExpiry(event: Event): void {
    this.expiry.set(inputValue(event));
    this.expiryError.set(null);
  }

  protected toggleScope(scope: Scope, event: Event): void {
    const next = new Set(this.scopes());
    if (isChecked(event)) next.add(scope);
    else next.delete(scope);
    this.scopes.set(next);
    this.scopesError.set(null);
  }

  protected scopesText(token: Token): string {
    return token.scopes.map(scopeLabel).join(', ');
  }

  protected isExpired(token: Token): boolean {
    return token.expiresAt !== null && Date.parse(token.expiresAt) <= Date.now();
  }

  /** Opens "New token" on an empty form: the name, Read only, 90 days, no message. */
  protected openCreate(): void {
    this.created.set(null);
    this.name.set('');
    this.scopes.set(new Set(['read']));
    this.expiry.set('90');
    this.nameError.set(null);
    this.scopesError.set(null);
    this.expiryError.set(null);
    this.createError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  /** Cancel, or Done after the secret: the dialog closes, and its close forgets the secret. */
  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.forget();
  }

  protected forget(): void {
    this.created.set(null);
    // The secret is gone: the page no longer asks to copy it.
    const name = this.createdName;
    if (name !== null) {
      this.createdName = null;
      this.announcement.set($localize`:@@tokens.createdDone:Token ${name}:name: created.`);
    }
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const name = this.name().trim();
    const scopes = SCOPES.filter((s) => this.scopes().has(s));
    const days = this.expiry() === '' ? null : Number(this.expiry());
    let valid = true;
    if (!name) {
      this.nameError.set($localize`:@@tokens.nameRequired:Enter a name for the token.`);
      valid = false;
    }
    if (scopes.length === 0) {
      this.scopesError.set($localize`:@@tokens.scopeRequired:Choose at least one scope.`);
      valid = false;
    }
    if (days !== null && !(Number.isInteger(days) && days >= 1 && days <= MAX_EXPIRY_DAYS)) {
      this.expiryError.set($localize`:@@tokens.expiryInvalid:Choose one of the offered expiries.`);
      valid = false;
    }
    if (!valid) {
      this.focusFirstInvalid();
      return;
    }
    // A secret on screen belongs to the previous token: it goes before the next is asked for.
    this.created.set(null);
    this.createError.set(null);
    await this.run(async () => {
      const token = await ok(
        this.api.client.POST('/api/v0/tokens', {
          body: { name, scopes, ...(days === null ? {} : { expiresInDays: days }) },
        }),
      );
      // The page was left meanwhile: its secret is not kept.
      if (this.destroyed) return;
      this.created.set(token.token);
      this.createdName = token.name;
      clearField(this.nameField(), this.name);
      this.announcement.set(
        $localize`:@@tokens.created:Token ${token.name}:name: created. Copy it now: it is shown only this once.`,
      );
      await this.list.refresh();
    }, true);
    if (this.destroyed) return;
    // Closed while the server answered (Escape, Cancel): the dialog opens again on the outcome, or
    // the secret of a token it made could never be copied.
    const outcome =
      this.created() ??
      this.createError() ??
      this.nameError() ??
      this.scopesError() ??
      this.expiryError();
    if (outcome !== null) {
      openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
    }
  }

  /** Asks in the page's dialog; nothing is sent until its Revoke. */
  protected revoke(token: Token): void {
    if (this.busy()) return;
    this.pendingRevoke.set({
      token,
      question: $localize`:@@tokens.confirmRevoke:Revoke the token "${token.name}:name:"? Scripts using it stop working.`,
    });
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pendingRevoke() !== null,
    );
  }

  protected async confirmRevoke(): Promise<void> {
    const pending = this.pendingRevoke();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingRevoke.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    await this.applyRevoke(pending.token);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is revoked. */
  protected cancelRevoke(): void {
    this.pendingRevoke.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  private async applyRevoke(token: Token): Promise<void> {
    if (this.busy()) return;
    const index = this.list.items().findIndex((t) => t.id === token.id);
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/tokens/{id}', { params: { path: { id: token.id } } }),
      );
      await this.list.refresh();
      this.announcement.set($localize`:@@tokens.revoked:Token ${token.name}:name: revoked.`);
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  /** Moves focus to the first field with an error (after the error is rendered). */
  private focusFirstInvalid(): void {
    afterNextRender(
      () => {
        if (this.nameError()) this.nameField()?.nativeElement.focus();
        else if (this.scopesError()) {
          this.scopesField()?.nativeElement.querySelector<HTMLInputElement>('input')?.focus();
        } else if (this.expiryError()) this.expiryField()?.nativeElement.focus();
      },
      { injector: this.injector },
    );
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refusal of the dialog's form (`inDialog`) that names no field shows in the dialog.
   */
  private async run(action: () => Promise<void>, inDialog = false): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const fields = fieldErrors(err);
      if (fields['body.name'] !== undefined) {
        this.nameError.set(
          $localize`:@@tokens.nameInvalid:Enter a name of at most 100 characters, without control characters.`,
        );
      } else if (fields['body.scopes'] !== undefined) {
        this.scopesError.set($localize`:@@tokens.scopeRequired:Choose at least one scope.`);
      } else if (fields['body.expiresInDays'] !== undefined) {
        this.expiryError.set(
          $localize`:@@tokens.expiryInvalid:Choose one of the offered expiries.`,
        );
      } else if (inDialog) {
        this.createError.set(problemMessage(err));
        return;
      } else {
        this.error.set(problemMessage(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
        return;
      }
      this.focusFirstInvalid();
    } finally {
      this.busy.set(false);
    }
  }
}
