import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  DestroyRef,
  type ElementRef,
  effect,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../../api/api';
import { ApiError, fieldErrors, problemMessage } from '../../api/errors';
import type { ItemOf } from '../../api/types';
import { DateTimePipe } from '../../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { keepFocus, rowAt } from '../../shared/focus';
import { clearField, inputValue } from '../../shared/forms';
import { Icon } from '../../shared/icon';
import { KeysetList } from '../../shared/keyset';
import { SecretOnce } from '../../settings/secret-once';
import type { ProjectDto } from '../current-project';

type ProjectToken = ItemOf<'/api/v0/projects/{id}/tokens'>;
/** The expiries offered, in days ('' = never); the server accepts 1 to 3 650. */
const EXPIRY_DAYS = ['30', '90', '365', ''];
const MAX_EXPIRY_DAYS = 3650;
const PAGE_SIZE = 50;

/**
 * Project → Settings → Analysis tokens (spec §3.4): the project's live analysis tokens with a
 * quiet Revoke, and "New token" in a dialog. The whole token is in the `POST` answer alone, shown
 * once in `SecretOnce` and dropped on Done, on closing the dialog, on the next creation and when
 * the panel is left (same rules as Settings → Tokens). Escape does not close the dialog while it
 * shows the secret.
 */
@Component({
  selector: 'q-project-tokens-panel',
  imports: [DateTimePipe, Icon, SecretOnce],
  templateUrl: './project-tokens-panel.html',
  styleUrl: './project-tokens-panel.css',
})
export class ProjectTokensPanel {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  readonly project = input.required<ProjectDto>();

  protected readonly list = new KeysetList<ProjectToken, string>((id, cursor) =>
    ok(
      this.api.client.GET('/api/v0/projects/{id}/tokens', {
        params: { path: { id }, query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly name = signal('');
  protected readonly expiry = signal('90');
  /** The new token's secret, until Done, the dialog closing, the next creation or leaving. */
  protected readonly created = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  protected readonly expiryError = signal<string | null>(null);
  protected readonly createError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The token the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingRevoke = signal<{ token: ProjectToken; question: string } | null>(null);
  protected readonly expiries = EXPIRY_DAYS;
  /** The panel was left: a late answer keeps no secret and opens no dialog. */
  private destroyed = false;
  private createdName: string | null = null;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  private readonly expiryField = viewChild<ElementRef<HTMLSelectElement>>('expiryField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    effect(() => {
      const id = this.project().id;
      untracked(() => void this.list.reset(id));
    });
    inject(DestroyRef).onDestroy(() => {
      this.destroyed = true;
      this.created.set(null);
    });
  }

  /** Escape does not close the dialog while it shows the secret; Done does. */
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

  /** Opens "New token" on an empty form: the name, 90 days, no message. */
  protected openCreate(): void {
    this.created.set(null);
    this.name.set('');
    this.expiry.set('90');
    this.nameError.set(null);
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
    const name = this.createdName;
    if (name !== null) {
      this.createdName = null;
      this.announcement.set($localize`:@@projectTokens.createdDone:Token ${name}:name: created.`);
    }
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const name = this.name().trim();
    const days = this.expiry() === '' ? null : Number(this.expiry());
    let valid = true;
    if (!name) {
      this.nameError.set($localize`:@@projectTokens.nameRequired:Enter a name.`);
      valid = false;
    }
    if (days !== null && !(Number.isInteger(days) && days >= 1 && days <= MAX_EXPIRY_DAYS)) {
      this.expiryError.set(
        $localize`:@@projectTokens.expiryInvalid:Choose one of the offered expiries.`,
      );
      valid = false;
    }
    if (!valid) {
      this.focusFirstInvalid();
      return;
    }
    // A secret on screen belongs to the previous token: it goes before the next is asked for.
    this.created.set(null);
    this.createError.set(null);
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      const token = await ok(
        this.api.client.POST('/api/v0/projects/{id}/tokens', {
          params: { path: { id: this.project().id } },
          body: { name, ...(days === null ? {} : { expiresInDays: days }) },
        }),
      );
      // The panel was left meanwhile: its secret is not kept.
      if (this.destroyed) return;
      this.created.set(token.token);
      this.createdName = token.name;
      clearField(this.nameField(), this.name);
      this.announcement.set(
        $localize`:@@projectTokens.created:Token ${token.name}:name: created. Copy it now: it is shown only this once.`,
      );
      await this.list.refresh();
    } catch (err) {
      this.showCreateFailure(err);
    } finally {
      this.busy.set(false);
    }
    if (this.destroyed) return;
    // Closed while the server answered (Escape, Cancel): the dialog opens again on the outcome, or
    // the secret of a token it made could never be copied.
    const outcome = this.created() ?? this.createError() ?? this.nameError() ?? this.expiryError();
    if (outcome !== null) {
      openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
    }
  }

  private showCreateFailure(err: unknown): void {
    const fields = fieldErrors(err);
    if (fields['body.name'] !== undefined) {
      this.nameError.set(
        $localize`:@@projectTokens.nameInvalid:Enter a name of at most 100 characters, without control characters.`,
      );
    } else if (fields['body.expiresInDays'] !== undefined) {
      this.expiryError.set(
        $localize`:@@projectTokens.expiryInvalid:Choose one of the offered expiries.`,
      );
    } else if (err instanceof ApiError && err.status === 409) {
      this.nameError.set(
        $localize`:@@projectTokens.nameTaken:A token with this name already exists. Choose another name.`,
      );
    } else {
      this.createError.set(problemMessage(err));
      return;
    }
    this.focusFirstInvalid();
  }

  /** Asks in the panel's dialog; nothing is sent until its Revoke. */
  protected revoke(token: ProjectToken): void {
    if (this.busy()) return;
    this.pendingRevoke.set({
      token,
      question: $localize`:@@projectTokens.confirmRevoke:Revoke the token ${token.name}:name:? CI jobs that use it stop working.`,
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

  private async applyRevoke(token: ProjectToken): Promise<void> {
    if (this.busy()) return;
    const index = this.list.items().findIndex((t) => t.id === token.id);
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}/tokens/{tokenId}', {
          params: { path: { id: this.project().id, tokenId: token.id } },
        }),
      );
      await this.list.refresh();
      this.announcement.set($localize`:@@projectTokens.revoked:Token ${token.name}:name: revoked.`);
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    } catch (err) {
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }

  /** Moves focus to the first field with an error (after the error is rendered). */
  private focusFirstInvalid(): void {
    afterNextRender(
      () => {
        if (this.nameError()) this.nameField()?.nativeElement.focus();
        else if (this.expiryError()) this.expiryField()?.nativeElement.focus();
      },
      { injector: this.injector },
    );
  }
}
