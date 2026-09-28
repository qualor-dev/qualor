import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  type ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { DateTimePipe } from '../shared/date-time.pipe';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import {
  cleanKey,
  knownReasonText,
  licenseTexts,
  MAX_KEY_TEXT,
  reasonText,
  type LicenseStatus,
} from './license-text';

export type { LicenseStatus } from './license-text';

/**
 * Settings → Licence (enterprise.md §11), instance admins only. Shows the edition and state in
 * words, the licence's customer, dates and limits, and either a form to paste a key (source
 * uploaded or none) or the variable that sets it (environment, file). A saved key applies at the
 * next start (§6), so the page says a restart is required until then.
 *
 * The key is sent once, in the `PUT` body only: it is not kept in any signal after the answer, not
 * announced, not logged, and the field is emptied as soon as it is sent. The field refuses password
 * managers and spelling services (`autocomplete="off"`, `data-1p-ignore`, `data-lpignore`,
 * `spellcheck="false"`).
 */
@Component({
  selector: 'q-license-page',
  imports: [DateTimePipe],
  templateUrl: './license.page.html',
})
export class LicensePage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly session = inject(SessionStore);
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);

  protected readonly status = signal<LicenseStatus | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly key = signal('');
  protected readonly keyError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /**
   * The saved key was removed in this visit. The status cannot tell (the server still runs with the
   * key it booted with, and `restartRequired` is true either way), so Remove is hidden until a key
   * is saved again or the server restarted.
   */
  private readonly removedPending = signal(false);
  protected readonly texts = licenseTexts;
  /** Why the boot key was rejected, in the UI's words; null when the server gave no known reason. */
  protected readonly rejectedReason = computed(() => knownReasonText(this.status()?.reason));

  /** The form is offered only when the key does not come from a variable (enterprise.md §9). */
  protected readonly managedBy = computed(() => {
    const source = this.status()?.source;
    if (source === 'environment') return 'QUALOR_LICENSE';
    if (source === 'file') return 'QUALOR_LICENSE_FILE';
    return null;
  });
  /** A key is saved in Qualor: the server booted with one, or one waits for the next start. */
  protected readonly canRemove = computed(() => {
    const s = this.status();
    if (s === null || this.removedPending()) return false;
    return s.source === 'uploaded' || (s.source === null && s.restartRequired);
  });

  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly keyField = viewChild<ElementRef<HTMLTextAreaElement>>('keyField');

  constructor() {
    if (this.instanceAdmin()) void this.load();
  }

  private async load(): Promise<void> {
    try {
      this.status.set(await ok(this.api.client.GET('/api/v0/license')));
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  protected setKey(event: Event): void {
    this.key.set(inputValue(event));
    this.keyError.set(null);
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const key = cleanKey(this.key());
    if (key === '') {
      this.keyError.set(licenseTexts.required());
      this.focusKey();
      return;
    }
    if (key.length > MAX_KEY_TEXT) {
      this.keyError.set(reasonText('malformed'));
      this.focusKey();
      return;
    }
    // Sent once: the field and its signal are emptied whatever the answer, so the key is never
    // on screen again (a refused key is pasted afresh, after the copy is fixed).
    clearField(this.keyField(), this.key);
    await this.run(async () => {
      const status = await ok(this.api.client.PUT('/api/v0/license', { body: { key } }));
      this.status.set(status);
      this.removedPending.set(false);
      this.announcement.set(
        status.restartRequired ? licenseTexts.saved() : licenseTexts.savedSame(),
      );
    });
  }

  protected async remove(): Promise<void> {
    if (this.busy()) return;
    if (!window.confirm(licenseTexts.confirmRemove())) return;
    await this.run(async () => {
      const status = await ok(this.api.client.DELETE('/api/v0/license'));
      this.status.set(status);
      this.removedPending.set(true);
      this.announcement.set(
        status.restartRequired ? licenseTexts.removed() : licenseTexts.removedNothing(),
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  /** Runs one change; while one runs, the buttons stay focusable but do nothing. */
  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.keyError.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const field = this.fieldMessage(err);
      if (field !== null) {
        this.keyError.set(field);
        this.focusKey();
        return;
      }
      if (err instanceof ApiError && err.code === 'LICENSE_MANAGED_BY_ENVIRONMENT') {
        // The page was older than the server's start: show where the key comes from now.
        this.error.set(licenseTexts.managedByEnvironment());
        void this.load();
      } else {
        this.error.set(problemMessage(err));
      }
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }

  /**
   * The message under the key field for a refused key, in the UI's words: the reason a
   * `LICENSE_INVALID` names, an expired key, or a key the schema refused (too long, not text).
   * The schema check (422) runs before the server's 409 and 403 checks (task 9 review), so any
   * 422 on `body.key` is about the key.
   */
  private fieldMessage(err: unknown): string | null {
    if (!(err instanceof ApiError) || err.status !== 422) return null;
    const message = fieldErrors(err)['body.key'];
    if (err.code === 'LICENSE_EXPIRED') return licenseTexts.expired();
    // The machine code in `reason` (enterprise.md §9), never the English `errors[].message`.
    if (err.code === 'LICENSE_INVALID') {
      return knownReasonText(err.problem?.reason) ?? licenseTexts.rejected();
    }
    if (message !== undefined) return reasonText('malformed');
    return null;
  }

  private focusKey(): void {
    afterNextRender(() => this.keyField()?.nativeElement.focus(), { injector: this.injector });
  }
}
