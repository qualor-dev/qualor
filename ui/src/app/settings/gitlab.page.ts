import { DOCUMENT } from '@angular/common';
import {
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
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { gitlabTestText } from './gitlab-text';

export type Connection = ItemOf<'/api/v0/scm-connections'>;

/**
 * A base URL as the server stores it (scm.md §2.1: normalised, without a trailing slash), so that
 * re-typing the same address does not count as a new one. Null when it is not a URL at all.
 */
function normalBaseUrl(raw: string): string | null {
  try {
    return new URL(raw).href.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** A refused field of a connection's own form. */
interface RowError {
  field: 'url' | 'token';
  message: string;
}

/**
 * GitLab (scm.md §2), for org admins: the organisation's GitLab connections (a base URL and an
 * access token, which is write-only: it is sent once, never shown, and emptied from the page after
 * every submission) and a test of each. The server checks the URL (its SSRF rules, 422 on
 * `body.baseUrl`) and wants the token again with a new address (422 on `body.token`). Test answers
 * are shown in the page's own words per code (§4.4); the GitHub tab lists and changes GitHub
 * connections, and Repositories maps each project to a connection of either provider (step 11:
 * the mapping moved there from this page).
 *
 * Step 8 of the redesign (spec §7.8): each connection a panel whose pill says how its last test
 * here went (Not tested, Connected, Test failed: the server keeps no state), with Test and a quiet
 * Delete; its own form in setting rows; "New connection" (a short create form) in a dialog; the
 * deletion asks in the page's dialog instead of `confirm()`.
 */
@Component({
  selector: 'q-gitlab-page',
  imports: [DateTimePipe, Icon, RouterLink],
  templateUrl: './gitlab.page.html',
  styleUrl: './scm.page.css',
})
export class GitLabPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.scm.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.scm.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.scm.manage'));
  protected readonly connections = new KeysetList<Connection, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/scm-connections', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  /** The GitLab connections this page lists; the mapping offers every connection. */
  protected readonly gitlabConnections = computed(() =>
    this.connections.items().filter((c) => c.provider === 'gitlab'),
  );
  protected readonly url = signal('');
  protected readonly token = signal('');
  protected readonly urlError = signal<string | null>(null);
  protected readonly tokenError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** Test results and project messages, by connection or project id. */
  protected readonly results = signal<Record<string, string>>({});
  /** How each connection's last test on this page went, for its pill. */
  protected readonly outcomes = signal<Record<string, 'ok' | 'failed'>>({});
  /** A refused addition other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  /** The deletion the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingDelete = signal<{ connection: Connection; question: string } | null>(
    null,
  );
  /** Refused fields of the connections' own forms, by connection id. */
  protected readonly rowErrors = signal<Record<string, RowError>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
  private readonly tokenField = viewChild<ElementRef<HTMLInputElement>>('tokenField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        // Whatever belonged to the previous organisation goes, whether or not this one is shown.
        this.orgGeneration++;
        this.announcement.set(null);
        this.error.set(null);
        this.urlError.set(null);
        this.tokenError.set(null);
        this.results.set({});
        this.outcomes.set({});
        this.createError.set(null);
        this.rowErrors.set({});
        clearField(this.tokenField(), this.token);
        if (organizationId && admin) {
          void this.connections.reset(organizationId);
        }
      });
    });
    inject(DestroyRef).onDestroy(() => this.token.set(''));
  }

  protected setUrl(event: Event): void {
    this.url.set(inputValue(event));
    this.urlError.set(null);
  }

  protected setToken(event: Event): void {
    this.token.set(inputValue(event));
    this.tokenError.set(null);
  }

  protected clearRowError(connection: Connection): void {
    if (this.rowErrors()[connection.id] === undefined) return;
    this.rowErrors.update((all) => without(all, connection.id));
  }

  protected rowError(connection: Connection, field: RowError['field']): string | null {
    const error = this.rowErrors()[connection.id];
    return error?.field === field ? error.message : null;
  }

  /** Opens "New connection" on an empty address and token, with no message. */
  protected openCreate(): void {
    this.url.set('');
    clearField(this.tokenField(), this.token);
    this.urlError.set(null);
    this.tokenError.set(null);
    this.createError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  /** Cancel, or Escape: the dialog closes and the token typed in it goes. */
  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
    clearField(this.tokenField(), this.token);
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const baseUrl = this.url().trim();
    const token = this.token();
    this.urlError.set(baseUrl ? null : badUrl());
    this.tokenError.set(token ? null : badToken());
    this.createError.set(null);
    if (!baseUrl || !token) {
      this.focusFirstInvalid();
      return;
    }
    const generation = this.orgGeneration;
    try {
      await this.run(
        async () => {
          await ok(
            this.api.client.POST('/api/v0/scm-connections', {
              body: { organizationId, provider: 'gitlab', baseUrl, token },
            }),
          );
          if (generation !== this.orgGeneration) return;
          clearField(this.urlField(), this.url);
          this.announcement.set($localize`:@@gitlab.created:GitLab connection added.`);
          this.closeCreate();
          await this.connections.refresh();
        },
        (err) => {
          // A refused address or token goes to its field (run's own mapping); the rest shows in
          // the dialog that is still open.
          const fields = fieldErrors(err);
          if (fields['body.baseUrl'] !== undefined || fields['body.token'] !== undefined) {
            return false;
          }
          this.createError.set(problemMessage(err));
          return true;
        },
      );
    } finally {
      // The token never stays on the page after a submission, whatever the answer was.
      clearField(this.tokenField(), this.token);
    }
    this.focusFirstInvalid();
  }

  /**
   * A connection's own form: a new token, and with it, optionally, a new address. The token is
   * read from the field and never kept; a new address without a token is refused here, as the
   * server would (scm.md §2.1: the stored token only ever goes to the address it was saved for).
   */
  protected async update(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const urlField = form?.querySelector<HTMLInputElement>('input[type="url"]') ?? null;
    const tokenField = form?.querySelector<HTMLInputElement>('input[type="password"]') ?? null;
    if (this.busy()) return;
    // The token is read once and the field emptied at once, before any check or request: whatever
    // happens next (a refusal here, a 422, a network error), it never stays on the page.
    const token = tokenField?.value ?? '';
    if (tokenField) tokenField.value = '';
    const typed = (urlField?.value ?? connection.baseUrl).trim();
    const changed = typed !== '' && normalBaseUrl(typed) !== connection.baseUrl;
    const refuse = (field: RowError['field'], message: string) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: { field, message } }));
      (field === 'url' ? urlField : tokenField)?.focus();
    };
    if (typed === '' || !token) {
      if (typed === '') refuse('url', badUrl());
      else refuse('token', changed ? tokenForNewUrl() : badToken());
      return;
    }
    this.clearRowError(connection);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.PATCH('/api/v0/scm-connections/{id}', {
            params: { path: { id: connection.id } },
            body: changed ? { baseUrl: typed, token } : { token },
          }),
        );
        if (generation !== this.orgGeneration) return;
        this.connections.items.update((items) =>
          items.map((c) => (c.id === updated.id ? updated : c)),
        );
        this.results.update((all) => without(all, connection.id));
        // A new token or address has not been tested yet.
        this.outcomes.update((all) => without(all, connection.id));
        this.announcement.set(
          changed
            ? $localize`:@@gitlab.urlChanged:The connection now points at ${updated.baseUrl}:url:.`
            : $localize`:@@gitlab.tokenReplaced:The token of ${updated.baseUrl}:url: was replaced.`,
        );
      },
      (err) => {
        const fields = fieldErrors(err);
        if (fields['body.baseUrl'] !== undefined) refuse('url', badUrl());
        else if (fields['body.token'] !== undefined) {
          refuse('token', changed ? tokenForNewUrl() : badToken());
        } else return false;
        return true;
      },
    );
  }

  protected async test(connection: Connection): Promise<void> {
    if (this.busy()) return;
    const generation = this.orgGeneration;
    await this.run(async () => {
      const result = await ok(
        this.api.client.POST('/api/v0/scm-connections/{id}/test', {
          params: { path: { id: connection.id } },
          body: {},
        }),
      );
      if (generation !== this.orgGeneration) return;
      const text = gitlabTestText(result);
      this.results.update((all) => ({ ...all, [connection.id]: text }));
      const passed = result.ok && !!result.user;
      this.outcomes.update((all) => ({ ...all, [connection.id]: passed ? 'ok' : 'failed' }));
      // A failure reads as one: the error alert, never the green news of a success.
      if (passed) this.announcement.set(text);
      else this.error.set(text);
    });
  }

  /** Asks in the page's dialog; nothing is sent until its Delete. */
  protected remove(connection: Connection): void {
    if (this.busy()) return;
    this.pendingDelete.set({
      connection,
      question: $localize`:@@gitlab.confirmDelete:Delete the GitLab connection to ${connection.baseUrl}:url:? Its projects stop being decorated.`,
    });
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pendingDelete() !== null,
    );
  }

  protected async confirmDelete(): Promise<void> {
    const pending = this.pendingDelete();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingDelete.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    await this.applyDelete(pending.connection);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is deleted. */
  protected cancelDelete(): void {
    this.pendingDelete.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  private async applyDelete(connection: Connection): Promise<void> {
    if (this.busy()) return;
    const generation = this.orgGeneration;
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/scm-connections/{id}', {
          params: { path: { id: connection.id } },
        }),
      );
      if (generation !== this.orgGeneration) return;
      await this.connections.refresh();
      this.rowErrors.update((all) => without(all, connection.id));
      this.results.update((all) => without(all, connection.id));
      this.outcomes.update((all) => without(all, connection.id));
      this.announcement.set(
        $localize`:@@gitlab.deleted:GitLab connection ${connection.baseUrl}:url: deleted.`,
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  /** A 422 on a project's connection or GitLab project goes to that field, which takes focus. */
  private focusFirstInvalid(): void {
    if (this.urlError()) this.urlField()?.nativeElement.focus();
    else if (this.tokenError()) this.tokenField()?.nativeElement.focus();
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refused field goes to its field; anything else to the page's alert.
   */
  private async run(action: () => Promise<void>, field?: (err: unknown) => boolean): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    const generation = this.orgGeneration;
    try {
      await action();
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      if (field?.(err)) return;
      const fields = fieldErrors(err);
      if (fields['body.baseUrl'] !== undefined) this.urlError.set(badUrl());
      else if (fields['body.token'] !== undefined) this.tokenError.set(badToken());
      else {
        this.error.set(problemMessage(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}

function without<T>(all: Record<string, T>, id: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([key]) => key !== id));
}

function badUrl(): string {
  return $localize`:@@gitlab.badUrl:Use the https address of your GitLab, without a user name, password, query or fragment. An internal GitLab must be listed, with its port, by the operator in QUALOR_SCM_INTERNAL_HOSTS.`;
}

function badToken(): string {
  return $localize`:@@gitlab.badToken:Paste the access token as GitLab shows it (no spaces).`;
}

function tokenForNewUrl(): string {
  return $localize`:@@gitlab.tokenForNewUrl:Changing the address needs the token again: Qualor sends a stored token only to the address it was saved for.`;
}
