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
import { clearField, inputValue, isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { CopyValue } from './copy-value';
import { gitlabTestText } from './gitlab-text';
import { WEBHOOK_SECRET } from './webhook-secret';

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

/** A refused field of a connection's own forms: its address and token, and its webhook secret. */
interface RowError {
  field: 'url' | 'token' | 'newSecret' | 'secret';
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
 * 6I-4: each connection also shows the URL of its webhook, to paste into the GitLab project's
 * webhooks with the secret, so that replies and commands in merge requests are answered at once.
 * The secret is write-only like the token: set, replaced or removed here, read from its field once,
 * sent once, never shown. A new address with a stored secret needs it again, or its removal.
 *
 * Step 8 of the redesign (spec §7.8): each connection a panel whose pill says how its last test
 * here went (Not tested, Connected, Test failed: the server keeps no state), with Test and a quiet
 * Delete; its own form in setting rows; "New connection" (a short create form) in a dialog; the
 * deletion asks in the page's dialog instead of `confirm()`.
 *
 * Onboarding ("Connections"): each connection has the switch "Allow Qualor to set up CI", which
 * lets Add repositories open merge requests and write CI/CD variables. It is off for connections
 * made before it existed, and asked (on by default) in "New connection". A switch saves at once.
 */
@Component({
  selector: 'q-gitlab-page',
  imports: [CopyValue, DateTimePipe, Icon, RouterLink],
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
  /** "New connection": whether Qualor may set up CI through it. */
  protected readonly ciSetupAllowed = signal(true);
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
    this.ciSetupAllowed.set(true);
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
              body: {
                organizationId,
                provider: 'gitlab',
                baseUrl,
                token,
                ciSetupAllowed: this.ciSetupAllowed(),
              },
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
   * A connection's own form: a new token, and with it, optionally, a new address and, while a
   * webhook secret is stored, a new secret or its removal. The token and the secret are read from
   * their fields and never kept; a new address without a token is refused here, as the server would
   * (scm.md §2.1: the stored token only ever goes to the address it was saved for), and so is one
   * with a stored secret that is neither given again nor dropped.
   */
  protected async update(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const urlField = form?.querySelector<HTMLInputElement>('input[type="url"]') ?? null;
    const tokenField = form?.querySelector<HTMLInputElement>('input[name="token"]') ?? null;
    const secretField =
      form?.querySelector<HTMLInputElement>('input[name="webhookSecret"]') ?? null;
    const dropField = form?.querySelector<HTMLInputElement>('input[name="dropSecret"]') ?? null;
    if (this.busy()) return;
    // The token and the secret are read once and their fields emptied at once, before any check or
    // request: whatever happens next (a refusal here, a 422, a network error), neither stays on
    // the page.
    const token = tokenField?.value ?? '';
    const secret = secretField?.value ?? '';
    if (tokenField) tokenField.value = '';
    if (secretField) secretField.value = '';
    const typed = (urlField?.value ?? connection.baseUrl).trim();
    const changed = typed !== '' && normalBaseUrl(typed) !== connection.baseUrl;
    // The box is shown only while a secret is stored.
    const secretStored = connection.gitlab?.webhookSecretSet ?? false;
    const drop = secretStored && (dropField?.checked ?? false);
    const refuse = (field: RowError['field'], message: string) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: { field, message } }));
      const target = { url: urlField, token: tokenField, newSecret: secretField, secret: null }[
        field
      ];
      target?.focus();
    };
    const refusal = updateRefusal({ typed, token, changed, secret, drop, secretStored });
    if (refusal) {
      refuse(...refusal);
      return;
    }
    this.clearRowError(connection);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await this.patch(connection, {
          ...(changed ? { baseUrl: typed } : {}),
          token,
          ...secretPatch(secret, drop),
        });
        if (generation !== this.orgGeneration) return;
        if (dropField) dropField.checked = false;
        this.announcement.set(updatedText({ changed, drop, secret, baseUrl: updated.baseUrl }));
      },
      (err) => {
        const fields = fieldErrors(err);
        if (fields['body.baseUrl'] !== undefined) refuse('url', badUrl());
        else if (fields['body.token'] !== undefined) {
          refuse('token', changed ? tokenForNewUrl() : badToken());
        } else if (fields['body.webhookSecret'] !== undefined) {
          refuse('newSecret', changed && secret === '' ? secretForNewUrl() : badSecret());
        } else return false;
        return true;
      },
    );
  }

  /** Sets (or replaces) the webhook secret; the field is read once and emptied at once. */
  protected async setSecret(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const field = form?.querySelector<HTMLInputElement>('input[type="password"]') ?? null;
    if (!field) return;
    const secret = field.value;
    field.value = '';
    if (this.busy()) return;
    const refuse = () => {
      this.rowErrors.update((all) => ({
        ...all,
        [connection.id]: { field: 'secret', message: badSecret() },
      }));
      field.focus();
    };
    if (!WEBHOOK_SECRET.test(secret)) {
      refuse();
      return;
    }
    this.clearRowError(connection);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        await this.patch(connection, { webhookSecret: secret });
        if (generation !== this.orgGeneration) return;
        this.announcement.set($localize`:@@gitlab.secretSet:The webhook secret was set.`);
      },
      (err) => {
        if (fieldErrors(err)['body.webhookSecret'] === undefined) return false;
        refuse();
        return true;
      },
    );
  }

  protected setCreateCiSetup(event: Event): void {
    this.ciSetupAllowed.set(isChecked(event));
  }

  /**
   * The CI-setup switch of a connection, saved at once. Refused (or while another change runs), the
   * switch goes back to what the connection says.
   */
  protected async setCiSetup(connection: Connection, event: Event): Promise<void> {
    const toggle = event.target instanceof HTMLInputElement ? event.target : null;
    const allowed = isChecked(event);
    const was = connection.gitlab?.ciSetupAllowed ?? false;
    if (this.busy()) {
      if (toggle) toggle.checked = was;
      return;
    }
    const generation = this.orgGeneration;
    let saved = false;
    await this.run(async () => {
      const updated = await this.patch(connection, { ciSetupAllowed: allowed }, false);
      saved = true;
      if (generation !== this.orgGeneration) return;
      const url = updated.baseUrl;
      this.announcement.set(
        allowed
          ? $localize`:@@gitlab.ciSetupOn:CI setup is on for ${url}:url:.`
          : $localize`:@@gitlab.ciSetupOff:CI setup is off for ${url}:url:.`,
      );
    });
    if (!saved && toggle) toggle.checked = was;
  }

  protected async removeSecret(connection: Connection): Promise<void> {
    if (this.busy()) return;
    const generation = this.orgGeneration;
    await this.run(async () => {
      await this.patch(connection, { webhookSecret: null });
      if (generation !== this.orgGeneration) return;
      this.announcement.set(
        $localize`:@@gitlab.secretRemoved:The webhook secret was removed: replies and commands are answered at the next analysis.`,
      );
    });
  }

  /**
   * Changes the connection (`PATCH`) and puts the answer in the list. A changed token, address or
   * secret has not been tested yet, and the last test's result is of what it was (`untested`); the
   * CI-setup switch changes nothing a test checks.
   */
  private async patch(
    connection: Connection,
    body: {
      baseUrl?: string;
      token?: string;
      webhookSecret?: string | null;
      ciSetupAllowed?: boolean;
    },
    untested = true,
  ): Promise<Connection> {
    const updated = await ok(
      this.api.client.PATCH('/api/v0/scm-connections/{id}', {
        params: { path: { id: connection.id } },
        body,
      }),
    );
    this.connections.items.update((items) => items.map((c) => (c.id === updated.id ? updated : c)));
    if (untested) {
      this.results.update((all) => without(all, connection.id));
      this.outcomes.update((all) => without(all, connection.id));
    }
    return updated;
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

function secretAndDrop(): string {
  return $localize`:@@gitlab.secretAndDrop:Type a new webhook secret or tick "Drop the webhook secret", not both.`;
}

function badSecret(): string {
  return $localize`:@@gitlab.badSecret:Use 16 to 256 printable characters without spaces, the same as the Secret token in the GitLab project's webhook (openssl rand -hex 32 makes a good one).`;
}

function secretForNewUrl(): string {
  return $localize`:@@gitlab.secretForNewUrl:Changing the address needs the webhook secret again, or tick "Drop the webhook secret".`;
}

/** What an update of a connection is refused for before it is sent, and on which field; or null. */
function updateRefusal(u: {
  typed: string;
  token: string;
  changed: boolean;
  secret: string;
  drop: boolean;
  secretStored: boolean;
}): [RowError['field'], string] | null {
  if (u.typed === '') return ['url', badUrl()];
  if (!u.token) return ['token', u.changed ? tokenForNewUrl() : badToken()];
  if (u.secret !== '' && u.drop) return ['newSecret', secretAndDrop()];
  if (u.secret !== '' && !WEBHOOK_SECRET.test(u.secret)) return ['newSecret', badSecret()];
  if (u.changed && u.secretStored && u.secret === '' && !u.drop) {
    return ['newSecret', secretForNewUrl()];
  }
  return null;
}

/** The webhook secret part of an update: the new secret, its removal, or none. */
function secretPatch(secret: string, drop: boolean): { webhookSecret?: string | null } {
  if (secret !== '') return { webhookSecret: secret };
  return drop ? { webhookSecret: null } : {};
}

/** What a saved update says, by what it changed. */
function updatedText(u: { changed: boolean; drop: boolean; secret: string; baseUrl: string }) {
  const { baseUrl } = u;
  if (u.changed) {
    if (u.drop) {
      return $localize`:@@gitlab.urlChangedSecretRemoved:The connection now points at ${baseUrl}:url:, and its webhook secret was removed: replies and commands are answered at the next analysis.`;
    }
    if (u.secret !== '')
      return $localize`:@@gitlab.urlChangedSecretReplaced:The connection now points at ${baseUrl}:url:, and its webhook secret was replaced.`;
    return $localize`:@@gitlab.urlChanged:The connection now points at ${baseUrl}:url:.`;
  }
  if (u.drop) {
    return $localize`:@@gitlab.tokenReplacedSecretRemoved:The token of ${baseUrl}:url: was replaced, and its webhook secret was removed: replies and commands are answered at the next analysis.`;
  }
  if (u.secret !== '')
    return $localize`:@@gitlab.tokenAndSecretReplaced:The token and the webhook secret of ${baseUrl}:url: were replaced.`;
  return $localize`:@@gitlab.tokenReplaced:The token of ${baseUrl}:url: was replaced.`;
}
