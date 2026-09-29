import { DOCUMENT } from '@angular/common';
import {
  computed,
  Component,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openModal } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { githubTestText } from './github-text';
import type { Connection } from './gitlab.page';

/** github.md §2.2: the private key's size limit, checked before a file is read. */
const KEY_MAX_BYTES = 16 * 1024;
/** github.md §2.2: the App id as GitHub shows it (no zero, no leading zeros, a safe integer). */
const APP_ID = /^[1-9][0-9]{0,15}$/;
/** github.md §2.2: the webhook secret, 16–256 printable ASCII characters without spaces. */
const WEBHOOK_SECRET = /^[\x21-\x7e]{16,256}$/;

/** A base URL as the server stores it (normalised, without a trailing slash); null when not a URL. */
function normalBaseUrl(raw: string): string | null {
  try {
    return new URL(raw).href.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** The fields of the new-App form. */
type CreateField = 'url' | 'appId' | 'key' | 'secret';

/** A refused field of a connection's own forms. */
interface RowError {
  field: 'url' | 'key' | 'newSecret' | 'appId' | 'secret' | 'ref';
  message: string;
}

/**
 * GitHub (github.md §2), for org admins: the organisation's GitHub App connections (the API root,
 * the App id, and the private key and optional webhook secret, which are write-only: read from
 * their fields once, sent once, never kept in the page's state, never shown, and emptied from the
 * page at every submission), a test of each against an `owner/repo`, and the changes the API
 * allows (a new key, and with it a new address; the App id; the webhook secret set or removed).
 * Test answers and refusals are shown in the page's own words (§5.4). Projects are mapped on the
 * GitLab tab, which maps to either provider.
 *
 * Step 8 of the redesign (spec §7.8): each App a panel whose pill says how its last test here went
 * (the server keeps no state), with its facts, the test and a quiet Delete; its forms and the new
 * App's form (a long configuration form, so on the page) in setting rows; a deletion asks in the
 * page's dialog instead of `confirm()`.
 */
@Component({
  selector: 'q-github-page',
  imports: [DateTimePipe, Icon, RouterLink],
  templateUrl: './github.page.html',
  styleUrl: './scm.page.css',
})
export class GitHubPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
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
  /** Only GitHub connections are this page's; the GitLab tab lists the others. */
  protected readonly apps = computed(() =>
    this.connections.items().filter((c) => c.provider === 'github'),
  );
  protected readonly url = signal('https://api.github.com');
  protected readonly appId = signal('');
  protected readonly createErrors = signal<Partial<Record<CreateField, string>>>({});
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** Test results, by connection id. */
  protected readonly results = signal<Record<string, string>>({});
  /** How each App's last test on this page went, for its pill. */
  protected readonly outcomes = signal<Record<string, 'ok' | 'failed'>>({});
  /** The deletion the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingDelete = signal<{ connection: Connection; question: string } | null>(
    null,
  );
  /** Refused fields of the connections' own forms, by connection id. */
  protected readonly rowErrors = signal<Record<string, RowError>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
  private readonly appIdField = viewChild<ElementRef<HTMLInputElement>>('appIdField');
  private readonly keyField = viewChild<ElementRef<HTMLTextAreaElement>>('keyField');
  private readonly secretField = viewChild<ElementRef<HTMLInputElement>>('secretField');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        this.orgGeneration++;
        this.announcement.set(null);
        this.error.set(null);
        this.createErrors.set({});
        this.results.set({});
        this.outcomes.set({});
        this.rowErrors.set({});
        this.emptySecrets();
        if (organizationId && admin) void this.connections.reset(organizationId);
      });
    });
    // Nothing typed into a secret field outlives the page.
    inject(DestroyRef).onDestroy(() => this.emptySecrets());
  }

  protected setUrl(event: Event): void {
    this.url.set(inputValue(event));
    this.clearCreateError('url');
  }

  protected setAppId(event: Event): void {
    this.appId.set(inputValue(event));
    this.clearCreateError('appId');
  }

  protected clearCreateError(field: CreateField): void {
    if (this.createErrors()[field] === undefined) return;
    this.createErrors.update((all) => without(all, field));
  }

  protected createError(field: CreateField): string | null {
    return this.createErrors()[field] ?? null;
  }

  protected clearRowError(connection: Connection): void {
    if (this.rowErrors()[connection.id] === undefined) return;
    this.rowErrors.update((all) => without(all, connection.id));
  }

  protected rowError(connection: Connection, field: RowError['field']): string | null {
    const error = this.rowErrors()[connection.id];
    return error?.field === field ? error.message : null;
  }

  /** The name of a connection's card: its App id and address (two Apps may share an address). */
  protected label(connection: Connection): string {
    return $localize`:@@github.cardLabel:GitHub App ${connection.github?.appId ?? ''}:appId: at ${connection.baseUrl}:url:`;
  }

  /**
   * A `.pem` file chosen for a key field: at most 16 KiB (refused before it is read), read into
   * the field as text. The file input is emptied again, so the page keeps no handle on the file.
   */
  protected async loadKey(
    event: Event,
    target: HTMLTextAreaElement,
    refuse: (message: string) => void,
  ): Promise<void> {
    const input = event.target instanceof HTMLInputElement ? event.target : null;
    const file = input?.files?.[0];
    if (!input || !file) return;
    input.value = '';
    target.value = '';
    if (file.size > KEY_MAX_BYTES) {
      refuse(keyFileTooLarge());
      return;
    }
    let text: string;
    try {
      text = await file.text();
    } catch {
      refuse(keyFileUnreadable());
      return;
    }
    target.value = text;
    target.dispatchEvent(new Event('input'));
  }

  protected refuseCreateKey = (message: string): void => {
    this.createErrors.update((all) => ({ ...all, key: message }));
    this.keyField()?.nativeElement.focus();
  };

  protected refuseRowKey(connection: Connection, form: HTMLFormElement): (message: string) => void {
    return (message) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: { field: 'key', message } }));
      form.querySelector<HTMLTextAreaElement>('textarea')?.focus();
    };
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    // The key and the secret are read once and their fields emptied at once, before any check or
    // request: whatever happens next (an ignored submit, a refusal here, a 422, a network error),
    // they never stay.
    const key = this.keyField()?.nativeElement;
    const secretInput = this.secretField()?.nativeElement;
    const privateKey = key?.value ?? '';
    const secret = secretInput?.value ?? '';
    if (key) key.value = '';
    if (secretInput) secretInput.value = '';
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const baseUrl = this.url().trim();
    const appId = this.appId().trim();
    const errors: Partial<Record<CreateField, string>> = {};
    if (normalBaseUrl(baseUrl) === null) errors.url = badUrl();
    if (!validAppId(appId)) errors.appId = badAppId();
    if (privateKey.trim() === '') errors.key = badKey();
    else if (new TextEncoder().encode(privateKey).length > KEY_MAX_BYTES)
      errors.key = keyTooLarge();
    if (secret !== '' && !WEBHOOK_SECRET.test(secret)) errors.secret = badSecret();
    this.createErrors.set(errors);
    if (Object.keys(errors).length > 0) {
      this.focusFirstInvalid();
      return;
    }
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        await ok(
          this.api.client.POST('/api/v0/scm-connections', {
            body: {
              organizationId,
              provider: 'github',
              baseUrl,
              appId,
              privateKey,
              ...(secret ? { webhookSecret: secret } : {}),
            },
          }),
        );
        if (generation !== this.orgGeneration) return;
        this.url.set('https://api.github.com');
        const urlField = this.urlField();
        if (urlField) urlField.nativeElement.value = 'https://api.github.com';
        clearField(this.appIdField(), this.appId);
        this.announcement.set($localize`:@@github.created:GitHub App added.`);
        await this.connections.refresh();
      },
      (err) => {
        const fields = fieldErrors(err);
        const refused: Partial<Record<CreateField, string>> = {};
        if (fields['body.baseUrl'] !== undefined) refused.url = badUrl();
        if (fields['body.appId'] !== undefined) refused.appId = badAppId();
        if (fields['body.privateKey'] !== undefined) refused.key = badKey();
        if (fields['body.webhookSecret'] !== undefined) refused.secret = badSecret();
        if (Object.keys(refused).length === 0) return false;
        this.createErrors.set(refused);
        this.focusFirstInvalid();
        return true;
      },
    );
  }

  /**
   * A connection's key form: a new private key, and with it, optionally, a new address. A new
   * address with a stored webhook secret needs the secret again or its removal (github.md §2.2:
   * no stored credential ever serves an address it was not entered for); refused here as the
   * server would. The key and the secret are read from their fields and emptied at once.
   */
  protected async replaceKey(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    if (!form) return;
    const urlField = form.querySelector<HTMLInputElement>('input[type="url"]');
    const keyField = form.querySelector<HTMLTextAreaElement>('textarea');
    const secretField = form.querySelector<HTMLInputElement>('input[type="password"]');
    const dropField = form.querySelector<HTMLInputElement>('input[type="checkbox"]');
    const privateKey = keyField?.value ?? '';
    const secret = secretField?.value ?? '';
    if (keyField) keyField.value = '';
    if (secretField) secretField.value = '';
    if (this.busy()) return;
    const typed = (urlField?.value ?? connection.baseUrl).trim();
    const changed = typed !== '' && normalBaseUrl(typed) !== connection.baseUrl;
    const secretStored = connection.github?.webhookSecretSet ?? false;
    // The box is shown only while a secret is stored.
    const drop = secretStored && (dropField?.checked ?? false);
    const refuse = (field: RowError['field'], message: string) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: { field, message } }));
      const target = { url: urlField, key: keyField, newSecret: secretField }[
        field as 'url' | 'key' | 'newSecret'
      ];
      target?.focus();
    };
    const refusal: [RowError['field'], string] | null =
      typed === '' || normalBaseUrl(typed) === null
        ? ['url', badUrl()]
        : privateKey.trim() === ''
          ? ['key', changed ? keyForNewUrl() : badKey()]
          : secret !== '' && drop
            ? ['newSecret', secretAndDrop()]
            : secret !== '' && !WEBHOOK_SECRET.test(secret)
              ? ['newSecret', badSecret()]
              : changed && secretStored && secret === '' && !drop
                ? ['newSecret', secretForNewUrl()]
                : null;
    if (refusal) {
      refuse(...refusal);
      return;
    }
    this.clearRowError(connection);
    const body: { baseUrl?: string; privateKey: string; webhookSecret?: string | null } = {
      ...(changed ? { baseUrl: typed } : {}),
      privateKey,
    };
    if (secret !== '') body.webhookSecret = secret;
    else if (drop) body.webhookSecret = null;
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await this.patch(connection, body);
        if (generation !== this.orgGeneration) return;
        if (dropField) dropField.checked = false;
        const appId = updated.github?.appId ?? '';
        this.announcement.set(
          changed
            ? drop
              ? $localize`:@@github.urlChangedSecretRemoved:The App now uses ${updated.baseUrl}:url:, and its webhook secret was removed: the Re-run button does nothing now.`
              : $localize`:@@github.urlChanged:The App now uses ${updated.baseUrl}:url:.`
            : drop
              ? $localize`:@@github.keyReplacedSecretRemoved:The private key of App ${appId}:appId: was replaced, and its webhook secret was removed: the Re-run button does nothing now.`
              : $localize`:@@github.keyReplaced:The private key of App ${appId}:appId: was replaced.`,
        );
      },
      (err) => {
        const fields = fieldErrors(err);
        if (fields['body.baseUrl'] !== undefined) refuse('url', badUrl());
        else if (fields['body.privateKey'] !== undefined) refuse('key', badKey());
        else if (fields['body.webhookSecret'] !== undefined) {
          refuse('newSecret', changed && secret === '' ? secretForNewUrl() : badSecret());
        } else return false;
        return true;
      },
    );
  }

  protected async changeAppId(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const field = form?.querySelector<HTMLInputElement>('input') ?? null;
    if (!field || this.busy()) return;
    const appId = field.value.trim();
    const refuse = () => {
      this.rowErrors.update((all) => ({
        ...all,
        [connection.id]: { field: 'appId', message: badAppId() },
      }));
      field.focus();
    };
    if (!validAppId(appId)) {
      refuse();
      return;
    }
    this.clearRowError(connection);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await this.patch(connection, { appId });
        if (generation !== this.orgGeneration) return;
        this.announcement.set(
          $localize`:@@github.appIdChanged:The App id is now ${updated.github?.appId ?? appId}:appId:.`,
        );
      },
      (err) => {
        if (fieldErrors(err)['body.appId'] === undefined) return false;
        refuse();
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
        this.announcement.set($localize`:@@github.secretSet:The webhook secret was set.`);
      },
      (err) => {
        if (fieldErrors(err)['body.webhookSecret'] === undefined) return false;
        refuse();
        return true;
      },
    );
  }

  protected async removeSecret(connection: Connection): Promise<void> {
    if (this.busy()) return;
    const generation = this.orgGeneration;
    await this.run(async () => {
      await this.patch(connection, { webhookSecret: null });
      if (generation !== this.orgGeneration) return;
      this.announcement.set(
        $localize`:@@github.secretRemoved:The webhook secret was removed: the Re-run button does nothing now.`,
      );
    });
  }

  protected async test(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const field = form?.querySelector<HTMLInputElement>('input') ?? null;
    const projectRef = field?.value.trim() ?? '';
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const result = await ok(
          this.api.client.POST('/api/v0/scm-connections/{id}/test', {
            params: { path: { id: connection.id } },
            body: projectRef ? { projectRef } : {},
          }),
        );
        if (generation !== this.orgGeneration) return;
        const text = githubTestText(result);
        this.results.update((all) => ({ ...all, [connection.id]: text }));
        this.outcomes.update((all) => ({ ...all, [connection.id]: result.ok ? 'ok' : 'failed' }));
        this.announcement.set(text);
      },
      (err) => {
        if (fieldErrors(err)['body.projectRef'] === undefined) return false;
        this.rowErrors.update((all) => ({
          ...all,
          [connection.id]: { field: 'ref', message: badRef() },
        }));
        field?.focus();
        return true;
      },
    );
  }

  /** Asks in the page's dialog; nothing is sent until its Delete. */
  protected remove(connection: Connection): void {
    if (this.busy()) return;
    const appId = connection.github?.appId ?? '';
    this.pendingDelete.set({
      connection,
      question: $localize`:@@github.confirmDelete:Delete the GitHub App ${appId}:appId: at ${connection.baseUrl}:url:? Its projects stop being decorated.`,
    });
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) openModal(dialog);
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
    const appId = connection.github?.appId ?? '';
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
        $localize`:@@github.deleted:GitHub App ${appId}:appId: at ${connection.baseUrl}:url: deleted.`,
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  private async patch(
    connection: Connection,
    body: {
      baseUrl?: string;
      appId?: string;
      privateKey?: string;
      webhookSecret?: string | null;
    },
  ): Promise<Connection> {
    const updated = await ok(
      this.api.client.PATCH('/api/v0/scm-connections/{id}', {
        params: { path: { id: connection.id } },
        body,
      }),
    );
    this.connections.items.update((items) => items.map((c) => (c.id === updated.id ? updated : c)));
    this.results.update((all) => without(all, connection.id));
    // Changed settings have not been tested yet.
    this.outcomes.update((all) => without(all, connection.id));
    return updated;
  }

  /**
   * Empties every key and secret field of the page, the new-App form's and each connection's
   * (they are never bound to state), and unticks "Drop the webhook secret".
   */
  private emptySecrets(): void {
    const root = this.host.nativeElement;
    for (const field of root.querySelectorAll<HTMLTextAreaElement | HTMLInputElement>(
      'textarea, input[type="password"]',
    )) {
      field.value = '';
    }
    for (const box of root.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')) {
      box.checked = false;
    }
  }

  private focusFirstInvalid(): void {
    const errors = this.createErrors();
    const field = errors.url
      ? this.urlField()
      : errors.appId
        ? this.appIdField()
        : errors.key
          ? this.keyField()
          : errors.secret
            ? this.secretField()
            : undefined;
    field?.nativeElement.focus();
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
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}

function without<T>(all: Record<string, T>, id: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([key]) => key !== id));
}

function validAppId(appId: string): boolean {
  return APP_ID.test(appId) && Number(appId) <= Number.MAX_SAFE_INTEGER;
}

function badUrl(): string {
  return $localize`:@@github.badUrl:Use the API address: https://api.github.com, https://api.<subdomain>.ghe.com, or your GitHub Enterprise Server's address ending in /api/v3. An internal server must be listed, with its port, by the operator in QUALOR_SCM_INTERNAL_HOSTS.`;
}

function badAppId(): string {
  return $localize`:@@github.badAppId:Use the App id from the App's settings page on GitHub: digits only, not the client id.`;
}

function badKey(): string {
  return $localize`:@@github.badKey:Paste or upload the private key GitHub generated for the App: the whole .pem file, an unencrypted RSA key of at least 2048 bits.`;
}

function keyTooLarge(): string {
  return $localize`:@@github.keyTooLarge:The private key is larger than 16 KiB. Use the .pem file GitHub generated.`;
}

function keyFileTooLarge(): string {
  return $localize`:@@github.keyFileTooLarge:The key file is larger than 16 KiB. Choose the .pem file GitHub generated.`;
}

function keyForNewUrl(): string {
  return $localize`:@@github.keyForNewUrl:Changing the address needs the private key again: Qualor sends a stored key only to the address it was saved for.`;
}

function keyFileUnreadable(): string {
  return $localize`:@@github.keyFileUnreadable:The key file could not be read. Choose the .pem file GitHub generated again, or paste the key.`;
}

function secretAndDrop(): string {
  return $localize`:@@github.secretAndDrop:Type a new webhook secret or tick "Drop the webhook secret", not both.`;
}

function badSecret(): string {
  return $localize`:@@github.badSecret:Use 16 to 256 printable characters without spaces, the same as in the App's webhook settings (openssl rand -hex 32 makes a good one).`;
}

function secretForNewUrl(): string {
  return $localize`:@@github.secretForNewUrl:Changing the address needs the webhook secret again, or tick "Drop the webhook secret".`;
}

function badRef(): string {
  return $localize`:@@github.badRef:Use owner/repo, such as acme/api.`;
}
