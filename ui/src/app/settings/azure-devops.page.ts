import { DOCUMENT, NgTemplateOutlet } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  LOCALE_ID,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { azureBackgroundProblemText, azureCertificateExpiredOn, azureTestText } from './azure-text';
import type { Connection } from './gitlab.page';

type AuthKind = 'pat' | 'service_principal_secret' | 'service_principal_certificate';
type Field = 'url' | 'kind' | 'tenant' | 'client' | 'credential';
type Errors = Partial<Record<Field, string>>;

/** The certificate and key of a service principal: a PEM of at most 16 KiB, as the server takes. */
const PEM_MAX_BYTES = 16 * 1024;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A certificate this close to its end is flagged. */
const SOON_DAYS = 30;

/** What the shared field block of the create dialog and of a connection's form is given. */
interface FieldsContext {
  prefix: string;
  url: string;
  kind: AuthKind;
  tenant: string;
  client: string;
  /** False for an address that is not Azure DevOps Services: only a token works there. */
  principals: boolean;
  errors: Errors;
  changed: () => void;
  urlTyped: (event: Event) => void;
  kindChosen: (event: Event) => void;
  loadFile: (event: Event) => Promise<void>;
}

/**
 * Whether an address is Azure DevOps Services (`https://dev.azure.com/<org>` or
 * `https://<org>.visualstudio.com`), where service principals work; null while it is no address.
 */
function servicesAddress(raw: string): boolean | null {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  return url.hostname === 'dev.azure.com' || url.hostname.endsWith('.visualstudio.com');
}

/** An address as the server stores it (no trailing slash), so re-typing it is not a change. */
function normalBaseUrl(raw: string): string | null {
  try {
    return new URL(raw).href.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** Azure DevOps, for org admins: its connections, a test of each, and their credentials. */
@Component({
  selector: 'q-azure-devops-page',
  imports: [DateTimePipe, Icon, NgTemplateOutlet, RouterLink],
  templateUrl: './azure-devops.page.html',
  styleUrl: './scm.page.css',
})
export class AzureDevOpsPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly locale = inject(LOCALE_ID);
  protected readonly org = inject(OrgContext);
  protected readonly canRead = computed(() => this.org.can('org.scm.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.scm.manage'));
  protected readonly connections = new KeysetList<Connection, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/scm-connections', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  /** The Azure DevOps connections this page lists; the mapping offers every connection. */
  protected readonly azureConnections = computed(
    () => this.connections.items().filter((c) => c.provider === 'azure'), // provider-guard: this page lists Azure DevOps connections
  );
  protected readonly url = signal('');
  protected readonly kind = signal<AuthKind>('service_principal_secret');
  protected readonly createErrors = signal<Errors>({});
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly results = signal<Record<string, string>>({});
  protected readonly outcomes = signal<Record<string, 'ok' | 'failed'>>({});
  /** A refused addition other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  protected readonly pendingDelete = signal<{ connection: Connection; question: string } | null>(
    null,
  );
  /** What the connections' own forms hold that the page must know: kind and address typed. */
  private readonly rowKinds = signal<Record<string, AuthKind>>({});
  private readonly rowUrls = signal<Record<string, string>>({});
  protected readonly rowErrors = signal<Record<string, Errors>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  private orgGeneration = 0;

  /** The block of fields of "New connection". */
  protected readonly createFields = computed<FieldsContext>(() => ({
    prefix: 'azure',
    url: this.url(),
    kind: this.kind(),
    tenant: '',
    client: '',
    principals: servicesAddress(this.url()) !== false,
    errors: this.createErrors(),
    changed: () => this.createErrors.set({}),
    urlTyped: (event) => {
      const value = event.target instanceof HTMLInputElement ? event.target.value : '';
      this.url.set(value);
      if (servicesAddress(value) === false && this.kind() !== 'pat') this.kind.set('pat');
      this.createErrors.set({});
    },
    kindChosen: (event) => {
      this.kind.set(kindOf(event));
      this.createErrors.set({});
    },
    loadFile: (event) =>
      this.loadFile(event, (message) => this.createErrors.set({ credential: message })),
  }));

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        this.orgGeneration++;
        this.announcement.set(null);
        this.error.set(null);
        this.createErrors.set({});
        this.createError.set(null);
        this.results.set({});
        this.outcomes.set({});
        this.rowErrors.set({});
        this.rowKinds.set({});
        this.rowUrls.set({});
        if (organizationId && admin) void this.connections.reset(organizationId);
      });
    });
  }

  /** The block of fields of a connection's own form. */
  protected rowFields(c: Connection): FieldsContext {
    const url = this.rowUrls()[c.id] ?? c.baseUrl;
    return {
      prefix: `row-${c.id}`,
      url: c.baseUrl,
      kind: this.rowKind(c),
      tenant: c.azure?.tenantId ?? '',
      client: c.azure?.clientId ?? '',
      principals: servicesAddress(url) !== false,
      errors: this.rowErrors()[c.id] ?? {},
      changed: () => this.rowErrors.update((all) => without(all, c.id)),
      urlTyped: (event) => {
        const value = event.target instanceof HTMLInputElement ? event.target.value : '';
        this.rowUrls.update((all) => ({ ...all, [c.id]: value }));
        if (servicesAddress(value) === false && this.rowKind(c) !== 'pat') {
          this.rowKinds.update((all) => ({ ...all, [c.id]: 'pat' }));
        }
        this.rowErrors.update((all) => without(all, c.id));
      },
      kindChosen: (event) => {
        this.rowKinds.update((all) => ({ ...all, [c.id]: kindOf(event) }));
        this.rowErrors.update((all) => without(all, c.id));
      },
      loadFile: (event) =>
        this.loadFile(event, (message) =>
          this.rowErrors.update((all) => ({ ...all, [c.id]: { credential: message } })),
        ),
    };
  }

  private rowKind(c: Connection): AuthKind {
    return this.rowKinds()[c.id] ?? c.azure?.auth ?? 'pat';
  }

  protected kindText(kind: AuthKind): string {
    switch (kind) {
      case 'pat':
        return $localize`:@@azure.kind.pat:Personal access token`;
      case 'service_principal_secret':
        return $localize`:@@azure.kind.secret:Service principal with a client secret`;
      case 'service_principal_certificate':
        return $localize`:@@azure.kind.certificate:Service principal with a certificate`;
    }
  }

  /** The words of a connection's recorded background problem, null without one. */
  protected problemText(c: Connection): string | null {
    return c.problem
      ? azureBackgroundProblemText(c.problem, azureCertificateExpiredOn(c, this.locale))
      : null;
  }

  /** The state of a connection's certificate: expired, ending within a month, or fine. */
  protected certificateState(c: Connection): 'expired' | 'soon' | 'ok' | null {
    const notAfter = c.azure?.certificate?.notAfter;
    if (!notAfter) return null;
    const left = new Date(notAfter).getTime() - Date.now();
    if (left <= 0) return 'expired';
    return left <= SOON_DAYS * 86_400_000 ? 'soon' : 'ok';
  }

  protected openCreate(): void {
    this.url.set('');
    this.kind.set('service_principal_secret');
    this.createErrors.set({});
    this.createError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  /** Cancel, or Escape: the dialog closes; what was typed goes with the next opening. */
  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
    this.clearCredential(dialog);
  }

  /** A `.pem` file chosen for the certificate: read into its field (at most 16 KiB). */
  private async loadFile(event: Event, refuse: (message: string) => void): Promise<void> {
    const input = event.target instanceof HTMLInputElement ? event.target : null;
    const file = input?.files?.[0];
    const form = input?.form;
    const target = form?.querySelector<HTMLTextAreaElement>('textarea[name="credential"]');
    if (!input || !file || !target) return;
    input.value = '';
    target.value = '';
    if (file.size > PEM_MAX_BYTES) {
      refuse(fileTooLarge());
      return;
    }
    try {
      target.value = await file.text();
    } catch {
      refuse(fileUnreadable());
      return;
    }
    target.dispatchEvent(new Event('input'));
  }

  private clearCredential(within: ParentNode | null | undefined): void {
    const field = within?.querySelector<HTMLInputElement | HTMLTextAreaElement>(
      '[name="credential"]',
    );
    if (field) field.value = '';
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    // Read once and emptied at once: whatever happens next, the credential does not stay.
    const value = (name: string) =>
      form?.querySelector<HTMLInputElement>(`[name="${name}"]`)?.value ?? '';
    const credential = value('credential');
    this.clearCredential(form);
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const baseUrl = this.url().trim();
    const kind = this.kind();
    const input = {
      kind,
      url: baseUrl,
      tenant: value('tenant').trim(),
      client: value('client').trim(),
      credential,
    };
    const refused = refusalOf(input, false);
    this.createError.set(null);
    this.createErrors.set(refused);
    if (Object.keys(refused).length > 0) {
      this.focusFirstInvalid(form, refused);
      return;
    }
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        await ok(
          this.api.client.POST('/api/v0/scm-connections', {
            body: { organizationId, provider: 'azure', baseUrl, ...credentialBody(input) },
          }),
        );
        if (generation !== this.orgGeneration) return;
        this.announcement.set($localize`:@@azure.created:Azure DevOps connection added.`);
        this.closeCreate();
        await this.connections.refresh();
      },
      (err) => {
        const fields = refusalsOf(err, kind, false);
        if (Object.keys(fields).length > 0) {
          this.createErrors.set(fields);
          this.focusFirstInvalid(form, fields);
        } else this.createError.set(problemMessage(err));
        return true;
      },
    );
  }

  /** A connection's own form: its address, kind, ids and a credential, always given again. */
  protected async update(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const value = (name: string) =>
      form?.querySelector<HTMLInputElement>(`[name="${name}"]`)?.value ?? '';
    const credential = value('credential');
    const tenant = value('tenant').trim();
    const client = value('client').trim();
    this.clearCredential(form);
    if (this.busy()) return;
    const kind = this.rowKind(connection);
    const typed = value('url').trim();
    const changed = typed !== '' && normalBaseUrl(typed) !== connection.baseUrl;
    const input = { kind, url: typed, tenant, client, credential };
    const refuse = (errors: Errors) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: errors }));
      this.focusFirstInvalid(form, errors);
    };
    const refused = refusalOf(input, changed);
    if (Object.keys(refused).length > 0) {
      refuse(refused);
      return;
    }
    this.rowErrors.update((all) => without(all, connection.id));
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.PATCH('/api/v0/scm-connections/{id}', {
            params: { path: { id: connection.id } },
            body: { ...(changed ? { baseUrl: typed } : {}), ...credentialBody(input) },
          }),
        );
        this.connections.items.update((items) =>
          items.map((c) => (c.id === updated.id ? updated : c)),
        );
        this.results.update((all) => without(all, connection.id));
        this.outcomes.update((all) => without(all, connection.id));
        if (generation !== this.orgGeneration) return;
        this.rowKinds.update((all) => without(all, connection.id));
        this.rowUrls.update((all) => without(all, connection.id));
        const baseUrl = updated.baseUrl;
        this.announcement.set(
          $localize`:@@azure.updated:The credential of ${baseUrl}:url: was replaced.`,
        );
      },
      (err) => {
        const fields = refusalsOf(err, kind, changed);
        if (Object.keys(fields).length === 0) return false;
        refuse(fields);
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
      const text = azureTestText(result, azureCertificateExpiredOn(connection, this.locale));
      this.results.update((all) => ({ ...all, [connection.id]: text }));
      const passed = result.ok && !!result.user;
      // A passing test clears the background problem the server recorded.
      if (result.ok) {
        this.connections.items.update((items) =>
          items.map((c) => (c.id === connection.id ? { ...c, problem: null } : c)),
        );
      }
      this.outcomes.update((all) => ({ ...all, [connection.id]: passed ? 'ok' : 'failed' }));
      // A failure reads as one: the error alert, never the green news of a success.
      if (passed) this.announcement.set(text);
      else this.error.set(text);
    });
  }

  protected remove(connection: Connection): void {
    if (this.busy()) return;
    this.pendingDelete.set({
      connection,
      question: $localize`:@@azure.confirmDelete:Delete the Azure DevOps connection to ${connection.baseUrl}:url:? Projects mapped to it are no longer linked to their repositories.`,
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
        $localize`:@@azure.deleted:Azure DevOps connection ${connection.baseUrl}:url: deleted.`,
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  /** The first refused field of a form takes focus. */
  private focusFirstInvalid(form: HTMLFormElement | null, errors: Errors): void {
    const order: Field[] = ['url', 'kind', 'tenant', 'client', 'credential'];
    const first = order.find((field) => errors[field] !== undefined);
    if (!first || !form) return;
    const name = first === 'kind' ? 'input[type="radio"]:checked' : `[name="${first}"]`;
    form.querySelector<HTMLElement>(name)?.focus();
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refused field is handled by `field`; anything else goes to the page's alert.
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

function kindOf(event: Event): AuthKind {
  const value = event.target instanceof HTMLInputElement ? event.target.value : '';
  if (value === 'service_principal_secret' || value === 'service_principal_certificate') {
    return value;
  }
  return 'pat';
}

interface FormInput {
  kind: AuthKind;
  url: string;
  tenant: string;
  client: string;
  credential: string;
}

/** The fields of the chosen kind, and no others: the server refuses a field of another kind. */
function credentialBody(input: FormInput) {
  switch (input.kind) {
    case 'pat':
      return { azureAuth: 'pat' as const, token: input.credential };
    case 'service_principal_secret':
      return {
        azureAuth: 'service_principal_secret' as const,
        tenantId: input.tenant,
        clientId: input.client,
        token: input.credential,
      };
    case 'service_principal_certificate':
      return {
        azureAuth: 'service_principal_certificate' as const,
        tenantId: input.tenant,
        clientId: input.client,
        certificate: input.credential,
      };
  }
}

/** What a form is refused for before it is sent, by field; empty when it can go. */
function refusalOf(input: FormInput, addressChanged: boolean): Errors {
  const errors: Errors = {};
  if (input.url === '') errors.url = badUrl();
  if (input.kind !== 'pat') {
    if (!GUID.test(input.tenant)) errors.tenant = badTenant();
    if (!GUID.test(input.client)) errors.client = badClient();
  }
  if (input.credential.trim() === '') {
    errors.credential = addressChanged ? credentialForNewUrl() : badCredential(input.kind);
  } else if (
    input.kind === 'service_principal_certificate' &&
    new TextEncoder().encode(input.credential).length > PEM_MAX_BYTES
  ) {
    errors.credential = fileTooLarge();
  }
  return errors;
}

/** The server's 422 on a field, in the UI's own words. */
function refusalsOf(err: unknown, kind: AuthKind, addressChanged: boolean): Errors {
  const fields = fieldErrors(err);
  const errors: Errors = {};
  if (fields['body.baseUrl'] !== undefined) errors.url = badUrl();
  if (fields['body.azureAuth'] !== undefined) errors.kind = serverTakesPat();
  if (fields['body.tenantId'] !== undefined) errors.tenant = badTenant();
  if (fields['body.clientId'] !== undefined) errors.client = badClient();
  if (fields['body.token'] !== undefined || fields['body.certificate'] !== undefined) {
    errors.credential = addressChanged ? credentialForNewUrl() : badCredential(kind);
  }
  return errors;
}

function badUrl(): string {
  return $localize`:@@azure.badUrl:Use the https address of your Azure DevOps: https://dev.azure.com/your-organization for Azure DevOps Services, or https://host/collection for Azure DevOps Server. An internal server must be listed, with its port, by the operator in QUALOR_SCM_INTERNAL_HOSTS.`;
}

function badTenant(): string {
  return $localize`:@@azure.badTenant:Use the directory (tenant) id of the app registration, a GUID such as 11111111-2222-3333-4444-555555555555.`;
}

function badClient(): string {
  return $localize`:@@azure.badClient:Use the application (client) id of the app registration, a GUID such as 11111111-2222-3333-4444-555555555555.`;
}

function badCredential(kind: AuthKind): string {
  switch (kind) {
    case 'pat':
      return $localize`:@@azure.badPat:Paste the personal access token as Azure DevOps shows it (no spaces).`;
    case 'service_principal_secret':
      return $localize`:@@azure.badSecret:Paste the value of the client secret (no spaces).`;
    case 'service_principal_certificate':
      return $localize`:@@azure.badCertificate:Paste or upload the certificate as one PEM: its CERTIFICATE block and its unencrypted private key (RSA, at least 2048 bits).`;
  }
}

function credentialForNewUrl(): string {
  return $localize`:@@azure.credentialForNewUrl:Changing the address needs the credential again: Qualor sends a stored credential only to the address it was saved for.`;
}

function serverTakesPat(): string {
  return $localize`:@@azure.serverTakesPat:Azure DevOps Server takes a personal access token.`;
}

function fileTooLarge(): string {
  return $localize`:@@azure.fileTooLarge:The certificate is larger than 16 KiB. Use the PEM file with the certificate and its private key.`;
}

function fileUnreadable(): string {
  return $localize`:@@azure.fileUnreadable:The file could not be read. Choose the PEM file again, or paste its text.`;
}
