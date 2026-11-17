import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { JiraConnection, JiraSettingsAnswer, JiraTestResult } from '../api/types';
import { jiraProblemFix, jiraProblemText } from '../jira/jira-text';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';

type Deployment = JiraConnection['deployment'];
type TokenField = 'url' | 'api' | 'email' | 'token';

/** Each field's input, in the form's order: the first with an error takes the focus. */
const FIELD_INPUTS: readonly (readonly [TokenField, string])[] = [
  ['url', 'jira-site-url'],
  ['api', 'jira-api-url'],
  ['email', 'jira-email'],
  ['token', 'jira-token'],
];

/** An address as the server stores it: no trailing slash, so re-typing it is no change. */
function normalUrl(raw: string): string {
  return raw.trim().replace(/\/+$/, '');
}

/**
 * Jira (0.16 spec §6.1), for org admins: the organisation's one Jira connection. Jira Cloud takes
 * the address, the email and an API token (a scoped token also needs its API URL); Data Center the
 * address and a personal access token. The token is write-only: read from its field when sent,
 * never shown, emptied after every submission, and optional on an update that keeps the address.
 * A new deployment, address or API URL needs the token again and deletes the mappings and links of
 * the old one, so the page asks first with the counts (the server decides; its 422 shows under the
 * token field). Test checks the stored connection; a stored background problem shows as a banner
 * with the fix.
 */
@Component({
  selector: 'q-jira-settings-page',
  imports: [DateTimePipe],
  templateUrl: './jira.page.html',
  styleUrl: './jira.page.css',
})
export class JiraSettingsPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);
  protected readonly canRead = computed(() => this.org.can('org.jira.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.jira.manage'));

  protected readonly loaded = signal(false);
  /** The first read failed: no form until the connection's state is known (Save would replace it). */
  protected readonly loadFailed = signal(false);
  protected readonly connection = signal<JiraConnection | null>(null);
  protected readonly publicUrlSet = signal(true);
  protected readonly deployment = signal<Deployment>('cloud');
  protected readonly siteUrl = signal('');
  protected readonly apiUrl = signal('');
  protected readonly email = signal('');
  protected readonly fieldError = signal<Partial<Record<TokenField, string>>>({});
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly testResult = signal<JiraTestResult | null>(null);
  protected readonly busy = signal(false);
  /** The address change the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingChange = signal<{ mappings: number; links: number } | null>(null);
  protected readonly changeMappings = computed(() => this.pendingChange()?.mappings ?? 0);
  protected readonly changeLinks = computed(() => this.pendingChange()?.links ?? 0);
  protected readonly removing = signal(false);

  protected readonly tokenLabel = computed(() =>
    this.deployment() === 'cloud'
      ? $localize`:@@jira.apiToken:API token`
      : $localize`:@@jira.personalToken:Personal access token`,
  );
  protected readonly problem = computed(() => {
    const stored = this.connection()?.problem;
    if (!stored) return null;
    return {
      text: jiraProblemText(stored.code),
      fix: jiraProblemFix(stored.code),
      at: stored.at,
    };
  });
  protected readonly failure = computed(() => {
    const failed = this.testResult()?.problem;
    return failed ? { text: jiraProblemText(failed.code), fix: jiraProblemFix(failed.code) } : null;
  });
  protected readonly linkTotal = computed(() => {
    const links = this.connection()?.links;
    return links
      ? links.pending + links.created + links.failed + links.missing + links.dismissed
      : 0;
  });

  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly tokenField = viewChild<ElementRef<HTMLInputElement>>('tokenField');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  private readonly removeDialog = viewChild<ElementRef<HTMLDialogElement>>('removeDialog');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        this.orgGeneration++;
        this.loaded.set(false);
        this.loadFailed.set(false);
        this.announcement.set(null);
        this.error.set(null);
        this.testResult.set(null);
        this.fieldError.set({});
        this.connection.set(null);
        this.emptyToken();
        if (organizationId && admin) void this.load(organizationId);
      });
    });
  }

  private emptyToken(): void {
    const field = this.tokenField()?.nativeElement;
    if (field) field.value = '';
  }

  private async load(organizationId: string): Promise<void> {
    const generation = this.orgGeneration;
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/organizations/{id}/jira', {
          params: { path: { id: organizationId } },
        }),
      );
      if (generation !== this.orgGeneration) return;
      this.apply(answer);
      this.loaded.set(true);
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      this.error.set(problemMessage(err));
      this.loadFailed.set(true);
    }
  }

  protected retry(): void {
    const organizationId = this.org.currentId();
    if (!organizationId) return;
    this.error.set(null);
    this.loadFailed.set(false);
    void this.load(organizationId);
  }

  private apply(answer: JiraSettingsAnswer): void {
    this.publicUrlSet.set(answer.publicUrlSet);
    this.show(answer.connection);
  }

  /** Puts a connection (or none) on the page and its fields. */
  private show(connection: JiraConnection | null): void {
    this.connection.set(connection);
    this.deployment.set(connection?.deployment ?? 'cloud');
    this.siteUrl.set(connection?.siteUrl ?? '');
    this.apiUrl.set(connection?.apiUrl ?? '');
    this.email.set(connection?.email ?? '');
  }

  protected setDeployment(event: Event): void {
    this.deployment.set(inputValue(event) === 'data_center' ? 'data_center' : 'cloud');
    this.clearErrors();
  }

  protected setSiteUrl(event: Event): void {
    this.siteUrl.set(inputValue(event));
    this.clearErrors();
  }

  protected setApiUrl(event: Event): void {
    this.apiUrl.set(inputValue(event));
    this.clearErrors();
  }

  protected setEmail(event: Event): void {
    this.email.set(inputValue(event));
    this.clearErrors();
  }

  protected clearErrors(): void {
    if (Object.keys(this.fieldError()).length > 0) this.fieldError.set({});
  }

  /** Whether the form's deployment, address or API URL differ from the stored connection. */
  private addressChanged(connection: JiraConnection): boolean {
    const api = normalUrl(this.apiUrl());
    return (
      this.deployment() !== connection.deployment ||
      normalUrl(this.siteUrl()) !== connection.siteUrl ||
      (this.deployment() === 'cloud' ? api : '') !== (connection.apiUrl ?? '')
    );
  }

  protected save(event: Event): void {
    event.preventDefault();
    if (this.busy()) return;
    const connection = this.connection();
    const typedUrl = normalUrl(this.siteUrl());
    const token = this.tokenField()?.nativeElement.value ?? '';
    const errors: Partial<Record<TokenField, string>> = {};
    if (!typedUrl) errors.url = badUrl();
    if (this.deployment() === 'cloud' && !this.email().trim()) errors.email = badEmail();
    if (!connection && !token) errors.token = tokenNeeded();
    this.fieldError.set(errors);
    if (Object.keys(errors).length > 0) {
      this.focusFirstInvalid();
      return;
    }
    if (connection && this.addressChanged(connection)) {
      // The changed address deletes the mappings and links: ask first, with what goes.
      this.pendingChange.set({ mappings: connection.mappedProjects, links: this.linkTotal() });
      openAfterRender(
        this.injector,
        () => this.confirmDialog()?.nativeElement,
        () => this.pendingChange() !== null,
      );
      return;
    }
    void this.send();
  }

  protected async confirmChange(): Promise<void> {
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingChange.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    await this.send();
  }

  protected cancelChange(): void {
    this.pendingChange.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  /** The PUT: the token is read from its field once and the field emptied after the answer. */
  private async send(): Promise<void> {
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const field = this.tokenField()?.nativeElement;
    const token = field?.value ?? '';
    const cloud = this.deployment() === 'cloud';
    const created = this.connection() === null;
    const generation = this.orgGeneration;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      const saved = await ok(
        this.api.client.PUT('/api/v0/organizations/{id}/jira', {
          params: { path: { id: organizationId } },
          body: {
            deployment: this.deployment(),
            siteUrl: normalUrl(this.siteUrl()),
            apiUrl: cloud ? normalUrl(this.apiUrl()) || null : null,
            email: cloud ? this.email().trim() : null,
            ...(token ? { token } : {}),
          },
        }),
      );
      if (generation !== this.orgGeneration) return;
      this.show(saved);
      this.testResult.set(null);
      this.announcement.set(
        created
          ? $localize`:@@jira.created:Jira connection saved. Test it to check the token.`
          : $localize`:@@jira.updated:Jira connection updated.`,
      );
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      this.refuse(err, token !== '');
    } finally {
      // The token never stays on the page after a submission, whatever the answer was.
      this.emptyToken();
      this.busy.set(false);
    }
    this.focusFirstInvalid();
  }

  /** A refused field goes to its field, in the UI's own words; anything else to the alert. */
  private refuse(err: unknown, tokenSent: boolean): void {
    const fields = fieldErrors(err);
    const errors: Partial<Record<TokenField, string>> = {};
    if (fields['body.siteUrl'] !== undefined) errors.url = badUrl();
    if (fields['body.apiUrl'] !== undefined) errors.api = badApiUrl();
    if (fields['body.email'] !== undefined) errors.email = badEmail();
    if (fields['body.token'] !== undefined) {
      errors.token = tokenSent ? badToken() : tokenNeeded();
    }
    if (Object.keys(errors).length > 0) {
      this.fieldError.set(errors);
      return;
    }
    this.error.set(problemMessage(err));
    keepFocus(this.injector, this.document, () => this.heading().nativeElement);
  }

  private focusFirstInvalid(): void {
    const errors = this.fieldError();
    const first = FIELD_INPUTS.find(([field]) => errors[field]);
    if (first) this.document.getElementById(first[1])?.focus();
  }

  protected async test(): Promise<void> {
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const generation = this.orgGeneration;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    this.testResult.set(null);
    try {
      const result = await ok(
        this.api.client.POST('/api/v0/organizations/{id}/jira/test', {
          params: { path: { id: organizationId } },
        }),
      );
      if (generation !== this.orgGeneration) return;
      this.testResult.set(result);
      // A passing test clears the stored background problem.
      if (result.ok) this.connection.update((c) => (c ? { ...c, problem: null } : c));
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  /** Asks in the page's dialog; nothing is sent until its Remove connection. */
  protected remove(): void {
    if (this.busy()) return;
    this.removing.set(true);
    openAfterRender(
      this.injector,
      () => this.removeDialog()?.nativeElement,
      () => this.removing(),
    );
  }

  protected cancelRemove(): void {
    this.removing.set(false);
    const dialog = this.removeDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  protected async confirmRemove(): Promise<void> {
    const organizationId = this.org.currentId();
    this.removing.set(false);
    const dialog = this.removeDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    if (!organizationId || this.busy()) return;
    const generation = this.orgGeneration;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/organizations/{id}/jira', {
          params: { path: { id: organizationId } },
        }),
      );
      if (generation !== this.orgGeneration) return;
      this.show(null);
      this.testResult.set(null);
      this.announcement.set($localize`:@@jira.removed:Jira connection removed.`);
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}

function badUrl(): string {
  return $localize`:@@jira.badUrl:Use the https address of your Jira, without a user name, password, query or fragment. Jira Cloud: https://your-site.atlassian.net. An internal Jira must be listed, with its port, by the operator in QUALOR_JIRA_INTERNAL_HOSTS.`;
}

function badApiUrl(): string {
  return $localize`:@@jira.badApiUrl:Use https://api.atlassian.com/ex/jira/ followed by the cloud id of your site.`;
}

function badEmail(): string {
  return $localize`:@@jira.badEmail:Enter the email of the Atlassian account that owns the token.`;
}

function tokenNeeded(): string {
  return $localize`:@@jira.tokenNeeded:Enter the token. A new connection, or a changed deployment or address, needs it: Qualor sends a stored token only to the address it was saved for.`;
}

function badToken(): string {
  return $localize`:@@jira.badToken:Paste the token as Jira shows it (no spaces).`;
}
