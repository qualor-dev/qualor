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
import { ok } from '../api/api';
import { type AuditSettings, EeApi, type EeResponse, type StreamTest } from '../api/ee';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { SystemInfo } from '../shell/system-info';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openModal } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { inputValue, isChecked } from '../shared/forms';
import { SecretOnce } from './secret-once';

/** What `PUT /ee/audit/settings` answers: the settings, with a secret it just generated. */
type AuditSettingsSaved = EeResponse<'/api/v0/ee/audit/settings', 'put'>;

/** A change the confirmation dialog asks about: a save that drops the stream, a removal, a new secret. */
interface Pending {
  kind: 'save' | 'remove' | 'regenerate';
  question: string;
}

function removeQuestion(): string {
  return $localize`:@@auditSettings.confirmRemoveStream:Remove the SIEM stream? Events are no longer sent; they stay in the audit log.`;
}

/** rbac-audit.md §11.1: retention is a whole number of days, 30 to 36 500. */
const MIN_DAYS = 30;
const MAX_DAYS = 36_500;

/**
 * Settings → Audit settings (rbac-audit.md §11, §14, §17, feature `audit-log`, instance admins):
 * how many days events are kept, and the SIEM stream (URL, active, and its signing secret, which
 * the server returns once when it generates one and which this page shows once with
 * `q-secret-once`, then forgets), a test batch and the stream's delivery status. Nothing is asked
 * of the enterprise API while the feature is inactive or the caller is not an instance admin.
 *
 * The stream card needs `audit-log.stream` too (§14.4, plan 5D). Without it the card's fields and
 * buttons are disabled with a licence note, a stream kept from before is shown read-only with its
 * status and a **Remove** button (`stream: null`), **Save** sends the retention alone, and no stream
 * route is called.
 *
 * Step 9 of the redesign (spec §7.8): retention and the stream in panels of setting rows, the
 * stream's status in a panel with its actions; each confirmation asks in the page's dialog instead
 * of the browser's `confirm()`, with the same words.
 */
@Component({
  selector: 'q-audit-settings-page',
  imports: [DateTimePipe, SecretOnce],
  templateUrl: './audit-settings.page.html',
  styleUrl: './audit-settings.page.css',
})
export class AuditSettingsPage {
  private readonly ee = inject(EeApi);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  protected readonly licensed = computed(() => this.info.features().includes('audit-log'));
  /** §14.4: the SIEM stream is the feature `audit-log.stream` (the Enterprise plan). */
  protected readonly streamLicensed = computed(() =>
    this.info.features().includes('audit-log.stream'),
  );
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  /** A failed `GET /system/info`, shown instead of an empty page. */
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly allowed = computed(() => this.licensed() && this.instanceAdmin());

  protected readonly current = signal<AuditSettings | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly retention = signal('');
  protected readonly url = signal('');
  protected readonly active = signal(true);
  protected readonly retentionError = signal<string | null>(null);
  protected readonly urlError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  /** A secret the server just generated, until "Done", the next change or leaving the page. */
  protected readonly secret = signal<string | null>(null);
  protected readonly test = signal<StreamTest | null>(null);
  protected readonly busy = signal(false);
  protected readonly minDays = MIN_DAYS;
  protected readonly maxDays = MAX_DAYS;
  /** The change the confirmation dialog asks about; null while it is closed. */
  protected readonly pending = signal<Pending | null>(null);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      untracked(() => {
        this.current.set(null);
        this.secret.set(null);
        if (allowed) void this.load();
      });
    });
    inject(DestroyRef).onDestroy(() => this.secret.set(null));
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      this.show(await ok(this.ee.client.GET('/api/v0/ee/audit/settings')));
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  private show(settings: AuditSettings): void {
    this.current.set(settings);
    this.retention.set(String(settings.retentionDays));
    this.url.set(settings.stream?.url ?? '');
    this.active.set(settings.stream?.active ?? true);
  }

  protected setRetention(event: Event): void {
    this.retention.set(inputValue(event));
    this.retentionError.set(null);
  }

  protected setUrl(event: Event): void {
    this.url.set(inputValue(event));
    this.urlError.set(null);
  }

  protected setActive(event: Event): void {
    this.active.set(isChecked(event));
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const days = Number(this.retention());
    if (!Number.isInteger(days) || days < MIN_DAYS || days > MAX_DAYS) {
      this.retentionError.set(this.retentionText());
      this.focus('audit-retention');
      return;
    }
    const streamLicensed = this.streamLicensed();
    const url = this.url().trim();
    if (streamLicensed && !url && this.current()?.stream) {
      this.ask({ kind: 'save', question: removeQuestion() });
      return;
    }
    await this.applySave(days, streamLicensed, url);
  }

  private async applySave(days: number, streamLicensed: boolean, url: string): Promise<void> {
    await this.run(async () => {
      try {
        const saved = await ok(
          this.ee.client.PUT('/api/v0/ee/audit/settings', {
            body: streamLicensed
              ? { retentionDays: days, stream: url ? { url, active: this.active() } : null }
              : { retentionDays: days },
          }),
        );
        this.showSaved(saved);
        this.announcement.set($localize`:@@auditSettings.saved:Audit settings saved.`);
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 422) throw err;
        const fields = fieldErrors(err);
        if ('body.retentionDays' in fields) this.retentionError.set(this.retentionText());
        if ('body.stream.url' in fields) {
          this.urlError.set(
            $localize`:@@auditSettings.urlInvalid:Use an https URL of a public host, at most 2 048 characters. The instance settings decide whether plain http and internal hosts are allowed, as for webhooks.`,
          );
        }
        if (this.retentionError()) this.focus('audit-retention');
        else if (this.urlError()) this.focus('audit-stream-url');
        else throw err;
      }
    });
  }

  /** The saved settings; a secret the server just generated is shown once. */
  private showSaved(saved: AuditSettingsSaved): void {
    const { secret, ...stream } = saved.stream ?? {};
    this.show({
      retentionDays: saved.retentionDays,
      stream: saved.stream ? (stream as NonNullable<AuditSettings['stream']>) : null,
    });
    this.secret.set(secret ?? null);
  }

  /** Without `audit-log.stream`: removes a stream kept from before, once the dialog is answered. */
  protected removeStream(): void {
    if (this.busy() || !this.current()?.stream) return;
    this.ask({ kind: 'remove', question: removeQuestion() });
  }

  private ask(pending: Pending): void {
    this.pending.set(pending);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  protected async confirmPending(): Promise<void> {
    const pending = this.pending();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pending.set(null);
    this.closeConfirm();
    if (pending.kind === 'save') {
      await this.applySave(Number(this.retention()), this.streamLicensed(), this.url().trim());
    } else if (pending.kind === 'remove') {
      await this.applyRemove();
    } else {
      await this.applyRegenerate();
    }
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing changes. */
  protected cancelPending(): void {
    this.pending.set(null);
    this.closeConfirm();
  }

  private closeConfirm(): void {
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  /** `stream: null` alone: the stream kept from before goes. */
  private async applyRemove(): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      this.showSaved(
        await ok(this.ee.client.PUT('/api/v0/ee/audit/settings', { body: { stream: null } })),
      );
      this.announcement.set($localize`:@@auditSettings.streamRemoved:The SIEM stream was removed.`);
      // The button went with the stream's card.
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  protected regenerate(): void {
    if (this.busy() || !this.streamLicensed()) return;
    this.ask({
      kind: 'regenerate',
      question: $localize`:@@auditSettings.confirmRegenerate:Regenerate the stream secret? The receiver must be given the new secret: batches signed with it fail the old check.`,
    });
  }

  private async applyRegenerate(): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      const { secret } = await ok(
        this.ee.client.POST('/api/v0/ee/audit/settings/stream/regenerate-secret'),
      );
      this.secret.set(secret);
      this.announcement.set(
        $localize`:@@auditSettings.regenerated:A new stream secret was generated.`,
      );
    });
  }

  protected async sendTest(): Promise<void> {
    if (this.busy() || !this.streamLicensed()) return;
    this.test.set(null);
    await this.run(async () => {
      this.test.set(await ok(this.ee.client.POST('/api/v0/ee/audit/settings/stream/test')));
    });
  }

  protected forget(): void {
    this.secret.set(null);
  }

  private retentionText(): string {
    return $localize`:@@auditSettings.retentionInvalid:Keep events between 30 and 36 500 days.`;
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
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
