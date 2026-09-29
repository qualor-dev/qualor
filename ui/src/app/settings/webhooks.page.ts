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
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { DeliveryStrip, deliveryStatusLabel, type StripDelivery } from '../charts/delivery-strip';
import { clip } from '../shared/text';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openModal } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { SecretOnce } from './secret-once';

export type Webhook = ItemOf<'/api/v0/webhooks'>;
type Delivery = ItemOf<'/api/v0/webhooks/{id}/deliveries'>;
type WebhookEvent = Webhook['events'][number];
const EVENTS: WebhookEvent[] = ['analysis.completed', 'gate.status_changed'];
/** How many deliveries a webhook shows: its strip's 20 (spec §6.8). */
const DELIVERIES_SHOWN = 20;
/** The server keeps at most 1 KiB of a receiver's answer (api.md `GET /webhooks/{id}/deliveries`). */
const EXCERPT_MAX_LENGTH = 1024;
/** C0 controls but tab and line feed, DEL, and the C1 controls. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function eventLabel(event: WebhookEvent): string {
  return event === 'analysis.completed'
    ? $localize`:@@webhooks.event.analysis:Analysis completed`
    : $localize`:@@webhooks.event.gate:Quality gate status changed`;
}

/**
 * A receiver's answer as the page shows it: text (it is only ever interpolated), without control
 * characters (the server strips C0 controls already; a terminal escape or a bell has no business
 * on screen either way), at most 1 KiB.
 */
export function excerptText(excerpt: string | null): string {
  return clip((excerpt ?? '').replace(CONTROL, ''), EXCERPT_MAX_LENGTH);
}

/**
 * The organisation's webhooks (api.md §3 Webhooks), for org admins: add one for every project,
 * switch it on or off, delete it, and read its last deliveries. The generated secret is shown
 * once (`SecretOnce`) and dropped on "Done", on closing its dialog, on the next addition, on a
 * change of organisation and when the page is left. A URL the server refuses (https only, public
 * hosts only: its SSRF checks, 422 on `body.url`) is reported on the URL field. Redelivery,
 * secret rotation and per-project webhooks stay in the API (plan 1F ruling Y7).
 *
 * Step 8 of the redesign (spec §7.8): each webhook a panel with its URL, its events as tags, its
 * state and quiet Switch off / Switch on and Delete; its last 20 deliveries as a strip with the
 * success rate (loaded with the list), and the same deliveries in a table ("Recent deliveries",
 * read again when opened). "New webhook" opens a dialog holding the form, which then shows the
 * secret; a deletion asks in the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-webhooks-page',
  imports: [DateTimePipe, DeliveryStrip, Icon, SecretOnce],
  templateUrl: './webhooks.page.html',
  styleUrl: './webhooks.page.css',
})
export class WebhooksPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.webhooks.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.webhooks.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.webhooks.manage'));
  protected readonly list = new KeysetList<Webhook, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/webhooks', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly deliveries = signal<Record<string, Delivery[] | 'loading' | 'failed'>>({});
  /** Each loaded webhook's deliveries as its strip draws them. */
  protected readonly strips = computed(() => {
    const strips: Record<string, StripDelivery[]> = {};
    for (const [id, value] of Object.entries(this.deliveries())) {
      if (!Array.isArray(value)) continue;
      strips[id] = value.map((d) => ({
        key: d.id,
        status: d.status,
        at: d.createdAt,
        label: eventLabel(d.event),
        code: d.responseCode,
      }));
    }
    return strips;
  });
  protected readonly url = signal('');
  protected readonly events = signal<ReadonlySet<WebhookEvent>>(new Set(EVENTS));
  /** The new webhook's secret, until "Done", the next addition or leaving the page. */
  protected readonly secret = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  /** A refused addition other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  protected readonly urlError = signal<string | null>(null);
  protected readonly eventsError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The deletion the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingDelete = signal<{ webhook: Webhook; question: string } | null>(null);
  protected readonly allEvents = EVENTS;
  protected readonly eventLabel = eventLabel;
  protected readonly deliveryStatusLabel = deliveryStatusLabel;
  protected readonly excerptText = excerptText;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly hooks = viewChild<ElementRef<HTMLElement>>('hooks');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;
  /** The latest delivery request per webhook: an older answer is dropped. */
  private readonly deliveryRequests = new Map<string, number>();
  private deliveryRequest = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        // Whatever belonged to the previous organisation goes, whether or not this one is shown.
        this.orgGeneration++;
        this.secret.set(null);
        this.announcement.set(null);
        this.deliveries.set({});
        this.deliveryRequests.clear();
        if (organizationId && admin) void this.list.reset(organizationId);
      });
    });
    // Each listed webhook's strip: its deliveries are read once it is listed.
    effect(() => {
      const webhooks = this.list.items();
      untracked(() => {
        const known = this.deliveries();
        for (const webhook of webhooks) {
          if (!(webhook.id in known)) void this.loadDeliveries(webhook);
        }
      });
    });
    inject(DestroyRef).onDestroy(() => this.secret.set(null));
  }

  protected setUrl(event: Event): void {
    this.url.set(inputValue(event));
    this.urlError.set(null);
  }

  protected toggleEvent(event: WebhookEvent, change: Event): void {
    const next = new Set(this.events());
    if (isChecked(change)) next.add(event);
    else next.delete(event);
    this.events.set(next);
    this.eventsError.set(null);
  }

  /** Opens "New webhook" on an empty URL and both events. */
  protected openCreate(): void {
    this.secret.set(null);
    this.url.set('');
    this.events.set(new Set(EVENTS));
    this.urlError.set(null);
    this.eventsError.set(null);
    this.createError.set(null);
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  /** Cancel, or Done after the secret: the dialog closes, and its close forgets the secret. */
  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.forget();
  }

  protected forget(): void {
    this.secret.set(null);
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const url = this.url().trim();
    const events = EVENTS.filter((e) => this.events().has(e));
    if (!url) this.urlError.set(badUrl());
    if (events.length === 0) this.eventsError.set(noEvent());
    if (!url || events.length === 0) return;
    this.secret.set(null);
    this.createError.set(null);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const created = await ok(
          this.api.client.POST('/api/v0/webhooks', { body: { organizationId, url, events } }),
        );
        // Added to the organisation that was current when asked: never shown under another one.
        if (generation !== this.orgGeneration) return;
        this.secret.set(created.secret ?? null);
        clearField(this.urlField(), this.url);
        this.announcement.set(
          $localize`:@@webhooks.created:Webhook added. Copy its secret now: it is shown only this once.`,
        );
        await this.list.refresh();
      },
      (err) => this.createError.set(problemMessage(err)),
    );
  }

  /** Switches a webhook on or off; the panel and its button stay, the button says what is next. */
  protected async toggleActive(webhook: Webhook): Promise<void> {
    if (this.busy()) return;
    const active = !webhook.active;
    await this.run(async () => {
      const updated = await ok(
        this.api.client.PATCH('/api/v0/webhooks/{id}', {
          params: { path: { id: webhook.id } },
          body: { active },
        }),
      );
      this.list.items.update((items) => items.map((w) => (w.id === updated.id ? updated : w)));
      this.announcement.set(
        updated.active
          ? $localize`:@@webhooks.switchedOn:Webhook ${updated.url}:url: switched on.`
          : $localize`:@@webhooks.switchedOff:Webhook ${updated.url}:url: switched off.`,
      );
    });
  }

  /** Asks in the page's dialog; nothing is sent until its Delete. */
  protected remove(webhook: Webhook): void {
    if (this.busy()) return;
    this.pendingDelete.set({
      webhook,
      question: $localize`:@@webhooks.confirmDelete:Delete the webhook to ${webhook.url}:url:? Its delivery history goes too.`,
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
    await this.applyDelete(pending.webhook);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is deleted. */
  protected cancelDelete(): void {
    this.pendingDelete.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  private async applyDelete(webhook: Webhook): Promise<void> {
    if (this.busy()) return;
    const index = this.list.items().findIndex((w) => w.id === webhook.id);
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/webhooks/{id}', { params: { path: { id: webhook.id } } }),
      );
      await this.list.refresh();
      this.deliveryRequests.delete(webhook.id);
      this.deliveries.update((all) =>
        Object.fromEntries(Object.entries(all).filter(([id]) => id !== webhook.id)),
      );
      this.announcement.set($localize`:@@webhooks.deleted:Webhook ${webhook.url}:url: deleted.`);
      keepFocus(
        this.injector,
        this.document,
        () => this.sectionAt(index)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  /** "Recent deliveries" opened: its table (and the strip) read again. */
  protected openDeliveries(webhook: Webhook, toggle: Event): void {
    if (!(toggle.target instanceof HTMLDetailsElement) || !toggle.target.open) return;
    void this.loadDeliveries(webhook, true);
  }

  /**
   * Reads a webhook's last deliveries. A reload keeps the shown ones until the answer comes (the
   * table stays open); only the latest request's answer is kept.
   */
  protected async loadDeliveries(webhook: Webhook, reload = false): Promise<void> {
    const request = ++this.deliveryRequest;
    this.deliveryRequests.set(webhook.id, request);
    const current = () => this.deliveryRequests.get(webhook.id) === request;
    if (!reload || !Array.isArray(this.deliveries()[webhook.id])) {
      this.deliveries.update((all) => ({ ...all, [webhook.id]: 'loading' }));
    }
    try {
      const page = await ok(
        this.api.client.GET('/api/v0/webhooks/{id}/deliveries', {
          params: { path: { id: webhook.id }, query: { limit: DELIVERIES_SHOWN } },
        }),
      );
      if (current()) this.deliveries.update((all) => ({ ...all, [webhook.id]: page.items }));
    } catch {
      if (current()) this.deliveries.update((all) => ({ ...all, [webhook.id]: 'failed' }));
    }
  }

  /** The deliveries of a webhook once they have loaded. */
  protected loaded(webhook: Webhook): Delivery[] | null {
    const value = this.deliveries()[webhook.id];
    return Array.isArray(value) ? value : null;
  }

  private sectionAt(index: number): HTMLElement | null {
    const sections = [
      ...(this.hooks()?.nativeElement.querySelectorAll<HTMLElement>('section[data-key]') ?? []),
    ];
    return sections[Math.min(index, sections.length - 1)] ?? null;
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refusal names its field, else goes to `onError` (the dialog that is open) or the page's alert.
   */
  private async run(action: () => Promise<void>, onError?: (err: unknown) => void): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.urlError.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const fields = fieldErrors(err);
      if (fields['body.url'] !== undefined) {
        this.urlError.set(badUrl());
      } else if (fields['body.events'] !== undefined) {
        this.eventsError.set(noEvent());
      } else if (onError) {
        onError(err);
      } else {
        this.error.set(problemMessage(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}

function badUrl(): string {
  return $localize`:@@webhooks.badUrl:Use an https URL of a public host, without a user name, password or fragment.`;
}

function noEvent(): string {
  return $localize`:@@webhooks.noEvent:Choose at least one event.`;
}
