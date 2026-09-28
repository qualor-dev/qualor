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
import { clip } from '../shared/text';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { SecretOnce } from './secret-once';

export type Webhook = ItemOf<'/api/v0/webhooks'>;
type Delivery = ItemOf<'/api/v0/webhooks/{id}/deliveries'>;
type WebhookEvent = Webhook['events'][number];
const EVENTS: WebhookEvent[] = ['analysis.completed', 'gate.status_changed'];
/** How many deliveries a webhook shows (plan 1F ruling Y7). */
const DELIVERIES_SHOWN = 10;
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

function deliveryStatusLabel(status: Delivery['status']): string {
  switch (status) {
    case 'succeeded':
      return $localize`:@@webhooks.delivery.succeeded:Delivered`;
    case 'failed':
      return $localize`:@@webhooks.delivery.failed:Failed`;
    default:
      return $localize`:@@webhooks.delivery.pending:Pending`;
  }
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
 * switch it on or off, delete it, and read its last 10 deliveries. The generated secret is shown
 * once (`SecretOnce`) and dropped on "Done", on the next addition, on a change of organisation and
 * when the page is left. A URL the server refuses (https only, public hosts only: its SSRF checks,
 * 422 on `body.url`) is reported on the URL field. Redelivery, secret rotation and per-project
 * webhooks stay in the API (plan 1F ruling Y7).
 */
@Component({
  selector: 'q-webhooks-page',
  imports: [DateTimePipe, SecretOnce],
  templateUrl: './webhooks.page.html',
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
  protected readonly url = signal('');
  protected readonly events = signal<ReadonlySet<WebhookEvent>>(new Set(EVENTS));
  /** The new webhook's secret, until "Done", the next addition or leaving the page. */
  protected readonly secret = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly urlError = signal<string | null>(null);
  protected readonly eventsError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly allEvents = EVENTS;
  protected readonly eventLabel = eventLabel;
  protected readonly deliveryStatusLabel = deliveryStatusLabel;
  protected readonly excerptText = excerptText;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly hooks = viewChild<ElementRef<HTMLElement>>('hooks');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
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
    inject(DestroyRef).onDestroy(() => this.secret.set(null));
  }

  protected eventsText(webhook: Webhook): string {
    return webhook.events.map(eventLabel).join(', ');
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
    const generation = this.orgGeneration;
    await this.run(async () => {
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
    });
  }

  protected async setActive(webhook: Webhook, change: Event): Promise<void> {
    const box = change.target instanceof HTMLInputElement ? change.target : null;
    if (this.busy()) {
      if (box) box.checked = webhook.active;
      return;
    }
    const active = isChecked(change);
    await this.run(
      async () => {
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
      },
      () => {
        // The box shows what the server has, not what was asked for.
        if (box) box.checked = webhook.active;
      },
    );
  }

  protected async remove(webhook: Webhook): Promise<void> {
    if (this.busy()) return;
    if (
      !window.confirm(
        $localize`:@@webhooks.confirmDelete:Delete the webhook to ${webhook.url}:url:? Its delivery history goes too.`,
      )
    ) {
      return;
    }
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

  protected async loadDeliveries(webhook: Webhook, toggle: Event): Promise<void> {
    if (!(toggle.target instanceof HTMLDetailsElement) || !toggle.target.open) return;
    const request = ++this.deliveryRequest;
    this.deliveryRequests.set(webhook.id, request);
    const current = () => this.deliveryRequests.get(webhook.id) === request;
    this.deliveries.update((all) => ({ ...all, [webhook.id]: 'loading' }));
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

  /** Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. */
  private async run(action: () => Promise<void>, failed?: () => void): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.urlError.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      failed?.();
      const fields = fieldErrors(err);
      if (fields['body.url'] !== undefined) {
        this.urlError.set(badUrl());
      } else if (fields['body.events'] !== undefined) {
        this.eventsError.set(noEvent());
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
