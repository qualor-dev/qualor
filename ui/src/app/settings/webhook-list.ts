import { DOCUMENT } from '@angular/common';
import type { ElementRef } from '@angular/core';
import {
  Component,
  computed,
  DestroyRef,
  effect,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { DeliveryStrip, deliveryStatusLabel, type StripDelivery } from '../charts/delivery-strip';
import { clip } from '../shared/text';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue, isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { RouterLink } from '@angular/router';
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

/** A webhook belongs to a scope: organisation scope (null) shows all, a project only its own. */
export function inScope(w: Webhook, projectId: string | null): boolean {
  return projectId === null || w.projectId === projectId;
}

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
 * hosts only: its SSRF checks, 422 on `body.url`) is reported on the URL field. Each webhook
 * carries a scope tag (all projects, or one project); the organisation's list can add a webhook
 * for one project, a project's list (`projectId` set) shows its own webhooks only and adds to
 * itself.
 *
 * Step 8 of the redesign (spec §7.8): each webhook a panel with its URL, its events as tags, its
 * state and quiet Switch off / Switch on and Delete; its last 20 deliveries as a strip with the
 * success rate (loaded with the list), and the same deliveries in a table ("Recent deliveries",
 * read again when opened). "New webhook" opens a dialog holding the form, which then shows the
 * secret; a deletion asks in the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-webhook-list',
  imports: [DateTimePipe, DeliveryStrip, Icon, RouterLink, SecretOnce],
  templateUrl: './webhook-list.html',
  styleUrl: './webhook-list.css',
})
export class WebhookList {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  /** The organisation whose webhooks are listed. */
  readonly organizationId = input<string | null>(null);
  /** The role may add, switch and delete webhooks. */
  readonly canManage = input(false);
  /** Null: the organisation's scope, every webhook; an id: only that project's webhooks. */
  readonly projectId = input<string | null>(null);
  /** Where focus goes when a deleted row leaves nothing to focus: the embedding page's heading. */
  readonly focusFallback = input<() => HTMLElement | null>(() => null);
  /** Whether `projects` is still being read, complete, or could not be read. */
  readonly projectsState = input<'loading' | 'ready' | 'failed'>('ready');
  /** The project-scope list has been read to its last page. */
  protected readonly complete = signal(false);
  /** The organisation's projects: names for the scope tags and the select. */
  readonly projects = input<readonly { id: string; name: string }[]>([]);
  protected readonly visible = computed(() =>
    this.list.items().filter((w) => inScope(w, this.projectId())),
  );
  protected readonly sortedProjects = computed(() =>
    [...this.projects()].sort((a, b) => a.name.localeCompare(b.name)),
  );
  /** The scope the dialog's select holds: '' for all projects. */
  protected readonly scope = signal('');
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
  private readonly secretValue = signal<string | null>(null);
  readonly secret = this.secretValue.asReadonly();
  protected readonly error = signal<string | null>(null);
  /** A refused addition other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  protected readonly urlError = signal<string | null>(null);
  protected readonly eventsError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The page was left: a late answer keeps no secret and opens no dialog. */
  private destroyed = false;
  /** The dialog shows a new webhook's secret, until it closes. */
  private secretShown = false;
  /** The deletion the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingDelete = signal<{ webhook: Webhook; question: string } | null>(null);
  protected readonly allEvents = EVENTS;
  protected readonly eventLabel = eventLabel;
  protected readonly deliveryStatusLabel = deliveryStatusLabel;
  protected readonly excerptText = excerptText;
  private readonly hooks = viewChild<ElementRef<HTMLElement>>('hooks');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;
  private loadToken = 0;
  /** The latest delivery request per webhook: an older answer is dropped. */
  private readonly deliveryRequests = new Map<string, number>();
  private deliveryRequest = 0;

  constructor() {
    effect(() => {
      const organizationId = this.organizationId();
      const projectId = this.projectId();
      untracked(() => {
        // Whatever belonged to the previous organisation goes, whether or not this one is shown.
        this.orgGeneration++;
        this.secretValue.set(null);
        this.announcement.set(null);
        this.deliveries.set({});
        this.deliveryRequests.clear();
        if (organizationId) void this.load(organizationId, projectId !== null);
      });
    });
    // Each listed webhook's strip: its deliveries are read once it is listed.
    effect(() => {
      const webhooks = this.visible();
      untracked(() => {
        const known = this.deliveries();
        for (const webhook of webhooks) {
          if (!(webhook.id in known)) void this.loadDeliveries(webhook);
        }
      });
    });
    inject(DestroyRef).onDestroy(() => {
      this.destroyed = true;
      this.loadToken++;
      this.secretValue.set(null);
    });
  }

  /** Loads the first page; a project's panel reads on to the last one, as it filters on the client. */
  private async load(organizationId: string, all: boolean): Promise<void> {
    const token = ++this.loadToken;
    this.complete.set(false);
    await this.list.reset(organizationId);
    if (all) await this.list.loadRest(() => token === this.loadToken);
    if (token === this.loadToken) this.complete.set(true);
  }

  /** The tag of a webhook's scope: the project's name, or null when the project is gone. */
  protected projectName(id: string | null): string | null {
    return this.projects().find((p) => p.id === id)?.name ?? null;
  }

  protected setScope(event: Event): void {
    this.scope.set(inputValue(event));
  }

  /**
   * Escape does not close the dialog while it shows the secret (step 9 review): one reflexive key
   * would lose a secret shown only once. Done closes it; Escape still closes the form.
   */
  protected keepSecret(event: Event): void {
    if (this.secret()) event.preventDefault();
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
  openCreate(): void {
    this.secretValue.set(null);
    this.url.set('');
    this.scope.set('');
    this.events.set(new Set(EVENTS));
    this.urlError.set(null);
    this.eventsError.set(null);
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
    this.secretValue.set(null);
    // The secret is gone: the page no longer asks to copy it.
    if (this.secretShown) {
      this.secretShown = false;
      this.announcement.set($localize`:@@webhooks.createdDone:Webhook added.`);
    }
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.organizationId();
    if (!organizationId || this.busy()) return;
    const url = this.url().trim();
    const events = EVENTS.filter((e) => this.events().has(e));
    if (!url) this.urlError.set(badUrl());
    if (events.length === 0) this.eventsError.set(noEvent());
    if (!url || events.length === 0) return;
    this.secretValue.set(null);
    this.createError.set(null);
    const generation = this.orgGeneration;
    const projectId = this.projectId() ?? (this.scope() || null);
    await this.run(
      async () => {
        const created = await ok(
          this.api.client.POST('/api/v0/webhooks', {
            body: { organizationId, url, events, ...(projectId ? { projectId } : {}) },
          }),
        );
        // Added to the organisation that was current when asked: never shown under another one,
        // nor kept by a page that was left meanwhile.
        if (generation !== this.orgGeneration || this.destroyed) return;
        this.secretValue.set(created.secret ?? null);
        this.secretShown = created.secret !== undefined && created.secret !== null;
        clearField(this.urlField(), this.url);
        this.announcement.set(
          $localize`:@@webhooks.created:Webhook added. Copy its secret now: it is shown only this once.`,
        );
        await this.list.refresh();
      },
      (err) => this.createError.set(problemMessage(err)),
    );
    if (generation !== this.orgGeneration || this.destroyed) return;
    // Closed while the server answered (Escape, Cancel): the dialog opens again on the outcome, or
    // the secret of a webhook it made could never be copied.
    const outcome = this.secret() ?? this.createError() ?? this.urlError() ?? this.eventsError();
    if (outcome !== null) {
      openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
    }
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
        () => this.focusFallback()(),
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
        keepFocus(this.injector, this.document, () => this.focusFallback()());
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
