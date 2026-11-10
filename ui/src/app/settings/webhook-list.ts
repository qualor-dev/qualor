import { DOCUMENT } from '@angular/common';
import type { ElementRef } from '@angular/core';
import {
  Component,
  computed,
  DestroyRef,
  effect,
  inject,
  InjectionToken,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
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
import { SystemInfo } from '../shell/system-info';
import { SecretOnce } from './secret-once';

export type Webhook = ItemOf<'/api/v0/webhooks'>;
type Delivery = ItemOf<'/api/v0/webhooks/{id}/deliveries'>;
type WebhookEvent = Webhook['events'][number];
type DeliveryEvent = Delivery['event'];
export type WebhookKind = Webhook['kind'];
/** The events each kind may subscribe to (6G spec §4; the test message's `chat.test` never is). */
const GENERIC_EVENTS: WebhookEvent[] = ['analysis.completed', 'gate.status_changed'];
/** Offered to generic webhooks only where `vuln.alerts` is licensed (Business and Enterprise). */
const VULNERABILITY_EVENT: WebhookEvent = 'vulnerabilities.found';
const CHAT_EVENTS: WebhookEvent[] = ['gate.failed', 'gate.recovered', 'digest.weekly'];
const KINDS: WebhookKind[] = ['generic', 'slack', 'teams'];
/** How many deliveries a webhook shows: its strip's 20 (spec §6.8). */
const DELIVERIES_SHOWN = 20;
/** The server keeps at most 1 KiB of a receiver's answer (api.md `GET /webhooks/{id}/deliveries`). */
const EXCERPT_MAX_LENGTH = 1024;
/** C0 controls but tab and line feed, DEL, and the C1 controls. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

/** How long after a redelivery the deliveries are read again (the receiver has been called). */
const REREAD_DELAY_MS = 3000;

/**
 * Schedules a function once and returns what cancels it. A token so that specs can fire the re-read
 * after a redelivery by hand instead of waiting for the clock.
 */
export const REREAD_AFTER_REDELIVERY = new InjectionToken<(run: () => void) => () => void>(
  'REREAD_AFTER_REDELIVERY',
  {
    providedIn: 'root',
    factory: () => (run) => {
      const timer = setTimeout(run, REREAD_DELAY_MS);
      return () => clearTimeout(timer);
    },
  },
);

/** A webhook belongs to a scope: organisation scope (null) shows all, a project only its own. */
export function inScope(w: Webhook, projectId: string | null): boolean {
  return projectId === null || w.projectId === projectId;
}

function eventsOf(kind: WebhookKind, vulnerabilityAlerts: boolean): WebhookEvent[] {
  if (kind !== 'generic') return CHAT_EVENTS;
  return vulnerabilityAlerts ? [...GENERIC_EVENTS, VULNERABILITY_EVENT] : GENERIC_EVENTS;
}

/** The browser's IANA zone, the default of a new chat webhook (6G spec §5). */
export function browserTimeZone(): string {
  try {
    return new Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

/** The zones the browser knows, for the searchable list; `UTC` first (the list leaves it out). */
export const TIME_ZONES: readonly string[] = (() => {
  try {
    return ['UTC', ...Intl.supportedValuesOf('timeZone').filter((z) => z !== 'UTC')];
  } catch {
    return ['UTC'];
  }
})();

function kindLabel(kind: WebhookKind): string {
  switch (kind) {
    case 'slack':
      return $localize`:@@webhooks.kind.slack:Slack`;
    case 'teams':
      return $localize`:@@webhooks.kind.teams:Microsoft Teams`;
    default:
      return $localize`:@@webhooks.kind.generic:Generic (signed JSON)`;
  }
}

function eventLabel(event: DeliveryEvent): string {
  switch (event) {
    case 'analysis.completed':
      return $localize`:@@webhooks.event.analysis:Analysis completed`;
    case 'gate.status_changed':
      return $localize`:@@webhooks.event.gate:Quality gate status changed`;
    case 'vulnerabilities.found':
      return $localize`:@@webhooks.event.vulnerabilitiesFound:New vulnerabilities (daily)`;
    case 'gate.failed':
      return $localize`:@@webhooks.event.gateFailed:Quality gate failed (main branch)`;
    case 'gate.recovered':
      return $localize`:@@webhooks.event.gateRecovered:Quality gate passes again (main branch)`;
    case 'digest.weekly':
      return $localize`:@@webhooks.event.digest:Weekly security digest`;
    case 'vulnerabilities.exploited':
      return $localize`:@@webhooks.event.vulnerabilitiesExploited:Exploited vulnerabilities (at once)`;
    case 'chat.test':
      return $localize`:@@webhooks.event.test:Test message`;
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
 * switch it on or off, delete it, and read its last deliveries. The generated secret is shown
 * once (`SecretOnce`) and dropped on "Done", on closing its dialog, on the next addition, on a
 * change of organisation and when the page is left. A URL the server refuses (https only, public
 * hosts only: its SSRF checks, 422 on `body.url`) is reported on the URL field. Each webhook
 * carries a scope tag (all projects, or one project); the organisation's list can add a webhook
 * for one project, a project's list (`projectId` set) shows its own webhooks only and adds to
 * itself. A manager can send a delivery again (its answer is read after a few seconds) and rotate
 * a webhook's secret: the new one is shown once, like the first, and dropped the same ways.
 *
 * Step 8 of the redesign (spec §7.8): each webhook a panel with its URL, its events as tags, its
 * state and quiet Switch off / Switch on and Delete; its last 20 deliveries as a strip with the
 * success rate (loaded with the list), and the same deliveries in a table ("Recent deliveries",
 * read again when opened). "New webhook" opens a dialog holding the form, which then shows the
 * secret; a deletion asks in the page's dialog instead of the browser's `confirm()`.
 *
 * 6G: the form asks the kind first. A Slack or Microsoft Teams webhook subscribes to the chat
 * events, has a time zone for its weekly digest (the browser's by default) and no secret (the
 * dialog closes on success); its URL is shown masked, and its panel offers Send test instead of
 * Rotate secret. Without `QUALOR_PUBLIC_URL` the form warns that messages carry no links (R11).
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
  private readonly system = inject(SystemInfo);
  /** R11: without QUALOR_PUBLIC_URL chat messages carry no links. */
  protected readonly publicUrlMissing = computed(
    () => this.system.info()?.mcp.reason === 'PUBLIC_URL_MISSING',
  );
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
  protected readonly events = signal<ReadonlySet<WebhookEvent>>(new Set(GENERIC_EVENTS));
  /** The new webhook's kind; it never changes later (R4). */
  protected readonly kind = signal<WebhookKind>('generic');
  protected readonly kinds = KINDS;
  protected readonly kindLabel = kindLabel;
  /** Whether the dialog offers `vulnerabilities.found` (the dialog only creates; it never rewrites). */
  private readonly vulnerabilityAlerts = computed(() =>
    this.system.features().includes('vuln.alerts'),
  );
  protected readonly kindEvents = computed(() => eventsOf(this.kind(), this.vulnerabilityAlerts()));
  /** The weekly digest's zone of a new chat webhook. */
  protected readonly timezone = signal(browserTimeZone());
  protected readonly timeZones = TIME_ZONES;
  protected readonly timezoneError = signal<string | null>(null);
  /** Webhooks whose test message is being queued, by id. */
  protected readonly testing = signal<ReadonlySet<string>>(new Set());
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
  private readonly rereadAfter = inject(REREAD_AFTER_REDELIVERY);
  /** The pending re-read per webhook; cancelled with the list or the organisation. */
  private readonly rereads = new Map<string, () => void>();
  /** Deliveries being sent again, by id. */
  protected readonly redelivering = signal<ReadonlySet<string>>(new Set());
  /** A refused redelivery, by delivery id: shown in that delivery's row. */
  protected readonly redeliverErrors = signal<Record<string, string>>({});
  /** The webhook whose secret the rotation dialog is about; null while it is closed. */
  protected readonly rotating = signal<Webhook | null>(null);
  private readonly rotatedSecret = signal<string | null>(null);
  protected readonly rotated = this.rotatedSecret.asReadonly();
  protected readonly rotateError = signal<string | null>(null);
  private readonly rotateDialog = viewChild<ElementRef<HTMLDialogElement>>('rotateDialog');

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
        this.cancelRereads();
        this.redelivering.set(new Set());
        this.testing.set(new Set());
        this.redeliverErrors.set({});
        this.rotatedSecret.set(null);
        this.rotating.set(null);
        this.rotateError.set(null);
        const rotateDialog = this.rotateDialog()?.nativeElement;
        if (rotateDialog) closeModal(rotateDialog);
        // Whatever load-all was running is superseded, also when no organisation is left.
        this.loadToken++;
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
      this.rotatedSecret.set(null);
      this.cancelRereads();
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

  /** Reloads after a change; a project's panel then reads on to the last page again. */
  private async refreshList(): Promise<void> {
    await this.list.refresh();
    if (this.projectId() === null) return;
    const token = this.loadToken;
    await this.list.loadRest(() => token === this.loadToken);
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

  /** Another kind: its own events, all chosen, and no error of the previous kind's answer. */
  protected setKind(kind: WebhookKind): void {
    this.kind.set(kind);
    this.events.set(new Set(eventsOf(kind, this.vulnerabilityAlerts())));
    this.urlError.set(null);
    this.eventsError.set(null);
    this.timezoneError.set(null);
  }

  protected setTimezone(event: Event): void {
    this.timezone.set(inputValue(event));
    this.timezoneError.set(null);
  }

  protected toggleEvent(event: WebhookEvent, change: Event): void {
    const next = new Set(this.events());
    if (isChecked(change)) next.add(event);
    else next.delete(event);
    this.events.set(next);
    this.eventsError.set(null);
  }

  /** Opens "New webhook" as a generic one, on an empty URL, all its events and the browser's zone. */
  openCreate(): void {
    this.secretValue.set(null);
    this.url.set('');
    this.scope.set('');
    this.kind.set('generic');
    this.events.set(new Set(eventsOf('generic', this.vulnerabilityAlerts())));
    this.timezone.set(browserTimeZone());
    this.timezoneError.set(null);
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
    const kind = this.kind();
    const events = eventsOf(kind, this.vulnerabilityAlerts()).filter((e) => this.events().has(e));
    const timezone = this.timezone().trim();
    if (!url) this.urlError.set(badUrl());
    if (events.length === 0) this.eventsError.set(noEvent());
    if (!url || events.length === 0) return;
    this.secretValue.set(null);
    this.createError.set(null);
    this.timezoneError.set(null);
    const generation = this.orgGeneration;
    const projectId = this.projectId() ?? (this.scope() || null);
    await this.run(
      async () => {
        const created = await ok(
          this.api.client.POST('/api/v0/webhooks', {
            body: {
              organizationId,
              ...(kind === 'generic' ? {} : { kind }),
              url,
              events,
              ...(kind === 'generic' ? {} : { timezone: timezone || 'UTC' }),
              ...(projectId ? { projectId } : {}),
            },
          }),
        );
        // Added to the organisation that was current when asked: never shown under another one,
        // nor kept by a page that was left meanwhile.
        if (generation !== this.orgGeneration || this.destroyed) return;
        if (created.secret === undefined || created.secret === null) {
          // 6G: Slack and Teams webhooks have no secret: nothing to copy, the dialog closes.
          clearField(this.urlField(), this.url);
          this.closeCreate();
          this.announcement.set($localize`:@@webhooks.createdChat:Webhook added.`);
          await this.refreshList();
          return;
        }
        this.secretValue.set(created.secret ?? null);
        this.secretShown = created.secret !== undefined && created.secret !== null;
        clearField(this.urlField(), this.url);
        this.announcement.set(
          $localize`:@@webhooks.created:Webhook added. Copy its secret now: it is shown only this once.`,
        );
        await this.refreshList();
      },
      (err) => this.createError.set(problemMessage(err)),
    );
    if (generation !== this.orgGeneration || this.destroyed) return;
    // Closed while the server answered (Escape, Cancel): the dialog opens again on the outcome, or
    // the secret of a webhook it made could never be copied.
    const outcome =
      this.secret() ??
      this.createError() ??
      this.urlError() ??
      this.eventsError() ??
      this.timezoneError();
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
      await this.refreshList();
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

  private cancelRereads(): void {
    for (const cancel of this.rereads.values()) cancel();
    this.rereads.clear();
  }

  /** Sends a delivery again: the new one is queued on top, and the table is read again soon. */
  protected async redeliver(webhook: Webhook, delivery: Delivery): Promise<void> {
    if (this.redelivering().has(delivery.id)) return;
    const generation = this.orgGeneration;
    const mark = (on: boolean) =>
      this.redelivering.update((set) => {
        const next = new Set(set);
        if (on) next.add(delivery.id);
        else next.delete(delivery.id);
        return next;
      });
    mark(true);
    this.redeliverErrors.update((all) =>
      Object.fromEntries(Object.entries(all).filter(([id]) => id !== delivery.id)),
    );
    this.announcement.set(null);
    try {
      const queued = await ok(
        this.api.client.POST('/api/v0/webhooks/{id}/deliveries/{deliveryId}/redeliver', {
          params: { path: { id: webhook.id, deliveryId: delivery.id } },
        }),
      );
      if (generation !== this.orgGeneration || this.destroyed) return;
      this.deliveries.update((all) => {
        const known = all[webhook.id];
        const rest = Array.isArray(known) ? known : [];
        return { ...all, [webhook.id]: [queued, ...rest].slice(0, DELIVERIES_SHOWN) };
      });
      this.announcement.set($localize`:@@webhooks.redelivered:Delivery sent again.`);
      this.rereads.get(webhook.id)?.();
      this.rereads.set(
        webhook.id,
        this.rereadAfter(() => {
          this.rereads.delete(webhook.id);
          if (generation === this.orgGeneration && !this.destroyed) {
            void this.loadDeliveries(webhook, true);
          }
        }),
      );
    } catch (err) {
      if (generation !== this.orgGeneration || this.destroyed) return;
      const message = redeliverMessage(err);
      this.redeliverErrors.update((all) => ({ ...all, [delivery.id]: message }));
    } finally {
      if (generation === this.orgGeneration) mark(false);
    }
  }

  /** 6G R2: a test message through the delivery queue; the deliveries are read again soon. */
  protected async sendTest(webhook: Webhook): Promise<void> {
    if (this.busy() || this.testing().has(webhook.id)) return;
    const generation = this.orgGeneration;
    const mark = (on: boolean) =>
      this.testing.update((set) => {
        const next = new Set(set);
        if (on) next.add(webhook.id);
        else next.delete(webhook.id);
        return next;
      });
    mark(true);
    this.announcement.set(null);
    this.error.set(null);
    try {
      const queued = await ok(
        this.api.client.POST('/api/v0/webhooks/{id}/test', {
          params: { path: { id: webhook.id } },
        }),
      );
      if (generation !== this.orgGeneration || this.destroyed) return;
      this.deliveries.update((all) => {
        const known = all[webhook.id];
        const rest = Array.isArray(known) ? known : [];
        return { ...all, [webhook.id]: [queued, ...rest].slice(0, DELIVERIES_SHOWN) };
      });
      this.announcement.set(
        $localize`:@@webhooks.testSent:Test message queued. It appears in the channel within a minute; see Recent deliveries.`,
      );
      this.rereads.get(webhook.id)?.();
      this.rereads.set(
        webhook.id,
        this.rereadAfter(() => {
          this.rereads.delete(webhook.id);
          if (generation === this.orgGeneration && !this.destroyed) {
            void this.loadDeliveries(webhook, true);
          }
        }),
      );
    } catch (err) {
      if (generation !== this.orgGeneration || this.destroyed) return;
      this.error.set(testMessage(err));
    } finally {
      if (generation === this.orgGeneration) mark(false);
    }
  }

  /** Asks in the rotation dialog; nothing is sent until its "Rotate secret". */
  protected askRotate(webhook: Webhook): void {
    if (this.busy()) return;
    this.rotatedSecret.set(null);
    this.rotateError.set(null);
    this.rotating.set(webhook);
    openAfterRender(
      this.injector,
      () => this.rotateDialog()?.nativeElement,
      () => this.rotating() !== null,
    );
  }

  protected async confirmRotate(): Promise<void> {
    const webhook = this.rotating();
    if (!webhook) {
      // Nothing is pending (the organisation changed meanwhile): the dialog has no business open.
      const dialog = this.rotateDialog()?.nativeElement;
      if (dialog) closeModal(dialog);
      return;
    }
    if (this.busy()) return;
    this.rotateError.set(null);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.POST('/api/v0/webhooks/{id}/regenerate-secret', {
            params: { path: { id: webhook.id } },
          }),
        );
        if (generation !== this.orgGeneration || this.destroyed) return;
        this.rotatedSecret.set(updated.secret ?? null);
        this.list.items.update((items) =>
          items.map((w) => (w.id === updated.id ? stripSecret(updated) : w)),
        );
      },
      (err) => this.rotateError.set(problemMessage(err)),
    );
    if (generation !== this.orgGeneration || this.destroyed) return;
    // Closed while the server answered: it opens again, or the new secret could never be copied.
    if (this.rotated() !== null || this.rotateError() !== null) {
      openAfterRender(this.injector, () => this.rotateDialog()?.nativeElement);
    }
  }

  /** Escape does not close the dialog while it shows the new secret. */
  protected keepRotated(event: Event): void {
    if (this.rotated()) event.preventDefault();
  }

  /** Cancel, Done or the dialog closing otherwise: the secret is dropped. */
  protected closeRotate(): void {
    const dialog = this.rotateDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.forgetRotation();
  }

  protected forgetRotation(): void {
    this.rotatedSecret.set(null);
    this.rotateError.set(null);
    this.rotating.set(null);
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
        // A chat URL's refusal names its host rule (or the retired connectors): the server's words.
        this.urlError.set(this.kind() === 'generic' ? badUrl() : fields['body.url']);
      } else if (fields['body.timezone'] !== undefined) {
        this.timezoneError.set(
          $localize`:@@webhooks.badZone:Choose a time zone from the list, such as Europe/Berlin or UTC.`,
        );
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

function stripSecret(webhook: Webhook & { secret?: string | null }): Webhook {
  const rest: Webhook & { secret?: string | null } = { ...webhook };
  delete rest.secret;
  return rest;
}

/** What a refused redelivery says in its row (api.md `POST .../redeliver`). */
function redeliverMessage(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 404:
        return $localize`:@@webhooks.redeliverGone:This delivery is no longer kept.`;
      case 409:
        return $localize`:@@webhooks.redeliverOff:The webhook is switched off: switch it on to send again.`;
      case 429:
        return $localize`:@@webhooks.redeliverRate:Too many redeliveries; try again in a minute.`;
    }
  }
  return problemMessage(err);
}

/** What a refused test message says (R2). */
function testMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === 'WEBHOOK_INACTIVE') {
      return $localize`:@@webhooks.testOff:The webhook is switched off: switch it on to send a test message.`;
    }
    if (err.status === 429) {
      return $localize`:@@webhooks.testRate:Too many messages for this webhook; try again in a minute.`;
    }
  }
  return problemMessage(err);
}

function badUrl(): string {
  return $localize`:@@webhooks.badUrl:Use an https URL of a public host, without a user name, password or fragment.`;
}

function noEvent(): string {
  return $localize`:@@webhooks.noEvent:Choose at least one event.`;
}
