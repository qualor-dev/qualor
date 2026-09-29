import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
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
import { Api, ok } from '../api/api';
import {
  type AuditEvent,
  type AuditEventsQuery,
  type AuditHead,
  type AuditVerification,
  EeApi,
} from '../api/ee';
import { ApiError, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { label } from '../i18n/labels';
import { OrgContext } from '../org/org-context';
import { SystemInfo } from '../shell/system-info';
import { DateTimePipe } from '../shared/date-time.pipe';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';

const DAY_MS = 24 * 60 * 60 * 1000;
/** The default period: the last 30 days, today included (UTC, as every date of the app). */
const DEFAULT_DAYS = 30;
/** `GET /ee/audit/export` takes at most 366 days (rbac-audit.md §12). */
const EXPORT_MAX_DAYS = 366;
/** rbac-audit.md §13: at most 20 actions, each an exact name or a prefix ending in `.*`. */
const MAX_ACTIONS = 20;
const ACTION = /^[a-z][a-z_]*(\.[a-z][a-z_]*)*(\.\*)?$/;
const PAGE_SIZE = 50;
/** The part of the hash the page shows; the copy button copies all 64 characters. */
const HASH_PREFIX = 12;

type Outcome = '' | 'success' | 'failure';
type Field = 'from' | 'to' | 'action' | 'user' | 'project';
/** The query the list and the export use: the filters with their names resolved to ids. */
type Applied = Omit<AuditEventsQuery, 'limit' | 'cursor'> & { from: string; to: string };

/** `YYYY-MM-DD` of an instant, in UTC. */
function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** The instant a UTC day starts, or null for anything but a real `YYYY-MM-DD` day. */
function dayStart(day: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  const ms = Date.parse(`${day}T00:00:00.000Z`);
  return Number.isNaN(ms) || utcDay(ms) !== day ? null : ms;
}

/** The query string of an applied filter, with one `action` per action (repeated parameters). */
function queryString(applied: Applied): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(applied)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) params.append(key, String(item));
  }
  return params.toString();
}

/**
 * Settings → Audit log (rbac-audit.md §13, §17, feature `audit-log`): the recorded events, newest
 * first, with filters (period, actions, outcome, user, project, and the organisation for instance
 * admins), "Load more", a row's details, and **Export JSON Lines** of the period as a plain
 * download link, so the browser writes the streamed file to disk instead of this page holding it.
 * An org admin sees only its organisation's events: every request carries the current
 * organisation. Instance admins also see the chain head and verify the chain. Nothing is
 * asked of the enterprise API while the feature is inactive or the caller may not read the log.
 */
@Component({
  selector: 'q-audit-log-page',
  imports: [DateTimePipe],
  templateUrl: './audit-log.page.html',
  styleUrl: './audit-log.page.css',
})
export class AuditLogPage {
  private readonly api = inject(Api);
  private readonly ee = inject(EeApi);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);

  protected readonly list = new KeysetList<AuditEvent, Applied>((applied, cursor) =>
    ok(
      this.ee.client.GET('/api/v0/ee/audit/events', {
        params: { query: { ...applied, limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );

  protected readonly licensed = computed(() => this.info.features().includes('audit-log'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  /** A failed `GET /system/info`, shown instead of an empty page. */
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  /** An organisation admin (not an instance admin): reads its current organisation's events. */
  protected readonly orgReader = computed(
    () => !this.instanceAdmin() && this.org.can('org.audit.read'),
  );
  protected readonly allowed = computed(
    () => this.licensed() && (this.instanceAdmin() || this.orgReader()),
  );

  protected readonly from = signal(utcDay(Date.now() - (DEFAULT_DAYS - 1) * DAY_MS));
  protected readonly to = signal(utcDay(Date.now()));
  protected readonly actions = signal('');
  protected readonly outcome = signal<Outcome>('');
  protected readonly username = signal('');
  protected readonly projectKey = signal('');
  protected readonly organizationId = signal('');
  protected readonly fieldError = signal<Partial<Record<Field, string>>>({});
  protected readonly applied = signal<Applied | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The seqs whose details are shown. */
  protected readonly expanded = signal<ReadonlySet<string>>(new Set());

  protected readonly head = signal<AuditHead | null>(null);
  protected readonly headError = signal<string | null>(null);
  protected readonly verification = signal<AuditVerification | null>(null);
  protected readonly verifyError = signal<string | null>(null);
  protected readonly verifying = signal(false);
  protected readonly copyState = signal<'idle' | 'copied' | 'failed'>('idle');

  /** The export's address for the applied filters, or null when the period is too long for it. */
  protected readonly exportHref = computed(() => {
    const applied = this.applied();
    if (!applied) return null;
    const days = (Date.parse(applied.to) - Date.parse(applied.from)) / DAY_MS;
    return days > EXPORT_MAX_DAYS ? null : `/api/v0/ee/audit/export?${queryString(applied)}`;
  });
  protected readonly exportMaxDays = EXPORT_MAX_DAYS;

  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  /** Counts scope changes (organisation, user): an answer for an earlier one is dropped. */
  private generation = 0;

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      const instanceAdmin = this.instanceAdmin();
      const organizationId = this.org.currentId();
      untracked(() => {
        this.generation++;
        // The replaced search leaves `busy` alone (its generation is stale), and the new one may
        // stop before it marks itself busy (an invalid filter, a scope it may not read).
        this.busy.set(false);
        this.expanded.set(new Set());
        this.fieldError.set({});
        this.error.set(null);
        this.applied.set(null);
        this.head.set(null);
        this.verification.set(null);
        // The rows of the previous scope go at once, even while its answer is still on its way.
        this.list.clear();
        if (!allowed || (!instanceAdmin && !organizationId)) return;
        void this.apply(true);
        if (instanceAdmin) void this.loadHead();
      });
    });
  }

  protected set(field: 'from' | 'to' | 'actions' | 'username' | 'projectKey', event: Event): void {
    this[field].set(inputValue(event));
    const key: Field =
      field === 'actions'
        ? 'action'
        : field === 'username'
          ? 'user'
          : field === 'projectKey'
            ? 'project'
            : field;
    this.fieldError.update((errors) => ({ ...errors, [key]: undefined }));
  }

  protected setOutcome(event: Event): void {
    this.outcome.set(inputValue(event) as Outcome);
  }

  protected setOrganization(event: Event): void {
    this.organizationId.set(inputValue(event));
  }

  protected async submit(event: Event): Promise<void> {
    event.preventDefault();
    await this.apply();
  }

  /**
   * Checks the filters, resolves the user and project names to ids, and loads the first page.
   * `scopeChanged` (a new organisation or user) runs even while an earlier search is busy: that
   * one's answer is dropped, so the page never keeps the previous organisation's events.
   */
  private async apply(scopeChanged = false): Promise<void> {
    if (this.busy() && !scopeChanged) return;
    const errors: Partial<Record<Field, string>> = {};
    const from = dayStart(this.from());
    const to = dayStart(this.to());
    if (from === null) errors.from = $localize`:@@audit.dayRequired:Enter a day.`;
    if (to === null) errors.to = $localize`:@@audit.dayRequired:Enter a day.`;
    if (from !== null && to !== null && to < from) {
      errors.to = $localize`:@@audit.periodBackwards:The period ends before it starts.`;
    }
    const actions = this.actions()
      .split(/[\s,]+/)
      .filter((a) => a !== '');
    if (actions.length > MAX_ACTIONS || actions.some((a) => !ACTION.test(a))) {
      errors.action = $localize`:@@audit.actionInvalid:Use action names such as auth.login, or a prefix such as project_member.*, separated by commas (at most 20).`;
    }
    if (Object.keys(errors).length > 0 || from === null || to === null) {
      this.fieldError.set(errors);
      this.focusFirstError(errors);
      return;
    }
    const generation = this.generation;
    this.busy.set(true);
    this.error.set(null);
    try {
      const actorUserId = await this.userId();
      const projectId = await this.projectId();
      if (generation !== this.generation) return;
      if (actorUserId === null || projectId === null) return;
      const organizationId = this.instanceAdmin()
        ? this.organizationId() || undefined
        : (this.org.currentId() ?? undefined);
      const applied: Applied = {
        from: new Date(from).toISOString(),
        to: new Date(to + DAY_MS).toISOString(),
        ...(actions.length > 0 ? { action: actions } : {}),
        ...(this.outcome() ? { outcome: this.outcome() as 'success' | 'failure' } : {}),
        ...(actorUserId ? { actorUserId } : {}),
        ...(projectId ? { projectId } : {}),
        ...(organizationId ? { organizationId } : {}),
      };
      this.fieldError.set({});
      this.expanded.set(new Set());
      this.applied.set(applied);
      await this.list.reset(applied);
    } catch (err) {
      if (generation !== this.generation) return;
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      // A search replaced by a scope change leaves `busy` to the one that replaced it.
      if (generation === this.generation) this.busy.set(false);
    }
  }

  /** The id of the user named in the filter, '' for none, null when no such user exists. */
  private async userId(): Promise<string | null> {
    const username = this.username().trim();
    if (!username) return '';
    try {
      const user = await ok(
        this.api.client.GET('/api/v0/users/lookup', { params: { query: { username } } }),
      );
      return user.id;
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 422)) {
        this.fail({
          user: $localize`:@@audit.noSuchUser:No active user has that name. Check the spelling.`,
        });
        return null;
      }
      throw err;
    }
  }

  /** The id of the project named in the filter, '' for none, null when none can be seen. */
  private async projectId(): Promise<string | null> {
    const key = this.projectKey().trim();
    if (!key) return '';
    try {
      const project = await ok(
        this.api.client.GET('/api/v0/projects/by-key', { params: { query: { key } } }),
      );
      return project.id;
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 422)) {
        this.fail({
          project: $localize`:@@audit.noSuchProject:No project you can see has that key.`,
        });
        return null;
      }
      throw err;
    }
  }

  private fail(errors: Partial<Record<Field, string>>): void {
    this.fieldError.set(errors);
    this.focusFirstError(errors);
  }

  private focusFirstError(errors: Partial<Record<Field, string>>): void {
    const order: Field[] = ['from', 'to', 'action', 'user', 'project'];
    const first = order.find((f) => errors[f]);
    if (!first) return;
    afterNextRender(() => this.document.getElementById(`audit-${first}`)?.focus(), {
      injector: this.injector,
    });
  }

  protected isExpanded(event: AuditEvent): boolean {
    return this.expanded().has(event.seq);
  }

  protected toggle(event: AuditEvent): void {
    this.expanded.update((all) => {
      const next = new Set(all);
      if (next.has(event.seq)) next.delete(event.seq);
      else next.add(event.seq);
      return next;
    });
  }

  protected actorText(event: AuditEvent): string {
    const actor = event.actor;
    if (actor.type !== 'user') return label('auditActor', actor.type);
    const name = actor.username ?? actor.userId ?? '';
    return actor.tokenId ? $localize`:@@audit.actorToken:${name}:name: (with a token)` : name;
  }

  protected targetText(event: AuditEvent): string {
    const target = event.target;
    if (!target) return '';
    const name = target.label ?? target.id;
    return name ? `${target.type}: ${name}` : target.type;
  }

  protected outcomeText(event: AuditEvent): string {
    return label('auditOutcome', event.outcome);
  }

  protected readonly outcomes = ['success', 'failure'] as const;

  protected outcomeLabel(outcome: string): string {
    return label('auditOutcome', outcome);
  }

  protected detailsText(event: AuditEvent): string {
    return JSON.stringify(event.details, null, 2);
  }

  protected breakText(reason: string): string {
    return label('auditBreak', reason);
  }

  private async loadHead(): Promise<void> {
    const generation = this.generation;
    this.headError.set(null);
    try {
      const head = await ok(this.ee.client.GET('/api/v0/ee/audit/head'));
      if (generation === this.generation) this.head.set(head);
    } catch (err) {
      if (generation === this.generation) this.headError.set(problemMessage(err));
    }
  }

  protected async verify(): Promise<void> {
    if (this.verifying()) return;
    this.verifying.set(true);
    this.verification.set(null);
    this.verifyError.set(null);
    try {
      this.verification.set(await ok(this.ee.client.GET('/api/v0/ee/audit/verify')));
    } catch (err) {
      this.verifyError.set(problemMessage(err));
    } finally {
      this.verifying.set(false);
    }
  }

  protected async copyHash(): Promise<void> {
    const hash = this.head()?.hash;
    if (!hash) return;
    try {
      await navigator.clipboard.writeText(hash);
      this.copyState.set('copied');
    } catch {
      // No Clipboard API (an insecure context) or permission refused: the hash is in the details.
      this.copyState.set('failed');
    }
  }

  protected hashStart(hash: string): string {
    return hash.slice(0, HASH_PREFIX);
  }
}
