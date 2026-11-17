import { DOCUMENT, NgTemplateOutlet } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  ElementRef,
  inject,
  Injector,
  input,
  LOCALE_ID,
  linkedSignal,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { ApiError } from '../api/errors';
import type { JiraLink, JiraLinkItem } from '../api/types';
import { DateTimePipe, formatDate } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { Icon } from '../shared/icon';
import { safeHelpUri } from '../shared/links';
import { JiraProjectState } from './jira-project';
import { createJiraLinks, jiraRequestError, jiraStateGone, type JiraTarget } from './jira-request';
import { jiraFailureText } from './jira-text';

/**
 * How long ago the status was read: "checked 5 min ago" (`count` of the unit), the day once it
 * is a day old.
 */
interface CheckedAgo {
  unit: 'now' | 'minutes' | 'hours' | 'day';
  count: number;
  date: string;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** Numbers the views of a page, for the ids of their dialogs. */
let views = 0;

function skippedText(skipped: JiraLinkItem['skipped'] | undefined): string {
  return skipped === 'NOT_FOUND'
    ? $localize`:@@jira.link.notFound:This finding no longer exists.`
    : $localize`:@@jira.link.notEligible:This finding cannot get a Jira issue now.`;
}

/**
 * `q-jira-link`: a finding's Jira link (spec §6.9), the same in the issue page's "Jira" card and,
 * `compact`, as a pill in a list row.
 * - No link: "Create Jira issue" with `canTriage`, a `linkable` finding and a mapped project; in
 *   the card, a project admin of an unmapped project sees "Map this project to Jira" instead.
 * - Pending: "Creating…". Created: the key, linked to Jira in a new tab, its status pill and when
 *   it was read. Failed: why, and Retry. Missing: "Not found in Jira", and Create again.
 * - Unlink asks first; the Jira issue stays in Jira.
 * Without a Jira connection it shows nothing at all. An action's answer shows at once, and
 * `changed` tells the page to read the finding again (which then refreshes while pending, R22).
 */
@Component({
  selector: 'q-jira-link',
  imports: [DateTimePipe, Icon, NgTemplateOutlet, RouterLink],
  templateUrl: './jira-link.html',
  styleUrl: './jira-link.css',
})
export class JiraLinkView {
  private readonly api = inject(Api);
  private readonly jira = inject(JiraProjectState);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly locale = inject(LOCALE_ID);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef).nativeElement;

  readonly link = input<JiraLink | null>(null);
  readonly linkable = input(false);
  readonly canTriage = input(false);
  readonly projectId = input.required<string>();
  readonly target = input.required<JiraTarget>();
  /** The pill form of a list row: no card, and actions named after the finding. */
  readonly compact = input(false);
  /** The link changed here: the page reads the finding again. */
  readonly changed = output();

  protected readonly uid = `jira-link-${++views}`;
  /** The link shown: the page's, or the answer of an action here until the page reads it again. */
  protected readonly shown = linkedSignal<JiraLink | null>(() => {
    const link = this.link();
    return link && link.state !== 'dismissed' ? link : null;
  });
  private readonly state = computed(() => this.jira.of(this.projectId())());
  /** Known to have no connection: nothing of Jira shows. */
  private readonly disconnected = computed(() => this.state()?.connected === false);
  protected readonly canCreate = computed(
    () => this.canTriage() && this.linkable() && this.state()?.mapped === true,
  );
  /** In the card, never in a row (it would repeat on every one): the way to map the project. */
  protected readonly canMap = computed(() => {
    const state = this.state();
    return (
      !this.compact() &&
      this.linkable() &&
      state?.connected === true &&
      !state.mapped &&
      state.canMap
    );
  });
  protected readonly visible = computed(
    () =>
      !this.disconnected() &&
      (this.shown() !== null || this.canCreate() || this.canMap() || this.error() !== null),
  );

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly confirming = signal(false);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');

  protected readonly url = computed(() => safeHelpUri(this.shown()?.url));
  protected readonly failure = computed(() => {
    const failure = this.shown()?.failure;
    return failure ? jiraFailureText(failure) : null;
  });
  protected readonly checked = computed<CheckedAgo | null>(() => {
    const at = this.shown()?.statusCheckedAt;
    if (!at) return null;
    const age = Math.max(0, Date.now() - new Date(at).getTime());
    const date = formatDate(at, this.locale);
    if (age < MINUTE) return { unit: 'now', count: 0, date };
    if (age < HOUR) return { unit: 'minutes', count: Math.floor(age / MINUTE), date };
    if (age < 24 * HOUR) return { unit: 'hours', count: Math.floor(age / HOUR), date };
    return { unit: 'day', count: 0, date };
  });

  /** "CVE-2026-0001 in lodash", for the accessible names of a row's actions. */
  private readonly subject = computed(() => {
    const target = this.target();
    if ('issueId' in target) return null;
    const { vulnerabilityId: id, packageName: name } = target;
    return $localize`:@@jira.link.subject:${id}:id: in ${name}:package:`;
  });
  protected readonly labels = computed(() => {
    const subject = this.compact() ? this.subject() : null;
    if (subject === null) return { create: null, retry: null, createAgain: null, unlink: null };
    return {
      create: $localize`:@@jira.link.createLabel:Create Jira issue for ${subject}:subject:`,
      retry: $localize`:@@jira.link.retryLabel:Retry the Jira issue for ${subject}:subject:`,
      createAgain: $localize`:@@jira.link.createAgainLabel:Create the Jira issue for ${subject}:subject: again`,
      unlink: $localize`:@@jira.link.unlinkLabel:Unlink the Jira issue of ${subject}:subject:`,
    };
  });

  protected async create(): Promise<void> {
    const target = this.target();
    const body =
      'issueId' in target
        ? { issueIds: [target.issueId] }
        : {
            vulnerabilities: [
              { packageName: target.packageName, vulnerabilityId: target.vulnerabilityId },
            ],
          };
    await this.act(async () => {
      const [item] = await createJiraLinks(this.api, this.projectId(), body);
      if (!item?.link) {
        this.error.set(skippedText(item?.skipped));
        return false;
      }
      this.shown.set(item.link);
      return true;
    });
  }

  /** Retry (failed) and Create again (missing): the link goes back to pending. */
  protected async retry(): Promise<void> {
    const id = this.shown()?.id;
    if (!id) return;
    await this.act(async () => {
      this.shown.set(
        await ok(
          this.api.client.POST('/api/v0/jira-links/{id}/retry', { params: { path: { id } } }),
        ),
      );
      return true;
    });
  }

  protected openUnlink(): void {
    if (this.busy()) return;
    this.error.set(null);
    this.confirming.set(true);
    openAfterRender(
      this.injector,
      () => this.dialog()?.nativeElement,
      () => this.confirming(),
    );
  }

  protected closeUnlink(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.confirming.set(false);
  }

  protected async unlink(event: Event): Promise<void> {
    event.preventDefault();
    this.closeUnlink();
    const id = this.shown()?.id;
    if (!id) return;
    await this.act(async () => {
      await done(this.api.client.DELETE('/api/v0/jira-links/{id}', { params: { path: { id } } }));
      this.shown.set(null);
      return true;
    });
  }

  /** Runs one action; `run` answers whether the link changed, which the page is told. */
  private async act(run: () => Promise<boolean>): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      if (await run()) this.changed.emit();
    } catch (err) {
      this.error.set(jiraRequestError(err));
      if (jiraStateGone(err)) this.jira.reload(this.projectId());
      // Changed elsewhere meanwhile (retried, created): the page reads what it is now.
      if (err instanceof ApiError && err.code === 'JIRA_LINK_NOT_RETRYABLE') this.changed.emit();
    } finally {
      this.busy.set(false);
    }
    this.keepFocus();
  }

  /** The button used is gone now: keep keyboard users in the view, not on the page's body. */
  private keepFocus(): void {
    afterNextRender(
      () => {
        const active = this.document.activeElement;
        if (active !== null && active !== this.document.body) return;
        const target =
          this.heading()?.nativeElement ?? this.host.querySelector<HTMLElement>('a, button');
        target?.focus();
      },
      { injector: this.injector },
    );
  }
}
