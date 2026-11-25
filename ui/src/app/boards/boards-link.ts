import { DOCUMENT, NgTemplateOutlet } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
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
import { Api, done, ok } from '../api/api';
import { ApiError } from '../api/errors';
import type { BoardsLink, BoardsLinkItem } from '../api/types';
import { DateTimePipe, formatDate } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { Icon } from '../shared/icon';
import { safeHelpUri } from '../shared/links';
import { BoardsProjectState } from './boards-project';
import {
  type BoardsTarget,
  boardsRequestError,
  boardsStateGone,
  createBoardsLinks,
} from './boards-request';
import { boardsFailureText } from './boards-text';

/**
 * How long ago the state was read: "checked 5 min ago" (`count` of the unit), the day once it is a
 * day old.
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

/** Why a create made no link, by the skip's code. */
function skippedText(skipped: BoardsLinkItem['skipped'] | undefined): string {
  switch (skipped) {
    case 'NOT_FOUND':
      return $localize`:@@boards.link.notFound:This finding no longer exists.`;
    // With no link: the finding has a Jira link (one tracker per finding).
    case 'ALREADY_LINKED':
      return $localize`:@@boards.link.inJira:This finding already has a Jira issue.`;
    default:
      return $localize`:@@boards.link.notEligible:This finding cannot get a work item now.`;
  }
}

/**
 * `q-boards-link`: a finding's Azure Boards work item, the same in the issue page's "Azure Boards"
 * card and, `compact`, as a pill in a list row. The page shows it in place of `q-jira-link` when
 * the finding has a Boards link or the project is mapped to Boards (`showsBoards`).
 * - No link: "Create work item" with `canTriage`, a `linkable` finding and a mapped project.
 * - Pending: "Creating…". Created: `#<id>`, linked to Azure DevOps in a new tab, the work item's
 *   state pill and when it was read. Failed: why, and Retry. Missing: "Not found in Azure Boards",
 *   and Create again. Retry and Create again only for a finding still `linkable`.
 * - Unlink asks first; the work item stays in Azure Boards.
 * Without a link and a mapping it shows nothing at all. An action's answer shows at once, and
 * `changed` tells the page to read the finding again (which then refreshes while pending).
 */
@Component({
  selector: 'q-boards-link',
  imports: [DateTimePipe, Icon, NgTemplateOutlet],
  templateUrl: './boards-link.html',
  styleUrl: './boards-link.css',
})
export class BoardsLinkView {
  private readonly api = inject(Api);
  private readonly boards = inject(BoardsProjectState);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly locale = inject(LOCALE_ID);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef).nativeElement;
  private destroyed = false;

  readonly link = input<BoardsLink | null>(null);
  readonly linkable = input(false);
  readonly canTriage = input(false);
  readonly projectId = input.required<string>();
  readonly target = input.required<BoardsTarget>();
  /** The pill form of a list row: no card, and actions named after the finding. */
  readonly compact = input(false);
  /** The link changed here: the page reads the finding again. */
  readonly changed = output();

  protected readonly uid = `boards-link-${++views}`;
  /** The link shown: the page's, or the answer of an action here until the page reads it again. */
  protected readonly shown = linkedSignal<BoardsLink | null>(() => {
    const link = this.link();
    return link && link.state !== 'dismissed' ? link : null;
  });
  private readonly state = computed(() => this.boards.of(this.projectId())());
  protected readonly canCreate = computed(
    () => this.canTriage() && this.linkable() && this.state()?.mapped === true,
  );
  protected readonly visible = computed(
    () => this.shown() !== null || this.canCreate() || this.error() !== null,
  );

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly confirming = signal(false);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');

  protected readonly url = computed(() => safeHelpUri(this.shown()?.url));
  protected readonly failure = computed(() => {
    const failure = this.shown()?.failure;
    return failure ? boardsFailureText(failure) : null;
  });
  protected readonly checked = computed<CheckedAgo | null>(() => {
    const at = this.shown()?.stateCheckedAt;
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
    return $localize`:@@boards.link.subject:${id}:id: in ${name}:package:`;
  });
  protected readonly labels = computed(() => {
    const subject = this.compact() ? this.subject() : null;
    if (subject === null) return { create: null, retry: null, createAgain: null, unlink: null };
    return {
      create: $localize`:@@boards.link.createLabel:Create an Azure Boards work item for ${subject}:subject:`,
      retry: $localize`:@@boards.link.retryLabel:Retry the work item for ${subject}:subject:`,
      createAgain: $localize`:@@boards.link.createAgainLabel:Create the work item for ${subject}:subject: again`,
      unlink: $localize`:@@boards.link.unlinkLabel:Unlink the work item of ${subject}:subject:`,
    };
  });

  constructor() {
    inject(DestroyRef).onDestroy(() => (this.destroyed = true));
  }

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
      const [item] = await createBoardsLinks(this.api, this.projectId(), body);
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
          this.api.client.POST('/api/v0/boards-links/{id}/retry', { params: { path: { id } } }),
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
      await done(this.api.client.DELETE('/api/v0/boards-links/{id}', { params: { path: { id } } }));
      this.shown.set(null);
      return true;
    });
  }

  /**
   * Runs one action; `run` answers whether the link changed, which the page is told. A view gone
   * while its request was out (its row left with another page or filter) does nothing more.
   */
  private async act(run: () => Promise<boolean>): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    let outcome: { changed: boolean } | { error: unknown };
    try {
      outcome = { changed: await run() };
    } catch (error) {
      outcome = { error };
    }
    this.busy.set(false);
    if (this.destroyed) return;
    if ('error' in outcome) {
      const err = outcome.error;
      this.error.set(boardsRequestError(err));
      if (boardsStateGone(err)) this.boards.reload(this.projectId());
      // Changed elsewhere meanwhile (retried, created): the page reads what it is now.
      if (err instanceof ApiError && err.code === 'BOARDS_LINK_NOT_RETRYABLE') this.changed.emit();
    } else if (outcome.changed) {
      this.changed.emit();
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
