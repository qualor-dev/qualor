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
  linkedSignal,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { Api } from '../api/api';
import { ApiError } from '../api/errors';
import { closeModal, openAfterRender } from '../shared/dialog';
import { Icon } from '../shared/icon';
import { safeHelpUri } from '../shared/links';
import { assertNever } from '../shared/scm-provider';
import { FixProjectState } from './fix-project';
import {
  cancelFix,
  createFix,
  type FixShown,
  type FixTarget,
  fixRequestError,
  retryFix,
} from './fix-request';
import { fixReasonText, isNoFixReason } from './fix-text';

/** Numbers the views of a page, for the ids of their dialogs. */
let views = 0;

/** Problems that say the project's fix settings are not what the page thought: read them again. */
const SETTINGS_GONE = new Set([
  'FIXES_DISABLED',
  'SCM_NOT_BOUND',
  'FIX_MRS_NOT_ALLOWED',
  'MONITORING_OFF',
  'FIX_LIMIT_REACHED',
]);

/** The states in which the fix is over: nothing runs, a new request re-arms it. */
const ENDED = new Set<FixShown['state']>([
  'merged',
  'fixed',
  'declined',
  'taken_over',
  'cancelled',
]);
/** The states that show the version the fix moves to (not a re-armed fix's old one, T8d). */
const VERSION_SHOWN = new Set<FixShown['state']>(['open', 'merged', 'fixed']);
/** A cancel is possible: not while the server writes the branch (`committing`, 409 FIX_BUSY). */
const CANCELABLE = new Set<FixShown['state']>(['requested', 'preparing', 'open']);
/** The states of a fix in flight (they count against the cap, R9). */
const ACTIVE = new Set<FixShown['state']>(['requested', 'preparing', 'committing', 'open']);
const isActive = (fix: FixShown | null): boolean => fix !== null && ACTIVE.has(fix.state);

/**
 * `q-fix-link`: a vulnerable package's fix MR (spec §6.9), the same in the issue page's "Fix MR"
 * card and, `compact`, as a pill in a list row.
 * - No fix: "Create fix MR" with `canTriage` and a `fixable` package.
 * - `requested`: "Waiting for the fix job". `preparing` and `committing`: "Preparing". Neither shows
 *   a version: a fix that was re-armed still holds its last one (T8d).
 * - `open`: the MR (or PR) as a link, its version, "updating" while it is rebuilt; with a failure
 *   (the last rebuild failed) the reason and Retry beside the link (R8).
 * - `failed` and `no_fix`: why, and Retry. Ended fixes (`merged`, `fixed`, `declined`,
 *   `taken_over`, `cancelled`) say so, with Create again for a `fixable` package. Declined means
 *   a person closed the MR, fixed that the vulnerability left main (T11a).
 * - Cancel on a fix in flight asks first.
 * Without fix MRs switched on and usable for the project it shows nothing, but (ruling FW11) a fix
 * in flight of a project whose fix MRs are switched off: R18 still tracks its MR, so it shows with
 * Cancel as its only action. An action's answer shows at once, and `changed` tells the page to
 * read the finding again.
 */
@Component({
  selector: 'q-fix-link',
  imports: [Icon, NgTemplateOutlet],
  templateUrl: './fix-link.html',
  styleUrl: './fix-link.css',
})
export class FixLinkView {
  private readonly api = inject(Api);
  private readonly fixes = inject(FixProjectState);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef).nativeElement;
  private destroyed = false;

  readonly fix = input<FixShown | null>(null);
  readonly fixable = input(false);
  readonly canTriage = input(false);
  readonly projectId = input.required<string>();
  readonly target = input.required<FixTarget>();
  /** The pill form of a list row: no card, and actions named after the package. */
  readonly compact = input(false);
  /** The fix changed here: the page reads the finding again. */
  readonly changed = output();

  protected readonly uid = `fix-link-${++views}`;
  /** The fix shown: the page's, or the answer of an action here until the page reads it again. */
  protected readonly shown = linkedSignal<FixShown | null>(() => this.fix());
  private readonly state = computed(() => this.fixes.of(this.projectId())());
  /** Fix MRs are on and usable for the project: every action is offered. */
  private readonly usable = computed(() => this.state()?.usable === true);
  /**
   * Ruling FW11: the project switched its fix MRs off while this fix is in flight (the page's, or
   * the one shown here): it is still shown, with Cancel only.
   */
  private readonly inFlightWhileOff = computed(
    () => this.state()?.enabled === false && (isActive(this.fix()) || isActive(this.shown())),
  );
  protected readonly canCreate = computed(
    () => this.usable() && this.canTriage() && this.fixable() && this.target().ecosystem !== '',
  );
  protected readonly visible = computed(
    () =>
      this.inFlightWhileOff() ||
      (this.usable() && (this.shown() !== null || this.canCreate() || this.error() !== null)),
  );
  /** "MR" on GitLab, "PR" on GitHub and Azure DevOps, the plain "MR" while the provider is not known. */
  protected readonly word = computed(() => {
    const provider = this.state()?.provider;
    if (provider === null || provider === undefined) return 'MR';
    switch (provider) {
      case 'github':
        return 'PR';
      case 'gitlab':
        return 'MR';
      case 'azure':
        return 'PR';
      default:
        return assertNever(provider, 'provider');
    }
  });

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly confirming = signal(false);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');

  protected readonly url = computed(() => safeHelpUri(this.shown()?.mrUrl));
  /** "MR !12" on GitLab, "PR #12" on GitHub, "PR !12" on Azure DevOps. */
  protected readonly mrLabel = computed(() => {
    const number = this.shown()?.mrNumber;
    if (number === null || number === undefined) return null;
    const provider = this.state()?.provider;
    if (provider === null || provider === undefined) {
      return $localize`:@@fix.link.mr:MR !${number}:number:`;
    }
    switch (provider) {
      case 'github':
        return $localize`:@@fix.link.pr:PR #${number}:number:`;
      case 'gitlab':
        return $localize`:@@fix.link.mr:MR !${number}:number:`;
      case 'azure':
        return $localize`:@@fix.link.pr.azure:PR !${number}:number:`;
      default:
        return assertNever(provider, 'provider');
    }
  });
  /** The version the fix moves to, only where it is the current one. */
  protected readonly version = computed(() => {
    const fix = this.shown();
    return fix !== null && VERSION_SHOWN.has(fix.state) ? fix.targetVersion : null;
  });
  /**
   * Why it failed or has no fix; an open MR carries the failure of its last rebuild, which may be
   * a no-fix reason (ruling FW12: read as one).
   */
  protected readonly failure = computed(() => {
    const fix = this.shown();
    const failure = fix?.failure;
    if (!fix || !failure) return null;
    return fixReasonText(fix.state, failure);
  });
  /** The reason is a no-fix one: shown as a tag, not as a failure. */
  protected readonly noFixReason = computed(() => {
    const fix = this.shown();
    return fix?.state === 'no_fix' || isNoFixReason(fix?.failure?.code ?? '');
  });
  protected readonly canRetry = computed(() => {
    const fix = this.shown();
    if (fix === null || !this.canTriage() || !this.usable()) return false;
    return (
      fix.state === 'failed' || fix.state === 'no_fix' || (fix.state === 'open' && !!fix.failure)
    );
  });
  protected readonly canCreateAgain = computed(() => {
    const fix = this.shown();
    return (
      fix !== null && this.usable() && this.canTriage() && this.fixable() && ENDED.has(fix.state)
    );
  });
  protected readonly canCancel = computed(() => {
    const fix = this.shown();
    return fix !== null && this.canTriage() && CANCELABLE.has(fix.state);
  });

  protected readonly labels = computed(() => {
    if (!this.compact()) return { create: null, retry: null, createAgain: null, cancel: null };
    const subject = this.target().packageName;
    return {
      create: $localize`:@@fix.link.createLabel:Create fix MR for ${subject}:subject:`,
      retry: $localize`:@@fix.link.retryLabel:Retry: the fix MR for ${subject}:subject:`,
      createAgain: $localize`:@@fix.link.createAgainLabel:Create again: the fix MR for ${subject}:subject:`,
      cancel: $localize`:@@fix.link.cancelLabel:Cancel the fix MR for ${subject}:subject:`,
    };
  });

  constructor() {
    inject(DestroyRef).onDestroy(() => (this.destroyed = true));
  }

  protected async create(): Promise<void> {
    await this.act(async () => {
      this.shown.set(await createFix(this.api, this.projectId(), this.target()));
      return true;
    });
  }

  /** Retry (failed, no fix, an open MR's failure) and Create again (ended): requested again. */
  protected async retry(): Promise<void> {
    const id = this.shown()?.id;
    if (!id) return;
    await this.act(async () => {
      this.shown.set(await retryFix(this.api, id));
      return true;
    });
  }

  protected openCancel(): void {
    if (this.busy()) return;
    this.error.set(null);
    this.confirming.set(true);
    openAfterRender(
      this.injector,
      () => this.dialog()?.nativeElement,
      () => this.confirming(),
    );
  }

  protected closeCancel(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.confirming.set(false);
  }

  protected async cancel(event: Event): Promise<void> {
    event.preventDefault();
    this.closeCancel();
    const fix = this.shown();
    if (!fix) return;
    await this.act(async () => {
      await cancelFix(this.api, fix.id);
      this.shown.set({ ...fix, state: 'cancelled', refresh: false });
      return true;
    });
  }

  /**
   * Runs one action; `run` answers whether the fix changed, which the page is told. A view gone
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
    if ('error' in outcome) this.failed(outcome.error);
    else if (outcome.changed) this.settled();
    this.keepFocus();
  }

  /** The fix changed: the page reads the finding again, and the project's count of fixes. */
  private settled(): void {
    this.fixes.reload(this.projectId());
    this.changed.emit();
  }

  private failed(err: unknown): void {
    this.error.set(fixRequestError(err, this.state()?.maxOpen));
    if (!(err instanceof ApiError)) return;
    if (err.code !== null && SETTINGS_GONE.has(err.code)) this.fixes.reload(this.projectId());
    // Changed elsewhere meanwhile (retried, cancelled): the page reads what it is now.
    if (err.code === 'FIX_NOT_RETRYABLE' || err.status === 404) this.changed.emit();
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
