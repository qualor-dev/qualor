import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { SessionStore } from '../auth/session';
import { daysChoices, OFF } from '../project/settings/cleanup-panel';
import { inputValue } from '../shared/forms';

type CleanupDefaults = ResponseBody<'/api/v0/system/cleanup', 'get'>;

/** The server default's days as a select value: null is off. */
function choiceOf(days: number | null): string {
  return days === null ? OFF : String(days);
}

/** A select value as the server default's days. */
function daysOf(choice: string): number | null {
  return choice === OFF ? null : Number(choice);
}

/**
 * Settings → Cleanup (issue #38), for instance admins: the server defaults of the cleanup of
 * branches and merge requests that have not been analysed for a while. Both are off until an admin
 * sets them; a project follows them unless a project admin set its own rule. Saved with
 * `PUT /system/cleanup`.
 */
@Component({
  selector: 'q-cleanup-page',
  templateUrl: './cleanup.page.html',
  styleUrl: './cleanup.page.css',
})
export class CleanupPage {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);

  /** The stored defaults; null until the first answer. */
  protected readonly current = signal<CleanupDefaults | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly branches = signal(OFF);
  protected readonly mergeRequests = signal(OFF);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');

  protected readonly branchChoices = computed(() =>
    daysChoices(this.current()?.branchesDays ?? null),
  );
  protected readonly mergeRequestChoices = computed(() =>
    daysChoices(this.current()?.mergeRequestsDays ?? null),
  );

  protected readonly dirty = computed(() => {
    const c = this.current();
    return (
      c !== null &&
      (this.branches() !== choiceOf(c.branchesDays) ||
        this.mergeRequests() !== choiceOf(c.mergeRequestsDays))
    );
  });

  constructor() {
    effect(() => {
      const admin = this.instanceAdmin();
      untracked(() => {
        if (admin) void this.load();
      });
    });
  }

  protected setBranches(event: Event): void {
    this.branches.set(inputValue(event));
    this.touched();
  }

  protected setMergeRequests(event: Event): void {
    this.mergeRequests.set(inputValue(event));
    this.touched();
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy() || !this.dirty()) return;
    this.busy.set(true);
    this.touched();
    try {
      const saved = await ok(
        this.api.client.PUT('/api/v0/system/cleanup', {
          body: {
            branchesDays: daysOf(this.branches()),
            mergeRequestsDays: daysOf(this.mergeRequests()),
          },
        }),
      );
      this.show(saved);
      this.announcement.set($localize`:@@cleanup.saved:The cleanup settings were saved.`);
    } catch (err) {
      this.error.set(problemMessage(err));
      this.heading().nativeElement.focus();
    } finally {
      this.busy.set(false);
    }
  }

  private touched(): void {
    this.announcement.set(null);
    this.error.set(null);
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      this.show(await ok(this.api.client.GET('/api/v0/system/cleanup')));
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  private show(defaults: CleanupDefaults): void {
    this.current.set(defaults);
    this.branches.set(choiceOf(defaults.branchesDays));
    this.mergeRequests.set(choiceOf(defaults.mergeRequestsDays));
  }
}
