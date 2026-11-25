import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../../api/api';
import { fieldErrors, problemMessage } from '../../api/errors';
import type { ResponseBody } from '../../api/types';
import { can } from '../../auth/permissions';
import { clearField, inputValue } from '../../shared/forms';
import type { ProjectDto } from '../current-project';

type Cleanup = ResponseBody<'/api/v0/projects/{id}/cleanup', 'get'>;

/** A choice of a rule's select: its value and its words. */
export interface DaysChoice {
  value: string;
  text: string;
}

/** The numbers of days a cleanup rule offers, here and in Settings → Cleanup. */
export const CLEANUP_DAYS: readonly number[] = [30, 60, 90, 180, 365];

/** The select value of "off"; a number of days is its own digits. */
export const OFF = 'off';
/** The select value of "the server default" (the project's null). */
const DEFAULT = 'default';

/** The server's bounds on the keep patterns (server/src/routes/cleanup.ts). */
const MAX_PATTERNS = 20;
const MAX_PATTERN_LENGTH = 255;
const CONTROL_CHARACTER = /\p{Cc}/u;
const KEEP_PATH = 'body.keepBranches';

/** A number of days, as a choice reads it. */
export function daysText(days: number): string {
  return days === 1
    ? $localize`:@@cleanup.oneDay:1 day`
    : $localize`:@@cleanup.days:${days}:days: days`;
}

/**
 * "Off" and the days of {@link CLEANUP_DAYS}, with the stored number in order when it is none of
 * them (a value set through the API keeps its own choice).
 */
export function daysChoices(stored: number | null): DaysChoice[] {
  const days = [...CLEANUP_DAYS];
  if (stored !== null && stored > 0 && !days.includes(stored)) {
    days.push(stored);
    days.sort((a, b) => a - b);
  }
  return [
    { value: OFF, text: $localize`:@@cleanup.off:Off` },
    ...days.map((n) => ({ value: String(n), text: daysText(n) })),
  ];
}

/** A project's own days as a select value: null is the server default, 0 is off. */
function projectChoice(days: number | null): string {
  if (days === null) return DEFAULT;
  return days === 0 ? OFF : String(days);
}

/** A select value as the project's own days. */
function projectDays(choice: string): number | null {
  if (choice === DEFAULT) return null;
  return choice === OFF ? 0 : Number(choice);
}

/** The first choice of a project's rule: the server default, and what it is. */
function defaultChoice(serverDefault: number | null): DaysChoice {
  return {
    value: DEFAULT,
    text:
      serverDefault === null
        ? $localize`:@@cleanup.serverDefaultOff:Server default (off)`
        : $localize`:@@cleanup.serverDefault:Server default (${daysText(serverDefault)}:days:)`,
  };
}

/**
 * Project → Settings → Cleanup (issue #38): after how many days without an analysis Qualor deletes
 * the project's branches and merge requests, the branches it always keeps, and the project's own
 * keep patterns. Each rule follows the server default, is off, or has its own days. The panel
 * reads its own settings (they are not part of the project) and starts its form again from every
 * answer it gets; without `project.settings` it only shows them.
 */
@Component({
  selector: 'q-cleanup-panel',
  templateUrl: './cleanup-panel.html',
  styleUrl: './cleanup-panel.css',
})
export class CleanupPanel {
  private readonly api = inject(Api);
  /** Bumped by every load; an answer of an older one is dropped. */
  private loadSeq = 0;
  readonly project = input.required<ProjectDto>();

  /** The last state the server gave; null until the first answer. */
  protected readonly loaded = signal<Cleanup | null>(null);
  protected readonly loadError = signal<string | null>(null);
  /** A load runs: Try again stays in the page, disabled, so keyboard focus stays on it. */
  protected readonly loading = signal(false);

  protected readonly canEdit = computed(() => can(this.project().permissions, 'project.settings'));

  protected readonly branches = signal(DEFAULT);
  protected readonly mergeRequests = signal(DEFAULT);
  protected readonly keep = signal<readonly string[]>([]);
  protected readonly keepText = signal('');
  protected readonly keepError = signal<string | null>(null);
  private readonly keepField = viewChild<ElementRef<HTMLInputElement>>('keepField');

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);

  protected readonly branchChoices = computed(() => {
    const l = this.loaded();
    if (!l) return [];
    return [defaultChoice(l.serverDefaults.branchesDays), ...daysChoices(l.branchesDays)];
  });

  protected readonly mergeRequestChoices = computed(() => {
    const l = this.loaded();
    if (!l) return [];
    return [defaultChoice(l.serverDefaults.mergeRequestsDays), ...daysChoices(l.mergeRequestsDays)];
  });

  /** The main branch: the project's main branch row, or its name while it has no analysis. */
  protected readonly mainBranch = computed(
    () => this.loaded()?.alwaysKept.mainBranch ?? this.project().mainBranchName,
  );

  protected readonly dirty = computed(() => {
    const l = this.loaded();
    if (!l) return false;
    const keep = this.keep();
    return (
      this.branches() !== projectChoice(l.branchesDays) ||
      this.mergeRequests() !== projectChoice(l.mergeRequestsDays) ||
      keep.length !== l.keepBranches.length ||
      keep.some((p, i) => p !== l.keepBranches[i]) ||
      // A pattern typed and not added yet: Save adds it.
      this.keepText().trim() !== ''
    );
  });

  constructor() {
    // Only the id: the page reads the project again after other panels save, with the same id.
    const projectId = computed(() => this.project().id);
    effect(() => {
      const id = projectId();
      untracked(() => void this.load(id));
    });
  }

  private seed(state: Cleanup): void {
    this.loaded.set(state);
    this.branches.set(projectChoice(state.branchesDays));
    this.mergeRequests.set(projectChoice(state.mergeRequestsDays));
    this.keep.set(state.keepBranches);
    clearField(this.keepField(), this.keepText);
    this.keepError.set(null);
  }

  protected async load(id: string, retry = false): Promise<void> {
    const seq = ++this.loadSeq;
    this.loaded.set(null);
    // A retry keeps the alert and its button until the answer, so focus is not dropped.
    if (!retry) this.loadError.set(null);
    this.loading.set(true);
    try {
      const state = await ok(
        this.api.client.GET('/api/v0/projects/{id}/cleanup', { params: { path: { id } } }),
      );
      if (seq === this.loadSeq) {
        this.loadError.set(null);
        this.seed(state);
      }
    } catch (err) {
      if (seq === this.loadSeq) this.loadError.set(problemMessage(err));
    } finally {
      if (seq === this.loadSeq) this.loading.set(false);
    }
  }

  private touched(): void {
    this.announcement.set(null);
    this.error.set(null);
  }

  protected setBranches(event: Event): void {
    this.branches.set(inputValue(event));
    this.touched();
  }

  protected setMergeRequests(event: Event): void {
    this.mergeRequests.set(inputValue(event));
    this.touched();
  }

  // The keep patterns: a chip per pattern, typed into one field. A comma is no separator: a glob
  // may hold one ({a,b}).

  /** Why `text` cannot be added as a keep pattern; null when it can. */
  private patternProblem(text: string): string | null {
    if (CONTROL_CHARACTER.test(text)) {
      return $localize`:@@cleanup.keepControl:A pattern cannot contain a control character.`;
    }
    if (text.length > MAX_PATTERN_LENGTH) {
      return $localize`:@@cleanup.keepLength:A pattern can have at most ${MAX_PATTERN_LENGTH}:max: characters.`;
    }
    if (this.keep().includes(text)) {
      return $localize`:@@cleanup.keepTaken:This pattern is already in the list.`;
    }
    if (this.keep().length >= MAX_PATTERNS) {
      return $localize`:@@cleanup.keepCount:Use at most ${MAX_PATTERNS}:max: patterns.`;
    }
    return null;
  }

  /** Adds the typed text as a pattern; false (with the reason shown) when it cannot be one. */
  private commitPattern(raw: string): boolean {
    const text = raw.trim();
    if (text === '') return true;
    const problem = this.patternProblem(text);
    this.keepError.set(problem);
    if (problem !== null) return false;
    this.keep.update((keep) => [...keep, text]);
    return true;
  }

  protected typePattern(event: Event): void {
    this.keepText.set(inputValue(event));
    this.keepError.set(null);
    this.touched();
  }

  protected enterPattern(event: Event): void {
    event.preventDefault();
    if (this.commitPattern(this.keepText())) clearField(this.keepField(), this.keepText);
  }

  /** Leaving the field keeps what was typed: Save never drops a pattern the person wrote. */
  protected leavePatterns(): void {
    if (this.keepText().trim() !== '' && this.commitPattern(this.keepText())) {
      clearField(this.keepField(), this.keepText);
    }
  }

  protected removePattern(pattern: string): void {
    this.touched();
    this.keepError.set(null);
    this.keep.update((keep) => keep.filter((p) => p !== pattern));
    this.keepField()?.nativeElement.focus();
  }

  protected removePatternLabel(pattern: string): string {
    return $localize`:@@cleanup.removePattern:Remove the pattern ${pattern}:pattern:`;
  }

  protected async save(): Promise<void> {
    if (this.busy() || !this.dirty() || !this.canEdit()) return;
    this.touched();
    // The pattern still in the field goes with the others, or stops the save with its reason.
    if (!this.commitPattern(this.keepText())) return;
    clearField(this.keepField(), this.keepText);
    const id = this.project().id;
    const seq = this.loadSeq;
    const current = () => id === this.project().id && seq === this.loadSeq;
    this.busy.set(true);
    try {
      const state = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/cleanup', {
          params: { path: { id } },
          body: {
            branchesDays: projectDays(this.branches()),
            mergeRequestsDays: projectDays(this.mergeRequests()),
            keepBranches: [...this.keep()],
          },
        }),
      );
      if (current()) {
        this.seed(state);
        this.announcement.set($localize`:@@cleanup.saved:The cleanup settings were saved.`);
      }
    } catch (err) {
      if (!current()) return;
      if (Object.keys(fieldErrors(err)).some((path) => path.startsWith(KEEP_PATH))) {
        this.keepError.set(
          $localize`:@@cleanup.keepInvalid:One of the patterns is not a valid branch pattern.`,
        );
      } else {
        this.error.set(problemMessage(err));
      }
    } finally {
      this.busy.set(false);
    }
  }
}
