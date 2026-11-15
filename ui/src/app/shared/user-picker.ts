import {
  afterNextRender,
  booleanAttribute,
  Component,
  computed,
  DestroyRef,
  type ElementRef,
  inject,
  Injector,
  input,
  model,
  signal,
  viewChild,
} from '@angular/core';
import { ApiError, problemMessage } from '../api/errors';
import { wrapIndex } from './menu-keys';

/** A person the picker suggests: what `GET /users/search` and the members list both carry. */
export interface UserSuggestion {
  id: string;
  username: string;
  displayName: string | null;
}

/**
 * Where the suggestions come from: the page's request for the people whose name starts with
 * `query` (at most ten). A refusal is thrown as the API's error, so the picker can say why.
 */
export type UserSource = (query: string) => Promise<readonly UserSuggestion[]>;

/** How long typing must pause before the picker asks (each keystroke would be a request). */
export const SEARCH_DELAY_MS = 250;
/** A user name is 1 to 64 characters (`GET /users/lookup`, `GET /users/search`). */
const USERNAME_MAX_LENGTH = 64;
/** The gap between the field and its list, and the least height the list keeps (three rows). */
const LIST_GAP_PX = 4;
const LIST_MIN_PX = 112;

type State = 'idle' | 'short' | 'loading' | 'results' | 'empty' | 'error';

/** Orders suggestions by username, by UTF-16 code units. */
function byUsername(a: UserSuggestion, b: UserSuggestion): number {
  if (a.username < b.username) return -1;
  return a.username > b.username ? 1 : 0;
}

/**
 * `q-user-picker`: a user name field that suggests people as one types, in the ARIA 1.2 combobox
 * pattern (an input with role combobox, aria-expanded, aria-controls and aria-activedescendant,
 * over a listbox of options). The page owns the label (`for` = `inputId`), the field's error and
 * the source of the suggestions, so each screen decides who may be suggested.
 *
 * - It asks `source` once typing has paused for 250 ms, and only from `minLength` characters
 *   (code points, as the server counts them); a shorter name gets a hint, not a request. Only the
 *   answer to the latest request is shown: an earlier one arriving late is dropped. An answer
 *   that arrives once the field has lost the focus is kept, the list closed, for ArrowDown.
 * - ArrowDown and ArrowUp move through the suggestions (the highlighted one scrolled into view),
 *   Enter picks one, Escape closes the list (and only the list: a dialog around it stays open); a
 *   click picks one too. ArrowDown asks again only when the text changed since the last answer.
 * - Free text stays allowed: `selected` is the suggestion picked, null as soon as the text changes,
 *   and a page that gets a name without a pick resolves it itself (`GET /users/lookup`).
 * - Searching, no match, a short name and a refused search are said in a polite live region,
 *   which is always rendered; a refusal (429 RATE_LIMITED among them) is shown, never dropped.
 */
@Component({
  selector: 'q-user-picker',
  templateUrl: './user-picker.html',
  styleUrl: './user-picker.css',
})
export class UserPicker {
  /** The input's id, which the page's `<label for>` names. */
  readonly inputId = input.required<string>();
  readonly source = input.required<UserSource>();
  /** The fewest characters the source accepts (`GET /users/search`: 2, or 1 for an instance admin). */
  readonly minLength = input(2);
  /** The page's error for the field: marks the input invalid when set. */
  readonly invalid = input(false);
  /** The id of the page's error (or hint) that describes the input, if any. */
  readonly describedBy = input<string | null>(null);
  /** The input takes the focus when its dialog opens (the dialog's `autofocus`). */
  readonly autofocus = input(false, { transform: booleanAttribute });
  /** The form needs a name here (`aria-required`; the page checks it on submit). */
  readonly required = input(false, { transform: booleanAttribute });

  /** The text in the field. */
  readonly text = model('');
  /** The suggestion picked; null once the text no longer is its name (free text). */
  readonly selected = model<UserSuggestion | null>(null);

  protected readonly state = signal<State>('idle');
  protected readonly suggestions = signal<readonly UserSuggestion[]>([]);
  protected readonly active = signal(-1);
  protected readonly errorText = signal('');
  protected readonly open = computed(
    () => this.state() === 'results' && this.suggestions().length > 0,
  );
  protected readonly listboxId = computed(() => `${this.inputId()}-listbox`);
  protected readonly statusId = computed(() => `${this.inputId()}-status`);
  protected readonly activeId = computed(() =>
    this.open() && this.active() >= 0 ? this.optionId(this.active()) : null,
  );
  protected readonly maxLength = USERNAME_MAX_LENGTH;
  /** The list's height limit: the room under the field, in its dialog or the window. */
  protected readonly listMax = signal<string | null>(null);

  private readonly injector = inject(Injector);
  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>('field');
  private readonly list = viewChild.required<ElementRef<HTMLElement>>('list');
  private timer: ReturnType<typeof setTimeout> | undefined;
  /** Counts requests (and cancellations): only the latest request's answer is shown. */
  private generation = 0;
  /** The query of the last answer (suggestions, none, or a refusal); null once the text changed. */
  private answered: string | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancel());
  }

  protected optionId(index: number): string {
    return `${this.inputId()}-option-${index}`;
  }

  /** "username — Display Name"; the display name only when it says something more. */
  protected extra(user: UserSuggestion): string | null {
    const name = user.displayName?.trim() ?? '';
    return name === '' || name === user.username ? null : name;
  }

  protected onInput(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.text.set(value);
    if (this.selected() !== null) this.selected.set(null);
    this.schedule(value);
  }

  protected onKeydown(event: KeyboardEvent): void {
    // While an input method composes a character, its keys are its own (Enter confirms it);
    // Safari ends a composition with a keydown of keyCode 229 after compositionend.
    if (event.isComposing || event.keyCode === 229) return;
    switch (event.key) {
      case 'Tab':
        // The list closes before the browser moves the focus, so it moves on to the next control
        // (an open list that scrolls could otherwise take it, then hide with it). Tab goes on.
        if (this.open()) {
          this.state.set('idle');
          this.active.set(-1);
        }
        return;
      case 'ArrowDown':
        event.preventDefault();
        this.arrowDown();
        return;
      case 'ArrowUp':
        event.preventDefault();
        this.arrowUp();
        return;
      case 'Enter': {
        const user = this.open() ? this.suggestions()[this.active()] : undefined;
        // Without a highlighted suggestion, Enter submits the form with the text as typed.
        if (!user) {
          this.close();
          return;
        }
        event.preventDefault();
        this.pick(user);
        return;
      }
      case 'Escape':
        // The list closes (its suggestions kept for ArrowDown); a dialog around it stays open.
        if (!this.open()) return;
        event.preventDefault();
        event.stopPropagation();
        this.state.set('idle');
        this.active.set(-1);
        return;
    }
  }

  /** Keeps the focus in the input while the list (an option, its padding, its scrollbar) is pressed. */
  protected keepFocus(event: MouseEvent): void {
    event.preventDefault();
  }

  protected pick(user: UserSuggestion): void {
    this.cancel();
    this.answered = null;
    this.text.set(user.username);
    this.field().nativeElement.value = user.username;
    this.selected.set(user);
    this.state.set('idle');
    this.suggestions.set([]);
    this.active.set(-1);
  }

  /** Focus left the field: the list closes, the suggestions are kept for ArrowDown. */
  protected onBlur(): void {
    if (this.state() === 'results') this.state.set('idle');
    this.active.set(-1);
  }

  /** Focuses the input (a page's refused name keeps the focus on it). */
  focus(): void {
    this.field().nativeElement.focus();
  }

  /** Empties the field and forgets the pick (after an addition). */
  clear(): void {
    this.close();
    this.text.set('');
    this.selected.set(null);
    this.field().nativeElement.value = '';
  }

  /** Stops a pending or running search and closes the list (the page submits, its dialog closed). */
  close(): void {
    this.cancel();
    this.answered = null;
    this.state.set('idle');
    this.suggestions.set([]);
    this.active.set(-1);
    this.errorText.set('');
  }

  /** ArrowDown: the next suggestion, else the closed list again, else a search at once. */
  private arrowDown(): void {
    if (this.open()) this.move(1);
    else if (this.canReopen()) this.reopen(0);
    else this.searchNow();
  }

  /** ArrowUp: the previous suggestion, else the closed list again at its last suggestion. */
  private arrowUp(): void {
    if (this.open()) this.move(-1);
    else if (this.canReopen()) this.reopen(this.suggestions().length - 1);
  }

  /** The list is closed with its suggestions kept, so an arrow key opens it again. */
  private canReopen(): boolean {
    return this.suggestions().length > 0 && this.state() === 'idle';
  }

  private reopen(index: number): void {
    this.fit();
    this.state.set('results');
    this.highlight(index);
  }

  private move(step: number): void {
    // From the first, ArrowUp wraps to the last; from the last, ArrowDown wraps to the first.
    this.highlight(wrapIndex(this.active() + step, this.suggestions().length));
  }

  /** Highlights a suggestion and scrolls the list, once rendered, so that it shows. */
  private highlight(index: number): void {
    this.active.set(index);
    afterNextRender(
      () => {
        const option = this.list().nativeElement.children.item(index);
        if (this.active() === index) option?.scrollIntoView?.({ block: 'nearest' });
      },
      { injector: this.injector },
    );
  }

  /**
   * Keeps the list within the room under the field: inside a dialog, down to the dialog's bottom
   * edge (the list then overlays the dialog instead of making it scroll), else down to the
   * window's. At least about three rows, at most about six.
   */
  private fit(): void {
    const input = this.field().nativeElement;
    const dialog = input.closest('dialog');
    const bottom = dialog
      ? dialog.getBoundingClientRect().bottom
      : (input.ownerDocument.defaultView?.innerHeight ?? 0);
    const room = Math.floor(bottom - input.getBoundingClientRect().bottom - LIST_GAP_PX * 2);
    this.listMax.set(`min(15rem, ${Math.max(room, LIST_MIN_PX)}px)`);
  }

  private schedule(value: string): void {
    this.cancel();
    this.answered = null;
    this.suggestions.set([]);
    this.active.set(-1);
    this.errorText.set('');
    const query = value.trim();
    if (query === '') {
      this.state.set('idle');
      return;
    }
    if ([...query].length < this.minLength()) {
      this.state.set('short');
      return;
    }
    this.state.set('loading');
    this.timer = setTimeout(() => void this.search(query), SEARCH_DELAY_MS);
  }

  /**
   * ArrowDown on a closed list: ask at once for the text as it stands, unless that text already
   * has its answer (no match, or a refusal), which pressing again would only ask for again.
   */
  private searchNow(): void {
    const query = this.text().trim();
    if (query === '' || [...query].length < this.minLength() || query === this.answered) return;
    this.cancel();
    this.state.set('loading');
    void this.search(query);
  }

  private async search(query: string): Promise<void> {
    this.timer = undefined;
    const generation = ++this.generation;
    try {
      const found = await this.source()(query);
      if (generation !== this.generation) return;
      const sorted = [...found].sort(byUsername);
      this.answered = query;
      this.suggestions.set(sorted);
      this.active.set(-1);
      // The field lost the focus meanwhile: no list opens under it; ArrowDown opens it later.
      const focused =
        this.field().nativeElement.ownerDocument.activeElement === this.field().nativeElement;
      if (sorted.length === 0) {
        this.state.set('empty');
      } else if (focused) {
        this.fit();
        this.state.set('results');
      } else {
        this.state.set('idle');
      }
    } catch (err) {
      if (generation !== this.generation) return;
      this.answered = query;
      this.suggestions.set([]);
      this.errorText.set(
        err instanceof ApiError && err.code === 'RATE_LIMITED'
          ? $localize`:@@userPicker.rateLimited:Too many searches in a minute. Wait a moment, or type the whole user name.`
          : $localize`:@@userPicker.failed:Suggestions are not available: ${problemMessage(err)}:reason: You can still type the whole user name.`,
      );
      this.state.set('error');
    }
  }

  /** Forgets the pending search and any answer still on its way. */
  private cancel(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.generation++;
  }
}
