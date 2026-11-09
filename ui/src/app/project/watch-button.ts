import {
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import type { RequestBody, ResponseBody } from '../api/types';
import { isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';

export type WatchState = ResponseBody<'/api/v0/projects/{id}/watch', 'get'>;
export type WatchSettings = RequestBody<'/api/v0/projects/{id}/watch', 'put'>;
export type EventKey = keyof WatchSettings['events'];

/** What "Watch" starts with (mail E3 N2, N3): the main branch and every event. */
export const DEFAULT_WATCH: WatchSettings = {
  branches: 'main',
  events: { gateFailed: true, gateRecovered: true, analysisFailed: true, newVulnerabilities: true },
};

/** The settings of a watch the server confirmed; `null` when not watching. */
function settingsOf(state: WatchState | null): WatchSettings | null {
  return state?.watching ? { branches: state.branches, events: { ...state.events } } : null;
}

/**
 * The project's Watch button in the band (mail E3): off, "Watch" starts watching with the defaults
 * and opens the menu; on, "Watching" opens the menu with the scope, the three events and "Stop
 * watching". The menu says why no email would arrive. Escape closes it and gives the focus back; a
 * click elsewhere, scrolling or resizing closes it too. The band clips what overflows it, so the
 * menu is a manual popover in the top layer, placed under the button (as the shell's user menu).
 *
 * Each change builds on the settings the menu shows, and the PUTs go one at a time: a change made
 * while one is on its way is sent after it (only the latest), so quick clicks never undo each
 * other. A refused change puts the menu back to what the server holds. Answers about a project
 * the button no longer shows are dropped (the page reuses the component across projects).
 */
@Component({
  selector: 'q-watch-button',
  imports: [Icon, RouterLink],
  templateUrl: './watch-button.html',
  styleUrl: './watch-button.css',
  host: {
    '(keydown.escape)': 'close()',
    '(document:click)': 'clickOutside($event)',
    '(window:resize)': 'close(false)',
    '(window:scroll)': 'close(false)',
  },
})
export class WatchButton {
  private readonly api = inject(Api);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  readonly projectId = input.required<string>();

  /** The watch as the server last confirmed it; `null` until the first answer. */
  protected readonly state = signal<WatchState | null>(null);
  /** What the menu shows: the settings asked for, saved or on their way. */
  protected readonly settings = signal<WatchSettings | null>(null);
  protected readonly open = signal(false);
  protected readonly loading = signal(false);
  /** A PUT or the DELETE is on its way. */
  protected readonly busy = signal(false);
  protected readonly stopping = signal(false);
  protected readonly error = signal<string | null>(null);
  private readonly button = viewChild.required<ElementRef<HTMLButtonElement>>('button');
  private readonly menu = viewChild<ElementRef<HTMLElement>>('menu');

  /** Bumped when the project changes: answers of an earlier generation are dropped. */
  private generation = 0;
  /** The settings to send once the PUT on its way has answered (the latest change only). */
  private queued: WatchSettings | null = null;
  /** The running sequence of PUTs, if any. */
  private saving: Promise<void> | null = null;

  protected readonly hint = computed(() => {
    switch (this.state()?.emailBlocker) {
      case 'no_address':
        return $localize`:@@watch.hint.noAddress:You have no email address: ask an administrator to add one.`;
      case 'not_configured':
        return $localize`:@@watch.hint.notConfigured:Email isn't set up on this server.`;
      case 'preference_off':
        return $localize`:@@watch.hint.preferenceOff:Notification email is off in your settings.`;
      default:
        return null;
    }
  });

  constructor() {
    effect(() => {
      this.projectId();
      untracked(() => {
        this.generation += 1;
        this.queued = null;
        this.saving = null;
        this.busy.set(false);
        this.stopping.set(false);
        this.open.set(false);
        this.state.set(null);
        this.settings.set(null);
        void this.load();
      });
    });
    // The opened menu goes to the top layer under the button, its right edge on the button's,
    // never taller than the viewport below it (it scrolls instead).
    effect(() => {
      const el = this.menu()?.nativeElement;
      if (!el) return;
      const rect = this.button().nativeElement.getBoundingClientRect();
      const top = Math.round(rect.bottom + 6);
      el.style.top = `${top}px`;
      el.style.right = `${Math.max(0, Math.round(document.documentElement.clientWidth - rect.right))}px`;
      el.style.maxHeight = `calc(100dvh - ${top}px - var(--gutter))`;
      // jsdom has no Popover API (the shell's closeMenu does the same check).
      const popover = el as Partial<Pick<HTMLElement, 'showPopover'>>;
      if (popover.showPopover && !el.matches(':popover-open')) popover.showPopover.call(el);
    });
  }

  private async load(): Promise<void> {
    const generation = this.generation;
    const id = this.projectId();
    this.loading.set(true);
    this.error.set(null);
    try {
      const state = await ok(
        this.api.client.GET('/api/v0/projects/{id}/watch', { params: { path: { id } } }),
      );
      if (generation === this.generation) this.confirm(state);
    } catch (err) {
      if (generation === this.generation) this.error.set(problemMessage(err));
    } finally {
      if (generation === this.generation) this.loading.set(false);
    }
  }

  private confirm(state: WatchState): void {
    this.state.set(state);
    this.settings.set(settingsOf(state));
  }

  protected async toggle(): Promise<void> {
    if (this.open()) {
      this.close();
      return;
    }
    if (this.busy() || this.loading()) return;
    const generation = this.generation;
    // A first answer that failed: ask again (the menu then shows the error if it fails again).
    if (this.state() === null) await this.load();
    if (generation !== this.generation) return;
    if (this.state()?.watching === false) await this.edit(DEFAULT_WATCH);
    if (generation === this.generation) this.open.set(true);
  }

  /** Closes the menu; `refocus` gives the focus back to the button (not after a click elsewhere). */
  protected close(refocus = true): void {
    if (!this.open()) return;
    this.open.set(false);
    if (refocus) this.button().nativeElement.focus();
  }

  protected clickOutside(event: Event): void {
    if (event.target instanceof Node && !this.host.nativeElement.contains(event.target)) {
      this.close(false);
    }
  }

  protected setBranches(branches: WatchSettings['branches']): void {
    const current = this.settings();
    if (current) void this.edit({ ...current, branches });
  }

  protected setEvent(key: EventKey, event: Event): void {
    const current = this.settings();
    if (!current) return;
    const events = { ...current.events };
    events[key] = isChecked(event);
    void this.edit({ ...current, events });
  }

  /** Shows `next` at once and saves it, after the PUT on its way if there is one. */
  private edit(next: WatchSettings): Promise<void> {
    this.settings.set(next);
    this.queued = next;
    this.saving ??= this.drain(this.generation);
    return this.saving;
  }

  private async drain(generation: number): Promise<void> {
    const id = this.projectId();
    this.busy.set(true);
    try {
      while (this.queued !== null) {
        const body = this.queued;
        this.queued = null;
        this.error.set(null);
        try {
          const state = await ok(
            this.api.client.PUT('/api/v0/projects/{id}/watch', {
              params: { path: { id } },
              body,
            }),
          );
          if (generation !== this.generation) return;
          this.state.set(state);
          // A newer change is still to be sent: keep showing it.
          if (this.queued === null) this.settings.set(settingsOf(state));
        } catch (err) {
          if (generation !== this.generation) return;
          this.error.set(problemMessage(err));
          // On purpose: a change queued behind the refused one is dropped too. It was made on top
          // of settings the server never took, so the menu goes back to the last saved state.
          this.queued = null;
          this.settings.set(settingsOf(this.state()));
          this.restoreInputs();
        }
      }
    } finally {
      if (generation === this.generation) {
        this.saving = null;
        this.busy.set(false);
      }
    }
  }

  /**
   * Puts the boxes back to the settings shown: a `[checked]` binding whose value did not change
   * leaves the box the user clicked as it is.
   */
  private restoreInputs(): void {
    const menu = this.menu()?.nativeElement;
    const s = this.settings();
    if (!menu || !s) return;
    for (const box of menu.querySelectorAll<HTMLInputElement>('input')) {
      box.checked =
        box.type === 'radio' ? box.value === s.branches : s.events[box.value as EventKey] === true;
    }
  }

  protected async stop(): Promise<void> {
    if (this.busy() || !this.state()?.watching) return;
    const generation = this.generation;
    const id = this.projectId();
    this.busy.set(true);
    this.stopping.set(true);
    this.error.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}/watch', { params: { path: { id } } }),
      );
      if (generation !== this.generation) return;
      const state = this.state();
      this.confirm({
        watching: false,
        emailReady: state?.emailReady ?? false,
        emailBlocker: state?.emailBlocker ?? null,
        vulnerabilityAlerts: state?.vulnerabilityAlerts ?? false,
      });
      this.close();
    } catch (err) {
      if (generation === this.generation) this.error.set(problemMessage(err));
    } finally {
      if (generation === this.generation) {
        this.busy.set(false);
        this.stopping.set(false);
      }
    }
  }
}
