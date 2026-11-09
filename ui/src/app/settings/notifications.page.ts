import { Component, ElementRef, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { SessionStore } from '../auth/session';
import type { EventKey, WatchSettings } from '../project/watch-button';
import { inputValue, isChecked } from '../shared/forms';

export type Notifications = ResponseBody<'/api/v0/me/notifications', 'get'>;
type Watched = Notifications['watches'][number];
type Preferences = Notifications['preferences'];
type PreferenceKey = keyof Preferences;

function settingsOf(w: Watched): WatchSettings {
  return { branches: w.branches, events: { ...w.events } };
}

/**
 * Settings → Notifications (mail E3): the switch for all notification email (with the address it
 * goes to), the failing-webhook switch for organisation administrators, and every project the
 * person watches with its scope, events and "Stop watching". Each change is saved at once.
 *
 * Every change builds on what the page shows (the settings asked for), and the PUTs go one at a
 * time per watch (and for the two switches together): a change made while one is on its way is
 * sent after it, and only the latest of several is sent. A refused change puts the controls back
 * to what the server holds, boxes and select included, and says so. Answers about a watch that
 * was stopped meanwhile are dropped.
 */
@Component({
  selector: 'q-notifications-page',
  imports: [RouterLink],
  templateUrl: './notifications.page.html',
  styleUrl: './notifications.page.css',
})
export class NotificationsPage {
  private readonly api = inject(Api);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  /** The read-only demo account changes nothing (the server refuses it). */
  protected readonly demo = inject(SessionStore).demo;
  /** What the controls show: the settings asked for, saved or on their way. */
  protected readonly data = signal<Notifications | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  /** Projects whose "Stop watching" is on its way. */
  protected readonly stopping = signal<ReadonlySet<string>>(new Set());

  /** The preferences and watches as the server last confirmed them. */
  private confirmedPreferences: Preferences | null = null;
  private readonly confirmedWatches = new Map<string, WatchSettings>();
  /** Per watch: the settings to send once the PUT on its way has answered (the latest only). */
  private readonly queuedWatches = new Map<string, WatchSettings>();
  private readonly savingWatches = new Map<string, Promise<void>>();
  private queuedPreferences: Partial<Preferences> | null = null;
  private savingPreferences: Promise<void> | null = null;

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    try {
      const data = await ok(this.api.client.GET('/api/v0/me/notifications'));
      this.confirmedPreferences = data.preferences;
      for (const w of data.watches) this.confirmedWatches.set(w.project.id, settingsOf(w));
      this.data.set(data);
    } catch (err) {
      this.error.set(problemMessage(err));
    }
  }

  private update(change: (d: Notifications) => Notifications): void {
    const d = this.data();
    if (d) this.data.set(change(d));
  }

  private shown(projectId: string): Watched | undefined {
    return this.data()?.watches.find((x) => x.project.id === projectId);
  }

  private begin(): void {
    this.error.set(null);
    this.announcement.set(null);
  }

  protected setPreference(key: PreferenceKey, event: Event): Promise<void> {
    const value = isChecked(event);
    this.begin();
    this.update((d) => ({ ...d, preferences: { ...d.preferences, [key]: value } }));
    this.queuedPreferences = { ...this.queuedPreferences, [key]: value };
    this.savingPreferences ??= this.drainPreferences();
    return this.savingPreferences;
  }

  private async drainPreferences(): Promise<void> {
    try {
      while (this.queuedPreferences !== null) {
        const body = this.queuedPreferences;
        this.queuedPreferences = null;
        try {
          const { preferences } = await ok(
            this.api.client.PUT('/api/v0/me/notifications', { body }),
          );
          this.confirmedPreferences = preferences;
          // A newer change is still to be sent: keep showing it.
          if (this.queuedPreferences === null) this.update((d) => ({ ...d, preferences }));
        } catch (err) {
          this.error.set(problemMessage(err));
          this.queuedPreferences = null;
          const confirmed = this.confirmedPreferences;
          if (confirmed) this.update((d) => ({ ...d, preferences: confirmed }));
          this.restorePreferenceBoxes();
        }
      }
    } finally {
      this.savingPreferences = null;
    }
  }

  protected branchesLabel(w: Watched): string {
    return $localize`:@@notifications.branchesOf:Branches of ${w.project.name}:name:`;
  }

  protected gateFailedLabel(w: Watched): string {
    return $localize`:@@notifications.gateFailedOf:Gate fails: ${w.project.name}:name:`;
  }

  protected gateRecoveredLabel(w: Watched): string {
    return $localize`:@@notifications.gateRecoveredOf:Gate passes again: ${w.project.name}:name:`;
  }

  protected analysisFailedLabel(w: Watched): string {
    return $localize`:@@notifications.analysisFailedOf:Analysis fails: ${w.project.name}:name:`;
  }

  protected stopLabel(w: Watched): string {
    return $localize`:@@notifications.stopOf:Stop watching ${w.project.name}:name:`;
  }

  protected setBranches(w: Watched, event: Event): Promise<void> {
    const branches = inputValue(event) === 'all' ? 'all' : 'main';
    return this.edit(w.project.id, (current) => ({ ...current, branches }));
  }

  protected setEvent(w: Watched, key: EventKey, event: Event): Promise<void> {
    const value = isChecked(event);
    return this.edit(w.project.id, (current) => ({
      ...current,
      events: { ...current.events, [key]: value },
    }));
  }

  /** Shows the change on top of the settings shown now and saves it, after the PUT on its way. */
  private edit(
    projectId: string,
    change: (current: WatchSettings) => WatchSettings,
  ): Promise<void> {
    const current = this.shown(projectId);
    if (!current || this.stopping().has(projectId)) return Promise.resolve();
    this.begin();
    const next = change(settingsOf(current));
    this.show(projectId, next);
    this.queuedWatches.set(projectId, next);
    const saving = this.savingWatches.get(projectId) ?? this.drainWatch(projectId);
    this.savingWatches.set(projectId, saving);
    return saving;
  }

  private show(projectId: string, settings: WatchSettings): void {
    this.update((d) => ({
      ...d,
      watches: d.watches.map((x) =>
        x.project.id === projectId
          ? { ...x, branches: settings.branches, events: { ...x.events, ...settings.events } }
          : x,
      ),
    }));
  }

  private async drainWatch(projectId: string): Promise<void> {
    try {
      for (let body = this.queuedWatches.get(projectId); body;) {
        this.queuedWatches.delete(projectId);
        try {
          const saved = await ok(
            this.api.client.PUT('/api/v0/projects/{id}/watch', {
              params: { path: { id: projectId } },
              body,
            }),
          );
          if (!this.shown(projectId)) return;
          if (!saved.watching) {
            // Stopped elsewhere meanwhile: nothing to show any more.
            this.dropRow(projectId);
            return;
          }
          const confirmed = { branches: saved.branches, events: { ...saved.events } };
          this.confirmedWatches.set(projectId, confirmed);
          // A newer change is still to be sent: keep showing it.
          if (!this.queuedWatches.has(projectId)) this.show(projectId, confirmed);
        } catch (err) {
          if (!this.shown(projectId)) return;
          this.error.set(problemMessage(err));
          this.queuedWatches.delete(projectId);
          const confirmed = this.confirmedWatches.get(projectId);
          if (confirmed) this.show(projectId, confirmed);
          this.restoreRowControls(projectId);
        }
        body = this.queuedWatches.get(projectId);
      }
    } finally {
      this.savingWatches.delete(projectId);
    }
  }

  private dropRow(projectId: string): void {
    this.queuedWatches.delete(projectId);
    this.confirmedWatches.delete(projectId);
    this.update((d) => ({ ...d, watches: d.watches.filter((x) => x.project.id !== projectId) }));
  }

  protected async stop(w: Watched): Promise<void> {
    const id = w.project.id;
    if (this.stopping().has(id)) return;
    this.begin();
    this.stopping.update((s) => new Set(s).add(id));
    // Nothing more is saved for a watch that is going; the PUT on its way finishes first.
    this.queuedWatches.delete(id);
    try {
      await this.savingWatches.get(id);
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}/watch', { params: { path: { id } } }),
      );
      this.dropRow(id);
      // A change refused while the stop waited for it no longer matters: the watch is gone.
      this.error.set(null);
      this.announcement.set(
        $localize`:@@notifications.stopped:You no longer watch ${w.project.name}:name:.`,
      );
    } catch (err) {
      this.error.set(problemMessage(err));
    } finally {
      this.stopping.update((s) => {
        const rest = new Set(s);
        rest.delete(id);
        return rest;
      });
    }
  }

  /**
   * Puts the boxes and the select of a row back to the settings shown: a `[checked]` or
   * `[selected]` binding whose value did not change leaves the control the user touched as it is.
   */
  private restoreRowControls(projectId: string): void {
    const current = this.shown(projectId);
    if (!current) return;
    for (const row of this.host.nativeElement.querySelectorAll('tbody tr')) {
      if (row.getAttribute('data-project') !== projectId) continue;
      const select = row.querySelector('select');
      if (select) select.value = current.branches;
      for (const box of row.querySelectorAll<HTMLInputElement>('input[data-event]')) {
        box.checked = current.events[box.dataset['event'] as EventKey] === true;
      }
    }
  }

  private restorePreferenceBoxes(): void {
    const current = this.data()?.preferences;
    if (!current) return;
    for (const box of this.host.nativeElement.querySelectorAll<HTMLInputElement>(
      'input[data-preference]',
    )) {
      box.checked = current[box.dataset['preference'] as PreferenceKey] === true;
    }
  }
}
