import {
  computed,
  Injectable,
  inject,
  type Signal,
  signal,
  untracked,
  type WritableSignal,
} from '@angular/core';
import { Api, ok } from '../api/api';
import type { FixSettingsAnswer } from '../api/types';

/** What a finding needs to know of its project's fix MRs (spec §6.9). */
export interface FixProjectView {
  /** The project switched fix MRs on. */
  enabled: boolean;
  /** The connection's provider: it names the request "MR" or "PR". */
  provider: 'gitlab' | 'github' | null;
  /** Requests can be made: on, a mapped repository, an allowing connection, monitoring on. */
  usable: boolean;
  /** The fixes in flight, by state: they count against `maxOpen`. */
  counts: Record<string, number>;
  maxOpen: number;
}

interface Entry {
  answer: WritableSignal<FixSettingsAnswer | null>;
  view: Signal<FixProjectView | null>;
}

/**
 * The fix MR state of projects, `GET /projects/{id}/fixes/settings` read once per project: every
 * finding of a list shares the one read. The pages that show findings provide their own instance,
 * so a visit reads it fresh; a view is null until the read answered, and stays so when it failed.
 */
@Injectable({ providedIn: 'root' })
export class FixProjectState {
  private readonly api = inject(Api);
  private readonly entries = new Map<string, Entry>();

  of(projectId: string): Signal<FixProjectView | null> {
    return this.entry(projectId).view;
  }

  /** Reads it again: a request was refused because the settings or the limit changed. */
  reload(projectId: string): void {
    void this.load(projectId, this.entry(projectId).answer);
  }

  private entry(projectId: string): Entry {
    const known = this.entries.get(projectId);
    if (known) return known;
    const answer = signal<FixSettingsAnswer | null>(null);
    const view = computed<FixProjectView | null>(() => {
      const a = answer();
      if (a === null) return null;
      const p = a.preconditions;
      return {
        enabled: a.settings.enabled,
        provider: p.provider,
        usable: a.settings.enabled && p.scmBound && p.fixMrsAllowed && p.monitoringOn,
        counts: a.counts,
        maxOpen: a.settings.maxOpen,
      };
    });
    const entry = { answer, view };
    this.entries.set(projectId, entry);
    // Asked from a template or a computed: the request starts outside the reactive context.
    untracked(() => void Promise.resolve().then(() => this.load(projectId, answer)));
    return entry;
  }

  private async load(projectId: string, answer: Entry['answer']): Promise<void> {
    try {
      answer.set(
        await ok(
          this.api.client.GET('/api/v0/projects/{id}/fixes/settings', {
            params: { path: { id: projectId } },
          }),
        ),
      );
    } catch {
      // Unreadable: the finding offers nothing new.
    }
  }
}
