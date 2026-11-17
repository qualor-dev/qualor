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
import type { JiraProjectSettings } from '../api/types';
import { CurrentProject } from '../project/current-project';

/** What a finding needs to know of its project's Jira (spec §6.9). */
export interface JiraProjectView {
  /** The organisation has a Jira connection: without one a finding shows nothing of Jira. */
  connected: boolean;
  /** The project is mapped to a Jira project: Jira issues can be created. */
  mapped: boolean;
  /** The caller may map it (`project.settings`): "Map this project to Jira" leads there. */
  canMap: boolean;
}

interface Entry {
  answer: WritableSignal<JiraProjectSettings | null>;
  view: Signal<JiraProjectView | null>;
}

/**
 * The Jira state of projects, `GET /projects/{id}/jira` read once per project: every finding of a
 * list shares the one read. The pages that show findings provide their own instance, so a visit
 * reads it fresh (a mapping saved in the settings meanwhile shows); a view is null until the read
 * answered, and stays so when it failed.
 */
@Injectable({ providedIn: 'root' })
export class JiraProjectState {
  private readonly api = inject(Api);
  private readonly project = inject(CurrentProject);
  private readonly entries = new Map<string, Entry>();

  of(projectId: string): Signal<JiraProjectView | null> {
    return this.entry(projectId).view;
  }

  /** Reads it again: a create was refused because the connection or the mapping went. */
  reload(projectId: string): void {
    void this.load(projectId, this.entry(projectId).answer);
  }

  private entry(projectId: string): Entry {
    const known = this.entries.get(projectId);
    if (known) return known;
    const answer = signal<JiraProjectSettings | null>(null);
    const view = computed<JiraProjectView | null>(() => {
      const settings = answer();
      if (settings === null) return null;
      return {
        connected: settings.connection !== null,
        mapped: settings.connection !== null && settings.mapping !== null,
        canMap: this.project.canChange(projectId, 'project.settings'),
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
          this.api.client.GET('/api/v0/projects/{id}/jira', {
            params: { path: { id: projectId } },
          }),
        ),
      );
    } catch {
      // Unreadable: the finding shows its link, if any, and offers nothing new.
    }
  }
}
