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
import type { BoardsProjectSettings } from '../api/types';

/** What a finding needs to know of its project's Azure Boards. */
export interface BoardsProjectView {
  /** The project is mapped to an Azure DevOps project: work items can be created. */
  mapped: boolean;
}

interface Entry {
  answer: WritableSignal<BoardsProjectSettings | null>;
  view: Signal<BoardsProjectView | null>;
}

/**
 * The Azure Boards state of projects, `GET /projects/{id}/boards` read once per project: every
 * finding of a list shares the one read. The pages that show findings provide their own instance,
 * so a visit reads it fresh (a mapping saved in the settings meanwhile shows); a view is null until
 * the read answered, and stays so when it failed.
 */
@Injectable({ providedIn: 'root' })
export class BoardsProjectState {
  private readonly api = inject(Api);
  private readonly entries = new Map<string, Entry>();

  of(projectId: string): Signal<BoardsProjectView | null> {
    return this.entry(projectId).view;
  }

  /** Reads it again: a request was refused because the connection or the mapping went. */
  reload(projectId: string): void {
    void this.load(projectId, this.entry(projectId).answer);
  }

  private entry(projectId: string): Entry {
    const known = this.entries.get(projectId);
    if (known) return known;
    const answer = signal<BoardsProjectSettings | null>(null);
    const view = computed<BoardsProjectView | null>(() => {
      const settings = answer();
      return settings === null ? null : { mapped: settings.mapping !== null };
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
          this.api.client.GET('/api/v0/projects/{id}/boards', {
            params: { path: { id: projectId } },
          }),
        ),
      );
    } catch {
      // Unreadable: the finding shows its link, if any, and Jira as before otherwise.
    }
  }
}

/**
 * One tracker per finding (Ruling 9): a finding shows its Azure Boards link, or the way to create
 * one, when it has a Boards link or its project is mapped to Boards; a finding with a Jira link
 * shows Jira only. Otherwise it shows Jira as before.
 */
export function showsBoards(
  finding: { jira: object | null; boards: object | null },
  project: BoardsProjectView | null,
): boolean {
  return finding.jira === null && (finding.boards !== null || project?.mapped === true);
}
