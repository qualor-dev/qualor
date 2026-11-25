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
  /** The read answered or failed: until then no finding offers a tracker's action. */
  settled: boolean;
  /** The project is mapped to an Azure DevOps project: work items can be created. */
  mapped: boolean;
  /** The read failed: findings without a Boards link fall back to Jira. */
  unreadable: boolean;
}

interface Entry {
  projectId: string;
  answer: WritableSignal<BoardsProjectSettings | null>;
  failed: WritableSignal<boolean>;
  view: Signal<BoardsProjectView>;
}

/**
 * The Azure Boards state of projects, `GET /projects/{id}/boards` read once per project: every
 * finding of a list shares the one read. The pages that show findings provide their own instance,
 * so a visit reads it fresh (a mapping saved in the settings meanwhile shows). A view is unsettled
 * until the read answered or failed; a failed read is `unreadable` unless an earlier one answered.
 */
@Injectable({ providedIn: 'root' })
export class BoardsProjectState {
  private readonly api = inject(Api);
  private readonly entries = new Map<string, Entry>();

  of(projectId: string): Signal<BoardsProjectView> {
    return this.entry(projectId).view;
  }

  /** Reads it again: a request was refused because the connection or the mapping went. */
  reload(projectId: string): void {
    void this.load(this.entry(projectId));
  }

  private entry(projectId: string): Entry {
    const known = this.entries.get(projectId);
    if (known) return known;
    const answer = signal<BoardsProjectSettings | null>(null);
    const failed = signal(false);
    const view = computed<BoardsProjectView>(() => {
      const settings = answer();
      if (settings !== null) {
        return { settled: true, mapped: settings.mapping !== null, unreadable: false };
      }
      return { settled: failed(), mapped: false, unreadable: failed() };
    });
    const entry: Entry = { projectId, answer, failed, view };
    this.entries.set(projectId, entry);
    // Asked from a template or a computed: the request starts outside the reactive context.
    untracked(() => void Promise.resolve().then(() => this.load(entry)));
    return entry;
  }

  private async load(entry: Entry): Promise<void> {
    try {
      entry.answer.set(
        await ok(
          this.api.client.GET('/api/v0/projects/{id}/boards', {
            params: { path: { id: entry.projectId } },
          }),
        ),
      );
      entry.failed.set(false);
    } catch {
      // Unreadable: a finding shows its Boards link, if any, and Jira as before otherwise.
      entry.failed.set(true);
    }
  }
}

/**
 * Which tracker a finding shows, one per finding (Ruling 9):
 * - its Jira link, when it has one;
 * - its Azure Boards link, or Boards when the project is mapped to Boards;
 * - Jira as before once the Boards state is known not to be mapped, or could not be read;
 * - neither while the Boards state is still unread, so no Jira action flashes on a Boards project.
 */
export function findingTracker(
  finding: { jira: object | null; boards: object | null },
  project: BoardsProjectView,
): 'jira' | 'boards' | null {
  if (finding.jira !== null) return 'jira';
  if (finding.boards !== null || project.mapped) return 'boards';
  return project.settled ? 'jira' : null;
}
