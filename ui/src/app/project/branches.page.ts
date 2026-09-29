import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  input,
  linkedSignal,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openModal } from '../shared/dialog';
import { GateBadge } from '../shared/gate-badge';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { MeasurePipe } from '../shared/measure.pipe';
import { type Branch, branchTitle, mergeRequestLink } from './branches';
import { CurrentProject } from './current-project';

type Kind = 'branch' | 'merge_request' | '';
const PAGE_SIZE = 50;

/**
 * A project's branches and merge requests with their gate and new-code measures (spec §7.3): a
 * segmented filter by kind, the table in a panel, and, for those who may (`project.branches.delete`),
 * deleting a branch or merge request other than the main one after a confirmation. The server
 * deletes its analyses and issues with it (a cascade); after it, focus moves to the result, since
 * the row and its button are gone.
 */
@Component({
  selector: 'q-branches-page',
  imports: [DateTimePipe, GateBadge, Icon, MeasurePipe, RouterLink],
  templateUrl: './branches.page.html',
  styleUrl: './branches.page.css',
})
export class BranchesPage {
  private readonly api = inject(Api);
  private readonly project = inject(CurrentProject);
  readonly projectId = input.required<string>();

  /** rbac-audit.md §17: the action shows once the project says the caller may use it. */
  protected readonly canDelete = computed(() =>
    this.project.canChange(this.projectId(), 'project.branches.delete'),
  );
  /** The branch the confirmation is about; null while the dialog is closed. */
  protected readonly toDelete = signal<Branch | null>(null);
  protected readonly deleting = signal(false);
  protected readonly deleteError = signal<string | null>(null);
  /** The last deletion's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  protected readonly deleteTitle = computed(() =>
    this.toDelete()?.kind === 'merge_request'
      ? $localize`:@@branches.delete.titleMr:Delete this merge request?`
      : $localize`:@@branches.delete.title:Delete this branch?`,
  );
  private readonly deleteDialog = viewChild<ElementRef<HTMLDialogElement>>('deleteDialog');
  private readonly status = viewChild<ElementRef<HTMLElement>>('status');

  /** The kind filter; back to every kind when the route reuses the page for another project. */
  protected readonly kind = linkedSignal<string, Kind>({
    source: () => this.projectId(),
    computation: () => '',
  });
  /** The new-code measures the table shows, in column order. */
  protected readonly columns = ['new_issues', 'new_coverage'];
  protected readonly list = new KeysetList<Branch, { projectId: string; kind: Kind }>(
    (params, cursor) =>
      ok(
        this.api.client.GET('/api/v0/projects/{id}/branches', {
          params: {
            path: { id: params.projectId },
            query: {
              limit: PAGE_SIZE,
              ...(params.kind ? { kind: params.kind } : {}),
              ...(cursor ? { cursor } : {}),
            },
          },
        }),
      ),
  );
  protected readonly branchTitle = branchTitle;
  /**
   * scm.md §8: the merge request's page, only as an http(s) link. The server stores it only when
   * it is on the connection's base URL; members cannot read connections, so that check stays there.
   */
  protected readonly mrLink = (branch: Branch) =>
    mergeRequestLink(branch.mrUrl, branch.mrTitle || branchTitle(branch));
  /** Each Delete names its branch, starting with the word it shows (WCAG label in name). */
  protected readonly deleteLabel = (branch: Branch) =>
    $localize`:@@branches.deleteLabel:Delete ${branchTitle(branch)}:branch:`;

  constructor() {
    effect(() => this.project.use(this.projectId()));
    effect(() => {
      const params = { projectId: this.projectId(), kind: this.kind() };
      untracked(() => void this.list.reset(params));
    });
  }

  protected askDelete(branch: Branch): void {
    this.toDelete.set(branch);
    this.deleteError.set(null);
    const dialog = this.deleteDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  protected closeDelete(): void {
    const dialog = this.deleteDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected async confirmDelete(): Promise<void> {
    const branch = this.toDelete();
    if (!branch || this.deleting()) return;
    this.deleting.set(true);
    this.deleteError.set(null);
    try {
      await ok(
        this.api.client.DELETE('/api/v0/branches/{id}', { params: { path: { id: branch.id } } }),
      );
      this.closeDelete();
      this.toDelete.set(null);
      this.announcement.set($localize`:@@branches.deleted:Deleted ${branchTitle(branch)}:branch:.`);
      await this.list.reload();
      this.status()?.nativeElement.focus();
    } catch (err) {
      this.deleteError.set(problemMessage(err));
    } finally {
      this.deleting.set(false);
    }
  }

  /** The filter's choices, in the segmented control's order. */
  protected readonly kinds: { id: Kind; label: string }[] = [
    { id: '', label: $localize`:@@branches.kind.every:All` },
    { id: 'branch', label: $localize`:@@branches.kind.branch:Branches` },
    { id: 'merge_request', label: $localize`:@@branches.kind.mr:Merge requests` },
  ];
}
