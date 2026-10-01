import { Component, computed, inject, input, output, resource } from '@angular/core';
import { Api, ok } from '../../api/api';
import { type Branch, branchTitle } from '../branches';

/** 10 000 branches: past that the list stops rather than walk an endless project. */
const PAGE_SIZE = 500;
const MAX_PAGES = 20;

/**
 * The branch and merge request switcher of the Code tab: a select of the project's branches, the
 * main branch first, then the branches, then the merge requests, each titled as the Branches page
 * titles it. It announces the branch id picked and leaves the navigation to its page.
 */
@Component({
  selector: 'q-branch-picker',
  templateUrl: './branch-picker.html',
  styleUrl: './branch-picker.css',
})
export class BranchPicker {
  private readonly api = inject(Api);
  readonly projectId = input.required<string>();
  readonly branchId = input<string | undefined>(undefined);
  readonly picked = output<string>();

  protected readonly branches = resource({
    params: () => this.projectId(),
    loader: async ({ params }) => {
      const all: Branch[] = [];
      let cursor: string | undefined;
      for (let pages = 0; pages < MAX_PAGES; pages++) {
        const page = await ok(
          this.api.client.GET('/api/v0/projects/{id}/branches', {
            params: {
              path: { id: params },
              query: { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) },
            },
          }),
        );
        all.push(...page.items);
        if (!page.nextCursor || page.nextCursor === cursor) break;
        cursor = page.nextCursor;
      }
      return all;
    },
  });

  protected readonly options = computed(() => {
    const rank = (b: Branch) => (b.isMain ? 0 : b.kind === 'branch' ? 1 : 2);
    return (this.branches.hasValue() ? this.branches.value() : [])
      .map((branch, index) => ({ branch, index }))
      .sort((a, b) => rank(a.branch) - rank(b.branch) || a.index - b.index)
      .map(({ branch }) => ({ id: branch.id, title: branchTitle(branch) }));
  });

  protected pick(event: Event): void {
    const id = (event.target as HTMLSelectElement).value;
    if (id) this.picked.emit(id);
  }
}
