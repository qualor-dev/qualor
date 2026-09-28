import { Component, effect, inject, input, linkedSignal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { DateTimePipe } from '../shared/date-time.pipe';
import { inputValue } from '../shared/forms';
import { GateBadge } from '../shared/gate-badge';
import { KeysetList } from '../shared/keyset';
import { safeHelpUri } from '../shared/links';
import { MeasurePipe } from '../shared/measure.pipe';
import { type Branch, branchTitle } from './branches';

type Kind = 'branch' | 'merge_request' | '';
const PAGE_SIZE = 50;

/** A project's branches and merge requests with their gate and new-code measures. */
@Component({
  selector: 'q-branches-page',
  imports: [DateTimePipe, GateBadge, MeasurePipe, RouterLink],
  templateUrl: './branches.page.html',
})
export class BranchesPage {
  private readonly api = inject(Api);
  readonly projectId = input.required<string>();

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
   * scm.md §8: the merge request in GitLab, only as an http(s) link (plan 1F ruling Y5). The server
   * stores it only when it is on the connection's base URL; members cannot read connections, so
   * that check stays on the server.
   */
  protected readonly gitlabLink = (branch: Branch) => safeHelpUri(branch.mrUrl);
  /** Each link names its merge request, starting with the words it shows (WCAG label in name). */
  protected readonly gitlabLinkLabel = (branch: Branch) =>
    $localize`:@@branches.openInGitLabLabel:Open in GitLab: ${branch.mrTitle || branchTitle(branch)}:mergeRequest:`;

  constructor() {
    effect(() => {
      const params = { projectId: this.projectId(), kind: this.kind() };
      untracked(() => void this.list.reset(params));
    });
  }

  protected setKind(event: Event): void {
    const value = inputValue(event);
    this.kind.set(value === 'branch' || value === 'merge_request' ? value : '');
  }
}
