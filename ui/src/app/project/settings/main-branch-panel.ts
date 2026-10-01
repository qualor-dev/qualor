import { Component, computed, inject, input, linkedSignal, output, signal } from '@angular/core';
import { Api, ok } from '../../api/api';
import { ApiError, fieldErrors, problemMessage } from '../../api/errors';
import { inputValue } from '../../shared/forms';
import type { ProjectDto } from '../current-project';

const FIELD_PATH = 'body.mainBranchName';

/**
 * Project → Settings → Main branch (spec §3.3): the name of the branch the project measures new
 * code on. A 409 or 422 (a name that is taken or invalid) shows on the field; `saved` tells the
 * page to read the project again, so the header and the Branches tab follow.
 */
@Component({
  selector: 'q-main-branch-panel',
  templateUrl: './main-branch-panel.html',
  styleUrl: './main-branch-panel.css',
})
export class MainBranchPanel {
  private readonly api = inject(Api);
  readonly project = input.required<ProjectDto>();
  readonly saved = output();

  /** The saved name: a primitive, so reading the project again with the same name changes nothing. */
  private readonly mainBranchName = computed(() => this.project().mainBranchName);
  /** The field, started again only when the saved main branch name changes. */
  protected readonly name = linkedSignal(() => this.mainBranchName());
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);

  protected readonly dirty = computed(() => {
    const trimmed = this.name().trim();
    return trimmed !== '' && trimmed !== this.mainBranchName();
  });

  protected setName(event: Event): void {
    this.name.set(inputValue(event));
    this.announcement.set(null);
    this.error.set(null);
    this.nameError.set(null);
  }

  protected async save(): Promise<void> {
    if (this.busy() || !this.dirty()) return;
    const mainBranchName = this.name().trim();
    this.busy.set(true);
    this.error.set(null);
    this.nameError.set(null);
    this.announcement.set(null);
    try {
      await ok(
        this.api.client.PATCH('/api/v0/projects/{id}', {
          params: { path: { id: this.project().id } },
          body: { mainBranchName },
        }),
      );
      this.announcement.set(
        $localize`:@@mainBranch.saved:Main branch is now ${mainBranchName}:name:.`,
      );
      this.saved.emit();
    } catch (err) {
      const message = fieldErrors(err)[FIELD_PATH];
      if (message !== undefined) {
        this.nameError.set(message);
      } else if (err instanceof ApiError && (err.status === 409 || err.status === 422)) {
        this.nameError.set(problemMessage(err));
      } else {
        this.error.set(problemMessage(err));
      }
    } finally {
      this.busy.set(false);
    }
  }
}
