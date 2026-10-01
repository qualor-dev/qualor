import {
  Component,
  computed,
  type ElementRef,
  inject,
  Injector,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import { Api, done } from '../../api/api';
import { problemMessage } from '../../api/errors';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { inputValue } from '../../shared/forms';
import { CurrentProject, type ProjectDto } from '../current-project';

/**
 * Project → Settings → Danger zone (spec §3.6): "Delete project" opens a dialog that says what
 * goes and asks for the project key; the danger button works only when the typed key equals the
 * project's key exactly (no trimming, case-sensitive). `DELETE /projects/{id}?confirm=<key>`;
 * on 204 the project is forgotten (so nothing asks for it again) and Projects opens with a notice.
 * What the server refuses (409, 422) shows in the dialog, which stays open.
 */
@Component({
  selector: 'q-delete-project-panel',
  templateUrl: './delete-project-panel.html',
  styleUrl: './delete-project-panel.css',
})
export class DeleteProjectPanel {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly router = inject(Router);
  private readonly store = inject(CurrentProject);
  readonly project = input.required<ProjectDto>();

  protected readonly typed = signal('');
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly matches = computed(() => this.typed() === this.project().key);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');

  protected setTyped(event: Event): void {
    this.typed.set(inputValue(event));
  }

  protected open(): void {
    this.typed.set('');
    this.error.set(null);
    openAfterRender(this.injector, () => this.dialog()?.nativeElement);
  }

  protected close(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.typed.set('');
    this.error.set(null);
  }

  protected async confirm(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.matches() || this.busy()) return;
    const { id, key, name } = this.project();
    this.busy.set(true);
    this.error.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}', {
          params: { path: { id }, query: { confirm: key } },
        }),
      );
    } catch (err) {
      this.error.set(problemMessage(err));
      this.busy.set(false);
      return;
    }
    this.busy.set(false);
    // Forgotten first, so the frame never asks for the deleted project again.
    this.store.forget();
    await this.router.navigate(['/projects'], {
      state: { notice: $localize`:@@projectDelete.done:Project ${name}:name: deleted.` },
    });
  }
}
