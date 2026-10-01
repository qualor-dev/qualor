import {
  afterRenderEffect,
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  input,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { can } from '../../auth/permissions';
import { SessionStore } from '../../auth/session';
import { CurrentProject } from '../current-project';
import { GateProfilesPanel } from './gate-profiles-panel';
import { NewCodePanel } from './new-code-panel';

/**
 * Project → Settings: one panel per setting, each shown for its own permission (spec §3). The
 * panels are components of this folder; they emit `saved` when the project changed, and the page
 * reads the project again.
 */
@Component({
  selector: 'q-project-settings-page',
  imports: [GateProfilesPanel, NewCodePanel],
  templateUrl: './project-settings.page.html',
  styleUrl: './project-settings.page.css',
})
export class ProjectSettingsPage {
  protected readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  private readonly router = inject(Router);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly fragment = toSignal(inject(ActivatedRoute).fragment, { initialValue: null });
  private scrolledToFragment = false;
  readonly projectId = input.required<string>();

  protected readonly project = this.store.current;
  protected readonly show = computed(() => {
    const p = this.project();
    if (!p) return null;
    return {
      settings: can(p.permissions, 'project.settings'),
      tokens: can(p.permissions, 'project.tokens.manage'),
      delete: can(p.permissions, 'project.delete'),
      webhooks: this.session.orgCan(p.organizationId, 'org.webhooks.manage'),
    };
  });

  /** `project.analyze`: the new-code panel reads the baseline only for those who may analyse. */
  protected readonly canAnalyze = computed(() => {
    const p = this.project();
    return p !== null && can(p.permissions, 'project.analyze');
  });

  constructor() {
    effect(() => this.store.use(this.projectId()));
    effect(() => {
      const show = this.show();
      if (show && !Object.values(show).some(Boolean)) {
        void this.router.navigate(['/projects', this.projectId()], { replaceUrl: true });
      }
    });
    // A URL that already names a panel: scroll to it once the panels have rendered.
    afterRenderEffect(() => {
      const fragment = this.fragment();
      if (this.scrolledToFragment || fragment === null || this.show() === null) return;
      if (this.reveal(fragment)) this.scrolledToFragment = true;
    });
  }

  /** An index link: keeps the fragment in the URL, scrolls to the panel and focuses its heading. */
  protected go(id: string, event: Event): void {
    event.preventDefault();
    void this.router.navigate([], { fragment: id, replaceUrl: true });
    this.reveal(id);
  }

  private reveal(id: string): boolean {
    const section = this.host.nativeElement.querySelector<HTMLElement>(`section.panel[id="${id}"]`);
    if (!section) return false;
    section.scrollIntoView();
    section.querySelector<HTMLElement>('h2')?.focus({ preventScroll: true });
    return true;
  }
}
