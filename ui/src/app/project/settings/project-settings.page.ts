import {
  afterRenderEffect,
  Component,
  computed,
  DOCUMENT,
  effect,
  ElementRef,
  inject,
  input,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { can } from '../../auth/permissions';
import { SessionStore } from '../../auth/session';
import { CurrentProject } from '../current-project';
import { ProjectAiPanel } from './ai-panel';
import { GateProfilesPanel } from './gate-profiles-panel';
import { MainBranchPanel } from './main-branch-panel';
import { NewCodePanel } from './new-code-panel';
import { DeleteProjectPanel } from './delete-project-panel';
import { ProjectTokensPanel } from './project-tokens-panel';
import { ProjectWebhooksPanel } from './project-webhooks-panel';
import { VulnerabilityPanel } from './vulnerability-panel';

/**
 * The panels that took over an earlier panel's address: an old link or bookmark still leads to the
 * panel that holds its setting now.
 */
const MOVED: ReadonlyMap<string, string> = new Map([
  ['ai-review', 'ai'],
  ['auto-fix', 'ai'],
]);

/**
 * Project → Settings: one panel per setting, each shown for its own permission (spec §3). The
 * panels are components of this folder; they emit `saved` when the project changed, and the page
 * reads the project again.
 */
@Component({
  selector: 'q-project-settings-page',
  imports: [
    DeleteProjectPanel,
    GateProfilesPanel,
    MainBranchPanel,
    NewCodePanel,
    ProjectAiPanel,
    ProjectTokensPanel,
    ProjectWebhooksPanel,
    RouterLink,
    VulnerabilityPanel,
  ],
  templateUrl: './project-settings.page.html',
  styleUrl: './project-settings.page.css',
})
export class ProjectSettingsPage {
  protected readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  private readonly router = inject(Router);
  private readonly document = inject(DOCUMENT);
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

  /**
   * An index link's plain click: its `routerLink` puts the panel in the address, and this scrolls
   * to it and focuses its heading. A click that opens the link elsewhere (the middle button, Ctrl,
   * ⌘ or Shift) is the browser's, and leaves this page as it is.
   */
  protected go(id: string, event: MouseEvent): void {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }
    this.scrolledToFragment = true;
    this.reveal(id);
  }

  /**
   * Scrolls to the panel `id` names (or the one that took its setting over) and focuses its
   * heading; false while it is not there.
   */
  private reveal(id: string): boolean {
    // By id, not by a selector: the address may hold any text.
    const section = this.document.getElementById(MOVED.get(id) ?? id);
    if (section?.tagName !== 'SECTION' || !this.host.nativeElement.contains(section)) return false;
    section.scrollIntoView();
    section.querySelector<HTMLElement>('h2')?.focus({ preventScroll: true });
    return true;
  }
}
