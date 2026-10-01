import { Component, computed, effect, inject, input } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { can } from '../../auth/permissions';
import { SessionStore } from '../../auth/session';
import { CurrentProject } from '../current-project';

/** The project permissions that open the Settings tab (the organisation's webhooks one besides). */
export const SETTINGS_PERMISSIONS = [
  'project.settings',
  'project.tokens.manage',
  'project.delete',
] as const;

/** Whether the Settings tab has anything for a caller (project permissions, org webhooks). */
export function settingsVisible(
  projectPermissions: readonly string[],
  orgWebhooks: boolean,
): boolean {
  return orgWebhooks || SETTINGS_PERMISSIONS.some((p) => can(projectPermissions, p));
}

/**
 * Project → Settings: one panel per setting, each shown for its own permission (spec §3). The
 * panels are components of this folder; they emit `saved` when the project changed, and the page
 * reads the project again.
 */
@Component({
  selector: 'q-project-settings-page',
  imports: [RouterLink],
  templateUrl: './project-settings.page.html',
  styleUrl: './project-settings.page.css',
})
export class ProjectSettingsPage {
  private readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  private readonly router = inject(Router);
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

  constructor() {
    effect(() => this.store.use(this.projectId()));
    effect(() => {
      const show = this.show();
      if (show && !Object.values(show).some(Boolean)) {
        void this.router.navigate(['/projects', this.projectId()], { replaceUrl: true });
      }
    });
  }
}
