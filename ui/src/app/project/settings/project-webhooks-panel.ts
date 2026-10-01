import { Component, computed, type ElementRef, inject, input, viewChild } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SessionStore } from '../../auth/session';
import { Icon } from '../../shared/icon';
import { WebhookList } from '../../settings/webhook-list';
import type { ProjectDto } from '../current-project';

/**
 * Project → Settings → Webhooks (spec §3.5): the shared `WebhookList` in project scope, for
 * callers who manage the organisation's webhooks (the page decides when the panel is shown).
 * "New webhook" lives in the panel head and opens the list's create dialog.
 */
@Component({
  selector: 'q-project-webhooks-panel',
  imports: [Icon, RouterLink, WebhookList],
  templateUrl: './project-webhooks-panel.html',
  styleUrl: './project-webhooks-panel.css',
})
export class ProjectWebhooksPanel {
  private readonly session = inject(SessionStore);
  readonly project = input.required<ProjectDto>();
  protected readonly canManage = computed(() =>
    this.session.orgCan(this.project().organizationId, 'org.webhooks.manage'),
  );
  private readonly list = viewChild(WebhookList);
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');
  protected readonly headingFocus = (): HTMLElement | null => this.heading()?.nativeElement ?? null;

  protected openCreate(): void {
    this.list()?.openCreate();
  }
}
