import { Component, computed, inject, viewChild } from '@angular/core';
import { OrgContext } from '../org/org-context';
import { WebhookList } from './webhook-list';

export { excerptText, type Webhook } from './webhook-list';

/**
 * Settings → Webhooks: the organisation's webhooks, for org admins (api.md §3 Webhooks). The page
 * holds the heading and the intro; the list, its dialogs and the secret shown once are
 * `WebhookList`.
 */
@Component({
  selector: 'q-webhooks-page',
  imports: [WebhookList],
  templateUrl: './webhooks.page.html',
})
export class WebhooksPage {
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.webhooks.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.webhooks.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.webhooks.manage'));
  private readonly list = viewChild(WebhookList);
  /** The secret the list shows, for the page's tests; null while there is none. */
  protected readonly secret = (): string | null => this.list()?.secret() ?? null;
}
