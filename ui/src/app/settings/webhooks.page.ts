import {
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../api/api';
import type { ItemOf } from '../api/types';
import { KeysetList } from '../shared/keyset';
import { OrgContext } from '../org/org-context';
import { Icon } from '../shared/icon';
import { WebhookList } from './webhook-list';

export { excerptText, type Webhook } from './webhook-list';

/**
 * Settings → Webhooks: the organisation's webhooks, for org admins (api.md §3 Webhooks). The page
 * holds the heading and the intro; the list, its dialogs and the secret shown once are
 * `WebhookList`.
 */
@Component({
  selector: 'q-webhooks-page',
  imports: [Icon, WebhookList],
  templateUrl: './webhooks.page.html',
})
export class WebhooksPage {
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.webhooks.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.webhooks.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.webhooks.manage'));
  private readonly api = inject(Api);
  /** The organisation's projects (every page), for the scope tags and the scope select. */
  private readonly projectList = new KeysetList<ItemOf<'/api/v0/projects'>, string>(
    (organizationId, cursor) =>
      ok(
        this.api.client.GET('/api/v0/projects', {
          params: { query: { organizationId, limit: 100, ...(cursor ? { cursor } : {}) } },
        }),
      ),
  );
  protected readonly projects = computed(() =>
    this.projectList.items().map(({ id, name }) => ({ id, name })),
  );
  private readonly projectsDone = signal(false);
  private projectsToken = 0;
  protected readonly projectsError = this.projectList.error;
  protected readonly projectsState = computed<'loading' | 'ready' | 'failed'>(() =>
    this.projectList.error() !== null ? 'failed' : this.projectsDone() ? 'ready' : 'loading',
  );
  private readonly list = viewChild(WebhookList);
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');
  protected readonly headingFocus = (): HTMLElement | null => this.heading()?.nativeElement ?? null;

  protected openCreate(): void {
    this.list()?.openCreate();
  }

  constructor() {
    inject(DestroyRef).onDestroy(() => this.projectsToken++);
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        this.projectsToken++;
        this.projectsDone.set(false);
        this.projectList.clear();
        if (organizationId && admin) void this.loadProjects(organizationId);
      });
    });
  }

  private async loadProjects(organizationId: string): Promise<void> {
    const token = ++this.projectsToken;
    await this.projectList.reset(organizationId);
    await this.projectList.loadRest(() => token === this.projectsToken);
    if (token === this.projectsToken) this.projectsDone.set(true);
  }

  /** The secret the list shows, for the page's tests; null while there is none. */
  protected readonly secret = (): string | null => this.list()?.secret() ?? null;
}
