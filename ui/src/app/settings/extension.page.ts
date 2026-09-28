import { Component, computed, inject, input } from '@angular/core';
import { problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { SystemInfo } from '../shell/system-info';

/**
 * `/settings/ee/:id`: the page behind a plugin's settings entry (enterprise.md §10.4) that the UI
 * has no screen for. The ids it knows (`audit-log`, `audit-settings`, rbac-audit.md §17) have
 * their own routes before this one (`settings.routes.ts`) and never reach it; any other entry is
 * named here with the note that its screen is not in this web UI. An id no active feature
 * registered is "Not found". The
 * entries are listed for instance admins only; anyone else who opens the address is told so, and a
 * failed `GET /system/info` is shown instead of an empty page.
 */
@Component({
  selector: 'q-extension-page',
  templateUrl: './extension.page.html',
})
export class ExtensionPage {
  private readonly info = inject(SystemInfo);
  private readonly session = inject(SessionStore);
  readonly id = input.required<string>();
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly loaded = computed(() => this.info.info() !== null);
  protected readonly loadError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly extension = computed(
    () => this.info.extensions().find((e) => e.id === this.id()) ?? null,
  );
}
