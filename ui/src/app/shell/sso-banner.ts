import { Component, computed, inject, resource } from '@angular/core';
import { ok } from '../api/api';
import { EeApi } from '../api/ee';
import { SessionStore } from '../auth/session';
import { SystemInfo } from './system-info';

/**
 * A bar under the header for instance admins while `sso` is active (sso-scim.md §10.4): the
 * server runs with `QUALOR_FORCE_PASSWORD_SIGN_IN=true`, so everyone with a password may sign in
 * with it whatever the stored policy. `GET /ee/sso/settings` is asked once per signed-in admin;
 * other users, a community server and a failed load show nothing. Like the licence banner, it is
 * a `status` region only while it has something to say.
 */
@Component({
  selector: 'q-sso-banner',
  templateUrl: './sso-banner.html',
})
export class SsoBanner {
  private readonly ee = inject(EeApi);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);

  private readonly settings = resource({
    params: () => {
      const user = this.session.user();
      return user?.isInstanceAdmin && this.info.features().includes('sso') ? user.id : undefined;
    },
    loader: () => ok(this.ee.client.GET('/api/v0/ee/sso/settings')),
  });

  protected readonly forced = computed(
    () => this.settings.hasValue() && this.settings.value().forced,
  );
}
