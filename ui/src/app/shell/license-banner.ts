import { Component, computed, inject, resource } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { SessionStore } from '../auth/session';
import type { LicenseStatus } from '../settings/license-text';
import { DateTimePipe } from '../shared/date-time.pipe';

type Notice = 'expiresSoon' | 'grace' | 'expired';

/** What the banner has to say about a status, or null when there is nothing to say. */
export function licenseNotice(status: LicenseStatus | null): Notice | null {
  if (status === null) return null;
  if (status.state === 'grace') return 'grace';
  if (status.state === 'active' && status.expiresSoon) return 'expiresSoon';
  if (status.state === 'expired') return 'expired';
  return null;
}

/**
 * A bar under the header for instance admins (enterprise.md §11): the licence expires within 30
 * days, is in its grace period, or has expired and the enterprise features are off. It links to
 * the licence page. Other users see nothing and the licence is not even asked for; a failed load
 * shows nothing either. The bar is a `status` region only while it has something to say, so a
 * page's own status region stays the only one on the page otherwise.
 */
@Component({
  selector: 'q-license-banner',
  imports: [RouterLink, DateTimePipe],
  templateUrl: './license-banner.html',
})
export class LicenseBanner {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);

  private readonly licence = resource({
    params: () => {
      const user = this.session.user();
      return user?.isInstanceAdmin ? user.id : undefined;
    },
    loader: () => ok(this.api.client.GET('/api/v0/license')),
  });

  protected readonly status = computed(() =>
    this.licence.hasValue() ? this.licence.value() : null,
  );
  protected readonly notice = computed(() => licenseNotice(this.status()));
}
