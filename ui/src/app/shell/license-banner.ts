import { Component, computed, inject, resource, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { SessionStore } from '../auth/session';
import { LICENSE_EMAIL, type LicenseStatus } from '../settings/license-text';
import { DateTimePipe } from '../shared/date-time.pipe';

type Notice = 'expiresSoon' | 'grace' | 'expired' | 'trialEndsSoon';

/** The local date (YYYY-MM-DD) on which an admin dismissed the trial banner, per browser. */
export const TRIAL_DISMISS_KEY = 'qualor.trial-banner-dismissed';

const DAY = 86_400_000;

function localToday(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function readDismissed(): string | null {
  try {
    return localStorage.getItem(TRIAL_DISMISS_KEY);
  } catch {
    return null;
  }
}

/** What the banner has to say about a status, or null when there is nothing to say. */
export function licenseNotice(status: LicenseStatus | null): Notice | null {
  if (status === null) return null;
  if (status.license?.trial) {
    return status.state === 'active' && status.expiresSoon ? 'trialEndsSoon' : null;
  }
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
  /** Kept here too, so Dismiss works for this page load even when storage is blocked. */
  private readonly dismissedOn = signal<string | null>(readDismissed());

  protected readonly notice = computed(() => {
    const n = licenseNotice(this.status());
    return n === 'trialEndsSoon' && this.dismissedOn() === localToday() ? null : n;
  });
  protected readonly daysLeft = computed(() => {
    const expires = this.status()?.license?.expires;
    if (!expires) return 1;
    return Math.max(1, Math.ceil((new Date(expires).getTime() - Date.now()) / DAY));
  });
  protected readonly mailto = `mailto:${LICENSE_EMAIL}`;
  protected readonly email = LICENSE_EMAIL;

  protected dismissTrial(): void {
    const today = localToday();
    this.dismissedOn.set(today);
    try {
      localStorage.setItem(TRIAL_DISMISS_KEY, today);
    } catch {
      // Blocked storage: hidden until the next load only.
    }
  }
}
