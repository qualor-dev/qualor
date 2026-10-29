import type { RenderedMail } from '../payload';
import { html, type SafeHtml } from './html';
import { renderLayout, type LayoutInput } from './layout';
import { adminAlertReason, formatDay, instanceHost, publicLink } from './text';

/** E1 spec: 30, 7 and 1 day before expiry, the grace period, and its end. */
export const LICENSE_ALERT_VARIANTS = ['30d', '7d', '1d', 'grace', 'expired'] as const;
export type LicenseAlertVariant = (typeof LICENSE_ALERT_VARIANTS)[number];

export interface LicenseExpiryInput {
  variant: LicenseAlertVariant;
  /** The licence's `customer`. */
  licensee: string;
  /** "Business" or "Enterprise" (alerts/license-alerts.ts `licensePlan`). */
  plan: string;
  expires: Date;
  graceEndsAt: Date;
  now: Date;
  publicUrl: string | null;
  /** A trial key: no 30-day or grace wording; buying or extending goes through license@qualor.dev. */
  trial: boolean;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const days = (n: number) => (n === 1 ? '1 day' : `${n} days`);
const daysUntil = (to: Date, from: Date) =>
  Math.max(1, Math.ceil((to.getTime() - from.getTime()) / DAY_MS));

/** What stops when the grace period ends, in the words of docs/guide/enterprise.md. */
const WHAT_STOPS =
  'single sign-on stops (people with a password sign in with it), SCIM requests are refused, and the audit log stops recording new events';

interface LicenseWording {
  subject: string;
  intro: SafeHtml;
  title: string;
  badge: NonNullable<LayoutInput['badge']>;
}

const TRIAL_MAIL = html`<a href="mailto:license@qualor.dev">license@qualor.dev</a>`;

/** The words of a trial: it ends at `expires`, with no grace period. */
function trialWording(input: LicenseExpiryInput, expires: string): LicenseWording {
  const buy = html`<p style="margin:0">To buy a licence or extend the trial, write to ${TRIAL_MAIL}.</p>`;
  if (input.variant === 'expired') {
    return {
      subject: `Your Qualor ${input.plan} trial has ended`,
      intro: html`<p style="margin:0">The Qualor ${input.plan} trial of ${input.licensee} ended on ${expires}. Qualor runs as the community edition: ${WHAT_STOPS}. Nothing was deleted.</p>${buy}`,
      title: 'The trial has ended',
      badge: { text: 'Ended', tone: 'bad' },
    };
  }
  return {
    subject: `Your Qualor ${input.plan} trial ends in ${days(daysUntil(input.expires, input.now))}`,
    intro: html`<p style="margin:0">The Qualor ${input.plan} trial of ${input.licensee} ends on ${expires}. After that Qualor runs as the community edition: ${WHAT_STOPS}.</p>${buy}`,
    title: `The trial ends on ${expires}`,
    badge: { text: 'Ends soon', tone: 'warn' },
  };
}

/** The words of each stage: before expiry, in the grace period, and after it. */
function wording(input: LicenseExpiryInput, expires: string, graceEnds: string): LicenseWording {
  if (input.trial) return trialWording(input, expires);
  if (input.variant === '30d' || input.variant === '7d' || input.variant === '1d') {
    return {
      subject: `Your Qualor licence expires in ${days(daysUntil(input.expires, input.now))}`,
      intro: html`<p style="margin:0">The Qualor licence of ${input.licensee} expires on ${expires}. Renew it to keep the enterprise features. After that date a 14-day grace period starts, and everything keeps working until ${graceEnds}.</p>`,
      title: `The licence expires on ${expires}`,
      badge: { text: 'Expires soon', tone: 'warn' },
    };
  }
  if (input.variant === 'grace') {
    return {
      subject: `Your Qualor licence has expired: ${days(daysUntil(input.graceEndsAt, input.now))} of grace left`,
      intro: html`<p style="margin:0">The Qualor licence of ${input.licensee} expired on ${expires}. Everything keeps working during the grace period, until ${graceEnds}. Then Qualor runs as the community edition: ${WHAT_STOPS}. Nothing is deleted.</p>`,
      title: 'The licence has expired',
      badge: { text: 'Grace period', tone: 'bad' },
    };
  }
  return {
    subject: 'Your Qualor licence has expired',
    intro: html`<p style="margin:0">The grace period of the Qualor licence of ${input.licensee} ended on ${graceEnds}. Enterprise features are off: Qualor runs as the community edition until the licence is renewed, so ${WHAT_STOPS}. Nothing was deleted.</p>`,
    title: 'Enterprise features are off',
    badge: { text: 'Expired', tone: 'bad' },
  };
}

/** E1 spec: the licence expiry alert for instance administrators. */
export function renderLicenseExpiry(input: LicenseExpiryInput): RenderedMail {
  const host = instanceHost(input.publicUrl);
  const expires = formatDay(input.expires);
  const graceEnds = formatDay(input.graceEndsAt);
  const { subject, intro, title, badge } = wording(input, expires, graceEnds);
  return {
    subject,
    ...renderLayout({
      preheader: subject,
      title,
      badge,
      intro,
      facts: [
        ['Licensee', input.licensee],
        ['Plan', input.plan],
        [input.trial ? 'Trial ends' : 'Expires', expires],
        ...(input.trial ? [] : ([['Grace ends', graceEnds]] as [string, string][])),
      ],
      cta: {
        label: 'Open licence settings',
        url: publicLink(input.publicUrl, '/settings/license'),
        fallbackText: 'Open Settings → Licence in Qualor.',
      },
      after: input.trial
        ? html`<p style="margin:0">Apply a new key in Settings → Licence and restart the server.</p>`
        : html`<p style="margin:0">Apply a renewed key in Settings → Licence and restart the server.</p>`,
      reason: adminAlertReason(host),
      instanceHost: host,
    }),
  };
}
