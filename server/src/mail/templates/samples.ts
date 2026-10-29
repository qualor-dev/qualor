import type { RenderedMail } from '../payload';
import { accountSamples } from './account-samples';
import { notifySamples } from './notify-samples';
import { renderLicenseExpiry, type LicenseAlertVariant } from './license-expiry';
import { renderTestMail } from './test';
import { renderWebhookFailed } from './webhook-failed';

/** The fixed "now" of the samples. */
export const SAMPLE_NOW = new Date('2026-10-13T09:00:00Z');
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Every template and variant with fixed sample data, named `<kind>[-variant]`: the preview
 * (`pnpm --filter @qualor/server mail:preview`) and templates.test.ts. E2 and E3 add theirs here.
 */
export function sampleMails(
  publicUrl: string | null = 'https://qualor.example.com',
): { name: string; mail: RenderedMail }[] {
  const licence = (variant: LicenseAlertVariant, expires: string) =>
    renderLicenseExpiry({
      variant,
      licensee: 'Acme Corporation',
      plan: 'Business',
      expires: new Date(expires),
      graceEndsAt: new Date(Date.parse(expires) + 14 * DAY_MS),
      now: SAMPLE_NOW,
      publicUrl,
      trial: false,
    });
  return [
    {
      name: 'test',
      mail: renderTestMail({
        server: { host: 'smtp.example.com', port: 587, security: 'starttls' },
        sentBy: 'Ada Admin',
        at: SAMPLE_NOW,
        publicUrl,
      }),
    },
    { name: 'license.expiry-30d', mail: licence('30d', '2026-11-02T00:00:00Z') },
    { name: 'license.expiry-7d', mail: licence('7d', '2026-10-18T00:00:00Z') },
    { name: 'license.expiry-1d', mail: licence('1d', '2026-10-14T00:00:00Z') },
    { name: 'license.expiry-grace', mail: licence('grace', '2026-10-06T00:00:00Z') },
    { name: 'license.expiry-expired', mail: licence('expired', '2026-09-20T00:00:00Z') },
    {
      name: 'webhook.failed',
      mail: renderWebhookFailed({
        organization: 'Acme',
        project: 'Payments API',
        receiverHost: 'hooks.example.com',
        lastResponse: 503,
        attempts: 7,
        publicUrl,
      }),
    },
    ...accountSamples(publicUrl),
    ...notifySamples(publicUrl),
  ];
}
