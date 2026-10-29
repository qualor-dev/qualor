import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { renderLicenseExpiry } from './license-expiry';
import { sampleMails } from './samples';
import { renderWebhookFailed } from './webhook-failed';

const DIR = new URL('./', import.meta.url);
/** A public URL with a path prefix (Review Focus 3). */
const SAMPLE_URL = 'https://qualor.example.com/qualor';
const links = (page: string) => [...page.matchAll(/href="([^"]+)"/g)].map((m) => m[1] ?? '');

describe('the E1 messages (E1 spec, Templates)', () => {
  it('names every sample after its kind and variant, with the subjects of the spec', () => {
    expect(sampleMails(SAMPLE_URL).map(({ name, mail }) => [name, mail.subject])).toEqual([
      ['test', 'Qualor test message'],
      ['license.expiry-30d', 'Your Qualor licence expires in 20 days'],
      ['license.expiry-7d', 'Your Qualor licence expires in 5 days'],
      ['license.expiry-1d', 'Your Qualor licence expires in 1 day'],
      ['license.expiry-grace', 'Your Qualor licence has expired: 7 days of grace left'],
      ['license.expiry-expired', 'Your Qualor licence has expired'],
      ['webhook.failed', 'Webhook to hooks.example.com is failing'],
      ['account.password-reset', 'Reset your Qualor password'],
      ['account.invitation', 'Ada Admin invited you to Qualor'],
      ['account.password-changed-self', 'Your Qualor password was changed'],
      ['account.password-changed-reset', 'Your Qualor password was changed'],
      ['account.password-changed-admin', 'Your Qualor password was changed'],
      ['notify.gate-failed', 'Payments API: quality gate failed on main'],
      ['notify.gate-failed-mr', 'Payments API: quality gate failed on !42'],
      ['notify.gate-recovered', 'Payments API: quality gate passes again on main'],
      ['notify.analysis-failed', 'Payments API: an analysis of feature/refunds failed'],
      ['webhook.failed-organization', 'Webhook to hooks.example.com is failing'],
    ]);
  });

  it.each(sampleMails(SAMPLE_URL).map((s) => [s.name, s.mail] as const))(
    '%s: HTML under 90 KB with the logo, and a text part wrapped at 76 columns',
    (_name, mail) => {
      expect(Buffer.byteLength(mail.html, 'utf8')).toBeLessThan(90 * 1024);
      expect(mail.html).toContain('cid:logo@qualor');
      expect(mail.text).toContain('\n--\n');
      for (const line of mail.text.split('\n')) {
        if (!line.includes('://')) expect(line.length).toBeLessThanOrEqual(76);
      }
    },
  );

  it('keeps the public URL path in every link into Qualor', () => {
    const all = sampleMails(SAMPLE_URL).flatMap((s) => links(s.mail.html));
    for (const link of all.filter((l) => l !== 'https://qualor.dev')) {
      expect(link.startsWith(`${SAMPLE_URL}/`), link).toBe(true);
    }
    expect(all).toContain(`${SAMPLE_URL}/settings/license`);
    expect(all).toContain(`${SAMPLE_URL}/settings/webhooks`);
  });

  it('links nowhere into Qualor without a public URL, and says where to go instead', () => {
    for (const { name, mail } of sampleMails(null)) {
      expect(links(mail.html), name).toEqual(['https://qualor.dev']);
      expect(mail.text, name).not.toMatch(/https?:\/\//);
    }
    const licence = sampleMails(null).find((s) => s.name === 'license.expiry-30d')?.mail;
    expect(licence?.text).toContain('Open Settings → Licence in Qualor.');
    // The text part wraps at 76 columns, the 77-character sentence included.
    expect(licence?.text.replace(/\n/g, ' ')).toContain(
      'You get this because you are an instance administrator of this Qualor server.',
    );
  });

  it('says what stops when the grace period ends, and names no AI fix limit (6I D10)', () => {
    const mails = sampleMails(null).filter((s) => /^license\.expiry-(grace|expired)$/.test(s.name));
    expect(mails).toHaveLength(2);
    for (const { name, mail } of mails) {
      expect(mail.text.replace(/\n/g, ' '), name).toContain(
        'the audit log stops recording new events. Nothing',
      );
      expect(mail.text, name).not.toMatch(/fix suggestion/i);
      expect(mail.html, name).not.toMatch(/fix suggestion|per organi[sz]ation per day/i);
    }
  });

  it('escapes names in the HTML part and keeps them plain in the text part', () => {
    const webhook = renderWebhookFailed({
      organization: '<b>Acme</b> & Co',
      project: '"Pay" <svc>',
      receiverHost: 'hooks.example.com',
      lastResponse: null,
      attempts: 7,
      publicUrl: null,
    });
    expect(webhook.html).toContain('&lt;b&gt;Acme&lt;/b&gt; &amp; Co');
    expect(webhook.html).not.toContain('<b>Acme</b>');
    expect(webhook.html).toContain('&quot;Pay&quot; &lt;svc&gt;');
    expect(webhook.text).toContain('Organization: <b>Acme</b> & Co');
    expect(webhook.text).toContain('Last response: no answer');
    const licence = renderLicenseExpiry({
      variant: '7d',
      licensee: 'Acme <script>',
      plan: 'Business',
      expires: new Date('2026-10-18T00:00:00Z'),
      graceEndsAt: new Date('2026-11-01T00:00:00Z'),
      now: new Date('2026-10-13T09:00:00Z'),
      trial: false,
      publicUrl: null,
    });
    expect(licence.html).not.toContain('<script>');
    expect(licence.text).toContain('Licensee: Acme <script>');
  });

  it('lets E3 give the webhook alert another reason line and footer links', () => {
    const settings = 'https://qualor.example.com/settings/notifications';
    const mail = renderWebhookFailed({
      organization: 'Acme',
      project: null,
      receiverHost: 'hooks.example.com',
      lastResponse: 503,
      attempts: 7,
      publicUrl: null,
      reason: 'You get this because you are an administrator of Acme.',
      footerLinks: [{ label: 'Notification settings', url: settings }],
    });
    expect(mail.text.replace(/\n/g, ' ')).toContain(
      'You get this because you are an administrator of Acme.',
    );
    expect(mail.text).not.toContain('instance administrator');
    expect(mail.text).toContain(`Notification settings: ${settings}`);
    expect(mail.html).toContain(`href="${settings}"`);
    expect(mail.text).toContain('Last response: HTTP 503');
  });

  it('uses raw() nowhere but in html.ts and layout.ts', () => {
    const files = readdirSync(DIR).filter(
      (f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && f !== 'html.ts' && f !== 'layout.ts',
    );
    expect(files.length).toBeGreaterThanOrEqual(5);
    for (const f of files) expect(readFileSync(new URL(f, DIR), 'utf8'), f).not.toMatch(/\braw\(/);
  });
});
