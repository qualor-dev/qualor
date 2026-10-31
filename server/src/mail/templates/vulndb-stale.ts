import type { RenderedMail } from '../payload';
import { html } from './html';
import { renderLayout } from './layout';
import { formatDay, instanceHost, publicLink } from './text';

export interface VulndbStaleInput {
  /** When the current dataset was built (its `UpdatedAt`); null when unknown. */
  dataDate: Date | null;
  /** The last failed update, if any. */
  lastError: { code: string; message: string } | null;
  publicUrl: string | null;
}

/** 0.15: the vulnerability database is older than three days (once per dataset). */
export function renderVulndbStale(input: VulndbStaleInput): RenderedMail {
  const host = instanceHost(input.publicUrl);
  const subject = 'The Qualor vulnerability database is out of date';
  const facts: [string, string][] = [
    ['Data from', input.dataDate === null ? 'unknown' : formatDay(input.dataDate)],
  ];
  if (input.lastError !== null) {
    facts.push(['Last error', `${input.lastError.code}: ${input.lastError.message}`]);
  }
  return {
    subject,
    ...renderLayout({
      preheader: 'Vulnerability checks run against data that is more than 3 days old.',
      title: 'The vulnerability database is out of date',
      badge: { text: 'Stale', tone: 'warn' },
      intro: html`<p style="margin:0">The vulnerability data Qualor checks dependencies against is more than 3 days old, so new vulnerabilities are not reported yet. Check that the server can reach the database source, or upload a newer file.</p>`,
      facts,
      cta: {
        label: 'Open vulnerability database',
        url: publicLink(input.publicUrl, '/settings/vulnerability-db'),
        fallbackText: 'Open Settings → Vulnerability database in Qualor.',
      },
      after: html`<p style="margin:0">You get this once for each stale database.</p>`,
      reason: `You get this because you are an instance administrator of ${host ?? 'this Qualor server'}.`,
      instanceHost: host,
    }),
  };
}
