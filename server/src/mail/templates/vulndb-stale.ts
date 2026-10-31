import type { RenderedMail } from '../payload';
import { html, type SafeHtml } from './html';
import { renderLayout } from './layout';
import { formatDay, instanceHost, publicLink } from './text';

export interface VulndbStaleInput {
  /** The stale data: the Trivy database (the default), or KEV or EPSS (`vuln.priority`). */
  dataset?: 'trivy' | 'kev' | 'epss';
  /** When the data was built or released (Trivy `UpdatedAt`, KEV release, EPSS score date). */
  dataDate: Date | null;
  /** The last failed update, if any. */
  lastError: { code: string; message: string } | null;
  publicUrl: string | null;
}

interface StaleCopy {
  subject: string;
  title: string;
  preheader: string;
  intro: SafeHtml;
  /** The source named in the facts; none for the Trivy database. */
  source: string | null;
  after: SafeHtml;
}

const COPY: Record<NonNullable<VulndbStaleInput['dataset']>, StaleCopy> = {
  trivy: {
    subject: 'The Qualor vulnerability database is out of date',
    title: 'The vulnerability database is out of date',
    preheader: 'Vulnerability checks run against data that is more than 3 days old.',
    intro: html`<p style="margin:0">The vulnerability data Qualor checks dependencies against is more than 3 days old, so new vulnerabilities are not reported yet. Check that the server can reach the database source, or upload a newer file.</p>`,
    source: null,
    after: html`<p style="margin:0">You get this once for each stale database.</p>`,
  },
  kev: {
    subject: 'The Qualor list of exploited vulnerabilities is out of date',
    title: 'The list of exploited vulnerabilities is out of date',
    preheader: 'The list of exploited vulnerabilities was not refreshed for more than 3 days.',
    intro: html`<p style="margin:0">Qualor has not refreshed the CISA Known Exploited Vulnerabilities catalog for more than 3 days, so vulnerabilities exploited since then are not flagged yet. Check that the server can reach the catalog source, or upload a newer file.</p>`,
    source: 'CISA Known Exploited Vulnerabilities',
    after: html`<p style="margin:0">You get this once each time the list goes out of date.</p>`,
  },
  epss: {
    subject: 'The Qualor exploit probability data is out of date',
    title: 'The exploit probability data is out of date',
    preheader: 'The exploit probability scores are more than 3 days old.',
    intro: html`<p style="margin:0">The FIRST EPSS exploit probability scores Qualor shows are more than 3 days old, so they miss the latest changes. Check that the server can reach the EPSS source, or upload a newer file.</p>`,
    source: 'FIRST EPSS',
    after: html`<p style="margin:0">You get this once each time the data goes out of date.</p>`,
  },
};

/** 0.15: the vulnerability database, or KEV or EPSS, is older than three days (once each time). */
export function renderVulndbStale(input: VulndbStaleInput): RenderedMail {
  const host = instanceHost(input.publicUrl);
  const copy = COPY[input.dataset ?? 'trivy'];
  const facts: [string, string][] = [];
  if (copy.source !== null) facts.push(['Source', copy.source]);
  facts.push(['Data from', input.dataDate === null ? 'unknown' : formatDay(input.dataDate)]);
  if (input.lastError !== null) {
    facts.push(['Last error', `${input.lastError.code}: ${input.lastError.message}`]);
  }
  return {
    subject: copy.subject,
    ...renderLayout({
      preheader: copy.preheader,
      title: copy.title,
      badge: { text: 'Stale', tone: 'warn' },
      intro: copy.intro,
      facts,
      cta: {
        label: 'Open vulnerability database',
        url: publicLink(input.publicUrl, '/settings/vulnerability-db'),
        fallbackText: 'Open Settings → Vulnerability database in Qualor.',
      },
      after: copy.after,
      reason: `You get this because you are an instance administrator of ${host ?? 'this Qualor server'}.`,
      instanceHost: host,
    }),
  };
}
