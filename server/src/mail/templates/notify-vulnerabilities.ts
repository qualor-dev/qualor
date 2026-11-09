import type { RenderedMail } from '../payload';
import { html } from './html';
import { renderLayout } from './layout';
import { subjectLine } from './notify-common';
import {
  capRows,
  projectSections,
  projectsLabel,
  VULNERABILITY_REASON,
  vulnerabilityFooterLinks,
  type VulnerabilityMailLinks,
  type VulnerabilityMailProject,
} from './notify-vulnerability-common';

/** 4b: the daily digest of the new vulnerabilities of the projects a user watches. */
export function renderVulnerabilityDigest(input: {
  projects: VulnerabilityMailProject[];
  databaseDate: Date | null;
  links: VulnerabilityMailLinks;
}): RenderedMail {
  const projects = capRows(input.projects);
  const label = projectsLabel(projects);
  const data =
    input.databaseDate === null
      ? ''
      : html`<p style="margin:20px 0 0;font-size:13px;color:#4a5b73">Vulnerability data from ${input.databaseDate.toISOString().slice(0, 10)}.</p>`;
  const { html: body, text } = renderLayout({
    preheader: `New vulnerabilities in ${label}.`,
    title: `New vulnerabilities in ${label}`,
    badge: { text: 'New vulnerabilities', tone: 'bad' },
    intro: html`Qualor found new vulnerabilities in the branches and versions it tracks. Each is listed once, with the branches and versions where it is new.`,
    after: html`${projectSections(projects, input.links, false)}${data}`,
    reason: VULNERABILITY_REASON,
    footerLinks: vulnerabilityFooterLinks(input.links),
    instanceHost: input.links.instanceHost,
  });
  return { subject: subjectLine(`New vulnerabilities in ${label}`), html: body, text };
}
