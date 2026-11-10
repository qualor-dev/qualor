import type { ChatKind } from './kinds';
import type { ChatMessage } from './messages';
import { formatSlack } from './format-slack';
import { formatTeams } from './format-teams';

/** Where messages link to; every URL is null without QUALOR_PUBLIC_URL (6G spec D6). */
export interface ChatLinks {
  publicUrl: string | null;
}

export function chatLinks(publicUrl: string | null): ChatLinks {
  return { publicUrl: publicUrl === null ? null : publicUrl.replace(/\/+$/, '') };
}

export function projectsUrl(links: ChatLinks): string | null {
  return links.publicUrl === null ? null : `${links.publicUrl}/projects`;
}

export function projectUrl(links: ChatLinks, projectId: string): string | null {
  return links.publicUrl === null ? null : `${links.publicUrl}/projects/${projectId}`;
}

/** The project's Vulnerabilities tab. */
export function vulnerabilitiesUrl(links: ChatLinks, projectId: string): string | null {
  const project = projectUrl(links, projectId);
  return project === null ? null : `${project}/vulnerabilities`;
}

/** The branch page, as the gate emails link it (mail notify-common `branchLinks`). */
export function branchUrl(links: ChatLinks, projectId: string, branchId: string): string | null {
  const project = projectUrl(links, projectId);
  return project === null ? null : `${project}/branches/${branchId}`;
}

export function issueUrl(links: ChatLinks, projectId: string, issueId: string): string | null {
  const project = projectUrl(links, projectId);
  return project === null ? null : `${project}/issues/${issueId}`;
}

/** 6G spec §4: the request body for the kind (Slack Block Kit, Teams Adaptive Card message). */
export function formatChat(kind: ChatKind, message: ChatMessage, links: ChatLinks): unknown {
  return kind === 'slack' ? formatSlack(message, links) : formatTeams(message, links);
}
