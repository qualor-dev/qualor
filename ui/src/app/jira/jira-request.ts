import { Component, computed, input } from '@angular/core';
import { type Api, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import type { JiraLinkItem } from '../api/types';
import { jiraProblemText } from './jira-text';

/** `POST /projects/{id}/jira/links` takes at most this many issues… */
export const JIRA_ISSUES_MAX = 500;
/** …or this many vulnerabilities (the Vulnerabilities list's page is smaller). */
export const JIRA_VULNERABILITIES_MAX = 100;

/** A vulnerability of the project, by its package and id. */
export interface JiraPair {
  packageName: string;
  vulnerabilityId: string;
}

/** The finding a Jira issue is for: a code or Trivy issue, or a vulnerability. */
export type JiraTarget = { issueId: string } | JiraPair;

/** Asks Jira issues for findings; the items answer in the order sent. */
export async function createJiraLinks(
  api: Api,
  projectId: string,
  body: { issueIds: string[] } | { vulnerabilities: JiraPair[] },
): Promise<JiraLinkItem[]> {
  const answer = await ok(
    api.client.POST('/api/v0/projects/{id}/jira/links', {
      params: { path: { id: projectId } },
      body,
    }),
  );
  return answer.items;
}

/** What became of a request, counted for its result line ("12 queued, 3 already linked"). */
export interface JiraRequestSummary {
  queued: number;
  alreadyLinked: number;
  notLinkable: number;
  notFound: number;
}

export function requestSummary(items: readonly JiraLinkItem[]): JiraRequestSummary {
  const count = (skipped: JiraLinkItem['skipped']) =>
    items.filter((item) => item.skipped === skipped).length;
  return {
    queued: count(null),
    alreadyLinked: count('ALREADY_LINKED'),
    notLinkable: count('NOT_ELIGIBLE'),
    notFound: count('NOT_FOUND'),
  };
}

/**
 * A refused request in the UI's words: a 429 says how long to wait, a broken connection says
 * what is wrong with it (its problem code's text) before who fixes it.
 */
export function jiraRequestError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 429) {
      const seconds = err.retryAfter;
      if (seconds === null) {
        return $localize`:@@jira.request.rateLimited:Too many issue changes in a short time. Wait a minute and try again.`;
      }
      if (seconds < 60) {
        return $localize`:@@jira.request.rateLimitedSeconds:Too many issue changes in a short time. Try again in ${seconds}:seconds: s.`;
      }
      const minutes = Math.ceil(seconds / 60);
      return $localize`:@@jira.request.rateLimitedMinutes:Too many issue changes in a short time. Try again in ${minutes}:minutes: min.`;
    }
    const code = err.problem?.problemCode;
    if (err.code === 'JIRA_CONNECTION_BROKEN' && code) {
      return `${jiraProblemText(code)} ${problemMessage(err)}`;
    }
  }
  return problemMessage(err);
}

/** The project's Jira state is stale when a create says the connection or the mapping went. */
export function jiraStateGone(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === 'JIRA_NOT_CONNECTED' || err.code === 'JIRA_PROJECT_NOT_MAPPED')
  );
}

/**
 * `q-jira-request-result`: the result line of a request, "12 queued, 3 already linked, 1 not
 * linkable", each part a whole plural message and the parts that are zero left out.
 */
@Component({
  selector: 'q-jira-request-result',
  templateUrl: './jira-request.html',
  host: { class: 'jira-result' },
})
export class JiraRequestResult {
  readonly summary = input.required<JiraRequestSummary>();

  protected readonly parts = computed(() => {
    const s = this.summary();
    const parts: { kind: keyof JiraRequestSummary; count: number }[] = [
      { kind: 'queued', count: s.queued },
      { kind: 'alreadyLinked', count: s.alreadyLinked },
      { kind: 'notLinkable', count: s.notLinkable },
      { kind: 'notFound', count: s.notFound },
    ];
    return parts.filter((part) => part.count > 0);
  });
}
