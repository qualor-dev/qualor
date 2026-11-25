import { Component, computed, input } from '@angular/core';
import { type Api, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import type { BoardsLinkItem } from '../api/types';
import { jiraRequestError, type JiraRequestSummary } from '../jira/jira-request';
import { boardsProblemText } from './boards-text';

/** `POST /projects/{id}/boards/links` takes at most this many issues… */
export const BOARDS_ISSUES_MAX = 500;
/** …or this many vulnerabilities (the Vulnerabilities list's page is smaller). */
export const BOARDS_VULNERABILITIES_MAX = 100;

/** A vulnerability of the project, by its package and id. */
export interface BoardsPair {
  packageName: string;
  vulnerabilityId: string;
}

/** The finding a work item is for: a code or Trivy issue, or a vulnerability. */
export type BoardsTarget = { issueId: string } | BoardsPair;

/** Asks Azure Boards work items for findings; the items answer in the order sent. */
export async function createBoardsLinks(
  api: Api,
  projectId: string,
  body: { issueIds: string[] } | { vulnerabilities: BoardsPair[] },
): Promise<BoardsLinkItem[]> {
  const answer = await ok(
    api.client.POST('/api/v0/projects/{id}/boards/links', {
      params: { path: { id: projectId } },
      body,
    }),
  );
  return answer.items;
}

/** What became of a request, counted as Jira's are ("2 work items queued, 1 already linked"). */
export type BoardsRequestSummary = JiraRequestSummary;

export function boardsRequestSummary(items: readonly BoardsLinkItem[]): BoardsRequestSummary {
  const count = (skipped: BoardsLinkItem['skipped']) =>
    items.filter((item) => item.skipped === skipped).length;
  return {
    queued: count(null),
    alreadyLinked: count('ALREADY_LINKED'),
    notLinkable: count('NOT_ELIGIBLE'),
    notFound: count('NOT_FOUND'),
  };
}

/**
 * A refused request in the UI's words, by its code: a 429 says how long to wait (Jira's words, the
 * same limit on issue changes), a broken connection says what is wrong with it before who fixes it.
 */
export function boardsRequestError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 429) return jiraRequestError(err);
    const text = boardsProblemText(err.code, err.problem?.problemCode);
    if (text !== null) return text;
  }
  return problemMessage(err);
}

/** The project's Boards state is stale when a request says the connection or the mapping went. */
export function boardsStateGone(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === 'BOARDS_NOT_CONNECTED' || err.code === 'BOARDS_PROJECT_NOT_MAPPED')
  );
}

/**
 * `q-boards-request-result`: the result line of a request, "2 work items queued, 1 already linked,
 * 1 not linkable", each part a whole plural message and the parts that are zero left out.
 */
@Component({
  selector: 'q-boards-request-result',
  templateUrl: './boards-request.html',
  host: { class: 'boards-result' },
})
export class BoardsRequestResult {
  readonly summary = input.required<BoardsRequestSummary>();

  protected readonly parts = computed(() => {
    const s = this.summary();
    const parts: { kind: keyof BoardsRequestSummary; count: number }[] = [
      { kind: 'queued', count: s.queued },
      { kind: 'alreadyLinked', count: s.alreadyLinked },
      { kind: 'notLinkable', count: s.notLinkable },
      { kind: 'notFound', count: s.notFound },
    ];
    return parts.filter((part) => part.count > 0);
  });
}
