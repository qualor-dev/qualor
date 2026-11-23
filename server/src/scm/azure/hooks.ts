import { randomBytes } from 'node:crypto';
import { ScmError } from '../provider';
import type { AzureDevOpsClient, AzureSubscription } from './client';

/**
 * Qualor's own service hook subscriptions in Azure DevOps (sub-plan 5): the password Qualor
 * generates for them, which subscriptions are Qualor's, what their state is, and creating or
 * rewriting them for each Azure project that holds a mapped repository.
 */

/** The two events Qualor reads and the newest resource version each offers (probe item 9). */
export const HOOK_EVENT_VERSIONS = {
  'ms.vss-code.git-pullrequest-comment-event': '2.0',
  'git.pullrequest.updated': '1.0',
} as const;
export type HookEventType = keyof typeof HOOK_EVENT_VERSIONS;
const HOOK_EVENTS = Object.keys(HOOK_EVENT_VERSIONS) as HookEventType[];

/** What a subscribe call did for one event of one project. */
export type HookOutcome = 'created' | 'replaced' | 'unchanged' | 'refused';
export type HookState = 'enabled' | 'onProbation' | 'disabled';

/** 32 random bytes as base64url: 43 characters, inside the webhook secret pattern. */
export function generateHookPassword(): string {
  return randomBytes(32).toString('base64url');
}

const isHookEvent = (eventType: string): eventType is HookEventType =>
  Object.hasOwn(HOOK_EVENT_VERSIONS, eventType);

/** Qualor's own subscriptions: the ones that deliver to `url`, of one of the two events. */
export function ownSubscriptions(
  subscriptions: readonly AzureSubscription[],
  url: string,
): AzureSubscription[] {
  return subscriptions.filter((s) => s.url === url && isHookEvent(s.eventType));
}

/** `disabledByUser`, `disabledBySystem` and `disabledByInactiveIdentity` are all `disabled`. */
export function hookState(status: string): HookState {
  if (status === 'enabled') return 'enabled';
  if (status === 'onProbation') return 'onProbation';
  return 'disabled';
}

const SEVERITY: Record<HookState, number> = { enabled: 0, onProbation: 1, disabled: 2 };

/**
 * The state of one Azure project's hooks, or `missing` when either of the two events has no
 * subscription of Qualor's; otherwise the worse of the two.
 */
export function projectHookState(
  own: readonly AzureSubscription[],
  projectId: string,
): HookState | 'missing' {
  const states: HookState[] = [];
  for (const eventType of HOOK_EVENTS) {
    const found = own.find(
      (s) => s.eventType === eventType && s.projectId.toLowerCase() === projectId.toLowerCase(),
    );
    if (!found) return 'missing';
    states.push(hookState(found.status));
  }
  return states.reduce((worst, s) => (SEVERITY[s] > SEVERITY[worst] ? s : worst));
}

/** A refusal by Azure DevOps itself (no right to edit subscriptions, a rejected input). */
function refusedByAzure(err: unknown): boolean {
  return err instanceof ScmError && (err.status === 403 || err.kind === 'refused');
}

export interface SubscribeInput {
  client: AzureDevOpsClient;
  /** `consumerInputs.url`: Qualor's webhook address of the connection (https). */
  url: string;
  /** The Basic password Azure DevOps will send; never logged or returned. */
  password: string;
  /**
   * Whether Azure DevOps already holds this password. It cannot be read back (it answers
   * `********`), so a caller that does not know passes false and every subscription of Qualor's
   * is rewritten.
   */
  passwordKnownToAzure: boolean;
  /** The Azure projects (ids) that hold a mapped repository. */
  projectIds: readonly string[];
}

export interface ProjectOutcome {
  projectId: string;
  comment: HookOutcome;
  updated: HookOutcome;
}

/**
 * Creates Qualor's two subscriptions in each project, or rewrites those that exist when their
 * version or status differ, or when Azure DevOps may hold another password. An event whose newest
 * version Azure DevOps does not offer, and a project the identity may not edit, are `refused`; any
 * other failure is thrown.
 */
export async function subscribeProjects(input: SubscribeInput): Promise<ProjectOutcome[]> {
  const { client, url, password } = input;
  if (input.projectIds.length === 0) return [];
  const offered = new Map((await client.hookEventTypes()).map((e) => [e.id, e.versions]));
  const own = ownSubscriptions(await client.subscriptions(), url);
  const outcomes: ProjectOutcome[] = [];
  for (const projectId of input.projectIds) {
    const done = {} as Record<'comment' | 'updated', HookOutcome>;
    for (const eventType of HOOK_EVENTS) {
      const resourceVersion = HOOK_EVENT_VERSIONS[eventType];
      const key = eventType === 'git.pullrequest.updated' ? 'updated' : 'comment';
      if (!offered.get(eventType)?.includes(resourceVersion)) {
        done[key] = 'refused';
        continue;
      }
      const subscription = { eventType, resourceVersion, projectId, url, password };
      const existing = own.find(
        (s) => s.eventType === eventType && s.projectId.toLowerCase() === projectId.toLowerCase(),
      );
      try {
        if (!existing) {
          await client.createSubscription(subscription);
          done[key] = 'created';
        } else if (
          input.passwordKnownToAzure &&
          existing.resourceVersion === resourceVersion &&
          existing.status === 'enabled'
        ) {
          done[key] = 'unchanged';
        } else {
          await client.replaceSubscription(existing.id, subscription);
          done[key] = 'replaced';
        }
      } catch (err) {
        if (!refusedByAzure(err)) throw err;
        done[key] = 'refused';
      }
    }
    outcomes.push({ projectId, ...done });
  }
  return outcomes;
}
