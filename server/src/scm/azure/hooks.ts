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
/** A project's state in the Test: `stale` is subscribed, but with a password Azure DevOps may not hold. */
export type ProjectHookState = HookState | 'stale' | 'missing';

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

/**
 * The own subscription the subscribe button manages for one event in one Azure project: the first
 * listed. Any further one of the same event and project is left alone by the button, so the Test
 * and the backstop pass leave it alone too.
 */
export function managedSubscription(
  own: readonly AzureSubscription[],
  projectId: string,
  eventType: HookEventType,
): AzureSubscription | undefined {
  const project = projectId.toLowerCase();
  return own.find((s) => s.eventType === eventType && s.projectId.toLowerCase() === project);
}

/** The subscriptions the button manages in these Azure projects: for each, one per event at most. */
export function managedSubscriptions(
  own: readonly AzureSubscription[],
  projectIds: readonly string[],
): AzureSubscription[] {
  return projectIds.flatMap((projectId) =>
    HOOK_EVENTS.flatMap((eventType) => managedSubscription(own, projectId, eventType) ?? []),
  );
}

/** `disabledByUser`, `disabledBySystem` and `disabledByInactiveIdentity` are all `disabled`. */
export function hookState(status: string): HookState {
  if (status === 'enabled') return 'enabled';
  if (status === 'onProbation') return 'onProbation';
  return 'disabled';
}

/** The worst state wins: missing > disabled > onProbation > stale > enabled. */
const SEVERITY: Record<ProjectHookState, number> = {
  enabled: 0,
  stale: 1,
  onProbation: 2,
  disabled: 3,
  missing: 4,
};

/**
 * The state of one Azure project's hooks, or `missing` when either of the two events has no
 * subscription of Qualor's; otherwise the worse of the two. With `current` false (Azure DevOps may
 * hold another password than the stored one) an `enabled` project reads `stale`.
 */
export function projectHookState(
  own: readonly AzureSubscription[],
  projectId: string,
  current = true,
): ProjectHookState {
  const states: ProjectHookState[] = current ? [] : ['stale'];
  for (const eventType of HOOK_EVENTS) {
    const found = managedSubscription(own, projectId, eventType);
    if (!found) return 'missing';
    states.push(hookState(found.status));
  }
  return states.reduce((worst, s) => (SEVERITY[s] > SEVERITY[worst] ? s : worst));
}

/** Azure DevOps' own HTTP 400 or 403 (no right to edit subscriptions, a rejected input), not a transport refusal. */
function refusedByAzure(err: unknown): boolean {
  return err instanceof ScmError && (err.status === 403 || err.status === 400);
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

export interface SubscribeResult {
  /** The projects finished, in order. */
  projects: ProjectOutcome[];
  /** The failure that stopped the loop (not a refusal), or null. */
  failure: ScmError | null;
  /** Whether any subscription was created or rewritten (also in a project not finished). */
  wrote: boolean;
}

/**
 * Creates Qualor's two subscriptions in each project, or rewrites those that exist when their
 * version or status differ, or when Azure DevOps may hold another password. An event whose newest
 * version Azure DevOps does not offer, and a project the identity may not edit, are `refused`.
 * An own subscription deleted meanwhile (404 on its PUT) is created again. With more than one own
 * subscription of an event in a project the first is rewritten and the rest are left alone
 * (deleting is not available). Any other Azure DevOps failure stops the loop and is returned with
 * what was done so far; a failure that is not Azure DevOps' is thrown.
 */
export async function subscribeProjects(input: SubscribeInput): Promise<SubscribeResult> {
  const { client, url, password } = input;
  const result: SubscribeResult = { projects: [], failure: null, wrote: false };
  if (input.projectIds.length === 0) return result;
  try {
    const offered = new Map((await client.hookEventTypes()).map((e) => [e.id, e.versions]));
    const own = ownSubscriptions(await client.subscriptions(), url);
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
        const existing = managedSubscription(own, projectId, eventType);
        try {
          if (
            existing &&
            input.passwordKnownToAzure &&
            existing.resourceVersion === resourceVersion &&
            existing.status === 'enabled'
          ) {
            done[key] = 'unchanged';
            continue;
          }
          let outcome: HookOutcome = 'created';
          if (existing) {
            try {
              await client.replaceSubscription(existing.id, subscription);
              outcome = 'replaced';
            } catch (err) {
              if (!(err instanceof ScmError) || err.kind !== 'not_found') throw err;
            }
          }
          if (outcome === 'created') await client.createSubscription(subscription);
          result.wrote = true;
          done[key] = outcome;
        } catch (err) {
          if (!refusedByAzure(err)) throw err;
          done[key] = 'refused';
        }
      }
      result.projects.push({ projectId, ...done });
    }
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    result.failure = err;
  }
  return result;
}
