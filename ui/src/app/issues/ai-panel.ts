import {
  Component,
  computed,
  DestroyRef,
  effect,
  inject,
  InjectionToken,
  input,
  output,
  signal,
  untracked,
} from '@angular/core';
import { Api, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { type Branch, findBranch } from '../project/branches';
import { llmProblemText } from '../settings/ai-text';
import { DateTimePipe } from '../shared/date-time.pipe';
import { safeHelpUri } from '../shared/links';
import { assertNever, SCM_PROVIDERS, type ScmProvider } from '../shared/scm-provider';

type OrgAi = ResponseBody<'/api/v0/organizations/{id}/ai', 'get'>;
export type AiRequest = ResponseBody<'/api/v0/ai-requests/{id}', 'get'>;
type Feature = AiRequest['feature'];
type Result = NonNullable<AiRequest['result']>;
type ExplainResult = Extract<Result, { kind: 'explain' }>;
type TriageResult = Extract<Result, { kind: 'triage' }>;
type FixResult = Extract<Result, { kind: 'fix' }>;

/** How often a request in flight is read again (the server answers `Retry-After: 2`). */
export const AI_POLL_INTERVAL = new InjectionToken<number>('AI_POLL_INTERVAL', {
  factory: () => 2_000,
});
/** A queued post is followed for this many reads at most, then shown as queued. */
const POST_POLLS = 30;
/**
 * A read that fails is tried again after 1, 2, 4 and 8 poll intervals; after this many failures in
 * a row the request is no longer followed, and the person may ask again.
 */
const POLL_FAILURES = 4;

/** What the panel needs of the issue. */
export interface AiIssue {
  id: string;
  projectId: string;
  branchId: string;
  status: string;
}

/** The merge request (GitLab) or pull request (GitHub) a fix would be posted to. */
export interface PostTarget {
  kind: 'merge_request' | 'pull_request';
  /** `!42` on GitLab, `#42` on GitHub. */
  reference: string;
  title: string | null;
}

/** llm.md §8.2: a fix can be posted only on a merge request of a mapped project. */
export function postTarget(branch: Branch, provider: ScmProvider | null = null): PostTarget | null {
  if (branch.kind !== 'merge_request') return null;
  // A recorded address tells the provider; a branch without one (not decorated yet, or the link
  // is off the connection's web address) takes the project's connection's provider.
  if (branch.mrUrl === null) {
    return provider === null ? null : target(provider, branch);
  }
  for (const candidate of SCM_PROVIDERS) {
    if (POST_TARGETS[candidate].pattern.test(branch.mrUrl)) return target(candidate, branch);
  }
  return null;
}

function target(provider: ScmProvider, branch: Branch): PostTarget | null {
  switch (provider) {
    case 'github':
    case 'gitlab': {
      const { kind, prefix } = POST_TARGETS[provider];
      return { kind, reference: `${prefix}${branch.name}`, title: branch.mrTitle };
    }
    case 'azure': // azure-pending(6): posting a fix to an Azure DevOps pull request
      return null;
    default:
      return assertNever(provider, 'provider');
  }
}

/** How each provider's merge request address looks, and what its requests are called. */
const POST_TARGETS: Record<
  ScmProvider,
  { pattern: RegExp; kind: PostTarget['kind']; prefix: string }
> = {
  github: {
    pattern: /^https?:\/\/[^/]+\/.+\/pull\/\d+\/?$/,
    kind: 'pull_request',
    prefix: '#',
  },
  gitlab: {
    pattern: /^https?:\/\/[^/]+\/.+\/merge_requests\/\d+\/?$/,
    kind: 'merge_request',
    prefix: '!',
  },
  azure: {
    pattern: /[^\s\S]/, // azure-pending(6): an Azure DevOps pull request's address (this matches nothing)
    kind: 'pull_request',
    prefix: '!',
  },
};

/**
 * The issue view's AI assistant (llm.md §18): shown only when the issue's organisation has the
 * assistant enabled, and then only the features it has on (triage and fix only for an open issue).
 * Nothing is sent before a person clicks; the notice says what is sent where. Every answer is the
 * model's text shown as text (interpolation only, never HTML or Markdown, plan 1F ruling Y5)
 * and labelled as AI-generated. A triage answer is a suggestion only: "Mark as false positive…"
 * hands its id to the issue page's own transition form, where the person writes the comment and
 * decides. A fix is posted to the merge request only after a second, explicit confirmation; one no
 * person asked for (`automatic`, 4E-3a §4) says it was suggested automatically. For a project an
 * instance admin excluded from AI it offers nothing to ask or post, and says so: the server would
 * refuse.
 */
@Component({
  selector: 'q-ai-panel',
  imports: [DateTimePipe],
  templateUrl: './ai-panel.html',
})
export class AiPanel {
  private readonly api = inject(Api);
  private readonly pollMs = inject(AI_POLL_INTERVAL);
  readonly issue = input.required<AiIssue>();
  /**
   * The caller may start AI requests and post fixes (`ai.use`), and
   * may change the issue's status (`issue.triage`), rbac-audit.md §17. Without them the panel
   * shows the answers others asked for, and none of the buttons that would be refused.
   */
  readonly canAsk = input(false);
  readonly canTriage = input(false);
  /** The id of a triage suggestion the person wants to act on. */
  readonly acceptTriage = output<string>();

  protected readonly orgAi = signal<OrgAi | null>(null);
  /** An instance admin excluded the issue's project from AI: nothing of it can be asked. */
  protected readonly excluded = signal(false);
  protected readonly requests = signal<Record<Feature, AiRequest | null>>({
    explain: null,
    triage: null,
    fix: null,
  });
  /** The features whose ask is being sent (before the server answered). */
  protected readonly sending = signal<Partial<Record<Feature, boolean>>>({});
  protected readonly error = signal<string | null>(null);
  /** "The answer is ready", for the status region, once a request asked or followed succeeded. */
  protected readonly announcement = signal<string | null>(null);
  /** Where a fix would be posted: null unless the project is mapped and the branch is an MR. */
  protected readonly target = signal<PostTarget | null>(null);
  /** The fix request whose post waits for the person's confirmation. */
  protected readonly confirming = signal<string | null>(null);
  protected readonly posting = signal(false);

  protected readonly open = computed(() => this.issue().status === 'open');
  protected readonly visible = computed(() => {
    const ai = this.orgAi();
    return (
      ai !== null &&
      ai.enabled &&
      ai.provider !== null &&
      (ai.features.explain || ai.features.triage || ai.features.fix)
    );
  });
  /** Shown when something can be asked, or when there is an answer to read. */
  protected readonly shown = computed(
    () =>
      this.visible() && (this.canAsk() || Object.values(this.requests()).some((r) => r !== null)),
  );
  /** The person may ask, and the project is not excluded from AI: the ask buttons show. */
  protected readonly askable = computed(() => this.canAsk() && !this.excluded());
  protected readonly explain = computed(() => this.requests().explain);
  protected readonly triage = computed(() => this.requests().triage);
  protected readonly fix = computed(() => this.requests().fix);
  /** Whether a request is on its way or waiting for the model. */
  protected readonly working = computed(
    () =>
      Object.values(this.sending()).some(Boolean) ||
      Object.values(this.requests()).some((r) => this.pending(r)),
  );
  /**
   * Whether this feature's ask is on its way or its answer awaited: its buttons then do nothing
   * (and say so with aria-disabled); the other features stay usable.
   */
  protected busy(feature: Feature): boolean {
    return this.sending()[feature] === true || this.pending(this.requests()[feature]);
  }
  /** The issue's identity: a new status of the same issue keeps the answers and their polls. */
  private readonly issueKey = computed(() => `${this.issue().projectId}/${this.issue().id}`);

  /** Incremented per issue: an answer or a poll for an earlier issue is dropped. */
  private generation = 0;
  private readonly timers = new Set<ReturnType<typeof setTimeout>>();

  constructor() {
    effect(() => {
      this.issueKey();
      untracked(() => {
        const issue = this.issue();
        const generation = ++this.generation;
        this.stopPolling();
        this.orgAi.set(null);
        this.excluded.set(false);
        this.requests.set({ explain: null, triage: null, fix: null });
        this.sending.set({});
        this.error.set(null);
        this.announcement.set(null);
        this.target.set(null);
        this.confirming.set(null);
        this.posting.set(false);
        void this.load(issue, generation);
      });
    });
    inject(DestroyRef).onDestroy(() => {
      this.generation++;
      this.stopPolling();
    });
  }

  protected explainResult(request: AiRequest): ExplainResult | null {
    return request.result?.kind === 'explain' ? request.result : null;
  }

  protected triageResult(request: AiRequest): TriageResult | null {
    return request.result?.kind === 'triage' ? request.result : null;
  }

  protected fixResult(request: AiRequest): FixResult | null {
    return request.result?.kind === 'fix' ? request.result : null;
  }

  protected pending(request: AiRequest | null): boolean {
    return request !== null && (request.status === 'queued' || request.status === 'running');
  }

  protected failure(request: AiRequest): string | null {
    return request.status === 'failed' && request.error ? llmProblemText(request.error.code) : null;
  }

  protected verdictText(result: TriageResult): string {
    switch (result.verdict) {
      case 'likely_false_positive':
        return $localize`:@@ai.panel.verdict.falsePositive:Likely a false positive`;
      case 'likely_true_positive':
        return $localize`:@@ai.panel.verdict.truePositive:Likely a true positive`;
      case 'uncertain':
        return $localize`:@@ai.panel.verdict.uncertain:Uncertain`;
    }
  }

  protected confidenceText(result: TriageResult): string {
    switch (result.confidence) {
      case 'low':
        return $localize`:@@ai.panel.confidence.low:low confidence`;
      case 'medium':
        return $localize`:@@ai.panel.confidence.medium:medium confidence`;
      case 'high':
        return $localize`:@@ai.panel.confidence.high:high confidence`;
    }
  }

  /** The link to a posted suggestion: only an absolute http(s) address, else none. */
  protected postLink(request: AiRequest): string | null {
    return safeHelpUri(request.post?.url);
  }

  protected postFailure(request: AiRequest): string {
    return postFailureText(request.post?.reason ?? null);
  }

  /**
   * Whether an answer is about this very issue: the server may answer from a twin issue's request
   * (same fingerprint on another branch); its triage and fix are then shown but not acted on.
   */
  protected ownAnswer(request: AiRequest): boolean {
    return request.issueId === this.issue().id;
  }

  /**
   * A fix may be posted when it is one, is about this issue, the issue's branch is a merge request
   * of a mapped project, and it was not posted (or is not being posted) already.
   */
  protected postable(request: AiRequest): boolean {
    const result = this.fixResult(request);
    return (
      request.status === 'succeeded' &&
      result?.status === 'fixed' &&
      this.open() &&
      this.ownAnswer(request) &&
      this.target() !== null &&
      (request.post === null || request.post.status === 'failed')
    );
  }

  protected async ask(feature: Feature, refresh = false): Promise<void> {
    if (this.busy(feature)) return;
    const issue = this.issue();
    const generation = this.generation;
    this.error.set(null);
    this.announcement.set(null);
    this.confirming.set(null);
    this.sending.update((all) => ({ ...all, [feature]: true }));
    try {
      const answer = await ok(
        this.api.client.POST('/api/v0/issues/{id}/ai/{feature}', {
          params: { path: { id: issue.id, feature } },
          body: refresh ? { refresh: true } : {},
        }),
      );
      if (generation !== this.generation) return;
      this.store(answer, true);
      this.follow(answer, generation);
    } catch (err) {
      if (generation !== this.generation) return;
      this.error.set(askErrorText(err));
    } finally {
      if (generation === this.generation) {
        this.sending.update((all) => ({ ...all, [feature]: false }));
      }
    }
  }

  protected askPost(request: AiRequest): void {
    this.error.set(null);
    this.confirming.set(request.id);
  }

  protected cancelPost(): void {
    this.confirming.set(null);
  }

  /** The second step: the person confirmed; the post is sent. */
  protected async post(request: AiRequest): Promise<void> {
    if (this.posting() || this.confirming() !== request.id) return;
    const generation = this.generation;
    this.posting.set(true);
    this.error.set(null);
    try {
      const answer = await ok(
        this.api.client.POST('/api/v0/ai-requests/{id}/post', {
          params: { path: { id: request.id } },
          body: {},
        }),
      );
      if (generation !== this.generation) return;
      this.confirming.set(null);
      this.store(answer);
      this.follow(answer, generation);
    } catch (err) {
      if (generation !== this.generation) return;
      this.confirming.set(null);
      this.error.set(postErrorText(err));
    } finally {
      if (generation === this.generation) this.posting.set(false);
    }
  }

  private async load(issue: AiIssue, generation: number): Promise<void> {
    try {
      const project = await ok(
        this.api.client.GET('/api/v0/projects/{id}', { params: { path: { id: issue.projectId } } }),
      );
      const orgAi = await ok(
        this.api.client.GET('/api/v0/organizations/{id}/ai', {
          params: { path: { id: project.organizationId } },
        }),
      );
      if (generation !== this.generation) return;
      this.excluded.set(project.autoFix.excludedFromAi);
      this.orgAi.set(orgAi);
      if (!this.visible()) return;
      // A fix of an excluded project is never posted: the server refuses it.
      if (orgAi.features.fix && project.scmConnectionId !== null && !this.excluded()) {
        void this.loadTarget(issue, generation);
      }
      const latest = await ok(
        this.api.client.GET('/api/v0/issues/{id}/ai', { params: { path: { id: issue.id } } }),
      );
      if (generation !== this.generation) return;
      // Only the features the organisation has on are shown, and only they are followed.
      const on = (feature: Feature) => (orgAi.features[feature] ? latest[feature] : null);
      const requests = { explain: on('explain'), triage: on('triage'), fix: on('fix') };
      this.requests.set(requests);
      for (const request of Object.values(requests)) {
        if (request) this.follow(request, generation);
      }
    } catch (err) {
      // Without the organisation's settings the panel stays hidden: nothing can be asked.
      if (generation !== this.generation || this.orgAi() === null) return;
      this.error.set(problemMessage(err));
    }
  }

  /** The merge request of the issue's branch; none (no Post) when it is not one or unreadable. */
  private async loadTarget(issue: AiIssue, generation: number): Promise<void> {
    try {
      const branch = await findBranch(this.api, issue.projectId, issue.branchId);
      let target = postTarget(branch);
      if (target === null && branch.kind === 'merge_request' && branch.mrUrl === null) {
        target = postTarget(branch, await this.projectProvider(issue.projectId));
      }
      if (generation === this.generation) this.target.set(target);
    } catch {
      // Without the branch there is nothing to post to: Post is not offered.
    }
  }

  /** The provider of the project's connection (project.read, as the panel's page); null if unread. */
  private async projectProvider(projectId: string): Promise<ScmProvider | null> {
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/projects/{id}/fixes/settings', {
          params: { path: { id: projectId } },
        }),
      );
      return answer.preconditions.provider;
    } catch {
      return null;
    }
  }

  /**
   * Keeps a request's latest state. `fresh` is an answer to the person's ask or a poll: when it
   * has just succeeded, the status region says so.
   */
  private store(request: AiRequest, fresh = false): void {
    const before = this.requests()[request.feature];
    this.requests.update((all) => ({ ...all, [request.feature]: request }));
    const wasWaiting = before === null || before.id !== request.id || this.pending(before);
    if (fresh && wasWaiting && request.status === 'succeeded') {
      this.announcement.set($localize`:@@ai.panel.ready:The answer is ready.`);
    }
  }

  /** Reads a request again while the model works on it, or while its post is queued. */
  private follow(request: AiRequest, generation: number, polls = 0, failures = 0): void {
    const waiting =
      this.pending(request) || (request.post?.status === 'queued' && polls < POST_POLLS);
    if (!waiting) return;
    const timer = setTimeout(
      () => {
        this.timers.delete(timer);
        void this.poll(request, generation, polls + 1, failures);
      },
      this.pollMs * 2 ** failures,
    );
    this.timers.add(timer);
  }

  /**
   * One read of a followed request. A failed read is tried again with a growing delay; after
   * {@link POLL_FAILURES} in a row the request is dropped from the panel, so nothing stays
   * "asking" for ever and the person can ask again (the server answers with the same request if
   * it is still in flight).
   */
  private async poll(
    previous: AiRequest,
    generation: number,
    polls: number,
    failures: number,
  ): Promise<void> {
    if (generation !== this.generation) return;
    try {
      const request = await ok(
        this.api.client.GET('/api/v0/ai-requests/{id}', { params: { path: { id: previous.id } } }),
      );
      if (generation !== this.generation) return;
      this.store(request, true);
      this.follow(request, generation, polls);
    } catch {
      if (generation !== this.generation) return;
      if (failures + 1 < POLL_FAILURES) {
        this.follow(previous, generation, polls, failures + 1);
        return;
      }
      if (this.requests()[previous.feature]?.id === previous.id) {
        // A post that could not be followed keeps its last known state; an answer is dropped.
        if (this.pending(previous)) {
          this.requests.update((all) => ({ ...all, [previous.feature]: null }));
        }
      }
      this.error.set($localize`:@@ai.panel.pollFailed:The answer could not be read; ask again.`);
    }
  }

  private stopPolling(): void {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }
}

function detailOf(err: ApiError): string | null {
  return err.problem?.detail ?? null;
}

/** llm.md §16: why an ask was refused, in the page's own words. */
function askErrorText(err: unknown): string {
  if (!(err instanceof ApiError)) return problemMessage(err);
  switch (err.code) {
    case 'AI_DISABLED':
      return $localize`:@@ai.panel.error.disabled:This organization may not use AI.`;
    case 'AI_NOT_ELIGIBLE':
      switch (detailOf(err)) {
        case 'secret_rule':
          return $localize`:@@ai.panel.error.secretRule:Findings of secret rules are never sent.`;
        case 'credentials_file':
          return $localize`:@@ai.panel.error.credentialsFile:Issues in credential files are never sent.`;
        case 'excluded_path':
        case 'excluded_project':
          return $localize`:@@ai.panel.error.excluded:An administrator excluded this issue's path or project.`;
        case 'not_open':
          return notOpenText();
        case 'no_location':
        case 'no_snippet':
          return $localize`:@@ai.panel.error.noSnippet:A fix needs the code around the issue.`;
        default:
          return $localize`:@@ai.panel.error.notEligible:This issue cannot be sent to the AI assistant.`;
      }
    case 'AI_QUOTA_EXCEEDED':
      return $localize`:@@ai.panel.error.quota:The organization's AI budget for today is used up.`;
    case 'RATE_LIMITED':
      return $localize`:@@ai.panel.error.rateLimited:You asked too often; try again in a few minutes.`;
    default:
      return problemMessage(err);
  }
}

/** llm.md §8.2: why a post was refused. */
function postErrorText(err: unknown): string {
  if (!(err instanceof ApiError) || err.code !== 'AI_POST_NOT_POSSIBLE') return problemMessage(err);
  switch (detailOf(err)) {
    case 'not_merge_request':
      return $localize`:@@ai.panel.post.notMergeRequest:This issue is not on a merge request.`;
    case 'not_mapped':
      return $localize`:@@ai.panel.post.notMapped:The project is not mapped to GitLab or GitHub.`;
    case 'not_latest':
      return $localize`:@@ai.panel.post.notLatest:A newer analysis exists; ask for a new fix.`;
    case 'no_scm_context':
      return $localize`:@@ai.panel.post.noScmContext:Analyse the latest commit first.`;
    case 'already_posted':
      return $localize`:@@ai.panel.post.alreadyPosted:Already posted.`;
    case 'not_open':
      return notOpenText();
    default:
      return $localize`:@@ai.panel.post.notFix:Only a suggested fix can be posted.`;
  }
}

function notOpenText(): string {
  return $localize`:@@ai.panel.error.notOpen:Only open issues can be triaged or fixed.`;
}

/** llm.md §8.4: a failed post's reason. */
function postFailureText(reason: string | null): string {
  switch (reason) {
    case 'not_head':
      return $localize`:@@ai.panel.post.failed.notHead:Not posted: the merge request has a newer commit; analyse it and ask again.`;
    case 'changed':
      return $localize`:@@ai.panel.post.failed.changed:Not posted: the code on the merge request differs.`;
    case 'not_on_diff':
      return $localize`:@@ai.panel.post.failed.notOnDiff:Not posted: the lines are not added lines of the merge request.`;
    case 'closed':
      return $localize`:@@ai.panel.post.failed.closed:Not posted: the merge request is closed.`;
    case 'position_rejected':
      return $localize`:@@ai.panel.post.failed.position:Not posted: the merge request refused the position of the lines.`;
    case 'refused':
      return $localize`:@@ai.panel.post.failed.refused:Not posted: GitLab or GitHub refused the comment.`;
    case 'unreachable':
      return $localize`:@@ai.panel.post.failed.unreachable:Not posted: GitLab or GitHub could not be reached.`;
    case 'not_understood':
      return $localize`:@@ai.panel.post.failed.notUnderstood:Not posted: the answer of GitLab or GitHub was not understood.`;
    case 'not_possible':
      return $localize`:@@ai.panel.post.failed.notPossible:Not posted: the suggestion no longer applies to the issue; ask for a new fix.`;
    default:
      return $localize`:@@ai.panel.post.failed.other:Not posted.`;
  }
}
