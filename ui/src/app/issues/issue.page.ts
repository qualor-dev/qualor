import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  type ElementRef,
  effect,
  inject,
  input,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { isRetryable, problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { can } from '../auth/permissions';
import { notFound } from '../project/branches';
import { CurrentProject } from '../project/current-project';
import { DateTimePipe } from '../shared/date-time.pipe';
import { inputValue } from '../shared/forms';
import { isUuid } from '../shared/ids';
import { KeysetList } from '../shared/keyset';
import { safeHelpUri } from '../shared/links';
import { RetryOffer } from '../shared/retry';
import { AiPanel } from './ai-panel';
import { SEVERITIES } from './issue-filters';
import {
  allowedTargets,
  COMMENT_MAX_LENGTH,
  needsComment,
  type TransitionTarget,
} from './transitions';

export type IssueDetail = ResponseBody<'/api/v0/issues/{id}', 'get'>;
type ChangelogEntry = ResponseBody<'/api/v0/issues/{id}/changelog', 'get'>['items'][number];
type Severity = IssueDetail['severity'];

interface Snippet {
  startLine: number;
  lines: string[];
}

/** llm.md §7: with an AI triage suggestion, the comment's own part is at most this long. */
const SUGGESTION_COMMENT_MAX_LENGTH = 1700;

/** An oldest-first history is walked to its end after a change, for at most this many pages. */
const CHANGELOG_PAGES = 20;

/** The snippet the report carried (report-format.md §7), read defensively: the API types it open. */
export function readSnippet(raw: unknown): Snippet | null {
  const s = raw as Partial<Snippet> | null;
  if (typeof s !== 'object' || s === null || typeof s.startLine !== 'number') return null;
  if (!Array.isArray(s.lines) || !s.lines.every((l) => typeof l === 'string')) return null;
  return { startLine: s.startLine, lines: s.lines };
}

/**
 * One issue: its location and snippet, the rule and its description, the status change and
 * severity override, and the changelog. Rule descriptions are Markdown from analyzers; they are
 * shown as plain text (plan 1F ruling Y5), never rendered as HTML.
 *
 * - The history is oldest first; after a change it is loaded to its end, so the new entry (the
 *   server logs transitions and severity overrides) shows at the bottom.
 * - The route reuses this component when only `:issueId` changes: every piece of per-issue state
 *   is reset then, and an answer for the previous issue is ignored.
 * - After a change, focus moves to the "Change" heading and the result is announced in a live
 *   region, since the button used may be gone.
 * - A 503 `CONCURRENCY_CONFLICT` offers to send the same change again once `Retry-After` passed.
 * - An id that is not a UUID is "not found" without asking the server.
 */
@Component({
  selector: 'q-issue-page',
  imports: [AiPanel, DateTimePipe, LabelPipe, RouterLink],
  templateUrl: './issue.page.html',
})
export class IssuePage {
  private readonly api = inject(Api);
  private readonly document = inject(DOCUMENT);
  private readonly project = inject(CurrentProject);
  readonly projectId = input.required<string>();
  readonly issueId = input.required<string>();

  /**
   * What the caller's role allows on this project (rbac-audit.md §17): status changes and the
   * severity (`issue.triage`), and the AI requests (`ai.use`). Hidden, not refused with 403, while
   * the project has not said so.
   */
  protected readonly canTriage = computed(() =>
    this.project.canChange(this.projectId(), 'issue.triage'),
  );
  protected readonly canAsk = computed(() => this.project.canChange(this.projectId(), 'ai.use'));
  /** The project has loaded and the caller's role does not allow triage (a viewer). */
  protected readonly readOnlyRole = computed(() => {
    const permissions = this.project.permissions(this.projectId());
    return permissions !== undefined && !can(permissions, 'issue.triage');
  });

  protected readonly validId = computed(() => isUuid(this.issueId()));
  protected readonly issue = resource({
    params: () => (this.validId() ? this.issueId() : undefined),
    loader: ({ params }) =>
      ok(this.api.client.GET('/api/v0/issues/{id}', { params: { path: { id: params } } })),
  });
  /** The issue, or null while loading or after an error (`value()` throws in the error state). */
  protected readonly current = computed(() => (this.issue.hasValue() ? this.issue.value() : null));
  protected readonly loadError = computed(() => {
    if (!this.validId()) return problemMessage(notFound());
    const error = this.issue.error();
    return error ? problemMessage(error) : null;
  });
  protected readonly changelog = new KeysetList<ChangelogEntry, string>((id, cursor) =>
    ok(
      this.api.client.GET('/api/v0/issues/{id}/changelog', {
        params: { path: { id }, query: { limit: 100, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );

  protected readonly snippet = computed(() => readSnippet(this.current()?.snippet));
  protected readonly helpUri = computed(() => safeHelpUri(this.current()?.rule.helpUri));
  protected readonly targets = computed(() => allowedTargets(this.current()?.status ?? ''));
  protected readonly comment = signal('');
  /**
   * The AI triage suggestion the person chose to act on (llm.md §7): sent with a false-positive
   * transition only, so the changelog records that it was shown; the decision stays theirs.
   */
  protected readonly suggestionId = signal<string | null>(null);
  protected readonly severity = signal<Severity | null>(null);
  /** Setting the current severity again logs nothing (api.md), so it is not offered. */
  protected readonly severityChanged = computed(() => {
    const chosen = this.severity();
    return chosen !== null && chosen !== this.current()?.severity;
  });
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  /** The change a 503 refused, to send again as it was. */
  protected readonly retryOffer = new RetryOffer<() => Promise<void>>();
  /** Incremented per issue and per change: an answer for an older one is ignored. */
  private generation = 0;
  private readonly actionsHeading = viewChild<ElementRef<HTMLElement>>('actionsHeading');
  private readonly commentField = viewChild<ElementRef<HTMLTextAreaElement>>('commentField');

  protected readonly severities = SEVERITIES;
  protected readonly commentMax = computed(() =>
    this.suggestionId() ? SUGGESTION_COMMENT_MAX_LENGTH : COMMENT_MAX_LENGTH,
  );
  protected readonly needsComment = needsComment;
  protected readonly inputValue = inputValue;

  constructor() {
    effect(() => {
      // A malformed issue id asks the server nothing, the project included.
      if (this.validId()) this.project.use(this.projectId());
    });
    effect(() => {
      const id = this.issueId();
      const valid = this.validId();
      untracked(() => {
        this.generation++;
        this.comment.set('');
        this.suggestionId.set(null);
        this.severity.set(null);
        this.error.set(null);
        this.announcement.set(null);
        this.busy.set(false);
        this.retryOffer.clear();
        if (valid) void this.changelog.reset(id);
      });
    });
    inject(DestroyRef).onDestroy(() => this.retryOffer.clear());
  }

  protected changeText(entry: ChangelogEntry): string {
    if (entry.field === 'comment') return '';
    const kind = entry.field === 'status' ? 'status' : 'severity';
    const field =
      entry.field === 'status'
        ? $localize`:@@issue.changelog.status:Status`
        : $localize`:@@issue.changelog.severity:Severity`;
    return `${field}: ${label(kind, entry.oldValue)} → ${label(kind, entry.newValue)}`;
  }

  /**
   * The AI panel's "Mark as false positive…": the person's own transition form, with an empty
   * comment for them to write, ready to send the suggestion's id with the false-positive change.
   * Nothing changes until they press "False positive".
   */
  protected openFalsePositive(suggestionId: string): void {
    this.suggestionId.set(suggestionId);
    this.comment.set('');
    const field = this.commentField()?.nativeElement;
    if (field) {
      field.value = '';
      field.focus();
    }
  }

  protected dropSuggestion(): void {
    this.suggestionId.set(null);
    this.commentField()?.nativeElement.focus();
  }

  protected async transition(to: TransitionTarget): Promise<void> {
    const id = this.issueId();
    const comment = this.comment().trim();
    if (this.busy() || (needsComment(to) && !comment)) return;
    // The suggestion goes with the false-positive change only. It is dropped once a change
    // succeeds (another status included); a refused change keeps it for the next attempt.
    const suggestionId = to === 'false_positive' ? this.suggestionId() : null;
    await this.change(
      id,
      () =>
        ok(
          this.api.client.POST('/api/v0/issues/{id}/transition', {
            params: { path: { id } },
            body: {
              to,
              ...(comment ? { comment } : {}),
              ...(suggestionId ? { suggestionId } : {}),
            },
          }),
        ),
      (updated) =>
        $localize`:@@issue.changed.status:Status changed to ${label('status', updated.status)}:status:.`,
      () => this.suggestionId.set(null),
    );
  }

  protected setSeverity(event: Event): void {
    this.severity.set(inputValue(event) as Severity);
  }

  protected async saveSeverity(event: Event): Promise<void> {
    event.preventDefault();
    const id = this.issueId();
    const severity = this.severity();
    if (!severity || !this.severityChanged() || this.busy()) return;
    await this.change(
      id,
      () =>
        ok(
          this.api.client.PATCH('/api/v0/issues/{id}', {
            params: { path: { id } },
            body: { severity },
          }),
        ),
      (updated) =>
        $localize`:@@issue.changed.severity:Severity set to ${label('severity', updated.severity)}:severity:.`,
    );
  }

  protected async retry(): Promise<void> {
    if (this.busy()) return;
    const action = this.retryOffer.take();
    if (action) await action();
  }

  /**
   * Sends one change for issue `id`; its answer is dropped when another issue or change followed.
   * `done` runs once it succeeded (a retry of a refused change included).
   */
  private async change(
    id: string,
    request: () => Promise<IssueDetail>,
    announce: (updated: IssueDetail) => string,
    done?: () => void,
  ): Promise<void> {
    const generation = ++this.generation;
    const current = () => generation === this.generation && this.issueId() === id;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    this.retryOffer.clear();
    try {
      const updated = await request();
      if (!current()) return;
      this.issue.set(updated);
      done?.();
      this.comment.set('');
      this.announcement.set(announce(updated));
      await this.changelog.reloadToEnd(CHANGELOG_PAGES);
      if (current()) this.actionsHeading()?.nativeElement.focus();
    } catch (err) {
      if (!current()) return;
      this.error.set(problemMessage(err));
      if (isRetryable(err)) {
        this.retryOffer.offer(() => this.change(id, request, announce, done), err.retryAfter);
      }
      const active = this.document.activeElement;
      if (active === null || active === this.document.body) {
        this.actionsHeading()?.nativeElement.focus();
      }
    } finally {
      if (current()) this.busy.set(false);
    }
  }
}
