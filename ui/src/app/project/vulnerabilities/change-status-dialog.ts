import {
  afterNextRender,
  Component,
  computed,
  inject,
  Injector,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import type { ElementRef } from '@angular/core';
import { Api, ok } from '../../api/api';
import { fieldErrors, isRetryable, problemMessage } from '../../api/errors';
import type { RequestBody, ResponseBody } from '../../api/types';
import { LabelPipe } from '../../i18n/label.pipe';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { inputValue } from '../../shared/forms';
import { RetryOffer } from '../../shared/retry';

export type VulnerabilityItem = ResponseBody<
  '/api/v0/projects/{id}/vulnerabilities',
  'get'
>['items'][number];
type Decision = RequestBody<'/api/v0/projects/{id}/vulnerability-decisions', 'put'>;
export type DecisionStatus = Decision['status'];
export type Reason = NonNullable<Decision['reason']>;

/** The one target a view is about (`kind:id` in the URL), named for the "Only <target>" choice. */
export interface DialogTarget {
  kind: 'branch' | 'version';
  id: string;
  name: string;
}

export const VEX_REASONS: Reason[] = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
];
const STATUSES: DecisionStatus[] = ['open', 'false_positive', 'wont_fix'];

/**
 * Change status (vuln 2b §9.3): the status of one (package, vulnerability) for the whole project,
 * or, in the one-target view, for that target only. Not affected needs a VEX reason and a
 * comment, Affected, won't fix a comment; Save stays disabled until they are given, and while
 * nothing differs from the current decision. Choosing the project while the viewed target has its
 * own decision replaces that override (D10).
 */
@Component({
  selector: 'q-change-status-dialog',
  imports: [LabelPipe],
  templateUrl: './change-status-dialog.html',
  styleUrl: './change-status-dialog.css',
})
export class ChangeStatusDialog {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  readonly projectId = input.required<string>();
  /** The viewed target; null in the cross-target view. */
  readonly target = input<DialogTarget | null>(null);
  /** The decision was saved. */
  readonly saved = output();

  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly statusField = viewChild<ElementRef<HTMLSelectElement>>('statusField');
  private readonly reasonField = viewChild<ElementRef<HTMLSelectElement>>('reasonField');
  private readonly commentField = viewChild<ElementRef<HTMLTextAreaElement>>('commentField');

  protected readonly statuses = STATUSES;
  protected readonly reasons = VEX_REASONS;
  protected readonly item = signal<VulnerabilityItem | null>(null);
  protected readonly status = signal<DecisionStatus>('open');
  protected readonly reason = signal<Reason | ''>('');
  protected readonly comment = signal('');
  protected readonly appliesTo = signal<'project' | 'target'>('project');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly reasonError = signal<string | null>(null);
  protected readonly commentError = signal<string | null>(null);
  protected readonly retryOffer = new RetryOffer<true>();

  protected readonly needsReason = computed(() => this.status() === 'false_positive');
  protected readonly needsComment = computed(() => this.status() !== 'open');
  protected readonly ready = computed(
    () =>
      (!this.needsReason() || this.reason() !== '') &&
      (!this.needsComment() || this.comment().trim() !== ''),
  );
  /**
   * Status, reason, comment and Applies to all equal the card's current decision (final review
   * F5); without one, Open with no reason, no comment, for the project. Save would only stamp it
   * with another name and date.
   */
  protected readonly unchanged = computed(() => {
    const item = this.item();
    if (!item) return true;
    const decision = item.decision;
    const appliesTo =
      this.target() && decision && decision.scope !== 'project' ? 'target' : 'project';
    return (
      this.status() === (decision?.status ?? 'open') &&
      (this.needsReason() ? this.reason() : '') === (decision?.reason ?? '') &&
      this.comment().trim() === (decision?.comment ?? '').trim() &&
      this.appliesTo() === appliesTo
    );
  });

  /** Opens the dialog on a card, preselecting its current decision. */
  open(item: VulnerabilityItem): void {
    const decision = item.decision;
    this.item.set(item);
    this.status.set(decision?.status ?? item.status);
    this.reason.set(decision?.reason ?? '');
    this.comment.set(decision?.comment ?? '');
    const own = decision !== null && decision.scope !== 'project';
    this.appliesTo.set(this.target() && own ? 'target' : 'project');
    this.error.set(null);
    this.reasonError.set(null);
    this.commentError.set(null);
    this.retryOffer.clear();
    openAfterRender(this.injector, () => this.dialog()?.nativeElement);
    // After the dialog is open: the first field takes focus (showModal alone picks the first control).
    afterNextRender(() => this.statusField()?.nativeElement.focus(), { injector: this.injector });
  }

  protected close(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.retryOffer.clear();
  }

  protected setStatus(event: Event): void {
    const value = inputValue(event);
    this.status.set(STATUSES.find((s) => s === value) ?? 'open');
    this.reasonError.set(null);
    this.commentError.set(null);
  }

  protected setReason(event: Event): void {
    const value = inputValue(event);
    this.reason.set(VEX_REASONS.find((r) => r === value) ?? '');
    this.reasonError.set(null);
  }

  protected setComment(event: Event): void {
    this.comment.set(inputValue(event));
    this.commentError.set(null);
  }

  protected statusLabel(status: DecisionStatus): string {
    if (status === 'false_positive') {
      return $localize`:@@vulns.dialog.status.falsePositive:Not affected (false positive)`;
    }
    return status === 'wont_fix'
      ? $localize`:@@vulns.dialog.status.wontFix:Affected, won't fix`
      : $localize`:@@vulns.dialog.status.open:Open`;
  }

  protected setAppliesTo(value: 'project' | 'target'): void {
    this.appliesTo.set(value);
  }

  protected async submit(event: Event): Promise<void> {
    event.preventDefault();
    const item = this.item();
    if (!item || this.busy() || !this.ready() || this.unchanged()) return;
    const target = this.target();
    const own = target && item.decision && item.decision.scope !== 'project';
    const reason = this.reason();
    const comment = this.comment().trim();
    const body: Decision = {
      packageName: item.packageName,
      vulnerabilityId: item.vulnerabilityId,
      scope:
        target && this.appliesTo() === 'target'
          ? { kind: target.kind, id: target.id }
          : { kind: 'project' },
      status: this.status(),
      ...(this.needsReason() && reason !== '' ? { reason } : {}),
      ...(comment !== '' ? { comment } : {}),
      ...(target && own && this.appliesTo() === 'project'
        ? { replaceOverrideOf: { kind: target.kind, id: target.id } }
        : {}),
    };
    this.busy.set(true);
    this.error.set(null);
    this.retryOffer.clear();
    try {
      await ok(
        this.api.client.PUT('/api/v0/projects/{id}/vulnerability-decisions', {
          params: { path: { id: this.projectId() } },
          body,
        }),
      );
      this.close();
      this.saved.emit();
    } catch (err) {
      const fields = fieldErrors(err);
      if (fields['body.reason'] !== undefined) {
        this.reasonError.set(
          $localize`:@@vulns.dialog.reasonRequired:Choose a reason for Not affected.`,
        );
      }
      if (fields['body.comment'] !== undefined) {
        this.commentError.set(
          $localize`:@@vulns.dialog.commentRequired:Add a comment to explain the decision.`,
        );
      }
      if (this.reasonError()) this.reasonField()?.nativeElement.focus();
      else if (this.commentError()) this.commentField()?.nativeElement.focus();
      else {
        this.error.set(problemMessage(err));
        if (isRetryable(err)) this.retryOffer.offer(true, err.retryAfter);
      }
    } finally {
      this.busy.set(false);
    }
  }

  protected retry(): void {
    if (this.retryOffer.take()) void this.submit(new Event('submit'));
  }
}
