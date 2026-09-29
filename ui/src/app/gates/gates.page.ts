import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  resource,
  signal,
  viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { Icon } from '../shared/icon';
import { copyName } from '../shared/names';
import { PageHeader } from '../shared/page-header';

export type Gate = ItemOf<'/api/v0/quality-gates'>;

/** Usage counts read at most this many pages of 500 projects (5 000 projects). */
const USAGE_PAGES = 10;

/**
 * The organisation's quality gates (gates.md): the built-in one, copies, and the default. Only org
 * admins see the buttons (the server checks the role again); the built-in gate is read-only
 * (409 `BUILTIN_READ_ONLY`), so it is only offered for copying. Names need not be unique.
 *
 * - Deleting the default gate is allowed and leaves the organisation without one: projects that
 *   use the default are no longer gated. Its confirmation says so.
 * - After a change the list is refreshed in place (rows keep their elements), the result is
 *   announced in the live region, and focus moves on only when the button used is gone
 *   (`keepFocus`): to the same row, the next one, or the heading.
 *
 * Step 6 of the redesign (spec §7.6): the list on the ink band with "New gate" as a dialog; each
 * gate's conditions summed up; the projects using it, counted from `GET /projects` (a project
 * without a gate uses the default; at most 5 000 projects, and the page says when there are more);
 * quiet row actions; a deletion asks in the page's dialog instead of the browser's `confirm()`.
 */
@Component({
  selector: 'q-gates-page',
  imports: [Icon, PageHeader, RouterLink],
  templateUrl: './gates.page.html',
  styleUrl: './gates.page.css',
  host: { class: 'bleed' },
})
export class GatesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly session = inject(SessionStore);
  protected readonly org = inject(OrgContext);

  protected readonly list = new KeysetList<Gate, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/quality-gates', {
        params: { query: { organizationId, limit: 100, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly newName = signal('');
  protected readonly nameError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly inputValue = inputValue;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  /** A refused creation other than its name, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  /** The deletion the confirmation dialog asks about; null while it is closed. */
  protected readonly pendingDelete = signal<{ gate: Gate; question: string } | null>(null);

  /**
   * How many projects of the organisation use each gate id (`null`: the default). Only counted
   * for someone who sees every project: a project grant lists only its own (step 6 review).
   */
  private readonly usage = resource({
    params: () => {
      const organizationId = this.org.currentId();
      return this.session.seesWholeOrg(organizationId) ? (organizationId ?? undefined) : undefined;
    },
    loader: async ({ params }) => {
      const counts = new Map<string | null, number>();
      let cursor: string | undefined;
      let partial = false;
      for (let pages = 0; pages < USAGE_PAGES; pages++) {
        const result = await ok(
          this.api.client.GET('/api/v0/projects', {
            params: {
              query: { organizationId: params, limit: 500, ...(cursor ? { cursor } : {}) },
            },
          }),
        );
        for (const p of result.items) {
          counts.set(p.qualityGateId, (counts.get(p.qualityGateId) ?? 0) + 1);
        }
        partial = result.nextCursor !== null;
        if (!result.nextCursor) break;
        cursor = result.nextCursor;
      }
      return { counts, partial };
    },
  });
  protected readonly usagePartial = computed(
    () => this.usage.hasValue() && this.usage.value().partial,
  );

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      if (organizationId) void this.list.reset(organizationId);
    });
  }

  /** The projects using a gate; null while unknown. */
  protected usageOf(gate: Gate): number | null {
    if (!this.usage.hasValue()) return null;
    const { counts } = this.usage.value();
    return (counts.get(gate.id) ?? 0) + (gate.isDefault ? (counts.get(null) ?? 0) : 0);
  }

  /** "2 conditions, 1 on new code": what a gate checks, at a glance. */
  protected summary(gate: Gate): string {
    const all = gate.conditions.length;
    const onNew = gate.conditions.filter((c) => c.metric.startsWith('new_')).length;
    if (all === 0) return $localize`:@@gates.summary.none:No conditions`;
    if (onNew === all) {
      return all === 1
        ? $localize`:@@gates.summary.oneNew:1 condition on new code`
        : $localize`:@@gates.summary.allNew:${all}:count: conditions on new code`;
    }
    if (onNew === 0) {
      return all === 1
        ? $localize`:@@gates.summary.one:1 condition`
        : $localize`:@@gates.summary.many:${all}:count: conditions`;
    }
    return $localize`:@@gates.summary.some:${all}:count: conditions, ${onNew}:onNew: on new code`;
  }

  protected openCreate(): void {
    this.nameError.set(null);
    this.createError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected setName(event: Event): void {
    this.newName.set(inputValue(event));
    this.nameError.set(null);
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    const name = this.newName().trim();
    if (!organizationId || !name) return;
    await this.run(async () => {
      const gate = await ok(
        this.api.client.POST('/api/v0/quality-gates', { body: { organizationId, name } }),
      );
      await this.router.navigate(['/gates', gate.id]);
    }, 'create');
  }

  protected async copy(gate: Gate): Promise<void> {
    const name = copyName(gate.name, (n) => $localize`:@@gates.copyName:${n}:name: (copy)`);
    await this.run(async () => {
      const copy = await ok(
        this.api.client.POST('/api/v0/quality-gates/{id}/copy', {
          params: { path: { id: gate.id } },
          body: { name },
        }),
      );
      await this.router.navigate(['/gates', copy.id]);
    }, 'copy');
  }

  protected async setDefault(gate: Gate): Promise<void> {
    await this.run(async () => {
      await ok(
        this.api.client.POST('/api/v0/quality-gates/{id}/set-default', {
          params: { path: { id: gate.id } },
        }),
      );
      await this.list.refresh();
      this.announcement.set(
        $localize`:@@gates.madeDefault:${gate.name}:name: is now the default quality gate.`,
      );
      keepFocus(
        this.injector,
        this.document,
        () => rowByKey(this.table()?.nativeElement, gate.id)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  protected remove(gate: Gate): void {
    if (this.busy()) return;
    const question = gate.isDefault
      ? $localize`:@@gates.confirmDeleteDefault:Delete the default quality gate "${gate.name}:name:"? The organization is then left without a default gate: every project that uses the default is no longer gated until you make another gate the default.`
      : $localize`:@@gates.confirmDelete:Delete the quality gate "${gate.name}:name:"? Its projects fall back to the default gate.`;
    this.pendingDelete.set({ gate, question });
    openAfterRender(
      this.injector,
      () => this.confirmDialog()?.nativeElement,
      () => this.pendingDelete() !== null,
    );
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is deleted. */
  protected cancelDelete(): void {
    this.pendingDelete.set(null);
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected async confirmDelete(): Promise<void> {
    const pending = this.pendingDelete();
    if (!pending) return;
    this.cancelDelete();
    await this.delete(pending.gate);
  }

  private async delete(gate: Gate): Promise<void> {
    const index = this.list.items().findIndex((g) => g.id === gate.id);
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/quality-gates/{id}', { params: { path: { id: gate.id } } }),
      );
      await this.list.refresh();
      this.announcement.set($localize`:@@gates.deleted:Quality gate ${gate.name}:name: deleted.`);
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  /** Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. */
  private async run(
    action: () => Promise<void>,
    kind: 'create' | 'copy' | 'change' = 'change',
  ): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.nameError.set(null);
    this.createError.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const nameRefused = fieldErrors(err)['body.name'] !== undefined;
      if (nameRefused && kind === 'create') {
        this.nameError.set(
          $localize`:@@gates.nameInvalid:Enter a name of at most 100 characters, without control characters.`,
        );
        return;
      } else if (kind === 'create') {
        // The dialog is still open: the reason goes there, and focus stays in it.
        this.createError.set(problemMessage(err));
        return;
      } else if (nameRefused && kind === 'copy') {
        this.error.set(
          $localize`:@@gates.copyNameInvalid:The copy could not be named after this gate. Create a new gate instead.`,
        );
      } else {
        this.error.set(problemMessage(err));
      }
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
