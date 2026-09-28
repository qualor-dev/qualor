import { DOCUMENT } from '@angular/common';
import {
  Component,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { OrgContext } from '../org/org-context';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { copyName } from '../shared/names';

export type Gate = ItemOf<'/api/v0/quality-gates'>;

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
 */
@Component({
  selector: 'q-gates-page',
  imports: [RouterLink],
  templateUrl: './gates.page.html',
})
export class GatesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
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

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      if (organizationId) void this.list.reset(organizationId);
    });
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

  protected async remove(gate: Gate): Promise<void> {
    if (this.busy()) return;
    const question = gate.isDefault
      ? $localize`:@@gates.confirmDeleteDefault:Delete the default quality gate "${gate.name}:name:"? The organization is then left without a default gate: every project that uses the default is no longer gated until you make another gate the default.`
      : $localize`:@@gates.confirmDelete:Delete the quality gate "${gate.name}:name:"? Its projects fall back to the default gate.`;
    if (!window.confirm(question)) return;
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
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const nameRefused = fieldErrors(err)['body.name'] !== undefined;
      if (nameRefused && kind === 'create') {
        this.nameError.set(
          $localize`:@@gates.nameInvalid:Enter a name of at most 100 characters, without control characters.`,
        );
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
