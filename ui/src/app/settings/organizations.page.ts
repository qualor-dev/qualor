import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  type ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { Organization } from '../api/types';
import { AuthService } from '../auth/auth.service';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { refreshWhilePending } from '../jira/refresh';
import { Icon } from '../shared/icon';

/** The server's organisation key (`ORGANIZATION_KEY_PATTERN`): 2 to 64 of a-z, 0-9 and "-". */
const KEY_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/;
const KEY_MAX_LENGTH = 64;
/** The server's bound on a name (`text(255)`). */
const NAME_MAX_LENGTH = 255;
/** Projects read to count what a delete removes; more than this reads "more than 100". */
const PROJECT_PAGE_SIZE = 100;

type Field = 'name' | 'key';

/** A key made from a name: its letters and digits in lowercase, anything else as one hyphen. */
export function keyFrom(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+/, '')
    .slice(0, KEY_MAX_LENGTH)
    .replace(/-+$/, '');
}

/**
 * Settings → Organizations, for instance admins (`GET/POST /organizations`): the organisations of
 * this server, the current one marked, and "New organization" in a dialog. The server makes the
 * creator the new organisation's admin, so the session is read again (`GET /auth/me`) and the
 * header's switcher lists it at once. "Delete" asks for the organization's key in a dialog
 * (`DELETE /organizations/{id}?confirm=<key>`, as the project danger zone does); the server
 * answers 202 and deletes in the background, so the row reads "Deleting…" and the list is read
 * again every 3 s until the organization is gone. The list is the header's own (`OrgContext`), so
 * the two never disagree: once the current organization is gone, the header shows another one.
 */
@Component({
  selector: 'q-organizations-page',
  imports: [DateTimePipe, Icon],
  templateUrl: './organizations.page.html',
  styleUrl: './organizations.page.css',
})
export class OrganizationsPage {
  private readonly api = inject(Api);
  private readonly auth = inject(AuthService);
  private readonly session = inject(SessionStore);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly org = inject(OrgContext);
  protected readonly isAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  /** Why the organisations could not be read, if they could not. */
  protected readonly loadError = computed(() => {
    const err = this.org.organizations.error();
    return err ? problemMessage(err) : null;
  });
  protected readonly name = signal('');
  protected readonly key = signal('');
  protected readonly errors = signal<Partial<Record<Field, string>>>({});
  /** A refusal that names no field, shown in the dialog. */
  protected readonly dialogError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly keyMax = KEY_MAX_LENGTH;
  protected readonly nameMax = NAME_MAX_LENGTH;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  private readonly keyField = viewChild<ElementRef<HTMLInputElement>>('keyField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly deleteDialog = viewChild<ElementRef<HTMLDialogElement>>('deleteDialog');
  /** Whether the key was typed: from then on it no longer follows the name. */
  private keyTyped = false;
  /** The organization the delete dialog is about. */
  protected readonly deleteTarget = signal<Organization | null>(null);
  protected readonly typed = signal('');
  protected readonly deleteError = signal<string | null>(null);
  /** How many projects the organization holds, once read: a number, or null while unknown. */
  private readonly projectCount = signal<{ count: number; more: boolean } | null>(null);
  protected readonly matches = computed(() => {
    const target = this.deleteTarget();
    return target !== null && this.typed() === target.key;
  });
  protected readonly deleteProjects = computed(() => {
    const found = this.projectCount();
    if (found === null) return $localize`:@@orgs.deleteProjectsUnknown:its projects`;
    if (found.more) {
      return $localize`:@@orgs.deleteProjectsMore:more than ${found.count}:count: projects`;
    }
    if (found.count === 1) return $localize`:@@orgs.deleteProjectsOne:1 project`;
    return $localize`:@@orgs.deleteProjects:${found.count}:count: projects`;
  });

  constructor() {
    // R22's helper: while a delete is queued or running, the list is read again (3 s, 40 times).
    refreshWhilePending(
      () => this.org.orgs().some((o) => o.deleting),
      () => this.org.organizations.reload(),
      this.destroyRef,
    );
  }

  protected deleteLabel(organization: Organization): string {
    return $localize`:@@orgs.deleteNamed:Delete ${organization.name}:name:`;
  }

  /** Opens the delete dialog; the project count is read while it is open. */
  protected openDelete(organization: Organization): void {
    this.deleteTarget.set(organization);
    this.typed.set('');
    this.deleteError.set(null);
    this.projectCount.set(null);
    void this.readProjectCount(organization.id);
    openAfterRender(this.injector, () => this.deleteDialog()?.nativeElement);
  }

  private async readProjectCount(organizationId: string): Promise<void> {
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/projects', {
          params: { query: { organizationId, limit: PROJECT_PAGE_SIZE } },
        }),
      );
      if (this.deleteTarget()?.id !== organizationId) return;
      this.projectCount.set({ count: answer.items.length, more: answer.nextCursor !== null });
    } catch {
      // The sentence then names no number; the delete itself does not need it.
    }
  }

  protected setTyped(event: Event): void {
    this.typed.set(inputValue(event));
  }

  protected closeDelete(): void {
    const dialog = this.deleteDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.resetDelete();
  }

  /** Whatever closed the dialog (Cancel, Escape, a queued delete): no typed key or refusal stays. */
  protected resetDelete(): void {
    this.typed.set('');
    this.deleteError.set(null);
  }

  protected async confirmDelete(event: Event): Promise<void> {
    event.preventDefault();
    const target = this.deleteTarget();
    if (!target || !this.matches() || this.busy()) return;
    this.busy.set(true);
    this.deleteError.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/organizations/{id}', {
          params: { path: { id: target.id }, query: { confirm: target.key } },
        }),
      );
    } catch (err) {
      this.deleteError.set(problemMessage(err));
      // A delete already queued shows as Deleting… once the list is read again.
      if (err instanceof ApiError && err.code === 'ORGANIZATION_DELETING') {
        this.org.organizations.reload();
      }
      this.busy.set(false);
      return;
    }
    this.busy.set(false);
    this.closeDelete();
    this.announcement.set($localize`:@@orgs.deleteQueued:${target.name}:name: is being deleted.`);
    // The list says `deleting` now, which also starts the reads until it is gone.
    this.org.organizations.reload();
  }

  protected switchLabel(organization: Organization): string {
    return $localize`:@@orgs.switchNamed:Switch to ${organization.name}:name:`;
  }

  /**
   * Makes an organisation the current one, as the header's switcher does: once the pages with
   * unsaved changes let go of them.
   */
  protected async switchTo(organization: Organization): Promise<void> {
    if (!(await this.org.switchTo(organization.id))) return;
    this.announcement.set(
      $localize`:@@orgs.switched:${organization.name}:name: is the current organization now.`,
    );
    // The button made way for the "Current" tag.
    keepFocus(this.injector, this.document, () => this.heading().nativeElement);
  }

  /** Opens "New organization" on an empty form. */
  protected openCreate(): void {
    this.name.set('');
    this.key.set('');
    this.keyTyped = false;
    this.errors.set({});
    this.dialogError.set(null);
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected setName(event: Event): void {
    const name = inputValue(event);
    this.name.set(name);
    if (!this.keyTyped) this.key.set(keyFrom(name));
    this.errors.update((all) => ({
      ...all,
      name: undefined,
      ...(this.keyTyped ? {} : { key: undefined }),
    }));
  }

  protected setKey(event: Event): void {
    this.key.set(inputValue(event));
    // Emptied, the key follows the name again.
    this.keyTyped = this.key() !== '';
    this.errors.update((all) => ({ ...all, key: undefined }));
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const name = this.name().trim();
    const key = this.key().trim();
    const errors: Partial<Record<Field, string>> = {};
    if (!name) errors.name = nameMessage();
    if (!KEY_PATTERN.test(key)) errors.key = keyMessage();
    this.errors.set(errors);
    this.dialogError.set(null);
    if (Object.keys(errors).length > 0) {
      this.focusFirstInvalid();
      return;
    }
    this.busy.set(true);
    this.announcement.set(null);
    try {
      const created = await ok(
        this.api.client.POST('/api/v0/organizations', { body: { key, name } }),
      );
      this.closeCreate();
      // The header's switcher lists it at once; the list is read again only if it failed before.
      if (this.org.organizations.hasValue()) {
        this.org.organizations.update((all) => [...(all ?? []), created]);
      } else {
        this.org.organizations.reload();
      }
      try {
        // Its creator is its admin now: the session's permissions say so after `GET /auth/me`.
        await this.auth.refresh();
      } catch {
        // The organization exists; the next navigation reads the session again.
      }
      this.announcement.set(
        $localize`:@@orgs.created:${created.name}:name: created. You are its admin.`,
      );
    } catch (err) {
      this.createFailed(err);
      // Closed while the server answered (Escape, Cancel): the dialog opens again on the refusal.
      openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
    } finally {
      this.busy.set(false);
    }
  }

  /** Puts a refusal on its field; one that names none shows in the dialog, which stays open. */
  private createFailed(err: unknown): void {
    const fields = fieldErrors(err);
    const errors: Partial<Record<Field, string>> = {};
    if (fields['body.name'] !== undefined) errors.name = nameMessage();
    if (fields['body.key'] !== undefined) errors.key = keyMessage();
    if (err instanceof ApiError && err.code === 'ORG_KEY_TAKEN') errors.key = problemMessage(err);
    this.errors.set(errors);
    if (Object.keys(errors).length === 0) this.dialogError.set(problemMessage(err));
    this.focusFirstInvalid();
  }

  private focusFirstInvalid(): void {
    const errors = this.errors();
    let field: ElementRef<HTMLInputElement> | undefined;
    if (errors.name) field = this.nameField();
    else if (errors.key) field = this.keyField();
    field?.nativeElement.focus();
  }
}

function nameMessage(): string {
  return $localize`:@@orgs.nameRequired:Enter a name for the organization.`;
}

function keyMessage(): string {
  return $localize`:@@orgs.keyInvalid:Use 2 to 64 lowercase letters, digits and hyphens, starting with a letter or a digit.`;
}
