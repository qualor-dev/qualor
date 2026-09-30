import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  type ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { Organization } from '../api/types';
import { AuthService } from '../auth/auth.service';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';

/** The server's organisation key (`ORGANIZATION_KEY_PATTERN`): 2 to 64 of a-z, 0-9 and "-". */
const KEY_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/;
const KEY_MAX_LENGTH = 64;
/** The server's bound on a name (`text(255)`). */
const NAME_MAX_LENGTH = 255;

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
 * header's switcher lists it at once. The API renames and deletes nothing, so neither does this.
 * The list is the header's own (`OrgContext`), so the two never disagree.
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
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly keyMax = KEY_MAX_LENGTH;
  protected readonly nameMax = NAME_MAX_LENGTH;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  private readonly keyField = viewChild<ElementRef<HTMLInputElement>>('keyField');
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  /** Whether the key was typed: from then on it no longer follows the name. */
  private keyTyped = false;

  protected switchLabel(organization: Organization): string {
    return $localize`:@@orgs.switchNamed:Switch to ${organization.name}:name:`;
  }

  /** Makes an organisation the current one, as the header's switcher does. */
  protected switchTo(organization: Organization): void {
    this.org.select(organization.id);
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
    this.error.set(null);
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
    const field = errors.name ? this.nameField() : errors.key ? this.keyField() : undefined;
    field?.nativeElement.focus();
  }
}

function nameMessage(): string {
  return $localize`:@@orgs.nameRequired:Enter a name for the organization.`;
}

function keyMessage(): string {
  return $localize`:@@orgs.keyInvalid:Use 2 to 64 lowercase letters, digits and hyphens, starting with a letter or a digit.`;
}
