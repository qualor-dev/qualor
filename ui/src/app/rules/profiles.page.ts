import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  Injector,
  signal,
  viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { OrgContext } from '../org/org-context';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { Icon } from '../shared/icon';
import { copyName } from '../shared/names';
import { PageHeader } from '../shared/page-header';

export type Profile = ItemOf<'/api/v0/quality-profiles'>;
type Language = Profile['language'];
const LANGUAGES: Language[] = ['typescript', 'javascript', 'java', 'csharp', 'python', '*'];
/** data-model.md §4.4: a profile is at most the third level of its chain. */
const MAX_PROFILE_DEPTH = 3;

/**
 * Ruling B1 / P5: "Qualor way" names the built-in profiles in any case, spacing or punctuation
 * (the server's `nameSkeleton`, routes/profiles.ts). Checked here so the form can say so at once;
 * the server's 422 on `body.name` is shown too.
 */
export function isReservedProfileName(name: string): boolean {
  const skeleton = name
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, '');
  return skeleton === 'qualorway';
}

/** How deep a profile sits in its chain (1 without a parent); bounded, so a cycle cannot loop. */
function depth(profile: Profile, byId: ReadonlyMap<string, Profile>): number {
  let level = 1;
  for (let p = profile.parentId; p !== null && level <= MAX_PROFILE_DEPTH; level += 1) {
    p = byId.get(p)?.parentId ?? null;
  }
  return level;
}

/**
 * The organisation's quality profiles by language (a profile filters which reported rules
 * become issues). Built-in profiles are copied to be edited; a new profile may inherit from a
 * parent of its language, fixed at creation, at most three levels deep. Only org admins see the
 * buttons and the form (the server checks the role again).
 *
 * After a change the list is refreshed in place (rows keep their elements), the result is
 * announced in the live region, and focus moves on only when the button used is gone
 * (`keepFocus`). A refused copy is reported as such, never on the New-profile form's fields.
 */
@Component({
  selector: 'q-profiles-page',
  imports: [Icon, LabelPipe, PageHeader, RouterLink],
  templateUrl: './profiles.page.html',
  styleUrl: './profiles.page.css',
  host: { class: 'bleed' },
})
export class ProfilesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  protected readonly org = inject(OrgContext);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');

  protected readonly list = new KeysetList<Profile, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/quality-profiles', {
        params: { query: { organizationId, limit: 100, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  /** The profiles by language, in the languages' order; a language without one is left out. */
  protected readonly groups = computed(() =>
    LANGUAGES.map((language) => ({
      language,
      profiles: this.list.items().filter((p) => p.language === language),
    })).filter((group) => group.profiles.length > 0),
  );
  protected readonly names = computed(
    () => new Map(this.list.items().map((p) => [p.id, p.name] as const)),
  );

  protected readonly newName = signal('');
  protected readonly newLanguage = signal<Language>('typescript');
  protected readonly newParent = signal('');
  /** Profiles of the chosen language that a new child could inherit from. */
  protected readonly parents = computed(() => {
    const byId = new Map(this.list.items().map((p) => [p.id, p] as const));
    return this.list
      .items()
      .filter((p) => p.language === this.newLanguage() && depth(p, byId) < MAX_PROFILE_DEPTH);
  });
  protected readonly error = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  protected readonly parentError = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** A refused creation other than its fields, shown in the dialog that is still open. */
  protected readonly createError = signal<string | null>(null);
  /** The profile the delete confirmation asks about; null while it is closed. */
  protected readonly pendingDelete = signal<Profile | null>(null);
  protected readonly deleteQuestion = computed(() => {
    const profile = this.pendingDelete();
    return profile
      ? $localize`:@@profiles.confirmDelete:Delete the quality profile "${profile.name}:name:"?`
      : '';
  });
  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  protected readonly languages = LANGUAGES;
  protected readonly inputValue = inputValue;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      if (organizationId) void this.list.reset(organizationId);
    });
  }

  protected openCreate(): void {
    this.nameError.set(null);
    this.parentError.set(null);
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

  protected setLanguage(event: Event): void {
    const value = inputValue(event);
    this.newLanguage.set(LANGUAGES.find((l) => l === value) ?? 'typescript');
    this.newParent.set('');
    this.parentError.set(null);
  }

  protected setParent(event: Event): void {
    this.newParent.set(inputValue(event));
    this.parentError.set(null);
  }

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    const name = this.newName().trim();
    if (!organizationId || !name || this.busy()) return;
    this.announcement.set(null);
    if (isReservedProfileName(name)) {
      this.nameError.set(
        $localize`:@@profiles.nameReserved:This name is reserved for the built-in profiles.`,
      );
      return;
    }
    const parentId = this.newParent();
    await this.run(async () => {
      const profile = await ok(
        this.api.client.POST('/api/v0/quality-profiles', {
          body: {
            organizationId,
            name,
            language: this.newLanguage(),
            ...(parentId ? { parentId } : {}),
          },
        }),
      );
      await this.router.navigate(['/profiles', profile.id]);
    }, 'create');
  }

  protected async copy(profile: Profile): Promise<void> {
    const name = copyName(profile.name, (n) => $localize`:@@profiles.copyName:${n}:name: (copy)`);
    await this.run(async () => {
      const copy = await ok(
        this.api.client.POST('/api/v0/quality-profiles/{id}/copy', {
          params: { path: { id: profile.id } },
          body: { name },
        }),
      );
      await this.router.navigate(['/profiles', copy.id]);
    }, 'copy');
  }

  protected async setDefault(profile: Profile): Promise<void> {
    await this.run(async () => {
      await ok(
        this.api.client.POST('/api/v0/quality-profiles/{id}/set-default', {
          params: { path: { id: profile.id } },
        }),
      );
      await this.list.refresh();
      this.announcement.set(
        $localize`:@@profiles.madeDefault:${profile.name}:name: is now the default ${label('language', profile.language)}:language: profile.`,
      );
      keepFocus(
        this.injector,
        this.document,
        () => rowByKey(this.host.nativeElement, profile.id)?.querySelector('button'),
        () => this.heading().nativeElement,
      );
    });
  }

  protected remove(profile: Profile): void {
    if (this.busy()) return;
    this.pendingDelete.set(profile);
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
    const profile = this.pendingDelete();
    if (!profile) return;
    this.cancelDelete();
    await this.delete(profile);
  }

  private async delete(profile: Profile): Promise<void> {
    // The row's place in its own language panel, where focus stays: the list's order is not the
    // page's, whose rows are grouped by language (step 7 review). The built-in row always stays.
    const row = rowByKey(this.host.nativeElement, profile.id);
    const table = row?.closest('table') ?? undefined;
    const index = row && table ? [...table.querySelectorAll('tbody tr[data-key]')].indexOf(row) : 0;
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/quality-profiles/{id}', {
          params: { path: { id: profile.id } },
        }),
      );
      await this.list.refresh();
      this.announcement.set(
        $localize`:@@profiles.deleted:Quality profile ${profile.name}:name: deleted.`,
      );
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(table, index)?.querySelector('button'),
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
    this.parentError.set(null);
    this.createError.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      const fields = fieldErrors(err);
      if (kind === 'copy' && fields['body.name']) {
        this.error.set(
          $localize`:@@profiles.copyNameInvalid:The copy could not be named after this profile. Create a new profile instead.`,
        );
      } else if (kind === 'create' && (fields['body.name'] || fields['body.parentId'])) {
        if (fields['body.name']) {
          this.nameError.set(
            $localize`:@@profiles.nameInvalid:This name cannot be used. "Qualor way", in any spelling, is kept for the built-in profiles.`,
          );
        }
        if (fields['body.parentId']) {
          this.parentError.set(
            $localize`:@@profiles.parentInvalid:This profile cannot be the parent: it must be of the same language, and profiles inherit at most three levels deep.`,
          );
        }
      } else if (kind === 'create') {
        // The dialog is still open: the reason goes there.
        this.createError.set(problemMessage(err));
      } else {
        this.error.set(problemMessage(err));
      }
      if (kind !== 'create') {
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}
