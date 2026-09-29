import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, ok } from '../api/api';
import { EeApi, type SsoSettings } from '../api/ee';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { SessionStore } from '../auth/session';
import { SystemInfo } from '../shell/system-info';
import { closeModal, openAfterRender } from '../shared/dialog';
import { keepFocus } from '../shared/focus';
import { isChecked } from '../shared/forms';
import { ssoProblem } from './sso-settings-text';

type User = ItemOf<'/api/v0/users'>;
type PasswordSignIn = SsoSettings['passwordSignIn'];

/** sso-scim.md §10.1: at most 10 break-glass administrators. */
const MAX_BREAK_GLASS = 10;
const USER_PAGE = 500;
/** 500 × 20: far more users than an instance has instance admins among them to pick from. */
const MAX_USER_PAGES = 20;

/** One person the picker offers: an instance admin, or someone listed who no longer is one. */
interface Candidate {
  id: string;
  username: string;
  displayName: string | null;
  /** Active, an instance admin, with a password (§10.1): the only people who may be picked. */
  usable: boolean;
  /** Why not, when not. */
  reason: 'no-password' | 'inactive' | 'not-admin' | null;
}

/**
 * Settings → Sign-in (sso-scim.md §10, §18; feature `sso`, instance admins): who may still sign
 * in with a password. `everyone`, or only the break-glass administrators (up to 10 active instance
 * administrators with a password; a user without one cannot be picked). The page explains the
 * rules that keep someone able to sign in: the server refuses `break_glass_only` without a usable
 * listed admin or an enabled connection (422, shown on the field it names), and while the stored
 * policy limits password sign-in the last usable break-glass admin cannot be demoted or
 * deactivated (409 `LAST_BREAK_GLASS_ADMIN`). An admin who saves the limit without being listed is
 * warned that they will sign in with SSO from then on. While QUALOR_FORCE_PASSWORD_SIGN_IN is set
 * (`forced`), a note says the setting waits until it is removed.
 *
 * Step 9 of the redesign (spec §7.8): the choice and the picker in setting rows, the rules in a
 * panel below; limiting password sign-in asks in the page's dialog instead of the browser's
 * `confirm()`, with the same question.
 */
@Component({
  selector: 'q-sign-in-settings-page',
  templateUrl: './sign-in.page.html',
  styleUrl: './sign-in.page.css',
})
export class SignInSettingsPage {
  private readonly ee = inject(EeApi);
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  protected readonly licensed = computed(() => this.info.features().includes('sso'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly allowed = computed(() => this.licensed() && this.instanceAdmin());

  protected readonly current = signal<SsoSettings | null>(null);
  protected readonly candidates = signal<Candidate[]>([]);
  protected readonly loadError = signal<string | null>(null);
  protected readonly policy = signal<PasswordSignIn>('everyone');
  protected readonly selected = signal<ReadonlySet<string>>(new Set());
  protected readonly policyError = signal<string | null>(null);
  protected readonly pickerError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** The saving admin is not listed while the limit is chosen: they will need SSO (§10.1). */
  protected readonly selfNotListed = computed(() => {
    const me = this.session.user()?.id;
    return this.policy() === 'break_glass_only' && me !== undefined && !this.selected().has(me);
  });
  /** The limit the dialog asks about, with the administrators picked; null while it is closed. */
  protected readonly pendingLimit = signal<{ question: string; ids: string[] } | null>(null);
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      untracked(() => {
        this.current.set(null);
        if (allowed) void this.load();
      });
    });
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      const [settings, users] = await Promise.all([
        ok(this.ee.client.GET('/api/v0/ee/sso/settings')),
        this.allUsers(),
      ]);
      this.show(settings, users);
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  private async allUsers(): Promise<User[]> {
    const all: User[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < MAX_USER_PAGES; i++) {
      const page: { items: User[]; nextCursor: string | null } = await ok(
        this.api.client.GET('/api/v0/users', {
          params: { query: { limit: USER_PAGE, ...(cursor ? { cursor } : {}) } },
        }),
      );
      all.push(...page.items);
      cursor = page.nextCursor;
      if (!cursor) break;
    }
    return all;
  }

  private show(settings: SsoSettings, users: readonly User[]): void {
    this.current.set(settings);
    this.policy.set(settings.passwordSignIn);
    this.selected.set(new Set(settings.breakGlassUserIds));
    const listed = new Set(settings.breakGlassUserIds);
    const candidates: Candidate[] = users
      .filter((u) => u.isInstanceAdmin || listed.has(u.id))
      .map((u) => ({
        id: u.id,
        username: u.username,
        displayName: u.displayName,
        usable: u.active && u.isInstanceAdmin && u.hasPassword,
        reason: !u.hasPassword
          ? ('no-password' as const)
          : !u.active
            ? ('inactive' as const)
            : !u.isInstanceAdmin
              ? ('not-admin' as const)
              : null,
      }));
    candidates.sort((a, b) => a.username.localeCompare(b.username));
    this.candidates.set(candidates);
  }

  protected setPolicy(value: PasswordSignIn): void {
    this.policy.set(value);
    this.policyError.set(null);
  }

  /** A person who cannot be picked stays unpickable, but one listed earlier can be removed. */
  protected pickable(candidate: Candidate): boolean {
    return candidate.usable || this.selected().has(candidate.id);
  }

  protected toggle(candidate: Candidate, event: Event): void {
    const checked = isChecked(event);
    const next = new Set(this.selected());
    if (checked) next.add(candidate.id);
    else next.delete(candidate.id);
    this.selected.set(next);
    this.pickerError.set(null);
  }

  protected reasonText(reason: Candidate['reason']): string {
    switch (reason) {
      case 'no-password':
        return $localize`:@@signIn.reason.noPassword:No password`;
      case 'inactive':
        return $localize`:@@signIn.reason.inactive:Deactivated`;
      case 'not-admin':
        return $localize`:@@signIn.reason.notAdmin:No longer an instance admin`;
      default:
        return '';
    }
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    this.policyError.set(null);
    this.pickerError.set(null);
    const ids = [...this.selected()];
    if (ids.length > MAX_BREAK_GLASS) {
      this.pickerError.set(this.tooManyText());
      this.focus('sign-in-picker');
      return;
    }
    if (this.policy() === 'break_glass_only') {
      // §10.1: say exactly who keeps a password path before limiting it.
      const names = this.candidates()
        .filter((c) => this.selected().has(c.id))
        .map((c) => c.username)
        .join(', ');
      this.pendingLimit.set({
        question: $localize`:@@signIn.confirmLimit:Limit password sign-in? Only these administrators will be able to sign in with a password: ${names}:names:. Everyone else signs in with single sign-on.`,
        ids,
      });
      openAfterRender(
        this.injector,
        () => this.confirmDialog()?.nativeElement,
        () => this.pendingLimit() !== null,
      );
      return;
    }
    await this.applySave(ids);
  }

  protected async confirmLimit(): Promise<void> {
    const pending = this.pendingLimit();
    if (!pending) return;
    // Cleared first: the dialog's close event then finds nothing to cancel.
    this.pendingLimit.set(null);
    this.closeConfirm();
    await this.applySave(pending.ids);
  }

  /** Cancel, Escape or the dialog closing otherwise: nothing is saved. */
  protected cancelLimit(): void {
    this.pendingLimit.set(null);
    this.closeConfirm();
  }

  private closeConfirm(): void {
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog?.open) closeModal(dialog);
  }

  private async applySave(ids: string[]): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      try {
        const saved = await ok(
          this.ee.client.PUT('/api/v0/ee/sso/settings', {
            body: { passwordSignIn: this.policy(), breakGlassUserIds: ids },
          }),
        );
        this.current.set(saved);
        this.policy.set(saved.passwordSignIn);
        this.selected.set(new Set(saved.breakGlassUserIds));
        this.announcement.set(
          saved.passwordSignIn === 'everyone'
            ? $localize`:@@signIn.savedEveryone:Saved: everyone with a password may sign in with it.`
            : $localize`:@@signIn.savedLimited:Saved: only the break-glass administrators may sign in with a password.`,
        );
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 422) throw err;
        const fields = fieldErrors(err);
        if ('body.breakGlassUserIds' in fields) {
          this.pickerError.set(
            $localize`:@@signIn.breakGlassMissing:List at least one active instance administrator with a password.`,
          );
        }
        if ('body.passwordSignIn' in fields) {
          this.policyError.set(
            $localize`:@@signIn.connectionMissing:Enable a single sign-on connection first, so people have another way to sign in.`,
          );
        }
        if (this.policyError()) this.focus('sign-in-everyone');
        else if (this.pickerError()) this.focus('sign-in-picker');
        else throw err;
      }
    });
  }

  private tooManyText(): string {
    return $localize`:@@signIn.tooMany:Pick at most 10 break-glass administrators.`;
  }

  private focus(id: string): void {
    afterNextRender(() => this.document.getElementById(id)?.focus(), { injector: this.injector });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      this.error.set(ssoProblem(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
