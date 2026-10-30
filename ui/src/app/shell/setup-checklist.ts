import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { Lens } from '../charts/lens';
import { OrgContext } from '../org/org-context';
import { Icon } from '../shared/icon';
import { PHONE_WIDTH } from '../shared/media';
import {
  type Checklist,
  type ChecklistStep,
  SetupSteps,
  type StepId,
  type StepView,
} from './setup-steps';

export type { Checklist, StepId } from './setup-steps';

/** The reveal runs about 800 ms (onboarding notes, Motion); then the steps are drawn still. */
export const REVEAL_MS = 1100;
const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';
/** The corner's distance from the window's edges, and the room left above it, in px. */
const CORNER = 24;

/** Where this browser keeps what it remembers of an organisation's checklist. */
export function setupChecklistKey(organizationId: string): string {
  return `qualor.setup-checklist.${organizationId}`;
}

/** What this browser remembers of an organisation's checklist: never the server's state. */
interface Remembered {
  /** The person collapsed it (or opened it again). */
  collapsed?: boolean;
  /** "All set" was shown once. */
  allSetShown?: boolean;
  /** The steps that were done when the checklist was last seen: newer ones get the reveal. */
  seen?: StepId[];
}

const STEP_IDS: readonly StepId[] = ['connect', 'repositories', 'analysis', 'ai_review', 'team'];

function parseRemembered(raw: string | null): Remembered | null {
  if (raw === null) return null;
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (typeof value !== 'object' || value === null) return null;
    const seen = Array.isArray(value['seen'])
      ? STEP_IDS.filter((id) => (value['seen'] as unknown[]).includes(id))
      : undefined;
    return {
      ...(typeof value['collapsed'] === 'boolean' ? { collapsed: value['collapsed'] } : {}),
      ...(value['allSetShown'] === true ? { allSetShown: true } : {}),
      ...(seen ? { seen } : {}),
    };
  } catch {
    return null;
  }
}

const NAMES: Record<StepId, string> = {
  connect: $localize`:@@setup.step.connect:Connect GitHub or GitLab`,
  repositories: $localize`:@@setup.step.repositories:Add repositories`,
  analysis: $localize`:@@setup.step.analysis:Get the first analysis`,
  ai_review: $localize`:@@setup.step.aiReview:Turn on AI review`,
  team: $localize`:@@setup.step.team:Invite your team`,
};
/** Where each step is done. */
const LINKS: Record<StepId, string> = {
  connect: '/settings/github',
  repositories: '/projects/add',
  analysis: '/projects',
  ai_review: '/settings/ai-review',
  team: '/settings/members',
};
const STATE = {
  done: $localize`:@@setup.state.done:Done:`,
  todo: $localize`:@@setup.state.todo:To do:`,
  notCounted: $localize`:@@setup.state.notCounted:Not counted:`,
};
const ALL_SET = $localize`:@@setup.allSet:All set`;

/**
 * "Set up Qualor" (onboarding design, "The checklist (UI)"; notes, Layout): the first-setup steps
 * of the current organization for those who may create projects there (its admins), in the
 * corner. On ink, with the product's lens as its progress: one band of dots per step done, green
 * with a check at "All set".
 *
 * - The steps and their ticks come from the server only, asked again when the organization
 *   changes, when the person comes back to the tab and on a move to another page: never on a timer.
 * - Collapsed or open is per browser and organization (localStorage, kept in memory when the
 *   browser refuses storage). "Don't show again" is the server's (`PUT closed`), for that user and
 *   organization on every browser. "All set" opens once, then the checklist stays collapsed.
 * - A step done since this browser last saw the list prints its band of dots and draws its tick,
 *   once (not under reduced motion), and is said in a polite live region.
 * - A labelled complementary region, never a modal and never moving focus by itself. On a phone
 *   it is a small button in the header row that opens the panel under it; on a page whose float
 *   bar shows, the panel steps aside and the corner button rises above the bar.
 */
@Component({
  selector: 'q-setup-checklist',
  imports: [Icon, Lens, SetupSteps],
  templateUrl: './setup-checklist.html',
  styleUrl: './setup-checklist.css',
})
export class SetupChecklist {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly org = inject(OrgContext);
  private readonly document = inject(DOCUMENT);
  private readonly injector = inject(Injector);

  /** The organization whose checklist shows, with the user: none for those who may not act. */
  private readonly target = computed(
    () => {
      const user = this.session.user();
      const orgId = this.org.currentId();
      if (!user || !orgId || this.session.demo() || !this.org.can('org.projects.create')) {
        return undefined;
      }
      return { orgId, userId: user.id };
    },
    { equal: (a, b) => a?.orgId === b?.orgId && a?.userId === b?.userId },
  );

  private readonly checklist = resource({
    params: () => this.target(),
    loader: async ({ params }) => ({
      orgId: params.orgId,
      list: await ok(
        this.api.client.GET('/api/v0/organizations/{id}/setup-checklist', {
          params: { path: { id: params.orgId } },
        }),
      ),
    }),
  });
  /** The last answer; none while the first loads or after a failed load (nothing shows then). */
  private readonly data = computed(() =>
    this.checklist.hasValue() ? this.checklist.value() : null,
  );

  /** The person's choice for this organization: the panel, or the corner button. */
  private readonly open = signal(false);
  /** A page's float bar shows (the issues' or Add repositories' bulk bar). */
  private readonly floatBar = signal(false);
  /** The person opened the panel while the float bar showed. */
  private readonly openedOverBar = signal(false);
  /** How far the corner button rises to clear the float bar, in px. */
  protected readonly lift = signal(0);
  protected readonly phone = signal(false);
  protected readonly expanded = computed(
    () => this.open() && (!this.floatBar() || this.openedOverBar()),
  );
  /** The reveal running now: from which value the lens fills, and which ticks draw. */
  private readonly reveal = signal<{ orgId: string; from: number; steps: StepId[] } | null>(null);
  protected readonly announcement = signal('');
  protected readonly closing = signal(false);
  protected readonly closeError = signal<string | null>(null);

  private readonly aside = viewChild<ElementRef<HTMLElement>>('aside');
  private readonly launcher = viewChild<ElementRef<HTMLButtonElement>>('launcher');
  private readonly collapseButton = viewChild<ElementRef<HTMLButtonElement>>('collapseButton');
  /** The organization of the last answer: a new one starts from what the browser remembers. */
  private shownOrg: string | null = null;
  /** What was remembered while storage refused it, for this page's life. */
  private readonly memory = new Map<string, Remembered>();
  private revealTimer: ReturnType<typeof setTimeout> | undefined;

  protected readonly view = computed(() => {
    const data = this.data();
    if (!data || data.list.closed) return null;
    const { list, orgId } = data;
    const reveal = this.reveal();
    const revealing = reveal?.orgId === orgId ? reveal : null;
    const counted = list.steps.filter((s) => s.blocking);
    const done = counted.filter((s) => s.done).length;
    const total = counted.length;
    const allSet = list.allDone;
    const next = counted.find((s) => !s.done)?.id ?? null;
    const count = allSet
      ? ALL_SET
      : $localize`:@@setup.count:${done}:done: of ${total}:total: done`;
    return {
      allSet,
      count,
      short: allSet ? ALL_SET : `${done}/${total}`,
      name: allSet
        ? $localize`:@@setup.launchAllSet:Set up Qualor, all set`
        : $localize`:@@setup.launchName:Set up Qualor, ${count}:count:`,
      value: allSet ? 100 : total === 0 ? 0 : (100 * done) / total,
      from: revealing ? revealing.from : null,
      steps: list.steps.map((s) => stepView(s, next, revealing?.steps ?? [])),
    };
  });

  constructor() {
    const destroyRef = inject(DestroyRef);
    const view = this.document.defaultView;
    if (typeof view?.matchMedia === 'function') {
      const query = view.matchMedia(PHONE_WIDTH);
      this.phone.set(query.matches);
      const change = () => this.phone.set(query.matches);
      query.addEventListener?.('change', change);
      destroyRef.onDestroy(() => query.removeEventListener?.('change', change));
    }

    effect(() => {
      const data = this.data();
      if (data) untracked(() => this.arrived(data.orgId, data.list));
    });

    // Asked again when the person comes back to the tab, and on a move to another page (a new
    // path, not a new query): the steps are done on other pages and other tabs.
    const visible = () => {
      if (this.document.visibilityState === 'visible') this.refresh();
    };
    this.document.addEventListener('visibilitychange', visible);
    const router = inject(Router);
    const pathOf = (url: string) => url.split(/[?#]/, 1)[0] ?? url;
    // During the first navigation (the shell is part of it) there is no page yet to move from.
    let path: string | null = router.navigated ? pathOf(router.url) : null;
    const subscription = router.events.subscribe((event) => {
      if (!(event instanceof NavigationEnd)) return;
      const next = pathOf(event.urlAfterRedirects);
      if (path !== null && next !== path) this.refresh();
      path = next;
    });
    destroyRef.onDestroy(() => {
      this.document.removeEventListener('visibilitychange', visible);
      subscription.unsubscribe();
      clearTimeout(this.revealTimer);
    });

    afterNextRender(() => this.watchFloatBar(destroyRef));
    this.keepPageClear();
  }

  protected toggle(): void {
    if (this.expanded()) this.collapse();
    else this.expand();
  }

  protected expand(): void {
    this.open.set(true);
    if (this.floatBar()) this.openedOverBar.set(true);
    this.rememberChoice(false);
    // On a wide screen the corner button gives way to the panel: focus goes to its collapse
    // button. On a phone the button stays, and so does focus.
    if (!this.phone()) this.focusAfterRender(() => this.collapseButton());
  }

  protected collapse(): void {
    this.open.set(false);
    this.openedOverBar.set(false);
    this.rememberChoice(true);
    this.focusAfterRender(() => this.launcher());
  }

  protected escape(): void {
    if (this.expanded()) this.collapse();
  }

  /** A link in the panel was followed: on a phone the panel no longer covers the new page. */
  protected followed(): void {
    if (this.phone()) this.open.set(false);
  }

  /** "Don't show again": closed on the server for this user and organization, for good. */
  protected async close(): Promise<void> {
    const data = this.data();
    if (!data || this.closing()) return;
    this.closing.set(true);
    this.closeError.set(null);
    try {
      const list = await ok(
        this.api.client.PUT('/api/v0/organizations/{id}/setup-checklist', {
          params: { path: { id: data.orgId } },
          body: { closed: true },
        }),
      );
      if (this.data()?.orgId !== data.orgId) return;
      this.checklist.set({ orgId: data.orgId, list });
      // The region goes with the button that had focus: the page takes it.
      this.document.getElementById('main')?.focus({ preventScroll: true });
    } catch (err) {
      this.closeError.set(problemMessage(err));
    } finally {
      this.closing.set(false);
    }
  }

  private refresh(): void {
    const data = this.data();
    if (!data || data.list.closed || this.checklist.isLoading()) return;
    this.checklist.reload();
  }

  /** An answer arrived: the open state of a new organization, "All set" once, and the reveal. */
  private arrived(orgId: string, list: Checklist): void {
    const remembered = this.recall(orgId);
    const first = this.shownOrg !== orgId;
    this.shownOrg = orgId;
    const doneIds = list.steps.filter((s) => s.done).map((s) => s.id);
    const next: Remembered = { ...remembered, seen: doneIds };
    if (list.closed) {
      this.remember(orgId, next);
      return;
    }
    const firstAllSet = list.allDone && remembered.allSetShown !== true;
    if (first) {
      // Phones start collapsed; "All set" opens once and then stays collapsed.
      this.openedOverBar.set(false);
      this.open.set(!this.phone() && (list.allDone ? firstAllSet : remembered.collapsed !== true));
    } else if (firstAllSet && !this.phone()) {
      this.open.set(true);
    }
    if (firstAllSet) next.allSetShown = true;
    this.remember(orgId, next);

    const seen = remembered.seen;
    if (!seen) return;
    const newly = list.steps.filter((s) => s.done && !seen.includes(s.id));
    if (newly.length === 0) return;
    this.announcement.set(
      newly.map((s) => $localize`:@@setup.stepDone:${NAMES[s.id]}:step:: done`).join(' '),
    );
    if (this.reducedMotion()) return;
    const counted = list.steps.filter((s) => s.blocking);
    const before = counted.filter((s) => s.done && seen.includes(s.id)).length;
    this.reveal.set({
      orgId,
      from: counted.length === 0 ? 0 : (100 * before) / counted.length,
      steps: newly.map((s) => s.id),
    });
    clearTimeout(this.revealTimer);
    this.revealTimer = setTimeout(() => this.reveal.set(null), REVEAL_MS);
  }

  private reducedMotion(): boolean {
    const view = this.document.defaultView;
    return typeof view?.matchMedia === 'function' && view.matchMedia(REDUCED_MOTION).matches;
  }

  private rememberChoice(collapsed: boolean): void {
    const orgId = this.data()?.orgId;
    if (orgId) this.remember(orgId, { ...this.recall(orgId), collapsed });
  }

  private recall(orgId: string): Remembered {
    const kept = this.memory.get(orgId);
    if (kept) return kept;
    try {
      return parseRemembered(localStorage.getItem(setupChecklistKey(orgId))) ?? {};
    } catch {
      return {};
    }
  }

  private remember(orgId: string, value: Remembered): void {
    try {
      localStorage.setItem(setupChecklistKey(orgId), JSON.stringify(value));
      this.memory.delete(orgId);
    } catch {
      // Private mode or blocked storage: remembered for this page only.
      this.memory.set(orgId, value);
    }
  }

  private focusAfterRender(target: () => ElementRef<HTMLElement> | undefined): void {
    afterNextRender(() => target()?.nativeElement.focus(), { injector: this.injector });
  }

  /**
   * A page's float bar (fixed at the bottom, centred) and the panel would cover each other: the
   * panel steps aside while the bar shows, and the corner button rises above the bar where they
   * would overlap (below about 1300 px).
   */
  private watchFloatBar(destroyRef: DestroyRef): void {
    const view = this.document.defaultView;
    if (!view || typeof MutationObserver !== 'function') return;
    const check = () => {
      const bar = this.document.querySelector<HTMLElement>('.float-bar');
      this.floatBar.set(bar !== null);
      if (!bar) this.openedOverBar.set(false);
      this.lift.set(bar && !this.phone() ? this.liftOver(bar, view) : 0);
    };
    const observer = new MutationObserver(check);
    observer.observe(this.document.body, { childList: true, subtree: true });
    view.addEventListener('resize', check);
    check();
    destroyRef.onDestroy(() => {
      observer.disconnect();
      view.removeEventListener('resize', check);
    });
  }

  private liftOver(bar: HTMLElement, view: Window): number {
    const box = bar.getBoundingClientRect();
    if (box.width === 0) return 0;
    const button = this.launcher()?.nativeElement.offsetWidth || 200;
    const left = view.innerWidth - CORNER - button;
    return box.right > left - 8 ? Math.ceil(view.innerHeight - box.top + 12) : 0;
  }

  /**
   * While the panel or the corner button is in the corner, the page gets that much room at its
   * end (`--setup-clearance`, styles.css), so its last rows scroll clear of it.
   */
  private keepPageClear(): void {
    const root = this.document.documentElement;
    effect((onCleanup) => {
      const aside = this.aside()?.nativeElement;
      const view = this.document.defaultView;
      if (!aside || !view || typeof ResizeObserver !== 'function') return;
      const update = () => {
        if (view.getComputedStyle(aside).position === 'fixed') {
          root.style.setProperty('--setup-clearance', `${aside.offsetHeight + CORNER}px`);
        } else {
          root.style.removeProperty('--setup-clearance');
        }
      };
      const observer = new ResizeObserver(update);
      observer.observe(aside);
      update();
      onCleanup(() => {
        observer.disconnect();
        root.style.removeProperty('--setup-clearance');
      });
    });
  }
}

/** A step as the list draws it. */
function stepView(step: ChecklistStep, next: StepId | null, justDone: readonly StepId[]): StepView {
  const waiting = !step.done && step.hint === 'ask_server_admin';
  return {
    id: step.id,
    name: NAMES[step.id],
    done: step.done,
    waiting,
    next: step.id === next,
    justDone: step.done && justDone.includes(step.id),
    link: step.done || waiting ? null : LINKS[step.id],
    hint: step.hint,
    state: step.done ? STATE.done : waiting ? STATE.notCounted : STATE.todo,
  };
}
