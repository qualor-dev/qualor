import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  type ElementRef,
  inject,
  viewChild,
} from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../auth/auth.service';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { Icon } from '../shared/icon';
import { LicenseBanner } from './license-banner';
import { SetupChecklist } from './setup-checklist';
import { SsoBanner } from './sso-banner';
import { SystemInfo } from './system-info';
import { UpdateBanner } from './update-banner';
import { UpdateNotice } from './update-notice';

/**
 * The main-menu entries the UI has a screen for (4E-2 §4), by extension id: a plugin's entry for
 * any other id is skipped, since no route would answer it.
 */
const MAIN_NAV: Readonly<Record<string, { path: string; label: string }>> = {
  portfolio: { path: '/portfolio', label: $localize`:@@shell.nav.portfolio:Portfolio` },
};

/** The path of a router URL, without its query and fragment. */
const pathOf = (url: string) => url.split(/[?#]/, 1)[0] ?? url;

/**
 * The signed-in frame: skip link, the ink top bar with the main navigation and the user menu (a
 * popover with the account's links, spec §4), the licence banner and the forced-password banner
 * for instance admins (enterprise.md §11, sso-scim.md §10.4), and the page outlet. When the page changes (a new path, not just a new query such as a search), focus moves
 * to `main`, so keyboard and screen reader users start on the new page instead of on the link they
 * left.
 */
@Component({
  selector: 'q-shell',
  imports: [
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
    LicenseBanner,
    SetupChecklist,
    SsoBanner,
    UpdateBanner,
    Icon,
  ],
  templateUrl: './shell.html',
  styleUrl: './shell.css',
})
export class Shell {
  private readonly auth = inject(AuthService);
  protected readonly session = inject(SessionStore);
  protected readonly org = inject(OrgContext);
  /** The server's version and edition, at the foot of the user menu. */
  protected readonly system = inject(SystemInfo);
  /** A newer release from the server's update check, for instance admins (telemetry.md). */
  protected readonly updates = inject(UpdateNotice);
  /** The plugins' main-menu entries with a known screen, after "Quality gates". */
  protected readonly mainNav = computed(() =>
    this.system.mainNav().flatMap((e) => {
      const known = Object.hasOwn(MAIN_NAV, e.id) ? MAIN_NAV[e.id] : undefined;
      return known ? [{ id: e.id, ...known }] : [];
    }),
  );
  private readonly main = viewChild.required<ElementRef<HTMLElement>>('main');
  private readonly header = viewChild.required<ElementRef<HTMLElement>>('header');

  constructor() {
    const router = inject(Router);
    let previous: string | null = null;
    const subscription = router.events.subscribe((event) => {
      if (!(event instanceof NavigationEnd)) return;
      const path = pathOf(event.urlAfterRedirects);
      // The first page the frame shows keeps the browser's own focus handling.
      if (previous !== null && path !== previous) {
        this.main().nativeElement.focus({ preventScroll: true });
      }
      previous = path;
    });
    const destroyRef = inject(DestroyRef);
    destroyRef.onDestroy(() => subscription.unsubscribe());

    // Sticky parts (an issue's details, the settings navigation) sit below the top bar, which grows
    // past its 60px with the organization switcher, or when it wraps: they follow its height.
    const document = inject(DOCUMENT);
    afterNextRender(() => {
      const header = this.header().nativeElement;
      const root = document.documentElement;
      const view = document.defaultView;
      const update = () => {
        if (view?.getComputedStyle(header).position === 'sticky') {
          root.style.setProperty('--sticky-top', header.offsetHeight + 12 + 'px');
        } else {
          // Below 56rem the bar scrolls away: the stylesheet's value holds.
          root.style.removeProperty('--sticky-top');
        }
      };
      update();
      if (typeof ResizeObserver !== 'function') return;
      const observer = new ResizeObserver(update);
      observer.observe(header);
      view?.addEventListener('resize', update);
      destroyRef.onDestroy(() => {
        observer.disconnect();
        view?.removeEventListener('resize', update);
        root.style.removeProperty('--sticky-top');
      });
    });
  }

  /**
   * The organization switcher: a page with unsaved changes asks first. While it keeps the person
   * (Stay), nothing switches and the select shows the organization still in use.
   */
  protected async switchOrganization(event: Event): Promise<void> {
    const select = event.target as HTMLSelectElement;
    if (!(await this.org.switchTo(select.value))) select.value = this.org.currentId() ?? '';
  }

  protected logout(): void {
    void this.auth.logout();
  }

  /** Closes the user menu after a choice; jsdom has no Popover API, so it may be missing there. */
  protected closeMenu(menu: HTMLElement): void {
    const popover = menu as Partial<Pick<HTMLElement, 'hidePopover'>>;
    if (popover.hidePopover && menu.matches(':popover-open')) popover.hidePopover.call(menu);
  }
}
