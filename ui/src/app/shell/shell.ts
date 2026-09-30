import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  DestroyRef,
  type ElementRef,
  inject,
  viewChild,
} from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../auth/auth.service';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { inputValue } from '../shared/forms';
import { Icon } from '../shared/icon';
import { LicenseBanner } from './license-banner';
import { SsoBanner } from './sso-banner';

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
  imports: [RouterLink, RouterLinkActive, RouterOutlet, LicenseBanner, SsoBanner, Icon],
  templateUrl: './shell.html',
  styleUrl: './shell.css',
})
export class Shell {
  private readonly auth = inject(AuthService);
  protected readonly session = inject(SessionStore);
  protected readonly org = inject(OrgContext);
  protected readonly inputValue = inputValue;
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

  protected logout(): void {
    void this.auth.logout();
  }

  /** Closes the user menu after a choice; jsdom has no Popover API, so it may be missing there. */
  protected closeMenu(menu: HTMLElement): void {
    const popover = menu as Partial<Pick<HTMLElement, 'hidePopover'>>;
    if (popover.hidePopover && menu.matches(':popover-open')) popover.hidePopover.call(menu);
  }
}
