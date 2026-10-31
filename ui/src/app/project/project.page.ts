import {
  afterRenderEffect,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  input,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  type IsActiveMatchOptions,
  NavigationEnd,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import { filter, map } from 'rxjs';
import { ApiError, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { GateBadge } from '../shared/gate-badge';
import { Icon } from '../shared/icon';
import { type Crumb, PageHeader } from '../shared/page-header';
import { SystemInfo } from '../shell/system-info';
import { mergeRequestLink, notFound } from './branches';
import { CurrentProject } from './current-project';
import { settingsVisible } from './settings/settings-visibility';
import { newMarkerText } from './vulnerabilities/new-marker';
import { WatchButton } from './watch-button';

/**
 * A project's frame on the ink page band (spec §7.1): its name with the main branch's gate, the
 * key and the main branch (or those of the branch or merge request an overview shows), and tabs
 * for the overview, branches and issues, plus Access for organisation admins, in every edition,
 * the plugins' project tabs (Compliance, 4E-1 §4), and the Watch button (mail E3). The project
 * (and the caller's `permissions` on it, which the tabs use to hide what the caller may not do,
 * rbac-audit.md §17) is read through `CurrentProject`.
 */
@Component({
  selector: 'q-project-page',
  imports: [RouterLink, RouterLinkActive, RouterOutlet, GateBadge, Icon, PageHeader, WatchButton],
  templateUrl: './project.page.html',
  host: { class: 'bleed' },
})
export class ProjectPage {
  private readonly store = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  /** The read-only demo account watches nothing (the server refuses it). */
  protected readonly demo = this.session.demo;
  readonly projectId = input.required<string>();

  protected readonly project = this.store.project;
  /** The project once loaded; never `project.value()` in the error state, which throws. */
  protected readonly current = this.store.current;
  /**
   * The branch or merge request an overview shows, when not the main one: the band carries its
   * gate, its name, a merge request's title and its page instead of the main branch's (§7.1).
   */
  protected readonly shown = this.store.shownBranch;
  /** A merge request's page, named by its host (scm.md §8; see {@link mergeRequestLink}). */
  protected readonly mrLink = computed(() => {
    const b = this.shown();
    return b ? mergeRequestLink(b.mrUrl, b.mrTitle || b.title) : null;
  });
  protected readonly crumbs: Crumb[] = [
    { label: $localize`:@@project.crumb:Projects`, link: '/projects' },
  ];
  /**
   * The Access tab (rbac-audit.md §17): for those who read the members of the project's
   * organisation (`org.members.read`), whatever the licence (§1.3).
   */
  protected readonly showAccess = computed(() => {
    const project = this.current();
    return project !== null && this.session.orgCan(project.organizationId, 'org.members.read');
  });
  /**
   * The Settings tab: for whoever holds a project setting permission, or the organisation's
   * `org.webhooks.manage` (the Webhooks panel).
   */
  protected readonly showSettings = computed(() => {
    const p = this.current();
    return (
      p !== null &&
      settingsVisible(p.permissions, this.session.orgCan(p.organizationId, 'org.webhooks.manage'))
    );
  });
  /**
   * The Compliance tab (4E-1 §4): while a plugin lists the `project.tab` entry `compliance` and its
   * feature (`compliance-export`) is active; every reader of the project sees it.
   */
  protected readonly complianceTab = computed(() =>
    this.info.projectTabs().some((t) => t.id === 'compliance'),
  );
  /** The open issues of the branch the band shows, else of the main branch: the Issues tab's count. */
  protected readonly issueCount = computed(() => {
    const shown = this.shown();
    if (shown) return shown.issues;
    const value = this.current()?.mainBranch?.measures['issues'];
    return typeof value === 'number' ? value : null;
  });
  /** The Issues tab opens the list it counts: the shown branch's (`?branch=`), else the main one's. */
  protected readonly issuesQuery = computed(() => {
    const shown = this.shown();
    return shown ? { branch: shown.id } : null;
  });
  /** The Issues tab stays current on any issues page, whatever branch its link carries. */
  protected readonly issuesActive: IsActiveMatchOptions = {
    paths: 'subset',
    queryParams: 'ignored',
    matrixParams: 'ignored',
    fragment: 'ignored',
  };
  /**
   * The Vulnerabilities tab (vuln 2b): while monitoring is on for the project, `vulnerabilities` is
   * not null.
   */
  protected readonly showVulnerabilities = computed(() => !!this.current()?.vulnerabilities);
  /** The header badge: where the project has new vulnerabilities, or null. */
  protected readonly newVulnerabilities = computed(() => {
    const vulnerabilities = this.current()?.vulnerabilities;
    return vulnerabilities ? newMarkerText(vulnerabilities.newIn) : null;
  });
  /** A malformed id in the URL (422 on the path) is, for the reader, a project that does not exist. */
  protected readonly errorMessage = computed(() => {
    const error = this.project.error();
    if (!error) return null;
    const malformed = error instanceof ApiError && error.status === 422;
    return problemMessage(malformed ? notFound() : error);
  });

  private readonly tabs = viewChild<ElementRef<HTMLElement>>('tabs');
  private readonly url = toSignal(
    inject(Router).events.pipe(
      filter((e) => e instanceof NavigationEnd),
      map((e) => e.urlAfterRedirects),
    ),
  );

  constructor() {
    effect(() => this.store.use(this.projectId()));
    // On a phone the tabs scroll sideways (styles.css, .page-band .tabs): the current tab is
    // brought into view once the tabs it follows are shown, after each navigation, and when the
    // bar narrows (a turned phone). RouterLinkActive marks the current tab in a microtask it
    // queues while rendering, so this runs after it.
    afterRenderEffect((onCleanup) => {
      this.url();
      this.complianceTab();
      this.showAccess();
      this.showSettings();
      this.showVulnerabilities();
      const nav = this.tabs()?.nativeElement;
      if (!nav) return;
      queueMicrotask(() => revealActiveTab(nav));
      if (typeof ResizeObserver !== 'function') return;
      const resized = new ResizeObserver(() => revealActiveTab(nav));
      resized.observe(nav);
      onCleanup(() => resized.disconnect());
    });
  }
}

/** Scrolls the tab bar sideways, never the page, so that its active tab is wholly visible. */
function revealActiveTab(nav: HTMLElement): void {
  const active = nav.querySelector<HTMLElement>('a.active');
  if (!active || nav.scrollWidth <= nav.clientWidth) return;
  const bar = nav.getBoundingClientRect();
  const tab = active.getBoundingClientRect();
  // Whole pixels, rounded outwards: scrollLeft keeps no fraction on some screens.
  if (tab.left < bar.left) nav.scrollLeft -= Math.ceil(bar.left - tab.left);
  else if (tab.right > bar.right) nav.scrollLeft += Math.ceil(tab.right - bar.right);
}
