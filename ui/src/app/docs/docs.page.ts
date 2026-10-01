import { DOCUMENT } from '@angular/common';
import { afterRenderEffect, Component, computed, inject, input, resource } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { Title } from '@angular/platform-browser';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { PageHeader } from '../shared/page-header';
import { SystemInfo } from '../shell/system-info';
import { DocContent } from './doc-content';
import { guideNavigation, loadGuidePage } from './guide';
import { pageRoute, parseDocPage } from './markdown';

/**
 * `/docs` and `/docs/:page`: the user guide of this server's release, built into the app
 * (guide.ts), laid out as on qualor.dev/docs: the pages at the left, the article, its sections
 * at the right, previous and next page below. It needs no network beyond this server.
 */
@Component({
  selector: 'q-docs-page',
  imports: [RouterLink, PageHeader, DocContent],
  templateUrl: './docs.page.html',
  styleUrl: './docs.page.css',
})
export class DocsPage {
  /** The route's `:page`; absent on `/docs`, the guide's README. */
  readonly page = input<string>();
  protected readonly system = inject(SystemInfo);
  private readonly title = inject(Title);
  private readonly document = inject(DOCUMENT);
  private readonly fragment = toSignal(inject(ActivatedRoute).fragment, { initialValue: null });

  protected readonly name = computed(() => this.page() ?? 'README');
  private readonly readme = resource({ loader: () => loadGuidePage('README') });
  private readonly source = resource({
    params: () => this.name(),
    loader: ({ params }) => loadGuidePage(params),
  });

  protected readonly nav = computed(() => {
    const readme = this.readme.hasValue() ? this.readme.value() : null;
    return readme === null ? [] : guideNavigation(readme, $localize`:@@docs.overview:Overview`);
  });
  protected readonly doc = computed(() => {
    const markdown = this.source.hasValue() ? this.source.value() : null;
    return markdown === null ? null : parseDocPage(markdown, this.name());
  });
  /** The page name is not one of the guide's. */
  protected readonly missing = computed(
    () => this.source.hasValue() && this.source.value() === null,
  );
  protected readonly failed = computed(
    () => this.source.status() === 'error' || this.readme.status() === 'error',
  );
  protected readonly toc = computed(() => (this.doc()?.headings ?? []).filter((h) => h.depth === 2));
  private readonly position = computed(() => this.nav().findIndex((e) => e.page === this.name()));
  protected readonly prev = computed(() => this.nav()[this.position() - 1] ?? null);
  protected readonly next = computed(() => {
    const at = this.position();
    return at === -1 ? null : (this.nav()[at + 1] ?? null);
  });
  protected readonly route = pageRoute;
  protected readonly crumbs = [{ label: $localize`:@@docs.title:Documentation`, link: '/docs' }];

  constructor() {
    // Once a page is on screen: its title in the tab, and the scroll at its `#section` or its top
    // (the router keeps the scroll position, so the next page would open where the last one ended).
    afterRenderEffect(() => {
      const doc = this.doc();
      const fragment = this.fragment();
      if (doc === null) return;
      this.title.setTitle(`${doc.title} · ${$localize`:@@docs.title:Documentation`} · Qualor`);
      const view = this.document.defaultView;
      const target = fragment === null ? null : this.document.getElementById(fragment);
      if (target !== null) target.scrollIntoView();
      else if (view !== null && view.scrollY > 0) view.scrollTo(0, 0);
    });
  }

  protected reload(): void {
    this.readme.reload();
    this.source.reload();
  }
}
