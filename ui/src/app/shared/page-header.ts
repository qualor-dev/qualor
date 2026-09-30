import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';

export interface Crumb {
  label: string;
  link: string | readonly string[];
}

/**
 * `q-page-header` (spec §4): a page's title on the ink band under the top bar, with the brand's
 * halftone circle at its right: breadcrumbs, the title with its status, actions, a meta line and
 * tabs on the band's bottom edge. `compact` drops the extra room of list pages.
 */
@Component({
  selector: 'q-page-header',
  imports: [RouterLink],
  templateUrl: './page-header.html',
  styleUrl: './page-header.css',
  host: { class: 'page-band', '[class.compact]': 'compact()' },
})
export class PageHeader {
  readonly crumbs = input<readonly Crumb[]>([]);
  readonly compact = input(false);
}
