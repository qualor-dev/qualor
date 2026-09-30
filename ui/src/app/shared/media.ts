/**
 * The phone layout's width, as the stylesheets write it (`@media (max-width: 40rem)`): a page that
 * behaves differently on a phone asks this, never a number of its own.
 */
export const PHONE_WIDTH = '(max-width: 40rem)';

/** Whether the page is laid out for a phone now. */
export function onPhone(document: Document): boolean {
  const view = document.defaultView;
  // jsdom (the unit tests) has no matchMedia: there nothing is a phone unless a test says so.
  return typeof view?.matchMedia === 'function' && view.matchMedia(PHONE_WIDTH).matches;
}
