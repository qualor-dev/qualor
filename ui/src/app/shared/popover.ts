/**
 * Closes a native popover if it is open. jsdom has no Popover API, and its `matches` throws on
 * `:popover-open` (a throw counts as closed), so the specs stub both.
 */
export function closePopover(element: HTMLElement): void {
  const popover = element as Partial<Pick<HTMLElement, 'hidePopover'>>;
  if (!popover.hidePopover) return;
  let open: boolean;
  try {
    open = element.matches(':popover-open');
  } catch {
    open = false;
  }
  if (open) popover.hidePopover.call(element);
}
