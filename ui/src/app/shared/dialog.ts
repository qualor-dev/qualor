import { afterNextRender, type Injector } from '@angular/core';

/**
 * Native `<dialog>` modals (spec §5): short "New …" forms open with `showModal()`, which traps
 * focus, closes on Escape and returns focus to the button that opened it. jsdom has no
 * `showModal`/`close`, so there the `open` attribute stands in.
 */
type Modal = HTMLDialogElement & Partial<Pick<HTMLDialogElement, 'showModal' | 'close'>>;

export function openModal(dialog: HTMLDialogElement): void {
  const modal = dialog as Modal;
  // Not in the document any more (its page was left, an answer came late): nothing to open.
  if (modal.open || !modal.isConnected) return;
  if (modal.showModal) modal.showModal();
  else modal.setAttribute('open', '');
}

export function closeModal(dialog: HTMLDialogElement): void {
  const modal = dialog as Modal;
  if (!modal.open) return;
  if (modal.close) modal.close();
  else modal.removeAttribute('open');
}

/**
 * Opens the dialog once Angular has rendered what the page has just set — its title, its
 * question, an emptied form — so it is announced with its own words, never the last ones (steps 5
 * and 9 reviews). `still` is asked again then: a question cancelled meanwhile opens nothing.
 */
export function openAfterRender(
  injector: Injector,
  dialog: () => HTMLDialogElement | undefined,
  still: () => boolean = () => true,
): void {
  afterNextRender(
    () => {
      const element = dialog();
      if (element && still()) openModal(element);
    },
    { injector },
  );
}
