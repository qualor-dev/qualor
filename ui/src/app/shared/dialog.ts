/**
 * Native `<dialog>` modals (spec §5): short "New …" forms open with `showModal()`, which traps
 * focus, closes on Escape and returns focus to the button that opened it. jsdom has no
 * `showModal`/`close`, so there the `open` attribute stands in.
 */
type Modal = HTMLDialogElement & Partial<Pick<HTMLDialogElement, 'showModal' | 'close'>>;

export function openModal(dialog: HTMLDialogElement): void {
  const modal = dialog as Modal;
  if (modal.open) return;
  if (modal.showModal) modal.showModal();
  else modal.setAttribute('open', '');
}

export function closeModal(dialog: HTMLDialogElement): void {
  const modal = dialog as Modal;
  if (!modal.open) return;
  if (modal.close) modal.close();
  else modal.removeAttribute('open');
}
