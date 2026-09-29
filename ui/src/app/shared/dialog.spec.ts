import { closeModal, openModal } from './dialog';

describe('openModal and closeModal', () => {
  it('open a dialog as a modal and close it, harmlessly twice', () => {
    const dialog = document.createElement('dialog');
    document.body.append(dialog);
    try {
      openModal(dialog);
      expect(dialog.open).toBe(true);
      openModal(dialog);
      expect(dialog.open).toBe(true);
      closeModal(dialog);
      expect(dialog.open).toBe(false);
      closeModal(dialog);
      expect(dialog.open).toBe(false);
    } finally {
      dialog.remove();
    }
  });

  it('opens nothing once the dialog has left the document (its page was left)', () => {
    const dialog = document.createElement('dialog');
    // The browser throws InvalidStateError for showModal() on a detached dialog.
    const showModal = vi.fn(() => {
      throw new DOMException('The element is not in a Document.', 'InvalidStateError');
    });
    Object.assign(dialog, { showModal });
    expect(() => openModal(dialog)).not.toThrow();
    expect(showModal).not.toHaveBeenCalled();
    expect(dialog.open).toBe(false);
  });
});
