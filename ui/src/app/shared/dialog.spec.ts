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
});
