import { Component, type ElementRef, inject, Injector, signal, viewChild } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { closeModal, openAfterRender, openModal } from './dialog';

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

@Component({
  templateUrl: './dialog.spec.html',
})
class Asking {
  readonly question = signal('');
  readonly pending = signal(false);
  private readonly injector = inject(Injector);
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  ask(words: string): void {
    this.question.set(words);
    this.pending.set(true);
    openAfterRender(
      this.injector,
      () => this.dialog().nativeElement,
      () => this.pending(),
    );
  }
}

describe('openAfterRender (steps 5 and 9 reviews)', () => {
  /** The question's words at the moment the dialog opens. */
  function wordsWhenOpened(dialog: HTMLDialogElement): { words: string | null } {
    const seen = { words: null as string | null };
    new MutationObserver(() => {
      if (dialog.open && seen.words === null) {
        seen.words = dialog.querySelector('#question')?.textContent ?? '';
      }
    }).observe(dialog, { attributes: true, attributeFilter: ['open'] });
    return seen;
  }

  it('opens the dialog once the page has rendered the words it just set', async () => {
    const fixture = TestBed.createComponent(Asking);
    await fixture.whenStable();
    const dialog = (fixture.nativeElement as HTMLElement).querySelector('dialog')!;
    const seen = wordsWhenOpened(dialog);
    fixture.componentInstance.ask('Delete the gate?');
    await fixture.whenStable();
    await new Promise((resolve) => setTimeout(resolve));
    expect(dialog.open).toBe(true);
    expect(seen.words).toBe('Delete the gate?');
  });

  it('opens nothing when the question was cancelled before the render', async () => {
    const fixture = TestBed.createComponent(Asking);
    await fixture.whenStable();
    const dialog = (fixture.nativeElement as HTMLElement).querySelector('dialog')!;
    fixture.componentInstance.ask('Delete the gate?');
    fixture.componentInstance.pending.set(false);
    await fixture.whenStable();
    await new Promise((resolve) => setTimeout(resolve));
    expect(dialog.open).toBe(false);
  });
});
