import {
  afterNextRender,
  Component,
  type ElementRef,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';

/**
 * A token or secret the server returns exactly once (api.md: `POST /tokens`, `POST /webhooks`):
 * shown in a read-only field with a copy button and a warning. It takes focus when it appears, so
 * the keyboard is where the secret is. The UI never stores it: the page holding the value drops
 * it on "Done", on the next creation and when it is left, and nothing logs it. A page showing
 * several gives each its own `fieldId` and lets none take the focus (`autofocus`).
 */
@Component({
  selector: 'q-secret-once',
  templateUrl: './secret-once.html',
})
export class SecretOnce {
  readonly value = input.required<string>();
  readonly label = input.required<string>();
  /** The field's id, unique on the page; its warning is `<fieldId>-warning`. */
  readonly fieldId = input('secret-once');
  /** What to do with the secret, said before the warning ("Add it to the repository's secrets."). */
  readonly intro = input<string | null>(null);
  /** False where several secrets show at once: none of them takes the focus. */
  readonly autofocus = input(true);
  /** False in a dialog: Done sits in the dialog's footer, as every dialog's actions do (spec §5). */
  readonly showDone = input(true);
  /** The user has copied the secret (or given up on it): the page forgets it. */
  readonly done = output();
  protected readonly copyState = signal<'idle' | 'copied' | 'failed'>('idle');
  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>('field');

  constructor() {
    afterNextRender(() => {
      if (this.autofocus()) this.field().nativeElement.focus();
    });
  }

  protected async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.value());
      this.copyState.set('copied');
    } catch {
      // No Clipboard API (an insecure context) or permission refused: the field stays selectable.
      this.copyState.set('failed');
    }
  }
}
