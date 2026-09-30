import { Component, input, signal } from '@angular/core';

/**
 * A value an administrator copies into another system (sso-scim.md §4.1, §12.1: a redirect URI,
 * an entity id, the SCIM base URL): a labelled read-only field with a **Copy** button. Nothing
 * secret goes through it; secrets shown once use `q-secret-once`.
 */
@Component({
  selector: 'q-copy-value',
  templateUrl: './copy-value.html',
  styleUrl: './copy-value.css',
})
export class CopyValue {
  /** The field's id, unique on the page. */
  readonly fieldId = input.required<string>();
  readonly label = input.required<string>();
  readonly value = input.required<string>();
  protected readonly copyState = signal<'idle' | 'copied' | 'failed'>('idle');

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
