/** The value of the input, select or textarea an event came from (templates bind signals by hand). */
export function inputValue(event: Event): string {
  const target = event.target;
  if (
    target instanceof HTMLInputElement ||
    target instanceof HTMLSelectElement ||
    target instanceof HTMLTextAreaElement
  ) {
    return target.value;
  }
  return '';
}

export function isChecked(event: Event): boolean {
  return event.target instanceof HTMLInputElement && event.target.checked;
}

/**
 * Empties a field and its signal together. The `[value]` binding alone cannot do it when the
 * signal went from '' to the typed text and back to '' before a change detection ran (a quick
 * Enter): the binding still holds '' and leaves the typed text (a password, say) in the field.
 */
export function clearField(
  field: { nativeElement: HTMLInputElement | HTMLTextAreaElement } | undefined,
  value: { set(value: string): void },
): void {
  value.set('');
  if (field) field.nativeElement.value = '';
}
