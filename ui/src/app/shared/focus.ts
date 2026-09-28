import { afterNextRender, type Injector } from '@angular/core';

/**
 * The focus rule of the pages that change data (as the issue pages do): the control a keyboard
 * user pressed stays focused when it is still there. When it is gone or was removed with its row
 * (focus fell back to the body), focus moves, after the next render, to the first of `targets`
 * that is still in the page: the next row's control, then a heading or the live region.
 */
export function keepFocus(
  injector: Injector,
  document: Document,
  ...targets: (() => HTMLElement | null | undefined)[]
): void {
  afterNextRender(
    () => {
      const active = document.activeElement;
      if (active && active !== document.body && active.isConnected) return;
      for (const target of targets) {
        const element = target();
        if (element?.isConnected) {
          element.focus();
          return;
        }
      }
    },
    { injector },
  );
}

/** The row of a table body whose `data-key` is `key` (keys may hold any character). */
export function rowByKey(table: HTMLElement | undefined, key: string): HTMLElement | null {
  const rows = table?.querySelectorAll<HTMLElement>('tbody tr[data-key]') ?? [];
  return [...rows].find((row) => row.dataset['key'] === key) ?? null;
}

/** The row at `index` in a table body, or the last one when fewer are left. */
export function rowAt(table: HTMLElement | undefined, index: number): HTMLElement | null {
  const rows = [...(table?.querySelectorAll<HTMLElement>('tbody tr[data-key]') ?? [])];
  return rows[Math.min(index, rows.length - 1)] ?? null;
}
