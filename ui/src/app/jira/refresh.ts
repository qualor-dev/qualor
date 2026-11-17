import { type DestroyRef, effect, untracked } from '@angular/core';

/** R22: while a shown Jira link is pending, the page reads its data again this often… */
export const JIRA_REFRESH_MS = 3_000;
/** …at most this many times in a row (two minutes while Jira is slow). */
export const JIRA_REFRESH_MAX = 40;

/**
 * Reloads a page's data every {@link JIRA_REFRESH_MS} while `pending()` holds (a shown Jira link is
 * `pending`), at most {@link JIRA_REFRESH_MAX} times in a row; once nothing is pending the count
 * starts again. The timer chain does not depend on how the reloaded data compares to the old, and
 * it stops with the page. Call it in an injection context: it watches `pending` with an effect.
 */
export function refreshWhilePending(
  pending: () => boolean,
  reload: () => void,
  destroyRef: DestroyRef,
): void {
  let reloads = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = () => {
    clearTimeout(timer);
    timer = undefined;
  };
  const tick = () => {
    timer = undefined;
    if (!untracked(pending) || reloads >= JIRA_REFRESH_MAX) return;
    reloads++;
    reload();
    if (reloads < JIRA_REFRESH_MAX) timer = setTimeout(tick, JIRA_REFRESH_MS);
  };
  effect(() => {
    if (!pending()) {
      reloads = 0;
      stop();
    } else if (timer === undefined && reloads < JIRA_REFRESH_MAX) {
      timer = setTimeout(tick, JIRA_REFRESH_MS);
    }
  });
  destroyRef.onDestroy(stop);
}
