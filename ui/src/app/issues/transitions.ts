/** data-model.md §6 (plan 1E ruling I2): the transitions an issue in a status allows. */
export type TransitionTarget = 'open' | 'resolved' | 'wont_fix' | 'false_positive';

export const ALL_TARGETS: TransitionTarget[] = ['resolved', 'wont_fix', 'false_positive', 'open'];

export function allowedTargets(status: string): TransitionTarget[] {
  if (status === 'open') return ['resolved', 'wont_fix', 'false_positive'];
  if (status === 'resolved' || status === 'wont_fix' || status === 'false_positive') {
    return ['open'];
  }
  return [];
}

/** api.md: `wont_fix` and `false_positive` need a (non-blank) comment. */
export function needsComment(target: TransitionTarget): boolean {
  return target === 'wont_fix' || target === 'false_positive';
}

export const COMMENT_MAX_LENGTH = 2000;

/** api.md `POST /issues/bulk-transition`: at most this many ids per request. */
export const BULK_MAX_IDS = 500;
