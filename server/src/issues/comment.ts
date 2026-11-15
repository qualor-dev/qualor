import { ProblemError } from '../http/problem';
import type { UserStatus } from './status-writes';
import { commentRequired } from './transitions';

/** A blank comment is no comment; 422 COMMENT_REQUIRED where §6 requires one. */
export function transitionComment(to: UserStatus, raw: string | undefined): string | null {
  const comment = raw?.trim() ? raw.trim() : null;
  if (comment === null && commentRequired(to)) {
    throw new ProblemError(422, 'COMMENT_REQUIRED', `A comment is required to set ${to}`, {
      errors: [{ path: 'body.comment', message: `Required for ${to}` }],
    });
  }
  return comment;
}
