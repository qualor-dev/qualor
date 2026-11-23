import { ScmError } from './provider';
import { retryable } from './runtime';

/** More requests now would only be refused too (the retry waits for the provider's Retry-After). */
export const stopsTheJob = (e: ScmError) => e.kind === 'budget' || e.kind === 'rate_limited';

/**
 * The failures of a decoration's parts. A rate limit or the exhausted budget is the job's stop. Any
 * other failure is kept and the job goes on; it then fails with the stop if there is one, else the
 * first retryable one, else the first, so a part that can still succeed is tried again.
 */
export class Failures {
  stop: ScmError | null = null;
  private readonly kept: ScmError[] = [];

  /** Records a failure of the provider's; anything else (the database, a bug) is thrown on. */
  add(err: unknown): void {
    if (!(err instanceof ScmError)) throw err;
    if (stopsTheJob(err)) this.stop ??= err;
    else this.kept.push(err);
  }

  decisive(): ScmError | null {
    return this.stop ?? this.kept.find(retryable) ?? this.kept[0] ?? null;
  }
}

/** One part of the job: its failure is recorded, and null returned, so the others go on. */
export async function attempt<T>(failures: Failures, part: () => Promise<T>): Promise<T | null> {
  try {
    return await part();
  } catch (err) {
    failures.add(err);
    return null;
  }
}
