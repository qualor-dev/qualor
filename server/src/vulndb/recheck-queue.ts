import type { Executor } from '../db/client';

/** Asks for a re-check of the tracked targets: all of them, or those of these projects. */
export async function enqueueRecheck(
  db: Executor,
  scope: { all: true } | { projectIds: string[] },
): Promise<void> {
  // A no-op until Task 8 makes it real.
  void db;
  void scope;
}
