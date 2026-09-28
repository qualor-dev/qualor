import type { Severity } from '@qualor/shared';
import { eq, sql } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { UserRow } from '../auth/sessions';
import type { Db } from '../db/client';
import { issueChanges, issues } from '../db/schema';
import { enqueueReevaluations } from '../gates/reevaluate';
import type { IssueRow } from '../projects/access';
import { setLockTimeout, TRANSITION_LOCK_TIMEOUT_MS } from './transitions';

/**
 * `PATCH /issues/{id}` (api.md §3): a user severity override. The row is locked, so the changelog
 * records the severity it really replaced; setting the severity it already has changes nothing
 * and logs nothing. Waits at most {@link TRANSITION_LOCK_TIMEOUT_MS} for the row lock (then
 * 55P03, 503). Tracking keeps an overridden severity across analyses (tracking/writes.ts). A
 * changed severity re-evaluates the gate of the branch's latest analysis (scm.md §7).
 * Returns null when the issue was deleted meanwhile. With `audit`, a changed severity records
 * `issue.severity_changed` in the same transaction (rbac-audit.md §8).
 */
export async function overrideSeverity(
  db: Db,
  user: UserRow,
  issueId: string,
  severity: Severity,
  audit?: { recorder: AuditRecorder; context: AuditActorContext },
): Promise<IssueRow | null> {
  return db.transaction(async (tx) => {
    // Like a transition (ruling I4): wait at most 5 s for a row an ingestion holds, then 503.
    await setLockTimeout(tx, TRANSITION_LOCK_TIMEOUT_MS);
    const [current] = await tx
      .select()
      .from(issues)
      .where(eq(issues.id, issueId))
      .for('no key update');
    if (!current) return null;
    if (current.severity === severity && current.severityOverridden) return current;
    const [updated] = await tx
      .update(issues)
      .set({ severity, severityOverridden: true, updatedAt: sql`now()` })
      .where(eq(issues.id, issueId))
      .returning();
    if (current.severity !== severity) {
      await tx.insert(issueChanges).values({
        issueId,
        userId: user.id,
        field: 'severity',
        oldValue: current.severity,
        newValue: severity,
      });
      await enqueueReevaluations(tx, [issueId]);
      if (audit?.recorder.active()) {
        const refs = await projectRefs(tx, current.projectId);
        await audit.recorder.record(tx, audit.context, [
          {
            action: 'issue.severity_changed',
            organization: refs.organization,
            project: refs.project,
            target: { type: 'issue', id: issueId, label: null },
            details: { from: current.severity, to: severity },
          },
        ]);
      }
    }
    return updated ?? null;
  });
}
