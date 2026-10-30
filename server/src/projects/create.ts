import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { branches, projects } from '../db/schema';
import type { ProjectRow } from './access';

/** Who makes a change, as the audit log records it, and the recorder it records through. */
export interface AuditedActor {
  audit: AuditRecorder;
  actor: AuditActorContext;
}

/**
 * A project and its main branch, with the `project.created` event, in the caller's transaction
 * (`POST /projects`, and the repository-setup run). A key that is taken is the unique violation
 * the caller turns into its answer; run it in a savepoint to try another key after one.
 */
export async function createProject(
  tx: Executor,
  input: {
    organizationId: string;
    key: string;
    name: string;
    mainBranchName: string;
    createdBy: AuditedActor;
  },
): Promise<ProjectRow> {
  const created = first(
    await tx
      .insert(projects)
      .values({
        organizationId: input.organizationId,
        key: input.key,
        name: input.name,
        mainBranchName: input.mainBranchName,
      })
      .returning(),
  );
  await tx.insert(branches).values({
    projectId: created.id,
    kind: 'branch',
    name: created.mainBranchName,
    isMain: true,
  });
  const { audit, actor } = input.createdBy;
  // The refs are an audit-only read: none while audit-log is inactive (§8.1).
  if (audit.active()) {
    const refs = await projectRefs(tx, created.id);
    await audit.record(tx, actor, [
      {
        action: 'project.created',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'project', id: created.id, label: created.name },
        details: {
          key: created.key,
          name: created.name,
          mainBranchName: created.mainBranchName,
        },
      },
    ]);
  }
  return created;
}
