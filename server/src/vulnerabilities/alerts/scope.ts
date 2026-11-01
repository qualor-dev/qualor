import type { Executor } from '../../db/client';
import { projects } from '../../db/schema';
import type { Limits } from '../../limits';
import { readVulndbSettings } from '../../vulndb/settings';
import { projectTargets, type Target } from '../targets';

/**
 * The targets vulnerability alerts cover (4b A1): the tracked targets of each project whose own
 * switch is on. Empty unless `vuln.alerts` is active and the instance switch is on. A project
 * without a tracked target is not a key.
 */
export async function alertScope(
  db: Executor,
  limits: Pick<Limits, 'vulnerabilities'>,
): Promise<Map<string, Target[]>> {
  const scope = new Map<string, Target[]>();
  if (!limits.vulnerabilities.alerts) return scope;
  if (!(await readVulndbSettings(db)).enabled) return scope;
  const ids = (await db.select({ id: projects.id }).from(projects)).map((row) => row.id);
  for (const [projectId, targets] of await projectTargets(db, ids)) {
    if (targets.length > 0) scope.set(projectId, targets);
  }
  return scope;
}
