import { sql, type SQL } from 'drizzle-orm';

/** The CLI's engine entry for its licence pass (cli/src/analyzers/trivy-licenses.ts). */
export const LICENSE_ENGINE_ID = 'trivy-licenses';

/**
 * Whether the branch `branchId` (an SQL expression) has a dependency inventory: one of its
 * `branch_dependencies` rows, or, for an empty inventory, a succeeded analysis of the branch whose
 * licence pass completed (its `trivy-licenses` engine is `ok`, which is when the report carries
 * `dependencies`). Any such analysis counts, not only the latest. The one rule for the inventory
 * API, the vulnerability summary, the projects list and the alerts. The subqueries use the
 * aliases `inv_d` and `inv_a`, so an outer alias is never shadowed.
 */
export function branchHasInventory(branchId: SQL): SQL {
  const licensePassOk = JSON.stringify([{ id: LICENSE_ENGINE_ID, status: 'ok' }]);
  return sql`(EXISTS (SELECT 1 FROM branch_dependencies inv_d WHERE inv_d.branch_id = ${branchId})
     OR EXISTS (SELECT 1 FROM analyses inv_a
                 WHERE inv_a.branch_id = ${branchId} AND inv_a.status = 'succeeded'
                   AND inv_a.engines @> ${licensePassOk}::jsonb))`;
}
