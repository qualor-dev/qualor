/** Keys for pg_advisory_(xact_)lock. One place so two features never share a key by accident. */
export const LOCKS = {
  migrations: 7_310_001,
  bootstrap: 7_310_002,
  instanceAdmins: 7_310_004,
  housekeeping: 7_310_005,
  /**
   * The first key of `pg_try_advisory_xact_lock(key, hashtext(webhookId))`: one delivery attempt
   * per webhook at a time (ruling X7). The two-key form never collides with the one-key locks.
   */
  webhookDelivery: 7_310_006,
  /**
   * The first key of `pg_try_advisory_xact_lock(key, hashtext(organizationId || ':' || slot))`:
   * the delivery slots of one organisation (MAX_IN_FLIGHT_PER_ORGANIZATION in webhooks/deliver.ts).
   */
  webhookOrganizationSlot: 7_310_007,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(branchId))`: transitions of one branch
   * check for and enqueue its gate re-evaluation one at a time (scm.md §7), so at most one waits.
   */
  gateReevaluation: 7_310_008,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(branchId))`: a new decoration of a
   * branch and a retry of an older one check the branch's queue and enqueue one at a time (scm.md
   * §4.3), so a retry is never queued beside a newer decoration committed meanwhile.
   */
  scmDecoration: 7_310_009,
  /** `pg_advisory_xact_lock(key)`: one writer of the `llm` settings row at a time (llm.md §3.2). */
  llmSettings: 7_310_010,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(organizationId))`: the budget check and
   * the insert of one organisation's AI requests happen one at a time (llm.md §12.1).
   */
  llmQuota: 7_310_011,
  /** `pg_advisory_xact_lock(key)`: one writer of the audit chain at a time (rbac-audit.md §10.2). */
  auditChain: 7_310_012,
  /** `pg_try_advisory_xact_lock(key)`: one SIEM stream run at a time (rbac-audit.md §14.2). */
  auditStream: 7_310_013,
  /** `pg_advisory_xact_lock(key)`: one writer of the `audit` settings row at a time. */
  auditSettings: 7_310_014,
  /** The first key of `pg_advisory_xact_lock(key, hashtext(queue))`: plugin schedules (rbac-audit.md §15). */
  pluginSchedule: 7_310_015,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(projectId))`: one writer of a project's
   * grants at a time, so the 1 000-grant bound holds under concurrency (rbac-audit.md §7.2).
   */
  projectGrants: 7_310_016,
  /**
   * `pg_advisory_xact_lock(key)`: one writer of SSO connections at a time, so the 10-connection
   * bound holds under concurrency (sso-scim.md §4.1); also group mappings and SCIM tokens.
   */
  ssoConnections: 7_310_017,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(connectionId || ':' || subject))`: the
   * account resolution and linking of one IdP subject happen one at a time, so two first sign-ins
   * of the same person make one user (sso-scim.md §8).
   */
  ssoSubject: 7_310_018,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(identityId))`: one SCIM group sync of a
   * person at a time, taken after the request's member-row writes and before the person's SCIM
   * groups are read, so two concurrent group changes never both sync from a stale set
   * (sso-scim.md §9.1). Order: after row locks on identities, before organisation and project
   * locks; a request that syncs several people takes theirs sorted, all before the first sync.
   */
  scimSync: 7_310_019,
} as const;
