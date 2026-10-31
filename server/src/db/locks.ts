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
  /** `pg_advisory_xact_lock(key)`: one writer of the telemetry schedule at a time (telemetry.md). */
  telemetry: 7_310_020,
  /** `pg_advisory_xact_lock(key)`: one writer of the `mail` settings row at a time (E1 spec). */
  mailSettings: 7_310_021,
  /** `pg_advisory_xact_lock(key)`: the licence-alert schedule and its daily check, one at a time. */
  licenseAlerts: 7_310_022,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(projectId))`: one project's
   * "analysis failed" emails are queued one at a time, so the 6-hour dedupe holds (mail E3 N7).
   */
  analysisFailedMail: 7_310_023,
  /**
   * `pg_advisory_xact_lock(key)`: one writer of the `licensePolicy` settings row at a time (6M §4).
   */
  licensePolicy: 7_310_024,
  /** `pg_advisory_xact_lock(key)`: the weekly digest's schedule, one writer at a time (6G R14). */
  chatDigest: 7_310_025,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(branchId))`: the hourly state check of a
   * merge request that holds review snapshots is queued one at a time, so a branch has at most one
   * waiting (6I-3, R16). A snapshot's link takes it after the branch row and the snapshot row it
   * links, and holds it while it deletes the branch's older snapshots and wakes the review run
   * (snapshot-store.ts `keepOnly`): the older snapshot rows and the run rows are taken after it.
   * Only the check's own reschedule takes it with nothing else held.
   */
  reviewMrCheck: 7_310_026,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(branchId))`: the check for a queued scan
   * of a merge request's notes and the queueing of one are one step per branch (6I-4,
   * review/reply-queue.ts `queueScan`), so two deliveries never both queue one, and a delivery
   * decides on what the one before it committed. Only `queueScan` takes it, after a plain read of
   * the branch and with nothing else held, and under it runs only that check and the insert: a
   * delivery waits for another delivery's few milliseconds, never for a transaction that holds the
   * branch's row (ingestion), which does not take it. No order is owed to the other locks.
   */
  replyScan: 7_310_027,
  /** `pg_advisory_xact_lock(key)`: one writer of the `vulndb` settings row at a time (0.15). */
  vulndbSettings: 7_310_028,
  /** `pg_advisory_xact_lock(key)`: the `vulndb.update` job schedule, one writer at a time (0.15). */
  vulndbSchedule: 7_310_029,
  /** `pg_advisory_xact_lock(key)`: one read-modify-write of the `vulndb_state` row at a time (0.15). */
  vulndbState: 7_310_030,
  /**
   * `pg_advisory_xact_lock(key)`: requests for a vulnerability re-check merge into the queued job
   * one at a time, so two never both insert one (0.15, vulnerabilities/recheck.ts). Taken as late
   * as the caller's transaction allows (the ingestion's, a route's) and held to its commit: an
   * ingestion still updates its analysis and branch rows after it (ingest/process.ts), under the
   * locks it already holds, and takes no other lock.
   */
  vulnerabilityRecheck: 7_310_031,
  /**
   * The first key of `pg_advisory_xact_lock(key, hashtext(<project id>:<bucket>))`: one writer of
   * a (project, package, vulnerability) pair's decisions at a time (vuln plan 2b,
   * vulnerabilities/decisions.ts `lockDecisionPairs`). The pairs of a project fall into 1 024
   * buckets (`pairBucket`), so a transaction holds at most 1 024 of these per project. Lock order:
   * - A writer (a decision, a transition, the status import) takes it exclusive first, before any
   *   issue or decision row, all of its pairs in one statement in ascending key order; the
   *   issues of the pairs are then locked in one id-ordered statement.
   * - An ingestion takes it shared for the pairs of its Trivy findings (tracking/stage.ts
   *   `buildTrackingPlan`), the same way, before it reads the decisions and before it locks any
   *   issue (tracking/writes.ts `lockPlannedRows`). Before that it holds only its analysis row,
   *   its branch row (`FOR NO KEY UPDATE`, which a writer's foreign-key check never waits on) and
   *   rule rows, none of which a writer waits on.
   */
  vulnerabilityDecision: 7_310_032,
  /**
   * `pg_advisory_xact_lock(key)`: one replace of the KEV or EPSS table at a time (vuln plan 4a,
   * vulndb/priority/store.ts).
   */
  vulnerabilityPriority: 7_310_033,
  /** `pg_advisory_xact_lock(key)`: one read-modify-write of the priority datasets' state at a time (4a). */
  vulndbPriorityState: 7_310_034,
} as const;
