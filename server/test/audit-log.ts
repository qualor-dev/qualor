import type { AuditLog } from '../src/audit/recorder';

/** A recorder's logger for tests that do not look at its lines (rbac-audit.md §10.2.1). */
export const QUIET_AUDIT_LOG: AuditLog = Object.freeze({ error: () => undefined });
