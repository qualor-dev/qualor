import { createHash } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { and, desc, eq, inArray, lt, sql, type SQL } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import { actorOf, type AuditEventInput, type AuditRecorder } from '../audit/recorder';
import {
  requireOrganizationAccess,
  requireOrganizationMember,
  requireUser,
  type AccessContext,
} from '../auth/access';
import type { UserPrincipal } from '../auth/principal';
import type { Db, Executor } from '../db/client';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION, pgConstraint, pgErrorCode } from '../db/errors';
import { uuidv7 } from '../db/ids';
import {
  analyses,
  branches,
  complianceReports,
  organizations,
  projects,
  projectVersions,
  vulnerabilityTargetChecks,
  type ComplianceReportScope,
} from '../db/schema';
import { conflict, notFound, ProblemError, validationFailed } from '../http/problem';
import type {
  ComplianceDownloadFormat,
  ComplianceReportView,
  PluginCompliance,
} from '../plugins/contract';
import { projectForUser } from '../projects/access';
import { monitoringOn } from '../vulnerabilities/targets';
import { collectCompliance, ComplianceCollectError } from './collect';
import { cut } from './text';

export const FEATURE = 'compliance-export';
const PRIORITY_FEATURE = 'vuln.priority';
/** 4E-1 §1: the stored summary is at most 64 KiB of JSON. */
const SUMMARY_MAX = 65_536;
/** 4E-1 §1: a failed row's reason, in characters. */
const ERROR_MAX = 500;
const NAME_MAX = 255;
const LIST_MAX = 100;
const FORMATS: readonly ComplianceDownloadFormat[] = ['json', 'csv', 'pdf'];
const PENDING_KEY = 'compliance_reports_pending_key';
const SUMMARY_CHECK = 'compliance_reports_summary_size';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RETENTION = sql`interval '365 days'`;
const STALE = sql`interval '1 hour'`;

/** The report columns every caller-facing member reads, never `data`. */
const REPORT = {
  id: complianceReports.id,
  scope: complianceReports.scope,
  status: complianceReports.status,
  organizationId: organizations.id,
  organizationKey: organizations.key,
  organizationName: organizations.name,
  projectId: projects.id,
  projectKey: projects.key,
  projectName: projects.name,
  branchId: branches.id,
  branchName: branches.name,
  versionId: projectVersions.id,
  versionLabel: projectVersions.label,
  createdByName: complianceReports.createdByName,
  createdAt: complianceReports.createdAt,
  completedAt: complianceReports.completedAt,
  standards: complianceReports.standards,
  sha256: complianceReports.sha256,
  sizeBytes: complianceReports.sizeBytes,
  error: complianceReports.error,
  summary: complianceReports.summary,
};

type ReportRow = {
  id: string;
  scope: ComplianceReportScope;
  status: ComplianceReportView['status'];
  organizationId: string;
  organizationKey: string;
  organizationName: string;
  projectId: string | null;
  projectKey: string | null;
  projectName: string | null;
  branchId: string | null;
  branchName: string | null;
  versionId: string | null;
  versionLabel: string | null;
  createdByName: string;
  createdAt: Date;
  completedAt: Date | null;
  standards: ComplianceReportView['standards'];
  sha256: string | null;
  sizeBytes: number | null;
  error: string | null;
  summary: unknown;
};

function rowView(row: ReportRow, canDelete: boolean): ComplianceReportView {
  return {
    id: row.id,
    scope: row.scope,
    organization: { id: row.organizationId, key: row.organizationKey, name: row.organizationName },
    project:
      row.projectId === null
        ? null
        : { id: row.projectId, key: row.projectKey ?? '', name: row.projectName ?? '' },
    branch: row.branchId === null ? null : { id: row.branchId, name: row.branchName ?? '' },
    version: row.versionId === null ? null : { id: row.versionId, label: row.versionLabel ?? '' },
    status: row.status,
    createdBy: row.createdByName,
    createdAt: row.createdAt.toISOString(),
    completedAt: row.completedAt === null ? null : row.completedAt.toISOString(),
    standards: row.standards,
    sha256: row.sha256,
    sizeBytes: row.sizeBytes,
    error: row.error,
    summary: row.summary ?? null,
    canDelete,
  };
}

/** The audit references of a report: its organisation, its project, and the report as target. */
function references(row: ReportRow): Pick<AuditEventInput, 'organization' | 'project' | 'target'> {
  return {
    organization: { id: row.organizationId, key: row.organizationKey },
    project: row.projectId === null ? null : { id: row.projectId, key: row.projectKey ?? '' },
    target: {
      type: 'compliance_report',
      id: row.id,
      label: row.projectKey ?? row.organizationKey,
    },
  };
}

const isRefusal = (err: unknown): boolean =>
  err instanceof ProblemError && (err.status === 403 || err.status === 404);

/**
 * 4E-1 §1.1, §2.4, §3: the core service behind `ctx.compliance`. The caller-facing members check
 * the caller with the functions core routes use; a report the caller cannot read is a 404, never
 * a 403. The job-side members take no caller. Every member except `housekeeping` answers 403
 * FEATURE_NOT_LICENSED while the feature is inactive.
 */
export function createComplianceService(deps: {
  db: Db;
  isFeatureActive: (feature: string) => boolean;
  recorder: AuditRecorder;
}): PluginCompliance {
  const { db } = deps;
  const access: AccessContext = { db };

  const gate = (): void => {
    if (!deps.isFeatureActive(FEATURE)) {
      throw new ProblemError(
        403,
        'FEATURE_NOT_LICENSED',
        `The enterprise feature "${FEATURE}" is not licensed`,
      );
    }
  };

  const reportNotFound = (): ProblemError => notFound('Report');

  /** The reports matching `where`, joined with their names. */
  const selectReports = (where: SQL | undefined, executor: Executor = db) =>
    executor
      .select(REPORT)
      .from(complianceReports)
      .innerJoin(organizations, eq(organizations.id, complianceReports.organizationId))
      .leftJoin(projects, eq(projects.id, complianceReports.projectId))
      .leftJoin(branches, eq(branches.id, complianceReports.branchId))
      .leftJoin(projectVersions, eq(projectVersions.id, complianceReports.versionId))
      .where(where);

  /** Whether the caller holds org.compliance.manage (and the token scope) on the organisation. */
  const manages = async (principal: UserPrincipal, organizationId: string): Promise<boolean> => {
    try {
      await requireOrganizationAccess(access, principal, organizationId, 'org.compliance.manage');
      return true;
    } catch (err) {
      if (isRefusal(err)) return false;
      throw err;
    }
  };

  /** The read rule of a report's scope (4E-1 §3); a refusal is thrown as it comes. */
  const checkRead = async (principal: UserPrincipal, row: ReportRow): Promise<void> => {
    if (row.projectId === null) {
      await requireOrganizationMember(access, principal, row.organizationId);
    } else {
      await projectForUser(access, principal, row.projectId, 'project.read');
    }
  };

  /** The report, when the caller may read it; a missing and an unreadable report are one 404. */
  const readable = async (
    request: FastifyRequest,
    id: string,
  ): Promise<{ principal: UserPrincipal; row: ReportRow }> => {
    const principal = requireUser(request);
    if (typeof id !== 'string' || !UUID.test(id)) throw reportNotFound();
    const [row] = await selectReports(eq(complianceReports.id, id));
    if (!row) throw reportNotFound();
    try {
      await checkRead(principal, row);
    } catch (err) {
      if (isRefusal(err)) throw reportNotFound();
      throw err;
    }
    return { principal, row };
  };

  /** The branch a project report is built for: `branchId` (a plain branch of it) or the main one. */
  const reportBranch = async (
    projectId: string,
    branchId: string | undefined,
  ): Promise<{ id: string; name: string }> => {
    if (branchId !== undefined && (typeof branchId !== 'string' || !UUID.test(branchId))) {
      throw notFound('Branch');
    }
    const [branch] = await db
      .select({ id: branches.id, name: branches.name })
      .from(branches)
      .where(
        and(
          eq(branches.projectId, projectId),
          branchId === undefined
            ? eq(branches.isMain, true)
            : and(eq(branches.id, branchId), eq(branches.kind, 'branch')),
        ),
      );
    if (!branch) throw notFound('Branch');
    const [analysed] = await db
      .select({ id: analyses.id })
      .from(analyses)
      .where(and(eq(analyses.branchId, branch.id), eq(analyses.status, 'succeeded')))
      .limit(1);
    if (!analysed) throw conflict('NO_ANALYSIS', 'The branch has no successful analysis yet');
    return branch;
  };

  /**
   * The version a project report is built for (plan 5, V12), checked in order: it belongs to the
   * project (404), monitoring is on for the project and the instance (409 MONITORING_OFF), and it
   * has been checked for vulnerabilities (409 NOT_CHECKED).
   */
  const reportVersion = async (
    projectId: string,
    versionId: unknown,
  ): Promise<{ id: string; label: string }> => {
    if (typeof versionId !== 'string' || !UUID.test(versionId)) throw notFound('Version');
    const [version] = await db
      .select({ id: projectVersions.id, label: projectVersions.label })
      .from(projectVersions)
      .where(and(eq(projectVersions.id, versionId), eq(projectVersions.projectId, projectId)));
    if (!version) throw notFound('Version');
    if (!(await monitoringOn(db, projectId))) {
      throw conflict('MONITORING_OFF', 'Vulnerability monitoring is off for this project');
    }
    const [checked] = await db
      .select({ projectId: vulnerabilityTargetChecks.projectId })
      .from(vulnerabilityTargetChecks)
      .where(eq(vulnerabilityTargetChecks.versionId, version.id));
    if (!checked) {
      throw conflict('NOT_CHECKED', 'This version has not been checked for vulnerabilities yet');
    }
    return version;
  };

  const create: PluginCompliance['create'] = async (request, input, standards) => {
    gate();
    const principal = requireUser(request);
    const target = input as Partial<{
      organizationId: string;
      projectId: string;
      branchId: string;
      versionId: string;
    }>;
    let organizationId: string;
    let projectId: string | null = null;
    let branch: { id: string; name: string } | null = null;
    let version: { id: string; label: string } | null = null;
    if (typeof target.projectId === 'string') {
      const project = await projectForUser(
        access,
        principal,
        target.projectId,
        'project.compliance.create',
      );
      organizationId = project.organizationId;
      projectId = project.id;
      if (target.branchId !== undefined && target.versionId !== undefined) {
        throw validationFailed([
          { path: 'body.versionId', message: 'Give a branch or a version, not both' },
        ]);
      }
      if (target.versionId !== undefined) {
        version = await reportVersion(project.id, target.versionId);
      } else {
        branch = await reportBranch(project.id, target.branchId);
      }
    } else {
      if (typeof target.organizationId !== 'string') throw notFound('Organization');
      const org = await requireOrganizationAccess(
        access,
        principal,
        target.organizationId,
        'org.compliance.manage',
      );
      organizationId = org.organizationId;
    }
    const scope: ComplianceReportScope = projectId === null ? 'organization' : 'project';
    const user = principal.user;
    const createdByName = cut(user.displayName?.trim() || user.username, NAME_MAX) ?? '';

    let row: ReportRow;
    try {
      row = await db.transaction(async (tx) => {
        const id = uuidv7();
        await tx.insert(complianceReports).values({
          id,
          organizationId,
          projectId,
          branchId: branch?.id ?? null,
          versionId: version?.id ?? null,
          scope,
          status: 'pending',
          createdBy: user.id,
          createdByName,
          standards: standards.map((s) => ({
            id: s.id,
            version: s.version,
            sourceSha256: s.sourceSha256,
          })),
        });
        const [created] = await selectReports(eq(complianceReports.id, id), tx);
        if (!created) throw new Error('the inserted compliance report is missing');
        await deps.recorder.record(tx, actorOf(request), [
          {
            action: 'compliance.report.created',
            ...references(created),
            details: {
              scope,
              branch: branch?.name ?? null,
              ...(version === null ? {} : { version: { id: version.id, label: version.label } }),
            },
          },
        ]);
        return created;
      });
    } catch (err) {
      if (pgErrorCode(err) === PG_UNIQUE_VIOLATION && pgConstraint(err) === PENDING_KEY) {
        throw conflict('REPORT_PENDING', 'A report for this scope is already being built');
      }
      throw err;
    }
    return rowView(row, await manages(principal, row.organizationId));
  };

  const list: PluginCompliance['list'] = async (request, filter, page) => {
    gate();
    const principal = requireUser(request);
    if (!Number.isInteger(page.limit) || page.limit < 1 || page.limit > LIST_MAX) {
      throw validationFailed([{ path: 'query.limit', message: `Use 1 to ${LIST_MAX}` }]);
    }
    if (page.cursor !== undefined && (typeof page.cursor !== 'string' || !UUID.test(page.cursor))) {
      throw validationFailed([
        { path: 'query.cursor', message: 'Use a cursor from a previous page' },
      ]);
    }
    const f = filter as Partial<{ organizationId: string; projectId: string }>;
    let scopeCondition: SQL | undefined;
    let canDelete: boolean;
    if (typeof f.projectId === 'string') {
      const project = await projectForUser(access, principal, f.projectId, 'project.read');
      scopeCondition = eq(complianceReports.projectId, project.id);
      canDelete = await manages(principal, project.organizationId);
    } else {
      if (typeof f.organizationId !== 'string') throw notFound('Organization');
      const org = await requireOrganizationMember(access, principal, f.organizationId);
      scopeCondition = and(
        eq(complianceReports.organizationId, org.organizationId),
        eq(complianceReports.scope, 'organization'),
      );
      canDelete = await manages(principal, org.organizationId);
    }
    const rows = await selectReports(
      and(
        scopeCondition,
        page.cursor === undefined ? undefined : lt(complianceReports.id, page.cursor),
      ),
    )
      .orderBy(desc(complianceReports.id))
      .limit(page.limit + 1);
    const items = rows.slice(0, page.limit);
    const last = items.at(-1);
    return {
      items: items.map((r) => rowView(r, canDelete)),
      nextCursor: rows.length > page.limit && last ? last.id : null,
    };
  };

  const get: PluginCompliance['get'] = async (request, id) => {
    gate();
    const { principal, row } = await readable(request, id);
    return rowView(row, await manages(principal, row.organizationId));
  };

  const download: PluginCompliance['download'] = async (request, id, format) => {
    gate();
    if (!FORMATS.includes(format)) {
      throw validationFailed([{ path: 'query.format', message: 'Use json, csv or pdf' }]);
    }
    const { principal, row } = await readable(request, id);
    if (row.status !== 'ready') throw conflict('REPORT_NOT_READY', 'The report is not ready');
    const [stored] = await db
      .select({ data: complianceReports.data })
      .from(complianceReports)
      .where(and(eq(complianceReports.id, row.id), eq(complianceReports.status, 'ready')));
    if (!stored?.data || row.sha256 === null) throw reportNotFound();
    const canonical = gunzipSync(stored.data);
    await deps.recorder.record(db, actorOf(request), [
      {
        action: 'compliance.report.downloaded',
        ...references(row),
        details: { format, sha256: row.sha256 },
      },
    ]);
    return { view: rowView(row, await manages(principal, row.organizationId)), canonical };
  };

  const remove: PluginCompliance['remove'] = async (request, id) => {
    gate();
    const { principal, row } = await readable(request, id);
    await requireOrganizationAccess(access, principal, row.organizationId, 'org.compliance.manage');
    if (row.status === 'pending') {
      throw conflict('REPORT_PENDING', 'A report that is being built cannot be deleted');
    }
    await db.transaction(async (tx) => {
      const deleted = await tx
        .delete(complianceReports)
        .where(
          and(
            eq(complianceReports.id, row.id),
            inArray(complianceReports.status, ['ready', 'failed']),
          ),
        )
        .returning({ id: complianceReports.id });
      if (deleted.length === 0) throw reportNotFound();
      await deps.recorder.record(tx, actorOf(request), [
        { action: 'compliance.report.deleted', ...references(row), details: { scope: row.scope } },
      ]);
    });
  };

  const collect: PluginCompliance['collect'] = async (id, options) => {
    gate();
    try {
      return await collectCompliance(db, id, {
        ...options,
        priority: deps.isFeatureActive(PRIORITY_FEATURE),
      });
    } catch (err) {
      if (err instanceof ComplianceCollectError) {
        throw new ProblemError(422, 'REPORT_BUILD_FAILED', 'The report could not be built', {
          detail: err.message,
        });
      }
      throw err;
    }
  };

  const fail: PluginCompliance['fail'] = async (id, error) => {
    gate();
    if (typeof id !== 'string' || !UUID.test(id)) return false;
    const changed = await db
      .update(complianceReports)
      .set({
        status: 'failed',
        error: cut(String(error), ERROR_MAX) ?? '',
        completedAt: sql`now()`,
      })
      .where(and(eq(complianceReports.id, id), eq(complianceReports.status, 'pending')))
      .returning({ id: complianceReports.id });
    return changed.length > 0;
  };

  /**
   * A summary over 64 KiB, or a `sha256` that is not the SHA-256 of the canonical bytes, fails the
   * row instead and answers false: nothing was completed. The column's check counts the stored
   * jsonb text, which can be longer than JSON.stringify's, so its violation is the same refusal.
   * Core stores the SHA-256 it computed itself.
   */
  const complete: PluginCompliance['complete'] = async (id, result) => {
    gate();
    if (typeof id !== 'string' || !UUID.test(id)) return false;
    const refuse = async (reason: string): Promise<false> => {
      await fail(id, reason);
      return false;
    };
    const tooLarge = () => refuse('the report summary is too large');
    const sha256 = createHash('sha256').update(result.canonical).digest('hex');
    if (result.sha256 !== sha256) return refuse('the report hash does not match');
    if (Buffer.byteLength(JSON.stringify(result.summary) ?? '') > SUMMARY_MAX) return tooLarge();
    try {
      const changed = await db
        .update(complianceReports)
        .set({
          status: 'ready',
          data: gzipSync(result.canonical),
          sha256,
          sizeBytes: result.canonical.length,
          summary: result.summary,
          // The refs the build used: after a rolling upgrade they can differ from the
          // ones stored at creation, and the row must agree with the JSON.
          ...(result.standards === undefined
            ? {}
            : {
                standards: result.standards.map((s) => ({
                  id: s.id,
                  version: s.version,
                  sourceSha256: s.sourceSha256,
                })),
              }),
          completedAt: sql`now()`,
        })
        .where(and(eq(complianceReports.id, id), eq(complianceReports.status, 'pending')))
        .returning({ id: complianceReports.id });
      return changed.length > 0;
    } catch (err) {
      if (pgErrorCode(err) === PG_CHECK_VIOLATION && pgConstraint(err) === SUMMARY_CHECK) {
        return tooLarge();
      }
      throw err;
    }
  };

  /** 4E-1 §2.4 step 5: retention, and pending rows whose build did not finish. */
  const housekeeping: PluginCompliance['housekeeping'] = async () => {
    const deleted = await db
      .delete(complianceReports)
      .where(
        and(
          inArray(complianceReports.status, ['ready', 'failed']),
          lt(complianceReports.createdAt, sql`now() - ${RETENTION}`),
        ),
      )
      .returning({ id: complianceReports.id });
    const failed = await db
      .update(complianceReports)
      .set({ status: 'failed', error: 'the build did not finish', completedAt: sql`now()` })
      .where(
        and(
          eq(complianceReports.status, 'pending'),
          lt(complianceReports.createdAt, sql`now() - ${STALE}`),
        ),
      )
      .returning({ id: complianceReports.id });
    return { deleted: deleted.length, failed: failed.length };
  };

  return Object.freeze({
    create,
    list,
    get,
    download,
    remove,
    collect,
    complete,
    fail,
    housekeeping,
  } satisfies PluginCompliance);
}
