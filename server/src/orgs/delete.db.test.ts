import type { LicensePolicy } from '@qualor/shared';
import { and, count, eq, inArray, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedFix } from '../../test/fixes';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { bootstrap } from '../auth/bootstrap';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db } from '../db/client';
import {
  analyses,
  auditEvents,
  branches,
  dependencyFixes,
  gateConditions,
  instanceSettings,
  issues,
  jiraConnections,
  jobs,
  memberships,
  organizations,
  projects,
  qualityGates,
  qualityProfiles,
  scmConnections,
  users,
  webhookSubscriptions,
} from '../db/schema';
import { LICENSE_POLICY_SETTINGS_KEY } from '../licenses/settings';
import { DEFAULT_LLM_SETTINGS, DISABLED_ORGANIZATION, LLM_SETTINGS_KEY } from '../llm/settings';
import { createProject } from '../projects/create';
import { DEFAULT_MAX_ATTEMPTS, enqueue } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import {
  deleteOrganization,
  deletingOrganizations,
  ORGANIZATION_DELETE_QUEUE,
  organizationDeleteHandlers,
  organizationDeleteKey,
  queueOrganizationDelete,
} from './delete';
import { createOrganization } from './service';

/** An active recorder, so the organisation and its project leave audit events behind. */
const audit = createAuditRecorder({ isActive: () => true, log: QUIET_AUDIT_LOG });
const KEY = encryptionKey('test-secret-key-that-is-at-least-32-characters');

let t: TestDatabase;
let db: Db;
let adminId: string;

beforeAll(async () => {
  t = await createTestDatabase();
  db = t.db;
  await bootstrap(db, { username: 'admin', password: 'correct horse battery staple' });
  const [admin] = await db.select({ id: users.id }).from(users).where(eq(users.username, 'admin'));
  adminId = admin!.id;
});

afterAll(async () => {
  await t.close();
});

/** An organisation with its built-in gate and profiles, its admin and its `organization.created` event. */
async function newOrganization(key: string): Promise<string> {
  const org = await createOrganization(
    db,
    { key, name: `Org ${key}`, creatorId: adminId },
    { recorder: audit, context: SYSTEM_ACTOR },
  );
  return org.id;
}

interface Seeded {
  organizationId: string;
  memberId: string;
  projectId: string;
  analysisId: string;
  issueIds: string[];
  gateId: string;
  scmConnectionId: string;
  jiraConnectionId: string;
  webhookId: string;
  fixId: string;
}

/**
 * An organisation holding one of each: a member, a project (with its main branch and the
 * `project.created` event), an analysis, issues, a quality gate of its own with a condition, an SCM
 * connection the project is mapped to, a Jira connection, a webhook subscription and a fix row.
 */
async function seedOrganization(key: string): Promise<Seeded> {
  const organizationId = await newOrganization(key);
  const [member] = await db
    .insert(users)
    .values({ username: `${key}-member`, passwordHash: 'x' })
    .returning({ id: users.id });
  await db.insert(memberships).values({ organizationId, userId: member!.id, role: 'viewer' });
  const [gate] = await db
    .insert(qualityGates)
    .values({ organizationId, name: 'Strict' })
    .returning({ id: qualityGates.id });
  await db
    .insert(gateConditions)
    .values({ gateId: gate!.id, metricKey: 'new_violations', operator: 'gt', threshold: 0 });
  const [scm] = await db
    .insert(scmConnections)
    .values({
      organizationId,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.example.com',
      tokenEnc: encryptSecret(KEY, 'scm-token', 'scm_connections.token_enc'),
    })
    .returning({ id: scmConnections.id });
  const project = await db.transaction((tx) =>
    createProject(tx, {
      organizationId,
      key: `${key}-app`,
      name: `${key} app`,
      mainBranchName: 'main',
      createdBy: { audit, actor: SYSTEM_ACTOR },
    }),
  );
  await db
    .update(projects)
    .set({ qualityGateId: gate!.id, scmConnectionId: scm!.id, scmProjectRef: '42' })
    .where(eq(projects.id, project.id));
  const branchId = await mainBranchId(db, project.id);
  const [analysis] = await db
    .insert(analyses)
    .values({ projectId: project.id, branchId })
    .returning({ id: analyses.id });
  const ruleId = await seedRule(db, { key: 'eslint:no-eval' });
  const issueIds = [
    await seedIssue(db, { projectId: project.id, branchId, ruleId }),
    await seedIssue(db, { projectId: project.id, branchId, ruleId, status: 'resolved' }),
  ];
  const [jira] = await db
    .insert(jiraConnections)
    .values({
      organizationId,
      deployment: 'data_center',
      siteUrl: 'https://jira.example.com',
      tokenEnc: encryptSecret(KEY, 'jira-token', 'jira_connections.token_enc'),
    })
    .returning({ id: jiraConnections.id });
  const [webhook] = await db
    .insert(webhookSubscriptions)
    .values({
      organizationId,
      projectId: project.id,
      url: 'https://hooks.example.com/qualor',
      secretEnc: encryptSecret(KEY, 'hook-secret', 'webhook_subscriptions.secret_enc'),
      events: ['analysis.completed'],
    })
    .returning({ id: webhookSubscriptions.id });
  const fixId = await seedFix(db, { projectId: project.id, family: 'js', packageName: 'lodash' });
  return {
    organizationId,
    memberId: member!.id,
    projectId: project.id,
    analysisId: analysis!.id,
    issueIds,
    gateId: gate!.id,
    scmConnectionId: scm!.id,
    jiraConnectionId: jira!.id,
    webhookId: webhook!.id,
    fixId,
  };
}

async function countOf(table: PgTable, where: SQL | undefined): Promise<number> {
  const [row] = await db.select({ n: count() }).from(table).where(where);
  return row?.n ?? 0;
}

/** How many of the seeded rows each table still holds. */
async function heldRows(s: Seeded): Promise<Record<string, number>> {
  return {
    organizations: await countOf(organizations, eq(organizations.id, s.organizationId)),
    memberships: await countOf(memberships, eq(memberships.organizationId, s.organizationId)),
    projects: await countOf(projects, eq(projects.id, s.projectId)),
    branches: await countOf(branches, eq(branches.projectId, s.projectId)),
    analyses: await countOf(analyses, eq(analyses.id, s.analysisId)),
    issues: await countOf(issues, inArray(issues.id, s.issueIds)),
    qualityGates: await countOf(qualityGates, eq(qualityGates.organizationId, s.organizationId)),
    gateConditions: await countOf(gateConditions, eq(gateConditions.gateId, s.gateId)),
    qualityProfiles: await countOf(
      qualityProfiles,
      eq(qualityProfiles.organizationId, s.organizationId),
    ),
    scmConnections: await countOf(scmConnections, eq(scmConnections.id, s.scmConnectionId)),
    jiraConnections: await countOf(jiraConnections, eq(jiraConnections.id, s.jiraConnectionId)),
    webhookSubscriptions: await countOf(
      webhookSubscriptions,
      eq(webhookSubscriptions.id, s.webhookId),
    ),
    dependencyFixes: await countOf(dependencyFixes, eq(dependencyFixes.id, s.fixId)),
  };
}

const auditRowsOf = (organizationId: string) =>
  db
    .select()
    .from(auditEvents)
    .where(eq(auditEvents.organizationId, organizationId))
    .orderBy(auditEvents.seq);

const storedSetting = async (key: string): Promise<unknown> =>
  (
    await db
      .select({ value: instanceSettings.value })
      .from(instanceSettings)
      .where(eq(instanceSettings.key, key))
  )[0]?.value;

const storeSetting = (key: string, value: unknown) =>
  db
    .insert(instanceSettings)
    .values({ key, value })
    .onConflictDoUpdate({ target: instanceSettings.key, set: { value } });

const jobsOf = (organizationId: string) =>
  db
    .select({
      queue: jobs.queue,
      status: jobs.status,
      payload: jobs.payload,
      maxAttempts: jobs.maxAttempts,
    })
    .from(jobs)
    .where(eq(jobs.concurrencyKey, organizationDeleteKey(organizationId)));

/** A worker logger that keeps every line it is given, by level. */
function recordingLogger() {
  const lines: { level: string; message: unknown }[] = [];
  const at =
    (level: string) =>
    (...args: unknown[]): void =>
      void lines.push({ level, message: args[1] });
  return { lines, logger: { info: at('info'), warn: at('warn'), error: at('error') } };
}

const POLICY: LicensePolicy = {
  mode: 'allowlist',
  forbiddenGroups: [],
  forbidden: [],
  allowed: ['MIT'],
  warnUnknown: true,
};

describe('deleteOrganization (0.16 issue #37)', () => {
  it('deletes the organisation and what it holds', async () => {
    const s = await seedOrganization('doomed');
    const before = await heldRows(s);
    for (const [table, n] of Object.entries(before)) expect(n, table).toBeGreaterThan(0);

    expect(await deleteOrganization(db, s.organizationId)).toBe('deleted');

    const after = await heldRows(s);
    expect(after).toEqual(Object.fromEntries(Object.keys(after).map((table) => [table, 0])));
    // Its members are users of the instance: only their membership goes.
    expect(await countOf(users, eq(users.id, s.memberId))).toBe(1);
  });

  it('keeps the audit trail', async () => {
    const s = await seedOrganization('audited');
    const before = await auditRowsOf(s.organizationId);
    expect(before.map((e) => e.action)).toEqual(['organization.created', 'project.created']);

    expect(await deleteOrganization(db, s.organizationId)).toBe('deleted');

    expect(await auditRowsOf(s.organizationId)).toEqual(before);
  });

  it('profiles with a parent: a profile tree goes in one statement (RESTRICT on parent_id)', async () => {
    const organizationId = await newOrganization('tree');
    const profile = async (name: string, language: string, parentId: string | null) =>
      (
        await db
          .insert(qualityProfiles)
          .values({ organizationId, name, language, parentId })
          .returning({ id: qualityProfiles.id })
      )[0]!.id;
    const [builtinJava] = await db
      .select({ id: qualityProfiles.id })
      .from(qualityProfiles)
      .where(
        and(
          eq(qualityProfiles.organizationId, organizationId),
          eq(qualityProfiles.language, 'java'),
          eq(qualityProfiles.isBuiltin, true),
        ),
      );
    // A child of a built-in made before it, and a three-level tree made in order.
    await profile('Java strict', 'java', builtinJava!.id);
    const base = await profile('Base', 'typescript', null);
    const strict = await profile('Strict', 'typescript', base);
    await profile('Stricter', 'typescript', strict);

    expect(await deleteOrganization(db, organizationId)).toBe('deleted');

    expect(await countOf(qualityProfiles, eq(qualityProfiles.organizationId, organizationId))).toBe(
      0,
    );
  });

  it('tidies instance settings: only the other organisations’ entries remain', async () => {
    const doomed = await newOrganization('tidy-doomed');
    const kept = await newOrganization('tidy-kept');
    const licenses = {
      organizations: { [doomed]: POLICY, [kept]: { ...POLICY, allowed: ['Apache-2.0'] } },
      // A member a newer version wrote stays as it is.
      newer: { kept: true },
    };
    const llm = {
      ...DEFAULT_LLM_SETTINGS,
      organizations: {
        [doomed]: DISABLED_ORGANIZATION,
        [kept]: { ...DISABLED_ORGANIZATION, enabled: true },
      },
    };
    await storeSetting(LICENSE_POLICY_SETTINGS_KEY, licenses);
    await storeSetting(LLM_SETTINGS_KEY, llm);
    try {
      expect(await deleteOrganization(db, doomed)).toBe('deleted');

      expect(await storedSetting(LICENSE_POLICY_SETTINGS_KEY)).toEqual({
        ...licenses,
        organizations: { [kept]: licenses.organizations[kept] },
      });
      expect(await storedSetting(LLM_SETTINGS_KEY)).toEqual({
        ...llm,
        organizations: { [kept]: llm.organizations[kept] },
      });
    } finally {
      await db
        .delete(instanceSettings)
        .where(inArray(instanceSettings.key, [LICENSE_POLICY_SETTINGS_KEY, LLM_SETTINGS_KEY]));
    }
  });

  it('a missing row or entry is left as it is', async () => {
    // No row: none is written.
    expect(await deleteOrganization(db, await newOrganization('no-rows'))).toBe('deleted');
    expect(await storedSetting(LICENSE_POLICY_SETTINGS_KEY)).toBeUndefined();
    expect(await storedSetting(LLM_SETTINGS_KEY)).toBeUndefined();
    // A row without its entry, and one whose `organizations` is not an object (an array holding
    // its id): unchanged.
    const doomed = await newOrganization('no-entry');
    const other = await newOrganization('no-entry-other');
    const licenses = { organizations: { [other]: POLICY } };
    const llm = { ...DEFAULT_LLM_SETTINGS, organizations: [doomed, other] };
    await storeSetting(LICENSE_POLICY_SETTINGS_KEY, licenses);
    await storeSetting(LLM_SETTINGS_KEY, llm);
    try {
      expect(await deleteOrganization(db, doomed)).toBe('deleted');
      expect(await storedSetting(LICENSE_POLICY_SETTINGS_KEY)).toEqual(licenses);
      expect(await storedSetting(LLM_SETTINGS_KEY)).toEqual(llm);
    } finally {
      await db
        .delete(instanceSettings)
        .where(inArray(instanceSettings.key, [LICENSE_POLICY_SETTINGS_KEY, LLM_SETTINGS_KEY]));
    }
  });

  it('another organisation is untouched', async () => {
    const doomed = await seedOrganization('doomed-next');
    const other = await seedOrganization('neighbour');
    const before = await heldRows(other);
    const auditBefore = await auditRowsOf(other.organizationId);

    expect(await deleteOrganization(db, doomed.organizationId)).toBe('deleted');

    expect(await heldRows(other)).toEqual(before);
    expect(await auditRowsOf(other.organizationId)).toEqual(auditBefore);
  });

  it('gone: a second call answers gone and throws nothing', async () => {
    const organizationId = await newOrganization('twice');
    expect(await deleteOrganization(db, organizationId)).toBe('deleted');
    expect(await deleteOrganization(db, organizationId)).toBe('gone');
    expect(await deleteOrganization(db, '01900000-0000-7000-8000-000000000000')).toBe('gone');
  });
});

describe('the organization-delete job', () => {
  it('the handler: a queued delete runs once and succeeds; a malformed payload is logged once and completed', async () => {
    const organizationId = await newOrganization('by-job');
    await queueOrganizationDelete(db, organizationId);
    expect(organizationDeleteKey(organizationId)).toBe(`organization-delete:${organizationId}`);
    expect(await jobsOf(organizationId)).toEqual([
      {
        queue: ORGANIZATION_DELETE_QUEUE,
        status: 'queued',
        payload: { organizationId },
        maxAttempts: DEFAULT_MAX_ATTEMPTS,
      },
    ]);
    const run = recordingLogger();
    expect(
      await runUntilIdle(db, organizationDeleteHandlers({ db, logger: run.logger }), run.logger),
    ).toBe(1);
    expect(await countOf(organizations, eq(organizations.id, organizationId))).toBe(0);
    expect((await jobsOf(organizationId)).map((j) => j.status)).toEqual(['succeeded']);

    const untouched = await newOrganization('not-named');
    const malformed = await enqueue(db, {
      queue: ORGANIZATION_DELETE_QUEUE,
      payload: { organization: untouched },
    });
    const bad = recordingLogger();
    expect(
      await runUntilIdle(db, organizationDeleteHandlers({ db, logger: bad.logger }), bad.logger),
    ).toBe(1);
    expect(bad.lines).toHaveLength(1);
    expect(bad.lines[0]!.level).toBe('warn');
    const [job] = await db.select({ status: jobs.status }).from(jobs).where(eq(jobs.id, malformed));
    expect(job).toEqual({ status: 'succeeded' });
    expect(await countOf(organizations, eq(organizations.id, untouched))).toBe(1);
  });

  it('deleting: while its job is queued or running, not once it succeeded, died or failed', async () => {
    const queued = await newOrganization('deleting-queued');
    const running = await newOrganization('deleting-running');
    const failed = await newOrganization('deleting-failed');
    const idle = await newOrganization('deleting-idle');
    const all = [queued, running, failed, idle];
    expect(await deletingOrganizations(db, [])).toEqual(new Set());
    expect(await deletingOrganizations(db, all)).toEqual(new Set());

    for (const id of [queued, running, failed]) await queueOrganizationDelete(db, id);
    const setStatus = (id: string, status: 'running' | 'dead' | 'failed') =>
      db
        .update(jobs)
        .set({ status })
        .where(eq(jobs.concurrencyKey, organizationDeleteKey(id)));
    await setStatus(running, 'running');
    await setStatus(failed, 'failed');
    expect(await deletingOrganizations(db, all)).toEqual(new Set([queued, running]));

    // The running one dies: its organisation is usable again, and a Delete can be retried.
    await setStatus(running, 'dead');
    expect(await deletingOrganizations(db, all)).toEqual(new Set([queued]));

    // The queued one runs and succeeds.
    expect(
      await runUntilIdle(
        db,
        organizationDeleteHandlers({ db, logger: recordingLogger().logger }),
        recordingLogger().logger,
      ),
    ).toBe(1);
    expect((await jobsOf(queued)).map((j) => j.status)).toEqual(['succeeded']);
    expect(await deletingOrganizations(db, all)).toEqual(new Set());
  });

  it('an upper-case id in the payload: the entries are dropped and the organisation deleted (ruling C1)', async () => {
    const doomed = await newOrganization('upper-case');
    const kept = await newOrganization('upper-case-kept');
    const licenses = { organizations: { [doomed]: POLICY, [kept]: POLICY } };
    const llm = {
      ...DEFAULT_LLM_SETTINGS,
      organizations: { [doomed]: DISABLED_ORGANIZATION, [kept]: DISABLED_ORGANIZATION },
    };
    await storeSetting(LICENSE_POLICY_SETTINGS_KEY, licenses);
    await storeSetting(LLM_SETTINGS_KEY, llm);
    try {
      await queueOrganizationDelete(db, doomed.toUpperCase());
      expect((await jobsOf(doomed)).map((j) => j.payload)).toEqual([
        { organizationId: doomed.toUpperCase() },
      ]);
      const run = recordingLogger();
      expect(
        await runUntilIdle(db, organizationDeleteHandlers({ db, logger: run.logger }), run.logger),
      ).toBe(1);

      expect(await countOf(organizations, eq(organizations.id, doomed))).toBe(0);
      expect(await storedSetting(LICENSE_POLICY_SETTINGS_KEY)).toEqual({
        organizations: { [kept]: POLICY },
      });
      expect(await storedSetting(LLM_SETTINGS_KEY)).toEqual({
        ...llm,
        organizations: { [kept]: DISABLED_ORGANIZATION },
      });
    } finally {
      await db
        .delete(instanceSettings)
        .where(inArray(instanceSettings.key, [LICENSE_POLICY_SETTINGS_KEY, LLM_SETTINGS_KEY]));
    }
  });
});
