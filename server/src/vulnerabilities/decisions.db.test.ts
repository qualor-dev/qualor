import { and, asc, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedIssue, seedRule } from '../../test/issues';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { first } from '../db/rows';
import {
  auditEvents,
  branches,
  issueChanges,
  issues,
  jobs,
  organizations,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  users,
  vulnerabilityDecisions,
} from '../db/schema';
import { GATE_QUEUE } from '../gates/reevaluate';
import {
  effectiveDecision,
  writeDecision,
  type DecisionInput,
  type DecisionStatus,
} from './decisions';

const VULN = 'CVE-2026-0001';

describe('the vulnerability decision store', () => {
  let t: TestDatabase;
  let userId: string;
  let n = 0;
  const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
  const audit = { recorder, context: SYSTEM_ACTOR };

  interface Fixture {
    projectId: string;
    ids: { main: string; release: string; feature: string; mr: string };
    issue: { main: string; release: string; feature: string; mr: string; other: string };
  }

  /** A project with main, release/1.x (tracked), feature/x and merge request 7, a lodash issue each. */
  const fixture = async (): Promise<Fixture> => {
    n += 1;
    const organizationId = first(
      await t.db
        .insert(organizations)
        .values({ key: `dec${n}`, name: `Dec ${n}` })
        .returning(),
    ).id;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `dec${n}/api`, name: 'Api' })
        .returning(),
    ).id;
    await t.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId, branchPatterns: ['release/*'] });
    const branch = async (kind: 'branch' | 'merge_request', name: string, isMain = false) =>
      first(await t.db.insert(branches).values({ projectId, kind, name, isMain }).returning()).id;
    const ids = {
      main: await branch('branch', 'main', true),
      release: await branch('branch', 'release/1.x'),
      feature: await branch('branch', 'feature/x'),
      mr: await branch('merge_request', '7'),
    };
    const ruleId = await seedRule(t.db, { key: `trivy:${VULN}` });
    const open = (branchId: string, packageName: string) =>
      seedIssue(t.db, { projectId, branchId, ruleId, packageName });
    return {
      projectId,
      ids,
      issue: {
        main: await open(ids.main, 'lodash'),
        release: await open(ids.release, 'lodash'),
        feature: await open(ids.feature, 'lodash'),
        mr: await open(ids.mr, 'lodash'),
        other: await open(ids.main, 'lodash-es'),
      },
    };
  };

  const input = (
    f: Fixture,
    status: DecisionStatus,
    extra: Partial<DecisionInput> = {},
  ): DecisionInput => ({
    projectId: f.projectId,
    packageName: 'lodash',
    vulnerabilityId: VULN,
    scope: { kind: 'project' },
    status,
    reason: status === 'false_positive' ? 'component_not_present' : null,
    comment: 'because',
    userId,
    source: 'tab',
    ...extra,
  });
  const write = (i: DecisionInput, recorded = false) =>
    t.db.transaction((tx) => writeDecision(tx, i, recorded ? audit : undefined));
  const statusOf = async (id: string) =>
    first(await t.db.select().from(issues).where(eq(issues.id, id)));
  const statuses = async (f: Fixture) => ({
    main: (await statusOf(f.issue.main)).status,
    release: (await statusOf(f.issue.release)).status,
    feature: (await statusOf(f.issue.feature)).status,
    mr: (await statusOf(f.issue.mr)).status,
    other: (await statusOf(f.issue.other)).status,
  });
  const rows = (f: Fixture) =>
    t.db
      .select()
      .from(vulnerabilityDecisions)
      .where(eq(vulnerabilityDecisions.projectId, f.projectId));

  beforeAll(async () => {
    t = await createTestDatabase();
    userId = first(
      await t.db.insert(users).values({ username: 'dec-user', passwordHash: 'x' }).returning(),
    ).id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('applies a project-wide decision to every lodash issue and queues the gates', async () => {
    const f = await fixture();
    await t.db.delete(jobs);
    const result = await write(input(f, 'false_positive'));
    expect(await statuses(f)).toEqual({
      main: 'false_positive',
      release: 'false_positive',
      feature: 'false_positive',
      mr: 'false_positive',
      other: 'open',
    });
    expect(result.appliedIssueIds).toHaveLength(4);
    expect(result.previous).toBeNull();
    expect(result.decision).toMatchObject({
      status: 'false_positive',
      reason: 'component_not_present',
      decidedBy: userId,
      branchId: null,
      versionId: null,
    });
    const changes = await t.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, f.issue.main));
    expect(changes).toMatchObject([
      {
        userId,
        field: 'status',
        oldValue: 'open',
        newValue: 'false_positive',
        comment: 'because',
      },
    ]);
    expect((await statusOf(f.issue.main)).resolvedBy).toBe(userId);
    const queued = await t.db.select().from(jobs).where(eq(jobs.queue, GATE_QUEUE));
    expect(queued.length).toBeGreaterThanOrEqual(4);
    expect(await statusOf(f.issue.other)).toMatchObject({ resolvedAt: null });
  });

  it('reopens only the mirrored branches: main and tracked ones, not local triage', async () => {
    const f = await fixture();
    await write(input(f, 'false_positive'));
    await write(input(f, 'open'));
    expect(await statuses(f)).toMatchObject({
      main: 'open',
      release: 'open',
      feature: 'false_positive',
      mr: 'false_positive',
    });
    const main = await statusOf(f.issue.main);
    expect(main.resolvedAt).toBeNull();
    expect(main.resolvedBy).toBeNull();
  });

  it('lets a mirrored branch follow a change between non-open statuses, a local one not', async () => {
    const f = await fixture();
    await write(input(f, 'false_positive'));
    await write(input(f, 'wont_fix'));
    expect(await statuses(f)).toMatchObject({
      main: 'wont_fix',
      release: 'wont_fix',
      feature: 'false_positive',
      mr: 'false_positive',
    });
  });

  it('skips a branch with its own row on a project-wide write', async () => {
    const f = await fixture();
    await write(input(f, 'open', { scope: { kind: 'branch', id: f.ids.release } }));
    const result = await write(input(f, 'wont_fix'));
    expect(await statuses(f)).toMatchObject({
      main: 'wont_fix',
      release: 'open',
      feature: 'wont_fix',
      mr: 'wont_fix',
    });
    expect(result.appliedIssueIds).toHaveLength(3);
  });

  it('never changes resolved or closed issues, and skips skipIssueIds', async () => {
    const f = await fixture();
    const another = await seedIssue(t.db, {
      projectId: f.projectId,
      branchId: f.ids.feature,
      ruleId: await seedRule(t.db, { key: `trivy:${VULN}` }),
      packageName: 'lodash',
    });
    await t.db.update(issues).set({ status: 'resolved' }).where(eq(issues.id, f.issue.main));
    await t.db.update(issues).set({ status: 'closed' }).where(eq(issues.id, f.issue.release));
    const result = await write(
      input(f, 'wont_fix', { skipIssueIds: [f.issue.mr, f.issue.feature] }),
    );
    expect(await statuses(f)).toMatchObject({
      main: 'resolved',
      release: 'closed',
      feature: 'open',
      mr: 'open',
    });
    expect(result.appliedIssueIds).toEqual([another]);
  });

  it('changes only the issues a transition holds, and leaves their re-evaluation to it', async () => {
    const f = await fixture();
    await t.db.delete(jobs);
    const result = await write(
      input(f, 'false_positive', { heldIssueIds: [f.issue.main, f.issue.feature] }),
    );
    expect(await statuses(f)).toMatchObject({
      main: 'false_positive',
      release: 'open',
      feature: 'false_positive',
      mr: 'open',
    });
    expect([...result.appliedIssueIds].sort()).toEqual([f.issue.main, f.issue.feature].sort());
    expect(await t.db.select().from(jobs).where(eq(jobs.queue, GATE_QUEUE))).toEqual([]);
  });

  it('applies a branch decision to that branch only', async () => {
    const f = await fixture();
    await write(input(f, 'wont_fix', { scope: { kind: 'branch', id: f.ids.feature } }));
    expect(await statuses(f)).toMatchObject({
      main: 'open',
      release: 'open',
      feature: 'wont_fix',
      mr: 'open',
    });
  });

  it('writes a version decision without touching issues or queueing anything', async () => {
    const f = await fixture();
    await t.db.delete(jobs);
    const versionId = first(
      await t.db
        .insert(projectVersions)
        .values({
          projectId: f.projectId,
          label: 'v1',
          source: 'tag',
          tag: 'v1',
          analyzedAt: new Date(),
        })
        .returning(),
    ).id;
    const result = await write(input(f, 'wont_fix', { scope: { kind: 'version', id: versionId } }));
    expect(result.appliedIssueIds).toEqual([]);
    expect(await statuses(f)).toMatchObject({ main: 'open', mr: 'open' });
    expect(await t.db.select().from(jobs).where(eq(jobs.queue, GATE_QUEUE))).toEqual([]);
    expect(result.decision.versionId).toBe(versionId);
  });

  it('replaces an override: the branch row goes and the project decision reaches the branch', async () => {
    const f = await fixture();
    await write(input(f, 'open', { scope: { kind: 'branch', id: f.ids.release } }));
    await write(input(f, 'wont_fix', { replaceOverrideOf: { kind: 'branch', id: f.ids.release } }));
    expect((await rows(f)).map((r) => r.branchId)).toEqual([null]);
    expect((await statusOf(f.issue.release)).status).toBe('wont_fix');
  });

  it('keeps one row per scope and returns the previous one', async () => {
    const f = await fixture();
    await write(input(f, 'wont_fix', { comment: 'first' }));
    const second = await write(input(f, 'false_positive', { comment: 'second' }));
    expect(second.previous).toMatchObject({ status: 'wont_fix', comment: 'first' });
    expect(second.decision).toMatchObject({ status: 'false_positive', comment: 'second' });
    expect(await rows(f)).toHaveLength(1);
    const scope = { kind: 'branch', id: f.ids.main } as const;
    await write(input(f, 'wont_fix', { scope }));
    await write(input(f, 'open', { scope }));
    expect(await rows(f)).toHaveLength(2);
  });

  it('does nothing and queues nothing when no issue changes', async () => {
    const f = await fixture();
    await t.db.update(issues).set({ status: 'resolved' }).where(eq(issues.projectId, f.projectId));
    await t.db.delete(jobs);
    const result = await write(input(f, 'wont_fix'));
    expect(result.appliedIssueIds).toEqual([]);
    expect(await t.db.select().from(jobs).where(eq(jobs.queue, GATE_QUEUE))).toEqual([]);
  });

  it('answers the effective decision: the target row over the project row', async () => {
    const f = await fixture();
    const at = (branchId: string | null) => ({
      projectId: f.projectId,
      branchId,
      versionId: null,
      packageName: 'lodash',
      vulnerabilityId: VULN,
    });
    expect(await effectiveDecision(t.db, at(f.ids.release))).toBeNull();
    await write(input(f, 'wont_fix'));
    expect(await effectiveDecision(t.db, at(f.ids.release))).toMatchObject({
      status: 'wont_fix',
    });
    await write(input(f, 'open', { scope: { kind: 'branch', id: f.ids.release } }));
    expect(await effectiveDecision(t.db, at(f.ids.release))).toMatchObject({ status: 'open' });
    expect(await effectiveDecision(t.db, at(f.ids.main))).toMatchObject({ status: 'wont_fix' });
    expect(await effectiveDecision(t.db, at(null))).toMatchObject({ status: 'wont_fix' });
  });

  it('records the audit event with the details of the change', async () => {
    const f = await fixture();
    await write(input(f, 'wont_fix'), true);
    const result = await write(
      input(f, 'false_positive', {
        scope: { kind: 'branch', id: f.ids.feature },
        source: 'issue',
      }),
      true,
    );
    const events = await t.db
      .select()
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.action, 'vulnerability.decision_changed'),
          eq(auditEvents.projectId, f.projectId),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      targetType: 'vulnerability_decision',
      targetId: expect.any(String),
      projectId: f.projectId,
    });
    expect(events[0]?.details).toEqual({
      packageName: 'lodash',
      vulnerabilityId: VULN,
      scope: 'project',
      targetId: null,
      from: null,
      to: 'wont_fix',
      reason: null,
      commented: true,
      appliedIssues: 4,
      source: 'tab',
    });
    expect(events[1]?.details).toMatchObject({
      scope: 'branch',
      targetId: f.ids.feature,
      from: null,
      to: 'false_positive',
      reason: 'component_not_present',
      appliedIssues: result.appliedIssueIds.length,
      source: 'issue',
    });
  });
});
