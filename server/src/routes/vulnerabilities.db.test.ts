import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import { uuidv7 } from '../db/ids';
import {
  branches,
  projectVersions,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  users,
  vulnerabilityDecisions,
  vulnerabilityMatches,
  vulnerabilityTargetChecks,
} from '../db/schema';

const T0 = new Date('2026-10-20T10:00:00Z');
const BEFORE = new Date('2026-10-19T10:00:00Z');
const AFTER = new Date('2026-10-21T10:00:00Z');

interface Item {
  vulnerabilityId: string;
  packageName: string;
  severity: string;
  installedVersions: string[];
  fixedVersion: string | null;
  in: { kind: string; id: string; name: string }[];
  notIn: { kind: string; id: string; name: string }[];
  foundAt: string;
  withoutScan: boolean;
  new: boolean;
  ignored: boolean;
  status: string;
  decision: {
    scope: string;
    status: string;
    decidedBy: { id: string; name: string } | null;
  } | null;
}

describe('the Vulnerabilities tab read API (0.15)', () => {
  let h: IngestHarness;
  let viewer: Session;
  let outsider: Session;
  let n = 0;

  beforeAll(async () => {
    h = await createIngestHarness();
    const member = await createUser(h.ctx, { username: 'vtab-viewer' });
    await addMember(h.ctx, h.organizationId, member.id, 'viewer');
    viewer = await login(h.ctx, member.username, member.password);
    const stranger = await createUser(h.ctx, { username: 'vtab-outsider' });
    outsider = await login(h.ctx, stranger.username, stranger.password);
  });
  afterAll(async () => {
    await h.close();
  });

  const get = (url: string, session: Session = h.orgAdmin) =>
    h.ctx.app.inject({ method: 'GET', url: `/api/v0${url}`, headers: session.headers });

  /** A project with main, release/1.x and versions 2.0.0 (tracked) and 1.0.0 (not tracked). */
  const setup = async () => {
    const p = await h.project(`acme/vtab-${++n}`);
    await h.ctx.db.insert(projectVulnerabilitySettings).values({
      projectId: p.id,
      branchPatterns: ['release/*'],
      versionRule: 'lines',
      versionLines: 1,
    });
    const branch = async (name: string, isMain = false) =>
      (
        await h.ctx.db
          .insert(branches)
          .values({ projectId: p.id, kind: 'branch', name, isMain })
          .returning()
      )[0]!.id;
    const version = async (label: string, minute: number) =>
      (
        await h.ctx.db
          .insert(projectVersions)
          .values({
            projectId: p.id,
            label,
            source: 'tag',
            tag: label,
            analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, minute)),
          })
          .returning()
      )[0]!.id;
    const [mainRow] = await h.ctx.db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    const main = mainRow!.id;
    const release = await branch('release/1.x');
    const v2 = await version('2.0.0', 2);
    const v1 = await version('1.0.0', 1);
    return { projectId: p.id, main, release, v2, v1 };
  };
  const items = async (url: string, session?: Session) => {
    const res = await get(url, session);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as { items: Item[]; total: number };
  };
  const names = (list: Item[]) => list.map((i) => `${i.vulnerabilityId}/${i.packageName}`);

  it('lets a viewer read, answers 404 to a non-member and for an unknown target', async () => {
    const s = await setup();
    for (const path of ['/vulnerabilities/targets', '/vulnerabilities']) {
      expect((await get(`/projects/${s.projectId}${path}`, viewer)).statusCode).toBe(200);
      const denied = await get(`/projects/${s.projectId}${path}`, outsider);
      expect(denied.statusCode).toBe(404);
      expect(denied.json().code).toBe('NOT_FOUND');
    }
    const unknown = await get(`/projects/${s.projectId}/vulnerabilities?target=branch:${uuidv7()}`);
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json().code).toBe('NOT_FOUND');
    const foreign = await setup();
    const other = await get(
      `/projects/${s.projectId}/vulnerabilities?target=branch:${foreign.main}`,
    );
    expect(other.statusCode).toBe(404);
  });

  it('rejects a malformed query', async () => {
    const s = await setup();
    const base = `/projects/${s.projectId}/vulnerabilities`;
    for (const query of [
      'target=main',
      `target=tag:${s.main}`,
      'status=closed',
      'severity=urgent',
      'page=0',
      'pageSize=101',
      'pageSize=0',
      'extra=1',
    ]) {
      expect((await get(`${base}?${query}`)).statusCode, query).toBe(422);
    }
  });

  it('answers the summary header and the targets', async () => {
    const s = await setup();
    await seedTargetRow(h.ctx.db, {
      projectId: s.projectId,
      branchId: s.main,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
      severity: 'critical',
    });
    await seedCheck(h.ctx.db, { projectId: s.projectId, branchId: s.main, baselineAt: T0 });
    const res = await get(`/projects/${s.projectId}/vulnerabilities/targets`);
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({ monitoring: 'on', versionCount: 2, checkedAt: T0.toISOString() });
    expect(body.targets.map((x: { name: string }) => x.name)).toEqual([
      'main',
      'release/1.x',
      '2.0.0',
    ]);
    expect(body.targets[0].counts.critical).toBe(1);
    expect(body.untracked.map((x: { name: string }) => x.name)).toEqual(['1.0.0']);
  });

  it('lists items open first, then by severity, vulnerability id and package', async () => {
    const s = await setup();
    const row = (
      packageName: string,
      vulnerabilityId: string,
      severity: 'critical' | 'high' | 'low',
    ) =>
      seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId: s.main,
        packageName,
        vulnerabilityId,
        severity,
      });
    await row('b', 'CVE-2', 'high');
    await row('a', 'CVE-2', 'high');
    await row('c', 'CVE-1', 'high');
    await row('d', 'CVE-9', 'critical');
    await row('e', 'CVE-0', 'low');
    await row('f', 'CVE-0b', 'critical');
    await h.ctx.db.insert(vulnerabilityDecisions).values({
      projectId: s.projectId,
      packageName: 'f',
      vulnerabilityId: 'CVE-0b',
      status: 'wont_fix',
      comment: 'later',
    });
    const res = await items(`/projects/${s.projectId}/vulnerabilities`);
    expect(names(res.items)).toEqual([
      'CVE-9/d',
      'CVE-1/c',
      'CVE-2/a',
      'CVE-2/b',
      'CVE-0/e',
      'CVE-0b/f',
    ]);
    expect(res.total).toBe(6);
  });

  it('filters by status and severity', async () => {
    const s = await setup();
    const row = (packageName: string, severity: 'critical' | 'high') =>
      seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId: s.main,
        packageName,
        vulnerabilityId: `CVE-${packageName}`,
        severity,
      });
    await row('a', 'critical');
    await row('b', 'high');
    await row('c', 'high');
    await row('d', 'high');
    const decide = (packageName: string, status: 'false_positive' | 'wont_fix') =>
      h.ctx.db.insert(vulnerabilityDecisions).values({
        projectId: s.projectId,
        packageName,
        vulnerabilityId: `CVE-${packageName}`,
        status,
        reason: status === 'false_positive' ? 'component_not_present' : null,
      });
    await decide('c', 'false_positive');
    await decide('d', 'wont_fix');
    const base = `/projects/${s.projectId}/vulnerabilities`;
    expect(names((await items(`${base}?status=open`)).items)).toEqual(['CVE-a/a', 'CVE-b/b']);
    expect(names((await items(`${base}?status=false_positive`)).items)).toEqual(['CVE-c/c']);
    expect(names((await items(`${base}?status=wont_fix`)).items)).toEqual(['CVE-d/d']);
    expect((await items(`${base}?status=all`)).total).toBe(4);
    expect(names((await items(`${base}?severity=critical`)).items)).toEqual(['CVE-a/a']);
    expect(names((await items(`${base}?severity=high&status=open`)).items)).toEqual(['CVE-b/b']);
  });

  it('groups a pair across targets with in, notIn, installed versions and found date', async () => {
    const s = await setup();
    const common = {
      projectId: s.projectId,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
      severity: 'high' as const,
      fixedVersion: '4.17.21',
    };
    await seedTargetRow(h.ctx.db, {
      ...common,
      branchId: s.main,
      packageVersion: '4.17.0',
      firstSeenAt: AFTER,
    });
    await seedTargetRow(h.ctx.db, {
      ...common,
      branchId: s.release,
      packageVersion: '4.16.0',
      firstSeenAt: BEFORE,
    });
    const { items: list } = await items(`/projects/${s.projectId}/vulnerabilities`);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      installedVersions: ['4.16.0', '4.17.0'],
      fixedVersion: '4.17.21',
      in: [
        { kind: 'branch', id: s.main, name: 'main' },
        { kind: 'branch', id: s.release, name: 'release/1.x' },
      ],
      notIn: [{ kind: 'version', id: s.v2, name: '2.0.0' }],
      foundAt: BEFORE.toISOString(),
      status: 'open',
      decision: null,
      ignored: false,
    });
    const one = await items(`/projects/${s.projectId}/vulnerabilities?target=branch:${s.main}`);
    expect(one.items[0]).toMatchObject({
      installedVersions: ['4.17.0'],
      in: [{ kind: 'branch', id: s.main, name: 'main' }],
      notIn: [],
    });
  });

  it('flags without a scan and new per row, and ignored when every row is', async () => {
    const s = await setup();
    await seedCheck(h.ctx.db, { projectId: s.projectId, branchId: s.main, baselineAt: T0 });
    await seedCheck(h.ctx.db, { projectId: s.projectId, branchId: s.release, baselineAt: T0 });
    const row = (branchId: string, packageName: string, firstSeenAt: Date, ignored = false) =>
      seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId,
        packageName,
        vulnerabilityId: `CVE-${packageName}`,
        firstSeenAt,
        ignored,
      });
    await row(s.main, 'old', BEFORE);
    await row(s.main, 'fresh', AFTER);
    await row(s.main, 'fresh-ignored', AFTER, true);
    await row(s.main, 'fresh-triaged', AFTER);
    await row(s.main, 'half', AFTER, true);
    await row(s.release, 'half', BEFORE, false);
    await h.ctx.db.insert(vulnerabilityDecisions).values({
      projectId: s.projectId,
      packageName: 'fresh-triaged',
      vulnerabilityId: 'CVE-fresh-triaged',
      status: 'wont_fix',
    });
    const { items: list } = await items(`/projects/${s.projectId}/vulnerabilities`);
    const by = new Map(list.map((i) => [i.packageName, i]));
    expect(by.get('old')).toMatchObject({ withoutScan: false, new: false, ignored: false });
    expect(by.get('fresh')).toMatchObject({ withoutScan: true, new: true, ignored: false });
    expect(by.get('fresh-ignored')).toMatchObject({ withoutScan: true, new: false, ignored: true });
    expect(by.get('fresh-triaged')).toMatchObject({ withoutScan: true, new: false });
    expect(by.get('half')).toMatchObject({ withoutScan: true, new: false, ignored: false });
  });

  it('shows a target its own decision, and the project-wide decision without a target', async () => {
    const s = await setup();
    const [author] = await h.ctx.db.select().from(users).where(eq(users.username, 'vtab-viewer'));
    for (const branchId of [s.main, s.release]) {
      await seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
      });
    }
    await h.ctx.db.insert(vulnerabilityDecisions).values([
      {
        projectId: s.projectId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        status: 'false_positive',
        reason: 'component_not_present',
        comment: 'not shipped',
        decidedBy: author!.id,
      },
      {
        projectId: s.projectId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        branchId: s.release,
        status: 'open',
      },
    ]);
    const base = `/projects/${s.projectId}/vulnerabilities`;
    const wide = (await items(base)).items[0]!;
    expect(wide.status).toBe('false_positive');
    expect(wide.decision).toMatchObject({
      scope: 'project',
      status: 'false_positive',
      reason: 'component_not_present',
      comment: 'not shipped',
      decidedBy: { id: author!.id, name: expect.any(String) },
    });
    const onMain = (await items(`${base}?target=branch:${s.main}`)).items[0]!;
    expect(onMain.status).toBe('false_positive');
    const onRelease = (await items(`${base}?target=branch:${s.release}`)).items[0]!;
    expect(onRelease.status).toBe('open');
    expect(onRelease.decision).toMatchObject({ scope: 'branch', status: 'open' });
    expect(onRelease.decision?.decidedBy).toBeNull();
  });

  it('flags a row new on the branch whose Open override beats the project decision (Review Focus 1)', async () => {
    const s = await setup();
    const [release2] = await h.ctx.db
      .insert(branches)
      .values({ projectId: s.projectId, kind: 'branch', name: 'release/2.x' })
      .returning();
    for (const branchId of [s.main, release2!.id]) {
      await seedCheck(h.ctx.db, { projectId: s.projectId, branchId, baselineAt: T0 });
      await seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        firstSeenAt: AFTER,
      });
    }
    await h.ctx.db.insert(vulnerabilityDecisions).values([
      {
        projectId: s.projectId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        status: 'false_positive',
        reason: 'component_not_present',
      },
      {
        projectId: s.projectId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        branchId: release2!.id,
        status: 'open',
      },
    ]);
    const targets = (await get(`/projects/${s.projectId}/vulnerabilities/targets`)).json() as {
      targets: { name: string; new: number }[];
    };
    const newOf = new Map(targets.targets.map((x) => [x.name, x.new]));
    expect([newOf.get('main'), newOf.get('release/2.x')]).toEqual([0, 1]);
    const base = `/projects/${s.projectId}/vulnerabilities`;
    const onRelease = (await items(`${base}?target=branch:${release2!.id}`)).items;
    expect(onRelease).toMatchObject([{ vulnerabilityId: 'CVE-1', new: true, status: 'open' }]);
    const onMain = (await items(`${base}?target=branch:${s.main}`)).items;
    expect(onMain).toMatchObject([{ new: false, status: 'false_positive' }]);
  });

  it('shows the frozen rows of an untracked target and none of its rows without a target', async () => {
    const s = await setup();
    await seedTargetRow(h.ctx.db, {
      projectId: s.projectId,
      versionId: s.v1,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
    });
    const base = `/projects/${s.projectId}/vulnerabilities`;
    expect((await items(base)).total).toBe(0);
    const frozen = await items(`${base}?target=version:${s.v1}`);
    expect(frozen.total).toBe(1);
    expect(frozen.items[0]?.in).toEqual([{ kind: 'version', id: s.v1, name: '1.0.0' }]);
  });

  it('pages the list and keeps the total', async () => {
    const s = await setup();
    for (let i = 0; i < 5; i++) {
      await seedTargetRow(h.ctx.db, {
        projectId: s.projectId,
        branchId: s.main,
        packageName: `p${i}`,
        vulnerabilityId: `CVE-${i}`,
      });
    }
    const base = `/projects/${s.projectId}/vulnerabilities`;
    const first = await items(`${base}?pageSize=2`);
    expect([names(first.items), first.total]).toEqual([['CVE-0/p0', 'CVE-1/p1'], 5]);
    const last = await items(`${base}?pageSize=2&page=3`);
    expect([names(last.items), last.total]).toEqual([['CVE-4/p4'], 5]);
    const beyond = await items(`${base}?pageSize=2&page=9`);
    expect([beyond.items.length, beyond.total]).toEqual([0, 5]);
  });

  it('answers empty lists while monitoring is off', async () => {
    const s = await setup();
    await h.ctx.db
      .update(projectVulnerabilitySettings)
      .set({ enabled: false })
      .where(eq(projectVulnerabilitySettings.projectId, s.projectId));
    await seedTargetRow(h.ctx.db, {
      projectId: s.projectId,
      branchId: s.main,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
    });
    const summary = (await get(`/projects/${s.projectId}/vulnerabilities/targets`)).json();
    expect(summary).toMatchObject({
      monitoring: 'off',
      targets: [],
      untracked: [],
      versionCount: 2,
    });
    expect((await items(`/projects/${s.projectId}/vulnerabilities`)).total).toBe(0);
    // Final review F2: one target answers empty too, like the summary.
    const one = await items(`/projects/${s.projectId}/vulnerabilities?target=branch:${s.main}`);
    expect([one.items, one.total]).toEqual([[], 0]);
    const unknown = await get(`/projects/${s.projectId}/vulnerabilities?target=branch:${uuidv7()}`);
    expect(unknown.statusCode).toBe(404);
  });

  it('answers 300 tracked versions with 20 rows each in a few seconds', async () => {
    const p = await h.project(`acme/vtab-scale-${++n}`);
    await h.ctx.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId: p.id, versionRule: 'all' });
    const versions = await h.ctx.db
      .insert(projectVersions)
      .values(
        Array.from({ length: 300 }, (_, i) => ({
          projectId: p.id,
          label: `1.${i}.0`,
          source: 'tag' as const,
          tag: `1.${i}.0`,
          analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, i)),
        })),
      )
      .returning({ id: projectVersions.id });
    const matches = Array.from({ length: 20 }, (_, k) => ({
      purl: `pkg:npm/pkg${k}@1.0.0`,
      vulnerabilityId: `CVE-${k}`,
      severity: 'high' as const,
    }));
    await h.ctx.db.insert(vulnerabilityMatches).values(matches).onConflictDoNothing();
    await h.ctx.db.insert(targetVulnerabilities).values(
      versions.flatMap((v) =>
        matches.map((m, k) => ({
          projectId: p.id,
          versionId: v.id,
          ecosystem: 'npm',
          packageName: `pkg${k}`,
          packageVersion: '1.0.0',
          purl: m.purl,
          vulnerabilityId: m.vulnerabilityId,
        })),
      ),
    );
    await h.ctx.db.insert(vulnerabilityTargetChecks).values(
      versions.map((v) => ({
        projectId: p.id,
        versionId: v.id,
        basis: 'seed',
        baselineAt: BEFORE,
        checkedAt: T0,
      })),
    );

    const started = Date.now();
    const summary = (await get(`/projects/${p.id}/vulnerabilities/targets`)).json();
    const list = await items(`/projects/${p.id}/vulnerabilities`);
    const elapsed = Date.now() - started;
    expect(summary.targets).toHaveLength(301);
    expect(summary.targets[1].counts.high).toBe(20);
    expect(list.total).toBe(20);
    expect(list.items[0]?.in).toHaveLength(300);
    expect(elapsed).toBeLessThan(2000);
  });
});
