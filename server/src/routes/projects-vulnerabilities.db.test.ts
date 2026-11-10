import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  createTestContext,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { seedCheck, seedInventory, seedTargetRow } from '../../test/vulnerabilities';
import {
  branches,
  instanceSettings,
  jobs,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  vulnerabilityDecisions,
  vulnerabilityKev,
} from '../db/schema';
import { first } from '../db/rows';
import { fixedEdition } from '../license/edition';
import { communityLimits } from '../limits';
import type * as Portfolio from '../vulnerabilities/portfolio';
import { RECHECK_QUEUE } from '../vulnerabilities/recheck';
import type * as Summary from '../vulnerabilities/summary';

const markers = vi.hoisted(() => ({ calls: 0 }));
const facts = vi.hoisted(() => ({ portfolio: 0, main: 0 }));
vi.mock('../vulnerabilities/summary', async (importOriginal) => {
  const actual = await importOriginal<typeof Summary>();
  return {
    ...actual,
    newVulnerabilityMarkers: (...args: Parameters<typeof actual.newVulnerabilityMarkers>) => {
      markers.calls += 1;
      return actual.newVulnerabilityMarkers(...args);
    },
  };
});

vi.mock('../vulnerabilities/portfolio', async (importOriginal) => {
  const actual = await importOriginal<typeof Portfolio>();
  return {
    ...actual,
    portfolioVulnerabilityFacts: (
      ...args: Parameters<typeof actual.portfolioVulnerabilityFacts>
    ) => {
      facts.portfolio += 1;
      return actual.portfolioVulnerabilityFacts(...args);
    },
    mainOpenCounts: (...args: Parameters<typeof actual.mainOpenCounts>) => {
      facts.main += 1;
      return actual.mainOpenCounts(...args);
    },
  };
});

const T0 = new Date('2026-10-20T10:00:00Z');
const AFTER = new Date('2026-10-21T10:00:00Z');

describe('projects: the new-vulnerability marker', () => {
  let ctx: TestContext;
  let admin: Session;
  let org: string;
  let n = 0;

  const get = (url: string) =>
    ctx.app.inject({ method: 'GET', url: `/api/v0${url}`, headers: admin.headers });
  const instance = (enabled: boolean) =>
    ctx.db
      .insert(instanceSettings)
      .values({ key: 'vulndb', value: { enabled } })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value: { enabled } } });
  const rechecks = () =>
    ctx.db
      .select({ status: jobs.status, payload: jobs.payload })
      .from(jobs)
      .where(eq(jobs.queue, RECHECK_QUEUE));

  /** A project whose main branch has `fresh` new rows (none: a checked main with nothing new). */
  const seeded = async (fresh = 1) => {
    n += 1;
    const project = await createProject(ctx, admin, { organizationId: org, key: `vm${n}/api` });
    const main = first(
      await ctx.db.select().from(branches).where(eq(branches.projectId, project.id)),
    ).id;
    await seedCheck(ctx.db, { projectId: project.id, branchId: main, baselineAt: T0 });
    for (let i = 0; i < fresh; i += 1) {
      await seedTargetRow(ctx.db, {
        projectId: project.id,
        branchId: main,
        packageName: `p${i}`,
        vulnerabilityId: `CVE-${n}-${i}`,
        firstSeenAt: AFTER,
      });
    }
    return project.id;
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
  });
  afterAll(async () => {
    await ctx.close();
  });
  beforeEach(async () => {
    markers.calls = 0;
    facts.portfolio = 0;
    facts.main = 0;
    await instance(true);
  });

  // First: the page must hold only these projects, and the list is ordered by id.
  it('fills a page of 50 projects with one call of each count, quickly', async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 50; i += 1) ids.add(await seeded(3));
    markers.calls = 0;
    facts.portfolio = 0;
    facts.main = 0;
    const started = performance.now();
    const res = await get('/projects?limit=50');
    const elapsed = performance.now() - started;
    expect(res.statusCode, res.body).toBe(200);
    const items = res.json().items as {
      id: string;
      vulnerabilities: { newIn: { main: boolean } } | null;
    }[];
    expect(items).toHaveLength(50);
    expect(items.every((p) => ids.has(p.id))).toBe(true);
    expect(items.every((p) => p.vulnerabilities?.newIn.main === true)).toBe(true);
    expect(markers.calls).toBe(1);
    expect(facts).toEqual({ portfolio: 1, main: 1 });
    expect(elapsed).toBeLessThan(1000);
  });

  it('reports the targets with new vulnerabilities, in the list and for one project', async () => {
    const withNew = await seeded(2);
    const quiet = await seeded(0);
    const list = (await get('/projects?limit=200')).json().items as {
      id: string;
      vulnerabilities: unknown;
    }[];
    const of = (id: string) => list.find((p) => p.id === id)?.vulnerabilities;
    expect(of(withNew)).toMatchObject({ newIn: { main: true, branches: 0, versions: 0 } });
    expect(of(quiet)).toMatchObject({ newIn: { main: false, branches: 0, versions: 0 } });
    expect((await get(`/projects/${withNew}`)).json().vulnerabilities).toMatchObject({
      newIn: { main: true, branches: 0, versions: 0 },
    });
  });

  /**
   * A project whose main branch has an inventory and open rows of every kind, and two tracked
   * versions of which one has an open row: what the projects list counts (brief §A).
   */
  const counted = async () => {
    const id = await seeded(0);
    const main = first(await ctx.db.select().from(branches).where(eq(branches.projectId, id))).id;
    await seedInventory(ctx.db, { projectId: id, branchId: main });
    const row = (
      vulnerabilityId: string,
      extra: Partial<Parameters<typeof seedTargetRow>[1]> = {},
    ) =>
      seedTargetRow(ctx.db, {
        projectId: id,
        branchId: main,
        packageName: `pkg-${vulnerabilityId}`,
        vulnerabilityId,
        ...extra,
      });
    await row(`CVE-${n}-c1`, { severity: 'critical' });
    await row(`CVE-${n}-c2`, { severity: 'critical' });
    await row(`CVE-${n}-h1`, { severity: 'high' });
    await row(`CVE-${n}-m1`, { severity: 'medium' });
    await row(`CVE-${n}-ci`, { severity: 'critical', ignored: true });
    await row(`CVE-${n}-hf`, { severity: 'high' });
    await ctx.db.insert(vulnerabilityDecisions).values({
      projectId: id,
      packageName: `pkg-CVE-${n}-hf`,
      vulnerabilityId: `CVE-${n}-hf`,
      status: 'false_positive',
      reason: 'component_not_present',
    });
    const version = async (label: string, minute: number) =>
      first(
        await ctx.db
          .insert(projectVersions)
          .values({
            projectId: id,
            label,
            source: 'tag',
            tag: label,
            analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, minute)),
            hasInventory: true,
          })
          .returning(),
      ).id;
    const v1 = await version('1.0.0', 1);
    await version('2.0.0', 2);
    await seedTargetRow(ctx.db, {
      projectId: id,
      versionId: v1,
      packageName: 'old-pkg',
      vulnerabilityId: `CVE-2024-${7000 + n}`,
      severity: 'high',
    });
    await ctx.db
      .insert(vulnerabilityKev)
      .values({ vulnerabilityId: `CVE-2024-${7000 + n}`, dateAdded: '2024-03-05' });
    return { id, main };
  };

  it("carries the main branch's open Critical and High and the affected releases", async () => {
    const { id } = await counted();
    const quiet = await seeded(0);
    const list = (await get('/projects?limit=200')).json().items as {
      id: string;
      vulnerabilities: Record<string, unknown> | null;
    }[];
    // Ignored rows and a Not affected decision are not open; Medium is not counted. Without
    // vuln.priority there is no exploited number.
    // The rows are first seen after main's baseline: new as well.
    expect(list.find((p) => p.id === id)?.vulnerabilities).toEqual({
      newIn: { main: true, branches: 0, versions: 0 },
      main: { critical: 2, high: 1 },
      exploited: null,
      vulnerableReleases: 1,
    });
    expect((await get(`/projects/${id}`)).json().vulnerabilities).toMatchObject({
      main: { critical: 2, high: 1 },
      vulnerableReleases: 1,
    });
    // A main branch without a dependency inventory has no counts yet.
    expect(list.find((p) => p.id === quiet)?.vulnerabilities).toMatchObject({
      main: null,
      exploited: null,
      vulnerableReleases: 0,
    });
  });

  it('is null while the project switch or the instance switch is off', async () => {
    const id = await seeded();
    await ctx.db.insert(projectVulnerabilitySettings).values({ projectId: id, enabled: false });
    expect((await get(`/projects/${id}`)).json().vulnerabilities).toBeNull();
    await ctx.db
      .update(projectVulnerabilitySettings)
      .set({ enabled: true })
      .where(eq(projectVulnerabilitySettings.projectId, id));
    expect((await get(`/projects/${id}`)).json().vulnerabilities).not.toBeNull();
    await instance(false);
    expect((await get(`/projects/${id}`)).json().vulnerabilities).toBeNull();
    const list = (await get('/projects?limit=200')).json().items as {
      vulnerabilities: unknown;
    }[];
    expect(list.every((p) => p.vulnerabilities === null)).toBe(true);
  });

  it('queues a scoped re-check when the main branch changes, and only then', async () => {
    const id = await seeded(0);
    await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    const patch = (mainBranchName: string) =>
      ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/projects/${id}`,
        headers: admin.headers,
        payload: { mainBranchName },
      });
    expect((await patch('main')).statusCode).toBe(200);
    expect(await rechecks()).toEqual([]);
    expect((await patch('develop')).statusCode).toBe(200);
    expect(await rechecks()).toEqual([{ status: 'queued', payload: { projectIds: [id] } }]);

    await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    await instance(false);
    expect((await patch('trunk')).statusCode).toBe(200);
    expect(await rechecks()).toEqual([]);
    expect(
      first(await ctx.db.select().from(projects).where(eq(projects.id, id))).mainBranchName,
    ).toBe('trunk');
  });
});

describe('projects: the exploited count with vuln.priority', () => {
  let ctx: TestContext;
  let admin: Session;
  let org: string;

  beforeAll(async () => {
    ctx = await createTestContext({
      edition: fixedEdition({
        ...communityLimits(),
        vulnerabilities: { priority: true, alerts: false, sbom: false },
      }),
    });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    await ctx.db
      .insert(instanceSettings)
      .values({ key: 'vulndb', value: { enabled: true } })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value: { enabled: true } } });
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('counts the distinct KEV ids open on main and the tracked versions', async () => {
    const project = await createProject(ctx, admin, { organizationId: org, key: 'kev/api' });
    const main = first(
      await ctx.db.select().from(branches).where(eq(branches.projectId, project.id)),
    ).id;
    await seedInventory(ctx.db, { projectId: project.id, branchId: main });
    const version = first(
      await ctx.db
        .insert(projectVersions)
        .values({
          projectId: project.id,
          label: '1.0.0',
          source: 'tag',
          tag: '1.0.0',
          analyzedAt: new Date('2026-10-01T00:00:00Z'),
          hasInventory: true,
        })
        .returning(),
    ).id;
    const row = (
      target: { branchId: string } | { versionId: string },
      vulnerabilityId: string,
      extra: { ignored?: boolean } = {},
    ) =>
      seedTargetRow(ctx.db, {
        projectId: project.id,
        ...target,
        packageName: `pkg-${vulnerabilityId}`,
        vulnerabilityId,
        severity: 'critical',
        ...extra,
      });
    await row({ branchId: main }, 'CVE-2021-44228');
    await row({ versionId: version }, 'CVE-2021-44228');
    await row({ versionId: version }, 'CVE-2021-45046');
    await row({ branchId: main }, 'CVE-2022-22965', { ignored: true });
    await ctx.db.insert(vulnerabilityKev).values(
      ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-22965'].map((vulnerabilityId) => ({
        vulnerabilityId,
        dateAdded: '2021-12-10',
      })),
    );
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/projects?limit=50',
      headers: admin.headers,
    });
    const item = (res.json().items as { id: string; vulnerabilities: unknown }[]).find(
      (p) => p.id === project.id,
    );
    expect(item?.vulnerabilities).toEqual({
      newIn: { main: false, branches: 0, versions: 0 },
      main: { critical: 1, high: 0 },
      exploited: 2,
      vulnerableReleases: 1,
    });
  });
});
