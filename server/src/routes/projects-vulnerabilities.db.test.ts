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
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import {
  branches,
  instanceSettings,
  jobs,
  projects,
  projectVulnerabilitySettings,
} from '../db/schema';
import { first } from '../db/rows';
import { RECHECK_QUEUE } from '../vulnerabilities/recheck';
import type * as Summary from '../vulnerabilities/summary';

const markers = vi.hoisted(() => ({ calls: 0 }));
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
    await instance(true);
  });

  // First: the page must hold only these projects, and the list is ordered by id.
  it('fills a page of 50 projects with one marker call, quickly', async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 50; i += 1) ids.add(await seeded(3));
    markers.calls = 0;
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
    expect(of(withNew)).toEqual({ newIn: { main: true, branches: 0, versions: 0 } });
    expect(of(quiet)).toEqual({ newIn: { main: false, branches: 0, versions: 0 } });
    expect((await get(`/projects/${withNew}`)).json().vulnerabilities).toEqual({
      newIn: { main: true, branches: 0, versions: 0 },
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
