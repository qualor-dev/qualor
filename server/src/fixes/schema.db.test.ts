import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION } from '../db/errors';
import { uuidv7 } from '../db/ids';
import {
  dependencyFixes,
  organizations,
  projectFixSettings,
  projects,
  scmConnections,
  users,
} from '../db/schema';

const ENVELOPE = { v: 1 as const, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };

describe('the fix tables (0.16 fix MRs spec §7, migration 0033_fix_mrs)', () => {
  let t: TestDatabase;
  let organizationId: string;
  let seq = 0;

  const makeOrganization = async (): Promise<string> => {
    seq += 1;
    const [org] = await t.db
      .insert(organizations)
      .values({ key: `fix-org-${seq}`, name: `Org ${seq}` })
      .returning();
    return org!.id;
  };
  const makeProject = async () => {
    seq += 1;
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId, key: `fix-p-${seq}`, name: `P ${seq}` })
      .returning();
    return project!;
  };
  const fix = (projectId: string, over: Partial<typeof dependencyFixes.$inferInsert> = {}) => {
    seq += 1;
    return {
      projectId,
      family: 'js' as const,
      packageName: `pkg-${seq}`,
      state: 'requested' as const,
      origin: 'manual' as const,
      branch: `qualor/fix/js/pkg-${seq}`,
      ...over,
    };
  };

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = await makeOrganization();
  });
  afterAll(async () => {
    await t.close();
  });

  describe('accepts', () => {
    it('settings with the rule on and auto_since, and the defaults of a bare row', async () => {
      const project = await makeProject();
      const [rule] = await t.db
        .insert(projectFixSettings)
        .values({
          projectId: project.id,
          enabled: true,
          autoMinSeverity: 'high',
          autoExploited: true,
          autoSince: new Date(),
          maxOpen: 20,
        })
        .returning();
      expect(rule?.maxOpen).toBe(20);
      const other = await makeProject();
      const [bare] = await t.db
        .insert(projectFixSettings)
        .values({ projectId: other.id })
        .returning();
      expect(bare).toMatchObject({
        enabled: false,
        autoMinSeverity: null,
        autoExploited: false,
        autoSince: null,
        maxOpen: 5,
        lastClaimAt: null,
      });
    });

    it('a requested row with its defaults', async () => {
      const project = await makeProject();
      const [row] = await t.db.insert(dependencyFixes).values(fix(project.id)).returning();
      expect(row).toMatchObject({
        state: 'requested',
        refresh: false,
        generation: 1,
        targets: [],
        vulnerabilityIds: [],
        failure: null,
        prepared: null,
        mrNumber: null,
      });
    });

    it('a preparing row with its lease fields', async () => {
      const project = await makeProject();
      await t.db.insert(dependencyFixes).values(
        fix(project.id, {
          state: 'preparing',
          leaseTokenHash: 'a'.repeat(64),
          leaseUntil: new Date(Date.now() + 60_000),
        }),
      );
    });

    it('a committing row with prepared files and an open row with mr_number and head_sha', async () => {
      const project = await makeProject();
      await t.db.insert(dependencyFixes).values(
        fix(project.id, {
          state: 'committing',
          prepared: { baseSha: 'a'.repeat(40), files: [], lockfiles: [], unfixable: [] },
        }),
      );
      await t.db
        .insert(dependencyFixes)
        .values(fix(project.id, { state: 'open', mrNumber: 7, headSha: 'b'.repeat(40) }));
    });

    it('one package of each family in one project', async () => {
      const project = await makeProject();
      for (const family of ['js', 'go', 'maven', 'python'] as const) {
        await t.db.insert(dependencyFixes).values(fix(project.id, { family, packageName: 'same' }));
      }
    });
  });

  describe('refuses', () => {
    it.each([
      ['max_open 0', { maxOpen: 0 }],
      ['max_open 21', { maxOpen: 21 }],
      [
        'an auto_min_severity "unknown"',
        { autoMinSeverity: 'unknown' as never, autoSince: new Date() },
      ],
      ['the rule on (a severity) without auto_since', { autoMinSeverity: 'high' as const }],
      ['the rule on (exploited) without auto_since', { autoExploited: true }],
    ])('settings with %s', async (_what, over) => {
      const project = await makeProject();
      await expectPgError(
        t.db.insert(projectFixSettings).values({ projectId: project.id, ...over }),
        PG_CHECK_VIOLATION,
      );
    });

    it.each([
      ['family "gradle"', { family: 'gradle' as never }],
      ['state "stuck"', { state: 'stuck' as never }],
      ['origin "bot"', { origin: 'bot' as never }],
      ['generation 0', { generation: 0 }],
      ['state open without mr_number', { state: 'open' as const, headSha: 'b'.repeat(40) }],
      ['state open without head_sha', { state: 'open' as const, mrNumber: 3 }],
      ['state preparing without a lease', { state: 'preparing' as const }],
      [
        'state preparing with a token but no deadline',
        { state: 'preparing' as const, leaseTokenHash: 'a'.repeat(64) },
      ],
      ['state committing without prepared', { state: 'committing' as const }],
    ])('a fix with %s', async (_what, over) => {
      const project = await makeProject();
      await expectPgError(
        t.db.insert(dependencyFixes).values(fix(project.id, over)),
        PG_CHECK_VIOLATION,
      );
    });

    it('a second row of one (project, family, package)', async () => {
      const project = await makeProject();
      await t.db.insert(dependencyFixes).values(fix(project.id, { packageName: 'dup' }));
      await expectPgError(
        t.db.insert(dependencyFixes).values(fix(project.id, { packageName: 'dup' })),
        PG_UNIQUE_VIOLATION,
      );
    });
  });

  describe('cascades', () => {
    it('deleting the project deletes its settings and fixes', async () => {
      const project = await makeProject();
      await t.db.insert(projectFixSettings).values({ projectId: project.id });
      await t.db.insert(dependencyFixes).values(fix(project.id));
      await t.db.delete(projects).where(eq(projects.id, project.id));
      expect(
        await t.db
          .select()
          .from(projectFixSettings)
          .where(eq(projectFixSettings.projectId, project.id)),
      ).toEqual([]);
      expect(
        await t.db.select().from(dependencyFixes).where(eq(dependencyFixes.projectId, project.id)),
      ).toEqual([]);
    });

    it('deleting the user sets requested_by to NULL', async () => {
      const project = await makeProject();
      const [user] = await t.db
        .insert(users)
        .values({ username: `fix-user-${uuidv7()}` })
        .returning();
      const [row] = await t.db
        .insert(dependencyFixes)
        .values(fix(project.id, { requestedBy: user!.id }))
        .returning();
      await t.db.delete(users).where(eq(users.id, user!.id));
      const [kept] = await t.db
        .select()
        .from(dependencyFixes)
        .where(eq(dependencyFixes.id, row!.id));
      expect(kept?.requestedBy).toBeNull();
    });

    it('fix_mrs_allowed is false on a new SCM connection', async () => {
      const [conn] = await t.db
        .insert(scmConnections)
        .values({
          organizationId,
          provider: 'gitlab',
          baseUrl: 'https://gitlab.example.com',
          tokenEnc: ENVELOPE,
        })
        .returning();
      expect(conn?.fixMrsAllowed).toBe(false);
    });
  });
});
