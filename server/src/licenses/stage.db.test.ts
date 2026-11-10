import {
  filelessHash,
  type DependencyEntry,
  type LicensePolicy,
  type Report,
} from '@qualor/shared';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, reportWith, type ReportParts } from '../../test/reports';
import { mainBranchId } from '../../test/issues';
import { collectCompliance } from '../compliance/collect';
import {
  analyses,
  branches,
  complianceReports,
  gateConditions,
  instanceSettings,
  issues,
  measures,
  organizations,
  projects,
  qualityGates,
  rules,
} from '../db/schema';
import { communityLimits } from '../limits';
import { currentFindings, measuresOf } from '../portfolio/query';
import { LICENSE_POLICY_SETTINGS_KEY, writeLicensePolicy } from './settings';

/** Each issue's status and start line, by the package name its message starts with. */
function statusByPackage(
  found: readonly Pick<typeof issues.$inferSelect, 'message' | 'status' | 'startLine'>[],
) {
  return Object.fromEntries(found.map((i) => [i.message.split(' ')[0], [i.status, i.startLine]]));
}

/**
 * 6M §6–§7: a dependency whose licence the organisation's policy forbids becomes an ordinary
 * issue of engine `license` at ingestion. Its identity is the package (name@version) in its
 * lockfile, as a vulnerable dependency's is, and only an analysis that really judged the
 * inventory (the feature on, the field present) may close one (Review Focus 1 and 4).
 */
describe('licence policy stage (6M §6)', () => {
  let h: IngestHarness;
  let minute = 0;
  const limits = communityLimits();
  const LOCK = 'web/package-lock.json';
  const STRONG: LicensePolicy = {
    mode: 'denylist',
    forbiddenGroups: ['strong-copyleft'],
    forbidden: [],
    allowed: [],
    warnUnknown: false,
  };
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 9, 14, 10, minute++)).toISOString(),
      files: [lockfile()],
      findings: [],
      engines: [engine('trivy-licenses')],
      ...parts,
    });
  const lockfile = (newLines: [number, number][] | 'all' = [], path = LOCK) =>
    file(path, { language: 'other', lines: 400, newLines });
  const dep = (
    name: string,
    version: string,
    licenses: string[],
    line?: number,
    path = LOCK,
  ): DependencyEntry => ({
    ecosystem: 'npm',
    path,
    name,
    version,
    licenses,
    ...(line === undefined ? {} : { line }),
  });
  const setPolicy = (policy: LicensePolicy | null) =>
    h.ctx.db.transaction((tx) => writeLicensePolicy(tx, h.organizationId, policy));
  /** Stores the licence policy row as it is given, bypassing the write's checks. */
  const store = (value: unknown) =>
    h.ctx.db
      .insert(instanceSettings)
      .values({ key: LICENSE_POLICY_SETTINGS_KEY, value })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value } });
  const storedRow = async () =>
    (
      await h.ctx.db
        .select({ value: instanceSettings.value })
        .from(instanceSettings)
        .where(eq(instanceSettings.key, LICENSE_POLICY_SETTINGS_KEY))
    )[0]?.value;
  const warningsOf = async (id: string) =>
    ((await h.ctx.db.select().from(analyses).where(eq(analyses.id, id)))[0]!.warnings ?? []) as {
      code: string;
    }[];
  const mainOf = async (p: IngestProject) => {
    const [row] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    return row!.id;
  };
  const branchOf = async (p: IngestProject, kind: 'branch' | 'merge_request') => {
    const [row] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.kind, kind)));
    return row!.id;
  };
  /** The project's licence issues on a branch, with their rule key, oldest first. */
  const licenceIssues = async (p: IngestProject, branchId?: string) =>
    (
      await h.ctx.db
        .select({ issue: issues, ruleKey: rules.key })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .where(
          and(
            eq(issues.projectId, p.id),
            eq(issues.branchId, branchId ?? (await mainOf(p))),
            eq(rules.engineId, 'license'),
          ),
        )
        .orderBy(asc(issues.id))
    ).map((r) => ({ ...r.issue, ruleKey: r.ruleKey }));
  const measuresOfAnalysis = async (analysisId: string) => {
    const rows = await h.ctx.db.select().from(measures).where(eq(measures.analysisId, analysisId));
    return Object.fromEntries(
      rows.map((r) => [r.scope === 'new' ? `new_${r.metricKey}` : r.metricKey, r.value]),
    );
  };
  const withLimit = async <T>(on: boolean, run: () => Promise<T>): Promise<T> => {
    limits.licenses.policy = on;
    try {
      return await run();
    } finally {
      limits.licenses.policy = true;
    }
  };

  beforeAll(async () => {
    limits.licenses.policy = true;
    h = await createIngestHarness({ limits });
    await setPolicy(STRONG);
  });
  afterAll(async () => {
    await h.close();
  });

  it('turns forbidden and unknown licences into licensing issues of the built-in rules', async () => {
    const p = await h.project('licenses/findings');
    await setPolicy({ ...STRONG, warnUnknown: true });
    try {
      await p.ingestOk(
        report(p, {
          dependencies: [
            dep('mit-pkg', '1.0.0', ['MIT'], 10),
            dep('gpl-pkg', '2.1.0', ['GPL-3.0-only'], 20),
            dep('dual', '3.0.0', ['MIT OR GPL-2.0-or-later'], 30),
            dep('mystery', '', [], 40),
            dep('both', '1.0.0', ['GPL-2.0-only', 'MIT']),
          ],
        }),
      );
    } finally {
      await setPolicy(STRONG);
    }
    const found = await licenceIssues(p);
    expect(
      found.map((i) => ({
        ruleKey: i.ruleKey,
        message: i.message,
        severity: i.severity,
        quality: i.quality,
        kind: i.kind,
        status: i.status,
        path: i.path,
        startLine: i.startLine,
        endLine: i.endLine,
        inNewCode: i.inNewCode,
      })),
    ).toEqual([
      // Sorted by lockfile, ecosystem, name and version.
      {
        ruleKey: 'license:forbidden',
        message:
          "both 1.0.0 is licensed GPL-2.0-only AND MIT, which the organisation's licence policy forbids (Strong copyleft).",
        severity: 'high',
        quality: 'licensing',
        kind: 'issue',
        status: 'open',
        path: LOCK,
        startLine: null,
        endLine: null,
        inNewCode: false,
      },
      {
        ruleKey: 'license:forbidden',
        message:
          "gpl-pkg 2.1.0 is licensed GPL-3.0-only, which the organisation's licence policy forbids (Strong copyleft).",
        severity: 'high',
        quality: 'licensing',
        kind: 'issue',
        status: 'open',
        path: LOCK,
        startLine: 20,
        endLine: 20,
        inNewCode: false,
      },
      {
        ruleKey: 'license:unknown',
        message: 'mystery unknown version has no licence Qualor could read.',
        severity: 'info',
        quality: 'licensing',
        kind: 'issue',
        status: 'open',
        path: LOCK,
        startLine: 40,
        endLine: 40,
        inNewCode: false,
      },
    ]);
    const gpl = found[1]!;
    const identity = filelessHash('license:forbidden', 'gpl-pkg@2.1.0', LOCK);
    expect([gpl.lineHash, gpl.contextHash]).toEqual([identity, identity]);

    const builtins = await h.ctx.db
      .select()
      .from(rules)
      .where(inArray(rules.key, ['license:forbidden', 'license:unknown']))
      .orderBy(asc(rules.key));
    expect(
      builtins.map((r) => [
        r.key,
        r.engineId,
        r.engineRuleId,
        r.origin,
        r.defaultSeverity,
        r.quality,
        r.kind,
        r.descriptionMd,
      ]),
    ).toEqual([
      [
        'license:forbidden',
        'license',
        'forbidden',
        'builtin',
        'high',
        'licensing',
        'issue',
        "A dependency's licence is forbidden by the organisation's licence policy.",
      ],
      [
        'license:unknown',
        'license',
        'unknown',
        'builtin',
        'info',
        'licensing',
        'issue',
        'A dependency has no licence Qualor could read.',
      ],
    ]);
  });

  it('makes no unknown-licence issue unless the policy asks for it', async () => {
    const p = await h.project('licenses/no-warn');
    await p.ingestOk(report(p, { dependencies: [dep('mystery', '1.0.0', [], 40)] }));
    expect(await licenceIssues(p)).toEqual([]);
  });

  it('keeps a lockfile outside the report files as an issue that is not new code', async () => {
    const p = await h.project('licenses/outside-files');
    const path = 'build/testdata/package-lock.json';
    await p.ingestOk(
      report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 7, path)] }),
    );
    const found = await licenceIssues(p);
    expect(found.map((i) => [i.path, i.startLine, i.inNewCode, i.status])).toEqual([
      [path, 7, false, 'open'],
    ]);
  });

  it('merges duplicate inventory entries into one issue', async () => {
    const p = await h.project('licenses/duplicates');
    const twice = dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 9);
    await p.ingestOk(report(p, { dependencies: [twice, { ...twice, line: 12 }] }));
    const found = await licenceIssues(p);
    expect(found.map((i) => [i.ruleKey, i.startLine])).toEqual([['license:forbidden', 9]]);
  });

  describe('Review Focus 1: a licence issue is never closed by accident', () => {
    it('keeps the issue unchanged without a real licence run, and closes it once the policy is gone', async () => {
      const p = await h.project('licenses/never-closed');
      const gpl = dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15);
      await p.ingestOk(report(p, { dependencies: [gpl] }));
      const [before, ...rest] = await licenceIssues(p);
      expect(rest).toEqual([]);
      expect(before).toMatchObject({ status: 'open', ruleKey: 'license:forbidden' });

      const unchanged = async (label: string) => {
        const now = await licenceIssues(p);
        expect(now, label).toEqual([before]);
      };
      // A lapsed licence: the feature is off, the inventory without the package.
      await withLimit(false, () => p.ingestOk(report(p, { dependencies: [] })));
      await unchanged('licence lapsed');
      // An older CLI: no dependencies field at all.
      await p.ingestOk(report(p, { engines: [engine('eslint')] }));
      await unchanged('no dependencies field');
      // The licence pass failed, or timed out: the CLI leaves the field out.
      await p.ingestOk(report(p, { engines: [engine('trivy-licenses', [], 'failed')] }));
      await unchanged('trivy-licenses failed');
      await p.ingestOk(report(p, { engines: [engine('trivy-licenses', [], 'timeout')] }));
      await unchanged('trivy-licenses timed out');
      // A pass that did not finish cannot vouch for an inventory, even one the report carries.
      for (const status of ['failed', 'timeout', 'skipped'] as const) {
        await p.ingestOk(
          report(p, { engines: [engine('trivy-licenses', [], status)], dependencies: [] }),
        );
        await unchanged(`trivy-licenses ${status} with a partial inventory`);
      }
      // A report claiming the server's own engine ran is not the server running it.
      await p.ingestOk(
        report(p, {
          engines: [engine('trivy-licenses'), { ...engine('license'), kind: 'builtin' }],
        }),
      );
      await unchanged('a report claiming engine license');

      // A real run against an empty policy: the organisation removed its policy.
      await setPolicy(null);
      try {
        await p.ingestOk(report(p, { dependencies: [gpl] }));
      } finally {
        await setPolicy(STRONG);
      }
      const [after] = await licenceIssues(p);
      expect(after).toMatchObject({ id: before!.id, status: 'closed' });
    });

    it('opens and updates issues from a truncated inventory, but closes none (final review I1)', async () => {
      const p = await h.project('licenses/truncated');
      const kept = dep('gpl-kept', '1.0.0', ['GPL-3.0-only'], 15);
      const cut = dep('gpl-cut', '1.0.0', ['GPL-3.0-only'], 25);
      await p.ingestOk(report(p, { dependencies: [kept, cut] }));
      const before = await licenceIssues(p);
      expect(before.map((i) => [i.message.split(' ')[0], i.status])).toEqual([
        ['gpl-cut', 'open'],
        ['gpl-kept', 'open'],
      ]);
      const byName = async () => statusByPackage(await licenceIssues(p));

      // The CLI cut the inventory and said so: gpl-cut fell past the cap.
      const truncated = {
        code: 'DEPENDENCIES_TRUNCATED',
        message: '1 of 50001 dependencies were left out of the inventory',
        count: 1,
      };
      await p.ingestOk(
        report(p, {
          warnings: [truncated],
          dependencies: [{ ...kept, line: 16 }, dep('gpl-new', '1.0.0', ['GPL-3.0-only'], 35)],
        }),
      );
      expect(await byName()).toEqual({
        'gpl-cut': ['open', 25],
        'gpl-kept': ['open', 16],
        'gpl-new': ['open', 35],
      });

      // An inventory at the report's bound may have been cut without the warning (a report whose
      // warnings were capped): the same.
      const full = Array.from({ length: 50_000 }, (_, i) =>
        dep(`mit-${String(i).padStart(5, '0')}`, '1.0.0', ['MIT']),
      );
      full[0] = { ...kept, line: 17 };
      await p.ingestOk(report(p, { dependencies: full }));
      expect(await byName()).toEqual({
        'gpl-cut': ['open', 25],
        'gpl-kept': ['open', 17],
        'gpl-new': ['open', 35],
      });

      // A complete inventory closes what it no longer holds.
      await p.ingestOk(report(p, { dependencies: [{ ...kept, line: 17 }] }));
      expect(await byName()).toEqual({
        'gpl-cut': ['closed', 25],
        'gpl-kept': ['open', 17],
        'gpl-new': ['closed', 35],
      });
    });

    it('does not judge against a stored policy that does not parse, and keeps every issue (final review M4)', async () => {
      const p = await h.project('licenses/policy-invalid');
      const gpl = dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15);
      await p.ingestOk(report(p, { dependencies: [gpl] }));
      const [before, ...rest] = await licenceIssues(p);
      expect(rest).toEqual([]);
      expect(before).toMatchObject({ status: 'open' });

      const OTHER = '0190a6c2-0000-7000-8000-0000000000ff';
      try {
        // This organisation's entry no longer parses (a group id a newer version wrote), the
        // other organisation's does: the inventory without the package must not close its issue.
        for (const value of [
          {
            organizations: {
              [h.organizationId]: { ...STRONG, forbiddenGroups: ['future-group'] },
              [OTHER]: STRONG,
            },
          },
          { organizations: { [h.organizationId]: 'not a policy' } },
          { organizations: [] },
        ]) {
          await store(value);
          const judged = await p.ingestOk(report(p, { dependencies: [] }));
          expect(await licenceIssues(p), JSON.stringify(value)).toEqual([before]);
          expect(await warningsOf(judged)).toContainEqual({
            code: 'LICENSE_POLICY_INVALID',
            message:
              "the organisation's stored licence policy could not be read: the dependency licences were not judged, and the licence issues stay as they are",
            count: 1,
          });
          // Stored as it is: a write refuses a row whose outer shape is broken.
          await store({ organizations: { [h.organizationId]: STRONG } });
        }

        // Another organisation's bad entry does not hide this one's policy (Task 6).
        await store({ organizations: { [h.organizationId]: STRONG, [OTHER]: { mode: 'open' } } });
        const fine = await p.ingestOk(report(p, { dependencies: [gpl] }));
        expect((await licenceIssues(p)).map((i) => [i.id, i.status])).toEqual([
          [before!.id, 'open'],
        ]);
        expect((await warningsOf(fine)).map((w) => w.code)).not.toContain('LICENSE_POLICY_INVALID');
        // No entry for this organisation at all is no policy: the empty policy runs and closes.
        await store({ organizations: { [OTHER]: STRONG } });
        await p.ingestOk(report(p, { dependencies: [gpl] }));
        const [after] = await licenceIssues(p);
        expect(after).toMatchObject({ id: before!.id, status: 'closed' });
      } finally {
        await setPolicy(STRONG);
      }
    });

    it('keeps an unreadable entry when another organisation writes, until its own organisation removes it (final review)', async () => {
      const p = await h.project('licenses/policy-invalid-kept');
      const gpl = dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15);
      await p.ingestOk(report(p, { dependencies: [gpl] }));
      const [before, ...rest] = await licenceIssues(p);
      expect(rest).toEqual([]);
      expect(before).toMatchObject({ status: 'open' });
      const [writer] = await h.ctx.db
        .insert(organizations)
        .values({ key: 'licenses-writer', name: 'Writer' })
        .returning({ id: organizations.id });
      // A group id a newer version wrote: this version cannot read the entry.
      const unreadable = { ...STRONG, forbiddenGroups: ['future-group'] };
      try {
        await store({ organizations: { [h.organizationId]: unreadable } });
        // Another organisation saves its policy: this organisation's entry is carried over as is.
        await h.ctx.db.transaction((tx) => writeLicensePolicy(tx, writer!.id, STRONG));
        expect(await storedRow()).toEqual({
          organizations: { [h.organizationId]: unreadable, [writer!.id]: STRONG },
        });
        const kept = await p.ingestOk(report(p, { dependencies: [] }));
        expect(await licenceIssues(p)).toEqual([before]);
        expect((await warningsOf(kept)).map((w) => w.code)).toContain('LICENSE_POLICY_INVALID');

        // Its own organisation removes it: the next analysis runs with no policy, which closes.
        await setPolicy(null);
        expect(await storedRow()).toEqual({ organizations: { [writer!.id]: STRONG } });
        const none = await p.ingestOk(report(p, { dependencies: [gpl] }));
        expect((await warningsOf(none)).map((w) => w.code)).not.toContain('LICENSE_POLICY_INVALID');
        const [after] = await licenceIssues(p);
        expect(after).toMatchObject({ id: before!.id, status: 'closed' });
      } finally {
        await store({ organizations: { [h.organizationId]: STRONG } });
        await h.ctx.db.delete(organizations).where(eq(organizations.id, writer!.id));
      }
    });

    it("drops a report's own licence findings: they neither keep nor reopen an issue", async () => {
      const p = await h.project('licenses/forged-findings');
      const gpl = dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15);
      await p.ingestOk(report(p, { dependencies: [gpl] }));
      const [before] = await licenceIssues(p);
      // The finding a hand-made report would send to pass for the real one: the same rule,
      // place and hashes.
      const forged = {
        engineId: 'license',
        ruleId: 'forbidden',
        message: before!.message,
        severity: 'high',
        location: { path: LOCK, startLine: 15, endLine: 15 },
        lineHash: before!.lineHash,
        contextHash: before!.contextHash,
      } satisfies Report['findings'][number];
      const claiming = [
        engine('trivy-licenses'),
        { ...engine('license'), kind: 'builtin' as const },
      ];

      // The package is gone from a real inventory: the forged finding does not keep the issue.
      await p.ingestOk(report(p, { engines: claiming, findings: [forged], dependencies: [] }));
      const [closed] = await licenceIssues(p);
      expect(closed).toMatchObject({ id: before!.id, status: 'closed' });

      // Without a licence run, it does not reopen it either.
      await p.ingestOk(report(p, { engines: claiming, findings: [forged] }));
      expect(await licenceIssues(p)).toEqual([closed]);
      const reportedRules = await h.ctx.db
        .select()
        .from(rules)
        .where(and(eq(rules.engineId, 'license'), eq(rules.origin, 'reported')));
      expect(reportedRules).toEqual([]);
    });
  });

  it('places an entry by its normalised lockfile without a line, and leaves out one with no repository path', async () => {
    const p = await h.project('licenses/paths');
    await p.ingestOk(report(p, { dependencies: [dep('mit-pkg', '1.0.0', ['MIT'], 10)] }));
    const mr = await p.ingestOk(
      report(p, {
        branch: 'feature/paths',
        mergeRequest: { id: '11', targetBranch: 'main', sourceBranch: 'feature/paths' },
        baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
        files: [lockfile('all')],
        dependencies: [
          dep('mit-pkg', '1.0.0', ['MIT'], 10),
          dep('gpl-dot', '1.0.0', ['GPL-3.0-only'], 5, `./${LOCK}`),
          dep('gpl-abs', '1.0.0', ['GPL-3.0-only'], 6, '/builds/acme/package-lock.json'),
        ],
      }),
    );
    const found = await licenceIssues(p, await branchOf(p, 'merge_request'));
    // Never file-less, so never new code just for being first seen on the merge request.
    expect(found.map((i) => [i.message.split(' ')[0], i.path, i.startLine, i.inNewCode])).toEqual([
      ['gpl-dot', LOCK, null, false],
    ]);
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, mr));
    expect(row!.warnings).toContainEqual({
      code: 'DEPENDENCY_PATHS_INVALID',
      message:
        '1 dependencies the licence policy flags were left out: their lockfile path is not a repository path',
      count: 1,
    });
  });

  describe('Review Focus 4: identity across scans', () => {
    it("keeps the issue and its won't fix when the entry moves, and makes a version bump a new issue", async () => {
      const p = await h.project('licenses/identity');
      await p.ingestOk(
        report(p, {
          dependencies: [
            dep('a-pkg', '1.0.0', ['MIT'], 5),
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15),
          ],
        }),
      );
      const [first] = await licenceIssues(p);
      await h.ctx.db.update(issues).set({ status: 'wont_fix' }).where(eq(issues.id, first!.id));

      // The lockfile was re-ordered: the package now sits on line 42, above the other.
      await p.ingestOk(
        report(p, {
          files: [lockfile([[40, 45]])],
          dependencies: [
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 42),
            dep('a-pkg', '1.0.0', ['MIT'], 50),
          ],
        }),
      );
      let found = await licenceIssues(p);
      expect(found.map((i) => [i.id, i.startLine, i.status])).toEqual([
        [first!.id, 42, 'wont_fix'],
      ]);

      // A plain re-scan keeps the won't fix.
      await p.ingestOk(
        report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 42)] }),
      );
      found = await licenceIssues(p);
      expect(found.map((i) => [i.id, i.status])).toEqual([[first!.id, 'wont_fix']]);

      // A version bump is another package: the old issue closes, the new one opens.
      await p.ingestOk(
        report(p, { dependencies: [dep('gpl-pkg', '1.0.1', ['GPL-3.0-only'], 42)] }),
      );
      found = await licenceIssues(p);
      expect(found.map((i) => [i.id === first!.id, i.status, i.message.split(' is ')[0]])).toEqual([
        [true, 'closed', 'gpl-pkg 1.0.0'],
        [false, 'open', 'gpl-pkg 1.0.1'],
      ]);
    });

    it('makes the same package in two lockfiles two issues', async () => {
      const p = await h.project('licenses/two-lockfiles');
      await p.ingestOk(
        report(p, {
          files: [lockfile([], 'app/package-lock.json'), lockfile([], 'web/package-lock.json')],
          dependencies: [
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15, 'web/package-lock.json'),
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 15, 'app/package-lock.json'),
          ],
        }),
      );
      const found = await licenceIssues(p);
      expect(found.map((i) => i.path).sort()).toEqual([
        'app/package-lock.json',
        'web/package-lock.json',
      ]);
      expect(new Set(found.map((i) => i.fingerprint)).size).toBe(2);
    });
  });

  describe('new code', () => {
    it('marks the finding new when the merge request adds its lock entry, and fails a forbidden-licence gate', async () => {
      const p = await h.project('licenses/mr');
      const [gate] = await h.ctx.db
        .insert(qualityGates)
        .values({ organizationId: h.organizationId, name: 'No new forbidden licences' })
        .returning();
      await h.ctx.db.insert(gateConditions).values({
        gateId: gate!.id,
        metricKey: 'new_forbidden_licenses',
        operator: 'gt',
        threshold: 0,
      });
      await h.ctx.db.update(projects).set({ qualityGateId: gate!.id }).where(eq(projects.id, p.id));
      await p.ingestOk(report(p, { dependencies: [dep('mit-pkg', '1.0.0', ['MIT'], 10)] }));
      const mr = await p.ingestOk(
        report(p, {
          branch: 'feature/gpl',
          mergeRequest: { id: '9', targetBranch: 'main', sourceBranch: 'feature/gpl' },
          baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
          files: [lockfile([[20, 25]])],
          dependencies: [
            dep('mit-pkg', '1.0.0', ['MIT'], 10),
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 21),
          ],
        }),
      );
      const found = await licenceIssues(p, await branchOf(p, 'merge_request'));
      expect(found.map((i) => [i.startLine, i.inNewCode])).toEqual([[21, true]]);
      expect(await measuresOfAnalysis(mr)).toMatchObject({
        forbidden_licenses: 1,
        new_forbidden_licenses: 1,
        new_licensing_issues: 1,
      });
      const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, mr));
      expect(row!.gateStatus).toBe('failed');
      expect(row!.gateResult).toMatchObject({
        conditions: [{ metric: 'new_forbidden_licenses', value: 1, status: 'failed' }],
      });
    });

    it('does not count an unchanged entry as new code when a policy starts forbidding it', async () => {
      const p = await h.project('licenses/new-policy');
      await setPolicy(null);
      try {
        await p.ingestOk(
          report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 21)] }),
        );
      } finally {
        await setPolicy(STRONG);
      }
      expect(await licenceIssues(p)).toEqual([]);
      const second = await p.ingestOk(
        report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 21)] }),
      );
      const found = await licenceIssues(p);
      expect(found.map((i) => [i.status, i.inNewCode])).toEqual([['open', false]]);
      expect(await measuresOfAnalysis(second)).toMatchObject({
        forbidden_licenses: 1,
        new_forbidden_licenses: 0,
      });
    });
  });

  describe('measures (6M §7)', () => {
    it('counts licensing issues and forbidden licences, keeps the security rating, and measures unknown licences', async () => {
      const p = await h.project('licenses/measures');
      const id = await p.ingestOk(
        report(p, {
          dependencies: [
            dep('mit-pkg', '1.0.0', ['MIT'], 10),
            dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 20),
            dep('agpl-pkg', '1.0.0', ['AGPL-3.0-only'], 30),
            dep('mystery', '1.0.0', [], 40),
          ],
        }),
      );
      // AGPL is network copyleft, not forbidden by STRONG.
      expect(await measuresOfAnalysis(id)).toMatchObject({
        licensing_issues: 1,
        forbidden_licenses: 1,
        new_licensing_issues: 0,
        new_forbidden_licenses: 0,
        high_issues: 1,
        security_issues: 0,
        security_rating: 1,
        unknown_licenses_ratio: 25,
      });
      // A report without an inventory keeps the snapshot, and the ratio with it.
      const next = await p.ingestOk(report(p, { engines: [engine('eslint')] }));
      expect(await measuresOfAnalysis(next)).toMatchObject({
        forbidden_licenses: 1,
        unknown_licenses_ratio: 25,
      });
      // An empty inventory has no ratio.
      const empty = await p.ingestOk(report(p, { dependencies: [] }));
      expect(await measuresOfAnalysis(empty)).toMatchObject({
        forbidden_licenses: 0,
        licensing_issues: 0,
        unknown_licenses_ratio: null,
      });
    });

    it("updates the forbidden count when an issue is set to won't fix", async () => {
      const p = await h.project('licenses/reevaluate');
      const id = await p.ingestOk(
        report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 20)] }),
      );
      const [issue] = await licenceIssues(p);
      const res = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/issues/${issue!.id}/transition`,
        headers: h.orgAdmin.headers,
        payload: { to: 'wont_fix', comment: 'Accepted by legal' },
      });
      expect(res.statusCode, res.body).toBeLessThan(300);
      await p.ingestOk(
        report(p, { dependencies: [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 20)] }),
      );
      const [last] = await h.ctx.db
        .select({ id: branches.lastAnalysisId })
        .from(branches)
        .where(eq(branches.id, await mainOf(p)));
      expect(last!.id).not.toBe(id);
      expect(await measuresOfAnalysis(last!.id!)).toMatchObject({
        forbidden_licenses: 0,
        accepted_issues: 1,
      });
    });
  });

  describe('compliance and portfolio leave licensing out (6M L6)', () => {
    const vuln = {
      engineId: 'trivy',
      ruleId: 'CVE-2021-44906',
      message: 'minimist@1.2.5: CVE-2021-44906',
      severity: 'high',
      location: { path: LOCK, startLine: 15, endLine: 15 },
      lineHash: filelessHash('trivy:CVE-2021-44906', 'minimist@1.2.5', LOCK),
      contextHash: filelessHash('trivy:CVE-2021-44906', 'minimist@1.2.5', LOCK),
    } satisfies Report['findings'][number];
    const parts = (deps: DependencyEntry[] | undefined): ReportParts => ({
      engines: [
        engine('trivy', [{ id: 'CVE-2021-44906', quality: 'security', defaultSeverity: 'high' }]),
        engine('trivy-licenses'),
      ],
      findings: [vuln],
      ...(deps === undefined ? {} : { dependencies: deps }),
    });
    const DEPS = [dep('gpl-pkg', '1.0.0', ['GPL-3.0-only'], 20), dep('mystery', '1.0.0', [], 30)];

    it('gives the same portfolio figures with and without a licence issue', async () => {
      await setPolicy({ ...STRONG, warnUnknown: true });
      let withLicence: string, without: string;
      const a = await h.project('licenses/portfolio-a');
      const b = await h.project('licenses/portfolio-b');
      try {
        withLicence = await a.ingestOk(report(a, parts(DEPS)));
        without = await b.ingestOk(report(b, parts(undefined)));
      } finally {
        await setPolicy(STRONG);
      }
      expect(await licenceIssues(a)).toHaveLength(2);
      const raw = await measuresOfAnalysis(withLicence);
      expect(raw).toMatchObject({ issues: 3, high_issues: 2, info_issues: 1 });
      const m = await measuresOf(h.ctx.db, [withLicence, without]);
      expect(m.get(withLicence)).toEqual(m.get(without));
      expect(m.get(withLicence)).toMatchObject({ issues: 1, high_issues: 1, info_issues: 0 });
      const f = await currentFindings(h.ctx.db, [a.id, b.id]);
      expect(f.get(a.id)).toEqual(f.get(b.id));
    });

    it('gives the same compliance source with and without a licence issue', async () => {
      const p = await h.project('licenses/compliance');
      await p.ingestOk(report(p, parts(DEPS)));
      expect(await licenceIssues(p)).toHaveLength(1);
      const branchId = await mainBranchId(h.ctx.db, p.id);
      const collect = async () => {
        const [row] = await h.ctx.db
          .insert(complianceReports)
          .values({
            organizationId: h.organizationId,
            projectId: p.id,
            branchId,
            scope: 'project',
            createdByName: 'A',
            standards: [],
          })
          .returning({ id: complianceReports.id });
        const source = await collectCompliance(h.ctx.db, row!.id, { limit: 1000 });
        await h.ctx.db
          .update(complianceReports)
          .set({ status: 'failed', error: 'test' })
          .where(eq(complianceReports.id, row!.id));
        return { ...source, generatedAt: null };
      };
      const withLicence = await collect();
      expect(withLicence.findings).toHaveLength(1);
      await h.ctx.db.execute(
        sql`DELETE FROM issues WHERE project_id = ${p.id}
             AND rule_id IN (SELECT id FROM rules WHERE engine_id = 'license')`,
      );
      expect(await collect()).toEqual(withLicence);
    });
  });

  it('accepts the licence metrics in gate conditions', async () => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/quality-gates',
      headers: h.orgAdmin.headers,
      payload: { organizationId: h.organizationId, name: 'Licences' },
    });
    expect(res.statusCode).toBe(201);
    const { id } = res.json() as { id: string };
    for (const [metric, threshold] of [
      ['new_forbidden_licenses', 0],
      ['forbidden_licenses', 0],
      ['licensing_issues', 3],
      ['new_licensing_issues', 0],
      ['unknown_licenses_ratio', 20],
    ] as const) {
      const added = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/quality-gates/${id}/conditions`,
        headers: h.orgAdmin.headers,
        payload: { metric, operator: 'gt', threshold },
      });
      expect(added.statusCode, `${metric}: ${added.body}`).toBe(201);
    }
    const tooHigh = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/quality-gates/${id}/conditions`,
      headers: h.orgAdmin.headers,
      payload: { metric: 'new_unknown_licenses_ratio', operator: 'gt', threshold: 1 },
    });
    expect(tooHigh.statusCode).toBe(422);
  });
});

/**
 * Fix round 1 (review item 1): the `license:*` rules are global and the server's own. A report
 * can neither create nor change them, and a row a report created earlier is repaired.
 */
describe('the licence rules belong to the server (6M §6)', () => {
  let h: IngestHarness;
  const limits = communityLimits();
  const LOCK = 'web/package-lock.json';
  let minute = 0;
  const report = (p: IngestProject, parts: ReportParts): Report =>
    reportWith({
      projectKey: p.key,
      analysisDate: new Date(Date.UTC(2026, 9, 15, 10, minute++)).toISOString(),
      files: [file(LOCK, { language: 'other', lines: 400, newLines: [] })],
      findings: [],
      ...parts,
    });
  const gpl: DependencyEntry = {
    ecosystem: 'npm',
    path: LOCK,
    name: 'gpl-pkg',
    version: '1.0.0',
    licenses: ['GPL-3.0-only'],
    line: 15,
  };
  /** An engine `license` a hand-made report defines, with the wrong quality and kind. */
  const forgedEngine = {
    ...engine('license', [
      { id: 'forbidden', quality: 'security', kind: 'hotspot', defaultSeverity: 'blocker' },
      { id: 'made-up', quality: 'security' },
    ]),
    kind: 'builtin',
  } satisfies Report['engines'][number];
  const licenceRules = () =>
    h.ctx.db.select().from(rules).where(eq(rules.engineId, 'license')).orderBy(asc(rules.key));
  const issueQualities = async (p: IngestProject) =>
    (
      await h.ctx.db
        .select({ quality: issues.quality, kind: issues.kind, status: issues.status })
        .from(issues)
        .where(eq(issues.projectId, p.id))
    ).map((i) => [i.quality, i.kind, i.status]);

  beforeAll(async () => {
    limits.licenses.policy = true;
    h = await createIngestHarness({ limits });
    await h.ctx.db.transaction((tx) =>
      writeLicensePolicy(tx, h.organizationId, {
        mode: 'denylist',
        forbiddenGroups: ['strong-copyleft'],
        forbidden: [],
        allowed: [],
        warnUnknown: false,
      }),
    );
  });
  afterAll(async () => {
    await h.close();
  });

  it("creates no rule from a report's engine license, and the licence run's findings are licensing", async () => {
    const p = await h.project('license-rules/forged');
    // Before any licence run: the feature off, the report defining and referencing license rules.
    limits.licenses.policy = false;
    try {
      await p.ingestOk(
        report(p, {
          engines: [engine('eslint'), forgedEngine],
          findings: [
            {
              engineId: 'license',
              ruleId: 'made-up',
              message: 'forged',
              location: { path: LOCK, startLine: 3 },
              lineHash: 'a'.repeat(32),
              contextHash: 'a'.repeat(32),
            },
          ],
        }),
      );
    } finally {
      limits.licenses.policy = true;
    }
    expect(await licenceRules()).toEqual([]);
    expect(await issueQualities(p)).toEqual([]);

    await p.ingestOk(
      report(p, { engines: [engine('trivy-licenses'), forgedEngine], dependencies: [gpl] }),
    );
    const created = await licenceRules();
    expect(created.map((r) => [r.key, r.origin, r.quality, r.kind, r.defaultSeverity])).toEqual([
      ['license:forbidden', 'builtin', 'licensing', 'issue', 'high'],
      ['license:unknown', 'builtin', 'licensing', 'issue', 'info'],
    ]);
    expect(await issueQualities(p)).toEqual([['licensing', 'issue', 'open']]);
  });

  it('repairs a licence rule a report created before reports were barred from it', async () => {
    const p = await h.project('license-rules/repair');
    // As an older server let a report leave it: reported, security, a hotspot, with a CWE.
    await h.ctx.db
      .update(rules)
      .set({
        origin: 'reported',
        quality: 'security',
        kind: 'hotspot',
        defaultSeverity: 'blocker',
        name: 'forbidden',
        descriptionMd: 'Something else',
        helpUri: 'https://example.com/x',
        tags: ['x'],
        cwe: [79],
      })
      .where(eq(rules.key, 'license:forbidden'));
    await p.ingestOk(report(p, { engines: [engine('trivy-licenses')], dependencies: [gpl] }));
    const [repaired] = await h.ctx.db
      .select()
      .from(rules)
      .where(eq(rules.key, 'license:forbidden'));
    expect(repaired).toMatchObject({
      origin: 'builtin',
      engineId: 'license',
      engineRuleId: 'forbidden',
      name: 'Forbidden licence',
      descriptionMd: "A dependency's licence is forbidden by the organisation's licence policy.",
      helpUri: null,
      defaultSeverity: 'high',
      quality: 'licensing',
      kind: 'issue',
      tags: [],
      cwe: [],
    });
    expect(await issueQualities(p)).toEqual([['licensing', 'issue', 'open']]);
  });
});
