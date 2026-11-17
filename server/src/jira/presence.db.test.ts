import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { seedTargetRow } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import {
  branches,
  instanceSettings,
  projectVersions,
  projectVulnerabilitySettings,
} from '../db/schema';
import { writeVulndbSettings } from '../vulndb/settings';
import { goneIssueIds, pairKey, vulnerabilityPresence } from './presence';

const CVE = 'CVE-2026-4100';

describe('presence as the sync pass judges it (spec §6.5 "gone", T6d)', () => {
  let h: IngestHarness;
  let projectId: string;
  let main: string;
  let release: string;
  let feature: string;
  let mr: string;
  let versionId: string;
  let trivyRule: string;
  let codeRule: string;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const freshPair = () => ({ packageName: `pkg-presence-${++pkgs}`, vulnerabilityId: CVE });
  const trivy = (branchId: string, packageName: string, status?: 'closed') =>
    seedIssue(db(), {
      projectId,
      branchId,
      ruleId: trivyRule,
      path: 'package-lock.json',
      packageName,
      quality: 'security',
      ...(status === undefined ? {} : { status }),
    });

  beforeAll(async () => {
    h = await createIngestHarness();
    projectId = (await h.project('PRESENCE')).id;
    main = await mainBranchId(db(), projectId);
    const branch = async (name: string, kind: 'branch' | 'merge_request' = 'branch') =>
      (await db().insert(branches).values({ projectId, kind, name, isMain: false }).returning())[0]!
        .id;
    release = await branch('release/1');
    feature = await branch('feature/x');
    mr = await branch('42', 'merge_request');
    // release/* branches are tracked; the rule `none` tracks no version.
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, branchPatterns: ['release/*'], versionRule: 'none' });
    versionId = (
      await db()
        .insert(projectVersions)
        .values({ projectId, label: '1.0.0', source: 'tag', tag: 'v1.0.0', analyzedAt: new Date() })
        .returning()
    )[0]!.id;
    trivyRule = await seedRule(db(), { key: `trivy:${CVE}`, quality: 'security' });
    codeRule = await seedRule(db(), { key: 'eslint:no-eval' });
  });
  afterAll(async () => {
    await h.close();
  });
  beforeEach(async () => {
    await db().delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await db()
      .update(projectVulnerabilitySettings)
      .set({ enabled: true })
      .where(eq(projectVulnerabilitySettings.projectId, projectId));
  });

  it('present on a tracked target or as an open Trivy issue of main or a tracked branch; gone elsewhere', async () => {
    const onMain = freshPair();
    await seedTargetRow(db(), { projectId, branchId: main, ...onMain });
    const onVersion = freshPair();
    await seedTargetRow(db(), { projectId, versionId, ...onVersion });
    const onFeature = freshPair();
    await seedTargetRow(db(), { projectId, branchId: feature, ...onFeature });
    const trivyOnRelease = freshPair();
    await trivy(release, trivyOnRelease.packageName);
    const trivyOnMr = freshPair();
    await trivy(mr, trivyOnMr.packageName);
    const trivyClosed = freshPair();
    await trivy(main, trivyClosed.packageName, 'closed');
    const trivyOnFeature = freshPair();
    await trivy(feature, trivyOnFeature.packageName);
    const unknown = freshPair();

    const pairs = [
      onMain,
      onVersion,
      onFeature,
      trivyOnRelease,
      trivyOnMr,
      trivyClosed,
      trivyOnFeature,
      unknown,
    ];
    const presence = await vulnerabilityPresence(db(), projectId, pairs);
    expect(presence).not.toBeNull();
    expect(pairs.map((p) => presence!.get(pairKey(p.packageName, p.vulnerabilityId)))).toEqual([
      true, // a row on main
      false, // only on an untracked version: gone
      false, // only on an untracked branch
      true, // only an open Trivy issue of a tracked branch
      false, // only on a merge request
      false, // only a closed Trivy issue
      false, // only a Trivy issue of an untracked branch
      false, // nowhere
    ]);

    // The version tracked (pinned): the pair is present again.
    await db()
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.id, versionId));
    const again = await vulnerabilityPresence(db(), projectId, [onVersion]);
    expect(again?.get(pairKey(onVersion.packageName, onVersion.vulnerabilityId))).toBe(true);
    await db()
      .update(projectVersions)
      .set({ tracking: 'auto' })
      .where(eq(projectVersions.id, versionId));
  });

  it('triage is not gone (anti-goal 6, spec §11.9): a pair whose only tracked row is ignored is present', async () => {
    const ignored = freshPair();
    await seedTargetRow(db(), { projectId, branchId: main, ...ignored, ignored: true });
    const presence = await vulnerabilityPresence(db(), projectId, [ignored]);
    expect(presence?.get(pairKey(ignored.packageName, ignored.vulnerabilityId))).toBe(true);
  });

  it('monitoring off for the project or the instance: null, nothing is judged', async () => {
    const pair = freshPair();
    await seedTargetRow(db(), { projectId, branchId: main, ...pair });
    await db()
      .update(projectVulnerabilitySettings)
      .set({ enabled: false })
      .where(eq(projectVulnerabilitySettings.projectId, projectId));
    expect(await vulnerabilityPresence(db(), projectId, [pair])).toBeNull();

    await db()
      .update(projectVulnerabilitySettings)
      .set({ enabled: true })
      .where(eq(projectVulnerabilitySettings.projectId, projectId));
    await db().transaction((tx) =>
      writeVulndbSettings(tx, { enabled: false }, h.ctx.config.secretKey),
    );
    expect(await vulnerabilityPresence(db(), projectId, [pair])).toBeNull();
  });

  it('gone code issues are the closed ones', async () => {
    const open = await seedIssue(db(), { projectId, branchId: main, ruleId: codeRule });
    const resolved = await seedIssue(db(), {
      projectId,
      branchId: main,
      ruleId: codeRule,
      status: 'false_positive',
    });
    const closed = await seedIssue(db(), {
      projectId,
      branchId: main,
      ruleId: codeRule,
      status: 'closed',
    });
    expect(await goneIssueIds(db(), [open, resolved, closed])).toEqual(new Set([closed]));
    expect(await goneIssueIds(db(), [])).toEqual(new Set());
  });
});
