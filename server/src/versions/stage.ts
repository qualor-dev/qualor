import { and, eq } from 'drizzle-orm';
import { projectVersions } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import { parseVersionLabel } from './label';
import { isTrackedBranch, vulnerabilitySettings } from './settings';
import { replaceVersionDependencies, upsertVersion } from './store';

/** The longest version label (`project_versions_label_check`). */
const MAX_LABEL_CHARS = 100;

/**
 * Vulnerability monitoring, path 2: a branch analysis of a tracked branch whose `project.version`
 * is a release label becomes (or refreshes) that project version, when the project asks for it
 * (`labelVersions`). It never replaces a version a tag scan made, never records a parsed
 * pre-release, and never fails the analysis: a stale label is skipped.
 */
export const versionLabelStage: IngestionStage = {
  name: 'version-label',
  async run(ctx) {
    const { report, tx } = ctx;
    const label = report.project.version?.trim();
    if (!label || label.length > MAX_LABEL_CHARS) return;
    if (report.dependencies === undefined) return;
    if (parseVersionLabel(label)?.prerelease) return;
    const settings = await vulnerabilitySettings(tx, ctx.project.id);
    if (!settings.labelVersions || !isTrackedBranch(settings, ctx.branch)) return;
    const [existing] = await tx
      .select({ source: projectVersions.source })
      .from(projectVersions)
      .where(and(eq(projectVersions.projectId, ctx.project.id), eq(projectVersions.label, label)));
    if (existing?.source === 'tag') return;
    const version = await upsertVersion(tx, {
      projectId: ctx.project.id,
      label,
      source: 'label',
      tag: null,
      analysisId: ctx.analysisId,
      analyzedAt: new Date(report.analysisDate),
    });
    if (version === 'stale') return;
    await replaceVersionDependencies(tx, version.id, ctx.analysisId, report.dependencies);
  },
};
