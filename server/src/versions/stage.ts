import type { IngestionStage } from '../ingest/process';
import { parseVersionLabel } from './label';
import { isTrackedBranch, vulnerabilitySettings } from './settings';
import { upsertVersion } from './store';

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
    // A tag version of the label (`'kept'`) or a newer analysis of it (`'stale'`) changes nothing.
    await upsertVersion(tx, {
      projectId: ctx.project.id,
      label,
      source: 'label',
      tag: null,
      analysisId: ctx.analysisId,
      analyzedAt: new Date(report.analysisDate),
      inventory: { dependencies: report.dependencies, ignores: report.dependencyIgnores ?? null },
    });
  },
};
